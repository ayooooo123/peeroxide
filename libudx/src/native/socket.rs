use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;

use super::stream::{StreamEntry, Timewait};
use crate::error::{Result, UdxError};

/// An incoming unreliable datagram received on a [`UdxSocket`].
#[derive(Debug, Clone)]
pub struct Datagram {
    /// Raw payload bytes.
    pub data: Vec<u8>,
    /// Source address of the datagram.
    pub addr: SocketAddr,
}

/// What the receive loop does with one datagram.
enum Route {
    /// Handed to a live stream's queue.
    Stream,
    /// Answered by the time-wait entry with this `type_flags`.
    Timewait(Arc<Timewait>, u8),
    /// Nothing in the stream table: the whole datagram goes to the fallback.
    Fallback,
}

struct UdxSocketInner {
    udp: Mutex<Option<Arc<super::udp::Udp>>>,
    recv_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    streams: Arc<Mutex<HashMap<u32, StreamEntry>>>,
    fallback_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Datagram>>>>,
    /// Stream packets refused because the stream's queue was full. A packet
    /// refused because the stream is gone (the queue is closed) is not
    /// counted.
    dropped_stream_packets: AtomicU64,
}

impl UdxSocketInner {
    fn new() -> Self {
        Self {
            udp: Mutex::new(None),
            recv_task: Mutex::new(None),
            streams: Arc::new(Mutex::new(HashMap::new())),
            fallback_tx: Arc::new(Mutex::new(None)),
            dropped_stream_packets: AtomicU64::new(0),
        }
    }

    fn udp_arc(&self) -> Result<Arc<super::udp::Udp>> {
        self.udp
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
            .ok_or_else(|| UdxError::Io(std::io::Error::other("socket not bound")))
    }

    fn ensure_recv_loop(&self, handle: &UdxSocket) -> Result<()> {
        let mut guard = self.recv_task.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref handle) = *guard {
            if !handle.is_finished() {
                return Ok(());
            }
        }

        let udp = self.udp_arc()?;
        let streams = Arc::clone(&self.streams);
        let fallback_tx = Arc::clone(&self.fallback_tx);
        // Identify the arrival socket on every demultiplexed packet so a
        // stream mid-`change_remote` can answer on the path the packet came
        // from (C libudx routes by the `udx_socket_t` it arrived on).
        // The receive task must not keep its own owner (and thus its fd) alive.
        let socket = Arc::downgrade(&handle.inner);

        let handle = tokio::spawn(async move {
            use super::udp::{DATAGRAM_SIZE, Udp};
            /// Size of the slab that backs received stream packet bodies.
            /// About 44 full-MTU payloads share one heap allocation instead
            /// of allocating per datagram, while keeping retained memory per
            /// slab small.
            const RX_SLAB_BYTES: usize = 65_536;
            let udp_ptr = Arc::as_ptr(&udp) as usize;
            // Probe-only sockets (holepunch) keep one buffer; a batch is allocated
            // once stream traffic arrives.
            let mut bufs = vec![vec![0u8; DATAGRAM_SIZE]];
            let mut datagrams = Vec::new();
            let mut rx_slab = BytesMut::new();
            'receive: loop {
                if let Err(err) = udp.recv_batch(&mut bufs, &mut datagrams).await {
                    // C logs a receive error and keeps reading (udx.c:1950).
                    // Only a socket that can no longer name itself is gone.
                    if udp.local_addr().is_err() {
                        break;
                    }
                    tracing::debug!(%err, "udx: recv error");
                    tokio::task::yield_now().await;
                    continue;
                }
                let mut stream_packet = false;
                // Upgrade the weak owner once per receive batch instead of on
                // every packet.
                let mut batch_socket: Option<Arc<UdxSocketInner>> = None;
                // One guard serves a run of stream packets; anything else
                // releases it. The block ends (and the guard drops) before
                // the next `.await`.
                {
                    let mut streams_guard: Option<
                        std::sync::MutexGuard<'_, HashMap<u32, StreamEntry>>,
                    > = None;
                    for (index, range, addr) in datagrams.drain(..) {
                        // Decode from the receive buffer: no copy, and no lock
                        // for a datagram that is not a UDX packet.
                        let datagram = &bufs[index][range];
                        let header = if datagram.len() >= super::header::HEADER_SIZE {
                            super::header::Header::decode(datagram).ok()
                        } else {
                            None
                        };
                        let route = match header {
                            Some(header) => {
                                let guard = streams_guard.get_or_insert_with(|| {
                                    streams.lock().unwrap_or_else(|e| e.into_inner())
                                });
                                match guard.get(&header.remote_id) {
                                    Some(StreamEntry::Stream(tx)) => {
                                        let inner = match &batch_socket {
                                            Some(inner) => Arc::clone(inner),
                                            None => {
                                                let Some(upgraded) = socket.upgrade() else {
                                                    break 'receive;
                                                };
                                                let cloned = Arc::clone(&upgraded);
                                                batch_socket = Some(upgraded);
                                                cloned
                                            }
                                        };
                                        stream_packet = true;
                                        // Copy once into the slab without the
                                        // header; empty bodies (plain ACKs) do
                                        // not touch the slab or allocate.
                                        let body_slice = &datagram[super::header::HEADER_SIZE..];
                                        let body = if body_slice.is_empty() {
                                            Bytes::new()
                                        } else {
                                            if rx_slab.capacity() < body_slice.len() {
                                                rx_slab = BytesMut::with_capacity(
                                                    RX_SLAB_BYTES.max(body_slice.len()),
                                                );
                                            }
                                            rx_slab.extend_from_slice(body_slice);
                                            rx_slab.split().freeze()
                                        };
                                        let packet = super::stream::IncomingPacket {
                                            header,
                                            body,
                                            addr,
                                            socket: UdxSocket { inner },
                                            udp_ptr,
                                        };
                                        match tx.try_send(packet) {
                                            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
                                            // A full queue drops the packet like any
                                            // UDP overflow; the sender retransmits.
                                            Err(mpsc::error::TrySendError::Full(packet)) => {
                                                packet
                                                    .socket
                                                    .inner
                                                    .dropped_stream_packets
                                                    .fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                        Route::Stream
                                    }
                                    // C `process_timewait`: answered or ignored,
                                    // never handed on.
                                    Some(StreamEntry::Timewait(timewait)) => {
                                        Route::Timewait(Arc::clone(timewait), header.type_flags)
                                    }
                                    None => Route::Fallback,
                                }
                            }
                            None => Route::Fallback,
                        };
                        match route {
                            Route::Stream => continue,
                            Route::Timewait(timewait, type_flags) => {
                                streams_guard = None;
                                timewait.answer(type_flags);
                                continue;
                            }
                            Route::Fallback => {}
                        }
                        // Not a stream packet: release the stream table before
                        // taking the fallback lock, and copy it whole.
                        streams_guard = None;
                        let guard = fallback_tx.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(tx) = &*guard {
                            let _ = tx.send(Datagram {
                                data: datagram.to_vec(),
                                addr,
                            });
                        }
                    }
                }
                if stream_packet && bufs.len() == 1 {
                    bufs.resize_with(Udp::batch_buffers(), || vec![0; DATAGRAM_SIZE]);
                }
            }
        });

        *guard = Some(handle);
        Ok(())
    }

    fn close_impl(&self) {
        if let Some(handle) = self
            .recv_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            handle.abort();
        }
        *self.udp.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

impl Drop for UdxSocketInner {
    fn drop(&mut self) {
        self.close_impl();
    }
}

/// A UDP socket used for UDX stream transport and unreliable datagrams.
///
/// `UdxSocket` is a cheap-clone handle: cloning it increments a reference
/// count and all clones share the same underlying UDP socket. The socket is
/// closed (receive loop aborted) when the *last* clone is dropped.
///
/// Incoming packets are demultiplexed: UDX stream packets (identified by
/// header magic + stream ID) are routed to the owning [`super::stream::UdxStream`],
/// while non-UDX packets are delivered as [`Datagram`]s via [`recv_start`](Self::recv_start).
#[derive(Clone)]
pub struct UdxSocket {
    inner: Arc<UdxSocketInner>,
}

impl UdxSocket {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(UdxSocketInner::new()),
        }
    }

    /// Bind the socket to a local address. Returns an error if already bound.
    pub async fn bind(&self, addr: SocketAddr) -> Result<()> {
        if self
            .inner
            .udp
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Err(UdxError::Io(std::io::Error::other("socket already bound")));
        }
        let socket = super::udp::Udp::bind(addr).await?;
        *self.inner.udp.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(socket));
        // A rebind after `shutdown` restarts the demux loop for the same
        // stream map and datagram channel.
        self.inner.ensure_recv_loop(self)
    }

    /// Return the local address this socket is bound to.
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.inner.udp_arc()?.local_addr()?)
    }

    /// Number of stream packets dropped because the stream's incoming queue
    /// was full.
    ///
    /// A packet refused because the stream is gone (its queue is closed) is
    /// not counted, and neither is a datagram for no stream.
    pub fn dropped_stream_packets(&self) -> u64 {
        self.inner.dropped_stream_packets.load(Ordering::Relaxed)
    }

    /// Set the IP time-to-live (IPv4 `IP_TTL` / IPv6 hop limit) used for
    /// outgoing datagrams sent on this socket.
    ///
    /// A low TTL is used by NAT-holepunching probes that intentionally
    /// expire before reaching the remote peer (birthday-attack probes that
    /// must not trigger a "connection refused" ICMP response visible to the
    /// remote NAT), while the default TTL is used for regular traffic.
    pub fn set_ttl(&self, ttl: u32) -> Result<()> {
        let udp = self.inner.udp_arc()?;
        Ok(udp.set_ttl(ttl)?)
    }

    /// Return the currently configured IP time-to-live for this socket.
    pub fn ttl(&self) -> Result<u32> {
        let udp = self.inner.udp_arc()?;
        Ok(udp.ttl()?)
    }

    /// Get a shared reference to the underlying UDP socket.
    pub(crate) fn udp_arc(&self) -> Result<Arc<super::udp::Udp>> {
        self.inner.udp_arc()
    }

    /// Register a stream to receive packets addressed to `local_id`.
    ///
    /// Rejects registration if `local_id` is already occupied by a different live stream,
    /// but permits idempotent registration of the same stream.
    pub(crate) fn register_stream(
        &self,
        local_id: u32,
        tx: mpsc::Sender<super::stream::IncomingPacket>,
    ) -> Result<()> {
        let mut streams = self.inner.streams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(StreamEntry::Stream(existing)) = streams.get(&local_id) {
            if existing.same_channel(&tx) {
                drop(streams);
                self.inner.ensure_recv_loop(self)?;
                return Ok(());
            }
            if !existing.is_closed() {
                return Err(UdxError::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "stream ID already registered on socket",
                )));
            }
        }
        // A timewait entry gives way to the new stream (C `udx_stream_init`).
        streams.insert(local_id, StreamEntry::Stream(tx));
        drop(streams);
        self.inner.ensure_recv_loop(self)?;
        Ok(())
    }

    pub(crate) fn streams_ref(&self) -> Arc<Mutex<HashMap<u32, StreamEntry>>> {
        Arc::clone(&self.inner.streams)
    }

    /// Send an unreliable datagram to `addr`. Fire-and-forget.
    pub fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<()> {
        let udp = self.inner.udp_arc()?;
        if !matches!(udp.try_send_to(data, addr), Err(err) if err.kind() == std::io::ErrorKind::WouldBlock)
        {
            return Ok(());
        }
        let data = data.to_vec();
        tokio::spawn(async move {
            let _ = udp.send_to(&data, addr).await;
        });
        Ok(())
    }

    /// Begin receiving non-stream datagrams on this socket.
    pub fn recv_start(&self) -> Result<mpsc::UnboundedReceiver<Datagram>> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self
            .inner
            .fallback_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(tx);
        self.inner.ensure_recv_loop(self)?;
        Ok(rx)
    }

    /// Close the socket and stop the receive loop.
    ///
    /// Because `UdxSocket` is a clone handle, this closes the shared socket
    /// for every clone. The handle can be bound again with [`Self::bind`].
    pub async fn close(self) -> Result<()> {
        self.inner.close_impl();
        Ok(())
    }

    /// Close the underlying UDP socket and stop the receive loop without
    /// consuming the handle.
    ///
    /// Any send attempted afterwards fails (`socket not bound`), and the
    /// handle can be bound again with [`Self::bind`] — the UDX stream map and
    /// datagram channel survive, which is what a DHT suspend/resume cycle
    /// needs (dht-rpc `io.suspend()` closes both sockets and rebinds on
    /// `io.resume()`).
    ///
    /// Resolves once the receive task has dropped its reference to the OS
    /// socket, so the port can be rebound immediately (dht-rpc awaits both
    /// `close()` calls before rebinding for the same reason).
    pub async fn shutdown(&self) {
        let handle = self
            .inner
            .recv_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        self.inner
            .udp
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::header::{FLAG_DATA, HEADER_SIZE, Header};
    use super::*;
    use std::time::Duration;

    /// A wire-format stream packet (header + payload) for demux tests.
    fn stream_packet(remote_id: u32, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut packet = Header {
            type_flags: FLAG_DATA,
            data_offset: 0,
            remote_id,
            recv_window: 4096,
            seq,
            ack: 0,
        }
        .encode()
        .to_vec();
        packet.extend_from_slice(payload);
        packet
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "unreliable datagram task-allocation benchmark"]
    async fn datagram_task_benchmark() {
        let spawned = std::env::var("UDX_ASYNC_DATAGRAMS").as_deref() == Ok("1");
        let sender = UdxSocket::new();
        let receiver = UdxSocket::new();
        sender.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        receiver.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let destination = receiver.local_addr().await.unwrap();
        let mut incoming = receiver.recv_start().unwrap();
        let payload = [42; 64];
        let start = std::time::Instant::now();
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            for _ in 0..1024 {
                for _ in 0..32 {
                    if spawned {
                        let udp = sender.udp_arc().unwrap();
                        let data = payload.to_vec();
                        tokio::spawn(async move {
                            let _ = udp.send_to(&data, destination).await;
                        });
                    } else {
                        sender.send_to(&payload, destination).unwrap();
                    }
                }
                for _ in 0..32 {
                    assert_eq!(incoming.recv().await.unwrap().data, payload);
                }
            }
        })
        .await
        .unwrap();
        println!(
            "DATAGRAM spawned={spawned} packets=32768 seconds={:.6}",
            start.elapsed().as_secs_f64()
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dropping_socket_handles_releases_udp_sockets() {
        let mut sockets = Vec::new();
        for _ in 0..64 {
            let socket = UdxSocket::new();
            socket.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let udp = socket.udp_arc().unwrap();
            sockets.push(Arc::downgrade(&udp));
            let clone = socket.clone();
            drop(socket);
            assert!(sockets.last().unwrap().upgrade().is_some());
            drop(clone);
        }
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while sockets.iter().any(|socket| socket.upgrade().is_some()) {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await;
        let live = sockets
            .iter()
            .filter(|socket| socket.upgrade().is_some())
            .count();
        assert_eq!(
            live, 0,
            "dropping 64 bound handles leaked {live} UDP sockets"
        );
    }

    #[tokio::test]
    async fn socket_registration_rejects_overwrite_permits_idempotent() {
        let socket = UdxSocket::new();
        socket
            .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .expect("bind");

        let (tx1, rx1) = mpsc::channel(1);
        let (tx2, _rx2) = mpsc::channel(1);

        // 1. Initial registration of tx1 at ID 10 succeeds
        socket
            .register_stream(10, tx1.clone())
            .expect("initial registration");

        // 2. Same-stream registration (tx1 clone, same channel) succeeds idempotently
        socket
            .register_stream(10, tx1.clone())
            .expect("idempotent registration");

        // 3. Different stream (tx2, different channel) at ID 10 is rejected
        let err = socket.register_stream(10, tx2.clone());
        assert!(
            err.is_err(),
            "registration with different stream must be rejected"
        );

        // 4. Close tx1 (drop receiver rx1) -> tx1 is now closed
        drop(rx1);
        assert!(tx1.is_closed());

        // 5. Now tx2 can register at ID 10
        socket
            .register_stream(10, tx2)
            .expect("registration after previous stream closed");
    }

    /// One batch: a stream packet, a datagram with no stream, then another
    /// stream packet. Both stream packets must reach the stream in order while
    /// the fallback receiver gets the whole datagram, its first 20 bytes
    /// included. A body-only fallback copy or a stream-table lock held across
    /// the fallback send is wrong.
    #[tokio::test]
    async fn mixed_batch_keeps_stream_order_and_whole_fallback_datagram() {
        let socket = UdxSocket::new();
        socket.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let to = socket.local_addr().await.unwrap();

        let (tx, mut rx) = mpsc::channel(8);
        socket.register_stream(10, tx).unwrap();
        let mut fallback = socket.recv_start().unwrap();

        let first = stream_packet(10, 0, b"first");
        let stranger = stream_packet(77, 0, b"fallback");
        let second = stream_packet(10, 1, b"second");
        for packet in [&first, &stranger, &second] {
            peer.send_to(packet, to).await.unwrap();
        }

        let (one, two) = tokio::time::timeout(Duration::from_secs(1), async {
            let one = rx.recv().await.expect("first stream packet");
            let two = rx.recv().await.expect("second stream packet");
            (one, two)
        })
        .await
        .expect("stream packets did not arrive in order");
        assert_eq!((one.header.seq, one.body.as_ref()), (0, &b"first"[..]));
        assert_eq!((two.header.seq, two.body.as_ref()), (1, &b"second"[..]));

        let datagram = tokio::time::timeout(Duration::from_secs(1), fallback.recv())
            .await
            .expect("fallback datagram")
            .expect("fallback receiver open");
        assert_eq!(
            datagram.data, stranger,
            "the fallback gets the whole datagram, header included"
        );
        assert_eq!(&datagram.data[..HEADER_SIZE], &stranger[..HEADER_SIZE]);
    }

    /// A full stream queue must count one drop for each refused packet and a
    /// closed queue (the stream is gone) must count none. Dropping a packet
    /// with `let _ = try_send` (nothing counted) or counting the closed queue
    /// is the wrong behaviour this catches.
    #[tokio::test]
    async fn full_stream_queue_is_counted_but_a_closed_one_is_not() {
        let socket = UdxSocket::new();
        socket.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let to = socket.local_addr().await.unwrap();
        let mut fallback = socket.recv_start().unwrap();

        // Queues by hand, no processor task: capacity 2 accepts two packets
        // and refuses the rest.
        let (tx, mut rx) = mpsc::channel(2);
        socket.register_stream(10, tx).unwrap();
        // A stream that is gone: its sender is closed, not full.
        let (closed_tx, closed_rx) = mpsc::channel(2);
        drop(closed_rx);
        socket.register_stream(11, closed_tx).unwrap();

        for i in 0..5u8 {
            peer.send_to(&stream_packet(10, u32::from(i), &[i]), to)
                .await
                .unwrap();
        }
        for _ in 0..2 {
            peer.send_to(&stream_packet(11, 0, b"gone"), to)
                .await
                .unwrap();
        }
        // A datagram for no stream is the marker: the demux handles the
        // datagrams in order, so everything above has been processed once it
        // reaches the fallback.
        peer.send_to(&stream_packet(99, 0, b"marker"), to)
            .await
            .unwrap();
        let marker = tokio::time::timeout(Duration::from_secs(1), fallback.recv())
            .await
            .expect("marker datagram")
            .expect("fallback receiver open");
        assert_eq!(&marker.data[HEADER_SIZE..], b"marker");

        assert_eq!(
            socket.dropped_stream_packets(),
            3,
            "the three packets refused by the full queue, and only those"
        );
        let queued: Vec<Vec<u8>> = (0..2)
            .map(|_| rx.try_recv().expect("queued packet").body.to_vec())
            .collect();
        assert_eq!(queued, [vec![0], vec![1]]);
        assert!(
            rx.try_recv().is_err(),
            "the queue accepted more than its capacity"
        );
    }
}
