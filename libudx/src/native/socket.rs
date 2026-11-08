use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::error::{Result, UdxError};

/// An incoming unreliable datagram received on a [`UdxSocket`].
#[derive(Debug, Clone)]
pub struct Datagram {
    /// Raw payload bytes.
    pub data: Vec<u8>,
    /// Source address of the datagram.
    pub addr: SocketAddr,
}

struct UdxSocketInner {
    udp: Mutex<Option<Arc<tokio::net::UdpSocket>>>,
    recv_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    streams: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<super::stream::IncomingPacket>>>>,
    fallback_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Datagram>>>>,
}

impl UdxSocketInner {
    fn new() -> Self {
        Self {
            udp: Mutex::new(None),
            recv_task: Mutex::new(None),
            streams: Arc::new(Mutex::new(HashMap::new())),
            fallback_tx: Arc::new(Mutex::new(None)),
        }
    }

    fn udp_arc(&self) -> Result<Arc<tokio::net::UdpSocket>> {
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
            let mut buf = vec![0u8; 65536];
            while let Ok((len, addr)) = udp.recv_from(&mut buf).await {
                let packet = buf[..len].to_vec();

                if len >= super::header::HEADER_SIZE {
                    if let Ok(hdr) = super::header::Header::decode(&packet) {
                        let guard = streams.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(tx) = guard.get(&hdr.remote_id) {
                            let Some(inner) = socket.upgrade() else {
                                break;
                            };
                            let _ = tx.send(super::stream::IncomingPacket {
                                data: packet,
                                addr,
                                socket: UdxSocket { inner },
                            });
                            continue;
                        }
                    }
                }

                let guard = fallback_tx.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(ref tx) = *guard {
                    let _ = tx.send(Datagram { data: packet, addr });
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
        let socket = tokio::net::UdpSocket::bind(addr).await?;
        *self.inner.udp.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(socket));
        // A rebind after `shutdown` restarts the demux loop for the same
        // stream map and datagram channel.
        self.inner.ensure_recv_loop(self)
    }

    /// Return the local address this socket is bound to.
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.inner.udp_arc()?.local_addr()?)
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
    pub(crate) fn udp_arc(&self) -> Result<Arc<tokio::net::UdpSocket>> {
        self.inner.udp_arc()
    }

    /// Register a stream to receive packets addressed to `local_id`.
    ///
    /// Rejects registration if `local_id` is already occupied by a different live stream,
    /// but permits idempotent registration of the same stream.
    pub(crate) fn register_stream(
        &self,
        local_id: u32,
        tx: mpsc::UnboundedSender<super::stream::IncomingPacket>,
    ) -> Result<()> {
        let mut streams = self.inner.streams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = streams.get(&local_id) {
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
        streams.insert(local_id, tx);
        drop(streams);
        self.inner.ensure_recv_loop(self)?;
        Ok(())
    }

    pub(crate) fn streams_ref(
        &self,
    ) -> Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<super::stream::IncomingPacket>>>> {
        Arc::clone(&self.inner.streams)
    }

    /// Send an unreliable datagram to `addr`. Fire-and-forget.
    pub fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<()> {
        let udp = self.inner.udp_arc()?;
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
    use super::*;

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
        assert_eq!(live, 0, "dropping 64 bound handles leaked {live} UDP sockets");
    }

    #[tokio::test]
    async fn socket_registration_rejects_overwrite_permits_idempotent() {
        let socket = UdxSocket::new();
        socket
            .bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .expect("bind");

        let (tx1, rx1) = mpsc::unbounded_channel();
        let (tx2, _rx2) = mpsc::unbounded_channel();

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
}
