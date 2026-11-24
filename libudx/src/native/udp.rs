//! The OS UDP socket behind a [`super::socket::UdxSocket`].
//!
//! On Linux and Android a paced burst to one peer leaves in one `sendmsg`
//! (UDP GSO) and the receive loop reads many datagrams per call (`recvmmsg`
//! with GRO): a stream's packets are almost all the same size, so this turns
//! one system call per packet into one per burst. Other platforms still send
//! one datagram per call, but a receive waits for one datagram and then takes
//! the datagrams that already wait, one for each buffer.

use std::io;
use std::net::SocketAddr;

/// Largest UDP payload the kernel accepts in one GSO send.
#[cfg(any(target_os = "linux", target_os = "android"))]
const GSO_MAX_BYTES: usize = 65_507;

/// `EMSGSIZE` on Linux and Android (generic errno table; this crate does
/// not depend on `libc` directly).
#[cfg(any(target_os = "linux", target_os = "android"))]
const EMSGSIZE: i32 = 90;

#[cfg(any(target_os = "linux", target_os = "android"))]
thread_local! {
    /// The packets of one GSO send joined into one slice of bytes, kept for
    /// the thread between calls: one buffer for each thread that sends, not
    /// one for each stream, and never larger than one GSO send
    /// ([`GSO_MAX_BYTES`]). A call reserves the bytes of its run in one step
    /// before it appends the packets, so a steady burst on a thread allocates
    /// the buffer once and then reuses it.
    static SEND_SCRATCH: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The send buffer's allocation address and capacity, for the tests.
#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
fn send_scratch() -> (*const u8, usize) {
    SEND_SCRATCH.with_borrow_mut(|scratch| (scratch.as_ptr(), scratch.capacity()))
}

/// Receive buffer for one datagram (UDX packets are at most 1500 bytes; DHT
/// messages are smaller than 64 KiB).
pub(crate) const DATAGRAM_SIZE: usize = 65_536;

/// Kernel socket buffer sizes to try, largest first (JS PearTube's
/// `tuneUdxSocket`): a full congestion window sent in one burst must not
/// overflow a 208 KiB default receive buffer on the other side.
const SOCKET_BUFFERS: [usize; 3] = [8 << 20, 4 << 20, 2 << 20];

pub(crate) struct Udp {
    socket: tokio::net::UdpSocket,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    state: quinn_udp::UdpSocketState,
    /// One stream's burst at a time: on macOS, streams on several worker
    /// threads sending into one socket spend most of `sendto` contending for
    /// its kernel lock (3x the CPU per packet with four peers).
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    send_lock: std::sync::Mutex<()>,
}

impl Udp {
    pub(crate) async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = tokio::net::UdpSocket::bind(addr).await?;
        let sock = socket2::SockRef::from(&socket);
        // Best effort: the kernel caps these at its own maximum.
        let _ = SOCKET_BUFFERS
            .iter()
            .find(|&&size| sock.set_recv_buffer_size(size).is_ok());
        let _ = SOCKET_BUFFERS
            .iter()
            .find(|&&size| sock.set_send_buffer_size(size).is_ok());
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let state = quinn_udp::UdpSocketState::new((&socket).into())?;
        Ok(Self {
            socket,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            state,
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            send_lock: std::sync::Mutex::new(()),
        })
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub(crate) fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.socket.set_ttl(ttl)
    }

    pub(crate) fn ttl(&self) -> io::Result<u32> {
        self.socket.ttl()
    }

    pub(crate) fn try_send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.socket.try_send_to(buf, addr)
    }

    pub(crate) async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(buf, addr).await
    }

    /// Send `packets` in order. Errors are dropped like single sends: UDX
    /// retransmits what the network loses. Returns the datagram size of a
    /// GSO run the kernel refused with `EMSGSIZE` (segment plus headers above
    /// the route MTU); that run went out again one datagram at a time.
    pub(crate) async fn send_batch<P: AsRef<[u8]>>(
        &self,
        packets: &[(P, SocketAddr)],
    ) -> Option<usize> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let mut too_big = None;
            let mut rest = packets;
            while !rest.is_empty() {
                let run = gso_run(rest, self.state.max_gso_segments());
                let (batch, tail) = rest.split_at(run);
                rest = tail;
                let destination = batch[0].1;
                if run == 1 {
                    let _ = self.socket.send_to(batch[0].0.as_ref(), destination).await;
                    continue;
                }
                // The bytes of the whole run in one reservation: the first
                // burst on a thread allocates once instead of growing step by
                // step, and a later burst of the same shape allocates nothing.
                let bytes: usize = batch.iter().map(|(packet, _)| packet.as_ref().len()).sum();
                let segment_size = batch[0].0.as_ref().len();
                // `try_send`, not `send`: `send` reports EMSGSIZE as success.
                let sent = self
                    .socket
                    .async_io(tokio::io::Interest::WRITABLE, || {
                        SEND_SCRATCH.with_borrow_mut(|scratch| {
                            // A retry after `WouldBlock` fills the buffer
                            // again: the kernel took none of it.
                            scratch.clear();
                            scratch.reserve_exact(bytes);
                            for (packet, _) in batch {
                                scratch.extend_from_slice(packet.as_ref());
                            }
                            let transmit = quinn_udp::Transmit {
                                destination,
                                ecn: None,
                                contents: scratch.as_slice(),
                                segment_size: Some(segment_size),
                                src_ip: None,
                            };
                            self.state.try_send((&self.socket).into(), &transmit)
                        })
                    })
                    .await;
                if matches!(&sent, Err(e) if e.raw_os_error() == Some(EMSGSIZE)) {
                    too_big = Some(segment_size);
                    for (packet, to) in batch {
                        let _ = self.socket.send_to(packet.as_ref(), *to).await;
                    }
                }
            }
            too_big
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let mut sent = 0;
            while sent < packets.len() {
                {
                    let _burst = self.send_lock.lock().unwrap_or_else(|e| e.into_inner());
                    while let Some((packet, destination)) = packets.get(sent) {
                        match self.socket.try_send_to(packet.as_ref(), *destination) {
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            _ => sent += 1,
                        }
                    }
                }
                if sent < packets.len() && self.socket.writable().await.is_err() {
                    return None;
                }
            }
            None
        }
    }

    /// Wait for datagrams and append each to `out` as
    /// `(buffer index, range in buffer, source)`. `bufs` holds one or more
    /// receive buffers of [`DATAGRAM_SIZE`] bytes; with GRO one buffer can
    /// carry several datagrams. Elsewhere each buffer carries one datagram:
    /// the first read waits and the datagrams already waiting fill the rest.
    pub(crate) async fn recv_batch(
        &self,
        bufs: &mut [Vec<u8>],
        out: &mut Vec<(usize, std::ops::Range<usize>, SocketAddr)>,
    ) -> io::Result<()> {
        out.clear();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let mut meta = [quinn_udp::RecvMeta::default(); quinn_udp::BATCH_SIZE];
            let count = bufs.len().min(meta.len());
            let received = self
                .socket
                .async_io(tokio::io::Interest::READABLE, || {
                    let mut rest = bufs[..count].iter_mut();
                    let mut slices: [io::IoSliceMut<'_>; quinn_udp::BATCH_SIZE] =
                        std::array::from_fn(|_| match rest.next() {
                            Some(buf) => io::IoSliceMut::new(buf),
                            None => io::IoSliceMut::new(&mut []),
                        });
                    self.state.recv(
                        (&self.socket).into(),
                        &mut slices[..count],
                        &mut meta[..count],
                    )
                })
                .await?;
            for (index, meta) in meta[..received].iter().enumerate() {
                let stride = meta.stride.max(1);
                let mut start = 0;
                while start < meta.len {
                    let end = (start + stride).min(meta.len);
                    out.push((index, start..end, meta.addr));
                    start = end;
                }
            }
            Ok(())
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            receive_waiting(&self.socket, bufs, out).await
        }
    }

    /// Receive buffers the loop should hold once stream traffic arrives.
    pub(crate) fn batch_buffers() -> usize {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // 8 x 64 KiB: room for GRO bursts without 2 MiB per socket.
            quinn_udp::BATCH_SIZE.min(8)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            // No receive offload here, so one datagram for each buffer: 16
            // buffers of 64 KiB take a burst of 16 in one wake.
            16
        }
    }
}

/// Wait for one datagram, then take the datagrams that already wait in
/// `socket`, one for each further buffer of `bufs`.
///
/// A failure of the first read is returned: nothing was taken. An error on a
/// later buffer (including `WouldBlock`, which means that nothing waits) ends
/// the call with `Ok(())` so that the datagrams already taken reach the
/// caller; an error that stays shows again at the next wait on the first
/// buffer.
#[cfg(any(test, not(any(target_os = "linux", target_os = "android"))))]
async fn receive_waiting(
    socket: &tokio::net::UdpSocket,
    bufs: &mut [Vec<u8>],
    out: &mut Vec<(usize, std::ops::Range<usize>, SocketAddr)>,
) -> io::Result<()> {
    // The caller keeps `bufs` non-empty, as the read of `bufs[0]` required;
    // a missing buffer still takes nothing and succeeds.
    let Some((first, rest)) = bufs.split_first_mut() else {
        return Ok(());
    };
    let (len, addr) = socket.recv_from(first.as_mut_slice()).await?;
    out.push((0, 0..len, addr));
    for (index, buf) in rest.iter_mut().enumerate() {
        // Stop at the first error, also `WouldBlock` (nothing waits): the
        // datagrams already taken must reach the caller, and an error that
        // stays shows again at the next wait on the first buffer.
        match socket.try_recv_from(buf.as_mut_slice()) {
            Ok((len, addr)) => out.push((index + 1, 0..len, addr)),
            Err(_) => break,
        }
    }
    Ok(())
}

/// Length of the GSO run at the front of `packets`: one destination, every
/// packet the size of the first except a shorter last one, within the
/// kernel's segment and byte limits.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn gso_run<P: AsRef<[u8]>>(packets: &[(P, SocketAddr)], max_segments: usize) -> usize {
    let (first, destination) = (packets[0].0.as_ref(), packets[0].1);
    let size = first.len();
    let limit = max_segments.min(GSO_MAX_BYTES / size.max(1)).max(1);
    let mut run = 1;
    while run < packets.len() && run < limit {
        let (packet, to) = &packets[run];
        let len = packet.as_ref().len();
        if *to != destination || len > size {
            break;
        }
        run += 1;
        if len < size {
            break;
        }
    }
    run
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::*;

    fn packets(sizes: &[usize], to: &[u16]) -> Vec<(Vec<u8>, SocketAddr)> {
        sizes
            .iter()
            .zip(to)
            .map(|(&n, &port)| (vec![0; n], SocketAddr::from(([127, 0, 0, 1], port))))
            .collect()
    }

    #[test]
    fn gso_runs_split_on_destination_size_and_limits() {
        // A shorter packet ends a run; a longer one starts a new run.
        assert_eq!(
            gso_run(&packets(&[1200, 1200, 800, 1200], &[1, 1, 1, 1]), 64),
            3
        );
        assert_eq!(gso_run(&packets(&[800, 1200], &[1, 1]), 64), 1);
        // Another destination ends a run.
        assert_eq!(gso_run(&packets(&[1200, 1200, 1200], &[1, 1, 2]), 64), 2);
        // Segment and byte limits.
        assert_eq!(gso_run(&packets(&[1200; 10], &[1; 10]), 4), 4);
        assert_eq!(gso_run(&packets(&[1500; 60], &[1; 60]), 64), 43);
    }

    /// A limit that turns a lost datagram into a failure instead of a hang.
    const LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

    /// Send `sent` from `sender`, then read at `receiver` until every packet
    /// has arrived; return each payload with its source in arrival order.
    async fn exchanged(
        sender: &Udp,
        receiver: &Udp,
        sent: &[(Vec<u8>, SocketAddr)],
    ) -> Vec<(Vec<u8>, SocketAddr)> {
        sender.send_batch(sent).await;
        let mut bufs = vec![vec![0; DATAGRAM_SIZE]; Udp::batch_buffers()];
        let mut out = Vec::new();
        let mut got = Vec::with_capacity(sent.len());
        while got.len() < sent.len() {
            tokio::time::timeout(LIMIT, receiver.recv_batch(&mut bufs, &mut out))
                .await
                .expect("a datagram of the batch did not arrive")
                .unwrap();
            for (index, range, addr) in &out {
                got.push((bufs[*index][range.clone()].to_vec(), *addr));
            }
        }
        got
    }

    #[tokio::test]
    async fn batch_send_arrives_as_separate_datagrams() {
        // Catches a run joined into one datagram or reordered, and a received
        // datagram labelled with a source other than the sender's address.
        let a = Udp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let b = Udp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let source = a.local_addr().unwrap();
        let to = b.local_addr().unwrap();
        let sent: Vec<(Vec<u8>, SocketAddr)> = (0..10u8)
            .map(|i| (vec![i; if i == 9 { 300 } else { 1200 }], to))
            .collect();
        let got = exchanged(&a, &b, &sent).await;
        for (_, addr) in &got {
            assert_eq!(*addr, source);
        }
        assert_eq!(
            got.into_iter()
                .map(|(payload, _)| payload)
                .collect::<Vec<_>>(),
            sent.into_iter()
                .map(|(payload, _)| payload)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn the_batch_arrives_whole_over_ipv6_loopback() {
        // Catches a GSO send and a receive that work over IPv4 loopback but
        // lose, join or reorder the datagrams of a batch on an IPv6 socket,
        // and a source address reported for the wrong family.
        let host = "[::1]:0";
        let a = match Udp::bind(host.parse().unwrap()).await {
            Ok(socket) => socket,
            Err(error) => {
                eprintln!("skipping the IPv6 check: {host} cannot be bound ({error})");
                return;
            }
        };
        let b = match Udp::bind(host.parse().unwrap()).await {
            Ok(socket) => socket,
            Err(error) => {
                eprintln!("skipping the IPv6 check: {host} cannot be bound ({error})");
                return;
            }
        };
        let source = a.local_addr().unwrap();
        let to = b.local_addr().unwrap();
        let sent: Vec<(Vec<u8>, SocketAddr)> = (0..10u8)
            .map(|i| (vec![i; if i == 9 { 300 } else { 1200 }], to))
            .collect();
        let got = exchanged(&a, &b, &sent).await;
        for (_, addr) in &got {
            assert_eq!(*addr, source);
        }
        assert_eq!(
            got.into_iter()
                .map(|(payload, _)| payload)
                .collect::<Vec<_>>(),
            sent.into_iter()
                .map(|(payload, _)| payload)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn a_sixty_thousand_byte_datagram_in_a_batch_arrives_whole() {
        // Catches a run that cuts the large datagram at a segment or byte
        // limit, or drops it after `EMSGSIZE`, and a datagram before or after
        // it that is lost or reordered.
        let a = Udp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let b = Udp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let to = b.local_addr().unwrap();
        let sent: Vec<(Vec<u8>, SocketAddr)> = vec![
            (vec![1; 1_200], to),
            (vec![2; 60_000], to),
            (vec![3; 1_200], to),
        ];
        let got = exchanged(&a, &b, &sent).await;
        assert_eq!(
            got.into_iter()
                .map(|(payload, _)| payload)
                .collect::<Vec<_>>(),
            sent.into_iter()
                .map(|(payload, _)| payload)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn the_send_buffer_is_kept_for_the_next_burst() {
        // Catches a buffer made new for every `send_batch` call instead of
        // kept for the thread, which pays one allocation and one free for
        // each burst.
        let a = Udp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let b = Udp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        if a.state.max_gso_segments() < 20 {
            eprintln!("skipping: this kernel does not join a burst into one GSO send");
            return;
        }
        let to = b.local_addr().unwrap();
        let burst: Vec<(Vec<u8>, SocketAddr)> = (0..20).map(|_| (vec![0; 1_200], to)).collect();
        a.send_batch(&burst).await;
        let (first_pointer, first_capacity) = send_scratch();
        assert!(
            first_capacity >= 24_000,
            "a 20-packet burst of 1,200 bytes needs 24,000 bytes, got {first_capacity}"
        );
        a.send_batch(&burst).await;
        let (second_pointer, second_capacity) = send_scratch();
        assert_eq!(second_capacity, first_capacity);
        assert_eq!(second_pointer, first_pointer);
    }

    #[tokio::test]
    async fn the_first_burst_reserves_its_run_in_one_step() {
        // Catches a buffer that grows step by step while the packets of the
        // first burst are appended instead of being reserved at once: 20
        // packets of 1,200 bytes appended one by one to an empty `Vec` that
        // doubles end at 38,400 bytes; one reservation for the run ends at
        // 24,000.
        let a = Udp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let b = Udp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        if a.state.max_gso_segments() < 20 {
            eprintln!("skipping: this kernel does not join a burst into one GSO send");
            return;
        }
        let to = b.local_addr().unwrap();
        let burst: Vec<(Vec<u8>, SocketAddr)> = (0..20).map(|_| (vec![0; 1_200], to)).collect();
        a.send_batch(&burst).await;
        let (_, capacity) = send_scratch();
        assert!(
            capacity >= 24_000,
            "the buffer is smaller than the burst that filled it: {capacity}"
        );
        assert!(
            capacity < 38_400,
            "the first burst grew the buffer step by step past its 24,000-byte run: {capacity}"
        );
    }
}

/// [`receive_waiting`] on loopback, compiled on every system: the module
/// above needs a Linux or Android socket for `send_batch` and `recv_batch`.
#[cfg(test)]
mod receive_waiting_tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// A limit that turns a wrong version into a failure instead of a hang.
    const LIMIT: Duration = Duration::from_secs(5);

    async fn bind() -> tokio::net::UdpSocket {
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    #[tokio::test]
    async fn a_burst_that_waits_is_read_in_one_call() {
        // Catches a call that returns only the first datagram, one that loses
        // an empty datagram, and one that labels a datagram with the wrong
        // buffer index.
        let receiver = bind().await;
        let sender = bind().await;
        let from = sender.local_addr().unwrap();
        let to = receiver.local_addr().unwrap();
        let sent: Vec<Vec<u8>> = [1200usize, 0, 1, 9000, 1200]
            .into_iter()
            .enumerate()
            .map(|(fill, len)| vec![fill as u8 + 1; len])
            .collect();
        for datagram in &sent {
            sender.send_to(datagram, to).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut bufs = vec![vec![0; DATAGRAM_SIZE]; 8];
        let mut out = Vec::new();
        tokio::time::timeout(LIMIT, receive_waiting(&receiver, &mut bufs, &mut out))
            .await
            .expect("receive_waiting timed out")
            .unwrap();

        assert_eq!(out.len(), sent.len());
        for (index, ((buffer, range, addr), datagram)) in out.iter().zip(&sent).enumerate() {
            assert_eq!(*buffer, index);
            assert_eq!(*range, 0..datagram.len());
            assert_eq!(*addr, from);
            assert_eq!(&bufs[*buffer][range.clone()], datagram.as_slice());
        }
    }

    #[tokio::test]
    async fn a_burst_larger_than_the_buffers_takes_two_calls() {
        // Catches a read past the last buffer, and a datagram lost or repeated
        // at the border between two calls.
        let receiver = bind().await;
        let sender = bind().await;
        let to = receiver.local_addr().unwrap();
        let sent: Vec<Vec<u8>> = (0..6u8)
            .map(|fill| vec![fill + 1; 1000 + usize::from(fill)])
            .collect();
        for datagram in &sent {
            sender.send_to(datagram, to).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut bufs = vec![vec![0; DATAGRAM_SIZE]; 4];
        let mut out = Vec::new();
        tokio::time::timeout(LIMIT, receive_waiting(&receiver, &mut bufs, &mut out))
            .await
            .expect("first receive_waiting timed out")
            .unwrap();
        assert_eq!(out.len(), 4);
        let mut got: Vec<Vec<u8>> = out
            .iter()
            .map(|(buffer, range, _)| bufs[*buffer][range.clone()].to_vec())
            .collect();
        out.clear();

        tokio::time::timeout(LIMIT, receive_waiting(&receiver, &mut bufs, &mut out))
            .await
            .expect("second receive_waiting timed out")
            .unwrap();
        assert_eq!(out.len(), 2);
        got.extend(
            out.iter()
                .map(|(buffer, range, _)| bufs[*buffer][range.clone()].to_vec()),
        );
        assert_eq!(got, sent);
    }

    #[tokio::test]
    async fn one_buffer_reads_one_datagram() {
        // Catches an index outside the buffers when the socket holds only one.
        let receiver = bind().await;
        let sender = bind().await;
        let to = receiver.local_addr().unwrap();
        let sent = [vec![1u8; 100], vec![2u8; 200]];
        for datagram in &sent {
            sender.send_to(datagram, to).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut bufs = vec![vec![0; DATAGRAM_SIZE]; 1];
        let mut out = Vec::new();
        for datagram in sent {
            tokio::time::timeout(LIMIT, receive_waiting(&receiver, &mut bufs, &mut out))
                .await
                .expect("receive_waiting timed out")
                .unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].0, 0);
            assert_eq!(&bufs[0][out[0].1.clone()], datagram.as_slice());
            out.clear();
        }
    }

    #[tokio::test]
    async fn the_call_waits_for_the_first_datagram() {
        // Catches a call that returns with no datagram, and one whose loop
        // does not wait for the first datagram.
        let receiver = bind().await;
        let sender = bind().await;
        let to = receiver.local_addr().unwrap();
        let mut bufs = vec![vec![0; DATAGRAM_SIZE]; 4];
        let mut out = Vec::new();

        let started = Instant::now();
        let send = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            sender.send_to(&[42u8; 100], to).await.unwrap();
        });
        tokio::time::timeout(LIMIT, receive_waiting(&receiver, &mut bufs, &mut out))
            .await
            .expect("receive_waiting timed out")
            .unwrap();
        send.await.unwrap();

        assert!(started.elapsed() >= Duration::from_millis(25));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 0);
    }
}
