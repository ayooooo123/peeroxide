//! The OS UDP socket behind a [`super::socket::UdxSocket`].
//!
//! On Linux and Android a paced burst to one peer leaves in one `sendmsg`
//! (UDP GSO) and the receive loop reads many datagrams per call (`recvmmsg`
//! with GRO): a stream's packets are almost all the same size, so this turns
//! one system call per packet into one per burst. Other platforms send and
//! receive one datagram per call.

use std::io;
use std::net::SocketAddr;

/// Largest UDP payload the kernel accepts in one GSO send.
#[cfg(any(target_os = "linux", target_os = "android"))]
const GSO_MAX_BYTES: usize = 65_507;

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
    /// retransmits what the network loses.
    pub(crate) async fn send_batch(&self, packets: &[(Vec<u8>, SocketAddr)]) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let mut scratch = Vec::new();
            let mut rest = packets;
            while !rest.is_empty() {
                let run = gso_run(rest, self.state.max_gso_segments());
                let (batch, tail) = rest.split_at(run);
                rest = tail;
                let destination = batch[0].1;
                if run == 1 {
                    let _ = self.socket.send_to(&batch[0].0, destination).await;
                    continue;
                }
                scratch.clear();
                for (packet, _) in batch {
                    scratch.extend_from_slice(packet);
                }
                let transmit = quinn_udp::Transmit {
                    destination,
                    ecn: None,
                    contents: &scratch,
                    segment_size: Some(batch[0].0.len()),
                    src_ip: None,
                };
                let _ = self
                    .socket
                    .async_io(tokio::io::Interest::WRITABLE, || {
                        self.state.send((&self.socket).into(), &transmit)
                    })
                    .await;
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let mut sent = 0;
            while sent < packets.len() {
                {
                    let _burst = self.send_lock.lock().unwrap_or_else(|e| e.into_inner());
                    while let Some((packet, destination)) = packets.get(sent) {
                        match self.socket.try_send_to(packet, *destination) {
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            _ => sent += 1,
                        }
                    }
                }
                if sent < packets.len() && self.socket.writable().await.is_err() {
                    return;
                }
            }
        }
    }

    /// Wait for datagrams and append each to `out` as `(range in buffer, source)`.
    /// `bufs` holds one or more receive buffers of [`DATAGRAM_SIZE`] bytes; with
    /// GRO one buffer can carry several datagrams.
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
                    let mut slices: Vec<io::IoSliceMut<'_>> = bufs[..count]
                        .iter_mut()
                        .map(|b| io::IoSliceMut::new(b))
                        .collect();
                    self.state
                        .recv((&self.socket).into(), &mut slices, &mut meta[..count])
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
            let (len, addr) = self.socket.recv_from(&mut bufs[0]).await?;
            out.push((0, 0..len, addr));
            Ok(())
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
            1
        }
    }
}

/// Length of the GSO run at the front of `packets`: one destination, every
/// packet the size of the first except a shorter last one, within the
/// kernel's segment and byte limits.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn gso_run(packets: &[(Vec<u8>, SocketAddr)], max_segments: usize) -> usize {
    let (first, destination) = (&packets[0].0, packets[0].1);
    let size = first.len();
    let limit = max_segments.min(GSO_MAX_BYTES / size.max(1)).max(1);
    let mut run = 1;
    while run < packets.len() && run < limit {
        let (packet, to) = &packets[run];
        if *to != destination || packet.len() > size {
            break;
        }
        run += 1;
        if packet.len() < size {
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

    #[tokio::test]
    async fn batch_send_arrives_as_separate_datagrams() {
        let a = Udp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let b = Udp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let to = b.local_addr().unwrap();
        let sent: Vec<(Vec<u8>, SocketAddr)> = (0..10u8)
            .map(|i| (vec![i; if i == 9 { 300 } else { 1200 }], to))
            .collect();
        a.send_batch(&sent).await;
        let mut bufs = vec![vec![0; DATAGRAM_SIZE]; Udp::batch_buffers()];
        let mut got = Vec::new();
        let mut out = Vec::new();
        while got.len() < sent.len() {
            b.recv_batch(&mut bufs, &mut out).await.unwrap();
            for (index, range, _) in &out {
                got.push(bufs[*index][range.clone()].to_vec());
            }
        }
        assert_eq!(got, sent.into_iter().map(|(p, _)| p).collect::<Vec<_>>());
    }
}
