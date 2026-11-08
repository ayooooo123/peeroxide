use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

pub(super) const BATCH_SIZE: usize = 8;
pub(super) const DATAGRAM_SIZE: usize = 65536;

#[cfg(any(target_os = "linux", target_os = "android"))]
static SOCKET_STATE: std::sync::LazyLock<quinn_udp::UdpSocketState> =
    std::sync::LazyLock::new(quinn_udp::UdpSocketState::new);
#[cfg(any(target_os = "linux", target_os = "android"))]
static CAPABILITIES: std::sync::LazyLock<quinn_udp::UdpState> =
    std::sync::LazyLock::new(quinn_udp::UdpState::new);

pub(super) async fn send_batch(socket: &UdpSocket, packets: Vec<(Vec<u8>, SocketAddr)>) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut packets = packets.into_iter();
        loop {
            let mut count = 0;
            let transmits: [quinn_udp::Transmit; BATCH_SIZE] = std::array::from_fn(|_| {
                let (contents, destination) = match packets.next() {
                    Some((data, destination)) => {
                        count += 1;
                        (bytes::Bytes::from(data), destination)
                    }
                    None => (bytes::Bytes::new(), SocketAddr::from(([0, 0, 0, 0], 0))),
                };
                quinn_udp::Transmit {
                    destination,
                    contents,
                    ecn: None,
                    segment_size: None,
                    src_ip: None,
                }
            });
            if count == 0 {
                break;
            }
            let mut sent = 0;
            while sent < count {
                let result = socket
                    .async_io(tokio::io::Interest::WRITABLE, || {
                        SOCKET_STATE.send(socket.into(), &CAPABILITIES, &transmits[sent..count])
                    })
                    .await;
                match result {
                    Ok(0) | Err(_) => {
                        for packet in &transmits[sent..count] {
                            let _ = socket.send_to(&packet.contents, packet.destination).await;
                        }
                        break;
                    }
                    Ok(count) => sent += count,
                }
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    for (packet, addr) in packets {
        // Darwin's *_msg_x ABI is private; Tokio's ready path uses one sendto.
        let _ = socket.send_to(&packet, addr).await;
    }
}

pub(super) async fn recv_batch(
    socket: &UdpSocket,
    buffers: &mut [Vec<u8>],
    packets: &mut [(usize, SocketAddr); BATCH_SIZE],
) -> io::Result<usize> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if buffers.len() > 1 {
        let mut metadata = [quinn_udp::RecvMeta::default(); BATCH_SIZE];
        let result = socket
            .async_io(tokio::io::Interest::READABLE, || {
                let count = buffers.len();
                let mut buffers = buffers.iter_mut();
                let mut slices: [io::IoSliceMut<'_>; BATCH_SIZE] = std::array::from_fn(|_| {
                    buffers.next().map_or_else(
                        || io::IoSliceMut::new(&mut []),
                        |buffer| io::IoSliceMut::new(buffer),
                    )
                });
                // Do not configure the socket: GRO/ECN/fragmentation options stay unchanged.
                SOCKET_STATE.recv(socket.into(), &mut slices[..count], &mut metadata)
            })
            .await;
        if let Ok(count) = result {
            for (packet, meta) in packets.iter_mut().zip(metadata).take(count) {
                *packet = (meta.len, meta.addr);
            }
            return Ok(count);
        }
    }
    packets[0] = socket.recv_from(&mut buffers[0]).await?;
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn batches_preserve_datagrams_and_source_addresses() {
        for host in ["127.0.0.1:0", "[::1]:0"] {
            let sender = UdpSocket::bind(host).await.unwrap();
            let receiver = UdpSocket::bind(host).await.unwrap();
            let source = sender.local_addr().unwrap();
            let destination = receiver.local_addr().unwrap();
            let packets: Vec<_> = (0..BATCH_SIZE)
                .map(|index| (vec![index as u8; index * 200], destination))
                .collect();
            send_batch(&sender, packets.clone()).await;
            let mut buffers = (0..BATCH_SIZE)
                .map(|_| vec![0; DATAGRAM_SIZE])
                .collect::<Vec<_>>();
            let mut received = [(0, destination); BATCH_SIZE];
            let mut index = 0;
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while index < packets.len() {
                    let count = recv_batch(&receiver, &mut buffers, &mut received)
                        .await
                        .unwrap();
                    for (offset, &(len, addr)) in received[..count].iter().enumerate() {
                        assert_eq!(addr, source);
                        assert_eq!(&buffers[offset][..len], packets[index].0);
                        index += 1;
                    }
                }
                // Darwin limits UDP sends to 9 KiB by default.
                let jumbo_len = if cfg!(any(target_os = "linux", target_os = "android")) {
                    60_000
                } else {
                    8_000
                };
                let jumbo = vec![42; jumbo_len];
                send_batch(&sender, vec![(jumbo.clone(), destination)]).await;
                assert_eq!(
                    recv_batch(&receiver, &mut buffers, &mut received)
                        .await
                        .unwrap(),
                    1
                );
                assert_eq!(&buffers[0][..received[0].0], jumbo);
            })
            .await
            .unwrap();
        }
    }
}
