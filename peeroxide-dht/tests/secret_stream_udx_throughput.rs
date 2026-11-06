//! SecretStream over UDX on a simulated 50 ms RTT: frames must pipeline.
//!
//! A `flush()` after every frame makes each `SecretStream::write` wait for
//! the peer's UDX ACK, so a bulk sender gets one frame per round trip.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use libudx::{UdxRuntime, UdxSocket};
use peeroxide_dht::noise;
use peeroxide_dht::secret_stream::SecretStream;

/// Forward datagrams from `listen` to `dest` after `delay`, one task per packet.
async fn delay_proxy(dest: SocketAddr, delay: Duration) -> SocketAddr {
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind proxy"));
    let addr = sock.local_addr().expect("proxy addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((len, _)) = sock.recv_from(&mut buf).await {
            let packet = buf[..len].to_vec();
            let out = Arc::clone(&sock);
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = out.send_to(&packet, dest).await;
            });
        }
    });
    addr
}

async fn bound(runtime: &UdxRuntime) -> (UdxSocket, SocketAddr) {
    let sock = runtime.create_socket().await.expect("socket");
    sock.bind("127.0.0.1:0".parse().unwrap()).await.expect("bind");
    let addr = sock.local_addr().await.expect("local addr");
    (sock, addr)
}

#[tokio::test(flavor = "multi_thread")]
async fn bulk_frames_pipeline_over_simulated_rtt() {
    let _ = tracing_subscriber::fmt::try_init();
    let delay = Duration::from_millis(25);

    tokio::time::timeout(Duration::from_secs(60), async {
        let runtime = UdxRuntime::new().expect("runtime");
        let (sock_a, addr_a) = bound(&runtime).await;
        let (sock_b, addr_b) = bound(&runtime).await;
        let via_to_b = delay_proxy(addr_b, delay).await;
        let via_to_a = delay_proxy(addr_a, delay).await;

        let stream_a = runtime.create_stream(1).await.expect("stream a");
        let stream_b = runtime.create_stream(2).await.expect("stream b");
        stream_a.connect(&sock_a, 2, via_to_b).await.expect("connect a");
        stream_b.connect(&sock_b, 1, via_to_a).await.expect("connect b");

        let (client, server) = tokio::join!(
            SecretStream::new(true, stream_a.into_async_stream(), noise::generate_keypair()),
            SecretStream::new(false, stream_b.into_async_stream(), noise::generate_keypair()),
        );
        let mut client = client.expect("client handshake");
        let mut server = server.expect("server handshake");

        let frames = 256;
        let frame = vec![0xABu8; 16 * 1024];
        let started = Instant::now();
        let writer = tokio::spawn({
            let frame = frame.clone();
            async move {
                for _ in 0..frames {
                    client.write(&frame).await.expect("write frame");
                }
                client.shutdown().await.expect("shutdown");
                client
            }
        });

        let mut received = 0usize;
        while let Some(msg) = server.read().await.expect("read frame") {
            assert_eq!(msg.len(), frame.len());
            received += msg.len();
        }
        let elapsed = started.elapsed();
        let _client = writer.await.expect("writer panicked");

        let mib = received as f64 / (1024.0 * 1024.0);
        eprintln!(
            "secret-stream over udx, {} ms RTT: {mib:.0} MiB in {elapsed:?} ({:.1} MiB/s)",
            2 * delay.as_millis(),
            mib / elapsed.as_secs_f64()
        );
        assert_eq!(received, frames * frame.len());
        // One frame per round trip would need 256 * 50 ms = 12.8 s.
        assert!(elapsed < Duration::from_secs(5), "frames are not pipelined: {elapsed:?}");
    })
    .await
    .expect("test timed out");
}
