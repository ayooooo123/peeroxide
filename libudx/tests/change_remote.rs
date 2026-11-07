#![deny(clippy::all)]

//! `change_remote`: a stream relayed through a third party moves to a direct
//! path mid-transfer (hyperdht's relay-to-direct upgrade) without losing or
//! duplicating bytes, and the relay can go away once both sides moved.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{create_bound_socket, create_runtime, random_payload, with_timeout};
use libudx::{UdxRuntime, UdxSocket, UdxStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const A_ID: u32 = 1;
const B_ID: u32 = 2;
const RELAY_A_ID: u32 = 10;
const RELAY_B_ID: u32 = 20;

/// Two relay streams on one socket, bridged like a blind relay: each learns
/// its peer from the first packet and forwards to the other.
async fn relay(rt: &UdxRuntime) -> (UdxStream, UdxStream, UdxSocket, SocketAddr) {
    let (socket, addr) = create_bound_socket(rt).await;
    let to_a = rt.create_stream(RELAY_A_ID).await.expect("relay a");
    let to_b = rt.create_stream(RELAY_B_ID).await.expect("relay b");
    to_a.set_firewall_hook(&socket, A_ID, |_, _, _| true).expect("hook a");
    to_b.set_firewall_hook(&socket, B_ID, |_, _, _| true).expect("hook b");
    to_a.relay_to(&to_b).expect("relay a→b");
    to_b.relay_to(&to_a).expect("relay b→a");
    (to_a, to_b, socket, addr)
}

/// A (the initiator) learns B's direct address out of band and moves first;
/// B notices A's packets arriving on its direct socket through the firewall
/// hook, exactly how hyperdht's server side triggers `changeRemote`.
#[tokio::test]
async fn relayed_stream_moves_to_a_direct_path_mid_transfer() {
    let _ = tracing_subscriber::fmt::try_init();

    with_timeout(Duration::from_secs(60), async {
        let rt = create_runtime();
        let (relay_a, relay_b, _relay_socket, relay_addr) = relay(&rt).await;

        // Each side dials the relay from one socket and is reachable
        // directly on another (hyperdht: DHT socket vs holepunch socket).
        let (socket_a, _) = create_bound_socket(&rt).await;
        let (socket_a2, addr_a2) = create_bound_socket(&rt).await;
        let (socket_b, _) = create_bound_socket(&rt).await;
        let (socket_b2, addr_b2) = create_bound_socket(&rt).await;

        let stream_a = rt.create_stream(A_ID).await.expect("stream a");
        stream_a.connect(&socket_a, RELAY_A_ID, relay_addr).await.expect("connect a");

        let (direct_tx, mut direct_rx) = tokio::sync::mpsc::unbounded_channel::<(UdxSocket, SocketAddr)>();
        let stream_b = rt.create_stream(B_ID).await.expect("stream b");
        stream_b
            .set_firewall_hook(&socket_b, RELAY_B_ID, move |socket, port, ip| {
                let _ = direct_tx.send((socket.clone(), SocketAddr::new(ip, port)));
                true
            })
            .expect("hook b");
        stream_b.listen_on(&socket_b2).expect("listen b2");
        stream_b.connect(&socket_b, RELAY_B_ID, relay_addr).await.expect("connect b");

        // Both relay legs learn their peer before the bulk starts.
        stream_b.write(b"hello").await.expect("b hello");
        stream_a.write(b"hello").await.expect("a hello");

        let a_remote = stream_a.remote_handle();
        let b_remote = stream_b.remote_handle();
        let mut a = stream_a.into_async_stream();
        let mut b = stream_b.into_async_stream();

        let payload = random_payload(3 * 1024 * 1024);
        let expected = payload.clone();
        let reader = tokio::spawn(async move {
            let mut hello = [0u8; 5];
            b.read_exact(&mut hello).await.expect("read hello");
            let mut got = vec![0u8; expected.len()];
            b.read_exact(&mut got).await.expect("read payload");
            assert!(got == expected, "payload differs after the migration");
            b
        });

        let mut hello = [0u8; 5];
        a.read_exact(&mut hello).await.expect("read hello");
        assert_eq!(hello, *b"hello");

        // First third crosses the relay; some of it is still in flight when
        // A moves to B's direct address, so the change completes deferred.
        let third = payload.len() / 3;
        a.write_all(&payload[..third]).await.expect("write via relay");
        tokio::time::sleep(Duration::from_millis(5)).await;
        a_remote
            .change_remote(&socket_a2, B_ID, addr_b2)
            .await
            .expect("a change_remote");
        a.write_all(&payload[third..2 * third]).await.expect("write during move");

        // B's hook saw A on the direct socket (not the relay packets on its
        // own socket) and follows.
        let (socket, addr) = direct_rx.recv().await.expect("b hook");
        assert_eq!(addr, addr_a2);
        assert_eq!(socket.local_addr().await.unwrap(), addr_b2);
        b_remote.change_remote(&socket, A_ID, addr).await.expect("b change_remote");
        a_remote.remote_observed().await.expect("a observed b directly");

        // The relay is gone; the rest must go direct.
        drop(relay_a);
        drop(relay_b);
        a.write_all(&payload[2 * third..]).await.expect("write direct");
        a.flush().await.expect("flush");

        let _b = reader.await.expect("reader");
    })
    .await;
}

#[tokio::test]
async fn change_remote_rejects_unconnected_and_bad_targets() {
    with_timeout(Duration::from_secs(10), async {
        let rt = create_runtime();
        let (socket, addr) = create_bound_socket(&rt).await;
        let (socket_other, _) = create_bound_socket(&rt).await;

        let idle = rt.create_stream(7).await.expect("idle stream");
        assert!(idle.remote_handle().change_remote(&socket, 8, addr).await.is_err());

        let (a, _b, socket_a, _socket_b) = common::create_connected_pair(&rt).await;
        let remote = a.remote_handle();
        let zero_port: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(remote.change_remote(&socket_a, B_ID, zero_port).await.is_err());
        // Nothing in flight: completes at once.
        remote.change_remote(&socket_other, B_ID, addr).await.expect("immediate change");
    })
    .await;
}

/// With data in flight on a slow path, the change completes only once that
/// data is ACKed (C defers until `seq_on_remote_changed` is acked).
#[tokio::test]
async fn change_remote_waits_for_in_flight_packets() {
    with_timeout(Duration::from_secs(30), async {
        let rt = create_runtime();
        let (socket_a, addr_a) = create_bound_socket(&rt).await;
        let (socket_b, addr_b) = create_bound_socket(&rt).await;
        let delay = Duration::from_millis(100);
        let proxy = common::proxy::UdpProxy::start(
            addr_a,
            addr_b,
            common::proxy::ProxyConfig::symmetric(common::proxy::DirectionConfig {
                delay,
                ..Default::default()
            }),
        )
        .await;

        let stream_a = rt.create_stream(A_ID).await.expect("stream a");
        let mut stream_b = rt.create_stream(B_ID).await.expect("stream b");
        stream_a.connect(&socket_a, B_ID, proxy.addr_for_a).await.expect("connect a");
        stream_b.connect(&socket_b, A_ID, proxy.addr_for_b).await.expect("connect b");

        let payload = random_payload(64 * 1024);
        let a_remote = stream_a.remote_handle();
        let sent = payload.clone();
        let writer = tokio::spawn(async move {
            stream_a.write(&sent).await.expect("write");
            stream_a
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let started = std::time::Instant::now();
        a_remote.change_remote(&socket_a, B_ID, addr_b).await.expect("change");
        assert!(
            started.elapsed() >= delay,
            "change completed in {:?} with packets still on the slow path",
            started.elapsed()
        );

        let mut got = Vec::new();
        while got.len() < payload.len() {
            got.extend(stream_b.read().await.expect("read").expect("eof"));
        }
        assert!(got == payload);
        let _a = writer.await.expect("writer");
        proxy.stop().await;
    })
    .await;
}
