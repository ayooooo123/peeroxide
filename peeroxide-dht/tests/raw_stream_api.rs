#![deny(clippy::all)]

//! `HyperDhtHandle::create_raw_stream` / `connect_raw_stream`, mirroring Node
//! `dht.createRawStream({ firewall })` and `HyperDHT.connectRawStream`.
//!
//! - A raw stream created with a firewall hook accepts pre-connect packets
//!   only when the hook agrees, exactly as `private-overlay.js` filters the
//!   data circuit against its control connection's remote address.
//! - The DHT owns the stream: `suspend()` closes it even though the caller
//!   still holds the [`RawStream`].

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide_dht::hyperdht::{self, HyperDhtConfig, RawStreamOptions};

const TEST_TIMEOUT: Duration = Duration::from_secs(20);

fn local_config() -> HyperDhtConfig {
    let mut config = HyperDhtConfig::default();
    config.dht.host = "127.0.0.1".to_string();
    config.dht.port = 0;
    config.dht.ephemeral = Some(false);
    config.dht.firewalled = false;
    config.dht.quick_firewall = false;
    config
}

#[tokio::test]
async fn firewall_hook_accepts_the_first_packet_and_stream_moves_data() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let runtime = UdxRuntime::new().expect("runtime");
        let (_task, node, _events) = hyperdht::spawn(&runtime, local_config())
            .await
            .expect("node");
        node.fully_bootstrapped().await.expect("bootstrapped");

        let primary = node
            .server_socket()
            .await
            .expect("socket")
            .expect("primary");
        let primary_addr = primary.local_addr().await.expect("addr");

        // The peer side: a plain UDX stream on its own socket.
        let peer_socket = runtime.create_socket().await.expect("peer socket");
        peer_socket
            .bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind");
        let peer_addr = peer_socket.local_addr().await.expect("peer addr");
        let peer_id = 4242;
        let peer = runtime.create_stream(peer_id).await.expect("peer stream");

        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = Arc::clone(&calls);
        let (hit_tx, mut hit_rx) = tokio::sync::mpsc::unbounded_channel();
        let expected = (peer_addr.ip(), peer_addr.port());
        let mut raw = node
            .create_raw_stream(
                &runtime,
                RawStreamOptions::new().with_firewall(move |_, port, host| {
                    hook_calls.fetch_add(1, Ordering::SeqCst);
                    if host == expected.0 && port == expected.1 {
                        let _ = hit_tx.send(());
                        false
                    } else {
                        true
                    }
                }),
            )
            .await
            .expect("raw stream");

        // The peer sends before the stream is connected: the packet reaches
        // the firewall hook, which accepts the source. The owner then arms
        // the peer id it learned out of band (private-overlay exchanges ids
        // over its control connection), and the retransmit is ACKed.
        peer.connect(&peer_socket, raw.id(), primary_addr)
            .await
            .expect("peer connect");
        let writer = tokio::spawn(async move { peer.write(b"pre-connect").await });
        hit_rx.recv().await.expect("firewall hook never fired");
        raw.connect(&primary, peer_id, peer_addr)
            .await
            .expect("late connect");
        writer.await.expect("writer task").expect("peer write");
        assert_eq!(
            raw.read().await.expect("read").as_deref(),
            Some(&b"pre-connect"[..])
        );
        assert!(calls.load(Ordering::SeqCst) >= 1);

        // The DHT owns the stream: suspend closes it under the caller.
        node.suspend().await.expect("suspend");
        let closed = tokio::time::timeout(Duration::from_secs(2), raw.read())
            .await
            .expect("raw stream outlived the suspend")
            .expect("read");
        assert!(closed.is_none());

        node.destroy().await.expect("destroy");
    })
    .await
    .expect("raw stream firewall test timed out");
}

/// Node semantics: the hook rejects with `true`. Only the named peer's
/// pre-connect data is queued; a stranger that sends first is dropped.
#[tokio::test]
async fn firewall_hook_rejects_a_stranger_and_accepts_the_named_peer() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let runtime = UdxRuntime::new().expect("runtime");
        let (_task, node, _events) = hyperdht::spawn(&runtime, local_config())
            .await
            .expect("node");
        node.fully_bootstrapped().await.expect("bootstrapped");

        let primary = node
            .server_socket()
            .await
            .expect("socket")
            .expect("primary");
        let primary_addr = primary.local_addr().await.expect("addr");

        // Two senders: a stranger that speaks first, then the named peer.
        let stranger_socket = runtime.create_socket().await.expect("stranger socket");
        stranger_socket
            .bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind");
        let stranger_addr = stranger_socket.local_addr().await.expect("addr");
        let stranger = runtime.create_stream(5555).await.expect("stranger stream");
        let stranger_abort = stranger.abort_handle();

        let peer_socket = runtime.create_socket().await.expect("peer socket");
        peer_socket
            .bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind");
        let peer_addr = peer_socket.local_addr().await.expect("addr");
        let peer_id = 4242;
        let peer = runtime.create_stream(peer_id).await.expect("peer stream");

        let (hit_tx, mut hit_rx) = tokio::sync::mpsc::unbounded_channel();
        let expected = (peer_addr.ip(), peer_addr.port());
        let mut raw = node
            .create_raw_stream(
                &runtime,
                RawStreamOptions::new().with_firewall(move |_, port, host| {
                    let _ = hit_tx.send((host, port));
                    // Node returns `true` to reject.
                    !(host == expected.0 && port == expected.1)
                }),
            )
            .await
            .expect("raw stream");

        // The stranger speaks first; its packet must not be queued.
        stranger
            .connect(&stranger_socket, raw.id(), primary_addr)
            .await
            .expect("stranger connect");
        let _stranger_write = tokio::spawn(async move {
            let _ = stranger.write(b"stranger").await;
        });
        wait_for_hook(&mut hit_rx, stranger_addr).await;

        // Then the named peer sends, still before the owner arms its id.
        peer.connect(&peer_socket, raw.id(), primary_addr)
            .await
            .expect("peer connect");
        let peer_write = tokio::spawn(async move { peer.write(b"peer").await });
        wait_for_hook(&mut hit_rx, peer_addr).await;

        raw.connect(&primary, peer_id, peer_addr)
            .await
            .expect("late connect");
        tokio::time::timeout(Duration::from_secs(2), peer_write)
            .await
            .expect("peer write never completed")
            .expect("writer task")
            .expect("peer write");
        assert_eq!(
            raw.read().await.expect("read").as_deref(),
            Some(&b"peer"[..])
        );

        stranger_abort.abort();
        node.destroy().await.expect("destroy");
    })
    .await
    .expect("raw stream firewall rejection test timed out");
}

/// Wait until the firewall hook reports a datagram from `addr`.
async fn wait_for_hook(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<(std::net::IpAddr, u16)>,
    addr: std::net::SocketAddr,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some((host, port)) = rx.recv().await {
            if host == addr.ip() && port == addr.port() {
                return;
            }
        }
        panic!("hook channel closed before {addr}");
    })
    .await
    .expect("firewall hook never saw the expected source");
}
