//! Connection keep-alive over real UDX streams, Rust to Rust.
//!
//! hyperdht gives every connection `keepAlive: dht.connectionKeepAlive`
//! (5000 ms by default): an idle secret stream writes one empty encrypted
//! message per interval, and every write pushes the next one back. These
//! tests use a short interval through `HyperDhtConfig::connection_keep_alive`.
//!
//! - `idle_connection_sends_keep_alives_and_writes_refresh_them`: both sides
//!   of an idle connection send an empty message about every interval, the
//!   reader never sees them, and a side that keeps writing sends none.
//! - `disabled_keep_alive_sends_nothing`: `connection_keep_alive: None`
//!   (Node `connectionKeepAlive: false`) keeps an idle connection silent.

use std::net::SocketAddr;
use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide_dht::hyperdht::{
    HyperDhtConfig, HyperDhtError, HyperDhtHandle, KeyPair, PeerConnection, ServerConfig, spawn,
};
use peeroxide_dht::hyperdht_messages::FIREWALL_UNKNOWN;
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);
const INTERVAL: Duration = Duration::from_millis(600);
/// 3-byte length + 1-byte tag + 16-byte MAC around an empty payload.
const KEEP_ALIVE_FRAME: u64 = 20;

struct Node {
    _task: tokio::task::JoinHandle<Result<(), HyperDhtError>>,
    handle: HyperDhtHandle,
    runtime: UdxRuntime,
    events: Option<tokio::sync::mpsc::UnboundedReceiver<peeroxide_dht::hyperdht::ServerEvent>>,
}

async fn node(keep_alive: Option<Duration>) -> Result<Node, HyperDhtError> {
    let mut config = HyperDhtConfig::default();
    config.dht.host = "127.0.0.1".to_string();
    config.dht.ephemeral = Some(false);
    config.dht.firewalled = false;
    config.connection_keep_alive = keep_alive;
    let runtime = UdxRuntime::new()?;
    let (task, handle, events) = spawn(&runtime, config).await?;
    Ok(Node {
        _task: task,
        handle,
        runtime,
        events: Some(events),
    })
}

/// A connected pair: (client side, server side).
async fn connect(
    keep_alive: Option<Duration>,
) -> Result<(Node, Node, PeerConnection, PeerConnection), Box<dyn std::error::Error>> {
    let mut server_node = node(keep_alive).await?;
    let client_node = node(keep_alive).await?;
    let server_keys = KeyPair::generate();
    let mut server = server_node.handle.create_server(
        &server_node.runtime,
        ServerConfig::new(server_keys.clone(), FIREWALL_UNKNOWN),
        server_node.events.take().expect("events"),
    );
    server.listen(&server_keys).await?;
    let address = server.address().expect("address");
    let client = client_node
        .handle
        .connect_to(
            &KeyPair::generate(),
            server_keys.public_key,
            SocketAddr::new(address.host.parse()?, address.port),
            &client_node.runtime,
        )
        .await?;
    let accepted = server.accept().await.ok_or("no accepted connection")?;
    // The server handle owns the accept loop; keep it running.
    tokio::spawn(async move {
        let _server = server;
        std::future::pending::<()>().await
    });
    Ok((server_node, client_node, client, accepted))
}

/// Keep a read pending on both sides for `duration`, as a Protomux owner
/// does; neither side may deliver a message.
async fn idle(client: &mut PeerConnection, server: &mut PeerConnection, duration: Duration) {
    let (a, b) = tokio::join!(
        timeout(duration, client.stream.read()),
        timeout(duration, server.stream.read()),
    );
    assert!(a.is_err(), "client read returned {a:?}");
    assert!(b.is_err(), "server read returned {b:?}");
}

#[tokio::test]
async fn idle_connection_sends_keep_alives_and_writes_refresh_them() {
    timeout(TEST_TIMEOUT, run_idle())
        .await
        .expect("test timed out")
        .expect("test failed");
}

async fn run_idle() -> Result<(), Box<dyn std::error::Error>> {
    let (_s, _c, mut client, mut server) = connect(Some(INTERVAL)).await?;
    let client_stats = client.stream.stats_handle();
    let server_stats = server.stream.stats_handle();
    let client_start = client_stats.raw_bytes_written();
    let server_start = server_stats.raw_bytes_written();

    // About five intervals of silence: about five keep-alives each way.
    idle(&mut client, &mut server, INTERVAL * 5 + INTERVAL / 6).await;
    for (side, written) in [
        ("client", client_stats.raw_bytes_written() - client_start),
        ("server", server_stats.raw_bytes_written() - server_start),
    ] {
        assert_eq!(
            written % KEEP_ALIVE_FRAME,
            0,
            "{side} wrote {written} bytes"
        );
        let count = written / KEEP_ALIVE_FRAME;
        assert!(
            (3..=6).contains(&count),
            "{side} sent {count} keep-alives in five intervals"
        );
    }
    assert_eq!(
        server_stats.raw_bytes_read(),
        client_stats.raw_bytes_written() - client_start,
        "every client keep-alive reached the server"
    );

    // A side that writes more often than the interval sends no keep-alive.
    let before = client_stats.raw_bytes_written();
    let writes = 12u64;
    for _ in 0..writes {
        client.stream.write(b"tick").await?;
        let (_, got) = tokio::join!(
            timeout(INTERVAL / 6, client.stream.read()),
            server.stream.read(),
        );
        assert_eq!(got?, Some(b"tick".to_vec()));
    }
    assert_eq!(
        client_stats.raw_bytes_written() - before,
        writes * (3 + 4 + 17),
        "writes refreshed the keep-alive timer"
    );

    // Silence again: keep-alives resume.
    let before = client_stats.raw_bytes_written();
    idle(&mut client, &mut server, INTERVAL * 2).await;
    assert!(client_stats.raw_bytes_written() > before);
    Ok(())
}

#[tokio::test]
async fn disabled_keep_alive_sends_nothing() {
    timeout(TEST_TIMEOUT, async {
        let (_s, _c, mut client, mut server) = connect(None).await?;
        let client_written = client.stream.stats_handle().raw_bytes_written();
        let server_written = server.stream.stats_handle().raw_bytes_written();
        idle(&mut client, &mut server, Duration::from_secs(2)).await;
        assert_eq!(
            client.stream.stats_handle().raw_bytes_written(),
            client_written
        );
        assert_eq!(
            server.stream.stats_handle().raw_bytes_written(),
            server_written
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await
    .expect("test timed out")
    .expect("test failed");
}
