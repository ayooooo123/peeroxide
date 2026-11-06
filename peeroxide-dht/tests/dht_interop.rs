//! Live interop test: Rust DhtNode ↔ Node.js dht-rpc bootstrapper.
//!
//! Verifies: bootstrap completes, ping returns valid response, and the node
//! detects that its own server socket is reachable (dht-rpc's PING_NAT
//! firewall check) so peers dial it instead of holepunching.

use std::io::BufRead;
use std::process::{Command, Stdio};
use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide_dht::peer::peer_id;
use peeroxide_dht::rpc::DhtConfig;

fn node_server_path() -> String {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    format!("{manifest}/../tests/node/dht-rpc-server.js")
}

#[tokio::test]
async fn rust_node_bootstraps_and_pings_js() {
    let _ = tracing_subscriber::fmt::try_init();

    let result = tokio::time::timeout(Duration::from_secs(30), run_interop()).await;

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("interop test failed: {e}"),
        Err(_) => panic!("interop test timed out after 30s"),
    }
}

async fn run_interop() -> Result<(), Box<dyn std::error::Error>> {
    // ── Spawn JS bootstrapper ────────────────────────────────────────────
    let mut child = Command::new("node")
        .arg(node_server_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let stdout = child.stdout.take().expect("no stdout");
    let stdin = child.stdin.take().expect("no stdin");

    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let info: serde_json::Value = serde_json::from_str(line.trim())?;
    let js_port = info["port"].as_u64().expect("missing port") as u16;
    assert!(info["ready"].as_bool().unwrap_or(false), "JS node not ready");
    tracing::info!(js_port, "JS bootstrapper ready");

    // ── Create Rust DHT node that bootstraps from the JS node ────────────
    let runtime = UdxRuntime::new()?;

    let mut config = DhtConfig::default();
    config.bootstrap = vec![format!("127.0.0.1:{js_port}")];
    config.port = 0;
    config.host = "127.0.0.1".to_string();
    config.firewalled = true;

    let (task, handle) = peeroxide_dht::rpc::spawn(&runtime, config).await?;

    // ── Bootstrap ────────────────────────────────────────────────────────
    tracing::info!("waiting for bootstrap to complete...");
    handle.bootstrapped().await?;
    tracing::info!("bootstrap complete");

    let table_sz = handle.table_size().await?;
    tracing::info!(table_sz, "routing table size after bootstrap");
    assert!(table_sz >= 1, "expected at least 1 node in table, got {table_sz}");

    // ── Ping the JS bootstrapper ─────────────────────────────────────────
    tracing::info!("sending ping to JS bootstrapper...");
    let ping_resp = handle.ping("127.0.0.1", js_port).await?;

    tracing::info!(?ping_resp, "ping response received");
    assert_eq!(ping_resp.from.host, "127.0.0.1");
    assert_eq!(ping_resp.from.port, js_port);
    assert!(ping_resp.rtt < Duration::from_secs(5), "RTT too high: {:?}", ping_resp.rtt);

    let expected_id = peer_id("127.0.0.1", js_port);
    assert_eq!(
        ping_resp.id,
        Some(expected_id),
        "JS bootstrapper should return its computed peer_id"
    );

    // ── Cleanup ──────────────────────────────────────────────────────────
    handle.destroy().await?;
    let _ = task.await;

    drop(stdin);
    drop(reader);
    let _ = child.kill();
    let _ = child.wait();

    drop(runtime);
    Ok(())
}

/// A node whose server socket is reachable must report `FIREWALL_OPEN` and a
/// remote address by the time `bootstrapped()` resolves: Hyperswarm peers read
/// those to decide whether to dial us directly. On loopback the JS
/// bootstrapper can always reach us, so the check must succeed.
#[tokio::test]
async fn rust_node_detects_reachable_server_socket() {
    let _ = tracing_subscriber::fmt::try_init();

    tokio::time::timeout(Duration::from_secs(30), async {
        let mut child = Command::new("node")
            .arg(node_server_path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn node");
        let stdin = child.stdin.take().expect("no stdin");
        let mut reader = std::io::BufReader::new(child.stdout.take().expect("no stdout"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("read ready line");
        let info: serde_json::Value = serde_json::from_str(line.trim()).expect("parse ready line");
        let js_port = info["port"].as_u64().expect("missing port") as u16;

        let runtime = UdxRuntime::new().expect("runtime");
        let mut config = DhtConfig::default();
        config.bootstrap = vec![format!("127.0.0.1:{js_port}")];
        config.port = 0;
        config.host = "127.0.0.1".to_string();
        config.firewalled = true;
        let (task, handle) = peeroxide_dht::rpc::spawn(&runtime, config).await.expect("spawn dht");
        handle.bootstrapped().await.expect("bootstrapped");

        assert_eq!(
            handle.firewalled().await.expect("firewalled"),
            peeroxide_dht::hyperdht_messages::FIREWALL_OPEN,
            "server socket is reachable on loopback, so the node must report FIREWALL_OPEN"
        );
        let addr = handle.remote_address().await.expect("remote_address");
        let addr = addr.expect("an open node knows its own address");
        assert_eq!(addr.host, "127.0.0.1");
        assert_eq!(
            addr.port,
            handle.local_port().await.expect("local_port"),
            "an open node advertises the port its server socket is bound to"
        );

        handle.destroy().await.expect("destroy");
        let _ = task.await;
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
    })
    .await
    .expect("test timed out after 30s");
}
