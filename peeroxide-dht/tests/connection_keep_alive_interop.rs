//! Connection keep-alive between a Rust and a Node hyperdht peer.
//!
//! - `idle_connection_with_node_stays_up`: a Rust client connects to a Node
//!   hyperdht server (both with the default 5000 ms `connectionKeepAlive`),
//!   both sides stay idle for 12 s, and each side receives the other's empty
//!   keep-alive messages (two at least) without delivering them. Then data
//!   crosses both ways and the Node side reports no error.

use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide_dht::hyperdht::{self, HyperDhtConfig, KeyPair};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Keep-alive frame on the Rust counters: 3-byte length + 17-byte body.
const RUST_FRAME: u64 = 20;
/// Node's `rawBytesRead` counts the 17-byte body only.
const NODE_FRAME: u64 = 17;

#[tokio::test]
async fn idle_connection_with_node_stays_up() {
    tokio::time::timeout(Duration::from_secs(60), run())
        .await
        .expect("interop test timed out")
        .expect("interop test failed");
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let script = format!(
        "{}/../tests/node/connection-keep-alive-peer.js",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut child = tokio::process::Command::new("node")
        .arg(script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdin.take().ok_or("stdin")?;
    let mut output = BufReader::new(child.stdout.take().ok_or("stdout")?);
    let mut next_json = async move || -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let mut line = String::new();
        output.read_line(&mut line).await?;
        Ok(serde_json::from_str(&line)?)
    };

    let ready = next_json().await?;
    let port = ready["port"].as_u64().ok_or("port")?;
    let remote: [u8; 32] = hex::decode(ready["publicKey"].as_str().ok_or("key")?)?
        .try_into()
        .map_err(|_| "key length")?;

    let runtime = UdxRuntime::new()?;
    let mut config = HyperDhtConfig::default();
    config.dht.host = "127.0.0.1".into();
    config.dht.bootstrap = vec![format!("127.0.0.1:{port}")];
    config.dht.firewalled = false;
    assert_eq!(
        config.connection_keep_alive,
        Some(hyperdht::DEFAULT_CONNECTION_KEEP_ALIVE)
    );
    let (_task, dht, _events) = hyperdht::spawn(&runtime, config).await?;
    dht.fully_bootstrapped().await?;
    let mut client = dht.connect(&KeyPair::generate(), remote, &runtime).await?;
    let stats = client.stream.stats_handle();

    // 12 s idle with a read pending: no message may be delivered.
    let idle = tokio::time::timeout(Duration::from_secs(12), client.stream.read()).await;
    assert!(idle.is_err(), "idle read returned {idle:?}");
    assert!(
        stats.raw_bytes_written() >= 2 * RUST_FRAME,
        "Rust sent {} keep-alive bytes in 12 s",
        stats.raw_bytes_written()
    );
    assert!(
        stats.raw_bytes_read() >= 2 * RUST_FRAME,
        "Rust received {} keep-alive bytes in 12 s",
        stats.raw_bytes_read()
    );

    input.write_all(b"status\n").await?;
    let status = next_json().await?;
    assert_eq!(status["status"], true, "Node connection closed: {status}");
    assert_eq!(status["errors"], serde_json::json!([]), "{status}");
    assert!(
        status["rawBytesRead"].as_u64().unwrap_or(0) >= 2 * NODE_FRAME,
        "Node saw no keep-alives: {status}"
    );

    client.stream.write(b"rust-ping").await?;
    let echoed = next_json().await?;
    assert_eq!(echoed["data"], "rust-ping", "{echoed}");
    assert_eq!(
        client.stream.read().await?,
        Some(b"js-reply:rust-ping".to_vec())
    );

    input.write_all(b"status\n").await?;
    let status = next_json().await?;
    assert_eq!(status["status"], true, "{status}");
    assert_eq!(status["errors"], serde_json::json!([]), "{status}");

    dht.destroy().await?;
    child.kill().await?;
    Ok(())
}
