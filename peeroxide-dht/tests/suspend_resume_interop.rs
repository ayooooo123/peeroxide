#![deny(clippy::all)]

//! Suspend/resume against a JS hyperdht testnet.
//!
//! Node `HyperDHT.suspend()` closes the sockets, so a suspended Rust node must
//! (a) refuse lookups and dials locally and (b) be unreachable from the JS
//! side. After `resume()` pings, announces and connections must work again
//! against the same JS node.

use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide_dht::hyperdht::{self, HyperDhtConfig, KeyPair};
use tokio::io::{AsyncBufReadExt, BufReader};

const TEST_TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test]
async fn suspend_and_resume_against_a_js_testnet() {
    let _ = tokio::time::timeout(TEST_TIMEOUT, run()).await.expect("JS suspend interop timed out");
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let script = format!("{}/../tests/node/hyperdht-suspend-peer.js", env!("CARGO_MANIFEST_DIR"));
    let mut child = tokio::process::Command::new("node")
        .arg(script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let _stdin = child.stdin.take().expect("stdin");
    let mut output = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    output.read_line(&mut line).await?;
    let ready: serde_json::Value = serde_json::from_str(&line)?;
    let bootstrap_port = ready["port"].as_u64().expect("bootstrap port");
    let dht_port = ready["dhtPort"].as_u64().expect("dht port") as u16;
    let js_key: [u8; 32] = hex::decode(ready["publicKey"].as_str().expect("key"))?
        .try_into()
        .map_err(|_| "bad key length")?;

    let runtime = UdxRuntime::new()?;
    let mut config = HyperDhtConfig::default();
    config.dht.host = "127.0.0.1".into();
    config.dht.bootstrap = vec![format!("127.0.0.1:{bootstrap_port}")];
    config.dht.ephemeral = Some(false);
    config.dht.firewalled = false;
    config.dht.quick_firewall = false;
    let (_task, node, _events) = hyperdht::spawn(&runtime, config).await?;
    node.fully_bootstrapped().await?;

    // A working baseline against the JS node.
    let pong = node.dht().ping("127.0.0.1", dht_port).await?;
    assert_eq!(pong.from.port, dht_port, "ephemeral JS node replies without an id");

    // ── Suspended ────────────────────────────────────────────────────────
    node.suspend().await?;
    assert!(node.dht().ping("127.0.0.1", dht_port).await.is_err());
    assert!(node.lookup([3u8; 32]).await.is_err());
    let keys = KeyPair::generate();
    assert!(node.connect(&keys, js_key, &runtime).await.is_err());

    // ── Resumed ──────────────────────────────────────────────────────────
    node.resume().await?;
    let pong = node.dht().ping("127.0.0.1", dht_port).await?;
    assert_eq!(pong.from.port, dht_port);

    let target: [u8; 32] = rand::random();
    node.announce(target, &keys, &[]).await?;
    node.lookup(target).await?;

    let mut client = node.connect(&keys, js_key, &runtime).await?;
    client.stream.write(b"still-alive").await?;
    assert_eq!(client.stream.read().await?, Some(b"still-alive".to_vec()));

    node.destroy().await?;
    child.kill().await?;
    Ok(())
}
