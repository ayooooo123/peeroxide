#![deny(clippy::all)]

//! The `private-overlay.js` raw-stream shape against a JS peer:
//! `dht.createRawStream({ firewall })` on both sides, ids exchanged over the
//! encrypted control connection, then `HyperDHT.connectRawStream(conn, raw,
//! remoteId)` / [`HyperDhtHandle::connect_raw_stream`].

use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide_dht::hyperdht::{self, HyperDhtConfig, KeyPair, RawStreamOptions};
use tokio::io::{AsyncBufReadExt, BufReader};

const TEST_TIMEOUT: Duration = Duration::from_secs(40);

#[tokio::test]
async fn raw_stream_connect_over_a_control_connection() {
    tokio::time::timeout(TEST_TIMEOUT, run())
        .await
        .expect("raw stream pair interop timed out")
        .expect("raw stream pair interop failed");
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let script = format!(
        "{}/../tests/node/raw-stream-pair.js",
        env!("CARGO_MANIFEST_DIR")
    );
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

    let keys = KeyPair::generate();
    let mut conn = node.connect(&keys, js_key, &runtime).await?;

    let js_raw: serde_json::Value =
        serde_json::from_slice(&conn.stream.read().await?.expect("JS raw id"))?;
    let js_raw_id = js_raw["id"].as_u64().expect("raw id") as u32;

    // Same firewall shape as private-overlay.js: only the control peer.
    let remote = conn.remote_addr.ok_or("no remote address")?;
    let (remote_ip, remote_port) = (remote.ip(), remote.port());
    let mut raw = node
        .create_raw_stream(
            &runtime,
            RawStreamOptions::new()
                .with_firewall(move |_, port, host| host != remote_ip || port != remote_port),
        )
        .await?;

    conn.stream
        .write(format!("{{\"id\":{}}}", raw.id()).as_bytes())
        .await?;
    node.connect_raw_stream(&conn, &raw, js_raw_id).await?;

    let confirmed: serde_json::Value = {
        let mut waited = None;
        for _ in 0..4 {
            let message = conn.stream.read().await?.expect("JS control message");
            let value: serde_json::Value = serde_json::from_slice(&message)?;
            if value["connected"] == true {
                waited = Some(value);
                break;
            }
        }
        waited.ok_or("JS never confirmed the raw stream")?
    };
    assert_eq!(confirmed["connected"], true);

    raw.write(b"circuit").await?;
    assert_eq!(raw.read().await?.as_deref(), Some(&b"circuit"[..]));

    node.destroy().await?;
    child.kill().await?;
    Ok(())
}
