#![deny(clippy::all)]

//! Blind-relay interoperability:
//!
//! - A JS `blind-relay` server: a peeroxide client reaches a JS peer that
//!   advertises `relayThrough` — every byte crosses the JS relay.
//! - A peeroxide relay server: two JS peers pair through
//!   [`peeroxide_dht::relay_service::run_relay_server`] and exchange data.

use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide_dht::hyperdht::{self, HyperDhtConfig, KeyPair};
use peeroxide_dht::relay_service::{self, RelayServiceConfig};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const TEST_TIMEOUT: Duration = Duration::from_secs(60);

fn plain_config(bootstrap: Vec<String>) -> HyperDhtConfig {
    let mut config = HyperDhtConfig::default();
    config.dht.host = "127.0.0.1".into();
    config.dht.port = 0;
    config.dht.bootstrap = bootstrap;
    config.dht.ephemeral = Some(false);
    config.dht.firewalled = false;
    config.dht.quick_firewall = false;
    config
}

#[tokio::test]
async fn peeroxide_client_relayed_through_a_js_relay() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let script = format!("{}/../tests/node/relay-through-peer.js", env!("CARGO_MANIFEST_DIR"));
        let mut child = tokio::process::Command::new("node")
            .arg(script)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("start JS relay peer");
        let _stdin = child.stdin.take().expect("stdin");
        let mut output = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        output.read_line(&mut line).await.expect("JS ready");
        let ready: serde_json::Value = serde_json::from_str(&line).expect("ready JSON");
        let port = ready["port"].as_u64().expect("port");
        let echo_key: [u8; 32] = hex::decode(ready["publicKey"].as_str().expect("key"))
            .expect("key hex")
            .try_into()
            .expect("key length");

        let runtime = UdxRuntime::new().expect("runtime");
        let (_task, dht, _events) = hyperdht::spawn(
            &runtime,
            plain_config(vec![format!("127.0.0.1:{port}")]),
        )
        .await
        .expect("DHT");
        dht.fully_bootstrapped().await.expect("bootstrapped");

        let keys = KeyPair::generate();
        let mut conn = dht.connect(&keys, echo_key, &runtime).await.expect("relayed connect");
        conn.stream.write(b"through-js-relay").await.expect("write");
        assert_eq!(
            conn.stream.read().await.expect("read").as_deref(),
            Some(&b"through-js-relay"[..])
        );

        dht.destroy().await.expect("destroy");
        child.kill().await.expect("stop JS");
    })
    .await
    .expect("JS relay interop timed out");
}

#[tokio::test]
async fn js_peers_pair_through_a_peeroxide_relay() {
    let _ = tracing_subscriber::fmt::try_init();
    tokio::time::timeout(TEST_TIMEOUT, async {
        let runtime = UdxRuntime::new().expect("runtime");
        let (_task, dht, events) = hyperdht::spawn(&runtime, plain_config(vec![]))
            .await
            .expect("DHT");
        dht.fully_bootstrapped().await.expect("bootstrapped");
        let port = dht.local_port().await.expect("port");

        let relay_keys = KeyPair::generate();
        let (relay, _relay_task) = relay_service::run_relay_server(
            runtime.handle(),
            dht.clone(),
            relay_keys.clone(),
            events,
            RelayServiceConfig::default(),
        );

        let script = format!("{}/../tests/node/relay-via-rust.js", env!("CARGO_MANIFEST_DIR"));
        let mut child = tokio::process::Command::new("node")
            .arg(script)
            .arg(port.to_string())
            .arg(hex::encode(relay_keys.public_key))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("start JS peers");
        let mut input = child.stdin.take().expect("stdin");
        let mut output = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        output.read_line(&mut line).await.expect("JS result");
        let result: serde_json::Value = serde_json::from_str(&line).expect("result JSON");
        assert_eq!(result["data"], "js-through-rust-relay", "JS result: {line}");
        assert_eq!(result["relayed"], true, "echo did not arrive from the relay socket: {line}");
        let stats = relay.stats();
        assert!(stats.pairings_matched >= 1, "relay matched {} pairings", stats.pairings_matched);
        assert!(stats.sessions_accepted >= 2, "relay saw {} sessions, expected both peers", stats.sessions_accepted);

        let _ = input.write_all(b"\n").await;
        dht.destroy().await.expect("destroy");
        child.kill().await.expect("stop JS");
    })
    .await
    .expect("peeroxide relay interop timed out");
}
