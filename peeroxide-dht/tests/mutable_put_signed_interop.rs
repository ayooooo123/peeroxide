#![deny(clippy::all)]

//! A guard forwards a mutable record signed by another key holder
//! (`mutable_put_signed`), and a JS `hyperdht` node reads it back with
//! `mutableGet`, verifying the signature against the endpoint's key.

use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide_dht::crypto::{mutable_signable, sign_detached, NS_MUTABLE_PUT};
use peeroxide_dht::hyperdht::{self, HyperDhtConfig, KeyPair};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn js_reads_back_a_record_signed_out_of_band() {
    let _ = tracing_subscriber::fmt::try_init();
    tokio::time::timeout(Duration::from_secs(60), async {
        let script = format!("{}/../tests/node/mutable-get-peer.js", env!("CARGO_MANIFEST_DIR"));
        let mut child = tokio::process::Command::new("node")
            .arg(script)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("start JS testnet");
        let mut input = child.stdin.take().expect("stdin");
        let mut output = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        output.read_line(&mut line).await.expect("JS ready");
        let ready: serde_json::Value = serde_json::from_str(&line).expect("ready JSON");
        let port = ready["port"].as_u64().expect("port");

        let runtime = UdxRuntime::new().expect("runtime");
        let mut config = HyperDhtConfig::default();
        config.dht.host = "127.0.0.1".into();
        config.dht.port = 0;
        config.dht.bootstrap = vec![format!("127.0.0.1:{port}")];
        config.dht.firewalled = false;
        config.dht.quick_firewall = false;
        let (_task, guard, _events) = hyperdht::spawn(&runtime, config).await.expect("DHT");
        guard.fully_bootstrapped().await.expect("bootstrapped");

        // The endpoint signs; the guard only ever sees the public key.
        let endpoint = KeyPair::generate();
        let (seq, value) = (7u64, b"signed by the endpoint".to_vec());
        let signature = sign_detached(
            &mutable_signable(&NS_MUTABLE_PUT, seq, &value),
            &endpoint.secret_key,
        );
        let result = guard
            .mutable_put_signed(&endpoint.public_key, &value, seq, signature)
            .await
            .expect("mutable_put_signed");
        assert!(!result.closest_nodes.is_empty(), "no node stored the record");

        input
            .write_all(format!("{} {seq}\n", hex::encode(endpoint.public_key)).as_bytes())
            .await
            .expect("ask JS");
        line.clear();
        output.read_line(&mut line).await.expect("JS result");
        let got: serde_json::Value = serde_json::from_str(&line).expect("result JSON");
        assert_eq!(got["seq"], seq, "JS result: {line}");
        assert_eq!(got["value"], "signed by the endpoint", "JS result: {line}");
        assert_eq!(got["signature"], hex::encode(signature), "JS result: {line}");

        guard.destroy().await.expect("destroy");
        child.kill().await.expect("stop JS");
    })
    .await
    .expect("mutable put interop timed out");
}
