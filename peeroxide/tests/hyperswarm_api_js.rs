//! Explicit-peer connections with the JS Hyperswarm reference on a local testnet.

use std::time::Duration;

use peeroxide::SwarmConfig;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn explicit_peers_connect_both_directions() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let script = format!("{}/../tests/node/hyperswarm-api-peer.js", env!("CARGO_MANIFEST_DIR"));
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
        let remote: [u8; 32] = hex::decode(ready["publicKey"].as_str().expect("key"))
            .expect("key hex").try_into().expect("key length");
        let config = || {
            let mut config = SwarmConfig::default();
            config.dht.dht.host = "127.0.0.1".into();
            config.dht.dht.bootstrap = vec![format!("127.0.0.1:{port}")];
            config.dht.dht.firewalled = false;
            config
        };
        let (_listener_task, listener, mut incoming) = peeroxide::spawn(config()).await.expect("listener");
        listener.listen().await.expect("listen");
        input.write_all(format!("{}\n", hex::encode(listener.key_pair().public_key)).as_bytes()).await.expect("request JS join");
        let (_joiner_task, joiner, mut outgoing) = peeroxide::spawn(config()).await.expect("joiner");
        joiner.join_peer(remote).await.expect("join JS peer");
        let mut from_js = incoming.recv().await.expect("JS joins Rust");
        let mut from_rust = outgoing.recv().await.expect("Rust joins JS");
        assert_eq!(from_js.peer.stream.read().await.expect("read JS"), Some(b"js-joiner".to_vec()));
        assert_eq!(from_rust.peer.stream.read().await.expect("read JS"), Some(b"js-listener".to_vec()));
        input.write_all(b"restart\n").await.expect("restart JS listener");
        line.clear();
        output.read_line(&mut line).await.expect("JS restart");
        assert!(serde_json::from_str::<serde_json::Value>(&line).expect("restart JSON")["restarted"].as_bool().unwrap_or(false));
        let mut reconnected = outgoing.recv().await.expect("Rust reconnects to JS");
        assert_eq!(reconnected.peer.stream.read().await.expect("read after restart"), Some(b"js-listener".to_vec()));
        listener.destroy_with_force(true).await.expect("destroy listener");
        joiner.destroy_with_force(true).await.expect("destroy joiner");
        child.kill().await.expect("stop JS testnet");
    }).await.expect("JS swarm interop timed out");
}
