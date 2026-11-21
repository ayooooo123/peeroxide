//! A Rust server's peer firewall against real Node hyperdht clients: the
//! allowed key connects, any other key gets no handshake reply.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide_dht::hyperdht::{self, HyperDhtConfig, KeyPair, ServerConfig};
use peeroxide_dht::hyperdht_messages::FIREWALL_OPEN;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn key(value: &serde_json::Value) -> [u8; 32] {
    hex::decode(value.as_str().expect("key"))
        .expect("key hex")
        .try_into()
        .expect("key length")
}

#[tokio::test]
async fn node_client_connects_only_with_an_allowed_key() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let script = format!(
            "{}/../tests/node/hyperdht-firewall-client.js",
            env!("CARGO_MANIFEST_DIR")
        );
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
        let allowed = key(&ready["allowed"]);
        let refused = key(&ready["refused"]);

        let runtime = UdxRuntime::new().expect("runtime");
        let mut config = HyperDhtConfig::default();
        config.dht.host = "127.0.0.1".into();
        config.dht.bootstrap = vec![format!("127.0.0.1:{port}")];
        config.dht.firewalled = false;
        let (_task, dht, _events) = hyperdht::spawn(&runtime, config).await.expect("DHT");
        dht.fully_bootstrapped().await.expect("bootstrap");

        let keys = KeyPair::generate();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let mut server_config = ServerConfig::new(keys.clone(), FIREWALL_OPEN);
        server_config.peer_firewall = Some(Arc::new(move |remote, _, _| {
            log.lock().unwrap().push(*remote);
            *remote != allowed
        }));
        let mut server = dht.create_shared_server(&runtime, server_config);
        server.listen(&keys).await.expect("listen");
        input
            .write_all(format!("{}\n", hex::encode(keys.public_key)).as_bytes())
            .await
            .expect("request JS dials");

        line.clear();
        output.read_line(&mut line).await.expect("refused outcome");
        let outcome: serde_json::Value = serde_json::from_str(&line).expect("refused JSON");
        assert!(
            outcome["refused"]["error"].is_string(),
            "the refused key must fail to connect: {outcome}"
        );

        let mut accepted = server.accept().await.expect("accept allowed client");
        assert_eq!(accepted.remote_public_key, allowed);
        let data = accepted
            .stream
            .read()
            .await
            .expect("read allowed client")
            .expect("payload");
        assert_eq!(data, b"allowed-client");
        accepted.stream.write(&data).await.expect("reply");
        line.clear();
        output.read_line(&mut line).await.expect("allowed outcome");
        let outcome: serde_json::Value = serde_json::from_str(&line).expect("allowed JSON");
        assert_eq!(outcome["allowed"]["data"], "allowed-client");

        let seen = seen.lock().unwrap().clone();
        assert!(seen.contains(&refused), "the hook saw the refused key");
        assert!(seen.contains(&allowed), "the hook saw the allowed key");

        server.close().await;
        dht.destroy().await.expect("destroy DHT");
        child.kill().await.expect("stop JS testnet");
    })
    .await
    .expect("peer firewall interop timed out");
}
