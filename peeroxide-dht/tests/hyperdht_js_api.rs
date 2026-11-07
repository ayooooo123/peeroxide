//! HyperDHT server and client connections against a local JS testnet.

use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide_dht::hyperdht::{self, HyperDhtConfig, KeyPair, ServerConfig};
use peeroxide_dht::hyperdht_messages::FIREWALL_OPEN;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn js_and_rust_servers_accept_each_others_clients() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let script = format!("{}/../tests/node/hyperdht-api-peer.js", env!("CARGO_MANIFEST_DIR"));
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
        let runtime = UdxRuntime::new().expect("runtime");
        let mut config = HyperDhtConfig::default();
        config.dht.host = "127.0.0.1".into();
        config.dht.bootstrap = vec![format!("127.0.0.1:{port}")];
        config.dht.firewalled = false;
        let (_task, dht, _events) = hyperdht::spawn(&runtime, config).await.expect("DHT");
        dht.fully_bootstrapped().await.expect("bootstrap");
        let keys = KeyPair::generate();
        let mut client = dht.connect(&keys, remote, &runtime).await.expect("connect to JS");
        client.stream.write(b"rust-client").await.expect("send to JS");
        assert_eq!(client.stream.read().await.expect("read JS"), Some(b"rust-client".to_vec()));
        let mut server = dht.create_shared_server(&runtime, ServerConfig::new(keys.clone(), FIREWALL_OPEN));
        server.listen(&keys).await.expect("listen");
        input.write_all(format!("{}\n", hex::encode(keys.public_key)).as_bytes()).await.expect("request JS dial");
        let mut accepted = server.accept().await.expect("accept JS");
        let data = accepted.stream.read().await.expect("read JS client").expect("payload");
        assert_eq!(data, b"js-client");
        accepted.stream.write(&data).await.expect("reply to JS");
        line.clear();
        output.read_line(&mut line).await.expect("read JS reply");
        let reply: serde_json::Value = serde_json::from_str(&line).expect("reply JSON");
        assert_eq!(reply["data"], "js-client");
        server.close().await;
        dht.destroy().await.expect("destroy DHT");
        child.kill().await.expect("stop JS testnet");
    }).await.expect("JS interop timed out");
}
