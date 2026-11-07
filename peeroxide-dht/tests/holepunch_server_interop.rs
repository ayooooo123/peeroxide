#![deny(clippy::all)]

//! Passive holepunching for [`HyperDhtServer`], both directions, on a local
//! testnet with `firewalled: true` peers (hyperdht's testnet firewall options).
//!
//! - `js_client_holepunches_into_a_rust_server`: the JS client is firewalled,
//!   so its handshake reaches the Rust server through a testnet relay and both
//!   sides punch. The Rust server resolves the punch into `accept()`.
//! - `rust_client_holepunches_into_a_js_server`: the Rust initiator drives the
//!   punch against a firewalled JS server.

use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide_dht::hyperdht::{self, HyperDhtConfig, KeyPair, ServerConfig};
use peeroxide_dht::hyperdht_messages::FIREWALL_UNKNOWN;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Child;

const TEST_TIMEOUT: Duration = Duration::from_secs(60);

struct JsPeer {
    child: Child,
    output: BufReader<tokio::process::ChildStdout>,
    input: tokio::process::ChildStdin,
}

impl JsPeer {
    async fn start(script: &str) -> Result<(Self, serde_json::Value), Box<dyn std::error::Error>> {
        let path = format!("{}/../tests/node/{script}", env!("CARGO_MANIFEST_DIR"));
        let mut child = tokio::process::Command::new("node")
            .arg(path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let input = child.stdin.take().expect("stdin");
        let mut output = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        output.read_line(&mut line).await?;
        let ready = serde_json::from_str(&line)?;
        Ok((Self { child, output, input }, ready))
    }

    async fn read_json(&mut self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let mut line = String::new();
        self.output.read_line(&mut line).await?;
        Ok(serde_json::from_str(&line)?)
    }
}

fn firewalled_config(bootstrap: u64) -> HyperDhtConfig {
    let mut config = HyperDhtConfig::default();
    config.dht.host = "127.0.0.1".into();
    config.dht.bootstrap = vec![format!("127.0.0.1:{bootstrap}")];
    config.dht.firewalled = true;
    // On loopback every socket is reachable; keep the node firewalled so the
    // relay/punch path is the only way in.
    config.dht.quick_firewall = false;
    config
}

#[tokio::test]
async fn js_client_holepunches_into_a_rust_server() {
    let _ = tracing_subscriber::fmt::try_init();
    tokio::time::timeout(TEST_TIMEOUT, async {
        let (mut js, ready) = JsPeer::start("holepunch-client.js").await.expect("JS client");
        let port = ready["port"].as_u64().expect("port");

        let runtime = UdxRuntime::new().expect("runtime");
        let (_task, dht, events) =
            hyperdht::spawn(&runtime, firewalled_config(port)).await.expect("DHT");
        dht.fully_bootstrapped().await.expect("bootstrapped");

        let keys = KeyPair::generate();
        let mut server = dht.create_server(
            &runtime,
            ServerConfig::new(keys.clone(), FIREWALL_UNKNOWN),
            events,
        );
        server.listen(&keys).await.expect("listen");

        js.input
            .write_all(format!("{}\n", hex::encode(keys.public_key)).as_bytes())
            .await
            .expect("ask JS to dial");

        let mut accepted = server.accept().await.expect("server accepted the punched client");
        let data = accepted.stream.read().await.expect("read JS").expect("payload");
        assert_eq!(data, b"js-client");
        accepted.stream.write(&data).await.expect("echo");
        let echoed = js.read_json().await.expect("JS echo");
        assert_eq!(echoed["data"], "js-client");

        server.close().await;
        dht.destroy().await.expect("destroy");
        js.child.kill().await.expect("stop JS");
    })
    .await
    .expect("JS -> Rust holepunch timed out");
}

#[tokio::test]
async fn rust_client_holepunches_into_a_js_server() {
    let _ = tracing_subscriber::fmt::try_init();
    tokio::time::timeout(TEST_TIMEOUT, async {
        let (_js, ready) = JsPeer::start("holepunch-server.js").await.expect("JS server");
        let port = ready["port"].as_u64().expect("port");
        let js_key: [u8; 32] = hex::decode(ready["publicKey"].as_str().expect("key"))
            .expect("key hex")
            .try_into()
            .expect("key length");

        let runtime = UdxRuntime::new().expect("runtime");
        let (_task, dht, _events) =
            hyperdht::spawn(&runtime, firewalled_config(port)).await.expect("DHT");
        dht.fully_bootstrapped().await.expect("bootstrapped");

        let keys = KeyPair::generate();
        let mut client = dht.connect(&keys, js_key, &runtime).await.expect("punched connect");
        client.stream.write(b"rust-client").await.expect("write");
        assert_eq!(
            client.stream.read().await.expect("read").as_deref(),
            Some(&b"rust-client"[..])
        );

        dht.destroy().await.expect("destroy");
    })
    .await
    .expect("Rust -> JS holepunch timed out");
}
