//! A connection that closed is forgotten, so the same peer can dial again.
//!
//! The swarm used to track only the closes of the connections it opened
//! itself. A server-side connection stayed in `connections` after its stream
//! died, so the peer's next handshake was answered and then dropped: the peer
//! held a reply and no UDX stream, and hung.
//!
//! - `rust_client_reconnects_after_the_server_drops_the_stream`: two Rust
//!   swarms; the server aborts the stream, the client redials within its
//!   retry backoff, and the server hands out a second connection.
//! - `node_client_reconnects_to_a_rust_server`: a Node hyperswarm client
//!   destroys its connection and redials; the Rust server yields a second
//!   connection for the same peer.

use std::io::{BufRead, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide::{JoinOpts, SwarmConfig, SwarmConnection, discovery_key, spawn as spawn_swarm};
use peeroxide_dht::hyperdht::{HyperDhtConfig, spawn};
use peeroxide_dht::rpc::DhtConfig;
use serde_json::Value;

fn local_dht(bootstrap: Vec<String>, firewalled: bool) -> HyperDhtConfig {
    let mut dht = DhtConfig::default();
    dht.bootstrap = bootstrap;
    dht.port = 0;
    dht.host = "127.0.0.1".to_string();
    dht.firewalled = firewalled;
    // On loopback every socket is reachable; a "firewalled" test node must
    // not discover that at bootstrap and switch to the direct path.
    dht.quick_firewall = false;
    if !firewalled {
        // A reachable node joins the routing table at once, as the Node
        // testnet nodes (`ephemeral: false`) do.
        dht.ephemeral = Some(false);
    }
    let mut config = HyperDhtConfig::default();
    config.dht = dht;
    config
}

fn server_only() -> JoinOpts {
    let mut opts = JoinOpts::default();
    opts.client = false;
    opts
}

fn client_only() -> JoinOpts {
    let mut opts = JoinOpts::default();
    opts.server = false;
    opts
}

async fn recv(
    conns: &mut tokio::sync::mpsc::Receiver<SwarmConnection>,
    what: &str,
    within: Duration,
) -> Result<SwarmConnection, Box<dyn std::error::Error>> {
    tokio::time::timeout(within, conns.recv())
        .await
        .map_err(|_| format!("timed out waiting for {what}"))?
        .ok_or_else(|| format!("connection channel closed while waiting for {what}").into())
}

#[tokio::test]
async fn rust_client_reconnects_after_the_server_drops_the_stream() {
    let _ = tracing_subscriber::fmt::try_init();

    match tokio::time::timeout(Duration::from_secs(30), rust_reconnect()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("rust reconnect test failed: {e}"),
        Err(_) => panic!("rust reconnect test timed out after 30s"),
    }
}

async fn rust_reconnect() -> Result<(), Box<dyn std::error::Error>> {
    let rt = UdxRuntime::new()?;
    let (_bs_join, bs, _bs_rx) = spawn(&rt, local_dht(vec![], false)).await?;
    let bootstrap = vec![format!("127.0.0.1:{}", bs.local_port().await?)];

    let topic = discovery_key(b"peeroxide-reconnect-after-close");

    let mut server_config = SwarmConfig::default();
    server_config.dht = local_dht(bootstrap.clone(), false);
    let (_server_task, server, mut server_conns) = spawn_swarm(server_config).await?;
    server.join(topic, server_only()).await?;
    server.flush().await?;

    let mut client_config = SwarmConfig::default();
    client_config.dht = local_dht(bootstrap, true);
    let (_client_task, client, mut client_conns) = spawn_swarm(client_config).await?;
    client.join(topic, client_only()).await?;

    let first = recv(
        &mut server_conns,
        "the first connection",
        Duration::from_secs(20),
    )
    .await?;
    let remote = *first.remote_public_key();
    tracing::info!(pk = %hex::encode(remote), "server accepted the first connection");

    // The client also got a connection object; it must not be mistaken for a
    // redial.
    let _ = recv(
        &mut client_conns,
        "the client's own connection",
        Duration::from_secs(18),
    )
    .await?;

    // Drop the stream as a peer that lost its connection would: the client
    // sees the close, forgets the peer's slot and redials.
    first.peer.stream.abort_handle().abort();
    drop(first);

    let second = recv(
        &mut server_conns,
        "the reconnection",
        Duration::from_secs(5),
    )
    .await?;
    assert_eq!(
        second.remote_public_key(),
        &remote,
        "the same peer must reach the server again"
    );
    assert!(!second.is_initiator, "the server accepts, it does not dial");
    tracing::info!("server accepted the redialled connection");

    server.destroy().await?;
    client.destroy().await?;
    bs.destroy().await?;
    Ok(())
}

// ── Node client helper ───────────────────────────────────────────────────────

fn script_path() -> String {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    format!("{manifest}/../tests/node/hyperswarm-reconnect-client.js")
}

struct JsClient {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    lines: Arc<Mutex<Vec<String>>>,
    _reader_thread: std::thread::JoinHandle<()>,
}

impl JsClient {
    fn start() -> Self {
        let mut child = Command::new("node")
            .arg(script_path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn node hyperswarm-reconnect-client.js");

        let stdout = child.stdout.take().expect("no stdout");
        let stdin = child.stdin.take().expect("no stdin");
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let lines_clone = lines.clone();

        let reader_thread = std::thread::spawn(move || {
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                lines_clone.lock().unwrap().push(line);
            }
        });

        Self {
            child,
            stdin,
            lines,
            _reader_thread: reader_thread,
        }
    }

    /// The local testnet the helper created, as `host:port` bootstraps, plus
    /// the client's public key.
    async fn read_ready(&self) -> (Vec<String>, String) {
        let ready = self.wait_event("ready", Duration::from_secs(20)).await;
        let bootstrap = ready["bootstrap"]
            .as_array()
            .expect("no bootstrap list")
            .iter()
            .map(|b| {
                format!(
                    "{}:{}",
                    b["host"].as_str().expect("bootstrap host"),
                    b["port"].as_u64().expect("bootstrap port")
                )
            })
            .collect();
        let public_key = ready["publicKey"]
            .as_str()
            .expect("no publicKey")
            .to_string();
        (bootstrap, public_key)
    }

    fn send(&mut self, cmd: Value) {
        let line = serde_json::to_string(&cmd).unwrap() + "\n";
        self.stdin
            .write_all(line.as_bytes())
            .expect("write to JS stdin");
        self.stdin.flush().expect("flush JS stdin");
    }

    async fn wait_event(&self, event: &str, within: Duration) -> Value {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            {
                let lines = self.lines.lock().unwrap();
                for line in lines.iter() {
                    if let Ok(v) = serde_json::from_str::<Value>(line) {
                        if v["event"].as_str() == Some(event)
                            || (event == "ready" && v["ready"].as_bool() == Some(true))
                        {
                            return v;
                        }
                    }
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for the JS '{event}' line"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for JsClient {
    fn drop(&mut self) {
        let _ = self.stdin.write_all(b"{\"cmd\":\"shutdown\"}\n");
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn node_client_reconnects_to_a_rust_server() {
    let _ = tracing_subscriber::fmt::try_init();

    match tokio::time::timeout(Duration::from_secs(40), node_reconnect()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("node reconnect test failed: {e}"),
        Err(_) => panic!("node reconnect test timed out after 40s"),
    }
}

async fn node_reconnect() -> Result<(), Box<dyn std::error::Error>> {
    let mut js = JsClient::start();
    let (bootstrap, js_pk) = js.read_ready().await;
    tracing::info!(?bootstrap, "JS testnet ready");

    let topic = discovery_key(b"peeroxide-reconnect-after-close-js");
    let topic_hex = hex::encode(topic);

    // Reachable server, so the Node client's handshake goes straight to it and
    // both sides dial; a firewalled server would add a holepunch to a test
    // about connection bookkeeping.
    let mut config = SwarmConfig::default();
    config.dht = local_dht(bootstrap, false);
    let (_task, server, mut server_conns) = spawn_swarm(config).await?;
    server.join(topic, server_only()).await?;
    server.flush().await?;

    js.send(serde_json::json!({ "cmd": "join", "topic": topic_hex }));
    js.wait_event("joined", Duration::from_secs(10)).await;

    let first = recv(
        &mut server_conns,
        "the first Node connection",
        Duration::from_secs(20),
    )
    .await?;
    assert_eq!(
        hex::encode(first.remote_public_key()),
        js_pk,
        "the connection must come from the Node client"
    );
    tracing::info!("server accepted the Node client");

    // The client destroys this connection and redials on its own.
    let second = recv(
        &mut server_conns,
        "the Node reconnection",
        Duration::from_secs(20),
    )
    .await?;
    assert_eq!(
        hex::encode(second.remote_public_key()),
        js_pk,
        "the same Node client must be able to redial"
    );
    js.wait_event("reconnected", Duration::from_secs(5)).await;

    server.destroy().await?;
    drop(js);
    Ok(())
}
