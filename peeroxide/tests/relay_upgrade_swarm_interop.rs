#![deny(clippy::all)]

//! Swarm-level relay→direct upgrade (Hyperswarm `relayThrough`) against JS,
//! both directions.
//!
//! 1. Rust swarm client -> JS swarm server:
//!    Rust client uses `join_peer` to known JS server key (server advertises relay).
//!    The relay lands first, transfer starts, holepunch moves stream to direct path.
//! 2. JS swarm client -> Rust swarm server:
//!    JS client offers relay to Rust swarm listen.
//!    The relay lands first, transfer starts, holepunch moves stream to direct path.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

use peeroxide::{SwarmConfig, spawn};
use peeroxide_dht::hyperdht::{HyperDhtConfig, PeerConnection};

const TEST_TIMEOUT: Duration = Duration::from_secs(90);
const CHUNK: usize = 16 * 1024;
const MAX_CHUNKS: usize = 4096;

struct JsPeer {
    child: Child,
    output: BufReader<tokio::process::ChildStdout>,
    input: tokio::process::ChildStdin,
}

impl JsPeer {
    async fn start(args: &[&str]) -> Result<(Self, serde_json::Value), Box<dyn std::error::Error>> {
        let path = format!(
            "{}/../tests/node/relay-upgrade-peer.js",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut child = Command::new("node")
            .arg(path)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let input = child.stdin.take().expect("stdin");
        let mut output = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        output.read_line(&mut line).await?;
        let ready = serde_json::from_str(&line)?;
        Ok((
            Self {
                child,
                output,
                input,
            },
            ready,
        ))
    }

    async fn read_json(&mut self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let mut line = String::new();
        self.output.read_line(&mut line).await?;
        Ok(serde_json::from_str(&line)?)
    }
}

struct Ready {
    port: u64,
    public_key: [u8; 32],
    relay_addr: SocketAddr,
}

fn ready(value: &serde_json::Value) -> Ready {
    let mut public_key = [0u8; 32];
    hex::decode_to_slice(
        value["publicKey"].as_str().expect("publicKey"),
        &mut public_key,
    )
    .expect("hex pk");
    let host = value["relayAddr"]["host"].as_str().expect("relay host");
    let port = value["relayAddr"]["port"].as_u64().expect("relay port") as u16;
    Ready {
        port: value["port"].as_u64().expect("bootstrap port"),
        public_key,
        relay_addr: SocketAddr::new(host.parse().expect("ip"), port),
    }
}

fn js_remote(event: &serde_json::Value) -> SocketAddr {
    let host = event["remote"]["host"].as_str().expect("host");
    let port = event["remote"]["port"].as_u64().expect("port") as u16;
    SocketAddr::new(host.parse().expect("ip"), port)
}

fn firewalled_config(bootstrap: u64) -> HyperDhtConfig {
    let mut config = HyperDhtConfig::default();
    config.dht.bootstrap = vec![format!("127.0.0.1:{bootstrap}")];
    config.dht.port = 0;
    config.dht.firewalled = true;
    config.dht.quick_firewall = false;
    config
}

fn expected_byte(offset: usize) -> u8 {
    let within = offset % CHUNK;
    if within < 8 {
        ((offset / CHUNK) as u64 >> (within * 8)) as u8
    } else {
        within as u8
    }
}

fn chunk(index: usize) -> Vec<u8> {
    (0..CHUNK)
        .map(|i| expected_byte(index * CHUNK + i))
        .collect()
}

/// Send chunks and verify the echo until the stream has left `relay_addr`
/// (plus a tail) or `MAX_CHUNKS`; returns the bytes exchanged. The echo
/// must come back in order and in full across the move.
async fn pump_until_moved(mut conn: PeerConnection, relay_addr: SocketAddr) -> usize {
    let remote = conn.stream.remote_handle();
    let mut sent = 0;
    let mut received = 0;
    let mut tail = 0;
    while sent < MAX_CHUNKS {
        let left = remote.remote_addr().is_some_and(|addr| addr != relay_addr);
        if left {
            tail += 1;
        }
        if tail > 8 {
            break;
        }
        conn.stream.write(&chunk(sent)).await.expect("write");
        sent += 1;
        let data = conn.stream.read().await.expect("read").expect("chunk");
        for (i, &b) in data.iter().enumerate() {
            assert_eq!(b, expected_byte(received + i), "data corrupt across move");
        }
        received += data.len();
    }
    assert!(
        tail > 8,
        "stream did not carry the direct-path transfer tail"
    );
    conn.stream.shutdown().await.expect("shutdown");
    while let Some(data) = conn.stream.read().await.expect("tail read") {
        for (i, &b) in data.iter().enumerate() {
            assert_eq!(b, expected_byte(received + i));
        }
        received += data.len();
    }
    assert_eq!(received, sent * CHUNK, "echo lost or duplicated bytes");
    received
}

#[tokio::test]
async fn rust_swarm_client_moves_off_the_relay_mid_transfer_against_js_swarm_server() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    tokio::time::timeout(TEST_TIMEOUT, async {
        let (mut js, value) = JsPeer::start(&["swarm-server"])
            .await
            .expect("JS swarm server");
        let ready = ready(&value);

        let mut config = SwarmConfig::default();
        config.dht = firewalled_config(ready.port);
        config.local_connection = false;
        let (_task, handle, mut conn_rx) = spawn(config).await.expect("spawn Rust swarm");

        // Rust client uses join_peer to known JS server key (server advertises relay).
        handle.join_peer(ready.public_key).await.expect("join_peer");

        let conn = conn_rx.recv().await.expect("peer connected");
        assert_eq!(
            conn.peer.remote_addr,
            Some(ready.relay_addr),
            "the relay must land first"
        );
        let opened = js.read_json().await.expect("JS open");
        assert_eq!(js_remote(&opened), ready.relay_addr);

        let bytes = pump_until_moved(conn.peer, ready.relay_addr).await;
        let done = js.read_json().await.expect("JS done");
        assert_eq!(done["bytes"].as_u64(), Some(bytes as u64));
        assert_ne!(
            js_remote(&done),
            ready.relay_addr,
            "JS side still on the relay"
        );

        handle.destroy().await.expect("destroy");
        js.child.kill().await.expect("stop JS");
    })
    .await
    .expect("Rust -> JS swarm relay upgrade timed out");
}

#[tokio::test]
async fn js_swarm_client_moves_off_the_relay_mid_transfer_into_rust_swarm_server() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    tokio::time::timeout(TEST_TIMEOUT, async {
        let (mut js, value) = JsPeer::start(&["swarm-client"])
            .await
            .expect("JS swarm client");
        let ready = ready(&value);

        let mut config = SwarmConfig::default();
        config.dht = firewalled_config(ready.port);
        config.local_connection = false;
        let (_task, handle, mut conn_rx) = spawn(config).await.expect("spawn Rust swarm");
        handle.listen().await.expect("listen");

        // JS client offers relay to Rust swarm listen.
        js.input
            .write_all(format!("{}\n", hex::encode(handle.key_pair().public_key)).as_bytes())
            .await
            .expect("ask JS to dial");

        let mut conn = conn_rx
            .recv()
            .await
            .expect("server accepted the relayed client");
        assert_eq!(
            conn.peer.remote_addr,
            Some(ready.relay_addr),
            "the relay must land first"
        );
        let opened = js.read_json().await.expect("JS open");
        assert_eq!(js_remote(&opened), ready.relay_addr);

        let remote = conn.peer.stream.remote_handle();
        let mut echoed = 0u64;
        while let Some(data) = conn.peer.stream.read().await.expect("read") {
            echoed += data.len() as u64;
            conn.peer.stream.write(&data).await.expect("echo");
        }
        conn.peer.stream.shutdown().await.expect("shutdown");
        let done = js.read_json().await.expect("JS done");
        assert_eq!(done["ok"], true, "JS saw a corrupted echo");
        assert_eq!(done["bytes"].as_u64(), Some(echoed));
        assert_ne!(
            js_remote(&done),
            ready.relay_addr,
            "JS side still on the relay"
        );
        assert_ne!(
            remote.remote_addr(),
            Some(ready.relay_addr),
            "Rust side still on the relay"
        );

        handle.destroy().await.expect("destroy");
        js.child.kill().await.expect("stop JS");
    })
    .await
    .expect("JS -> Rust swarm relay upgrade timed out");
}
