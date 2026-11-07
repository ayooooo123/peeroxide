#![deny(clippy::all)]

//! Relay→direct upgrade (hyperdht `relayThrough`) against JS, both
//! directions. The relay pairs the peers long before the holepunch lands,
//! so the connection opens relayed, a bulk transfer starts, and the punch
//! moves the stream to the direct path mid-transfer (`changeRemote` +
//! `confirmDirectUpgrade`) without losing or duplicating a byte. A server
//! that refuses to punch leaves the stream on the relay.

use std::net::SocketAddr;
use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide_dht::hyperdht::{self, ConnectOpts, HyperDhtConfig, KeyPair, PeerConnection, ServerConfig};
use peeroxide_dht::hyperdht_messages::FIREWALL_UNKNOWN;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Child;

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
        let path = format!("{}/../tests/node/relay-upgrade-peer.js", env!("CARGO_MANIFEST_DIR"));
        let mut child = tokio::process::Command::new("node")
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
        Ok((Self { child, output, input }, ready))
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
    relay_key: [u8; 32],
    relay_addr: SocketAddr,
}

fn ready(value: &serde_json::Value) -> Ready {
    let key = |name: &str| -> [u8; 32] {
        hex::decode(value[name].as_str().expect(name)).expect("hex").try_into().expect("key length")
    };
    let host = value["relayAddr"]["host"].as_str().expect("relay host");
    let port = value["relayAddr"]["port"].as_u64().expect("relay port");
    Ready {
        port: value["port"].as_u64().expect("port"),
        public_key: key("publicKey"),
        relay_key: key("relayKey"),
        relay_addr: format!("{host}:{port}").parse().expect("relay addr"),
    }
}

fn js_remote(event: &serde_json::Value) -> SocketAddr {
    let host = event["remote"]["host"].as_str().expect("remote host");
    let port = event["remote"]["port"].as_u64().expect("remote port");
    format!("{host}:{port}").parse().expect("remote addr")
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

fn expected_byte(offset: usize) -> u8 {
    let within = offset % CHUNK;
    if within < 8 { ((offset / CHUNK) as u64 >> (within * 8)) as u8 } else { within as u8 }
}

fn chunk(index: usize) -> Vec<u8> {
    (0..CHUNK).map(|i| expected_byte(index * CHUNK + i)).collect()
}

/// Send chunks and verify the echo until the stream has left `relay_addr`
/// (plus a tail) or `MAX_CHUNKS`; returns the bytes exchanged. The echo
/// must come back in order and in full across the move.
async fn pump_until_moved(conn: PeerConnection, relay_addr: SocketAddr) -> usize {
    let remote = conn.stream.remote_handle();
    let (mut read_half, mut write_half) = conn.stream.into_split();
    let sender = tokio::spawn(async move {
        let mut sent = 0;
        let mut tail = 0;
        while sent < MAX_CHUNKS && tail <= 8 {
            if remote.remote_addr().is_some_and(|addr| addr != relay_addr) {
                tail += 1;
            }
            write_half.write(&chunk(sent)).await.expect("write chunk");
            sent += 1;
        }
        write_half.shutdown().await.expect("shutdown");
        (sent, write_half)
    });
    let mut received = 0usize;
    while let Some(data) = read_half.read().await.expect("read echo") {
        for (i, byte) in data.iter().enumerate() {
            assert_eq!(*byte, expected_byte(received + i), "echo diverged at byte {}", received + i);
        }
        received += data.len();
    }
    let (sent, _write_half) = sender.await.expect("sender");
    assert_eq!(received, sent * CHUNK, "echo lost or duplicated bytes");
    assert!(sent < MAX_CHUNKS, "stream never moved off the relay");
    received
}

#[tokio::test]
async fn rust_client_moves_off_the_relay_mid_transfer_against_a_js_server() {
    let _ = tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).try_init();
    tokio::time::timeout(TEST_TIMEOUT, async {
        let (mut js, value) = JsPeer::start(&["server"]).await.expect("JS server");
        let ready = ready(&value);

        let runtime = UdxRuntime::new().expect("runtime");
        let (_task, dht, _events) =
            hyperdht::spawn(&runtime, firewalled_config(ready.port)).await.expect("DHT");
        dht.fully_bootstrapped().await.expect("bootstrapped");

        let keys = KeyPair::generate();
        let mut opts = ConnectOpts::default();
        opts.relay_through = Some(ready.relay_key);
        opts.local_connection = false;
        let conn = dht
            .connect_with_options(&keys, ready.public_key, &[], &runtime, opts)
            .await
            .expect("relayed connect");
        assert_eq!(conn.remote_addr, Some(ready.relay_addr), "the relay must land first");
        let opened = js.read_json().await.expect("JS open");
        assert_eq!(js_remote(&opened), ready.relay_addr);

        let bytes = pump_until_moved(conn, ready.relay_addr).await;
        let done = js.read_json().await.expect("JS done");
        assert_eq!(done["bytes"].as_u64(), Some(bytes as u64));
        assert_ne!(js_remote(&done), ready.relay_addr, "JS side still on the relay");

        dht.destroy().await.expect("destroy");
        js.child.kill().await.expect("stop JS");
    })
    .await
    .expect("Rust -> JS relay upgrade timed out");
}

#[tokio::test]
async fn rust_client_stays_relayed_when_the_js_server_refuses_to_punch() {
    let _ = tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).try_init();
    tokio::time::timeout(TEST_TIMEOUT, async {
        let (mut js, value) = JsPeer::start(&["server", "--no-punch"]).await.expect("JS server");
        let ready = ready(&value);

        let runtime = UdxRuntime::new().expect("runtime");
        let (_task, dht, _events) =
            hyperdht::spawn(&runtime, firewalled_config(ready.port)).await.expect("DHT");
        dht.fully_bootstrapped().await.expect("bootstrapped");

        let keys = KeyPair::generate();
        let mut opts = ConnectOpts::default();
        opts.relay_through = Some(ready.relay_key);
        opts.local_connection = false;
        let mut conn = dht
            .connect_with_options(&keys, ready.public_key, &[], &runtime, opts)
            .await
            .expect("relayed connect");
        assert_eq!(conn.remote_addr, Some(ready.relay_addr));
        let _opened = js.read_json().await.expect("JS open");

        // Short, so the aborted punch has settled before the transfer ends.
        let remote = conn.stream.remote_handle();
        let mut received = 0;
        for i in 0..64 {
            conn.stream.write(&chunk(i)).await.expect("write");
            let data = conn.stream.read().await.expect("read").expect("echo");
            assert_eq!(data, chunk(i));
            received += data.len();
            if i == 32 {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
        assert_eq!(remote.remote_addr(), Some(ready.relay_addr), "left the relay without a punch");
        conn.stream.shutdown().await.expect("shutdown");
        let done = js.read_json().await.expect("JS done");
        assert_eq!(done["bytes"].as_u64(), Some(received as u64));
        assert_eq!(js_remote(&done), ready.relay_addr);

        dht.destroy().await.expect("destroy");
        js.child.kill().await.expect("stop JS");
    })
    .await
    .expect("stays-relayed test timed out");
}

#[tokio::test]
async fn js_client_moves_off_the_relay_mid_transfer_into_a_rust_server() {
    let _ = tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).try_init();
    tokio::time::timeout(TEST_TIMEOUT, async {
        let (mut js, value) = JsPeer::start(&["client"]).await.expect("JS client");
        let ready = ready(&value);

        let runtime = UdxRuntime::new().expect("runtime");
        let (_task, dht, events) =
            hyperdht::spawn(&runtime, firewalled_config(ready.port)).await.expect("DHT");
        dht.fully_bootstrapped().await.expect("bootstrapped");

        let keys = KeyPair::generate();
        let mut server = dht.create_server(&runtime, ServerConfig::new(keys.clone(), FIREWALL_UNKNOWN), events);
        server.listen(&keys).await.expect("listen");
        js.input
            .write_all(format!("{}\n", hex::encode(keys.public_key)).as_bytes())
            .await
            .expect("ask JS to dial");

        let mut accepted = server.accept().await.expect("server accepted the relayed client");
        assert_eq!(accepted.remote_addr, Some(ready.relay_addr), "the relay must land first");
        let opened = js.read_json().await.expect("JS open");
        assert_eq!(js_remote(&opened), ready.relay_addr);

        let remote = accepted.stream.remote_handle();
        let mut echoed = 0u64;
        while let Some(data) = accepted.stream.read().await.expect("read") {
            echoed += data.len() as u64;
            accepted.stream.write(&data).await.expect("echo");
        }
        accepted.stream.shutdown().await.expect("shutdown");
        let done = js.read_json().await.expect("JS done");
        assert_eq!(done["ok"], true, "JS saw a corrupted echo");
        assert_eq!(done["bytes"].as_u64(), Some(echoed));
        assert_ne!(js_remote(&done), ready.relay_addr, "JS side still on the relay");
        assert_ne!(remote.remote_addr(), Some(ready.relay_addr), "Rust side still on the relay");

        server.close().await;
        dht.destroy().await.expect("destroy");
        js.child.kill().await.expect("stop JS");
    })
    .await
    .expect("JS -> Rust relay upgrade timed out");
}
