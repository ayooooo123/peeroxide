#![deny(clippy::all)]

//! Node-parity tests for the HyperDHT server surface — `createServer` /
//! `listen` / `address` / `suspend` / `resume` / `close` — and for the
//! secret-stream connection type returned by `connect`.
//!
//! Everything runs on 127.0.0.1 with no bootstrap nodes: the client dials the
//! server's advertised address directly, exercising the real Noise IK
//! handshake, the reply encoding, the UDX accept path and SecretStream
//! framing end to end.

use std::net::SocketAddr;
use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide_dht::crypto::hash;
use peeroxide_dht::hyperdht::{
    HyperDhtConfig, HyperDhtError, HyperDhtHandle, KeyPair, PeerConnection, ServerAddress,
    ServerConfig, ServerEvent, spawn,
};
use peeroxide_dht::hyperdht_messages::FIREWALL_UNKNOWN;
use tokio::sync::mpsc;

const TEST_TIMEOUT: Duration = Duration::from_secs(20);

fn local_config() -> HyperDhtConfig {
    let mut config = HyperDhtConfig::default();
    config.dht.host = "127.0.0.1".to_string();
    config.dht.ephemeral = Some(false);
    config.dht.firewalled = false;
    config
}

struct LocalNode {
    _task: tokio::task::JoinHandle<Result<(), HyperDhtError>>,
    handle: HyperDhtHandle,
    runtime: UdxRuntime,
}

async fn local_node() -> Result<(LocalNode, mpsc::UnboundedReceiver<ServerEvent>), HyperDhtError> {
    let runtime = UdxRuntime::new()?;
    let (task, handle, events) = spawn(&runtime, local_config()).await?;
    Ok((
        LocalNode {
            _task: task,
            handle,
            runtime,
        },
        events,
    ))
}

async fn dial(
    node: &LocalNode,
    key_pair: &KeyPair,
    remote: &KeyPair,
    address: &ServerAddress,
) -> Result<PeerConnection, HyperDhtError> {
    let ip = address
        .host
        .parse()
        .map_err(|_| HyperDhtError::HandshakeFailed(format!("bad host {}", address.host)))?;
    node.handle
        .connect_to(
            key_pair,
            remote.public_key,
            SocketAddr::new(ip, address.port),
            &node.runtime,
        )
        .await
}

/// `listen` publishes the target and the dial-able address, `connect` yields
/// the initiator's secret stream, `accept` yields the server's, and payloads
/// cross both ways.
async fn run_listen_accept_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let (server_node, server_events) = local_node().await?;
    let (client_node, _client_events) = local_node().await?;

    let server_keys = KeyPair::generate();
    let mut server = server_node.handle.create_server(
        &server_node.runtime,
        ServerConfig::new(server_keys.clone(), FIREWALL_UNKNOWN),
        server_events,
    );

    assert!(!server.listening());
    assert!(server.address().is_none());
    assert!(server.public_key().is_none());

    server.listen(&server_keys).await?;
    assert!(server.listening());
    assert_eq!(server.public_key(), Some(server_keys.public_key));
    assert_eq!(server.target(), Some(hash(&server_keys.public_key)));
    assert!(matches!(
        server.listen(&server_keys).await,
        Err(HyperDhtError::AlreadyListening)
    ));

    let address = server.address().expect("address after listen");
    assert_eq!(address.public_key, server_keys.public_key);
    assert_eq!(address.host, "127.0.0.1");
    assert_ne!(address.port, 0);

    let client_keys = KeyPair::generate();
    let mut client = dial(&client_node, &client_keys, &server_keys, &address).await?;
    assert!(client.is_initiator());
    assert_eq!(client.remote_public_key, server_keys.public_key);
    assert!(client.remote_addr.is_some());

    let mut accepted = server.accept().await.expect("server accepted connection");
    assert!(!accepted.is_initiator());
    assert_eq!(accepted.remote_public_key, client_keys.public_key);

    client.stream.write(b"ping").await?;
    assert_eq!(accepted.stream.read().await?, Some(b"ping".to_vec()));
    accepted.stream.write(b"pong").await?;
    assert_eq!(client.stream.read().await?, Some(b"pong".to_vec()));

    server.close().await;
    assert!(!server.listening());
    assert!(server.address().is_none());
    assert!(server.public_key().is_none());
    assert!(server.accept().await.is_none());

    Ok(())
}

/// A suspended server drops handshakes without touching its DHT; resuming
/// makes the same address accept again.
async fn run_suspend_resume() -> Result<(), Box<dyn std::error::Error>> {
    let (server_node, server_events) = local_node().await?;
    let (client_node, _client_events) = local_node().await?;

    let server_keys = KeyPair::generate();
    let mut server = server_node.handle.create_server(
        &server_node.runtime,
        ServerConfig::new(server_keys.clone(), FIREWALL_UNKNOWN),
        server_events,
    );
    server.listen(&server_keys).await?;
    let address = server.address().expect("address after listen");

    server.suspend().await?;
    let blocked = dial(&client_node, &KeyPair::generate(), &server_keys, &address).await;
    assert!(
        blocked.is_err(),
        "a suspended server must not complete a handshake"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(500), server.accept())
            .await
            .is_err(),
        "a suspended server must not hand out connections"
    );

    server.resume().await?;
    let client_keys = KeyPair::generate();
    let mut client = dial(&client_node, &client_keys, &server_keys, &address).await?;
    let mut accepted = server.accept().await.expect("accepted after resume");
    assert_eq!(accepted.remote_public_key, client_keys.public_key);

    client.stream.write(b"resumed").await?;
    assert_eq!(accepted.stream.read().await?, Some(b"resumed".to_vec()));

    Ok(())
}

#[tokio::test]
async fn server_listen_address_and_accept_roundtrip() {
    let _ = tracing_subscriber::fmt::try_init();
    match tokio::time::timeout(TEST_TIMEOUT, run_listen_accept_roundtrip()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("server roundtrip failed: {e}"),
        Err(_) => panic!("server roundtrip timed out"),
    }
}

#[tokio::test]
async fn server_suspend_resume() {
    let _ = tracing_subscriber::fmt::try_init();
    match tokio::time::timeout(TEST_TIMEOUT, run_suspend_resume()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("suspend/resume failed: {e}"),
        Err(_) => panic!("suspend/resume timed out"),
    }
}

#[tokio::test]
async fn two_servers_share_one_dht() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let (server_node, _events) = local_node().await.expect("server node");
        let (client_node, _events) = local_node().await.expect("client node");
        let first_key = KeyPair::generate();
        let second_key = KeyPair::generate();
        let mut first = server_node.handle.create_shared_server(
            &server_node.runtime,
            ServerConfig::new(first_key.clone(), FIREWALL_UNKNOWN),
        );
        let mut second = server_node.handle.create_shared_server(
            &server_node.runtime,
            ServerConfig::new(second_key.clone(), FIREWALL_UNKNOWN),
        );
        first.listen(&first_key).await.expect("first listen");
        second.listen(&second_key).await.expect("second listen");
        let client_key = KeyPair::generate();
        let mut connection = dial(
            &client_node,
            &client_key,
            &second_key,
            &second.address().unwrap(),
        )
        .await
        .expect("dial second");
        let mut accepted = second.accept().await.expect("second accept");
        connection.stream.write(b"second").await.expect("write");
        assert_eq!(
            accepted.stream.read().await.expect("read"),
            Some(b"second".to_vec())
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), first.accept())
                .await
                .is_err()
        );
        first.close().await;
        second.close().await;
    })
    .await
    .expect("shared servers timed out");
}
