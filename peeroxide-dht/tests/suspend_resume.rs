#![deny(clippy::all)]

//! DHT suspend/resume parity with dht-rpc `io.suspend()` / `io.resume()` and
//! hyperdht `HyperDHT#suspend()` / `#resume()`.
//!
//! - A suspended node sends nothing: its sockets are closed, in-flight
//!   requests fail with `IO_SUSPENDED`, and a third socket addressed by the
//!   node receives no datagrams for the whole suspended window.
//! - Resuming rebinds the server socket on its previous port, so a server
//!   listening before the suspend is still reachable afterwards, and pings,
//!   lookups and connections work again.

use std::net::SocketAddr;
use std::time::Duration;

use libudx::{Datagram, UdxRuntime};
use peeroxide_dht::hyperdht::{self, HyperDhtConfig, KeyPair, ServerConfig};
use peeroxide_dht::hyperdht_messages::FIREWALL_OPEN;
use peeroxide_dht::messages::Command;
use peeroxide_dht::rpc::{DhtError, UserRequestParams};
use tokio::sync::mpsc;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn local_config(bootstrap: Vec<String>) -> HyperDhtConfig {
    let mut config = HyperDhtConfig::default();
    config.dht.host = "127.0.0.1".to_string();
    config.dht.port = 0;
    config.dht.bootstrap = bootstrap;
    config.dht.ephemeral = Some(false);
    config.dht.firewalled = false;
    // On loopback every port is reachable; keep the node's advertised role
    // fixed instead of letting the firewall self-check flip it.
    config.dht.quick_firewall = false;
    config
}

/// A DHT request with a short timeout so a request to a plain (non-DHT)
/// socket returns promptly while still putting bytes on the wire.
fn short_request() -> UserRequestParams {
    let mut params = UserRequestParams::default();
    params.command = Command::Ping as u64;
    params.timeout_ms = Some(120);
    params.retries = Some(0);
    params
}

async fn next_datagram(rx: &mut mpsc::UnboundedReceiver<Datagram>) -> Option<Datagram> {
    tokio::time::timeout(Duration::from_millis(500), rx.recv())
        .await
        .ok()
        .flatten()
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(250)).await;
}

#[tokio::test]
async fn suspend_silences_the_node_and_resume_restores_it() {
    let _ = tokio::time::timeout(TEST_TIMEOUT, run()).await.expect("suspend/resume timed out");
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = UdxRuntime::new()?;

    let (_bootstrap_task, bootstrap, _bootstrap_events) =
        hyperdht::spawn(&runtime, local_config(vec![])).await?;
    bootstrap.fully_bootstrapped().await?;
    let bootstrap_port = bootstrap.local_port().await?;

    let (_node_task, node, node_events) = hyperdht::spawn(
        &runtime,
        local_config(vec![format!("127.0.0.1:{bootstrap_port}")]),
    )
    .await?;
    node.fully_bootstrapped().await?;

    // A server listening before the suspend, on the node's advertised port.
    let server_keys = KeyPair::generate();
    let mut server = node.create_server(
        &runtime,
        ServerConfig::new(server_keys.clone(), FIREWALL_OPEN),
        node_events,
    );
    server.listen(&server_keys).await?;
    let advertised = server.address().expect("server address");
    let address = SocketAddr::new(advertised.host.parse()?, advertised.port);

    // A third socket that is not a DHT node: requests addressed to it are
    // never answered, so it only counts what the node puts on the wire.
    let watcher = runtime.create_socket().await?;
    watcher.bind("127.0.0.1:0".parse()?).await?;
    let watcher_port = watcher.local_addr().await?.port();
    let mut seen = watcher.recv_start()?;

    // Baseline: while running, the node's request reaches the watcher.
    assert!(node
        .dht()
        .request(short_request(), "127.0.0.1", watcher_port)
        .await
        .is_err());
    assert!(next_datagram(&mut seen).await.is_some(), "no baseline datagram");

    // ── Suspend ──────────────────────────────────────────────────────────
    node.suspend().await?;
    while seen.try_recv().is_ok() {}
    settle().await;
    assert!(seen.try_recv().is_err(), "datagram while suspended");

    // Every request path fails the way dht-rpc's IO_SUSPENDED does.
    let refused = node
        .dht()
        .request(short_request(), "127.0.0.1", watcher_port)
        .await;
    assert!(matches!(refused, Err(DhtError::Suspended)), "got {refused:?}");
    let lookup = node.lookup([7u8; 32]).await;
    assert!(lookup.is_err(), "lookup ran while suspended");
    let ping = bootstrap.dht().ping("127.0.0.1", address.port()).await;
    assert!(ping.is_err(), "suspended server answered a ping");
    settle().await;
    assert!(seen.try_recv().is_err(), "datagram after a refused request");

    // ── Resume ───────────────────────────────────────────────────────────
    node.resume().await?;

    // The server socket kept its port, so the pre-suspend address dials.
    let client_keys = KeyPair::generate();
    let mut client = bootstrap
        .connect_to(&client_keys, server_keys.public_key, address, &runtime)
        .await?;
    client.stream.write(b"after-resume").await?;
    let mut accepted = server.accept().await.expect("server accepted after resume");
    assert_eq!(accepted.stream.read().await?, Some(b"after-resume".to_vec()));
    accepted.stream.write(b"pong").await?;
    assert_eq!(client.stream.read().await?, Some(b"pong".to_vec()));

    // Queries work again.
    let pong = node.dht().ping("127.0.0.1", bootstrap_port).await?;
    assert!(pong.id.is_some());
    node.lookup([9u8; 32]).await?;

    server.close().await;
    node.destroy().await?;
    bootstrap.destroy().await?;
    Ok(())
}

/// A query that is in flight when the suspend lands fails with `Suspended`
/// and stops retransmitting.
#[tokio::test]
async fn suspend_fails_inflight_queries() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let runtime = UdxRuntime::new().expect("runtime");
        let (_task, node, _events) = hyperdht::spawn(&runtime, local_config(vec![]))
            .await
            .expect("node");
        node.fully_bootstrapped().await.expect("bootstrapped");

        let watcher = runtime.create_socket().await.expect("socket");
        watcher.bind("127.0.0.1:0".parse().unwrap()).await.expect("bind");
        let watcher_port = watcher.local_addr().await.expect("addr").port();
        let mut seen = watcher.recv_start().expect("recv");
        while seen.try_recv().is_ok() {}

        let mut params = short_request();
        params.timeout_ms = Some(5_000);
        params.retries = Some(5);
        let dht = node.dht().clone();
        let pending =
            tokio::spawn(async move { dht.request(params, "127.0.0.1", watcher_port).await });

        // Let the first transmission go out, then suspend under it.
        assert!(next_datagram(&mut seen).await.is_some());
        node.suspend().await.expect("suspend");

        let outcome = tokio::time::timeout(Duration::from_secs(2), pending)
            .await
            .expect("in-flight request did not fail")
            .expect("task");
        assert!(matches!(outcome, Err(DhtError::Suspended)), "got {outcome:?}");

        while seen.try_recv().is_ok() {}
        settle().await;
        assert!(seen.try_recv().is_err(), "retransmit while suspended");

        node.destroy().await.expect("destroy");
    })
    .await
    .expect("in-flight suspend timed out");
}
