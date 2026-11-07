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
use peeroxide_dht::hyperdht::{self, HyperDhtConfig, HyperDhtError, KeyPair, ServerConfig};
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

/// A node that keeps its firewalled role, so requests leave from the client
/// socket (whose port `resume` rebinds).
fn firewalled_local_config() -> HyperDhtConfig {
    let mut config = local_config(vec![]);
    config.dht.firewalled = true;
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

/// dht-rpc's `io.resume()` falls back to an ephemeral port when the previous
/// client port is taken by a stream that outlived the suspend.
#[tokio::test]
async fn resume_falls_back_when_the_client_port_is_taken() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let runtime = UdxRuntime::new().expect("runtime");
        let (_task, node, _events) = hyperdht::spawn(&runtime, firewalled_local_config())
            .await
            .expect("node");
        node.fully_bootstrapped().await.expect("bootstrapped");

        let watcher = runtime.create_socket().await.expect("socket");
        watcher.bind("127.0.0.1:0".parse().unwrap()).await.expect("bind");
        let watcher_port = watcher.local_addr().await.expect("addr").port();
        let mut seen = watcher.recv_start().expect("recv");

        // A firewalled node sends from its client socket, so the datagram
        // source is the port `resume()` will try to rebind.
        assert!(node
            .dht()
            .request(short_request(), "127.0.0.1", watcher_port)
            .await
            .is_err());
        let client_addr = next_datagram(&mut seen).await.expect("no client datagram").addr;

        node.suspend().await.expect("suspend");

        // Stand in for a stream that kept the old client port alive.
        let squatter = runtime.create_socket().await.expect("squatter");
        squatter.bind(client_addr).await.expect("squatter bind");

        node.resume().await.expect("resume with the client port taken");

        // The client socket moved to an ephemeral port and still works.
        while seen.try_recv().is_ok() {}
        assert!(node
            .dht()
            .request(short_request(), "127.0.0.1", watcher_port)
            .await
            .is_err());
        let after = next_datagram(&mut seen).await.expect("no datagram after resume").addr;
        assert_ne!(after.port(), client_addr.port(), "client socket kept the squatted port");

        node.destroy().await.expect("destroy");
    })
    .await
    .expect("client-port fallback timed out");
}

/// Connections opened through `connect()` are in the DHT's raw-stream set, so
/// `suspend()` closes them: the caller reads EOF and the peer sees the DESTROY.
#[tokio::test]
async fn suspend_closes_connections_made_by_connect() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let runtime = UdxRuntime::new().expect("runtime");

        let (_a_task, a, a_events) = hyperdht::spawn(&runtime, local_config(vec![]))
            .await
            .expect("server node");
        a.fully_bootstrapped().await.expect("server bootstrapped");
        let server_keys = KeyPair::generate();
        let mut server = a.create_server(
            &runtime,
            ServerConfig::new(server_keys.clone(), FIREWALL_OPEN),
            a_events,
        );
        server.listen(&server_keys).await.expect("listen");
        let advertised = server.address().expect("server address");
        let address = SocketAddr::new(advertised.host.parse().unwrap(), advertised.port);

        let (_b_task, b, _b_events) = hyperdht::spawn(&runtime, local_config(vec![]))
            .await
            .expect("client node");
        b.fully_bootstrapped().await.expect("client bootstrapped");
        let client_keys = KeyPair::generate();
        let mut client = b
            .connect_to(&client_keys, server_keys.public_key, address, &runtime)
            .await
            .expect("connect");
        client.stream.write(b"hello").await.expect("write");
        let mut accepted = server.accept().await.expect("accepted");
        assert_eq!(accepted.stream.read().await.expect("read"), Some(b"hello".to_vec()));

        b.suspend().await.expect("suspend");

        let closed = tokio::time::timeout(Duration::from_secs(2), client.stream.read())
            .await
            .expect("client stream outlived the suspend");
        assert!(matches!(closed, Ok(None) | Err(_)), "got {closed:?}");

        let peer_closed = tokio::time::timeout(Duration::from_secs(5), accepted.stream.read())
            .await
            .expect("server stream stayed open after the suspend");
        assert!(matches!(peer_closed, Ok(None) | Err(_)), "got {peer_closed:?}");

        server.close().await;
        b.destroy().await.expect("client destroy");
        a.destroy().await.expect("server destroy");
    })
    .await
    .expect("connect suspend timed out");
}

/// Suspending during bootstrap fails every `fully_bootstrapped()` waiter with
/// `Suspended`, and resuming restarts the bootstrap so later waiters resolve.
#[tokio::test]
async fn suspend_fails_bootstrap_waiters_and_resume_retries() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let runtime = UdxRuntime::new().expect("runtime");

        // A plain socket that never answers: the only bootstrap node.
        let watcher = runtime.create_socket().await.expect("socket");
        watcher.bind("127.0.0.1:0".parse().unwrap()).await.expect("bind");
        let watcher_port = watcher.local_addr().await.expect("addr").port();
        let mut seen = watcher.recv_start().expect("recv");

        let (_task, node, _events) = hyperdht::spawn(
            &runtime,
            local_config(vec![format!("127.0.0.1:{watcher_port}")]),
        )
        .await
        .expect("node");

        let waiting = tokio::spawn({
            let node = node.clone();
            async move { node.fully_bootstrapped().await }
        });

        // The bootstrap query is on the wire when the suspend lands.
        assert!(next_datagram(&mut seen).await.is_some(), "no bootstrap datagram");

        node.suspend().await.expect("suspend");

        let outcome = tokio::time::timeout(Duration::from_secs(2), waiting)
            .await
            .expect("bootstrap waiter outlived the suspend")
            .expect("task");
        assert!(
            matches!(outcome, Err(HyperDhtError::Dht(DhtError::Suspended))),
            "got {outcome:?}"
        );

        node.resume().await.expect("resume");
        tokio::time::timeout(Duration::from_secs(10), node.fully_bootstrapped())
            .await
            .expect("bootstrap did not restart after the resume")
            .expect("bootstrapped after resume");

        node.destroy().await.expect("destroy");
    })
    .await
    .expect("bootstrap suspend timed out");
}
