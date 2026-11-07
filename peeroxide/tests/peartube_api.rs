//! Public swarm API used by PearTube: `listen`, `join_peer`, `leave_peer`,
//! `suspend`, `resume` and `destroy_with_force`, checked against the installed
//! `hyperswarm` JS semantics.
//!
//! - `listen_registers_and_announces_without_a_topic`: Node `listen()` starts
//!   the DHT server for `hash(public_key)` and announces that key, so a peer
//!   that knows only the key can find it. Calling it twice is a no-op.
//! - `join_peer_connects_and_moves_data_without_a_topic`: Node `joinPeer()`
//!   dials a peer without any topic join.
//! - `leave_peer_keeps_an_established_connection`: Node `leavePeer()` only
//!   clears the explicit flag; unknown peers are ignored and the stream stays
//!   open.
//! - `suspend_queues_explicit_peers_until_resume`: Node `suspend()` stops the
//!   dials but keeps the queue; `resume()` drains it.
//! - `suspend_defers_topic_discovery_until_resume`: a topic joined while
//!   suspended is announced only after `resume()`.
//! - `destroy_with_force_stops_the_swarm`: both destroy variants unregister
//!   the server and leave the handle reporting `Destroyed`.

use std::time::Duration;

use libudx::UdxRuntime;
use peeroxide::{JoinOpts, SwarmConfig, SwarmConnection, SwarmError, spawn as spawn_swarm};
use peeroxide_dht::crypto::hash;
use peeroxide_dht::hyperdht::{HyperDhtConfig, spawn};
use peeroxide_dht::rpc::DhtConfig;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

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
        dht.ephemeral = Some(false);
    }
    let mut config = HyperDhtConfig::default();
    config.dht = dht;
    config
}

type SwarmParts = (
    JoinHandle<()>,
    peeroxide::SwarmHandle,
    mpsc::Receiver<SwarmConnection>,
);

/// A local testnet: one bootstrap node plus three reachable nodes that store
/// announce records, so topic lookups and `hash(pk)` lookups both resolve.
struct Testnet {
    _rt: UdxRuntime,
    _bootstrap: peeroxide_dht::hyperdht::HyperDhtHandle,
    _nodes: Vec<peeroxide_dht::hyperdht::HyperDhtHandle>,
    _joins: Vec<JoinHandle<Result<(), peeroxide_dht::hyperdht::HyperDhtError>>>,
    addrs: Vec<String>,
}

impl Testnet {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let rt = UdxRuntime::new()?;
        let (bs_join, bootstrap, _bs_rx) = spawn(&rt, local_dht(vec![], false)).await?;
        let addrs = vec![format!("127.0.0.1:{}", bootstrap.local_port().await?)];

        let mut nodes = Vec::new();
        let mut joins = vec![bs_join];
        for _ in 0..3 {
            let (join, node, _rx) = spawn(&rt, local_dht(addrs.clone(), false)).await?;
            node.bootstrapped().await?;
            nodes.push(node);
            joins.push(join);
        }

        Ok(Self {
            _rt: rt,
            _bootstrap: bootstrap,
            _nodes: nodes,
            _joins: joins,
            addrs,
        })
    }

    async fn swarm(&self) -> Result<SwarmParts, Box<dyn std::error::Error>> {
        // Reachable nodes: this testnet exercises the swarm handle API, not
        // NAT traversal. A reachable server answers a forwarded handshake
        // with the direct (Listen) path, so the dialling peer connects without
        // a holepunch; the firewalled/holepunch paths have their own tests.
        let mut config = SwarmConfig::default();
        config.dht = local_dht(self.addrs.clone(), false);
        Ok(spawn_swarm(config).await?)
    }
}

async fn with_timeout<F>(what: &str, fut: F)
where
    F: Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    match tokio::time::timeout(Duration::from_secs(60), fut).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("{what} failed: {e}"),
        Err(_) => panic!("{what} timed out after 60s"),
    }
}

async fn next_conn(rx: &mut mpsc::Receiver<SwarmConnection>, what: &str) -> SwarmConnection {
    tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
        .unwrap_or_else(|| panic!("{what}: connection channel closed"))
}

async fn no_conn_within(rx: &mut mpsc::Receiver<SwarmConnection>, what: &str, wait: Duration) {
    if tokio::time::timeout(wait, rx.recv()).await.is_ok() {
        panic!("{what}: an unexpected connection was delivered");
    }
}

async fn wait_for<T>(
    what: &str,
    mut probe: impl AsyncFnMut() -> Option<T>,
) -> Result<T, Box<dyn std::error::Error>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(v) = probe().await {
            return Ok(v);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("timed out waiting for {what}").into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `true` when some lookup reply for `target` advertises `pk`.
async fn lookup_contains(
    dht: &peeroxide_dht::hyperdht::HyperDhtHandle,
    target: [u8; 32],
    pk: [u8; 32],
) -> bool {
    match dht.lookup(target).await {
        Ok(results) => results
            .iter()
            .flat_map(|r| r.peers.iter())
            .any(|p| p.public_key == pk),
        Err(_) => false,
    }
}

#[tokio::test]
async fn listen_registers_and_announces_without_a_topic() {
    with_timeout("listen", async {
        let net = Testnet::start().await?;
        let (_task, swarm, _rx) = net.swarm().await?;
        let pk = swarm.key_pair().public_key;

        swarm.listen().await?;
        // Idempotent, as Node's `listen()` is once `this.listening` is set.
        swarm.listen().await?;

        let target = hash(&pk);
        {
            let router = swarm.dht().router().lock().unwrap();
            assert!(
                router.get(&target).is_some(),
                "listen() must register the DHT server for hash(public_key)"
            );
        }

        let (_looker_task, looker, _looker_rx) = net.swarm().await?;
        wait_for("the listening swarm's announce", || async {
            lookup_contains(looker.dht(), target, pk)
                .await
                .then_some(())
        })
        .await?;

        swarm.destroy().await?;
        looker.destroy().await?;
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn join_peer_connects_and_moves_data_without_a_topic() {
    with_timeout("join_peer", async {
        let net = Testnet::start().await?;
        let (_server_task, server, mut server_conns) = net.swarm().await?;
        server.listen().await?;
        let server_pk = server.key_pair().public_key;

        let (_client_task, client, mut client_conns) = net.swarm().await?;

        // Our own key is not a peer, as Node's `_upsertPeer` skips it.
        client.join_peer(client.key_pair().public_key).await?;

        client.join_peer(server_pk).await?;

        let mut server_conn = next_conn(&mut server_conns, "the server side").await;
        let mut client_conn = next_conn(&mut client_conns, "the client side").await;

        assert_eq!(client_conn.remote_public_key(), &server_pk);
        assert_eq!(
            server_conn.remote_public_key(),
            &client.key_pair().public_key
        );
        assert!(client_conn.is_initiator, "the joining peer dials");
        assert!(!server_conn.is_initiator);
        assert!(
            client_conn.topics.is_empty(),
            "joinPeer does not attach a topic"
        );

        server_conn.peer.stream.write(b"ping").await?;
        let got = tokio::time::timeout(Duration::from_secs(10), client_conn.peer.stream.read())
            .await
            .map_err(|_| "timed out reading on the joining peer")??
            .ok_or("client stream closed before data")?;
        assert_eq!(got, b"ping");

        client_conn.peer.stream.write(b"pong").await?;
        let got = tokio::time::timeout(Duration::from_secs(10), server_conn.peer.stream.read())
            .await
            .map_err(|_| "timed out reading on the listening peer")??
            .ok_or("server stream closed before data")?;
        assert_eq!(got, b"pong");

        server.destroy().await?;
        client.destroy().await?;
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn leave_peer_keeps_an_established_connection() {
    with_timeout("leave_peer", async {
        let net = Testnet::start().await?;
        let (_server_task, server, mut server_conns) = net.swarm().await?;
        server.listen().await?;
        let server_pk = server.key_pair().public_key;

        let (_client_task, client, mut client_conns) = net.swarm().await?;
        client.join_peer(server_pk).await?;

        let mut server_conn = next_conn(&mut server_conns, "the server side").await;
        let mut client_conn = next_conn(&mut client_conns, "the client side").await;

        // An unknown peer is ignored, as in Node.
        client.leave_peer([0xEE; 32]).await?;
        client.leave_peer(server_pk).await?;

        server_conn.peer.stream.write(b"still here").await?;
        let got = tokio::time::timeout(Duration::from_secs(10), client_conn.peer.stream.read())
            .await
            .map_err(|_| "timed out reading after leavePeer")??
            .ok_or("leavePeer closed the established stream")?;
        assert_eq!(got, b"still here");

        server.destroy().await?;
        client.destroy().await?;
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn suspend_queues_explicit_peers_until_resume() {
    with_timeout("suspend/resume explicit peer", async {
        let net = Testnet::start().await?;
        let (_server_task, server, mut server_conns) = net.swarm().await?;
        server.listen().await?;
        let server_pk = server.key_pair().public_key;

        let (_client_task, client, mut client_conns) = net.swarm().await?;
        client.suspend().await?;
        client.suspend().await?; // idempotent, as in Node

        client.join_peer(server_pk).await?;

        no_conn_within(
            &mut client_conns,
            "a suspended swarm",
            Duration::from_secs(2),
        )
        .await;
        no_conn_within(
            &mut server_conns,
            "a peer of a suspended swarm",
            Duration::from_secs(2),
        )
        .await;

        client.resume().await?;
        client.resume().await?; // idempotent, as in Node

        next_conn(&mut client_conns, "the connection queued during suspend").await;

        server.destroy().await?;
        client.destroy().await?;
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn suspend_defers_topic_discovery_until_resume() {
    with_timeout("suspend/resume topic discovery", async {
        let net = Testnet::start().await?;
        let topic = [0x7c; 32];

        let (_server_task, server, _server_rx) = net.swarm().await?;
        let server_pk = server.key_pair().public_key;
        server
            .join(topic, {
                let mut opts = JoinOpts::default();
                opts.client = false;
                opts
            })
            .await?;
        server.flush().await?;

        let (_looker_task, looker, _looker_rx) = net.swarm().await?;
        wait_for("the server's topic announce", || async {
            lookup_contains(looker.dht(), topic, server_pk)
                .await
                .then_some(())
        })
        .await?;

        let (_client_task, client, _client_rx) = net.swarm().await?;
        let client_pk = client.key_pair().public_key;
        client.suspend().await?;
        client.join(topic, JoinOpts::default()).await?;

        // A join while suspended must not announce anything.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            !lookup_contains(looker.dht(), topic, client_pk).await,
            "a topic joined while suspended must not be announced"
        );

        client.resume().await?;
        wait_for("the client's topic announce after resume", || async {
            lookup_contains(looker.dht(), topic, client_pk)
                .await
                .then_some(())
        })
        .await?;
        client.flush().await?;

        server.destroy().await?;
        client.destroy().await?;
        looker.destroy().await?;
        Ok(())
    })
    .await;
}

#[tokio::test]
async fn destroy_with_force_stops_the_swarm() {
    with_timeout("destroy", async {
        let net = Testnet::start().await?;

        let (task, swarm, _rx) = net.swarm().await?;
        let target = hash(&swarm.key_pair().public_key);
        swarm.listen().await?;

        swarm.destroy_with_force(true).await?;
        assert!(
            swarm.dht().router().lock().unwrap().get(&target).is_none(),
            "destroy_with_force must unregister the server"
        );

        // Destroying again, either way, is a no-op as in Node.
        swarm.destroy_with_force(true).await?;
        swarm.destroy_with_force(false).await?;
        swarm.destroy().await?;

        // The actor task is the swarm's lifetime: once it is gone, every
        // command reports `Destroyed`.
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .map_err(|_| "the swarm actor did not exit after destroy")?
            .map_err(|e| format!("the swarm actor panicked: {e}"))?;

        assert!(matches!(swarm.listen().await, Err(SwarmError::Destroyed)));
        assert!(matches!(
            swarm.join_peer([0x11; 32]).await,
            Err(SwarmError::Destroyed)
        ));
        Ok(())
    })
    .await;
}
