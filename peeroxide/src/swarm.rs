use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::Rng;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::connection_set::{ConnectionInfo, ConnectionSet};
use crate::error::SwarmError;
use crate::peer_discovery::{DiscoveryEvent, PeerDiscoveryConfig, run_discovery};
use crate::peer_info::{PeerInfo, Priority};
use libudx::{RuntimeHandle, UdxRuntime};
use peeroxide_dht::crypto::hash;
use peeroxide_dht::hyperdht::{
    self, HyperDhtConfig, HyperDhtError, HyperDhtHandle, HyperDhtServer, KeyPair, PeerConnection,
    ServerConfig,
};
use peeroxide_dht::hyperdht_messages::FIREWALL_RANDOM;
use peeroxide_dht::messages::Ipv4Peer;
#[cfg(test)]
use peeroxide_dht::noise::Keypair as NoiseKeypair;
#[cfg(test)]
use peeroxide_dht::secret_stream::SecretStream;

/// Node keeps `_allConnections` and drops a connection on `'close'`; the
/// handle of a dead stream still pins its buffers, so prune on every push.
fn track_abort(aborts: &Mutex<Vec<libudx::UdxStreamAbort>>, handle: libudx::UdxStreamAbort) {
    if let Ok(mut aborts) = aborts.lock() {
        aborts.retain(|h| h.is_alive());
        aborts.push(handle);
    }
}

type ConnectionAbortMap = HashMap<[u8; 32], (u64, libudx::UdxStreamAbort)>;

/// Remember the abort handle of the connection registered under
/// `generation`, so a duplicate handshake can destroy the connection it
/// replaces (Node's `_handleServerConnectionSwap`). Same pruning as
/// [`track_abort`]: dead handles still pin their stream's buffers.
fn track_conn_abort(
    aborts: &Mutex<ConnectionAbortMap>,
    pk: [u8; 32],
    generation: u64,
    handle: libudx::UdxStreamAbort,
) {
    if let Ok(mut aborts) = aborts.lock() {
        aborts.retain(|_, (_, h)| h.is_alive());
        aborts.insert(pk, (generation, handle));
    }
}

/// Everything a spawned connection task needs to register its connection with
/// the actor before handing it out: the abort handles (for suspend, destroy and
/// duplicate swaps) and the close notification that frees the peer's slot.
#[derive(Clone)]
struct ConnectionWatch {
    aborts: Arc<Mutex<Vec<libudx::UdxStreamAbort>>>,
    conn_aborts: Arc<Mutex<ConnectionAbortMap>>,
    closed_tx: Option<mpsc::UnboundedSender<([u8; 32], u64)>>,
}

impl ConnectionWatch {
    /// Register `conn` for close/abort and give it back, ready to hand out.
    fn watch(&self, mut conn: PeerConnection, pk: [u8; 32], generation: u64) -> PeerConnection {
        track_abort(&self.aborts, conn.stream.abort_handle());
        track_conn_abort(
            &self.conn_aborts,
            pk,
            generation,
            conn.stream.abort_handle(),
        );
        if let (Some(closed), Some(sender)) = (
            conn.stream.take_close_notification(),
            self.closed_tx.clone(),
        ) {
            tokio::spawn(async move {
                let _ = closed.await;
                let _ = sender.send((pk, generation));
            });
        }
        conn
    }
}

/// Node's default `relayThrough` function: `(force || dht.randomized) ? relay : null`.
fn relay_for_dial(cfg: Option<[u8; 32]>, force: bool, randomized: bool) -> Option<[u8; 32]> {
    cfg.filter(|_| force || randomized)
}

/// Node's connect `onerror`: a holepunch failure with a relay configured pins
/// the peer to the relay and resets the attempts, so the relay retry is fast.
fn note_connect_error(info: &mut PeerInfo, relay_configured: bool, err: &SwarmError) {
    let holepunch_failure = matches!(
        err,
        SwarmError::Dht(HyperDhtError::HolepunchAborted | HyperDhtError::HolepunchFailed)
    );
    if relay_configured && holepunch_failure {
        info.force_relaying = true;
        info.attempts = 0;
    }
}

const DEFAULT_MAX_PEERS: usize = 64;
const DEFAULT_MAX_PARALLEL: usize = 3;

// Node's retry timer adds up to 500 ms of timer jitter to each tier.
const BACKOFF_S: [u64; 2] = [1000, 500];
const BACKOFF_M: [u64; 2] = [5000, 1000];
const BACKOFF_L: [u64; 2] = [15000, 2000];
const BACKOFF_X: [u64; 2] = [600_000, 120_000];

fn retry_delay(info: &PeerInfo) -> Duration {
    let tier = match (info.attempts, info.proven) {
        (0, _) | (1, true) => &BACKOFF_S,
        (1, false) | (2, true) => &BACKOFF_M,
        (2 | 3, false) | (3, true) => &BACKOFF_L,
        _ => &BACKOFF_X,
    };
    let mut rng = rand::rng();
    Duration::from_millis(tier[0] + rng.random_range(0..=tier[1]) + rng.random_range(0..=500))
}

fn short_hex(bytes: &[u8]) -> String {
    bytes.iter().take(4).fold(String::new(), |mut s, b| {
        use fmt::Write;
        write!(s, "{b:02x}").ok();
        s
    })
}

// ── Public types ─────────────────────────────────────────────────────────────

/// Configuration for a [`Hyperswarm`](SwarmHandle) instance.
#[non_exhaustive]
pub struct SwarmConfig {
    /// Ed25519 key pair. Auto-generated if `None`.
    pub key_pair: Option<KeyPair>,
    /// Underlying HyperDHT configuration.
    pub dht: HyperDhtConfig,
    /// Return after binding instead of waiting for bootstrap (default `false`).
    /// Topic discovery still waits for bootstrap before its first announce or lookup.
    pub eager: bool,
    /// Maximum total peer connections (default 64).
    pub max_peers: usize,
    /// Maximum concurrent outgoing connection attempts (default 3).
    pub max_parallel: usize,
    /// Fallback firewall classification when the DHT cannot report its state (default 0).
    pub firewall: u64,
    /// Public key of a blind relay used for `relayThrough`.
    ///
    /// As in Node hyperswarm, this is not a hard switch: the relay is used
    /// for a dial when the peer has `force_relaying` set (after a holepunch
    /// failure) or when this node's DHT classifies its NAT as
    /// `FIREWALL_RANDOM`, and a server only advertises it in its handshake
    /// replies when its own NAT is randomized.
    pub relay_through: Option<[u8; 32]>,
    /// Socket address of the relay node. When provided alongside `relay_through`,
    /// the server connects to the relay directly instead of discovering it via DHT.
    pub relay_address: Option<std::net::SocketAddr>,
    /// Enable the same-NAT LAN-shortcut (default `true`). When `false`,
    /// receivers ignore the loopback/private addresses advertised in the
    /// server's `addresses4` and always dial the public IP (= FE-holder's
    /// peer_address tag). Mirrors Node hyperdht `opts.localConnection`.
    ///
    /// Tests that want to exercise the real network path (without leaning
    /// on same-host loopback) should set this to `false`.
    pub local_connection: bool,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            key_pair: None,
            dht: HyperDhtConfig::default(),
            eager: false,
            max_peers: DEFAULT_MAX_PEERS,
            max_parallel: DEFAULT_MAX_PARALLEL,
            firewall: 0,
            relay_through: None,
            relay_address: None,
            local_connection: true,
        }
    }
}

impl SwarmConfig {
    /// Create a config pre-populated with the public HyperDHT bootstrap nodes.
    pub fn with_public_bootstrap() -> Self {
        Self {
            dht: HyperDhtConfig::with_public_bootstrap(),
            ..Self::default()
        }
    }
}

/// Options for joining a topic.
#[non_exhaustive]
pub struct JoinOpts {
    /// Announce on this topic (server mode).
    pub server: bool,
    /// Look up peers on this topic (client mode).
    pub client: bool,
}

impl Default for JoinOpts {
    fn default() -> Self {
        Self {
            server: true,
            client: true,
        }
    }
}

/// An established swarm connection.
#[non_exhaustive]
pub struct SwarmConnection {
    /// The underlying encrypted peer connection.
    pub peer: PeerConnection,
    /// `true` if we initiated this connection.
    pub is_initiator: bool,
    /// Topic(s) associated with this connection.
    pub topics: Vec<[u8; 32]>,
    _runtime: UdxRuntime,
}

impl SwarmConnection {
    /// Returns the remote peer's static public key.
    pub fn remote_public_key(&self) -> &[u8; 32] {
        &self.peer.remote_public_key
    }
}

impl fmt::Debug for SwarmConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SwarmConnection")
            .field(
                "remote_public_key",
                &short_hex(&self.peer.remote_public_key),
            )
            .field("is_initiator", &self.is_initiator)
            .field("topics", &self.topics.len())
            .finish()
    }
}

/// Clone-able handle for controlling a running Hyperswarm.
#[derive(Clone)]
pub struct SwarmHandle {
    cmd_tx: mpsc::Sender<SwarmCommand>,
    dht: HyperDhtHandle,
    key_pair: KeyPair,
}

impl SwarmHandle {
    /// Access the underlying [`HyperDhtHandle`] for low-level DHT operations.
    ///
    /// This exposes mutable/immutable storage, manual peer lookup, and other
    /// DHT primitives not covered by the high-level swarm API.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use peeroxide::{spawn, discovery_key, JoinOpts, SwarmConfig, KeyPair};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = SwarmConfig::with_public_bootstrap();
    /// let (_task, handle, _conn_rx) = spawn(config).await?;
    ///
    /// // Publish a mutable record under the swarm's own keypair
    /// let kp = handle.key_pair();
    /// handle.dht().mutable_put(kp, b"hello", 0).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Caveats
    ///
    /// - **Do not call `destroy()`** on the returned handle. The swarm owns
    ///   the DHT lifecycle; destroying it here will break discovery and
    ///   connection establishment.
    /// - **`connect` methods require a `UdxRuntime`** that is not accessible
    ///   from the public API. Use swarm-level topic joins for connection
    ///   establishment instead.
    pub fn dht(&self) -> &HyperDhtHandle {
        &self.dht
    }

    /// The Ed25519 key pair identifying this swarm node.
    ///
    /// This is the same key pair used for topic announcements and Noise
    /// handshakes. It can also be used with [`HyperDhtHandle::mutable_put`]
    /// to publish data that other peers can discover and verify.
    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }

    /// Join a topic for peer discovery.
    ///
    /// When `opts.server` is true, the swarm announces so other peers can
    /// connect to us. When `opts.client` is true, the swarm looks up peers
    /// and initiates connections.
    pub async fn join(&self, topic: [u8; 32], opts: JoinOpts) -> Result<(), SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::Join {
                topic,
                server: opts.server,
                client: opts.client,
                reply_tx,
            })
            .await
            .map_err(|_| SwarmError::Destroyed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)?
    }

    /// Leave a topic, stopping discovery and unannouncing.
    pub async fn leave(&self, topic: [u8; 32]) -> Result<(), SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::Leave { topic, reply_tx })
            .await
            .map_err(|_| SwarmError::Destroyed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)?
    }

    /// Wait until all joined topics have completed their initial discovery.
    pub async fn flush(&self) -> Result<(), SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::Flush { reply_tx })
            .await
            .map_err(|_| SwarmError::Destroyed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)?
    }

    /// Destroy the swarm, cancelling all discovery and closing connections.
    pub async fn destroy(&self) -> Result<(), SwarmError> {
        let _ = self.destroy_with_force(false).await;
        Ok(())
    }

    /// Destroy the swarm, optionally skipping the graceful shutdown.
    ///
    /// Mirrors Node `swarm.destroy({ force })`: without `force`, every joined
    /// topic stops announcing and the server stops before the DHT is torn
    /// down (`clear()` + `server.close()`); with `force` those tasks are
    /// aborted instead of awaited. Destroying an already-destroyed swarm is a
    /// no-op, as in Node.
    ///
    /// Connections already handed out through the connection channel are
    /// owned by the caller and are dropped by the caller, not here.
    pub async fn destroy_with_force(&self, force: bool) -> Result<(), SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(SwarmCommand::Destroy { force, reply_tx })
            .await
            .is_err()
        {
            return Ok(());
        }
        match reply_rx.await {
            Ok(result) => result,
            Err(_) => Ok(()),
        }
    }

    /// Start accepting connections for this swarm's own public key.
    ///
    /// Mirrors Node `swarm.listen()`: registers the DHT server on
    /// `hash(public_key)` and announces that key so peers that only know the
    /// key (see [`SwarmHandle::join_peer`]) can find us. Resolves once the
    /// first announce has completed. Calling it again is a no-op.
    pub async fn listen(&self) -> Result<(), SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::Listen { reply_tx })
            .await
            .map_err(|_| SwarmError::Destroyed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)?
    }

    /// Connect to a specific peer, without joining any topic.
    ///
    /// Mirrors Node `swarm.joinPeer(publicKey)`: the peer is queued for an
    /// immediate dial and, when the attempt fails, retried with the same
    /// backoff as a topic-discovered peer. Joining our own key, an
    /// already-connected peer, or the same peer twice is a no-op.
    pub async fn join_peer(&self, public_key: [u8; 32]) -> Result<(), SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::JoinPeer {
                public_key,
                reply_tx,
            })
            .await
            .map_err(|_| SwarmError::Destroyed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)?
    }

    /// Stop treating a peer as explicitly joined.
    ///
    /// Mirrors Node `swarm.leavePeer(publicKey)`: the peer stops being
    /// retried once it has no remaining topics. An established connection is
    /// not closed. Unknown peers are ignored.
    pub async fn leave_peer(&self, public_key: [u8; 32]) -> Result<(), SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::LeavePeer {
                public_key,
                reply_tx,
            })
            .await
            .map_err(|_| SwarmError::Destroyed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)?
    }

    /// Suspend the swarm: stop discovery, the server announcer and all
    /// pending dials, and forget every tracked connection, so no further
    /// connection attempts are made until [`SwarmHandle::resume`].
    ///
    /// Mirrors Node `swarm.suspend()`. Node also destroys the established
    /// connections it holds; here each connection has already been moved to
    /// the caller through the connection channel, so callers that want them
    /// closed must drop their [`SwarmConnection`]s.
    pub async fn suspend(&self) -> Result<(), SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::Suspend { reply_tx })
            .await
            .map_err(|_| SwarmError::Destroyed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)?
    }

    /// Resume a suspended swarm: restart discovery for every joined topic,
    /// the server announcer, and the queued connection attempts.
    ///
    /// Mirrors Node `swarm.resume()`. Resuming a swarm that is not suspended
    /// is a no-op.
    pub async fn resume(&self) -> Result<(), SwarmError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCommand::Resume { reply_tx })
            .await
            .map_err(|_| SwarmError::Destroyed)?;
        reply_rx.await.map_err(|_| SwarmError::ChannelClosed)?
    }
}

// ── Internal types ───────────────────────────────────────────────────────────

enum SwarmCommand {
    Join {
        topic: [u8; 32],
        server: bool,
        client: bool,
        reply_tx: oneshot::Sender<Result<(), SwarmError>>,
    },
    Leave {
        topic: [u8; 32],
        reply_tx: oneshot::Sender<Result<(), SwarmError>>,
    },
    Listen {
        reply_tx: oneshot::Sender<Result<(), SwarmError>>,
    },
    JoinPeer {
        public_key: [u8; 32],
        reply_tx: oneshot::Sender<Result<(), SwarmError>>,
    },
    LeavePeer {
        public_key: [u8; 32],
        reply_tx: oneshot::Sender<Result<(), SwarmError>>,
    },
    Suspend {
        reply_tx: oneshot::Sender<Result<(), SwarmError>>,
    },
    Resume {
        reply_tx: oneshot::Sender<Result<(), SwarmError>>,
    },
    Flush {
        reply_tx: oneshot::Sender<Result<(), SwarmError>>,
    },
    Destroy {
        force: bool,
        reply_tx: oneshot::Sender<Result<(), SwarmError>>,
    },
}

struct TopicState {
    is_server: bool,
    is_client: bool,
    cancel_tx: Option<oneshot::Sender<()>>,
    refreshed: bool,
    /// Discovery task for this topic. Kept so a suspend/destroy can stop it
    /// instead of letting it keep announcing.
    task: Option<JoinHandle<()>>,
}

async fn stop_task(task: Option<JoinHandle<()>>, graceful: bool) {
    let Some(mut task) = task else { return };
    if !graceful
        || tokio::time::timeout(Duration::from_secs(2), &mut task)
            .await
            .is_err()
    {
        task.abort();
    }
}

struct ActorConfig {
    max_peers: usize,
    max_parallel: usize,
    relay_through: Option<[u8; 32]>,
    local_connection: bool,
    eager: bool,
}

struct SwarmActor {
    key_pair: KeyPair,
    dht: HyperDhtHandle,
    config: ActorConfig,
    runtime_handle: Arc<RuntimeHandle>,

    topics: HashMap<[u8; 32], TopicState>,
    discovery_event_tx: mpsc::UnboundedSender<DiscoveryEvent>,

    peers: HashMap<[u8; 32], PeerInfo>,
    connections: ConnectionSet,
    /// Abort handles for every connection this swarm has produced, including
    /// the ones already handed to the caller through `conn_tx`. Node keeps
    /// `_allConnections` and destroys them on suspend/destroy.
    aborts: Arc<Mutex<Vec<libudx::UdxStreamAbort>>>,
    queue: Vec<[u8; 32]>,

    /// In-flight dials, so a suspend or destroy can abort them. The attempt's
    /// result arrives through `connect_result_tx`; an aborted one never does.
    connect_tasks: HashMap<[u8; 32], (u64, JoinHandle<()>)>,
    dial_generations: HashMap<[u8; 32], u64>,
    connect_result_tx: mpsc::UnboundedSender<ConnectAttemptResult>,
    /// Fires when a failed peer's retry backoff elapses (`lib/retry-timer.js`).
    retry_tx: mpsc::UnboundedSender<[u8; 32]>,

    /// `true` between [`SwarmHandle::suspend`] and [`SwarmHandle::resume`]:
    /// no dials, no announces, no new connections.
    suspended: bool,
    /// `true` once [`SwarmHandle::listen`] has been called. The DHT server
    /// stays registered across suspend/resume.
    listening: bool,
    server: HyperDhtServer,

    conn_tx: mpsc::Sender<SwarmConnection>,

    server_registered: bool,
    relay_address: Option<Ipv4Peer>,

    active_connects: usize,
    flush_waiters: Vec<oneshot::Sender<Result<(), SwarmError>>>,
    /// Fires `(pk, generation)` when a connection's stream closes, whichever
    /// side opened it (Node's `conn.on('close')`).
    closed_tx: Option<mpsc::UnboundedSender<([u8; 32], u64)>>,
    /// Generation of the connection registered in `connections` per peer, so
    /// a late close notification only retires the connection it belongs to.
    generations: HashMap<[u8; 32], u64>,
    /// Abort handle of that connection, so a duplicate handshake can destroy
    /// the connection it replaces.
    conn_aborts: Arc<Mutex<ConnectionAbortMap>>,
    next_generation: u64,
}
struct ConnectAttemptResult {
    public_key: [u8; 32],
    generation: u64,
    result: Result<(PeerConnection, UdxRuntime), SwarmError>,
}

// ── Spawn ────────────────────────────────────────────────────────────────────

/// Create and start a Hyperswarm instance.
///
/// The spawned swarm discovers peers by topic and establishes encrypted
/// UDX connections for each [`SwarmConnection`]. By default, server-side
/// handshakes advertise the direct or hole-punched path selected by the
/// DHT/NAT logic. If [`SwarmConfig::relay_through`] is set, the server side
/// instead instructs clients to pair through that blind-relay node and then
/// opens its side of the relayed connection directly to the configured relay
/// address (when [`SwarmConfig::relay_address`] is provided) or via DHT
/// discovery of the relay node.
///
/// Returns a background task handle, a control handle, and a receiver
/// that yields each new [`SwarmConnection`].
pub async fn spawn(
    config: SwarmConfig,
) -> Result<(JoinHandle<()>, SwarmHandle, mpsc::Receiver<SwarmConnection>), SwarmError> {
    let key_pair = config.key_pair.unwrap_or_else(KeyPair::generate);
    let runtime = UdxRuntime::new()?;

    let (dht_join, dht, _server_rx) = hyperdht::spawn(&runtime, config.dht).await?;
    if !config.eager {
        dht.bootstrapped().await?;
    }

    let local_port = dht.dht().local_port().await?;
    // Fetch the actual port of the socket the server-side firewall hook
    // listens on (matches `dht.server_socket()` = primary_socket port). This
    // is what we must advertise in `addresses4` so the receiver dials the
    // same UDP socket where the sender's UDX demux is registered. For
    // firewalled nodes (default) this is the client_socket port, NOT the
    // dht `local_port` (which is the server_socket port).
    let primary_socket_port = match dht.server_socket().await? {
        Some(s) => match s.local_addr().await {
            Ok(addr) => addr.port(),
            Err(_) => local_port,
        },
        None => local_port,
    };
    tracing::info!(
        target: "peeroxide::_events::swarm::started",
        port = local_port,
        primary_port = primary_socket_port,
        "swarm started"
    );

    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (conn_tx, conn_rx) = mpsc::channel(64);
    let (discovery_event_tx, discovery_event_rx) = mpsc::unbounded_channel();
    let (connect_result_tx, connect_result_rx) = mpsc::unbounded_channel::<ConnectAttemptResult>();
    let (retry_tx, retry_rx) = mpsc::unbounded_channel::<[u8; 32]>();

    let mut server = dht.create_shared_server(
        &runtime,
        ServerConfig::for_swarm(
            key_pair.clone(),
            config.firewall,
            config.relay_through,
            config.relay_address,
        ),
    );
    let server_conn_rx = server.take_connections();

    let handle_dht = dht.clone();
    let handle_key_pair = key_pair.clone();

    let actor = SwarmActor {
        key_pair,
        dht,
        config: ActorConfig {
            max_peers: config.max_peers,
            max_parallel: config.max_parallel,
            relay_through: config.relay_through,
            local_connection: config.local_connection,
            eager: config.eager,
        },
        runtime_handle: runtime.handle(),
        topics: HashMap::new(),
        discovery_event_tx,
        peers: HashMap::new(),
        connections: ConnectionSet::new(),
        aborts: Arc::new(Mutex::new(Vec::new())),
        queue: Vec::new(),
        connect_tasks: HashMap::new(),
        dial_generations: HashMap::new(),
        connect_result_tx,
        retry_tx,
        suspended: false,
        listening: false,
        server,
        server_registered: false,
        relay_address: config.relay_address.map(|addr| Ipv4Peer {
            host: addr.ip().to_string(),
            port: addr.port(),
        }),
        active_connects: 0,
        flush_waiters: Vec::new(),
        closed_tx: None,
        generations: HashMap::new(),
        conn_aborts: Arc::new(Mutex::new(HashMap::new())),
        next_generation: 0,
        conn_tx,
    };

    // Keep the DHT runtime alive for the swarm's lifetime.
    // We must await dht_join AFTER actor.run() (which calls dht.destroy()),
    // so the DhtNode finishes closing its IO sockets before we drop the runtime.
    let join = tokio::spawn(async move {
        actor
            .run(
                cmd_rx,
                discovery_event_rx,
                server_conn_rx,
                connect_result_rx,
                retry_rx,
            )
            .await;
        let _ = dht_join.await;
        drop(runtime);
    });

    let handle = SwarmHandle {
        cmd_tx,
        dht: handle_dht,
        key_pair: handle_key_pair,
    };
    Ok((join, handle, conn_rx))
}

// ── Actor ────────────────────────────────────────────────────────────────────

impl SwarmActor {
    async fn run(
        mut self,
        mut cmd_rx: mpsc::Receiver<SwarmCommand>,
        mut discovery_rx: mpsc::UnboundedReceiver<DiscoveryEvent>,
        mut server_conn_rx: mpsc::UnboundedReceiver<PeerConnection>,
        mut connect_result_rx: mpsc::UnboundedReceiver<ConnectAttemptResult>,
        mut retry_rx: mpsc::UnboundedReceiver<[u8; 32]>,
    ) {
        let (closed_tx, mut closed_rx) = mpsc::unbounded_channel();
        self.closed_tx = Some(closed_tx);

        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    let stop = self.handle_command(cmd).await;
                    if self.suspended || !self.server_registered {
                        while let Ok(conn) = server_conn_rx.try_recv() {
                            conn.stream.abort_handle().abort();
                        }
                    }
                    if stop { break; }
                }
                event = discovery_rx.recv() => {
                    if let Some(event) = event {
                        self.handle_discovery_event(event);
                    }
                }
                conn = server_conn_rx.recv(), if self.server_registered && !self.suspended => {
                    let Some(conn) = conn else { break };
                    self.handle_server_connection(conn);
                }
                result = connect_result_rx.recv() => {
                    if let Some(result) = result {
                        self.handle_connect_result(result);
                    }
                }
                pk = retry_rx.recv() => {
                    if let Some(pk) = pk {
                        self.handle_retry(pk);
                    }
                }
                closed = closed_rx.recv() => {
                    if let Some((pk, generation)) = closed {
                        self.handle_close(pk, generation);
                    }
                }
            }
        }

        for (_, state) in self.topics.drain() {
            if let Some(cancel) = state.cancel_tx {
                let _ = cancel.send(());
            }
            if let Some(task) = state.task {
                task.abort();
            }
        }

        self.server.close().await;

        if self.server_registered {
            let target = hash(&self.key_pair.public_key);
            self.dht.unregister_server(&target);
            self.server_registered = false;
        }

        let _ = self.dht.destroy().await;
    }

    /// Returns `true` when the actor should shut down.
    async fn handle_command(&mut self, cmd: SwarmCommand) -> bool {
        match cmd {
            SwarmCommand::Join {
                topic,
                server,
                client,
                reply_tx,
            } => {
                let result = self.do_join(topic, server, client).await;
                let _ = reply_tx.send(result);
                false
            }
            SwarmCommand::Leave { topic, reply_tx } => {
                let result = self.do_leave(topic).await;
                let _ = reply_tx.send(result);
                false
            }
            SwarmCommand::Listen { reply_tx } => {
                let result = self.do_listen().await;
                let _ = reply_tx.send(result);
                false
            }
            SwarmCommand::JoinPeer {
                public_key,
                reply_tx,
            } => {
                let result = self.do_join_peer(public_key);
                let _ = reply_tx.send(result);
                false
            }
            SwarmCommand::LeavePeer {
                public_key,
                reply_tx,
            } => {
                let result = self.do_leave_peer(&public_key);
                let _ = reply_tx.send(result);
                false
            }
            SwarmCommand::Suspend { reply_tx } => {
                let result = self.do_suspend().await;
                let _ = reply_tx.send(result);
                false
            }
            SwarmCommand::Resume { reply_tx } => {
                let result = self.do_resume().await;
                let _ = reply_tx.send(result);
                false
            }
            SwarmCommand::Flush { reply_tx } => {
                if self.suspended || self.all_topics_refreshed() {
                    let _ = reply_tx.send(Ok(()));
                } else {
                    self.flush_waiters.push(reply_tx);
                }
                false
            }
            SwarmCommand::Destroy { force, reply_tx } => {
                self.do_destroy(force).await;
                if self.server_registered {
                    let target = hash(&self.key_pair.public_key);
                    self.dht.unregister_server(&target);
                    self.server_registered = false;
                }
                let _ = reply_tx.send(Ok(()));
                true
            }
        }
    }

    fn relay_addresses(&self) -> Vec<Ipv4Peer> {
        self.relay_address
            .as_ref()
            .map_or_else(Vec::new, |a| vec![a.clone()])
    }

    async fn do_join(
        &mut self,
        topic: [u8; 32],
        server: bool,
        client: bool,
    ) -> Result<(), SwarmError> {
        if self.topics.contains_key(&topic) {
            return Ok(());
        }

        if server {
            self.ensure_server_listening().await?;
        }

        if self.suspended {
            // Node creates the discovery in a suspended state and only starts
            // it on resume; keep the join so resume can start it.
            self.topics.insert(
                topic,
                TopicState {
                    is_server: server,
                    is_client: client,
                    cancel_tx: None,
                    refreshed: false,
                    task: None,
                },
            );
        } else {
            self.spawn_discovery(topic, server, client);
        }
        Ok(())
    }

    /// Start discovery for one topic and remember its task so suspend/destroy
    /// can stop it.
    fn spawn_discovery(&mut self, topic: [u8; 32], server: bool, client: bool) {
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let config = PeerDiscoveryConfig {
            topic,
            is_server: server,
            is_client: client,
        };
        let dht = self.dht.clone();
        let key_pair = self.key_pair.clone();
        let relays = self.relay_addresses();
        let events = self.discovery_event_tx.clone();
        let eager = self.config.eager;
        let task = tokio::spawn(async move {
            let mut cancel_rx = cancel_rx;
            if eager {
                tokio::select! {
                    ready = dht.bootstrapped() => {
                        if ready.is_err() {
                            return;
                        }
                    }
                    _ = &mut cancel_rx => return,
                }
            }
            run_discovery(config, dht, key_pair, relays, events, cancel_rx).await;
        });

        self.topics.insert(
            topic,
            TopicState {
                is_server: server,
                is_client: client,
                cancel_tx: Some(cancel_tx),
                refreshed: false,
                task: Some(task),
            },
        );
    }

    /// Node `swarm.listen()`: complete shared listen and mark listening so
    /// leaving all server topics will not unregister the server.
    async fn do_listen(&mut self) -> Result<(), SwarmError> {
        self.listening = true;
        self.ensure_server_listening().await
    }

    async fn ensure_server_listening(&mut self) -> Result<(), SwarmError> {
        if self.suspended {
            return Ok(());
        }
        if !self.server.listening() {
            self.server
                .listen(&self.key_pair)
                .await
                .map_err(SwarmError::Dht)?;
            self.server_registered = true;
            tracing::debug!(
                pk = %short_hex(&self.key_pair.public_key),
                "server listening and registered"
            );
        } else if !self.server_registered {
            self.dht.register_server(&self.key_pair.public_key);
            self.server_registered = true;
            tracing::debug!(
                pk = %short_hex(&self.key_pair.public_key),
                "server re-registered"
            );
        }
        self.server.resume().await.map_err(SwarmError::Dht)?;
        Ok(())
    }

    /// Node `swarm.joinPeer(publicKey)`: queue a peer that was named
    /// explicitly instead of discovered on a topic.
    fn do_join_peer(&mut self, public_key: [u8; 32]) -> Result<(), SwarmError> {
        if public_key == self.key_pair.public_key {
            return Ok(());
        }

        // Node marks the peer explicit before the already-connected check, so
        // it is still retried if that connection later closes.
        let enqueue = {
            let info = self
                .peers
                .entry(public_key)
                .or_insert_with(|| PeerInfo::new(public_key, vec![]));
            info.explicit = true;
            let enqueue = !self.connections.has(&public_key)
                && !info.banned
                && !info.queued
                && !info.connecting;
            if enqueue {
                info.priority = info.get_priority();
                info.queued = true;
            }
            enqueue
        };
        if enqueue {
            self.queue.push(public_key);
            // Node queues the peer and calls _attemptClientConnections, which
            // does nothing while suspended; resume drains the queue.
            self.attempt_connections();
        }
        Ok(())
    }

    /// Node `swarm.leavePeer(publicKey)`: drop the explicit flag and garbage
    /// collect the peer when it has no topics left. A connection is not
    /// closed, as in Node.
    fn do_leave_peer(&mut self, public_key: &[u8; 32]) -> Result<(), SwarmError> {
        if let Some(info) = self.peers.get_mut(public_key) {
            info.explicit = false;
        }
        self.maybe_delete_peer(public_key);
        Ok(())
    }

    fn maybe_delete_peer(&mut self, public_key: &[u8; 32]) {
        let gc = self
            .peers
            .get(public_key)
            .is_some_and(|info| info.should_gc());
        if gc && !self.connections.has(public_key) {
            self.peers.remove(public_key);
        }
    }

    /// Node `_shouldRequeue`: an explicit peer is always retried; a
    /// discovered peer only while one of its topics is still joined.
    fn should_requeue(&self, public_key: &[u8; 32]) -> bool {
        self.peers.get(public_key).is_some_and(|info| {
            info.explicit || info.topics.iter().any(|t| self.topics.contains_key(t))
        })
    }

    /// Node `swarm.suspend()`: stop everything the swarm drives, close the
    /// DHT sockets and forget the connections it handed out.
    async fn do_suspend(&mut self) -> Result<(), SwarmError> {
        if self.suspended {
            return Ok(());
        }
        self.suspended = true;

        for state in self.topics.values_mut() {
            if let Some(cancel) = state.cancel_tx.take() {
                let _ = cancel.send(());
            }
            if let Some(task) = state.task.take() {
                task.abort();
            }
            state.refreshed = false;
        }

        for (_, (_, task)) in self.connect_tasks.drain() {
            task.abort();
        }
        self.dial_generations.clear();
        self.active_connects = 0;
        self.queue.clear();
        for info in self.peers.values_mut() {
            info.queued = false;
            info.connecting = false;
            info.set_waiting(false);
        }

        // Node `for (const connection of this._allConnections) connection.destroy()`.
        if let Ok(mut aborts) = self.aborts.lock() {
            for handle in std::mem::take(&mut *aborts) {
                handle.abort();
            }
        }
        self.connections = ConnectionSet::new();
        self.generations.clear();
        if let Ok(mut aborts) = self.conn_aborts.lock() {
            aborts.clear();
        }

        for waiter in self.flush_waiters.drain(..) {
            let _ = waiter.send(Ok(()));
        }

        // Suspend server before DHT suspend:
        self.server.suspend().await.map_err(SwarmError::Dht)?;
        self.dht.suspend().await?;
        Ok(())
    }

    /// Node `swarm.resume()`: resume the DHT, then restart discovery, the
    /// announcer and the queued connection attempts.
    async fn do_resume(&mut self) -> Result<(), SwarmError> {
        if !self.suspended {
            return Ok(());
        }
        self.dht.resume().await?;
        self.suspended = false;
        if self.listening || self.topics.values().any(|topic| topic.is_server) {
            self.ensure_server_listening().await?;
        }

        let topics: Vec<([u8; 32], bool, bool)> = self
            .topics
            .iter()
            .map(|(topic, state)| (*topic, state.is_server, state.is_client))
            .collect();
        for (topic, server, client) in topics {
            self.spawn_discovery(topic, server, client);
        }

        let requeue: Vec<[u8; 32]> = self
            .peers
            .iter()
            .filter(|(pk, info)| {
                let still_joined =
                    info.explicit || info.topics.iter().any(|t| self.topics.contains_key(t));
                !info.banned && !self.connections.has(pk) && still_joined
            })
            .map(|(pk, _)| *pk)
            .collect();
        for public_key in requeue {
            if let Some(info) = self.peers.get_mut(&public_key) {
                if info.queued || info.connecting {
                    continue;
                }
                info.priority = info.get_priority();
                info.queued = true;
            }
            self.queue.push(public_key);
        }

        self.attempt_connections();
        Ok(())
    }

    /// Node `swarm.destroy({ force })`: stop discovery and the announcer, then
    /// abort the remaining work. Without `force`, tasks get a bounded chance
    /// to finish their current announce instead of being cut off.
    async fn do_destroy(&mut self, force: bool) {
        self.suspended = true;
        self.server.close().await;
        for (_, mut state) in self.topics.drain() {
            if let Some(cancel) = state.cancel_tx.take() {
                let _ = cancel.send(());
            }
            stop_task(state.task.take(), !force).await;
        }

        for (_, (_, task)) in self.connect_tasks.drain() {
            task.abort();
        }
        self.dial_generations.clear();
        self.active_connects = 0;
        self.queue.clear();

        if let Ok(mut aborts) = self.aborts.lock() {
            for handle in std::mem::take(&mut *aborts) {
                handle.abort();
            }
        }
        if let Ok(mut aborts) = self.conn_aborts.lock() {
            for (_, (_, handle)) in aborts.drain() {
                handle.abort();
            }
        }
        self.connections = ConnectionSet::new();
        self.generations.clear();

        if self.server_registered {
            let target = hash(&self.key_pair.public_key);
            self.dht.unregister_server(&target);
            self.server_registered = false;
        }

        for waiter in self.flush_waiters.drain(..) {
            let _ = waiter.send(Err(SwarmError::Destroyed));
        }

        let _ = self.dht.destroy().await;
    }

    async fn do_leave(&mut self, topic: [u8; 32]) -> Result<(), SwarmError> {
        if let Some(state) = self.topics.remove(&topic) {
            if let Some(cancel) = state.cancel_tx {
                let _ = cancel.send(());
            }
            if let Some(task) = state.task {
                task.abort();
            }
            for peer in self.peers.values_mut() {
                peer.topics.retain(|t| *t != topic);
            }

            // `listen()` owns the server independently of topics, as Node's
            // `Server.listen()` does; only a join-registered server goes away.
            if state.is_server && self.server_registered && !self.listening {
                let has_remaining_server_topics = self.topics.values().any(|t| t.is_server);
                if !has_remaining_server_topics {
                    self.server.suspend().await.map_err(SwarmError::Dht)?;
                    let target = hash(&self.key_pair.public_key);
                    self.dht.unregister_server(&target);
                    self.server_registered = false;
                    tracing::debug!(
                        pk = %short_hex(&self.key_pair.public_key),
                        "server unregistered (no remaining server topics)"
                    );
                }
            }
        }
        Ok(())
    }

    fn handle_discovery_event(&mut self, event: DiscoveryEvent) {
        if self.suspended {
            return;
        }
        match event {
            DiscoveryEvent::PeerFound {
                public_key,
                relay_addresses,
                topic,
            } => {
                if public_key == self.key_pair.public_key {
                    return;
                }
                self.retire_if_dead(&public_key);
                if self.connections.has(&public_key) {
                    return;
                }
                if self.connections.len() >= self.config.max_peers {
                    return;
                }

                let info = self
                    .peers
                    .entry(public_key)
                    .or_insert_with(|| PeerInfo::new(public_key, relay_addresses.clone()));

                if !relay_addresses.is_empty() {
                    info.relay_addresses = relay_addresses;
                }
                if !info.topics.contains(&topic) {
                    info.topics.push(topic);
                }

                if !info.queued && !info.connecting && !info.banned && !info.is_waiting() {
                    info.queued = true;
                    info.priority = info.get_priority();
                    self.queue.push(public_key);
                    // Defer the dial attempt until RefreshComplete to avoid a
                    // queue-time relay-snapshot race. A single lookup typically
                    // yields multiple PeerFound events per peer (one per
                    // responding FE-holder) and relay_addresses accumulates
                    // across them. Spawning the dial on the first event would
                    // snapshot a partial list; the spawned task can't pick up
                    // later relay additions. RefreshComplete fires once all
                    // PeerFound events for a refresh have been processed, so
                    // info.relay_addresses is at its widest by then.
                }
            }
            DiscoveryEvent::RefreshComplete { topic } => {
                if let Some(state) = self.topics.get_mut(&topic) {
                    state.refreshed = true;
                }
                self.attempt_connections();
                self.check_flush_waiters();
            }
        }
    }

    fn all_topics_refreshed(&self) -> bool {
        !self.topics.is_empty() && self.topics.values().all(|topic| topic.refreshed)
    }

    fn check_flush_waiters(&mut self) {
        if self.all_topics_refreshed() {
            for waiter in self.flush_waiters.drain(..) {
                let _ = waiter.send(Ok(()));
            }
        }
    }

    /// The registration handles a connect task needs for the connection it
    /// just created (shared ownership, so it can be cloned into the task).
    fn connection_watch(&self) -> ConnectionWatch {
        ConnectionWatch {
            aborts: Arc::clone(&self.aborts),
            conn_aborts: Arc::clone(&self.conn_aborts),
            closed_tx: self.closed_tx.clone(),
        }
    }

    /// Destroy the connection we hold for `pk` (Node destroys the connection a
    /// duplicate handshake replaces). Do nothing if it is already gone.
    fn abort_connection(&mut self, pk: &[u8; 32]) {
        let Ok(mut aborts) = self.conn_aborts.lock() else {
            return;
        };
        let Some((generation, handle)) = aborts.remove(pk) else {
            return;
        };
        if self.generations.get(pk) == Some(&generation) {
            handle.abort();
        }
    }

    /// Prune dead abort handles and retire `pk` if `generation` matches current.
    fn handle_close(&mut self, pk: [u8; 32], generation: u64) {
        if let Ok(mut aborts) = self.aborts.lock() {
            aborts.retain(|h| h.is_alive());
        }
        if let Ok(mut conn_aborts) = self.conn_aborts.lock() {
            conn_aborts.retain(|_, (_, h)| h.is_alive());
        }

        // A stale generation belongs to a connection we have
        // already replaced; only the current one is retired.
        if self.generations.get(&pk) == Some(&generation) {
            self.retire_connection(&pk);
        }
    }

    /// Retire the active connection for `pk`: remove from registrations,
    /// notify peer info, and reschedule retry if we initiated it.
    fn retire_connection(&mut self, pk: &[u8; 32]) {
        self.generations.remove(pk);
        if let Ok(mut aborts) = self.conn_aborts.lock() {
            aborts.remove(pk);
        }
        let was_initiator = self
            .connections
            .get(pk)
            .is_some_and(|info| info.is_initiator);
        if self.connections.remove(pk) {
            if let Some(info) = self.peers.get_mut(pk) {
                info.disconnected();
            }
            if was_initiator {
                self.schedule_retry(*pk);
            }
        }
    }

    /// If an existing current stream is already dead, retire it before
    /// duplicate tie-break even when its close notification is queued.
    fn retire_if_dead(&mut self, pk: &[u8; 32]) -> bool {
        let is_dead = if let Ok(aborts) = self.conn_aborts.lock() {
            if let Some((generation, handle)) = aborts.get(pk) {
                self.generations.get(pk) == Some(generation) && !handle.is_alive()
            } else {
                false
            }
        } else {
            false
        };
        if is_dead {
            if let Ok(mut aborts) = self.aborts.lock() {
                aborts.retain(|h| h.is_alive());
            }
            self.retire_connection(pk);
            true
        } else {
            false
        }
    }

    fn handle_server_connection(&mut self, conn: PeerConnection) {
        let pk = conn.remote_public_key;
        if self.suspended || !self.server_registered || !conn.stream.abort_handle().is_alive() {
            conn.stream.abort_handle().abort();
            return;
        }

        self.retire_if_dead(&pk);

        // Dedup: compare public keys to decide tie-break
        if self.connections.has(&pk) {
            let we_are_dominant = self.key_pair.public_key > pk;
            if we_are_dominant {
                tracing::debug!(pk = %short_hex(&pk), "server: keeping dominant existing connection");
                conn.stream.abort_handle().abort();
                return;
            }
            tracing::debug!(
                pk = %short_hex(&pk),
                "server: duplicate incoming connection replaces existing connection"
            );
            self.abort_connection(&pk);
            self.connections.remove(&pk);
        }

        if self.connections.len() >= self.config.max_peers {
            tracing::debug!(pk = %short_hex(&pk), "server: at max connections");
            conn.stream.abort_handle().abort();
            return;
        }
        if self.dial_generations.remove(&pk).is_some() {
            self.active_connects = self.active_connects.saturating_sub(1);
            if let Some((_, task)) = self.connect_tasks.remove(&pk) {
                task.abort();
            }
        }
        self.queue.retain(|queued| queued != &pk);

        self.next_generation = self.next_generation.wrapping_add(1);
        let generation = self.next_generation;
        self.generations.insert(pk, generation);
        let conn = self.connection_watch().watch(conn, pk, generation);

        self.connections.add(
            pk,
            ConnectionInfo {
                is_initiator: false,
            },
        );

        let topics = if let Some(info) = self.peers.get_mut(&pk) {
            info.connected();
            info.topics.clone()
        } else {
            vec![]
        };

        let swarm_conn = SwarmConnection {
            peer: conn,
            is_initiator: false,
            topics,
            _runtime: UdxRuntime::shared(self.runtime_handle.clone()),
        };
        if self.conn_tx.try_send(swarm_conn).is_err() {
            tracing::warn!("connection channel full or closed, dropping connection");
        }
    }

    fn attempt_connections(&mut self) {
        if self.suspended {
            return;
        }
        while self.active_connects < self.config.max_parallel && !self.queue.is_empty() {
            // Sort by priority descending
            self.queue.sort_by(|a, b| {
                let pa = self.peers.get(a).map_or(Priority::VeryLow, |i| i.priority);
                let pb = self.peers.get(b).map_or(Priority::VeryLow, |i| i.priority);
                pb.cmp(&pa)
            });

            let pk = self.queue.remove(0);
            let (relay_addrs, force_relaying) = if let Some(info) = self.peers.get_mut(&pk) {
                info.queued = false;
                info.connecting = true;
                info.attempts += 1;
                (info.relay_addresses.clone(), info.force_relaying)
            } else {
                (vec![], false)
            };

            self.active_connects += 1;
            self.next_generation = self.next_generation.wrapping_add(1);
            let generation = self.next_generation;
            self.dial_generations.insert(pk, generation);

            let dht = self.dht.clone();
            let key_pair = self.key_pair.clone();
            let result_tx = self.connect_result_tx.clone();
            let rh = self.runtime_handle.clone();
            let mut connect_opts = peeroxide_dht::hyperdht::ConnectOpts::default();
            connect_opts.local_connection = self.config.local_connection;
            let relay_cfg = self.config.relay_through;

            let task = tokio::spawn(async move {
                let conn_runtime = UdxRuntime::shared(rh);
                // Node `_maybeRelayConnection(peerInfo.forceRelaying)`; the
                // NAT lookup lives here because the actor loop is sync.
                let randomized = dht.firewalled().await.ok() == Some(FIREWALL_RANDOM);
                connect_opts.relay_through = relay_for_dial(relay_cfg, force_relaying, randomized);
                tracing::debug!(pk = %short_hex(&pk), generation, "connecting to peer");
                match dht
                    .connect_with_options(&key_pair, pk, &relay_addrs, &conn_runtime, connect_opts)
                    .await
                {
                    Ok(conn) => {
                        tracing::info!(
                            target: "peeroxide::_events::peer::connected",
                            pk = %short_hex(&pk),
                            generation,
                            "peer connected"
                        );
                        let _ = result_tx.send(ConnectAttemptResult {
                            public_key: pk,
                            generation,
                            result: Ok((conn, conn_runtime)),
                        });
                    }
                    Err(e) => {
                        tracing::info!(
                            target: "peeroxide::_events::peer::connect_failed",
                            pk = %short_hex(&pk),
                            generation,
                            err = %e,
                            "peer connect failed"
                        );
                        let _ = result_tx.send(ConnectAttemptResult {
                            public_key: pk,
                            generation,
                            result: Err(SwarmError::Dht(e)),
                        });
                    }
                }
            });
            self.connect_tasks.insert(pk, (generation, task));
        }
    }

    fn handle_connect_result(&mut self, result: ConnectAttemptResult) {
        let pk = result.public_key;
        let generation = result.generation;
        let is_current_dial = self.dial_generations.get(&pk) == Some(&generation);

        if !is_current_dial {
            tracing::debug!(
                pk = %short_hex(&pk),
                generation,
                "stale dial result ignored"
            );
            if let Ok((conn, _)) = result.result {
                conn.stream.abort_handle().abort();
            }
            return;
        }

        self.dial_generations.remove(&pk);
        self.connect_tasks.remove(&pk);
        self.active_connects = self.active_connects.saturating_sub(1);

        if let Some(info) = self.peers.get_mut(&pk) {
            info.connecting = false;
        }

        if self.suspended {
            // Node destroys a connection that lands after suspend.
            if let Ok((conn, _)) = result.result {
                tracing::debug!(
                    pk = %short_hex(&pk),
                    "swarm suspended: dropping dial connection that landed during suspend"
                );
                conn.stream.abort_handle().abort();
            }
            return;
        }

        match result.result {
            Ok((conn, runtime)) => {
                self.retire_if_dead(&pk);

                // Dedup: compare public keys to decide tie-break
                if self.connections.has(&pk) {
                    let we_are_dominant = self.key_pair.public_key > pk;
                    if let Some(existing) = self.connections.get(&pk) {
                        if existing.is_initiator == we_are_dominant {
                            tracing::debug!(pk = %short_hex(&pk), "dedup: keeping existing");
                            conn.stream.abort_handle().abort();
                            self.attempt_connections();
                            return;
                        }
                    }
                    self.abort_connection(&pk);
                    self.connections.remove(&pk);
                }

                if self.connections.len() >= self.config.max_peers {
                    tracing::debug!(pk = %short_hex(&pk), "dial: at max connections");
                    conn.stream.abort_handle().abort();
                    self.attempt_connections();
                    return;
                }

                self.next_generation = self.next_generation.wrapping_add(1);
                let conn_gen = self.next_generation;
                self.generations.insert(pk, conn_gen);
                let conn = self.connection_watch().watch(conn, pk, conn_gen);

                self.connections
                    .add(pk, ConnectionInfo { is_initiator: true });

                let topics = if let Some(info) = self.peers.get_mut(&pk) {
                    info.connected();
                    info.topics.clone()
                } else {
                    vec![]
                };

                let swarm_conn = SwarmConnection {
                    peer: conn,
                    is_initiator: true,
                    topics,
                    _runtime: runtime,
                };
                if self.conn_tx.try_send(swarm_conn).is_err() {
                    tracing::warn!("connection channel full, dropping connection");
                }
            }
            Err(e) => {
                tracing::debug!(pk = %short_hex(&pk), err = %e, "connect failed");
                if let Some(info) = self.peers.get_mut(&pk) {
                    note_connect_error(info, self.config.relay_through.is_some(), &e);
                }
                self.schedule_retry(pk);
            }
        }

        self.attempt_connections();
    }

    /// Node `swarm._requeue`: a failed peer comes back after its backoff. Runs
    /// for topic-discovered peers and, unlike the previous topic-only retry,
    /// for explicit peers that have no topic at all.
    fn handle_retry(&mut self, pk: [u8; 32]) {
        if self.suspended {
            return;
        }
        let connected = self.connections.has(&pk);
        let should_requeue = self.should_requeue(&pk);
        let Some(info) = self.peers.get_mut(&pk) else {
            return;
        };
        info.set_waiting(false);
        if !connected && should_requeue && !info.banned && !info.queued && !info.connecting {
            info.priority = info.get_priority();
            info.queued = true;
            self.queue.push(pk);
        }
        self.attempt_connections();
    }

    fn schedule_retry(&mut self, pk: [u8; 32]) {
        let Some(info) = self.peers.get_mut(&pk) else {
            return;
        };
        if info.banned || (!info.explicit && (info.topics.is_empty() || info.attempts > 3)) {
            return;
        }

        let delay = retry_delay(info);
        info.set_waiting(true);

        let retry_tx = self.retry_tx.clone();

        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = retry_tx.send(pk);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_first_attempt_unproven() {
        let mut info = PeerInfo::new([0u8; 32], vec![]);
        info.attempts = 0;
        let d = retry_delay(&info);
        assert!(d.as_millis() >= 1000);
        assert!(d.as_millis() <= 2000);
    }

    #[test]
    fn retry_delay_first_attempt_proven() {
        let mut info = PeerInfo::new([0u8; 32], vec![]);
        info.attempts = 0;
        info.proven = true;
        let d = retry_delay(&info);
        assert!(d.as_millis() >= 1000);
        assert!(d.as_millis() <= 2000);
    }

    #[test]
    fn retry_delay_many_attempts() {
        let mut info = PeerInfo::new([0u8; 32], vec![]);
        info.attempts = 10;
        let d = retry_delay(&info);
        assert!(d.as_millis() >= 600_000);
        assert!(d.as_millis() <= 720_500);
    }

    #[test]
    fn short_hex_format() {
        let bytes = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33];
        assert_eq!(short_hex(&bytes), "deadbeef");
    }

    #[test]
    fn default_config() {
        let c = SwarmConfig::default();
        assert!(c.key_pair.is_none());
        assert_eq!(c.max_peers, 64);
        assert_eq!(c.max_parallel, 3);
        assert_eq!(c.firewall, 0);
    }

    #[test]
    fn default_join_opts() {
        let j = JoinOpts::default();
        assert!(j.server);
        assert!(j.client);
    }

    #[tokio::test]
    async fn abort_registries_prune_closed_streams() {
        let runtime = UdxRuntime::new().expect("runtime");
        let first = runtime.create_stream(1).await.expect("first");
        let second = runtime.create_stream(2).await.expect("second");
        let aborts = Mutex::new(Vec::new());
        let connections = Mutex::new(HashMap::new());
        track_abort(&aborts, first.abort_handle());
        track_conn_abort(&connections, [1; 32], 1, first.abort_handle());
        first.abort_handle().abort();
        track_abort(&aborts, second.abort_handle());
        track_conn_abort(&connections, [2; 32], 2, second.abort_handle());
        assert_eq!(aborts.lock().unwrap().len(), 1);
        let connections = connections.lock().unwrap();
        assert_eq!(connections.len(), 1);
        assert!(connections.contains_key(&[2; 32]));
    }

    #[test]
    fn relay_dial_follows_node_relay_function() {
        let cfg = Some([9u8; 32]);
        assert_eq!(
            relay_for_dial(cfg, false, false),
            None,
            "neither forced nor randomized"
        );
        assert_eq!(
            relay_for_dial(cfg, true, false),
            cfg,
            "a holepunch failure forces the relay"
        );
        assert_eq!(
            relay_for_dial(cfg, false, true),
            cfg,
            "a randomized NAT dials via the relay"
        );
        assert_eq!(
            relay_for_dial(None, true, true),
            None,
            "no relay configured"
        );
    }

    #[test]
    fn holepunch_failure_pins_the_peer_to_the_relay() {
        let mut info = PeerInfo::new([1u8; 32], vec![]);
        info.attempts = 2;
        note_connect_error(
            &mut info,
            true,
            &SwarmError::Dht(HyperDhtError::HolepunchAborted),
        );
        assert!(info.force_relaying);
        assert_eq!(info.attempts, 0, "the relay retry is fast");

        let mut aborted = PeerInfo::new([2u8; 32], vec![]);
        note_connect_error(
            &mut aborted,
            true,
            &SwarmError::Dht(HyperDhtError::HolepunchFailed),
        );
        assert!(aborted.force_relaying);

        let mut other = PeerInfo::new([3u8; 32], vec![]);
        note_connect_error(
            &mut other,
            true,
            &SwarmError::Dht(HyperDhtError::HandshakeFailed("x".into())),
        );
        assert!(
            !other.force_relaying,
            "only a holepunch failure forces the relay"
        );

        let mut no_relay = PeerInfo::new([4u8; 32], vec![]);
        note_connect_error(
            &mut no_relay,
            false,
            &SwarmError::Dht(HyperDhtError::HolepunchAborted),
        );
        assert!(!no_relay.force_relaying, "no relay configured");
    }

    #[tokio::test]
    async fn server_unregistered_on_leave_last_topic() {
        let config = SwarmConfig::default();

        let (_task, handle, _conn_rx) = crate::spawn(config).await.unwrap();
        let target = hash(&handle.key_pair().public_key);
        let topic = [0xAA; 32];

        handle
            .join(
                topic,
                JoinOpts {
                    server: true,
                    client: false,
                },
            )
            .await
            .unwrap();

        {
            let router = handle.dht().router().lock().unwrap();
            assert!(
                router.get(&target).is_some(),
                "server must be registered after join"
            );
        }

        handle.leave(topic).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        {
            let router = handle.dht().router().lock().unwrap();
            assert!(
                router.get(&target).is_none(),
                "server must be unregistered after leaving last server topic"
            );
        }

        handle.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn server_unregistered_on_destroy() {
        let config = SwarmConfig::default();

        let (_task, handle, _conn_rx) = crate::spawn(config).await.unwrap();
        let target = hash(&handle.key_pair().public_key);
        let topic = [0xBB; 32];

        handle
            .join(
                topic,
                JoinOpts {
                    server: true,
                    client: false,
                },
            )
            .await
            .unwrap();

        {
            let router = handle.dht().router().lock().unwrap();
            assert!(
                router.get(&target).is_some(),
                "server must be registered after join"
            );
        }

        handle.destroy().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        {
            let router = handle.dht().router().lock().unwrap();
            assert!(
                router.get(&target).is_none(),
                "server must be unregistered after destroy"
            );
        }
    }

    #[tokio::test]
    async fn server_unregistered_on_handle_drop() {
        let config = SwarmConfig::default();

        let (task, handle, _conn_rx) = crate::spawn(config).await.unwrap();
        let dht_handle = handle.dht().clone();
        let target = hash(&handle.key_pair().public_key);
        let topic = [0xCC; 32];

        handle
            .join(
                topic,
                JoinOpts {
                    server: true,
                    client: false,
                },
            )
            .await
            .unwrap();

        {
            let router = dht_handle.router().lock().unwrap();
            assert!(
                router.get(&target).is_some(),
                "server must be registered after join"
            );
        }

        drop(handle);
        drop(_conn_rx);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;

        {
            let router = dht_handle.router().lock().unwrap();
            assert!(
                router.get(&target).is_none(),
                "server must be unregistered after implicit shutdown (handle drop)"
            );
        }
    }

    async fn create_test_connection_pair(rt: &UdxRuntime) -> (PeerConnection, PeerConnection) {
        let socket_a = rt.create_socket().await.expect("socket_a");
        socket_a
            .bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind_a");
        let addr_a = socket_a.local_addr().await.expect("addr_a");

        let socket_b = rt.create_socket().await.expect("socket_b");
        socket_b
            .bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind_b");
        let addr_b = socket_b.local_addr().await.expect("addr_b");

        let (id_a, stream_a) = rt.create_random_stream().await.expect("stream_a");
        let (id_b, stream_b) = rt.create_random_stream().await.expect("stream_b");
        stream_a
            .connect(&socket_a, id_b, addr_b)
            .await
            .expect("connect_a");
        stream_b
            .connect(&socket_b, id_a, addr_a)
            .await
            .expect("connect_b");

        let kp_a = KeyPair::from_seed([1; 32]);
        let kp_b = KeyPair::from_seed([2; 32]);

        let noise_a = NoiseKeypair {
            public_key: kp_a.public_key,
            secret_key: kp_a.secret_key,
        };
        let noise_b = NoiseKeypair {
            public_key: kp_b.public_key,
            secret_key: kp_b.secret_key,
        };

        let (ss_a, ss_b) = tokio::try_join!(
            SecretStream::new(true, stream_a.into_async_stream(), noise_a),
            SecretStream::new(false, stream_b.into_async_stream(), noise_b)
        )
        .expect("handshake");

        (
            PeerConnection::new(ss_a, kp_b.public_key, socket_a, None),
            PeerConnection::new(ss_b, kp_a.public_key, socket_b, None),
        )
    }

    async fn make_test_actor(
        runtime: &UdxRuntime,
    ) -> (SwarmActor, mpsc::Receiver<SwarmConnection>) {
        let key_pair = KeyPair::generate();
        let (_dht_join, dht, _server_rx) = hyperdht::spawn(runtime, HyperDhtConfig::default())
            .await
            .expect("dht");

        let (conn_tx, conn_rx) = mpsc::channel(64);
        let (discovery_event_tx, _discovery_event_rx) = mpsc::unbounded_channel();
        let (connect_result_tx, _connect_result_rx) = mpsc::unbounded_channel();
        let (retry_tx, _retry_rx) = mpsc::unbounded_channel();
        let (closed_tx, _closed_rx) = mpsc::unbounded_channel();

        let mut server = dht.create_shared_server(
            runtime,
            ServerConfig::for_swarm(key_pair.clone(), 0, None, None),
        );
        let _server_conns = server.take_connections();

        let actor = SwarmActor {
            key_pair,
            dht,
            config: ActorConfig {
                max_peers: 64,
                max_parallel: 3,
                relay_through: None,
                local_connection: true,
                eager: false,
            },
            runtime_handle: runtime.handle(),
            topics: HashMap::new(),
            discovery_event_tx,
            peers: HashMap::new(),
            connections: ConnectionSet::new(),
            aborts: Arc::new(Mutex::new(Vec::new())),
            queue: Vec::new(),
            connect_tasks: HashMap::new(),
            dial_generations: HashMap::new(),
            connect_result_tx,
            retry_tx,
            suspended: false,
            listening: false,
            server,
            server_registered: true,
            relay_address: None,
            active_connects: 0,
            flush_waiters: Vec::new(),
            closed_tx: Some(closed_tx),
            generations: HashMap::new(),
            conn_aborts: Arc::new(Mutex::new(HashMap::new())),
            next_generation: 0,
            conn_tx,
        };
        (actor, conn_rx)
    }

    #[tokio::test]
    async fn ready_server_connection_invalidates_an_older_dial_completion() {
        let runtime = UdxRuntime::new().unwrap();
        let (mut actor, mut published) = make_test_actor(&runtime).await;
        let (incoming, _peer) = create_test_connection_pair(&runtime).await;
        let pk = incoming.remote_public_key;
        actor.dial_generations.insert(pk, 10);
        actor.active_connects = 1;
        actor.queue.push(pk);
        actor.handle_server_connection(incoming);
        let _current = published.try_recv().unwrap();
        let current_generation = *actor.generations.get(&pk).unwrap();
        assert!(!actor.dial_generations.contains_key(&pk));
        assert_eq!(actor.active_connects, 0);
        assert!(!actor.queue.contains(&pk));
        let (stale, _other) = create_test_connection_pair(&runtime).await;
        let stale_abort = stale.stream.abort_handle();
        actor.handle_connect_result(ConnectAttemptResult {
            public_key: pk,
            generation: 10,
            result: Ok((stale, UdxRuntime::shared(runtime.handle()))),
        });
        assert!(!stale_abort.is_alive());
        assert_eq!(actor.generations.get(&pk), Some(&current_generation));
        assert!(published.try_recv().is_err());
        assert_eq!(actor.active_connects, 0);
    }

    #[tokio::test]
    async fn ready_server_connections_are_rejected_when_closed_stopped_or_at_capacity() {
        let runtime = UdxRuntime::new().unwrap();
        for (registered, suspended, capacity, closed) in [
            (false, false, 1, false),
            (true, true, 1, false),
            (true, false, 0, false),
            (true, false, 1, true),
        ] {
            let (mut actor, mut published) = make_test_actor(&runtime).await;
            actor.server_registered = registered;
            actor.suspended = suspended;
            actor.config.max_peers = capacity;
            let (conn, _peer) = create_test_connection_pair(&runtime).await;
            let pk = conn.remote_public_key;
            let abort = conn.stream.abort_handle();
            if closed {
                abort.abort();
            }
            actor.handle_server_connection(conn);
            assert!(!abort.is_alive());
            assert!(!actor.connections.has(&pk));
            assert!(!actor.generations.contains_key(&pk));
            assert!(published.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn stale_dial_success_is_dropped_and_does_not_overwrite_newer_generation() {
        let runtime = UdxRuntime::new().expect("runtime");
        let (mut actor, mut conn_rx) = make_test_actor(&runtime).await;

        let pk = [42u8; 32];
        actor.active_connects = 1;
        actor.dial_generations.insert(pk, 1);

        // A newer dial generation replaces generation 1 before it finishes.
        actor.dial_generations.insert(pk, 2);

        // Generation 1 dial finishes late with Ok.
        let (conn1, _peer1) = create_test_connection_pair(&runtime).await;
        let handle1 = conn1.stream.abort_handle();
        actor.handle_connect_result(ConnectAttemptResult {
            public_key: pk,
            generation: 1,
            result: Ok((conn1, UdxRuntime::shared(runtime.handle()))),
        });

        // Stale success must not be published.
        assert!(
            conn_rx.try_recv().is_err(),
            "stale generation 1 connection must not be published"
        );
        // Stale stream must be aborted.
        assert!(
            !handle1.is_alive(),
            "stale connection stream must be aborted"
        );
        // Generation 2 must still be current dial generation.
        assert_eq!(actor.dial_generations.get(&pk), Some(&2));
        // active_connects must NOT be decremented by stale attempt.
        assert_eq!(
            actor.active_connects, 1,
            "stale attempt must not decrement active_connects"
        );

        // When generation 2 finishes, it is accepted and published.
        let (conn2, _peer2) = create_test_connection_pair(&runtime).await;
        let peer_pk = conn2.remote_public_key;
        actor.handle_connect_result(ConnectAttemptResult {
            public_key: pk,
            generation: 2,
            result: Ok((conn2, UdxRuntime::shared(runtime.handle()))),
        });

        let published = conn_rx
            .try_recv()
            .expect("generation 2 connection must be published");
        assert_eq!(published.peer.remote_public_key, peer_pk);
        let aborts = actor.conn_aborts.lock().unwrap();
        assert!(aborts.contains_key(&pk));
        assert_eq!(actor.active_connects, 0);
    }

    #[tokio::test]
    async fn stale_dial_failure_does_not_remove_replacement_connection_or_decrement_attempts() {
        let runtime = UdxRuntime::new().expect("runtime");
        let (mut actor, _conn_rx) = make_test_actor(&runtime).await;

        let pk = [43u8; 32];
        actor.connections.add(
            pk,
            ConnectionInfo {
                is_initiator: false,
            },
        );
        actor.generations.insert(pk, 10);
        actor.active_connects = 1;
        actor.dial_generations.insert(pk, 2);

        // A stale generation 1 dial fails late.
        actor.handle_connect_result(ConnectAttemptResult {
            public_key: pk,
            generation: 1,
            result: Err(SwarmError::ChannelClosed),
        });

        // Replacement connection and current dial attempt must NOT be touched.
        assert!(
            actor.connections.has(&pk),
            "stale failure must not remove replacement connection from ConnectionSet"
        );
        assert_eq!(
            actor.generations.get(&pk),
            Some(&10),
            "stale failure must not remove replacement generation"
        );
        assert_eq!(
            actor.dial_generations.get(&pk),
            Some(&2),
            "stale failure must not remove current dial generation"
        );
        assert_eq!(
            actor.active_connects, 1,
            "stale failure must not decrement active_connects of another attempt"
        );

        // Current dial generation 2 failure does clean up the dial.
        actor.handle_connect_result(ConnectAttemptResult {
            public_key: pk,
            generation: 2,
            result: Err(SwarmError::ChannelClosed),
        });
        assert_eq!(actor.dial_generations.get(&pk), None);
        assert_eq!(actor.active_connects, 0);
        // And replacement connection is still intact.
        assert!(actor.connections.has(&pk));
    }

    #[tokio::test]
    async fn server_connection_retires_dead_stream_and_publishes_ready_connection() {
        let runtime = UdxRuntime::new().expect("runtime");
        let (mut actor, mut conn_rx) = make_test_actor(&runtime).await;

        let (conn1, _peer1) = create_test_connection_pair(&runtime).await;
        let pk = conn1.remote_public_key;
        actor.handle_server_connection(conn1);
        let published1 = conn_rx.try_recv().expect("published1");
        assert_eq!(published1.peer.remote_public_key, pk);
        assert_eq!(actor.generations.get(&pk), Some(&1));

        // Stream dies
        published1.peer.stream.abort_handle().abort();

        // New server connection arrives for pk
        let (conn2, _peer2) = create_test_connection_pair(&runtime).await;
        actor.handle_server_connection(conn2);

        let published2 = conn_rx.try_recv().expect("published2");
        assert_eq!(published2.peer.remote_public_key, pk);
        assert_eq!(actor.generations.get(&pk), Some(&2));
    }

    #[tokio::test]
    async fn stale_close_does_not_remove_replacement_connection() {
        let runtime = UdxRuntime::new().expect("runtime");
        let (mut actor, _conn_rx) = make_test_actor(&runtime).await;

        let pk = [44u8; 32];
        let (conn1, _peer1) = create_test_connection_pair(&runtime).await;
        let (conn2, _peer2) = create_test_connection_pair(&runtime).await;

        actor.connections.add(
            pk,
            ConnectionInfo {
                is_initiator: false,
            },
        );
        actor.generations.insert(pk, 1);
        track_conn_abort(&actor.conn_aborts, pk, 1, conn1.stream.abort_handle());

        // Generation 2 replaces generation 1.
        actor.generations.insert(pk, 2);
        track_conn_abort(&actor.conn_aborts, pk, 2, conn2.stream.abort_handle());

        // Late close notification for generation 1 arrives.
        actor.handle_close(pk, 1);

        // Generation 2 must still be present.
        assert!(
            actor.connections.has(&pk),
            "stale close must not remove replacement connection from ConnectionSet"
        );
        assert_eq!(
            actor.generations.get(&pk),
            Some(&2),
            "stale close must not remove replacement generation"
        );
        let aborts = actor.conn_aborts.lock().unwrap();
        assert_eq!(aborts.get(&pk).map(|(generation, _)| *generation), Some(2));
    }

    #[tokio::test]
    async fn close_queued_behind_redial_retires_dead_stream_before_tie_break() {
        let runtime = UdxRuntime::new().expect("runtime");
        let (mut actor, _conn_rx) = make_test_actor(&runtime).await;

        let (conn1, _peer1) = create_test_connection_pair(&runtime).await;
        let abort_handle = conn1.stream.abort_handle();

        // Make actor dominant over pk:
        let pk = [0u8; 32];
        actor.key_pair = KeyPair {
            public_key: [0xff; 32],
            secret_key: [0xff; 64],
        };
        assert!(actor.key_pair.public_key > pk);

        actor.connections.add(
            pk,
            ConnectionInfo {
                is_initiator: false,
            },
        );
        actor.generations.insert(pk, 1);
        track_conn_abort(&actor.conn_aborts, pk, 1, abort_handle.clone());

        // Stream dies, but close notification has not been processed yet:
        abort_handle.abort();
        assert!(!abort_handle.is_alive());

        // A redial arrives. retire_if_dead runs before tie-break:
        assert!(actor.connections.has(&pk));
        assert!(
            actor.retire_if_dead(&pk),
            "retire_if_dead must retire the dead stream"
        );
        assert!(
            !actor.connections.has(&pk),
            "connections must be cleared so redial is not rejected by duplicate tie-break"
        );
        assert_eq!(actor.generations.get(&pk), None);

        // New handshake accepted as generation 2:
        actor.connections.add(
            pk,
            ConnectionInfo {
                is_initiator: false,
            },
        );
        actor.generations.insert(pk, 2);

        // Later, queued close notification for generation 1 finally arrives:
        actor.handle_close(pk, 1);

        // Generation 2 must not be removed by the queued stale close:
        assert!(actor.connections.has(&pk));
        assert_eq!(actor.generations.get(&pk), Some(&2));
    }

    #[tokio::test]
    async fn abort_registries_prune_on_close() {
        let runtime = UdxRuntime::new().expect("runtime");
        let (mut actor, _conn_rx) = make_test_actor(&runtime).await;

        let (conn1, _peer1) = create_test_connection_pair(&runtime).await;
        let (conn2, _peer2) = create_test_connection_pair(&runtime).await;

        track_abort(&actor.aborts, conn1.stream.abort_handle());
        track_abort(&actor.aborts, conn2.stream.abort_handle());
        track_conn_abort(
            &actor.conn_aborts,
            [1u8; 32],
            1,
            conn1.stream.abort_handle(),
        );
        track_conn_abort(
            &actor.conn_aborts,
            [2u8; 32],
            2,
            conn2.stream.abort_handle(),
        );

        // Abort first stream
        conn1.stream.abort_handle().abort();

        // handle_close prunes abort registries
        actor.handle_close([1u8; 32], 999);

        let aborts = actor.aborts.lock().unwrap();
        assert_eq!(
            aborts.len(),
            1,
            "dead abort handle must be pruned from aborts on close"
        );

        let conn_aborts = actor.conn_aborts.lock().unwrap();
        assert_eq!(
            conn_aborts.len(),
            1,
            "dead abort handle must be pruned from conn_aborts on close"
        );
        assert!(conn_aborts.contains_key(&[2u8; 32]));
    }
}
