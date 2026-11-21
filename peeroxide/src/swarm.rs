use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::Rng;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

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
use peeroxide_dht::secret_stream::{SecretStreamKeepAlive, SecretStreamStats};

/// Node keeps `_allConnections` and drops a connection on `'close'`; the
/// handle of a dead stream still pins its buffers, so prune on every push.
fn track_abort(aborts: &Mutex<Vec<libudx::UdxStreamAbort>>, handle: libudx::UdxStreamAbort) {
    if let Ok(mut aborts) = aborts.lock() {
        aborts.retain(|h| h.is_alive());
        aborts.push(handle);
    }
}

enum ConnectionState {
    Dialing {
        task: JoinHandle<()>,
    },
    Open {
        is_initiator: bool,
        abort: libudx::UdxStreamAbort,
        stats: SecretStreamStats,
        keep_alive: KeepAliveProbe,
    },
}

/// `existing.sendKeepAlive()` for a kept connection, at most one in flight.
/// The swarm hands connections out unsplit, so a probe resolves only when
/// the owner next polls the stream (Protomux keeps a read pending) or the
/// stream is dropped; until then later duplicates add no task.
struct KeepAliveProbe {
    handle: SecretStreamKeepAlive<libudx::UdxAsyncStream>,
    in_flight: Arc<AtomicBool>,
}

impl KeepAliveProbe {
    fn new(handle: SecretStreamKeepAlive<libudx::UdxAsyncStream>) -> Self {
        Self {
            handle,
            in_flight: Arc::new(AtomicBool::new(false)),
        }
    }

    fn send(&self) {
        if self.in_flight.swap(true, Ordering::AcqRel) {
            return;
        }
        let handle = self.handle.clone();
        let in_flight = Arc::clone(&self.in_flight);
        tokio::spawn(async move {
            let _ = handle.send_keep_alive().await;
            in_flight.store(false, Ordering::Release);
        });
    }
}

struct ConnectionEntry {
    generation: u64,
    state: ConnectionState,
}

type ConnectionMap = HashMap<[u8; 32], ConnectionEntry>;

/// Everything a spawned connection task needs to register its connection with
/// the actor before handing it out: the abort handles (for suspend and destroy)
/// and the close notification that frees the peer's slot.
#[derive(Clone)]
struct ConnectionWatch {
    aborts: Arc<Mutex<Vec<libudx::UdxStreamAbort>>>,
    closed_tx: Option<mpsc::UnboundedSender<([u8; 32], u64)>>,
}

impl ConnectionWatch {
    /// Register `conn` for close/abort and give it back, ready to hand out.
    fn watch(&self, mut conn: PeerConnection, pk: [u8; 32], generation: u64) -> PeerConnection {
        track_abort(&self.aborts, conn.stream.abort_handle());
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

/// Node's connect `onerror` (`shouldForceRelaying`): a holepunch failure with a relay
/// configured pins the peer to the relay and resets the attempts, so the relay retry is fast.
/// A probe timeout does not pin the peer, as in Node.
fn note_connect_error(info: &mut PeerInfo, relay_configured: bool, err: &SwarmError) {
    let holepunch_failure = matches!(
        err,
        SwarmError::Dht(
            HyperDhtError::HolepunchAborted
                | HyperDhtError::HolepunchFailed
                | HyperDhtError::HolepunchDoubleRandomizedNats
                | HyperDhtError::RemoteNotHolepunchable
        )
    );
    if relay_configured && holepunch_failure {
        info.force_relaying = true;
        info.attempts = 0;
    }
}

fn existing_is_outdated(stats: &SecretStreamStats) -> bool {
    stats.raw_bytes_read() > 0 && stats.raw_bytes_written() > 0
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
    /// The swarm aborts every connection it handed out through the connection
    /// channel, as Node `swarm.destroy()` does.
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
    /// server route is installed. Calling it again is a no-op.
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
    /// Mirrors Node `swarm.suspend()` and aborts every connection it handed
    /// out through the connection channel.
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
    /// Node's `_allConnections`: one entry owns each peer's current dial or
    /// open stream, so duplicate arbitration always sees in-flight dials.
    all_connections: ConnectionMap,
    /// Abort handles for streams already handed to the caller. Dials are
    /// cancelled through `all_connections`.
    aborts: Arc<Mutex<Vec<libudx::UdxStreamAbort>>>,
    queue: Vec<[u8; 32]>,
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

    flush_waiters: Vec<oneshot::Sender<Result<(), SwarmError>>>,
    /// Fires `(pk, generation)` when a connection's stream closes, whichever
    /// side opened it (Node's `conn.on('close')`).
    closed_tx: Option<mpsc::UnboundedSender<([u8; 32], u64)>>,
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
        all_connections: HashMap::new(),
        aborts: Arc::new(Mutex::new(Vec::new())),
        queue: Vec::new(),
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
        flush_waiters: Vec::new(),
        closed_tx: None,
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
                if self.suspended
                    || (self.all_topics_refreshed()
                        && (self.queue.is_empty()
                            || self.open_connections() >= self.config.max_peers)
                        && self.active_dials() == 0)
                {
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
        if let Some(state) = self.topics.remove(&topic) {
            let server = server || state.is_server;
            let client = client || state.is_client;
            if server == state.is_server && client == state.is_client {
                self.topics.insert(topic, state);
                return Ok(());
            }
            if let Some(cancel) = state.cancel_tx {
                let _ = cancel.send(());
            }
            if let Some(task) = state.task {
                task.abort();
            }
            if server {
                self.ensure_server_listening().await?;
            }
            if self.suspended {
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
            return Ok(());
        }

        if server {
            self.ensure_server_listening().await?;
        }
        if self.suspended {
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
                .listen_in_background(&self.key_pair)
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
        // Handshakes are answered again before this returns; the announce runs in the server task.
        self.server
            .resume_in_background()
            .await
            .map_err(SwarmError::Dht)?;
        Ok(())
    }

    /// Node `swarm.joinPeer(publicKey)`: queue a peer that was named
    /// explicitly instead of discovered on a topic.
    fn do_join_peer(&mut self, public_key: [u8; 32]) -> Result<(), SwarmError> {
        if public_key == self.key_pair.public_key {
            return Ok(());
        }
        let enqueue = {
            let info = self
                .peers
                .entry(public_key)
                .or_insert_with(|| PeerInfo::new(public_key, vec![]));
            info.explicit = true;
            let enqueue = !self.all_connections.contains_key(&public_key)
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
            self.attempt_connections();
        }
        Ok(())
    }

    /// Node `swarm.leavePeer(publicKey)`: drop the explicit flag and garbage
    /// collect the peer when it has no topics left. A connection is not closed.
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
        if gc && !self.all_connections.contains_key(public_key) {
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

        for (_, entry) in self.all_connections.drain() {
            match entry.state {
                ConnectionState::Dialing { task } => task.abort(),
                ConnectionState::Open { abort, .. } => abort.abort(),
            }
        }
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
            if let Err(error) = self.ensure_server_listening().await {
                self.suspended = true;
                let _ = self.dht.suspend().await;
                return Err(error);
            }
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
                !info.banned && !self.all_connections.contains_key(*pk) && still_joined
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
            tokio::spawn(stop_task(state.task.take(), !force));
        }

        for (_, entry) in self.all_connections.drain() {
            match entry.state {
                ConnectionState::Dialing { task } => task.abort(),
                ConnectionState::Open { abort, .. } => abort.abort(),
            }
        }
        self.queue.clear();
        if let Ok(mut aborts) = self.aborts.lock() {
            for handle in std::mem::take(&mut *aborts) {
                handle.abort();
            }
        }

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
            if state.is_server {
                let dht = self.dht.clone();
                let key_pair = self.key_pair.clone();
                tokio::spawn(async move {
                    let _ = dht.unannounce(topic, &key_pair).await;
                });
            }
            for peer in self.peers.values_mut() {
                peer.topics.retain(|t| *t != topic);
            }
            if state.is_server && self.server_registered && !self.listening {
                let has_remaining_server_topics = self.topics.values().any(|t| t.is_server);
                if !has_remaining_server_topics {
                    self.server.suspend().await.map_err(SwarmError::Dht)?;
                    let target = hash(&self.key_pair.public_key);
                    self.dht.unregister_server(&target);
                    self.server_registered = false;
                }
            }
        }
        self.check_flush_waiters();
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
                if self.all_connections.contains_key(&public_key) {
                    return;
                }
                if self.open_connections() >= self.config.max_peers {
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
        self.topics.values().all(|topic| topic.refreshed)
    }

    fn active_dials(&self) -> usize {
        self.all_connections
            .values()
            .filter(|entry| matches!(&entry.state, ConnectionState::Dialing { .. }))
            .count()
    }

    fn open_connections(&self) -> usize {
        self.all_connections
            .values()
            .filter(|entry| matches!(&entry.state, ConnectionState::Open { .. }))
            .count()
    }

    fn check_flush_waiters(&mut self) {
        if self.all_topics_refreshed()
            && (self.queue.is_empty() || self.open_connections() >= self.config.max_peers)
            && self.active_dials() == 0
        {
            for waiter in self.flush_waiters.drain(..) {
                let _ = waiter.send(Ok(()));
            }
        }
    }

    fn connection_watch(&self) -> ConnectionWatch {
        ConnectionWatch {
            aborts: Arc::clone(&self.aborts),
            closed_tx: self.closed_tx.clone(),
        }
    }

    fn abort_entry(&mut self, pk: &[u8; 32]) {
        let Some(entry) = self.all_connections.remove(pk) else {
            return;
        };
        match entry.state {
            ConnectionState::Dialing { task } => {
                task.abort();
                if let Some(info) = self.peers.get_mut(pk) {
                    info.connecting = false;
                    info.queued = false;
                }
            }
            ConnectionState::Open { abort, .. } => abort.abort(),
        }
    }

    /// Prune dead abort handles and retire `pk` if `generation` matches current.
    fn handle_close(&mut self, pk: [u8; 32], generation: u64) {
        if let Ok(mut aborts) = self.aborts.lock() {
            aborts.retain(|h| h.is_alive());
        }
        if self
            .all_connections
            .get(&pk)
            .is_some_and(|entry| entry.generation == generation)
        {
            self.retire_connection(&pk);
        }
    }

    /// Retire the active connection for `pk`, then retry if we dialled it.
    fn retire_connection(&mut self, pk: &[u8; 32]) {
        let was_initiator = self.all_connections.remove(pk).is_some_and(|entry| {
            matches!(
                entry.state,
                ConnectionState::Open {
                    is_initiator: true,
                    ..
                }
            )
        });
        if let Some(info) = self.peers.get_mut(pk) {
            info.disconnected();
        }
        if was_initiator {
            self.schedule_retry(*pk);
        }
        self.maybe_delete_peer(pk);
        self.attempt_connections();
        self.check_flush_waiters();
    }

    /// If an existing current stream is already dead, retire it before
    /// duplicate tie-break even when its close notification is queued.
    fn retire_if_dead(&mut self, pk: &[u8; 32]) -> bool {
        let dead = self.all_connections.get(pk).is_some_and(|entry| {
            matches!(
                &entry.state,
                ConnectionState::Open { abort, .. } if !abort.is_alive()
            )
        });
        if dead {
            self.retire_connection(pk);
        }
        dead
    }

    fn handle_server_connection(&mut self, conn: PeerConnection) {
        let pk = conn.remote_public_key;
        if self.suspended || !self.server_registered || !conn.stream.abort_handle().is_alive() {
            conn.stream.abort_handle().abort();
            return;
        }

        self.retire_if_dead(&pk);
        let replace_existing = if let Some(entry) = self.all_connections.get(&pk) {
            match &entry.state {
                ConnectionState::Dialing { .. } if self.key_pair.public_key > pk => {
                    // The dominant side keeps its in-flight dial, just as
                    // hyperswarm's `_allConnections` does.
                    conn.stream.abort_handle().abort();
                    return;
                }
                ConnectionState::Dialing { .. } => true,
                ConnectionState::Open {
                    stats, keep_alive, ..
                } => {
                    // Hyperswarm replaces a stream that has carried data:
                    // the remote peer is reconnecting after losing it.
                    let existing_is_outdated = existing_is_outdated(stats);
                    if !existing_is_outdated
                        && conn.is_initiator() != (self.key_pair.public_key > pk)
                    {
                        // `existing.sendKeepAlive()`: probe the kept
                        // connection so a dead one is found soon.
                        keep_alive.send();
                        conn.stream.abort_handle().abort();
                        return;
                    }
                    true
                }
            }
        } else {
            false
        };
        if replace_existing {
            self.abort_entry(&pk);
        }

        if self.open_connections() >= self.config.max_peers {
            tracing::debug!(pk = %short_hex(&pk), "server: at max connections");
            conn.stream.abort_handle().abort();
            return;
        }
        self.queue.retain(|queued| queued != &pk);
        if let Some(info) = self.peers.get_mut(&pk) {
            info.queued = false;
            info.connecting = false;
        }

        self.next_generation = self.next_generation.wrapping_add(1);
        let generation = self.next_generation;
        let abort = conn.stream.abort_handle();
        let stats = conn.stream.stats_handle();
        let keep_alive = KeepAliveProbe::new(conn.stream.keep_alive_handle());
        let conn = self.connection_watch().watch(conn, pk, generation);
        self.all_connections.insert(
            pk,
            ConnectionEntry {
                generation,
                state: ConnectionState::Open {
                    is_initiator: false,
                    abort,
                    stats,
                    keep_alive,
                },
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
        self.attempt_connections();
        self.check_flush_waiters();
    }

    fn attempt_connections(&mut self) {
        if self.suspended {
            return;
        }
        while self.active_dials() < self.config.max_parallel
            && self.open_connections() < self.config.max_peers
            && !self.queue.is_empty()
        {
            self.queue.sort_by(|a, b| {
                let pa = self.peers.get(a).map_or(Priority::VeryLow, |i| i.priority);
                let pb = self.peers.get(b).map_or(Priority::VeryLow, |i| i.priority);
                pb.cmp(&pa)
            });

            let pk = self.queue.remove(0);
            if self.all_connections.contains_key(&pk) {
                continue;
            }
            let (relay_addrs, force_relaying) = if let Some(info) = self.peers.get_mut(&pk) {
                info.queued = false;
                info.connecting = true;
                info.attempts += 1;
                (info.relay_addresses.clone(), info.force_relaying)
            } else {
                continue;
            };

            self.next_generation = self.next_generation.wrapping_add(1);
            let generation = self.next_generation;
            let dht = self.dht.clone();
            let key_pair = self.key_pair.clone();
            let result_tx = self.connect_result_tx.clone();
            let rh = self.runtime_handle.clone();
            let mut connect_opts = peeroxide_dht::hyperdht::ConnectOpts::default();
            connect_opts.local_connection = self.config.local_connection;
            let relay_cfg = self.config.relay_through;

            let task = tokio::spawn(async move {
                let conn_runtime = UdxRuntime::shared(rh);
                let randomized = dht.firewalled().await.ok() == Some(FIREWALL_RANDOM);
                connect_opts.relay_through = relay_for_dial(relay_cfg, force_relaying, randomized);
                match dht
                    .connect_with_options(&key_pair, pk, &relay_addrs, &conn_runtime, connect_opts)
                    .await
                {
                    Ok(conn) => {
                        let _ = result_tx.send(ConnectAttemptResult {
                            public_key: pk,
                            generation,
                            result: Ok((conn, conn_runtime)),
                        });
                    }
                    Err(e) => {
                        let _ = result_tx.send(ConnectAttemptResult {
                            public_key: pk,
                            generation,
                            result: Err(SwarmError::Dht(e)),
                        });
                    }
                }
            });
            self.all_connections.insert(
                pk,
                ConnectionEntry {
                    generation,
                    state: ConnectionState::Dialing { task },
                },
            );
        }
        self.check_flush_waiters();
    }

    fn handle_connect_result(&mut self, result: ConnectAttemptResult) {
        let pk = result.public_key;
        let generation = result.generation;
        let current = self.all_connections.get(&pk).is_some_and(|entry| {
            entry.generation == generation
                && matches!(&entry.state, ConnectionState::Dialing { .. })
        });
        if !current {
            if let Ok((conn, _)) = result.result {
                conn.stream.abort_handle().abort();
            }
            return;
        }
        self.all_connections.remove(&pk);
        if let Some(info) = self.peers.get_mut(&pk) {
            info.connecting = false;
        }

        if self.suspended {
            if let Ok((conn, _)) = result.result {
                conn.stream.abort_handle().abort();
            }
            return;
        }

        match result.result {
            Ok((conn, runtime)) => {
                if self.open_connections() >= self.config.max_peers {
                    conn.stream.abort_handle().abort();
                } else {
                    self.next_generation = self.next_generation.wrapping_add(1);
                    let generation = self.next_generation;
                    let abort = conn.stream.abort_handle();
                    let stats = conn.stream.stats_handle();
                    let keep_alive = KeepAliveProbe::new(conn.stream.keep_alive_handle());
                    let conn = self.connection_watch().watch(conn, pk, generation);
                    self.all_connections.insert(
                        pk,
                        ConnectionEntry {
                            generation,
                            state: ConnectionState::Open {
                                is_initiator: true,
                                abort,
                                stats,
                                keep_alive,
                            },
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
                        is_initiator: true,
                        topics,
                        _runtime: runtime,
                    };
                    if self.conn_tx.try_send(swarm_conn).is_err() {
                        tracing::warn!("connection channel full, dropping connection");
                    }
                }
            }
            Err(e) => {
                if let Some(info) = self.peers.get_mut(&pk) {
                    note_connect_error(info, self.config.relay_through.is_some(), &e);
                }
                self.schedule_retry(pk);
            }
        }
        self.attempt_connections();
        self.check_flush_waiters();
    }

    /// Node `swarm._requeue`: a failed peer comes back after its backoff.
    fn handle_retry(&mut self, pk: [u8; 32]) {
        if self.suspended {
            return;
        }
        let active = self.all_connections.contains_key(&pk);
        let should_requeue = self.should_requeue(&pk);
        let Some(info) = self.peers.get_mut(&pk) else {
            return;
        };
        info.set_waiting(false);
        if !active && should_requeue && !info.banned && !info.queued && !info.connecting {
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
        let info = PeerInfo::new([0u8; 32], vec![]);
        let d = retry_delay(&info);
        assert!(d.as_millis() >= 1000);
        assert!(d.as_millis() <= 2000);
    }

    #[test]
    fn relay_dial_follows_node_relay_function() {
        let cfg = Some([9u8; 32]);
        assert_eq!(relay_for_dial(cfg, false, false), None);
        assert_eq!(relay_for_dial(cfg, true, false), cfg);
        assert_eq!(relay_for_dial(cfg, false, true), cfg);
    }

    #[test]
    fn holepunch_failures_pin_the_peer_to_the_relay() {
        for error in [
            HyperDhtError::HolepunchAborted,
            HyperDhtError::HolepunchFailed,
            HyperDhtError::HolepunchDoubleRandomizedNats,
            HyperDhtError::RemoteNotHolepunchable,
        ] {
            let mut info = PeerInfo::new([1u8; 32], vec![]);
            note_connect_error(&mut info, true, &SwarmError::Dht(error));
            assert!(info.force_relaying);
            assert_eq!(info.attempts, 0);
        }
    }

    #[test]
    fn empty_topic_set_is_flushed() {
        assert!(
            HashMap::<[u8; 32], TopicState>::new()
                .values()
                .all(|topic| topic.refreshed)
        );
    }

    #[test]
    fn peer_without_pending_work_is_collectable() {
        let info = PeerInfo::new([0; 32], vec![]);
        assert!(info.should_gc());
    }
}
