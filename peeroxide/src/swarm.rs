use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use rand::Rng;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use std::sync::{Arc, Mutex};

use libudx::{RuntimeHandle, UdxRuntime, UdxSocket, UdxStream};
use peeroxide_dht::crypto::hash;
use peeroxide_dht::holepuncher::{HolepunchEvent, Holepuncher};
use peeroxide_dht::hyperdht::{
    self, HyperDhtConfig, HyperDhtHandle, KeyPair, PeerConnection, ServerEvent,
    ServerReply,
};
use peeroxide_dht::hyperdht_messages::{
    encode_handshake_to_bytes, encode_holepunch_msg_to_bytes, HandshakeMessage, HolepunchInfo,
    HolepunchMessage, HolepunchPayload, NoisePayload, RelayThroughInfo, SecretStreamInfo, UdxInfo,
    ERROR_NONE, FIREWALL_CONSISTENT, FIREWALL_OPEN, FIREWALL_RANDOM, FIREWALL_UNKNOWN,
    MODE_FROM_RELAY, MODE_FROM_SECOND_RELAY, MODE_FROM_SERVER, MODE_REPLY,
};
use peeroxide_dht::messages::Ipv4Peer;
use peeroxide_dht::noise::Keypair as NoiseKeypair;
use peeroxide_dht::noise_wrap::{NoiseWrap, NoiseWrapResult};
use peeroxide_dht::secret_stream::SecretStream;
use peeroxide_dht::secure_payload::SecurePayload;
use peeroxide_dht::socket_pool::SocketPool;

use crate::connection_set::{ConnectionInfo, ConnectionSet};
use crate::error::SwarmError;
use crate::peer_discovery::{run_discovery, DiscoveryEvent, PeerDiscoveryConfig};
use crate::peer_info::{PeerInfo, Priority};

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
        track_conn_abort(&self.conn_aborts, pk, generation, conn.stream.abort_handle());
        if let (Some(closed), Some(sender)) =
            (conn.stream.take_close_notification(), self.closed_tx.clone())
        {
            tokio::spawn(async move {
                let _ = closed.await;
                let _ = sender.send((pk, generation));
            });
        }
        conn
    }
}

const DEFAULT_MAX_PEERS: usize = 64;
const DEFAULT_MAX_PARALLEL: usize = 3;

/// HyperDHT refreshes server announcements approximately every five minutes.
const ANNOUNCE_REFRESH_INTERVAL: Duration = Duration::from_secs(300);
const ANNOUNCE_REFRESH_JITTER_MS: u64 = 500;

/// How long a graceful destroy waits for one discovery/announcer task to
/// stop announcing before aborting it anyway. Node's `clear()` awaits the
/// same tasks without a bound; a bound keeps `destroy()` from hanging on an
/// unreachable DHT.
const STOP_TASK_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the reply to a server-side PEER_HANDSHAKE is kept for duplicates
/// of the same request: the passive holepunch window (10 s) plus the 10 s
/// Node hyperdht keeps a settled handshake around (`HANDSHAKE_CLEAR_WAIT` in
/// `lib/server.js`).
const HANDSHAKE_REPLY_TTL: Duration = Duration::from_secs(20);

/// Upper bound on cached handshake replies. Anyone who knows our announced
/// public key can send distinct valid handshakes, so the cache must not grow
/// with them. Past this bound the oldest reply is evicted first: a flood can
/// then only cost a legitimate client its duplicate-dedup, never block new
/// handshakes. Legitimate traffic stays far below it (each entry lives 20 s).
const HANDSHAKE_REPLY_CACHE_CAPACITY: usize = 1024;

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
    /// Maximum total peer connections (default 64).
    pub max_peers: usize,
    /// Maximum concurrent outgoing connection attempts (default 3).
    pub max_parallel: usize,
    /// Firewall value sent in handshakes (default 0).
    pub firewall: u64,
    /// Public key of a relay node to force all server connections through.
    /// When set, server handshake replies include `relay_through` info directing
    /// clients to connect via the specified relay using the blind-relay protocol.
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
            .field("remote_public_key", &short_hex(&self.peer.remote_public_key))
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

struct ActorConfig {
    max_peers: usize,
    max_parallel: usize,
    firewall: u64,
    relay_through: Option<[u8; 32]>,
    relay_address: Option<std::net::SocketAddr>,
    local_connection: bool,
}

struct SwarmActor {
    key_pair: KeyPair,
    dht: HyperDhtHandle,
    config: ActorConfig,
    runtime_handle: Arc<RuntimeHandle>,
    local_port: u16,

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
    connect_tasks: HashMap<[u8; 32], JoinHandle<()>>,
    connect_result_tx: mpsc::UnboundedSender<ConnectAttemptResult>,
    /// Fires when a failed peer's retry backoff elapses (`lib/retry-timer.js`).
    retry_tx: mpsc::UnboundedSender<[u8; 32]>,

    /// `true` between [`SwarmHandle::suspend`] and [`SwarmHandle::resume`]:
    /// no dials, no announces, no new connections.
    suspended: bool,
    /// `true` once [`SwarmHandle::listen`] has been called. The DHT server
    /// stays registered across suspend/resume, but the announcer does not.
    listening: bool,
    /// Announces `hash(public_key)` and refreshes it, as Node's
    /// `Server.listen()` announcer does.
    announcer: Option<ServerAnnouncer>,

    conn_tx: mpsc::Sender<SwarmConnection>,

    server_registered: bool,
    relay_address: Option<Ipv4Peer>,

    active_connects: usize,
    flush_waiters: Vec<oneshot::Sender<Result<(), SwarmError>>>,
    server_failure_tx: Option<mpsc::UnboundedSender<[u8; 32]>>,
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

    // Passive-holepunch state. When the server is firewalled, each accepted
    // handshake stages an InFlightHolepunch entry instead of immediately
    // creating a UDX connection. The entry persists across PEER_HOLEPUNCH
    // rounds (preserving SecurePayload tokens + the Holepuncher's NAT
    // analysis) and is resolved into a real SwarmConnection only when the
    // firewall hook on the puncher's primary socket commits the 4-tuple.
    connects: HashMap<u64, InFlightHolepunch>,
    pending_handshakes: HashMap<[u8; 32], u64>,
    next_holepunch_id: u64,
    passive_hp_event_tx: mpsc::UnboundedSender<PassiveHolepunchEvent>,

    // Noise replies to recent PEER_HANDSHAKEs, keyed by the client's Noise
    // message. A Node client sends the same message through up to two relays
    // in parallel and keeps the first reply; every copy must get that reply.
    handshake_replies: HandshakeReplyCache,
}

/// The `hash(public_key)` announcer started by [`SwarmHandle::listen`].
struct ServerAnnouncer {
    cancel_tx: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

/// Announce `hash(public_key)`, the record peers look up to reach a listening
/// swarm. Mirrors the announcer Node's `Server.listen()` starts.
async fn announce_self(dht: &HyperDhtHandle, key_pair: &KeyPair, relays: &[Ipv4Peer]) {
    match dht.announce(hash(&key_pair.public_key), key_pair, relays).await {
        Ok(r) => tracing::debug!(closest = r.closest_nodes.len(), "server self-announce complete"),
        Err(e) => tracing::warn!(err = %e, "server self-announce failed"),
    }
}

/// Refresh the self-announcement until cancelled.
async fn run_server_announcer(
    dht: HyperDhtHandle,
    key_pair: KeyPair,
    relays: Vec<Ipv4Peer>,
    announce_now: bool,
    mut cancel_rx: oneshot::Receiver<()>,
) {
    // `listen()` has just announced; a resume has not, and must not wait a
    // full refresh interval to be discoverable again.
    if announce_now {
        announce_self(&dht, &key_pair, &relays).await;
    }
    loop {
        let jitter_ms = rand::rng().random_range(0..ANNOUNCE_REFRESH_JITTER_MS);
        let delay = ANNOUNCE_REFRESH_INTERVAL + Duration::from_millis(jitter_ms);
        tokio::select! {
            _ = tokio::time::sleep(delay) => announce_self(&dht, &key_pair, &relays).await,
            _ = &mut cancel_rx => break,
        }
    }
}

/// Stop a discovery/announcer task: give it a bounded chance to finish its
/// current announce when graceful, abort it otherwise.
async fn stop_task(task: Option<JoinHandle<()>>, graceful: bool) {
    let Some(mut task) = task else { return };
    if !graceful || tokio::time::timeout(STOP_TASK_TIMEOUT, &mut task).await.is_err() {
        task.abort();
    }
}

/// Noise replies to recent server-side PEER_HANDSHAKE requests, keyed by the
/// client's Noise message.
///
/// Node hyperdht clients send one handshake through up to two relays at once
/// (`lib/connect.js`, `Semaphore(2)`) and act on whichever reply arrives
/// first, so a server must answer every copy identically, as Node's
/// `Server._onpeerhandshake` does. Answering each copy with a fresh Noise
/// responder gives the client a reply for a session the server then replaces.
///
/// Entries are keyed by a hash of the client's Noise message and expire in
/// insertion order, so pruning is amortised O(1) per handshake. At most
/// `capacity` entries are kept; the oldest is evicted first.
struct HandshakeReplyCache {
    ttl: Duration,
    capacity: usize,
    entries: HashMap<[u8; 32], Vec<u8>>,
    order: VecDeque<(tokio::time::Instant, [u8; 32])>,
}

impl HandshakeReplyCache {
    fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// The Noise reply already sent for this client Noise message, if any.
    fn get(&mut self, client_noise: &[u8]) -> Option<Vec<u8>> {
        self.prune();
        self.entries.get(&hash(client_noise)).cloned()
    }

    /// Record the reply to a client Noise message. The first reply wins: a
    /// later insert for the same message is ignored.
    fn insert(&mut self, client_noise: &[u8], reply_noise: Vec<u8>) {
        self.prune();
        let key = hash(client_noise);
        if self.entries.contains_key(&key) || self.capacity == 0 {
            return;
        }
        while self.entries.len() >= self.capacity {
            let Some((_, oldest)) = self.order.pop_front() else { break };
            self.entries.remove(&oldest);
        }
        self.order.push_back((tokio::time::Instant::now(), key));
        self.entries.insert(key, reply_noise);
    }

    /// Drop expired entries. Also run periodically by the actor so replies do
    /// not outlive their TTL while no handshakes arrive.
    fn prune(&mut self) {
        while let Some((at, key)) = self.order.front() {
            if at.elapsed() < self.ttl {
                break;
            }
            self.entries.remove(key);
            self.order.pop_front();
        }
        if self.order.is_empty() && self.entries.capacity() > 0 {
            self.entries = HashMap::new();
            self.order = VecDeque::new();
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Drop every cached reply, releasing its storage. Used when the server
    /// is suspended: replies for pre-suspend handshakes must not be reused.
    fn clear(&mut self) {
        self.entries = HashMap::new();
        self.order = VecDeque::new();
    }
}

/// Wrap a Noise reply in the handshake envelope for the path the request took.
///
/// Per Node `lib/server.js _addHandshake`:
///   - inbound FROM_CLIENT → respond MODE_REPLY (direct reply path).
///   - inbound FROM_RELAY / FROM_SECOND_RELAY → respond MODE_FROM_SERVER
///     with peer_address pointing to the originating client (carried in
///     the inbound msg.peer_address). The dht layer will dispatch this
///     via dht.relay_with_tid back to the FE-holder, which then routes
///     a tid-preserved REPLY to the receiver.
fn encode_server_handshake_reply(
    inbound_mode: u64,
    peer_address: Option<Ipv4Peer>,
    noise_reply: Vec<u8>,
) -> Option<Vec<u8>> {
    let (mode, peer_address) = match inbound_mode {
        MODE_FROM_RELAY | MODE_FROM_SECOND_RELAY => (MODE_FROM_SERVER, peer_address),
        _ => (MODE_REPLY, None),
    };
    encode_handshake_to_bytes(&HandshakeMessage {
        mode,
        noise: noise_reply,
        peer_address,
        relay_address: None,
    })
    .ok()
}

/// State carried between the initial server handshake and the moment the
/// passive Holepuncher's primary socket sees its first probe. Owned
/// directly by `SwarmActor` (single-threaded mutation, no `Arc<Mutex>`).
struct InFlightHolepunch {
    remote_pk: [u8; 32],
    /// Persists across rounds so `token()` derivation is stable per Node
    /// `lib/holepuncher.js`.
    payload: SecurePayload,
    /// `None` once `punch()` has been spawned (the task takes ownership).
    /// Round handling between spawn and punch-land only updates state that
    /// can be reconstructed from the incoming round.
    puncher: Option<Holepuncher>,
    /// Listening-mode UDX stream whose `set_firewall_hook` will commit the
    /// 4-tuple when the first probe lands.
    udx_stream: UdxStream,
    /// Clone of the puncher's primary `UdxSocket`. Held independently so
    /// the live UDP socket survives even after `puncher` is moved into a
    /// spawned `punch()` task, and so we have something to hand to
    /// `PeerConnection::new` when finalizing.
    udx_socket: UdxSocket,
    /// Kept verbatim from the original handshake; consumed by `SecretStream::from_session`
    /// when the punch lands.
    noise_result: NoiseWrapResult,
    /// Highest round number we have accepted so far. Used purely to detect
    /// reordered PEER_HOLEPUNCH duplicates; replies always echo
    /// `remote_hp.round` to stay in lockstep with the client loop.
    round: u64,
    /// 10s deadline. Cancelled when the firewall hook fires or when a new
    /// handshake from the same remote_pk preempts this entry.
    abort_task: Option<JoinHandle<()>>,
    /// Pre-computed addresses advertised in PEER_HOLEPUNCH reply
    /// `addresses`. MUST point at OUR puncher socket, not echo back the
    /// initiator's reflexive address (Phase 3 MVP: loopback only).
    local_punch_addrs: Vec<Ipv4Peer>,
}

/// Internal actor-loop events fired by the passive-holepunch path.
/// Decoupled from `SwarmCommand` because the firewall-hook closure must be
/// `FnOnce + Send + 'static` and cannot await the public command channel.
enum PassiveHolepunchEvent {
    /// Firewall hook fired — the puncher's primary socket has bound a
    /// remote 4-tuple at `addr`. Time to finalize the SecretStream.
    Punched { id: u64, addr: SocketAddr },
    /// 10s deadline elapsed without the hook firing.
    Abort { id: u64 },
}

struct ConnectAttemptResult {
    public_key: [u8; 32],
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

    let (dht_join, dht, server_rx) = hyperdht::spawn(&runtime, config.dht).await?;
    dht.bootstrapped().await?;

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
    let (passive_hp_event_tx, passive_hp_event_rx) = mpsc::unbounded_channel();
    let (connect_result_tx, connect_result_rx) = mpsc::unbounded_channel::<ConnectAttemptResult>();
    let (retry_tx, retry_rx) = mpsc::unbounded_channel::<[u8; 32]>();

    let handle_dht = dht.clone();
    let handle_key_pair = key_pair.clone();

    let actor = SwarmActor {
        key_pair,
        dht,
        config: ActorConfig {
            max_peers: config.max_peers,
            max_parallel: config.max_parallel,
            firewall: config.firewall,
            relay_through: config.relay_through,
            relay_address: config.relay_address,
            local_connection: config.local_connection,
        },
        runtime_handle: runtime.handle(),
        local_port: primary_socket_port,
        topics: HashMap::new(),
        discovery_event_tx,
        peers: HashMap::new(),
        connections: ConnectionSet::new(),
        aborts: Arc::new(Mutex::new(Vec::new())),
        queue: Vec::new(),
        connect_tasks: HashMap::new(),
        connect_result_tx,
        retry_tx,
        suspended: false,
        listening: false,
        announcer: None,
        conn_tx,
        server_registered: false,
        relay_address: config.relay_address.map(|addr| Ipv4Peer {
            host: addr.ip().to_string(),
            port: addr.port(),
        }),
        active_connects: 0,
        flush_waiters: Vec::new(),
        server_failure_tx: None,
        closed_tx: None,
        generations: HashMap::new(),
        conn_aborts: Arc::new(Mutex::new(HashMap::new())),
        next_generation: 0,
        connects: HashMap::new(),
        pending_handshakes: HashMap::new(),
        next_holepunch_id: 0,
        passive_hp_event_tx,
        handshake_replies: HandshakeReplyCache::new(
            HANDSHAKE_REPLY_TTL,
            HANDSHAKE_REPLY_CACHE_CAPACITY,
        ),
    };

    // Keep the DHT runtime alive for the swarm's lifetime.
    // We must await dht_join AFTER actor.run() (which calls dht.destroy()),
    // so the DhtNode finishes closing its IO sockets before we drop the runtime.
    let join = tokio::spawn(async move {
        actor
            .run(
                cmd_rx,
                discovery_event_rx,
                server_rx,
                passive_hp_event_rx,
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
        mut server_rx: mpsc::UnboundedReceiver<ServerEvent>,
        mut passive_hp_event_rx: mpsc::UnboundedReceiver<PassiveHolepunchEvent>,
        mut connect_result_rx: mpsc::UnboundedReceiver<ConnectAttemptResult>,
        mut retry_rx: mpsc::UnboundedReceiver<[u8; 32]>,
    ) {
        // Reverse channel: spawned create_server_connection tasks signal back
        // on failure so the actor can release the pre-emptively reserved
        // `connections` slot. Without this, a single failed handshake stream
        // would lock that peer's slot forever, blocking any retry from a
        // different relay path.
        let (server_failure_tx, mut server_failure_rx) =
            mpsc::unbounded_channel::<[u8; 32]>();
        self.server_failure_tx = Some(server_failure_tx);
        let (closed_tx, mut closed_rx) = mpsc::unbounded_channel();
        self.closed_tx = Some(closed_tx);

        let mut reply_sweep = tokio::time::interval(HANDSHAKE_REPLY_TTL);
        reply_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    if self.handle_command(cmd).await {
                        break;
                    }
                }
                event = discovery_rx.recv() => {
                    if let Some(event) = event {
                        self.handle_discovery_event(event);
                    }
                }
                event = server_rx.recv() => {
                    if let Some(event) = event {
                        self.handle_server_event(event).await;
                    }
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
                        // A stale generation belongs to a connection we have
                        // already replaced; only the current one is retired.
                        if self.generations.get(&pk) == Some(&generation) {
                            self.generations.remove(&pk);
                            if let Ok(mut abort) = self.conn_aborts.lock() {
                                abort.remove(&pk);
                            }
                            let was_initiator = self
                                .connections
                                .get(&pk)
                                .is_some_and(|info| info.is_initiator);
                            if self.connections.remove(&pk) {
                                if let Some(info) = self.peers.get_mut(&pk) {
                                    info.disconnected();
                                }
                                if was_initiator {
                                    self.schedule_retry(pk);
                                }
                            }
                        }
                    }
                }
                pk = server_failure_rx.recv() => {
                    if let Some(pk) = pk {
                        if self.connections.remove(&pk) {
                            tracing::debug!(pk = %short_hex(&pk), "server: stream failed, released connection slot");
                        }
                    }
                }
                event = passive_hp_event_rx.recv() => {
                    if let Some(event) = event {
                        self.handle_passive_holepunch_event(event).await;
                    }
                }
                _ = reply_sweep.tick() => {
                    self.handshake_replies.prune();
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
        if let Some(announcer) = self.announcer.take() {
            let _ = announcer.cancel_tx.send(());
            announcer.task.abort();
        }

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
                let result = self.do_join(topic, server, client);
                let _ = reply_tx.send(result);
                false
            }
            SwarmCommand::Leave { topic, reply_tx } => {
                let result = self.do_leave(topic);
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

    fn do_join(&mut self, topic: [u8; 32], server: bool, client: bool) -> Result<(), SwarmError> {
        if self.topics.contains_key(&topic) {
            return Ok(());
        }

        if server && !self.server_registered {
            self.dht.register_server(&self.key_pair.public_key);
            self.server_registered = true;
            tracing::debug!(pk = %short_hex(&self.key_pair.public_key), "server registered");
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
        let task = tokio::spawn(run_discovery(
            PeerDiscoveryConfig {
                topic,
                is_server: server,
                is_client: client,
            },
            self.dht.clone(),
            self.key_pair.clone(),
            self.relay_addresses(),
            self.discovery_event_tx.clone(),
            cancel_rx,
        ));

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

    /// Node `swarm.listen()`: register the server for `hash(public_key)` and
    /// announce that key, so peers that know only the key can find us.
    async fn do_listen(&mut self) -> Result<(), SwarmError> {
        if !self.server_registered {
            self.dht.register_server(&self.key_pair.public_key);
            self.server_registered = true;
            tracing::debug!(
                pk = %short_hex(&self.key_pair.public_key),
                "server registered (listen)"
            );
        }
        if !self.listening {
            let target = hash(&self.key_pair.public_key);
            self.dht
                .announce(target, &self.key_pair, &self.relay_addresses())
                .await?;
            self.listening = true;
        }
        if self.suspended {
            return Ok(());
        }
        self.start_announcer(false);
        Ok(())
    }

    fn start_announcer(&mut self, announce_now: bool) {
        if self.announcer.is_some() {
            return;
        }
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let task = tokio::spawn(run_server_announcer(
            self.dht.clone(),
            self.key_pair.clone(),
            self.relay_addresses(),
            announce_now,
            cancel_rx,
        ));
        self.announcer = Some(ServerAnnouncer { cancel_tx, task });
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

        if let Some(announcer) = self.announcer.take() {
            let _ = announcer.cancel_tx.send(());
            announcer.task.abort();
        }

        for (_, task) in self.connect_tasks.drain() {
            task.abort();
        }
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

        for (_, mut entry) in self.connects.drain() {
            if let Some(task) = entry.abort_task.take() {
                task.abort();
            }
            if let Some(mut puncher) = entry.puncher.take() {
                puncher.destroy();
            }
        }
        self.pending_handshakes.clear();
        self.handshake_replies.clear();

        for waiter in self.flush_waiters.drain(..) {
            let _ = waiter.send(Ok(()));
        }

        // Node suspends the DHT last, after the server and discovery.
        self.dht.suspend().await?;
        Ok(())
    }

    /// Node `swarm.resume()`: resume the DHT, then restart discovery, the
    /// announcer and the queued connection attempts.
    async fn do_resume(&mut self) -> Result<(), SwarmError> {
        if !self.suspended {
            return Ok(());
        }
        self.suspended = false;
        self.dht.resume().await?;

        let topics: Vec<([u8; 32], bool, bool)> = self
            .topics
            .iter()
            .map(|(topic, state)| (*topic, state.is_server, state.is_client))
            .collect();
        for (topic, server, client) in topics {
            self.spawn_discovery(topic, server, client);
        }

        if self.listening {
            self.start_announcer(true);
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
        let graceful = !force;
        for (_, mut state) in self.topics.drain() {
            if let Some(cancel) = state.cancel_tx.take() {
                let _ = cancel.send(());
            }
            stop_task(state.task.take(), graceful).await;
        }
        if let Some(announcer) = self.announcer.take() {
            let _ = announcer.cancel_tx.send(());
            stop_task(Some(announcer.task), graceful).await;
        }

        for (_, task) in self.connect_tasks.drain() {
            task.abort();
        }
        self.active_connects = 0;
        self.queue.clear();

        for (_, mut entry) in self.connects.drain() {
            if let Some(task) = entry.abort_task.take() {
                task.abort();
            }
            if let Some(mut puncher) = entry.puncher.take() {
                puncher.destroy();
            }
        }
        self.pending_handshakes.clear();
        self.handshake_replies.clear();

        // Node closes the swarm's server and every connection on destroy.
        if let Ok(mut aborts) = self.aborts.lock() {
            for handle in std::mem::take(&mut *aborts) {
                handle.abort();
            }
        }

        for waiter in self.flush_waiters.drain(..) {
            let _ = waiter.send(Err(SwarmError::Destroyed));
        }
    }

    fn do_leave(&mut self, topic: [u8; 32]) -> Result<(), SwarmError> {
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
                let has_remaining_server_topics =
                    self.topics.values().any(|t| t.is_server);
                if !has_remaining_server_topics {
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

    fn attempt_connections(&mut self) {
        if self.suspended {
            return;
        }
        while self.active_connects < self.config.max_parallel && !self.queue.is_empty() {
            // Sort by priority descending
            self.queue.sort_by(|a, b| {
                let pa = self
                    .peers
                    .get(a)
                    .map_or(Priority::VeryLow, |i| i.priority);
                let pb = self
                    .peers
                    .get(b)
                    .map_or(Priority::VeryLow, |i| i.priority);
                pb.cmp(&pa)
            });

            let pk = self.queue.remove(0);
            let relay_addrs = if let Some(info) = self.peers.get_mut(&pk) {
                info.queued = false;
                info.connecting = true;
                info.attempts += 1;
                info.relay_addresses.clone()
            } else {
                vec![]
            };

            self.active_connects += 1;
            let dht = self.dht.clone();
            let key_pair = self.key_pair.clone();
            let result_tx = self.connect_result_tx.clone();
            let rh = self.runtime_handle.clone();
            let mut connect_opts = peeroxide_dht::hyperdht::ConnectOpts::default();
            connect_opts.local_connection = self.config.local_connection;

            let task = tokio::spawn(async move {
                let conn_runtime = UdxRuntime::shared(rh);
                tracing::debug!(pk = %short_hex(&pk), "connecting to peer");
                match dht
                    .connect_with_options(&key_pair, pk, &relay_addrs, &conn_runtime, connect_opts)
                    .await
                {
                    Ok(conn) => {
                        tracing::info!(
                            target: "peeroxide::_events::peer::connected",
                            pk = %short_hex(&pk),
                            "peer connected"
                        );
                        let _ = result_tx.send(ConnectAttemptResult {
                            public_key: pk,
                            result: Ok((conn, conn_runtime)),
                        });
                    }
                    Err(e) => {
                        tracing::info!(
                            target: "peeroxide::_events::peer::connect_failed",
                            pk = %short_hex(&pk),
                            err = %e,
                            "peer connect failed"
                        );
                        let _ = result_tx.send(ConnectAttemptResult {
                            public_key: pk,
                            result: Err(SwarmError::Dht(e)),
                        });
                    }
                }
            });
            self.connect_tasks.insert(pk, task);
        }
    }

    fn handle_connect_result(&mut self, result: ConnectAttemptResult) {
        self.active_connects = self.active_connects.saturating_sub(1);
        self.connect_tasks.remove(&result.public_key);

        if let Some(info) = self.peers.get_mut(&result.public_key) {
            info.connecting = false;
        }

        if self.suspended {
            // Node destroys a connection that lands after suspend.
            if result.result.is_ok() {
                tracing::debug!(
                    pk = %short_hex(&result.public_key),
                    "swarm suspended: dropping a connection that landed during suspend"
                );
            }
            return;
        }

        match result.result {
            Ok((conn, runtime)) => {
                let pk = result.public_key;

                // Dedup: compare public keys to decide tie-break
                if self.connections.has(&pk) {
                    let we_are_dominant = self.key_pair.public_key > pk;
                    if let Some(existing) = self.connections.get(&pk) {
                        if existing.is_initiator == we_are_dominant {
                            tracing::debug!(pk = %short_hex(&pk), "dedup: keeping existing");
                            return;
                        }
                    }
                    self.abort_connection(&pk);
                    self.connections.remove(&pk);
                }

                self.connections
                    .add(pk, ConnectionInfo { is_initiator: true });
                self.next_generation = self.next_generation.wrapping_add(1);
                let generation = self.next_generation;
                self.generations.insert(pk, generation);
                let conn = self.connection_watch().watch(conn, pk, generation);

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
                tracing::debug!(pk = %short_hex(&result.public_key), err = %e, "connect failed");
                self.schedule_retry(result.public_key);
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

    async fn handle_server_event(&mut self, event: ServerEvent) {
        // Node `_handleServerConnection` destroys a connection that arrives
        // while suspended; with no reply the DHT layer drops it.
        match event {
            ServerEvent::PeerHandshake {
                msg,
                from,
                peer_address,
                target: _,
                reply_tx,
            } => {
                if self.suspended {
                    let _ = reply_tx.send(None);
                    return;
                }
                self.handle_server_handshake(msg, from, peer_address, reply_tx).await;
            }
            ServerEvent::PeerHolepunch {
                msg,
                from: _,
                peer_address,
                target: _,
                reply_tx,
            } => {
                if self.suspended {
                    let _ = reply_tx.send(None);
                    return;
                }
                self.handle_peer_holepunch(msg, peer_address, reply_tx).await;
            }
            _ => {}
        }
    }

    async fn handle_server_handshake(
        &mut self,
        msg: HandshakeMessage,
        from: Ipv4Peer,
        peer_address: Option<Ipv4Peer>,
        reply_tx: oneshot::Sender<Option<ServerReply>>,
    ) {
        let initial_client_address = peer_address.clone().unwrap_or_else(|| from.clone());
        let is_forwarded = peer_address.is_some();

        if is_forwarded {
            tracing::debug!(
                relay = %format!("{}:{}", from.host, from.port),
                peer = %format!("{}:{}", initial_client_address.host, initial_client_address.port),
                "server handshake: forwarded — dialing peer_address"
            );
        }

        // The same request relayed by another node: answer with the same reply.
        if let Some(noise_reply) = self.handshake_replies.get(&msg.noise) {
            tracing::debug!(
                relay = %format!("{}:{}", from.host, from.port),
                "server handshake: duplicate of an answered handshake, resending its reply"
            );
            let reply = encode_server_handshake_reply(msg.mode, peer_address, noise_reply);
            let _ = reply_tx.send(reply.map(Into::into));
            return;
        }

        let noise_kp = NoiseKeypair {
            public_key: self.key_pair.public_key,
            secret_key: self.key_pair.secret_key,
        };

        let mut nw = NoiseWrap::new_responder(noise_kp);

        let remote_payload = match nw.recv(&msg.noise) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(err = %e, "server handshake: noise recv failed");
                let _ = reply_tx.send(None);
                return;
            }
        };

        if remote_payload.error != 0 {
            let _ = reply_tx.send(None);
            return;
        }

        let client_address = initial_client_address;

        let local_stream_id = hyperdht::alloc_stream_id();

        let (relay_token, relay_through_info) = if let Some(relay_pk) = self.config.relay_through {
            let token: [u8; 32] = rand::random();
            let info = RelayThroughInfo {
                version: 1,
                public_key: relay_pk,
                token,
            };
            (Some(token), Some(info))
        } else {
            (None, None)
        };

        // Decide how this handshake will connect (see `select_server_path`).
        let firewall_state = self.dht.firewalled().await.unwrap_or(FIREWALL_UNKNOWN);
        let path = select_server_path(
            relay_through_info.is_some(),
            firewall_state,
            remote_payload.firewall,
            is_forwarded,
        );
        tracing::debug!(
            ?path,
            server_firewall = firewall_state,
            client_firewall = remote_payload.firewall,
            forwarded = is_forwarded,
            "server handshake: path selected"
        );

        // Try to stage the passive Holepuncher up front so the reply we
        // send in this handshake can advertise the puncher's bound port
        // and the holepunch session id. If staging fails, fall back to a
        // reply with `holepunch: None` (the existing direct path); a
        // genuinely firewalled receiver will then time out and retry via
        // discovery rather than getting stuck on a broken half-state.
        // A handshake we will reject anyway (no free slot, no UDX info) is
        // not worth a puncher socket; the already-connected check needs the
        // client's key, which Noise only yields after the reply is sent.
        let can_accept = self.connections.len() < self.config.max_peers
            && remote_payload.udx.is_some();
        let holepunch_setup = if path == ServerPath::Holepunch && can_accept {
            match self
                .try_setup_passive_holepunch(
                    remote_payload.firewall,
                    local_stream_id,
                    remote_payload.udx.as_ref(),
                )
                .await
            {
                Ok(setup) => Some(setup),
                Err(e) => {
                    tracing::debug!(err = %e, "passive holepunch setup failed; sending direct-path reply");
                    None
                }
            }
        } else {
            None
        };

        // addresses4 advertised in our noise reply: real LAN interfaces
        // (Node parity, `hyperdht/lib/server.js:277-284`). The port we
        // pair with each address is the puncher socket's bound port when
        // a passive holepunch is staged — that's where the firewall hook
        // is registered, so same-host receivers dialling it land on a
        // real punch. Otherwise advertise the DHT primary socket port.
        let advertise_port = holepunch_setup
            .as_ref()
            .map_or(self.local_port, |s| s.puncher_port);
        let addresses4 = self.dht.noise_addresses4(advertise_port).await;

        // A client sends its PEER_HOLEPUNCH to `relay_address`, and the relay
        // forwards it to `peer_address`: that must be our own address as the
        // relay saw it (Node `Announcer.relays`), not the client's.
        let holepunch_info = match (&holepunch_setup, path) {
            (Some(setup), _) => Some(HolepunchInfo {
                id: setup.id,
                relays: self.dht.current_relays(),
            }),
            // No staged puncher behind this id: a PEER_HOLEPUNCH for it gets
            // no reply, as Node's `_onpeerholepunch` aborts one without a
            // puncher.
            (None, ServerPath::Dial { advertise_holepunch: true }) => {
                let id = self.next_holepunch_id;
                self.next_holepunch_id = self.next_holepunch_id.wrapping_add(1);
                Some(HolepunchInfo {
                    id,
                    relays: self.dht.current_relays(),
                })
            }
            _ => None,
        };

        let reply_payload = NoisePayload {
            version: 1,
            error: 0,
            firewall: self.config.firewall,
            holepunch: holepunch_info,
            addresses4,
            addresses6: vec![],
            udx: Some(UdxInfo {
                version: 1,
                reusable_socket: true,
                id: u64::from(local_stream_id),
                seq: 0,
            }),
            secret_stream: Some(SecretStreamInfo { version: 1 }),
            relay_through: relay_through_info,
            relay_addresses: self.config.relay_address.map(|addr| {
                vec![Ipv4Peer {
                    host: addr.ip().to_string(),
                    port: addr.port(),
                }]
            }),
        };

        let noise_reply = match nw.send(&reply_payload) {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(err = %e, "server handshake: noise send failed");
                if let Some(setup) = holepunch_setup {
                    setup.release();
                }
                let _ = reply_tx.send(None);
                return;
            }
        };

        let nw_result = match nw.finalize() {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(err = %e, "server handshake: noise finalize failed");
                if let Some(setup) = holepunch_setup {
                    setup.release();
                }
                let _ = reply_tx.send(None);
                return;
            }
        };

        let remote_pk = nw_result.remote_public_key;

        // A handshake we would reject (already connected, at max_peers, no
        // UDX info) neither takes up cache space nor keeps a staged
        // holepunch: that session would only be dropped when its punch landed.
        // Only the already-connected check can still release one here.
        let eligible = can_accept && !self.connections.has(&remote_pk);
        let holepunch_setup = match holepunch_setup {
            Some(setup) if !eligible => {
                tracing::debug!(pk = %short_hex(&remote_pk), "server: rejecting handshake, releasing staged holepunch");
                setup.release();
                None
            }
            setup => setup,
        };
        if eligible {
            self.handshake_replies.insert(&msg.noise, noise_reply.clone());
        }
        let _ = reply_tx.send(
            encode_server_handshake_reply(msg.mode, peer_address.clone(), noise_reply).map(Into::into),
        );

        // If we staged a passive holepunch above, hand ownership of the
        // staged state into the actor's `connects` map and return. Slot
        // accounting (self.connections.add) is deferred until the firewall
        // hook fires — see `PassiveHolepunchEvent::Punched` handling.
        if let Some(setup) = holepunch_setup {
            self.commit_passive_holepunch(setup, remote_pk, nw_result);
            return;
        }

        // Node `_handleServerConnection`: a handshake from a peer we are still
        // connected to replaces that connection when the tie-break picks the
        // new one; otherwise the new one is refused and the client retries.
        // Node also keeps the new connection when the existing one has already
        // carried traffic in both directions; `SecretStream` keeps no byte
        // counters, so the tie-break decides alone.
        if self.connections.has(&remote_pk) {
            let expected_initiator = self.key_pair.public_key > remote_pk;
            if expected_initiator {
                tracing::debug!(pk = %short_hex(&remote_pk), "server: keeping the existing connection");
                return;
            }
            tracing::debug!(
                pk = %short_hex(&remote_pk),
                "server: duplicate handshake replaces the existing connection"
            );
            self.abort_connection(&remote_pk);
            self.connections.remove(&remote_pk);
            self.generations.remove(&remote_pk);
        }
        if self.connections.len() >= self.config.max_peers {
            tracing::debug!("server: at max connections");
            return;
        }

        let remote_udx = match remote_payload.udx {
            Some(u) => u,
            None => {
                tracing::debug!("server: no UDX info in handshake");
                return;
            }
        };

        self.connections
            .add(remote_pk, ConnectionInfo { is_initiator: false });
        self.next_generation = self.next_generation.wrapping_add(1);
        let generation = self.next_generation;
        self.generations.insert(remote_pk, generation);
        let watch = self.connection_watch();

        let conn_tx = self.conn_tx.clone();

        if let (Some(relay_pk), Some(token)) = (self.config.relay_through, relay_token) {
            let dht = self.dht.clone();
            let key_pair = self.key_pair.clone();
            let relay_addr = self.config.relay_address;
            let rh = self.runtime_handle.clone();
            let failure_tx = self.server_failure_tx.clone();
            tokio::spawn(async move {
                match create_server_relay_connection(
                    rh,
                    dht,
                    key_pair,
                    relay_pk,
                    relay_addr,
                    token,
                    nw_result,
                )
                .await
                {
                    Ok((conn, runtime)) => {
                        let conn = watch.watch(conn, remote_pk, generation);
                        let swarm_conn = SwarmConnection {
                            peer: conn,
                            is_initiator: false,
                            topics: vec![],
                            _runtime: runtime,
                        };
                        if conn_tx.send(swarm_conn).await.is_err() {
                            tracing::warn!("connection channel closed");
                        }
                    }
                    Err(e) => {
                        tracing::debug!(err = %e, "server: relay connection failed");
                        if let Some(tx) = failure_tx {
                            let _ = tx.send(remote_pk);
                        }
                    }
                }
            });
        } else {
            let rh = self.runtime_handle.clone();
            let dht = self.dht.clone();
            let client_addr_for_task = client_address.clone();
            let failure_tx = self.server_failure_tx.clone();
            tokio::spawn(async move {
                match create_server_connection(
                    rh,
                    dht,
                    local_stream_id,
                    &remote_udx,
                    &client_addr_for_task,
                    matches!(path, ServerPath::Dial { .. }),
                    &nw_result,
                )
                .await
                {
                    Ok((conn, runtime)) => {
                        let conn = watch.watch(conn, remote_pk, generation);
                        let swarm_conn = SwarmConnection {
                            peer: conn,
                            is_initiator: false,
                            topics: vec![],
                            _runtime: runtime,
                        };
                        if conn_tx.send(swarm_conn).await.is_err() {
                            tracing::warn!("connection channel closed");
                        }
                    }
                    Err(e) => {
                        tracing::debug!(err = %e, "server: stream establishment failed");
                        if let Some(tx) = failure_tx {
                            let _ = tx.send(remote_pk);
                        }
                    }
                }
            });
        }
    }

    fn all_topics_refreshed(&self) -> bool {
        !self.topics.is_empty() && self.topics.values().all(|t| t.refreshed)
    }

    fn check_flush_waiters(&mut self) {
        if self.all_topics_refreshed() {
            for waiter in self.flush_waiters.drain(..) {
                let _ = waiter.send(Ok(()));
            }
        }
    }

    /// Stage a passive Holepuncher, create its listening UdxStream, wire
    /// the firewall hook, and arm the 10s abort timer — all the work that
    /// must happen *before* the handshake reply goes out (the reply has
    /// to advertise the puncher's bound port and the session id).
    async fn try_setup_passive_holepunch(
        &mut self,
        remote_firewall: u64,
        local_stream_id: u32,
        remote_udx: Option<&UdxInfo>,
    ) -> Result<HolepunchSetup, SwarmError> {
        use peeroxide_dht::hyperdht::HyperDhtError;

        let remote_udx = remote_udx.ok_or_else(|| {
            SwarmError::Dht(HyperDhtError::HandshakeFailed(
                "passive holepunch: client did not advertise UDX info".into(),
            ))
        })?;

        let remote_id = u32::try_from(remote_udx.id).map_err(|_| {
            SwarmError::Dht(HyperDhtError::StreamEstablishment(
                "remote UDX id out of u32 range".into(),
            ))
        })?;

        let pool = SocketPool::new("0.0.0.0".into());
        let runtime = UdxRuntime::shared(self.runtime_handle.clone());

        // Per the Holepuncher contract this is_initiator=false, firewalled=true
        // construction is the passive side of the punch. The HolepunchEvent
        // channel is intentionally discarded (`_event_rx` is dropped): the
        // passive puncher never emits `Connected` itself — the libudx
        // firewall hook on its primary socket is the authoritative
        // punch-landed signal for the server side.
        let (event_tx, _event_rx) = mpsc::unbounded_channel::<HolepunchEvent>();
        let mut puncher = Holepuncher::new(&pool, &runtime, true, false, remote_firewall, event_tx)
            .await
            .map_err(|e| {
                SwarmError::Dht(HyperDhtError::HandshakeFailed(format!(
                    "passive holepunch: socket pool acquire failed: {e}"
                )))
            })?;

        // Seed the passive puncher's NAT BEFORE punch() can run. auto_sample
        // takes ownership of the puncher socket's dht_reply_rx and must be
        // the only consumer — running it first guarantees that. Without this
        // the passive NAT stays UNKNOWN and the coerce_firewall revert
        // (removing UNKNOWN→CONSISTENT) would break the passive punch path.
        // Mirrors Node lib/holepuncher.js:13-20.
        let _added = puncher.auto_sample(self.dht.dht()).await;

        let socket_ref = puncher.primary_socket().ok_or_else(|| {
            SwarmError::Dht(HyperDhtError::StreamEstablishment(
                "puncher returned no primary socket".into(),
            ))
        })?;
        let socket = socket_ref.socket.clone();
        let socket_addr = socket.local_addr().await.map_err(|e| {
            SwarmError::Dht(HyperDhtError::StreamEstablishment(format!(
                "puncher socket local_addr failed: {e}"
            )))
        })?;
        let puncher_port = socket_addr.port();

        let udx_stream = runtime.create_stream(local_stream_id).await?;

        let holepunch_id = self.next_holepunch_id;
        self.next_holepunch_id = self.next_holepunch_id.wrapping_add(1);

        // The first accepted packet commits the remote address and notifies the actor.
        let event_tx = self.passive_hp_event_tx.clone();
        udx_stream.set_firewall_hook(&socket, remote_id, move |_sock, port, ip| {
            let addr = SocketAddr::new(ip, port);
            let _ = event_tx.send(PassiveHolepunchEvent::Punched {
                id: holepunch_id,
                addr,
            });
            true
        })?;

        let abort_tx = self.passive_hp_event_tx.clone();
        let abort_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let _ = abort_tx.send(PassiveHolepunchEvent::Abort { id: holepunch_id });
        });

        Ok(HolepunchSetup {
            id: holepunch_id,
            puncher_port,
            puncher,
            udx_stream,
            udx_socket: socket,
            abort_task,
        })
    }

    /// Move a successfully-staged setup into the `connects` map. Performs
    /// remote_pk dedup: if a previous handshake from this same peer is
    /// still in-flight, its puncher/stream/timer are dropped here so the
    /// new entry replaces them cleanly.
    fn commit_passive_holepunch(
        &mut self,
        setup: HolepunchSetup,
        remote_pk: [u8; 32],
        noise_result: NoiseWrapResult,
    ) {
        if let Some(old_id) = self.pending_handshakes.insert(remote_pk, setup.id) {
            if let Some(old_entry) = self.connects.remove(&old_id) {
                if let Some(task) = old_entry.abort_task {
                    task.abort();
                }
                tracing::debug!(
                    pk = %short_hex(&remote_pk),
                    old_id,
                    new_id = setup.id,
                    "passive holepunch: replacing stale in-flight entry"
                );
            }
        }

        let payload = SecurePayload::new(noise_result.holepunch_secret);

        // Holepunch payload `addresses` list (Algorithm B): prefer
        // autoSample-derived reflexive samples on the puncher; fall
        // back to local LAN interfaces when autoSample produced none.
        // Mirrors Node `hyperdht/lib/holepuncher.js:221-227`.
        let local_punch_addrs = setup.puncher.punch_addresses(setup.puncher_port);

        self.connects.insert(
            setup.id,
            InFlightHolepunch {
                remote_pk,
                payload,
                puncher: Some(setup.puncher),
                udx_stream: setup.udx_stream,
                udx_socket: setup.udx_socket,
                noise_result,
                round: 0,
                abort_task: Some(setup.abort_task),
                local_punch_addrs,
            },
        );
    }

    async fn handle_peer_holepunch(
        &mut self,
        msg: HolepunchMessage,
        peer_address: Ipv4Peer,
        reply_tx: oneshot::Sender<Option<ServerReply>>,
    ) {
        let Some(entry) = self.connects.get_mut(&msg.id) else {
            tracing::debug!(id = msg.id, "peer holepunch: unknown id");
            let _ = reply_tx.send(None);
            return;
        };

        let remote_hp = match entry.payload.decrypt(&msg.payload) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(id = msg.id, err = %e, "peer holepunch: decrypt failed");
                let _ = reply_tx.send(None);
                return;
            }
        };

        // Update the puncher's view of the remote side. Once `punch()` has
        // been moved into its spawned task, the puncher slot is `None` and
        // further updates are no-ops — by that point the probe loop is
        // already running with the verified address it captured.
        if let Some(puncher) = entry.puncher.as_mut() {
            if let Some(addrs) = &remote_hp.addresses {
                puncher.update_remote(
                    remote_hp.punching,
                    remote_hp.firewall,
                    addrs,
                    Some(peer_address.host.as_str()),
                );
            } else {
                puncher.update_remote(
                    remote_hp.punching,
                    remote_hp.firewall,
                    &[],
                    Some(peer_address.host.as_str()),
                );
            }
            // The passive puncher's NAT sampler is never fed (only the
            // active/initiator side's `run_holepunch_rounds` calls
            // `puncher.nat.add(...)` from PEER_HOLEPUNCH replies), so
            // `puncher.analyze(false).await` would deadlock forever
            // here, blocking the entire SwarmActor event loop. The
            // passive side's success signal is the firewall hook on
            // the puncher's primary UDX stream firing when the punch
            // probe lands — not a NAT classification gate.
        }

        if remote_hp.round > entry.round {
            entry.round = remote_hp.round;
        }

        // Spawn the active probe task only on the first round where the
        // initiator asks us to punch. `puncher.punch()` takes &mut self and
        // runs a long-lived probe loop, so the puncher is moved out and
        // owned by the task — subsequent rounds just keep building replies.
        if remote_hp.punching && entry.puncher.is_some() {
            if let Some(mut puncher) = entry.puncher.take() {
                tokio::spawn(async move {
                    let pool = SocketPool::new("0.0.0.0".into());
                    if let Ok(rt) = UdxRuntime::new() {
                        puncher.punch(&pool, &rt).await;
                    }
                });
            }
        }

        let server_firewall = self.dht.firewalled().await.unwrap_or(FIREWALL_UNKNOWN);
        let reply_hp = HolepunchPayload {
            error: ERROR_NONE,
            firewall: server_firewall,
            round: remote_hp.round,
            connected: false,
            punching: remote_hp.punching,
            addresses: Some(entry.local_punch_addrs.clone()),
            remote_address: Some(peer_address.clone()),
            token: Some(entry.payload.token(&peer_address.host)),
            remote_token: remote_hp.token,
        };

        let encrypted = match entry.payload.encrypt(&reply_hp) {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(id = msg.id, err = %e, "peer holepunch: encrypt failed");
                let _ = reply_tx.send(None);
                return;
            }
        };

        // Mirror item-8 handshake reply-mode selection: relayed inbound
        // (FROM_RELAY / FROM_SECOND_RELAY) MUST be answered with mode
        // FROM_SERVER so the FE-holder's router dispatches a tid-preserved
        // ReplyTo back to the original client. A direct FROM_CLIENT inbound
        // (currently unused for holepunch, but kept for symmetry) is
        // answered with MODE_REPLY.
        let reply_mode = match msg.mode {
            MODE_FROM_RELAY | MODE_FROM_SECOND_RELAY => MODE_FROM_SERVER,
            _ => MODE_REPLY,
        };

        let reply_msg = HolepunchMessage {
            mode: reply_mode,
            id: msg.id,
            payload: encrypted,
            peer_address: Some(peer_address),
        };

        let _ = reply_tx.send(encode_holepunch_msg_to_bytes(&reply_msg).ok().map(Into::into));
    }

    async fn handle_passive_holepunch_event(&mut self, event: PassiveHolepunchEvent) {
        match event {
            PassiveHolepunchEvent::Punched { id, addr } => {
                let Some(mut entry) = self.connects.remove(&id) else {
                    return;
                };
                if let Some(task) = entry.abort_task.take() {
                    task.abort();
                }
                self.pending_handshakes.remove(&entry.remote_pk);

                if self.connections.has(&entry.remote_pk) {
                    tracing::debug!(
                        pk = %short_hex(&entry.remote_pk),
                        "passive holepunch landed but already connected; dropping"
                    );
                    return;
                }
                if self.connections.len() >= self.config.max_peers {
                    tracing::debug!("passive holepunch landed but at max connections");
                    return;
                }

                tracing::debug!(
                    id,
                    pk = %short_hex(&entry.remote_pk),
                    ?addr,
                    "passive holepunch landed; finalizing SecretStream"
                );

                self.connections
                    .add(entry.remote_pk, ConnectionInfo { is_initiator: false });
                self.next_generation = self.next_generation.wrapping_add(1);
                let generation = self.next_generation;
                self.generations.insert(entry.remote_pk, generation);

                let runtime = UdxRuntime::shared(self.runtime_handle.clone());
                let conn_tx = self.conn_tx.clone();
                let failure_tx = self.server_failure_tx.clone();
                let watch = self.connection_watch();
                let remote_pk = entry.remote_pk;

                tokio::spawn(async move {
                    let async_stream = entry.udx_stream.into_async_stream();
                    let ss = match SecretStream::from_session(
                        false,
                        async_stream,
                        entry.noise_result.tx,
                        entry.noise_result.rx,
                        entry.noise_result.handshake_hash,
                        entry.noise_result.remote_public_key,
                    )
                    .await
                    {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!(err = %e, "passive holepunch: SecretStream failed");
                            if let Some(tx) = failure_tx {
                                let _ = tx.send(remote_pk);
                            }
                            return;
                        }
                    };

                    let conn = PeerConnection::with_remote_addr(ss, remote_pk, addr, entry.udx_socket, None);
                    let conn = watch.watch(conn, remote_pk, generation);
                    let swarm_conn = SwarmConnection {
                        peer: conn,
                        is_initiator: false,
                        topics: vec![],
                        _runtime: runtime,
                    };
                    if conn_tx.send(swarm_conn).await.is_err() {
                        tracing::warn!("connection channel closed");
                    }
                });
            }
            PassiveHolepunchEvent::Abort { id } => {
                let Some(mut entry) = self.connects.remove(&id) else {
                    return;
                };
                if let Some(task) = entry.abort_task.take() {
                    task.abort();
                }
                self.pending_handshakes.remove(&entry.remote_pk);
                if let Some(mut puncher) = entry.puncher.take() {
                    puncher.destroy();
                }
                tracing::warn!(
                    id,
                    pk = %short_hex(&entry.remote_pk),
                    "passive holepunch timed out"
                );
            }
        }
    }
}

/// How the server side of one handshake connects to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerPath {
    /// `relay_through` is configured: pair with the client through that blind
    /// relay. NAT traversal is bypassed entirely.
    Relay,
    /// Dial the client: connect our stream to its address, so we send the
    /// first packet and open our own NAT mapping towards it, as Node's
    /// `hs.onsocket(...)` does. With `advertise_holepunch`, the reply still
    /// offers `holepunch { id, relays }`, as a firewalled Node server does
    /// (`holepunch: ourRemoteAddr ? null : {...}`): an open Node client that
    /// sees it waits for our dial instead of dialling our firewalled address.
    Dial { advertise_holepunch: bool },
    /// Stage a passive holepunch that the client completes through our
    /// announce relays.
    Holepunch,
    /// Wait for the client's first packet and adopt its source address.
    Listen,
}

/// Choose the server-side path for a handshake, per Node hyperdht
/// `lib/server.js _addHandshake`.
///
/// - `relay_through` is whether *this* reply advertises `relay_through` info.
///   The swarm only sets it when its own NAT is randomized (see
///   [`SwarmConfig::relay_through`]), so a paired relay is always available.
/// - The client is *dialable* when it says it is `FIREWALL_OPEN`, or when its
///   handshake reached us directly rather than through a relay.
/// - We count as firewalled only once the DHT has settled on CONSISTENT or
///   RANDOM. UNKNOWN means NAT analysis hasn't gathered enough samples, and
///   the non-holepunch path is the safer choice there, as in Node.
fn select_server_path(
    relay_through: bool,
    server_firewall: u64,
    client_firewall: u64,
    forwarded: bool,
) -> ServerPath {
    let server_firewalled = matches!(server_firewall, FIREWALL_CONSISTENT | FIREWALL_RANDOM);
    if relay_through {
        ServerPath::Relay
    } else if client_firewall == FIREWALL_OPEN || !forwarded {
        ServerPath::Dial {
            advertise_holepunch: server_firewalled,
        }
    } else if server_firewalled {
        ServerPath::Holepunch
    } else {
        ServerPath::Listen
    }
}

/// Output of [`SwarmActor::try_setup_passive_holepunch`]. Holds everything
/// the actor needs to (a) build the handshake reply and (b) install the
/// in-flight entry once Noise finalisation has produced a `remote_pk` +
/// holepunch secret.
struct HolepunchSetup {
    id: u64,
    puncher_port: u16,
    puncher: Holepuncher,
    udx_stream: UdxStream,
    udx_socket: UdxSocket,
    abort_task: JoinHandle<()>,
}

impl HolepunchSetup {
    /// Drop a staged holepunch that will not be committed: stop its abort
    /// timer and close its puncher, as the timeout path does.
    fn release(self) {
        self.abort_task.abort();
        let mut puncher = self.puncher;
        puncher.destroy();
    }
}

/// Open the server side of a direct (non-relayed, non-holepunched) UDX stream.
///
/// With `dial` set, the stream connects to `client_address` straight away, so
/// our SecretStream header is the first packet and opens our NAT mapping
/// towards the client, as Node's `hs.onsocket(...)` does for an open or direct
/// client. Otherwise the stream listens and adopts the source of the first
/// packet that arrives for it.
async fn create_server_connection(
    runtime_handle: Arc<RuntimeHandle>,
    dht: HyperDhtHandle,
    local_stream_id: u32,
    remote_udx: &UdxInfo,
    client_address: &Ipv4Peer,
    dial: bool,
    noise_result: &peeroxide_dht::noise_wrap::NoiseWrapResult,
) -> Result<(PeerConnection, UdxRuntime), SwarmError> {
    let runtime = UdxRuntime::shared(runtime_handle);

    let remote_id = u32::try_from(remote_udx.id).map_err(|_| {
        SwarmError::Dht(peeroxide_dht::hyperdht::HyperDhtError::StreamEstablishment(
            "remote UDX id out of u32 range".into(),
        ))
    })?;

    let socket = dht
        .server_socket()
        .await
        .map_err(SwarmError::Dht)?
        .ok_or_else(|| {
            SwarmError::Dht(peeroxide_dht::hyperdht::HyperDhtError::StreamEstablishment(
                "DHT server socket not available".into(),
            ))
        })?;

    let stream = runtime.create_stream(local_stream_id).await?;
    let remote_addr = Arc::new(std::sync::Mutex::new(None));
    if dial {
        let ip = client_address.host.parse().map_err(|e| {
            SwarmError::Dht(peeroxide_dht::hyperdht::HyperDhtError::StreamEstablishment(
                format!("invalid client address {}: {e}", client_address.host),
            ))
        })?;
        let addr = SocketAddr::new(ip, client_address.port);
        stream.connect(&socket, remote_id, addr).await?;
        *remote_addr.lock().map_err(|_| SwarmError::ChannelClosed)? = Some(addr);
    } else {
        let observed = Arc::clone(&remote_addr);
        stream.set_firewall_hook(&socket, remote_id, move |_, port, ip| {
            if let Ok(mut addr) = observed.lock() {
                *addr = Some(SocketAddr::new(ip, port));
                true
            } else {
                false
            }
        })?;
    }

    let async_stream = stream.into_async_stream();
    let ss = SecretStream::from_session(
        false,
        async_stream,
        noise_result.tx,
        noise_result.rx,
        noise_result.handshake_hash,
        noise_result.remote_public_key,
    )
    .await
    .map_err(|e| SwarmError::Dht(peeroxide_dht::hyperdht::HyperDhtError::SecretStream(e)))?;

    let addr = remote_addr.lock().map_err(|_| SwarmError::ChannelClosed)?
        .ok_or(SwarmError::ChannelClosed)?;
    let conn = PeerConnection::with_remote_addr(ss, noise_result.remote_public_key, addr, socket, None);
    Ok((conn, runtime))
}

#[allow(clippy::too_many_arguments)]
async fn create_server_relay_connection(
    runtime_handle: Arc<RuntimeHandle>,
    dht: HyperDhtHandle,
    key_pair: KeyPair,
    relay_pk: [u8; 32],
    relay_addr: Option<std::net::SocketAddr>,
    token: [u8; 32],
    noise_result: peeroxide_dht::noise_wrap::NoiseWrapResult,
) -> Result<(PeerConnection, UdxRuntime), SwarmError> {
    use peeroxide_dht::blind_relay::BlindRelayClient;
    use peeroxide_dht::protomux::Mux;

    let runtime = UdxRuntime::shared(runtime_handle);

    // 1. HyperDHT connection to the relay node (control channel).
    // Use direct address when available, fall back to DHT routing.
    let connect_fut: std::pin::Pin<Box<dyn std::future::Future<Output = Result<PeerConnection, peeroxide_dht::hyperdht::HyperDhtError>> + Send>> =
        if let Some(addr) = relay_addr {
            tracing::debug!(?addr, "server: connecting to relay at known address");
            Box::pin(dht.connect_to(&key_pair, relay_pk, addr, &runtime))
        } else {
            Box::pin(dht.connect(&key_pair, relay_pk, &runtime))
        };
    let relay_conn = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        connect_fut,
    )
    .await
    .map_err(|_| {
        SwarmError::Dht(peeroxide_dht::hyperdht::HyperDhtError::HandshakeFailed(
            "relay connect timeout".into(),
        ))
    })?
    .map_err(SwarmError::Dht)?;

    let relay_addr = relay_conn.remote_addr.ok_or_else(|| {
        SwarmError::Dht(peeroxide_dht::hyperdht::HyperDhtError::StreamEstablishment(
            "relay connection has no remote_addr".into(),
        ))
    })?;

    // 2. Protomux over the control channel.
    let (mux, mux_run) = Mux::new(relay_conn.stream);
    let mux_task = tokio::spawn(mux_run);

    // 3. Open blind-relay client + pair as initiator (server initiates pairing).
    // Channel id = our public key (must match relay server's `id: socket.remotePublicKey`).
    let mut relay_client = BlindRelayClient::open(&mux, Some(key_pair.public_key.to_vec()))
        .await
        .map_err(|e| SwarmError::Dht(peeroxide_dht::hyperdht::HyperDhtError::Relay(e)))?;
    relay_client
        .wait_opened()
        .await
        .map_err(|e| SwarmError::Dht(peeroxide_dht::hyperdht::HyperDhtError::Relay(e)))?;

    let data_stream_id = peeroxide_dht::hyperdht::alloc_stream_id();

    let pair_response = relay_client
        .pair(true, &token, u64::from(data_stream_id))
        .await
        .map_err(|e| SwarmError::Dht(peeroxide_dht::hyperdht::HyperDhtError::Relay(e)))?;

    let remote_id = u32::try_from(pair_response.remote_id).map_err(|_| {
        SwarmError::Dht(peeroxide_dht::hyperdht::HyperDhtError::StreamEstablishment(
            "relay remote_id out of u32 range".into(),
        ))
    })?;

    // 4. Connect data UDX stream through the relay, reusing the control
    //    channel's socket so the relay sees traffic from the same source address.
    let data_stream = runtime.create_stream(data_stream_id).await?;
    data_stream
        .connect(&relay_conn.socket, remote_id, relay_addr)
        .await?;

    // 5. Wrap with SecretStream using the original Noise keys.
    // Server is responder (is_initiator=false) in the Noise handshake.
    let async_stream = data_stream.into_async_stream();
    let ss = SecretStream::from_session(
        false,
        async_stream,
        noise_result.tx,
        noise_result.rx,
        noise_result.handshake_hash,
        noise_result.remote_public_key,
    )
    .await
    .map_err(|e| SwarmError::Dht(peeroxide_dht::hyperdht::HyperDhtError::SecretStream(e)))?;

    let conn = PeerConnection::with_remote_addr(
        ss,
        noise_result.remote_public_key,
        relay_addr,
        relay_conn.socket,
        Some(mux_task),
    );
    Ok((conn, runtime))
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

    #[tokio::test(start_paused = true)]
    async fn handshake_reply_cache_returns_the_first_reply_until_it_expires() {
        let mut cache = HandshakeReplyCache::new(Duration::from_secs(20), 16);
        assert!(cache.get(b"noise-a").is_none());

        cache.insert(b"noise-a", b"reply-a".to_vec());
        assert_eq!(cache.get(b"noise-a").as_deref(), Some(&b"reply-a"[..]));
        assert!(cache.get(b"noise-b").is_none(), "other handshakes are not affected");

        cache.insert(b"noise-a", b"reply-other".to_vec());
        assert_eq!(
            cache.get(b"noise-a").as_deref(),
            Some(&b"reply-a"[..]),
            "the first reply wins"
        );

        tokio::time::advance(Duration::from_secs(19)).await;
        assert_eq!(cache.get(b"noise-a").as_deref(), Some(&b"reply-a"[..]));

        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(cache.get(b"noise-a").is_none());
        assert_eq!(cache.len(), 0, "expired entries are dropped");
        assert!(cache.order.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn handshake_reply_cache_evicts_the_oldest_entry_at_capacity() {
        let mut cache = HandshakeReplyCache::new(Duration::from_secs(20), 3);
        for i in 0u8..3 {
            cache.insert(&[i], vec![i]);
            tokio::time::advance(Duration::from_millis(1)).await;
        }
        assert_eq!(cache.len(), 3);

        cache.insert(&[3], vec![3]);
        assert_eq!(cache.len(), 3, "the cache never grows past its capacity");
        assert!(cache.get(&[0]).is_none(), "the oldest entry is evicted first");
        for i in 1u8..=3 {
            assert_eq!(cache.get(&[i]), Some(vec![i]));
        }

        // A flood of distinct handshakes stays bounded.
        for i in 0u32..10_000 {
            cache.insert(&i.to_le_bytes(), vec![0; 8]);
        }
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.order.len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn handshake_reply_cache_prune_expires_entries_without_new_handshakes() {
        let mut cache = HandshakeReplyCache::new(Duration::from_secs(20), 16);
        cache.insert(b"noise-a", b"reply-a".to_vec());
        tokio::time::advance(Duration::from_secs(10)).await;
        cache.insert(b"noise-b", b"reply-b".to_vec());

        tokio::time::advance(Duration::from_secs(11)).await;
        cache.prune();
        assert_eq!(cache.len(), 1, "only the expired entry is dropped");

        tokio::time::advance(Duration::from_secs(10)).await;
        cache.prune();
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.entries.capacity(), 0, "an empty cache releases its storage");
    }

    #[test]
    fn server_path_follows_node_server_add_handshake() {
        use ServerPath::*;
        const OPEN: u64 = FIREWALL_OPEN;
        const UNKNOWN: u64 = FIREWALL_UNKNOWN;
        const CONSISTENT: u64 = FIREWALL_CONSISTENT;
        const RANDOM: u64 = FIREWALL_RANDOM;

        // (relay_advertised, server, client, forwarded) -> path
        let cases = [
            // An advertised relay (randomized NAT) wins over everything.
            ((true, CONSISTENT, OPEN, false), Relay),
            ((true, UNKNOWN, UNKNOWN, true), Relay),
            // Open or direct clients are dialled; a firewalled server still
            // advertises a holepunch to them.
            ((false, CONSISTENT, OPEN, true), Dial { advertise_holepunch: true }),
            ((false, RANDOM, UNKNOWN, false), Dial { advertise_holepunch: true }),
            ((false, UNKNOWN, OPEN, true), Dial { advertise_holepunch: false }),
            ((false, OPEN, UNKNOWN, false), Dial { advertise_holepunch: false }),
            // A relayed, non-open client holepunches only to a firewalled server.
            ((false, CONSISTENT, UNKNOWN, true), Holepunch),
            ((false, RANDOM, CONSISTENT, true), Holepunch),
            ((false, UNKNOWN, UNKNOWN, true), Listen),
            ((false, OPEN, RANDOM, true), Listen),
        ];
        for ((relay_advertised, server, client, forwarded), want) in cases {
            assert_eq!(
                select_server_path(relay_advertised, server, client, forwarded),
                want,
                "relay_advertised={relay_advertised} server={server} client={client} forwarded={forwarded}"
            );
        }
    }

    #[test]
    fn server_handshake_reply_follows_the_inbound_mode() {
        use peeroxide_dht::hyperdht_messages::{decode_handshake_from_bytes, MODE_FROM_CLIENT};

        let client = Ipv4Peer {
            host: "10.0.0.1".to_string(),
            port: 4000,
        };

        for inbound in [MODE_FROM_RELAY, MODE_FROM_SECOND_RELAY] {
            let bytes = encode_server_handshake_reply(inbound, Some(client.clone()), vec![7; 48])
                .expect("encode");
            let m = decode_handshake_from_bytes(&bytes).expect("decode");
            assert_eq!(m.mode, MODE_FROM_SERVER);
            assert_eq!(m.peer_address.as_ref(), Some(&client));
            assert_eq!(m.noise, vec![7; 48]);
        }

        let bytes = encode_server_handshake_reply(MODE_FROM_CLIENT, Some(client), vec![7; 48])
            .expect("encode");
        let m = decode_handshake_from_bytes(&bytes).expect("decode");
        assert_eq!(m.mode, MODE_REPLY);
        assert!(m.peer_address.is_none());
    }

    #[tokio::test]
    async fn server_unregistered_on_leave_last_topic() {
        let config = SwarmConfig::default();

        let (_task, handle, _conn_rx) = crate::spawn(config).await.unwrap();
        let target = hash(&handle.key_pair().public_key);
        let topic = [0xAA; 32];

        handle.join(topic, JoinOpts { server: true, client: false }).await.unwrap();

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

        handle.join(topic, JoinOpts { server: true, client: false }).await.unwrap();

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

        handle.join(topic, JoinOpts { server: true, client: false }).await.unwrap();

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
}
