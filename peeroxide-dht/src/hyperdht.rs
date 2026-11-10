#![deny(clippy::all)]

use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use rand::random;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use libudx::{UdxAsyncStream, UdxRuntime, UdxSocket};

use crate::blind_relay::{BlindRelayClient, RelayError};
use crate::crypto::{
    NS_ANNOUNCE, NS_MUTABLE_PUT, NS_UNANNOUNCE, ann_signable, hash, mutable_signable,
    sign_detached, verify_detached,
};
use crate::holepuncher::{HolepunchEvent, Holepuncher};
use crate::hyperdht_messages::{
    ANNOUNCE, AnnounceMessage, ERROR_ABORTED, ERROR_NONE, ERROR_TRY_LATER, FIND_PEER,
    FIREWALL_OPEN, FIREWALL_UNKNOWN, HandshakeMessage, HolepunchInfo, HolepunchMessage,
    HolepunchPayload, HyperPeer, IMMUTABLE_GET, IMMUTABLE_PUT, LOOKUP, MODE_FROM_RELAY,
    MODE_FROM_SECOND_RELAY, MODE_FROM_SERVER, MODE_REPLY, MUTABLE_GET, MUTABLE_PUT,
    MutablePutRequest, NoisePayload, PEER_HANDSHAKE, PEER_HOLEPUNCH, RelayInfo, RelayThroughInfo,
    SecretStreamInfo, UNANNOUNCE, UdxInfo, decode_hyper_peer_from_bytes,
    decode_lookup_raw_reply_from_bytes, decode_mutable_get_response_from_bytes,
    encode_announce_to_bytes, encode_handshake_to_bytes, encode_holepunch_msg_to_bytes,
    encode_hyper_peer_to_bytes, encode_mutable_put_request_to_bytes,
};
use crate::messages::Ipv4Peer;
use crate::noise::Keypair as NoiseKeypair;
use crate::noise_wrap::{NoiseWrap, NoiseWrapResult};
use crate::peer::NodeId;
use crate::persistent::{
    HandlerReply, IncomingHyperRequest, Persistent, PersistentConfig, PersistentStats,
};
use crate::protomux::Mux;
use crate::query::QueryReply;
use crate::router::{ForwardEntry, HandshakeAction, HolepunchAction, Router};
use crate::rpc::{DhtConfig, DhtError, DhtHandle, UserQueryParams, UserRequestParams};
use crate::secret_stream::{SecretStream, SecretStreamError};
use crate::secure_payload::SecurePayload;
use crate::socket_pool::SocketPool;

// ── Errors ────────────────────────────────────────────────────────────────────

/// A nonzero random ID candidate for the legacy handshake-only API.
fn next_stream_id() -> u32 {
    random::<u32>().max(1)
}

/// Generate a nonzero random ID candidate without reserving it.
///
/// Prefer [`UdxRuntime::create_random_stream`] to select and reserve atomically.
/// Explicit `create_stream` rejects an occupied candidate instead of replacing it.
pub fn alloc_stream_id() -> u32 {
    next_stream_id()
}

/// Matches Node.js `isBogon` from the `bogon` package — returns true for
/// loopback, link-local, private RFC-1918, and other reserved ranges.
fn is_addr_private(host: &str) -> bool {
    let Ok(ip) = host.parse::<std::net::Ipv4Addr>() else {
        return true;
    };
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
        || ip.octets()[0] == 100 && ip.octets()[1] >= 64 && ip.octets()[1] <= 127 // CGN
}

/// Determines whether a direct connection should be attempted instead of holepunching.
///
/// Returns `true` (direct connect) when ANY of:
/// - The handshake was NOT relayed (client reached server directly)
/// - Server reports FIREWALL_OPEN
/// - Server has no holepunch relays (can't holepunch even if we wanted to)
/// - Both peers share the same host address
///
/// Matches Node.js connect.js decision logic.
pub fn should_direct_connect(
    relayed: bool,
    firewall: u64,
    remote_holepunchable: bool,
    same_host: bool,
) -> bool {
    !relayed || firewall == FIREWALL_OPEN || !remote_holepunchable || same_host
}

#[derive(Debug, Error)]
/// Errors returned by HyperDHT operations.
#[non_exhaustive]
pub enum HyperDhtError {
    /// Error propagated from the underlying DHT client.
    #[error("DHT error: {0}")]
    Dht(#[from] DhtError),
    /// Error while encoding or decoding protocol data.
    #[error("encoding error: {0}")]
    Encoding(#[from] crate::compact_encoding::EncodingError),
    /// Error from Noise handshake or session setup.
    #[error("noise error: {0}")]
    Noise(#[from] crate::noise::NoiseError),
    /// Error from the Noise wrapper layer.
    #[error("noise wrap error: {0}")]
    NoiseWrap(#[from] crate::noise_wrap::NoiseWrapError),
    /// Error from the router state machine.
    #[error("router error: {0}")]
    Router(#[from] crate::router::RouterError),
    /// Error while wrapping or unwrapping secure payloads.
    #[error("secure payload error: {0}")]
    SecurePayload(#[from] crate::secure_payload::SecurePayloadError),
    /// This DHT instance has been destroyed.
    #[error("node destroyed")]
    Destroyed,
    /// A signature did not verify.
    #[error("invalid signature")]
    InvalidSignature,
    /// A content hash did not match.
    #[error("invalid hash")]
    InvalidHash,
    /// The internal channel was closed.
    #[error("channel closed")]
    ChannelClosed,
    /// No peer was found for the requested target.
    #[error("peer not found")]
    PeerNotFound,
    /// No relay nodes were available for the operation.
    #[error("no relay nodes available")]
    NoRelayNodes,
    /// The handshake failed with the given message.
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    /// Hole punching did not succeed.
    #[error("holepunch failed")]
    HolepunchFailed,
    /// Hole punching was aborted by the remote side.
    #[error("holepunch aborted")]
    HolepunchAborted,
    /// The remote firewall rejected the connection.
    #[error("firewall rejected")]
    FirewallRejected,
    /// Error from the UDX transport layer.
    #[error("UDX error: {0}")]
    Udx(#[from] libudx::UdxError),
    /// Error from the secret stream layer.
    #[error("secret stream error: {0}")]
    SecretStream(#[from] SecretStreamError),
    /// Failed to establish a UDX stream.
    #[error("stream establishment failed: {0}")]
    StreamEstablishment(String),
    /// Error from the relay subsystem.
    #[error("relay error: {0}")]
    Relay(#[from] RelayError),
    /// [`HyperDhtServer::listen`] was called on an already-listening server.
    ///
    /// [`HyperDhtServer::listen`]: HyperDhtServer::listen
    #[error("already listening")]
    AlreadyListening,
    /// The [`HyperDhtServer`] has been closed or its accept task is gone.
    #[error("server closed")]
    ServerClosed,
}

// ── Server events (forwarded to listen() subscribers) ────────────────────────

/// Events forwarded to server-side listeners.
#[non_exhaustive]
pub enum ServerEvent {
    /// A peer handshake request that may need local server handling.
    PeerHandshake {
        /// The decoded handshake message.
        msg: HandshakeMessage,
        /// Address of the peer that sent the request to us.
        ///
        /// For a direct (non-forwarded) handshake, this is the remote peer.
        /// For a relayed handshake, this is the forwarding DHT node (the
        /// previous hop), NOT the originating peer; use `peer_address` for
        /// the originating peer's address in that case.
        from: Ipv4Peer,
        /// Address of the originating peer for a forwarded handshake, or
        /// `None` for a direct handshake.
        ///
        /// Populated from the relay-layer's `peer_address` payload field.
        /// Mirrors Node Hyperswarm's "peerAddress" semantics in
        /// `lib/router.js`. Servers should prefer this over `from` when
        /// choosing a remote address to dial.
        peer_address: Option<Ipv4Peer>,
        /// Optional DHT target associated with the request.
        target: Option<NodeId>,
        /// Reply channel for the generated response.
        reply_tx: oneshot::Sender<Option<ServerReply>>,
    },
    /// A peer holepunch request that may need local server handling.
    PeerHolepunch {
        /// The decoded holepunch message.
        msg: HolepunchMessage,
        /// Address of the peer that sent the request.
        from: Ipv4Peer,
        /// Address of the peer we should punch toward.
        peer_address: Ipv4Peer,
        /// Optional DHT target associated with the request.
        target: Option<NodeId>,
        /// Reply channel for the generated response.
        reply_tx: oneshot::Sender<Option<ServerReply>>,
    },
}

/// A server's answer to a handshake or holepunch request.
pub struct ServerReply {
    /// Encoded handshake or holepunch message.
    pub value: Vec<u8>,
    /// Socket to send it from. A server that staged a holepunch answers
    /// from the puncher socket, as hyperdht does (`{ socket: p.socket }`):
    /// the relay tags the reply with that socket's address, which is the one
    /// the client then punches toward. `None` sends from the DHT socket.
    pub socket: Option<UdxSocket>,
}

impl From<Vec<u8>> for ServerReply {
    fn from(value: Vec<u8>) -> Self {
        Self {
            value,
            socket: None,
        }
    }
}

// ── KeyPair ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
/// An Ed25519 key pair (libsodium layout: seed‖public_key).
pub struct KeyPair {
    /// The 32-byte public key.
    pub public_key: [u8; 32],
    /// The 64-byte secret key in libsodium layout.
    pub secret_key: [u8; 64],
}

impl KeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let seed: [u8; 32] = random();
        Self::from_seed(seed)
    }

    /// Derive a deterministic key pair from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let pk: [u8; 32] = signing_key.verifying_key().to_bytes();
        let mut sk = [0u8; 64];
        sk[..32].copy_from_slice(&seed);
        sk[32..].copy_from_slice(&pk);
        Self {
            public_key: pk,
            secret_key: sk,
        }
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &to_hex(self.public_key))
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    fn to_noise_keypair(&self) -> NoiseKeypair {
        NoiseKeypair {
            public_key: self.public_key,
            secret_key: self.secret_key,
        }
    }
}

// ── Result types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
/// Result from a LOOKUP query.
#[non_exhaustive]
pub struct LookupResult {
    /// Node that returned the lookup result.
    pub from: Ipv4Peer,
    /// Optional intermediate hop used to reach the node.
    pub to: Option<Ipv4Peer>,
    /// Peers advertised by the node.
    pub peers: Vec<HyperPeer>,
}

#[derive(Debug, Clone)]
/// Result from an ANNOUNCE operation.
#[non_exhaustive]
pub struct AnnounceResult {
    /// Closest nodes contacted during the announce.
    pub closest_nodes: Vec<Ipv4Peer>,
}

/// An in-flight announce, completed with [`AnnounceQuery::finished`].
pub struct AnnounceQuery {
    task: JoinHandle<Result<AnnounceResult, HyperDhtError>>,
}

impl AnnounceQuery {
    /// Wait for the announce query to finish.
    pub async fn finished(self) -> Result<AnnounceResult, HyperDhtError> {
        self.task.await.map_err(|_| HyperDhtError::ChannelClosed)?
    }
}

#[derive(Debug, Clone)]
/// Result from an immutable put operation.
#[non_exhaustive]
pub struct ImmutablePutResult {
    /// Content hash used as the target key.
    pub hash: [u8; 32],
    /// Closest nodes contacted during the write.
    pub closest_nodes: Vec<Ipv4Peer>,
}

#[derive(Debug, Clone)]
/// Result from a mutable put operation.
#[non_exhaustive]
pub struct MutablePutResult {
    /// Public key used as the mutable record key.
    pub public_key: [u8; 32],
    /// Closest nodes contacted during the write.
    pub closest_nodes: Vec<Ipv4Peer>,
    /// Record sequence number that was written.
    pub seq: u64,
    /// Signature over the stored value.
    pub signature: [u8; 64],
    /// Number of commit-phase requests that timed out.
    pub commit_timeouts: u32,
}

#[derive(Debug, Clone)]
/// Result from a mutable get operation.
#[non_exhaustive]
pub struct MutableGetResult {
    /// Retrieved value bytes.
    pub value: Vec<u8>,
    /// Sequence number attached to the value.
    pub seq: u64,
    /// Signature verifying the value.
    pub signature: [u8; 64],
    /// Node that returned the value.
    pub from: Ipv4Peer,
}

#[derive(Clone)]
/// Metadata needed to establish a peer connection.
#[non_exhaustive]
pub struct ConnectResult {
    /// Remote peer's public key.
    pub remote_public_key: [u8; 32],
    /// Address used to reach the server during handshake.
    pub server_address: Ipv4Peer,
    /// Address of the client-side peer endpoint.
    pub client_address: Ipv4Peer,
    /// Whether the connection was relayed through a third party.
    pub is_relayed: bool,
    /// Final Noise state and negotiated keys.
    pub noise: NoiseWrapResult,
    /// Local UDX stream id to use for the connection.
    pub local_stream_id: u32,
    /// Remote UDX metadata advertised by the peer.
    pub remote_udx: Option<UdxInfo>,
    /// The socket that received the successful holepunch probe, preserving its NAT mapping.
    /// Consumers should prefer it over the DHT server socket when present.
    pub udx_socket: Option<UdxSocket>,
}

impl fmt::Debug for ConnectResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectResult")
            .field("remote_public_key", &self.remote_public_key)
            .field("server_address", &self.server_address)
            .field("client_address", &self.client_address)
            .field("is_relayed", &self.is_relayed)
            .field("noise", &self.noise)
            .field("local_stream_id", &self.local_stream_id)
            .field("remote_udx", &self.remote_udx)
            .field(
                "udx_socket",
                &self.udx_socket.as_ref().map(|_| "Some(UdxSocket)"),
            )
            .finish()
    }
}

/// Established encrypted connection to a peer.
///
/// Wraps a [`SecretStream`] over a UDX transport, keeping the underlying
/// socket alive for the connection's lifetime.
#[non_exhaustive]
pub struct PeerConnection {
    /// Encrypted bidirectional stream to the peer.
    pub stream: SecretStream<UdxAsyncStream>,
    /// Remote peer's public key.
    pub remote_public_key: [u8; 32],
    /// Remote peer's network address (used by server-side relay to connect data streams).
    pub remote_addr: Option<std::net::SocketAddr>,
    /// The UDX socket underlying this connection. Public so relay flows
    /// in downstream crates can reuse the control channel's socket for
    /// data streams (matching Node.js behaviour).
    pub socket: UdxSocket,
    _relay_task: Option<JoinHandle<()>>,
}

impl PeerConnection {
    /// Create a new peer connection from its components.
    pub fn new(
        stream: SecretStream<UdxAsyncStream>,
        remote_public_key: [u8; 32],
        socket: UdxSocket,
        relay_task: Option<JoinHandle<()>>,
    ) -> Self {
        Self {
            stream,
            remote_public_key,
            remote_addr: None,
            socket,
            _relay_task: relay_task,
        }
    }

    /// Create a new peer connection with a known remote address.
    pub fn with_remote_addr(
        stream: SecretStream<UdxAsyncStream>,
        remote_public_key: [u8; 32],
        remote_addr: std::net::SocketAddr,
        socket: UdxSocket,
        relay_task: Option<JoinHandle<()>>,
    ) -> Self {
        Self {
            stream,
            remote_public_key,
            remote_addr: Some(remote_addr),
            socket,
            _relay_task: relay_task,
        }
    }

    /// Whether this side dialled the peer (`false` for server-side
    /// connections). Mirrors Node's `stream.isInitiator`.
    pub fn is_initiator(&self) -> bool {
        self.stream.is_initiator()
    }

    /// Connect a raw UDX stream over the same socket and peer address as this connection.
    pub async fn connect_raw_stream(
        &self,
        stream: &libudx::UdxStream,
        remote_id: u32,
    ) -> Result<(), HyperDhtError> {
        let addr = self.remote_addr.ok_or_else(|| {
            HyperDhtError::StreamEstablishment("connection has no known remote address".into())
        })?;
        stream.connect(&self.socket, remote_id, addr).await?;
        Ok(())
    }
}

impl fmt::Debug for PeerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerConnection")
            .field("remote_public_key", &&self.remote_public_key[..8])
            .field("remote_addr", &self.remote_addr)
            .field("relayed", &self._relay_task.is_some())
            .finish_non_exhaustive()
    }
}

/// Configuration used by the server-side handshake and holepunch handler.
#[derive(Clone)]
#[non_exhaustive]
pub struct ServerConfig {
    /// Server identity key pair.
    pub key_pair: KeyPair,
    /// Firewall mode advertised to connecting peers.
    pub firewall: u64,
    /// Blind relay offered to every client we cannot dial (Node
    /// `createServer({ relayThrough })`); the passive punch keeps running
    /// and moves the stream off the relay when it lands.
    pub relay_through: Option<[u8; 32]>,
    relay_randomized_only: bool,
    relay_addresses: Vec<Ipv4Peer>,
}

impl ServerConfig {
    /// Create a new server configuration.
    pub fn new(key_pair: KeyPair, firewall: u64) -> Self {
        Self {
            key_pair,
            firewall,
            relay_through: None,
            relay_randomized_only: false,
            relay_addresses: Vec::new(),
        }
    }

    /// Hyperswarm's default server relay policy: offer our relay only with randomized NAT.
    pub fn for_swarm(
        key_pair: KeyPair,
        firewall: u64,
        relay_through: Option<[u8; 32]>,
        relay_address: Option<SocketAddr>,
    ) -> Self {
        let relay_addresses = relay_address
            .into_iter()
            .map(|addr| Ipv4Peer {
                host: addr.ip().to_string(),
                port: addr.port(),
            })
            .collect();
        Self {
            key_pair,
            firewall,
            relay_through,
            relay_randomized_only: true,
            relay_addresses,
        }
    }
}

// ── Bootstrap defaults ────────────────────────────────────────────────────────

/// The three public HyperDHT bootstrap nodes (from `hyperdht/lib/constants.js`).
///
/// Format: `suggestedIP@hostname:port`.  `parse_bootstrap_str`
/// extracts the IP before `@`, so these work without DNS resolution.
pub const DEFAULT_BOOTSTRAP: [&str; 3] = [
    "88.99.3.86@node1.hyperdht.org:49737",
    "142.93.90.113@node2.hyperdht.org:49737",
    "138.68.147.8@node3.hyperdht.org:49737",
];

// ── Config ────────────────────────────────────────────────────────────────────

/// Per-connect options for [`HyperDhtHandle::connect_with_options`].
///
/// Default: same-NAT LAN-shortcut enabled (matches Node hyperdht's
/// `opts.localConnection` default of `true`).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConnectOpts {
    /// Allow the same-NAT LAN-shortcut. When `false`, the receiver
    /// ignores any loopback/private addresses the server advertised in
    /// its `addresses4` and dials only the public address. Set this to
    /// `false` to force the real-network code path under test.
    pub local_connection: bool,
    /// Blind relay to pair through while the direct path is still being
    /// tried (Node `dht.connect(pk, { relayThrough })`): whichever lands
    /// first carries the connection, and a later direct landing moves the
    /// stream off the relay.
    pub relay_through: Option<[u8; 32]>,
}

impl Default for ConnectOpts {
    fn default() -> Self {
        Self {
            local_connection: true,
            relay_through: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
/// Configuration for a HyperDHT instance.
#[non_exhaustive]
pub struct HyperDhtConfig {
    /// DHT transport and bootstrap settings.
    pub dht: DhtConfig,
    /// Persistent storage settings for stored records.
    pub persistent: PersistentConfig,
}

impl HyperDhtConfig {
    /// Create a config pre-populated with the public HyperDHT bootstrap nodes.
    ///
    /// This is the typical starting point for connecting to the live network.
    /// `DhtConfig::default()` intentionally keeps `bootstrap` empty so that
    /// unit tests can run without network access.
    pub fn with_public_bootstrap() -> Self {
        Self {
            dht: DhtConfig {
                bootstrap: DEFAULT_BOOTSTRAP.iter().map(|s| (*s).to_string()).collect(),
                ..DhtConfig::default()
            },
            persistent: PersistentConfig::default(),
        }
    }
}

// ── AdminRequest ──────────────────────────────────────────────────────────────

enum AdminRequest {
    PersistentStats {
        reply: oneshot::Sender<PersistentStats>,
    },
    /// Record FIND_PEER/LOOKUP serve for a local listener (`None` forgets it).
    LocalRecord {
        target: [u8; 32],
        record: Option<Vec<u8>>,
    },
}

// ── Raw streams (Node `HyperDHT#createRawStream`) ────────────────────────────

/// Firewall callback for a raw stream, Node
/// `createRawStream({ firewall(socket, port, host) })`.
///
/// Returning `true` rejects the packet; `false` accepts the source and
/// connects the stream to it.
pub type RawStreamFirewall = Box<dyn FnMut(&UdxSocket, u16, std::net::IpAddr) -> bool + Send>;

/// Options for [`HyperDhtHandle::create_raw_stream`].
///
/// Node's `framed: true` has no Rust equivalent — [`RawStream`] exposes the
/// byte stream directly.
#[non_exhaustive]
pub struct RawStreamOptions {
    /// Called for each packet that arrives before the stream is connected,
    /// and afterwards for packets arriving on another socket than the
    /// stream's (C `on_firewall`; hyperdht spots relay traffic this way).
    pub firewall: Option<RawStreamFirewall>,
}

impl RawStreamOptions {
    /// Options without a firewall hook.
    pub fn new() -> Self {
        Self { firewall: None }
    }

    /// Add the pre-connect firewall hook (Node `createRawStream({ firewall })`).
    pub fn with_firewall<F>(mut self, firewall: F) -> Self
    where
        F: FnMut(&UdxSocket, u16, std::net::IpAddr) -> bool + Send + 'static,
    {
        self.firewall = Some(Box::new(firewall));
        self
    }
}

impl Default for RawStreamOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// A raw UDX stream owned by the DHT, Node `dht.createRawStream()`.
///
/// The DHT keeps an abort handle for every raw stream it creates, so
/// [`HyperDhtHandle::suspend`] and [`HyperDhtHandle::destroy`] close them
/// (Node `rawStreams.clear()`), exactly as hyperdht does.
pub struct RawStream {
    id: u32,
    stream: libudx::UdxStream,
}

impl RawStream {
    /// The local UDX stream id (`rawStream.id`).
    pub fn id(&self) -> u32 {
        self.id
    }

    /// The underlying UDX stream.
    pub fn stream(&self) -> &libudx::UdxStream {
        &self.stream
    }

    /// Read the next chunk, or `None` once the stream is closed.
    pub async fn read(&mut self) -> Result<Option<Vec<u8>>, HyperDhtError> {
        Ok(self.stream.read().await?)
    }

    /// Write bytes, resolving once the peer ACKs them.
    pub async fn write(&self, data: &[u8]) -> Result<(), HyperDhtError> {
        Ok(self.stream.write(data).await?)
    }

    /// Forward every packet received on this stream to `destination`
    /// (`rawStream.relayTo(other)`).
    pub fn relay_to(&self, destination: &RawStream) -> Result<(), HyperDhtError> {
        Ok(self.stream.relay_to(&destination.stream)?)
    }

    /// Connect this stream over `socket` (`rawStream.connect(socket, id, port, host)`).
    ///
    /// On a stream primed with a firewall hook this arms the identity the
    /// stream will use once a packet is accepted, or fixes the peer id of a
    /// stream the hook already committed. Use [`change_remote`](Self::change_remote)
    /// to move a connected stream.
    pub async fn connect(
        &self,
        socket: &UdxSocket,
        remote_id: u32,
        addr: std::net::SocketAddr,
    ) -> Result<(), HyperDhtError> {
        Ok(self.stream.connect(socket, remote_id, addr).await?)
    }

    /// Move the connected stream to another peer and socket
    /// (`rawStream.changeRemote(socket, id, port, host)`); resolves once
    /// everything sent before the change is ACKed.
    pub async fn change_remote(
        &self,
        socket: &UdxSocket,
        remote_id: u32,
        addr: std::net::SocketAddr,
    ) -> Result<(), HyperDhtError> {
        Ok(self
            .stream
            .remote_handle()
            .change_remote(socket, remote_id, addr)
            .await?)
    }

    /// Take the id and underlying stream, leaving the DHT in charge of the
    /// stream's lifetime (abort on suspend/destroy still applies).
    pub fn into_stream(self) -> (u32, libudx::UdxStream) {
        (self.id, self.stream)
    }
}

impl fmt::Debug for RawStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawStream")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

// ── HyperDhtHandle ────────────────────────────────────────────────────────────

#[derive(Clone)]
/// Main public HyperDHT API handle.
pub struct HyperDhtHandle {
    dht: DhtHandle,
    router: Arc<Mutex<Router>>,
    server_tx: mpsc::UnboundedSender<ServerEvent>,
    server_routes:
        Arc<Mutex<std::collections::HashMap<[u8; 32], mpsc::UnboundedSender<ServerEvent>>>>,
    admin_tx: mpsc::UnboundedSender<AdminRequest>,
    current_relays: Arc<Mutex<Vec<RelayInfo>>>,
    /// Abort handles for every raw stream this DHT created
    /// (Node `HyperDHT#rawStreams`).
    raw_streams: Arc<Mutex<Vec<libudx::UdxStreamAbort>>>,
}

impl HyperDhtHandle {
    // ── WIRE STATS ────────────────────────────────────────────────────────────

    /// Snapshot of cumulative wire bytes (sent, received) since this DHT
    /// node started. Counts every UDP datagram exchanged at the IO layer
    /// — queries, requests, replies, retries, relays, and any user-issued
    /// puts/gets — regardless of which higher-level operation produced them.
    ///
    /// Useful for distinguishing "useful payload throughput" (what consumers
    /// see) from "raw network throughput" (what the OS sees). The ratio
    /// between them is the DHT's protocol amplification factor.
    pub fn wire_stats(&self) -> (u64, u64) {
        self.dht.wire_stats()
    }

    /// Borrow the shared wire-counter handle for long-lived sampling. The
    /// returned counters are `Arc<AtomicU64>` internally; cloning is cheap.
    pub fn wire_counters(&self) -> crate::io::WireCounters {
        self.dht.wire_counters()
    }

    // ── LOOKUP ────────────────────────────────────────────────────────────────

    /// Query the DHT for peers advertising the target.
    pub async fn lookup(&self, target: [u8; 32]) -> Result<Vec<LookupResult>, HyperDhtError> {
        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: LOOKUP,
                value: None,
                commit: false,
                concurrency: None,
            })
            .await?;

        let mut results = Vec::new();
        for reply in replies {
            if let Some(value) = &reply.value {
                if let Ok(raw) = decode_lookup_raw_reply_from_bytes(value) {
                    if !raw.peers.is_empty() {
                        results.push(LookupResult {
                            from: reply.from.clone(),
                            to: None,
                            peers: raw.peers,
                        });
                    }
                }
            }
        }
        Ok(results)
    }

    // ── ANNOUNCE ─────────────────────────────────────────────────────────────

    /// Start an announce with no explicit relay addresses.
    pub fn announce_query(&self, target: [u8; 32], key_pair: &KeyPair) -> AnnounceQuery {
        let dht = self.clone();
        let key_pair = key_pair.clone();
        AnnounceQuery {
            task: tokio::spawn(async move { dht.announce(target, &key_pair, &[]).await }),
        }
    }

    /// Announce this peer under the given target.
    pub async fn announce(
        &self,
        target: [u8; 32],
        key_pair: &KeyPair,
        relay_addresses: &[Ipv4Peer],
    ) -> Result<AnnounceResult, HyperDhtError> {
        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: LOOKUP,
                value: None,
                commit: true,
                concurrency: None,
            })
            .await?;

        let mut closest_nodes = Vec::new();
        let mut accepted_relays: Vec<RelayInfo> = Vec::new();

        for reply in &replies {
            closest_nodes.push(reply.from.clone());

            let token = match &reply.token {
                Some(t) => *t,
                None => continue,
            };
            let node_id = match &reply.from_id {
                Some(id) => *id,
                None => continue,
            };

            // Stored record uses caller-provided relays verbatim, matching
            // Node `_requestAnnounce`: `ann.peer.relayAddresses = relayAddresses || []`.
            // Closest-ack accumulation lives only in handle-state
            // (`current_relay_addresses` below) for *subsequent* announces
            // to consume — it is NEVER written into a stored peer record.
            // Do not "fix" this by re-adding per-record accumulation; the
            // TOPIC-close nodes don't hold FE for `hash(pk)`, so advertising
            // them as PEER_HANDSHAKE relays yields "empty reply".
            let record_relays: Vec<Ipv4Peer> = relay_addresses.iter().take(3).cloned().collect();

            let peer = HyperPeer {
                public_key: key_pair.public_key,
                relay_addresses: record_relays,
            };

            let peer_encoded = encode_hyper_peer_to_bytes(&peer)?;
            let signable =
                ann_signable(&target, &token, &node_id, &peer_encoded, &[], &NS_ANNOUNCE);
            let signature = sign_detached(&signable, &key_pair.secret_key);

            let ann = AnnounceMessage {
                peer: Some(peer),
                refresh: None,
                signature: Some(signature),
                bump: 0,
            };
            let ann_bytes = encode_announce_to_bytes(&ann)?;

            let _ = self
                .dht
                .request(
                    UserRequestParams {
                        token: Some(token),
                        command: ANNOUNCE,
                        target: Some(target),
                        value: Some(ann_bytes),
                        timeout_ms: None,
                        retries: None,
                    },
                    &reply.from.host,
                    reply.from.port,
                )
                .await;

            // Accumulate this acker into handle-state relay list (Node
            // `Announcer._commit`: `if (relayAddresses.length < 3)
            // relayAddresses.push({ host: msg.from.host, port: msg.from.port })`
            // and `relays.push({ relayAddress: msg.from, peerAddress: msg.to })`).
            // We push only once per accepted reply and cap at 3. Dedup is
            // implicit — each `reply.from` is a distinct DHT node.
            if accepted_relays.len() < 3 {
                accepted_relays.push(RelayInfo {
                    relay_address: reply.from.clone(),
                    peer_address: reply.to.clone(),
                });
            }
        }

        // Only update handle-state `current_relay_addresses` when announcing
        // on `hash(public_key)` (self-announce). Topic-announces also produce
        // a `closest_nodes` set, but those are topic-close nodes (NOT FE-holders
        // for PEER_HANDSHAKE forwarding). Mixing them into `current_relay_addresses`
        // — when parallel announces race on the shared Mutex — would corrupt
        // the relay list the topic-announce reads on a subsequent refresh.
        // See peer_discovery::do_refresh for the parallel-join order.
        if target == hash(&key_pair.public_key) {
            if let Ok(mut guard) = self.current_relays.lock() {
                *guard = accepted_relays;
            }
        }

        Ok(AnnounceResult { closest_nodes })
    }

    // ── FIND_PEER ─────────────────────────────────────────────────────────────

    /// Return the first peer record found for the target.
    pub async fn find_peer(&self, target: [u8; 32]) -> Result<Option<HyperPeer>, HyperDhtError> {
        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: FIND_PEER,
                value: None,
                commit: false,
                concurrency: None,
            })
            .await?;

        for reply in replies {
            if let Some(value) = reply.value {
                if let Ok(peer) = decode_hyper_peer_from_bytes(&value) {
                    return Ok(Some(peer));
                }
            }
        }
        Ok(None)
    }

    /// Run a FIND_PEER query and return all raw replies.
    ///
    /// Unlike [`find_peer`](Self::find_peer), this returns every reply from
    /// the iterative query so callers can try connecting through each
    /// responding node's address.
    pub async fn query_find_peer(
        &self,
        target: [u8; 32],
    ) -> Result<Vec<QueryReply>, HyperDhtError> {
        Ok(self
            .dht
            .query(UserQueryParams {
                target,
                command: FIND_PEER,
                value: None,
                commit: false,
                concurrency: None,
            })
            .await?)
    }

    // ── UNANNOUNCE ────────────────────────────────────────────────────────────

    /// Remove a previously announced peer record.
    pub async fn unannounce(
        &self,
        target: [u8; 32],
        key_pair: &KeyPair,
    ) -> Result<(), HyperDhtError> {
        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: LOOKUP,
                value: None,
                commit: false,
                concurrency: None,
            })
            .await?;

        for reply in &replies {
            let token = match &reply.token {
                Some(t) => *t,
                None => continue,
            };
            let node_id = match &reply.from_id {
                Some(id) => *id,
                None => continue,
            };

            let peer = HyperPeer {
                public_key: key_pair.public_key,
                relay_addresses: vec![],
            };
            let peer_encoded = encode_hyper_peer_to_bytes(&peer)?;
            let signable = ann_signable(
                &target,
                &token,
                &node_id,
                &peer_encoded,
                &[],
                &NS_UNANNOUNCE,
            );
            let signature = sign_detached(&signable, &key_pair.secret_key);

            let ann = AnnounceMessage {
                peer: Some(peer),
                refresh: None,
                signature: Some(signature),
                bump: 0,
            };
            let ann_bytes = encode_announce_to_bytes(&ann)?;

            let _ = self
                .dht
                .request(
                    UserRequestParams {
                        token: Some(token),
                        command: UNANNOUNCE,
                        target: Some(target),
                        value: Some(ann_bytes),
                        timeout_ms: None,
                        retries: None,
                    },
                    &reply.from.host,
                    reply.from.port,
                )
                .await;
        }

        Ok(())
    }

    // ── IMMUTABLE_PUT ────────────────────────────────────────────────────────

    /// Store immutable content under its content hash.
    pub async fn immutable_put(&self, value: &[u8]) -> Result<ImmutablePutResult, HyperDhtError> {
        let target = hash(value);

        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: IMMUTABLE_GET,
                value: None,
                commit: true,
                concurrency: None,
            })
            .await?;

        let mut closest_nodes = Vec::new();

        for reply in &replies {
            closest_nodes.push(reply.from.clone());

            let token = match &reply.token {
                Some(t) => *t,
                None => continue,
            };

            let _ = self
                .dht
                .request(
                    UserRequestParams {
                        token: Some(token),
                        command: IMMUTABLE_PUT,
                        target: Some(target),
                        value: Some(value.to_vec()),
                        timeout_ms: None,
                        retries: None,
                    },
                    &reply.from.host,
                    reply.from.port,
                )
                .await;
        }

        Ok(ImmutablePutResult {
            hash: target,
            closest_nodes,
        })
    }

    // ── IMMUTABLE_GET ────────────────────────────────────────────────────────

    /// Fetch immutable content by content hash.
    pub async fn immutable_get(&self, target: [u8; 32]) -> Result<Option<Vec<u8>>, HyperDhtError> {
        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: IMMUTABLE_GET,
                value: None,
                commit: false,
                concurrency: None,
            })
            .await?;

        for reply in replies {
            if let Some(value) = reply.value {
                if hash(&value) == target {
                    return Ok(Some(value));
                }
            }
        }
        Ok(None)
    }

    // ── MUTABLE_PUT ───────────────────────────────────────────────────────────

    /// Store a signed mutable record for the given key pair.
    pub async fn mutable_put(
        &self,
        key_pair: &KeyPair,
        value: &[u8],
        seq: u64,
    ) -> Result<MutablePutResult, HyperDhtError> {
        let signable = mutable_signable(&NS_MUTABLE_PUT, seq, value);
        let signature = sign_detached(&signable, &key_pair.secret_key);
        self.mutable_put_signed(&key_pair.public_key, value, seq, signature)
            .await
    }

    /// Store a mutable record whose signature was produced elsewhere, such
    /// as a guard forwarding an endpoint-signed record (Node `mutablePut`
    /// with `opts.signMutable` returning the precomputed signature; only
    /// `keyPair.publicKey` is used). The signature must be over
    /// `mutable_signable(NS_MUTABLE_PUT, seq, value)`; storing nodes verify
    /// it against `public_key`.
    pub async fn mutable_put_signed(
        &self,
        public_key: &[u8; 32],
        value: &[u8],
        seq: u64,
        signature: [u8; 64],
    ) -> Result<MutablePutResult, HyperDhtError> {
        let target = hash(public_key);

        let put = MutablePutRequest {
            public_key: *public_key,
            seq,
            value: value.to_vec(),
            signature,
        };
        let put_bytes = encode_mutable_put_request_to_bytes(&put)?;

        // Node queries with seq 0: the lookup only collects tokens.
        let seq_bytes = encode_compact_uint(0);

        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: MUTABLE_GET,
                value: Some(seq_bytes),
                commit: true,
                concurrency: None,
            })
            .await?;

        let mut closest_nodes = Vec::new();
        let mut commit_timeouts: u32 = 0;

        for reply in &replies {
            closest_nodes.push(reply.from.clone());

            let token = match &reply.token {
                Some(t) => *t,
                None => continue,
            };

            if let Err(DhtError::RequestFailed(_)) = self
                .dht
                .request(
                    UserRequestParams {
                        token: Some(token),
                        command: MUTABLE_PUT,
                        target: Some(target),
                        value: Some(put_bytes.clone()),
                        timeout_ms: None,
                        retries: None,
                    },
                    &reply.from.host,
                    reply.from.port,
                )
                .await
            {
                commit_timeouts += 1;
            }
        }

        Ok(MutablePutResult {
            public_key: *public_key,
            closest_nodes,
            seq,
            signature,
            commit_timeouts,
        })
    }

    // ── MUTABLE_GET ───────────────────────────────────────────────────────────

    /// Fetch and verify a mutable record for the given public key.
    pub async fn mutable_get(
        &self,
        public_key: &[u8; 32],
        seq: u64,
    ) -> Result<Option<MutableGetResult>, HyperDhtError> {
        let target = hash(public_key);
        let seq_bytes = encode_compact_uint(seq);

        let replies = self
            .dht
            .query(UserQueryParams {
                target,
                command: MUTABLE_GET,
                value: Some(seq_bytes),
                commit: false,
                concurrency: None,
            })
            .await?;

        for reply in replies {
            if let Some(value) = &reply.value {
                if let Ok(resp) = decode_mutable_get_response_from_bytes(value) {
                    if resp.seq >= seq {
                        let signable = mutable_signable(&NS_MUTABLE_PUT, resp.seq, &resp.value);
                        if verify_detached(&resp.signature, &signable, public_key) {
                            return Ok(Some(MutableGetResult {
                                value: resp.value,
                                seq: resp.seq,
                                signature: resp.signature,
                                from: reply.from,
                            }));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// Wait until the DHT is bootstrapped.
    pub async fn bootstrapped(&self) -> Result<(), HyperDhtError> {
        self.dht.bootstrapped().await.map_err(HyperDhtError::Dht)
    }

    /// Wait until the initial bootstrap query has completed.
    pub async fn fully_bootstrapped(&self) -> Result<(), HyperDhtError> {
        self.dht
            .fully_bootstrapped()
            .await
            .map_err(HyperDhtError::Dht)
    }

    /// Create a raw UDX stream owned by this DHT (Node
    /// `dht.createRawStream({ framed, firewall })`).
    ///
    /// With a firewall hook the stream listens on the DHT's primary socket and
    /// hands every packet that arrives before it is connected to the hook;
    /// [`RawStream::connect`] or [`Self::connect_raw_stream`] then fixes the
    /// peer. The DHT keeps the stream in its raw-stream set, so `suspend` and
    /// `destroy` close it.
    pub async fn create_raw_stream(
        &self,
        runtime: &UdxRuntime,
        options: RawStreamOptions,
    ) -> Result<RawStream, HyperDhtError> {
        let (id, stream) = runtime.create_random_stream().await?;
        if let Some(mut firewall) = options.firewall {
            let socket = self
                .dht
                .server_socket()
                .await?
                .ok_or(HyperDhtError::ChannelClosed)?;
            // The remote id is not known until the stream is connected; the
            // socket demux routes by this stream's local id. Node's hook
            // returns `true` to reject, libudx's to accept.
            stream.set_firewall_hook(&socket, 0, move |socket, port, host| {
                !firewall(socket, port, host)
            })?;
        }
        self.track_raw_stream(stream.abort_handle());
        Ok(RawStream { id, stream })
    }

    /// Connect `raw` over an established encrypted connection (Node
    /// `HyperDHT.connectRawStream(encryptedStream, rawStream, remoteId)`).
    ///
    /// The raw stream reuses the connection's socket and remote address, as
    /// `private-overlay` does when it opens a data circuit beside its control
    /// connection.
    pub async fn connect_raw_stream(
        &self,
        connection: &PeerConnection,
        raw: &RawStream,
        remote_id: u32,
    ) -> Result<(), HyperDhtError> {
        connection.connect_raw_stream(raw.stream(), remote_id).await
    }

    /// Keep `stream` in the raw-stream set so `suspend` and `destroy` close
    /// it (Node `dht._rawStreams.add`), dropping streams already gone.
    fn track_raw_stream(&self, stream: libudx::UdxStreamAbort) {
        let closed = stream.clone();
        let registry = Arc::downgrade(&self.raw_streams);
        if let Ok(mut streams) = self.raw_streams.lock() {
            streams.retain(|s| s.is_alive());
            streams.push(stream);
        }
        tokio::spawn(async move {
            closed.closed().await;
            if let Some(registry) = registry.upgrade() {
                if let Ok(mut streams) = registry.lock() {
                    streams.retain(|stream| stream.is_alive());
                }
            }
        });
    }

    /// Suspend the node (Node `HyperDHT#suspend()`): close both sockets, fail
    /// every in-flight query, drop raw streams and stop ticking.
    ///
    /// Listening servers keep their routing-table targets, but no packet can
    /// be sent or received until [`Self::resume`].
    pub async fn suspend(&self) -> Result<(), HyperDhtError> {
        // Node clears the raw-stream set before and after suspending dht-rpc.
        self.clear_raw_streams();
        let result = self.dht.suspend().await.map_err(HyperDhtError::Dht);
        self.clear_raw_streams();
        result
    }

    /// Resume a suspended node (Node `HyperDHT#resume()`): rebind the sockets
    /// on their previous ports and refresh the routing table.
    pub async fn resume(&self) -> Result<(), HyperDhtError> {
        self.dht.resume().await.map_err(HyperDhtError::Dht)
    }

    /// Destroy the underlying DHT instance.
    pub async fn destroy(&self) -> Result<(), HyperDhtError> {
        self.clear_raw_streams();
        self.dht.destroy().await.map_err(HyperDhtError::Dht)
    }

    /// Close every raw stream this DHT created (Node `rawStreams.clear()`).
    fn clear_raw_streams(&self) {
        if let Ok(mut streams) = self.raw_streams.lock() {
            for handle in std::mem::take(&mut *streams) {
                handle.abort();
            }
        }
    }

    /// Returns the number of nodes in the routing table.
    pub async fn table_size(&self) -> Result<usize, HyperDhtError> {
        self.dht.table_size().await.map_err(HyperDhtError::Dht)
    }

    /// Returns the local port the DHT server socket is bound to.
    pub async fn local_port(&self) -> Result<u16, HyperDhtError> {
        self.dht.local_port().await.map_err(HyperDhtError::Dht)
    }

    /// Returns the DHT server socket for multiplexing UDX streams.
    pub async fn server_socket(&self) -> Result<Option<UdxSocket>, HyperDhtError> {
        self.dht.server_socket().await.map_err(HyperDhtError::Dht)
    }

    /// Returns the actual listen socket (bound to the advertised server port).
    pub async fn listen_socket(&self) -> Result<Option<UdxSocket>, HyperDhtError> {
        self.dht.listen_socket().await.map_err(HyperDhtError::Dht)
    }

    /// Returns the externally-observed IPv4 address of this node, as inferred
    /// from the `to` field of inbound DHT responses (NAT consensus).
    ///
    /// Returns `None` until the NAT analysis has settled. Mirrors Node
    /// Hyperswarm's `dht.remoteAddress()`.
    pub async fn remote_address(&self) -> Result<Option<crate::messages::Ipv4Peer>, HyperDhtError> {
        self.dht.remote_address().await.map_err(HyperDhtError::Dht)
    }

    /// Build the IPv4 `addresses4` list to advertise in a noise handshake
    /// payload. Mirrors Node `hyperdht/lib/connect.js:420-437` and
    /// `hyperdht/lib/server.js:277-284`: the reflexive address from
    /// [`Self::remote_address`] (if any) is prepended, then the local
    /// IPv4 interface addresses from
    /// [`Holepuncher::local_addresses`](crate::holepuncher::Holepuncher::local_addresses)
    /// are appended. Order matters: the receiver iterates this list
    /// sequentially and LAN-special-cases on its side.
    pub async fn noise_addresses4(&self, port: u16) -> Vec<crate::messages::Ipv4Peer> {
        let mut out = Vec::new();
        if let Ok(Some(remote)) = self.remote_address().await {
            out.push(remote);
        }
        let bound = match self.server_socket().await {
            Ok(Some(socket)) => socket.local_addr().await.ok(),
            _ => None,
        };
        match bound.map(|addr| addr.ip()) {
            Some(std::net::IpAddr::V4(ip)) if !ip.is_unspecified() => {
                out.push(Ipv4Peer {
                    host: ip.to_string(),
                    port,
                });
            }
            _ => out.extend(crate::holepuncher::Holepuncher::local_addresses(port)),
        }
        out
    }

    /// Returns the current firewall classification (one of the
    /// `FIREWALL_OPEN` / `FIREWALL_UNKNOWN` / `FIREWALL_CONSISTENT` /
    /// `FIREWALL_RANDOM` constants from [`crate::hyperdht_messages`]).
    ///
    /// Mirrors Node Hyperswarm's `dht.firewalled`.
    pub async fn firewalled(&self) -> Result<u64, HyperDhtError> {
        self.dht.firewalled().await.map_err(HyperDhtError::Dht)
    }

    /// Returns the set of DHT-relay endpoints this node is currently
    /// announcing through (capped at 3, refreshed on each `announce()`).
    ///
    /// These are the addresses of DHT nodes that successfully accepted this
    /// node's last announce — meaning they hold a `ForwardEntry` and will
    /// relay `PEER_HANDSHAKE` on this node's behalf. Empty until the first
    /// `announce()` completes.
    ///
    /// Mirrors Node Hyperswarm's `Server.relayAddresses` / `Announcer.relayAddresses`.
    pub fn current_relay_addresses(&self) -> Vec<crate::messages::Ipv4Peer> {
        self.current_relays()
            .into_iter()
            .map(|relay| relay.relay_address)
            .collect()
    }

    /// The same relays as [`Self::current_relay_addresses`], each paired with
    /// our own address as that relay saw it when it accepted the announce.
    ///
    /// This is what a server advertises in the `holepunch.relays` of its
    /// handshake reply: a client sends its PEER_HOLEPUNCH to `relay_address`,
    /// and the relay forwards it to `peer_address`, so `peer_address` must be
    /// how that relay reaches *us*. Empty until the first `announce()` on
    /// `hash(public_key)` completes.
    ///
    /// Mirrors Node Hyperswarm's `Announcer.relays`
    /// (`{ relayAddress: msg.from, peerAddress: msg.to }`).
    pub fn current_relays(&self) -> Vec<RelayInfo> {
        self.current_relays
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Access the shared router state.
    pub fn router(&self) -> &Arc<Mutex<Router>> {
        &self.router
    }

    /// Access the underlying DHT handle.
    pub fn dht(&self) -> &DhtHandle {
        &self.dht
    }

    /// Returns persistent storage statistics collected from the request handler.
    pub async fn persistent_stats(&self) -> Result<PersistentStats, HyperDhtError> {
        let (tx, rx) = oneshot::channel();
        self.admin_tx
            .send(AdminRequest::PersistentStats { reply: tx })
            .map_err(|_| HyperDhtError::Destroyed)?;
        rx.await.map_err(|_| HyperDhtError::Destroyed)
    }

    /// Mark `hash(public_key)` as served by a local server: inbound
    /// `PEER_HANDSHAKE` for it is handled here, and FIND_PEER/LOOKUP answer
    /// with our own record even when no other node stored our announce
    /// (Node `server.listen()` → `dht._router.set(target, { record })`).
    pub fn register_server(&self, public_key: &[u8; 32]) {
        let target = hash(public_key);
        if let Ok(mut router) = self.router.lock() {
            router.set(
                &target,
                ForwardEntry {
                    relay: None,
                    has_server: true,
                    inserted: std::time::Instant::now(),
                },
            );
        }
        let record = encode_hyper_peer_to_bytes(&HyperPeer {
            public_key: *public_key,
            relay_addresses: Vec::new(),
        })
        .ok();
        let _ = self
            .admin_tx
            .send(AdminRequest::LocalRecord { target, record });
    }

    /// Remove the local-server marker and record for a target.
    pub fn unregister_server(&self, target: &[u8; 32]) {
        if let Ok(mut router) = self.router.lock() {
            router.delete(target);
        }
        let _ = self.admin_tx.send(AdminRequest::LocalRecord {
            target: *target,
            record: None,
        });
    }

    /// Access the server event sender.
    pub fn server_sender(&self) -> &mpsc::UnboundedSender<ServerEvent> {
        &self.server_tx
    }

    // ── CONNECT (client-side holepunch orchestration) ─────────────────────

    /// Connect to a remote peer using the DHT and relay fallback.
    pub async fn connect(
        &self,
        key_pair: &KeyPair,
        remote_public_key: [u8; 32],
        runtime: &UdxRuntime,
    ) -> Result<PeerConnection, HyperDhtError> {
        self.connect_with_nodes(key_pair, remote_public_key, &[], runtime)
            .await
    }

    /// Connect to a remote peer, optionally using known relay addresses first.
    ///
    /// Connection strategy (matches Node.js `findAndConnect` in
    /// `hyperdht/lib/connect.js`):
    /// 1. Try provided `relay_addresses` first (optimistic pre-connect).
    /// 2. Run FIND_PEER on hash(remote_pk); each responder is an FE-holder
    ///    (it returned a stored peer record), making it a known-good
    ///    PEER_HANDSHAKE forwarder. Try each `reply.from`, and additionally
    ///    each `peer.relay_addresses` entry from the stored records.
    /// 3. Fallback to FIND_NODE walk on hash(remote_pk) for nodes the DHT
    ///    routing table knows about but didn't store an FE.
    pub async fn connect_with_nodes(
        &self,
        key_pair: &KeyPair,
        remote_public_key: [u8; 32],
        relay_addresses: &[Ipv4Peer],
        runtime: &UdxRuntime,
    ) -> Result<PeerConnection, HyperDhtError> {
        self.connect_with_options(
            key_pair,
            remote_public_key,
            relay_addresses,
            runtime,
            ConnectOpts::default(),
        )
        .await
    }

    /// Like [`Self::connect_with_nodes`] but accepts a [`ConnectOpts`] options bag.
    ///
    /// Use this when you need to disable the same-NAT LAN-shortcut
    /// (e.g. to force the real-network code path under test).
    pub async fn connect_with_options(
        &self,
        key_pair: &KeyPair,
        remote_public_key: [u8; 32],
        relay_addresses: &[Ipv4Peer],
        runtime: &UdxRuntime,
        opts: ConnectOpts,
    ) -> Result<PeerConnection, HyperDhtError> {
        let mut last_err = HyperDhtError::NoRelayNodes;
        let mut tried: Vec<(String, u16)> = Vec::new();

        // Phase 1: Optimistic pre-connect through provided relay addresses.
        for relay in relay_addresses {
            tried.push((relay.host.clone(), relay.port));
            match self
                .connect_through_node(key_pair, &remote_public_key, relay, runtime, &opts)
                .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    tracing::debug!(relay = %format!("{}:{}", relay.host, relay.port), err = %e, "pre-connect relay attempt failed");
                    last_err = e;
                }
            }
        }

        let target = hash(&remote_public_key);

        // Phase 2: FIND_PEER on hash(pk). Responders are FE-holders (they
        // returned a stored peer record under this target). Their `reply.from`
        // address is a verified PEER_HANDSHAKE forwarder. This mirrors Node's
        // `findAndConnect` which does `dht.findPeer(c.target)` and tries each
        // `data.from`.
        let peer_replies = self.query_find_peer(target).await.unwrap_or_else(|e| {
            tracing::debug!(err = %e, "connect_with_nodes: FIND_PEER query failed");
            Vec::new()
        });
        tracing::debug!(
            reply_count = peer_replies.len(),
            "connect_with_nodes: FIND_PEER completed"
        );

        for reply in &peer_replies {
            if reply.value.is_none() {
                continue;
            }
            if tried
                .iter()
                .any(|(h, p)| h == &reply.from.host && *p == reply.from.port)
            {
                continue;
            }
            tried.push((reply.from.host.clone(), reply.from.port));
            tracing::debug!(
                relay = %format!("{}:{}", reply.from.host, reply.from.port),
                "connect_with_nodes: trying FE-holder"
            );
            match self
                .connect_through_node(key_pair, &remote_public_key, &reply.from, runtime, &opts)
                .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    tracing::debug!(
                        relay = %format!("{}:{}", reply.from.host, reply.from.port),
                        err = %e,
                        "FE-holder relay attempt failed"
                    );
                    last_err = e;
                }
            }
        }

        for reply in &peer_replies {
            if let Some(value) = &reply.value {
                if let Ok(peer) = decode_hyper_peer_from_bytes(value) {
                    for relay in &peer.relay_addresses {
                        if tried
                            .iter()
                            .any(|(h, p)| h == &relay.host && *p == relay.port)
                        {
                            continue;
                        }
                        tried.push((relay.host.clone(), relay.port));
                        match self
                            .connect_through_node(
                                key_pair,
                                &remote_public_key,
                                relay,
                                runtime,
                                &opts,
                            )
                            .await
                        {
                            Ok(result) => return Ok(result),
                            Err(e) => {
                                tracing::debug!(
                                    relay = %format!("{}:{}", relay.host, relay.port),
                                    err = %e,
                                    "peer-record relay attempt failed"
                                );
                                last_err = e;
                            }
                        }
                    }
                }
            }
        }

        // Phase 3: Fallback to FIND_NODE walk for closer nodes the DHT routing
        // table reaches but that didn't return an FE record (e.g. mid-refresh).
        let table_size = self.dht.table_size().await.unwrap_or(0);
        tracing::debug!(
            table_size,
            "connect_with_nodes: routing table size before FIND_NODE"
        );
        let node_replies = self
            .dht
            .find_node(target)
            .await
            .map_err(HyperDhtError::Dht)?;
        tracing::debug!(
            reply_count = node_replies.len(),
            "connect_with_nodes: FIND_NODE completed"
        );

        if relay_addresses.is_empty() && peer_replies.is_empty() && node_replies.is_empty() {
            return Err(HyperDhtError::PeerNotFound);
        }

        let mut candidates: Vec<Ipv4Peer> = Vec::new();
        for reply in &node_replies {
            candidates.push(reply.from.clone());
            for cn in &reply.closer_nodes {
                if !candidates
                    .iter()
                    .any(|c| c.host == cn.host && c.port == cn.port)
                {
                    candidates.push(cn.clone());
                }
            }
        }
        tracing::debug!(
            candidate_count = candidates.len(),
            "connect_with_nodes: total FIND_NODE candidates (replies + closer_nodes)"
        );

        for (i, candidate) in candidates.iter().enumerate() {
            let skip = tried
                .iter()
                .any(|(h, p)| h == &candidate.host && *p == candidate.port);
            tracing::debug!(
                i,
                candidate = %format!("{}:{}", candidate.host, candidate.port),
                skip,
                "connect_with_nodes: candidate check"
            );
            if skip {
                continue;
            }
            tried.push((candidate.host.clone(), candidate.port));
            tracing::debug!(
                candidate = %format!("{}:{}", candidate.host, candidate.port),
                "connect_with_nodes: trying node candidate"
            );
            match self
                .connect_through_node(key_pair, &remote_public_key, candidate, runtime, &opts)
                .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    tracing::debug!(
                        relay = %format!("{}:{}", candidate.host, candidate.port),
                        err = %e,
                        "find_node candidate attempt failed"
                    );
                    last_err = e;
                }
            }
        }

        Err(last_err)
    }

    /// Connect directly to a peer at a known address, bypassing DHT routing.
    ///
    /// Sends a PEER_HANDSHAKE directly to `target_addr` for `remote_public_key`.
    /// Useful when the target's address is already known (e.g. from prior
    /// configuration or out-of-band exchange), avoiding the FIND_NODE phase
    /// that requires the target to be well-propagated in the DHT.
    pub async fn connect_to(
        &self,
        key_pair: &KeyPair,
        remote_public_key: [u8; 32],
        target_addr: std::net::SocketAddr,
        runtime: &UdxRuntime,
    ) -> Result<PeerConnection, HyperDhtError> {
        let relay = Ipv4Peer {
            host: target_addr.ip().to_string(),
            port: target_addr.port(),
        };
        self.connect_through_node(
            key_pair,
            &remote_public_key,
            &relay,
            runtime,
            &ConnectOpts::default(),
        )
        .await
    }

    async fn connect_through_node(
        &self,
        key_pair: &KeyPair,
        remote_public_key: &[u8; 32],
        relay: &Ipv4Peer,
        runtime: &UdxRuntime,
        opts: &ConnectOpts,
    ) -> Result<PeerConnection, HyperDhtError> {
        let target = hash(remote_public_key);

        // Phase 1: Noise IK handshake via PEER_HANDSHAKE relay
        let mut nw = NoiseWrap::new_initiator(key_pair.to_noise_keypair(), *remote_public_key);

        let (local_stream_id, local_stream) = runtime.create_random_stream().await?;
        self.track_raw_stream(local_stream.abort_handle());

        // Advertise our reflexive address (if known) + local IPv4
        // interface addresses. Mirrors Node `lib/connect.js:420-437`. The
        // receiver sequentially probes this list and applies its own
        // LAN-special-case filtering — see `hyperdht/lib/server.js:426`.
        let client_addresses4 = match self.dht.local_port().await {
            Ok(p) => self.noise_addresses4(p).await,
            Err(_) => vec![],
        };

        // Node `connect.js:455`: a client-chosen relay rides in the handshake
        // with a fresh pairing token.
        let relay_token: Option<[u8; 32]> = opts.relay_through.map(|_| random());

        let local_payload = NoisePayload {
            version: 1,
            error: 0,
            firewall: FIREWALL_UNKNOWN,
            holepunch: None,
            addresses4: client_addresses4,
            addresses6: vec![],
            udx: Some(UdxInfo {
                version: 1,
                reusable_socket: true,
                id: u64::from(local_stream_id),
                seq: 0,
            }),
            secret_stream: Some(SecretStreamInfo { version: 1 }),
            relay_through: opts
                .relay_through
                .zip(relay_token)
                .map(|(public_key, token)| RelayThroughInfo {
                    version: 1,
                    public_key,
                    token,
                }),
            relay_addresses: None,
        };

        let noise_bytes = nw.send(&local_payload)?;
        let handshake_value = Router::encode_client_handshake(noise_bytes, None, None)?;

        let resp = self
            .dht
            .request(
                UserRequestParams {
                    token: None,
                    command: PEER_HANDSHAKE,
                    target: Some(target),
                    value: Some(handshake_value),
                    timeout_ms: Some(10000),
                    retries: Some(0),
                },
                &relay.host,
                relay.port,
            )
            .await?;

        if resp.error != 0 {
            return Err(HyperDhtError::HandshakeFailed(format!(
                "error code {}",
                resp.error
            )));
        }

        let reply_value = resp
            .value
            .ok_or_else(|| HyperDhtError::HandshakeFailed("empty reply".into()))?;

        let hs_result = {
            let router = self
                .router
                .lock()
                .map_err(|_| HyperDhtError::ChannelClosed)?;
            router.validate_handshake_reply(&reply_value, relay, &resp.from, &resp.to)?
        };

        let remote_payload = nw.recv(&hs_result.noise)?;
        let nw_result = nw.finalize()?;

        if remote_payload.error != 0 {
            return Err(HyperDhtError::FirewallRejected);
        }

        let remote_udx = remote_payload
            .udx
            .clone()
            .ok_or_else(|| HyperDhtError::HandshakeFailed("server sent no UDX info".into()))?;
        let remote_id = u32::try_from(remote_udx.id).map_err(|_| {
            HyperDhtError::StreamEstablishment("remote UDX id out of u32 range".into())
        })?;

        // Node `connect.js:534`: the server's relay wins over ours (it holds
        // the token both sides pair with); either way the direct path keeps
        // running and moves the stream off the relay when it lands.
        let relay_through = match (
            &remote_payload.relay_through,
            opts.relay_through.zip(relay_token),
        ) {
            (Some(theirs), _) => Some((theirs.public_key, theirs.token, false)),
            (None, Some((public_key, token))) => Some((public_key, token, true)),
            (None, None) => None,
        };
        let raced = RacedStream::new(local_stream);
        let direct = DirectDial {
            dht: self.clone(),
            hs_result,
            remote_payload: remote_payload.clone(),
            nw_result: nw_result.clone(),
            node: relay.clone(),
            target,
            local_stream_id,
            remote_id,
            local_connection: opts.local_connection,
            has_relay: relay_through.is_some(),
        };

        let Some((relay_pk, token, initiator)) = relay_through else {
            let landing = direct.run(runtime).await?;
            return raced.land(landing, &nw_result, true).await?.ok_or(
                HyperDhtError::StreamEstablishment("stream landed twice".into()),
            );
        };

        let (landed_tx, mut landed_rx) = mpsc::channel(2);
        let direct_runtime = UdxRuntime::shared(runtime.handle());
        let direct_tx = landed_tx.clone();
        tokio::spawn(async move {
            let _ = direct_tx.send(direct.run(&direct_runtime).await).await;
        });
        let relay_dht = self.clone();
        let relay_key_pair = key_pair.clone();
        let hints = remote_payload.relay_addresses.clone().unwrap_or_default();
        let relay_runtime = UdxRuntime::shared(runtime.handle());
        let relay_raced = Arc::clone(&raced);
        tokio::spawn(async move {
            let landing = relay_dht
                .relay_path(
                    &relay_key_pair,
                    relay_pk,
                    &hints,
                    initiator,
                    &token,
                    local_stream_id,
                    &relay_runtime,
                    &relay_raced,
                )
                .await;
            let _ = landed_tx.send(landing).await;
        });

        // Node `maybeDestroyEncryptedSocket`: a failed path is not fatal while
        // the other is still trying.
        let mut last_err = None;
        let first = loop {
            match landed_rx.recv().await {
                Some(Ok(landing)) => break landing,
                Some(Err(err)) => last_err = Some(err),
                None => return Err(last_err.unwrap_or(HyperDhtError::HolepunchFailed)),
            }
        };
        let conn = raced.land(first, &nw_result, true).await?;
        let noise = nw_result.clone();
        tokio::spawn(async move {
            while let Some(landing) = landed_rx.recv().await {
                match landing {
                    Ok(landing) => {
                        let _ = raced.land(landing, &noise, true).await;
                    }
                    Err(err) => tracing::debug!(%err, "alternate connection path failed"),
                }
            }
        });
        conn.ok_or(HyperDhtError::StreamEstablishment(
            "stream landed twice".into(),
        ))
    }
}

/// Everything the client's direct path needs after the handshake, owned so
/// it can run beside the relay (Node `holepunch(c, opts)`).
struct DirectDial {
    dht: HyperDhtHandle,
    hs_result: crate::router::HandshakeResult,
    remote_payload: NoisePayload,
    nw_result: NoiseWrapResult,
    /// The DHT node that forwarded our handshake; holepunch rounds go through it.
    node: Ipv4Peer,
    target: [u8; 32],
    local_stream_id: u32,
    remote_id: u32,
    local_connection: bool,
    has_relay: bool,
}

impl DirectDial {
    async fn run(self, runtime: &UdxRuntime) -> Result<Landing, HyperDhtError> {
        let DirectDial {
            dht,
            hs_result,
            remote_payload,
            nw_result,
            node,
            target,
            local_stream_id,
            remote_id,
            local_connection,
            has_relay,
        } = self;
        let this = &dht;
        let relay = &node;

        // Skip holepunching when the remote peer is directly reachable.
        // Node.js (connect.js) checks:
        //   payload.firewall === FIREWALL.OPEN  -- server says it's open
        //   (relayed && !remoteHolepunchable)   -- relayed but server has no HP relays
        //   same NAT (own remote addr matches server's reflexive)  -- LAN shortcut
        // In any of those cases, connect directly using the server address from the handshake.
        let remote_holepunchable = remote_payload
            .holepunch
            .as_ref()
            .is_some_and(|hp| !hp.relays.is_empty());

        // Use this handshake's reflexive address, not a sample from another relay/egress.
        let same_host =
            local_connection && hs_result.client_address.host == hs_result.server_address.host;

        tracing::debug!(
            relayed = hs_result.relayed,
            firewall = remote_payload.firewall,
            remote_holepunchable,
            same_host,
            server_address = %format!("{}:{}", hs_result.server_address.host, hs_result.server_address.port),
            "handshake complete, deciding connection path"
        );

        if should_direct_connect(
            hs_result.relayed,
            remote_payload.firewall,
            remote_holepunchable,
            same_host,
        ) {
            // Pick the dial target. When same-host is true (both peers
            // share a NAT), prefer a private/loopback address from the
            // remote's advertised list, since the public IP often can't be
            // reached from inside the same NAT (no NAT hairpin). Otherwise
            // prefer a non-private public address, falling back to the
            // FE-holder's-tagged server address. Mirrors Node
            // `lib/connect.js::holepunch` LAN-shortcut.
            let connect_addr = if same_host {
                remote_payload
                    .addresses4
                    .iter()
                    .find(|a| is_addr_private(&a.host))
                    .cloned()
                    .or_else(|| {
                        remote_payload
                            .addresses4
                            .iter()
                            .find(|a| !is_addr_private(&a.host))
                            .cloned()
                    })
                    .unwrap_or_else(|| hs_result.server_address.clone())
            } else {
                remote_payload
                    .addresses4
                    .iter()
                    .find(|a| !is_addr_private(&a.host))
                    .cloned()
                    .unwrap_or_else(|| hs_result.server_address.clone())
            };
            tracing::debug!(
                same_host,
                connect_addr = %format!("{}:{}", connect_addr.host, connect_addr.port),
                server_address = %format!("{}:{}", hs_result.server_address.host, hs_result.server_address.port),
                advertised = ?remote_payload.addresses4.iter().map(|a| format!("{}:{}", a.host, a.port)).collect::<Vec<_>>(),
                "direct-connect dial target chosen"
            );

            let socket = socket_or_new(this.server_socket().await?, runtime).await?;
            return Ok(Landing {
                socket,
                remote_id,
                addr: to_socket_addr(&connect_addr)?,
                relay: None,
            });
        }

        // Phase 2: Holepunch rounds via PEER_HOLEPUNCH relay
        let server_address = hs_result.server_address.clone();
        let hp_result = this
            .run_holepunch_rounds(
                &nw_result,
                &remote_payload,
                relay,
                &target,
                &server_address,
                runtime,
                local_stream_id,
                has_relay,
            )
            .await?;
        let socket = match hp_result.udx_socket.clone() {
            Some(s) => s,
            None => socket_or_new(this.server_socket().await?, runtime).await?,
        };
        Ok(Landing {
            socket,
            remote_id,
            addr: to_socket_addr(&hp_result.server_address)?,
            relay: None,
        })
    }
}

impl HyperDhtHandle {
    /// Dialling the relay is itself a connect; boxing it here (not inline)
    /// keeps the connect future's type from recursing.
    fn connect_boxed<'a>(
        &'a self,
        key_pair: &'a KeyPair,
        public_key: [u8; 32],
        hints: &'a [Ipv4Peer],
        runtime: &'a UdxRuntime,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<PeerConnection, HyperDhtError>> + Send + 'a>>
    {
        Box::pin(self.connect_with_nodes(key_pair, public_key, hints, runtime))
    }

    /// Pair with the peer through `relay_pk` (Node `relayConnection` /
    /// `_relayConnection`): dial the relay, open a blind-relay channel and
    /// pair our stream id with the peer's under `token`.
    #[allow(clippy::too_many_arguments)]
    async fn relay_path(
        &self,
        key_pair: &KeyPair,
        relay_pk: [u8; 32],
        relay_addr_hints: &[Ipv4Peer],
        is_initiator: bool,
        token: &[u8; 32],
        local_stream_id: u32,
        runtime: &UdxRuntime,
        raced: &RacedStream,
    ) -> Result<Landing, HyperDhtError> {
        /// Node `relayTimeout`: a relay that has not paired us in 15 s is abandoned.
        const RELAY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

        let relay_conn = self
            .connect_boxed(key_pair, relay_pk, relay_addr_hints, runtime)
            .await?;
        let relay_addr = relay_conn.remote_addr.ok_or_else(|| {
            HyperDhtError::StreamEstablishment("relay connection has no remote_addr".into())
        })?;
        // Known before any relayed packet can reach us, so a direct landing
        // from this address is recognised as relay traffic (Node `isRelay`).
        if let Ok(mut addr) = raced.relay_addr.lock() {
            *addr = Some(relay_addr);
        }
        let control = relay_conn.stream.abort_handle();
        // Protomux over the control channel; the relay server keys the
        // channel by our public key (`id = socket.remotePublicKey`).
        let (mux, mux_run) = Mux::new(relay_conn.stream);
        let keep_mux = mux.clone();
        let data_closed = raced.abort.clone();
        let close_control = control.clone();
        let mux_task = tokio::spawn(async move {
            // Pairing is not the end of the control connection's lifetime.
            let _keep_mux = keep_mux;
            tokio::select! {
                () = data_closed.closed() => close_control.abort(),
                () = mux_run => {}
            }
        });
        let pair = tokio::time::timeout(RELAY_TIMEOUT, async {
            let mut client =
                BlindRelayClient::open(&mux, Some(key_pair.public_key.to_vec())).await?;
            client.wait_opened().await?;
            client
                .pair(is_initiator, token, u64::from(local_stream_id))
                .await
        })
        .await;
        let remote_id = match pair {
            Ok(Ok(response)) => u32::try_from(response.remote_id).ok(),
            Ok(Err(err)) => {
                tracing::debug!(err = %err, "relay pairing failed");
                None
            }
            Err(_) => None,
        };
        let Some(remote_id) = remote_id else {
            control.abort();
            mux_task.abort();
            return Err(HyperDhtError::StreamEstablishment(
                "relay pairing failed".into(),
            ));
        };
        Ok(Landing {
            socket: relay_conn.socket,
            remote_id,
            addr: relay_addr,
            relay: Some((control, mux_task)),
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_holepunch_rounds(
        &self,
        nw_result: &NoiseWrapResult,
        remote_payload: &NoisePayload,
        relay: &Ipv4Peer,
        target: &[u8; 32],
        _server_address: &Ipv4Peer,
        runtime: &UdxRuntime,
        local_stream_id: u32,
        has_relay: bool,
    ) -> Result<ConnectResult, HyperDhtError> {
        // Node-shaped multi-round client holepunch loop.
        //
        // The previous (legacy) implementation sent exactly two PEER_HOLEPUNCH
        // messages — a probe (`punching=false`) and an immediate punch
        // (`punching=true`) — then waited for the local Holepuncher to emit a
        // Connected event. That does not match Node's `lib/connect.js`
        // semantics and fails against passive Node servers (and against our
        // own swarm-side passive holepunch server).
        //
        // The flow below mirrors Node:
        //   1. Up to `HOLEPUNCH_MAX_PROBE_ROUNDS` probe rounds, each with
        //      `punching=false`. After every reply we feed the new info into
        //      the Holepuncher via `update_remote(...)` and ask `analyze(false)`
        //      whether the local NAT state is stable enough to punch.
        //   2. A reply is only treated as "verified" when its `remote_token`
        //      echoes the token we sent on the same round — only the
        //      legitimate server could echo our random token through the
        //      encrypted FE-holder relay.
        //   3. Once we have at least one verified remote address AND
        //      `analyze(false)` is true we send a single final
        //      `punching=true` round, then race the local `puncher.punch()`
        //      against incoming `HolepunchEvent::Connected`/`Aborted` events,
        //      bounded by `HOLEPUNCH_TOTAL_DEADLINE`.
        //   4. `reply.error` is decoded each round: `ERROR_NONE` continues,
        //      `ERROR_TRY_LATER` is retried in the next probe round,
        //      `ERROR_ABORTED` returns `HolepunchAborted`, anything else
        //      returns `HolepunchFailed`.

        /// Maximum wall-clock time spent in the full holepunch flow (probes +
        /// final punch + waiting for Connected).
        const HOLEPUNCH_TOTAL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
        /// Maximum number of `punching=false` probe rounds before we either
        /// transition to the final punch round or give up.
        const HOLEPUNCH_MAX_PROBE_ROUNDS: u32 = 3;

        let sp = SecurePayload::new(nw_result.holepunch_secret);
        let pool = SocketPool::new("0.0.0.0".into());
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();

        let hp_id = remote_payload.holepunch.as_ref().map_or(0, |hp| hp.id);

        let mut puncher = Holepuncher::new(
            &pool,
            runtime,
            true,
            true,
            remote_payload.firewall,
            event_tx,
        )
        .await
        .map_err(|_| HyperDhtError::HolepunchFailed)?;

        // Seed the puncher's NAT classifier with reflexive samples from the
        // puncher socket's own UDP binding BEFORE punch() runs. Without this
        // the puncher.nat stays UNKNOWN (Phase 3's only sample source was
        // PEER_HOLEPUNCH replies, all from the same FE-holder, which Nat::add
        // dedupes after the first hit) and coerce_firewall would have to lie.
        // See Node lib/holepuncher.js:13-20 + lib/nat.js:25-79.
        let added = puncher.auto_sample(&self.dht).await;
        tracing::debug!(
            added,
            firewall = puncher.nat.firewall,
            "initiator auto_sample"
        );

        // Holepunch payload `addresses` list: prefer the puncher's
        // autoSample-derived reflexive samples (`puncher.nat.addresses`)
        // and fall back to local LAN interface enumeration when those are
        // empty. Mirrors Node `hyperdht/lib/holepuncher.js:221-227` (the
        // receiver iterates `remoteAddresses` to drive `_consistentProbe`).
        let local_punch_addrs: Vec<Ipv4Peer> = match puncher.primary_socket() {
            Some(sr) => match sr.socket.local_addr().await {
                Ok(addr) => puncher.punch_addresses(addr.port()),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };

        let deadline = tokio::time::Instant::now() + HOLEPUNCH_TOTAL_DEADLINE;

        // State carried between probe rounds.
        let mut cached_reply_token: Option<[u8; 32]> = None;
        let mut verified_remote_addr: Option<Ipv4Peer> = None;
        let mut last_round: u64 = 0;

        for round in 0u64..=u64::from(HOLEPUNCH_MAX_PROBE_ROUNDS) {
            last_round = round;

            // Fresh outbound token per round; the reply must echo this back
            // in `remote_token` for us to consider the host verified.
            let our_outbound_token: [u8; 32] = rand::random();

            let probe_payload = HolepunchPayload {
                error: ERROR_NONE,
                firewall: puncher.nat.firewall,
                round,
                connected: false,
                punching: false,
                addresses: Some(local_punch_addrs.clone()),
                remote_address: None,
                token: Some(our_outbound_token),
                remote_token: cached_reply_token,
            };

            let encrypted_probe = sp.encrypt(&probe_payload)?;
            let hp_value = Router::encode_client_holepunch(hp_id, encrypted_probe, None)?;

            tracing::debug!(round, hp_id, "probe sent");

            let hp_resp = self
                .dht
                .request(
                    UserRequestParams {
                        token: None,
                        command: PEER_HOLEPUNCH,
                        target: Some(*target),
                        value: Some(hp_value),
                        timeout_ms: None,
                        retries: None,
                    },
                    &relay.host,
                    relay.port,
                )
                .await?;

            if hp_resp.error != 0 {
                puncher.destroy();
                return Err(HyperDhtError::HolepunchFailed);
            }

            let Some(reply_value) = &hp_resp.value else {
                puncher.destroy();
                return Err(HyperDhtError::HolepunchFailed);
            };

            let hp_result = {
                let router = self
                    .router
                    .lock()
                    .map_err(|_| HyperDhtError::ChannelClosed)?;
                router.validate_holepunch_reply(reply_value, relay, &hp_resp.from, relay)?
            };

            let reply_hp = sp.decrypt(&hp_result.payload)?;

            match reply_hp.error {
                ERROR_NONE => {}
                ERROR_TRY_LATER => {
                    tracing::debug!(round, "reply ERROR_TRY_LATER, continuing");
                    cached_reply_token = reply_hp.token;
                    continue;
                }
                ERROR_ABORTED => {
                    puncher.destroy();
                    return Err(HyperDhtError::HolepunchAborted);
                }
                other => {
                    tracing::warn!(round, error = other, "holepunch reply server error");
                    puncher.destroy();
                    return Err(HyperDhtError::HolepunchFailed);
                }
            }

            // Mirror Node `connect.js:612-616`: feed NAT sampler.
            puncher.nat.add(&hp_result.peer_address, &hp_resp.from);

            // Token-echo verification: only consider the host verified if
            // the reply echoes back our outbound token in `remote_token`.
            let token_matches = reply_hp.remote_token == Some(our_outbound_token);
            let verified_host = if token_matches {
                Some(hp_result.peer_address.host.as_str())
            } else {
                None
            };

            tracing::debug!(
                round,
                punching = reply_hp.punching,
                firewall = reply_hp.firewall,
                addresses = reply_hp.addresses.as_ref().map_or(0, |a| a.len()),
                verified = token_matches,
                "probe reply"
            );

            if let Some(addrs) = &reply_hp.addresses {
                puncher.update_remote(reply_hp.punching, reply_hp.firewall, addrs, verified_host);
            }

            if token_matches {
                verified_remote_addr = Some(hp_result.peer_address.clone());
            }
            cached_reply_token = reply_hp.token;

            // Match Node `connect.js:630-634`: 1s grace on UNKNOWN firewall.
            if reply_hp.firewall == FIREWALL_UNKNOWN {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }

            // Synchronous early-exit: if BOTH local NAT is settled (sampled
            // enough to classify) AND remote firewall is settled AND we have
            // a verified remote address, we can short-circuit the remaining
            // probe rounds. We deliberately avoid `puncher.analyze(false).await`
            // here because that awaits `nat.analyzing()` which can't resolve
            // until `NAT_MIN_SAMPLES` samples have accumulated — calling it
            // mid-loop would deadlock the loop's own sample-accumulation work.
            // The post-loop `analyze(true)` provides the authoritative wait.
            if verified_remote_addr.is_some()
                && puncher.nat.is_settled()
                && reply_hp.firewall != FIREWALL_UNKNOWN
            {
                tracing::info!(
                    target: "peeroxide::_events::holepunch::nat_settled",
                    round,
                    "NAT settled + verified remote, transitioning to final punch round"
                );
                break;
            }
        }

        // shortcut: verified probe rounds may proceed with UNKNOWN local NAT;
        // require settled sampling here when porting Node's analyze/reopen gate.

        let Some(verified_addr) = verified_remote_addr else {
            tracing::warn!(
                target: "peeroxide::_events::holepunch::failed_no_verified_addr",
                "no verified remote address after probe rounds"
            );
            puncher.destroy();
            return Err(HyperDhtError::HolepunchFailed);
        };

        let mut final_round = last_round;
        loop {
            while !puncher.reserve_random_punch() {
                if !puncher.retry_random_punch(has_relay, deadline).await {
                    puncher.destroy();
                    return Err(HyperDhtError::HolepunchAborted);
                }
            }

            // ── Final punch round (single round with punching=true) ─────────────
            final_round = final_round.saturating_add(1);
            let final_outbound_token: [u8; 32] = rand::random();
            let punch_payload = HolepunchPayload {
                error: ERROR_NONE,
                firewall: puncher.nat.firewall,
                round: final_round,
                connected: false,
                punching: true,
                addresses: Some(local_punch_addrs.clone()),
                remote_address: Some(verified_addr.clone()),
                token: Some(final_outbound_token),
                remote_token: cached_reply_token,
            };

            let encrypted_punch = sp.encrypt(&punch_payload)?;
            let hp_punch_value = Router::encode_client_holepunch(hp_id, encrypted_punch, None)?;

            tracing::info!(
                target: "peeroxide::_events::holepunch::final_punch_sent",
                round = final_round,
                verified_addr = %format!("{}:{}", verified_addr.host, verified_addr.port),
                "final punch sent, waiting for Connected event"
            );

            let punch_resp = self
                .dht
                .request(
                    UserRequestParams {
                        token: None,
                        command: PEER_HOLEPUNCH,
                        target: Some(*target),
                        value: Some(hp_punch_value),
                        timeout_ms: None,
                        retries: None,
                    },
                    &relay.host,
                    relay.port,
                )
                .await?;

            if let Some(reply_value) = &punch_resp.value {
                let hp_result = {
                    let router = self
                        .router
                        .lock()
                        .map_err(|_| HyperDhtError::ChannelClosed)?;
                    router.validate_holepunch_reply(reply_value, relay, &punch_resp.from, relay)?
                };

                if let Ok(reply_hp) = sp.decrypt(&hp_result.payload) {
                    if reply_hp.error == ERROR_TRY_LATER {
                        if !puncher.retry_random_punch(has_relay, deadline).await {
                            puncher.destroy();
                            return Err(HyperDhtError::HolepunchAborted);
                        }
                        continue;
                    }
                    if reply_hp.error != ERROR_NONE {
                        puncher.destroy();
                        return Err(HyperDhtError::HolepunchAborted);
                    }
                    let verified_host = if reply_hp.remote_token == Some(final_outbound_token) {
                        Some(hp_result.peer_address.host.as_str())
                    } else {
                        None
                    };
                    if let Some(addrs) = &reply_hp.addresses {
                        puncher.update_remote(
                            reply_hp.punching,
                            reply_hp.firewall,
                            addrs,
                            verified_host,
                        );
                    }
                }
            }
            break;
        }

        // Spawn the local punch loop and race it against Connected / Aborted
        // events and the global deadline. The pinned `punch_fut` mutably
        // borrows `puncher` for the duration of the inner scope; on timeout
        // we exit the scope so the borrow is released before we call
        // `puncher.destroy()`.

        let timed_out = {
            let punch_fut = puncher.punch(&pool, runtime);
            tokio::pin!(punch_fut);
            let mut punch_done = false;
            let deadline_sleep = tokio::time::sleep_until(deadline);
            tokio::pin!(deadline_sleep);

            loop {
                tokio::select! {
                    ev = event_rx.recv() => {
                        match ev {
                            Some(HolepunchEvent::Connected { addr, socket }) => {
                                tracing::info!(
                                    target: "peeroxide::_events::holepunch::connected",
                                    from = %addr,
                                    "punch successful"
                                );
                                let connected_addr = Ipv4Peer {
                                    host: addr.ip().to_string(),
                                    port: addr.port(),
                                };
                                return Ok(ConnectResult {
                                    remote_public_key: nw_result.remote_public_key,
                                    server_address: connected_addr.clone(),
                                    client_address: connected_addr,
                                    is_relayed: true,
                                    noise: nw_result.clone(),
                                    local_stream_id,
                                    remote_udx: remote_payload.udx.clone(),
                                    udx_socket: Some(socket),
                                });
                            }
                            Some(HolepunchEvent::Aborted) | None => {
                                tracing::info!(
                                    target: "peeroxide::_events::holepunch::aborted",
                                    "punch aborted"
                                );
                                return Err(HyperDhtError::HolepunchAborted);
                            }
                        }
                    }
                    _ = punch_fut.as_mut(), if !punch_done => {
                        punch_done = true;
                        tracing::debug!("local punch loop completed, awaiting Connected event");
                    }
                    _ = deadline_sleep.as_mut() => {
                        break true;
                    }
                }
            }
        };

        if timed_out {
            tracing::debug!("punch deadline elapsed");
            puncher.destroy();
            return Err(HyperDhtError::HolepunchFailed);
        }

        unreachable!("holepunch select loop exited without return or timeout");
    }
}

/// One path that reached the peer: the socket to send from, the peer's
/// stream id and address, and for a relay landing the control connection
/// (its abort handle and mux task) to drop once a direct path is confirmed.
struct Landing {
    socket: UdxSocket,
    remote_id: u32,
    addr: SocketAddr,
    relay: Option<(libudx::UdxStreamAbort, JoinHandle<()>)>,
}

/// Node's `rawStream` + `onsocket` for a connection that may land through a
/// relay and directly: one UDX stream both paths share.
struct RacedStream {
    /// Taken by the first landing.
    stream: Mutex<Option<libudx::UdxStream>>,
    remote: libudx::UdxStreamRemote,
    abort: libudx::UdxStreamAbort,
    /// The relay control connection, while the stream runs over the relay.
    relay: Mutex<Option<libudx::UdxStreamAbort>>,
    /// Where relayed packets come from, so a hook firing for them is not
    /// mistaken for a direct landing (Node `isRelay`).
    relay_addr: Mutex<Option<SocketAddr>>,
}

impl RacedStream {
    fn new(stream: libudx::UdxStream) -> Arc<Self> {
        Arc::new(Self {
            remote: stream.remote_handle(),
            abort: stream.abort_handle(),
            stream: Mutex::new(Some(stream)),
            relay: Mutex::new(None),
            relay_addr: Mutex::new(None),
        })
    }

    /// Borrow the stream to arm hooks before any path lands.
    fn with_stream<T>(
        &self,
        f: impl FnOnce(&libudx::UdxStream) -> Result<T, HyperDhtError>,
    ) -> Result<T, HyperDhtError> {
        let guard = self
            .stream
            .lock()
            .map_err(|_| HyperDhtError::ChannelClosed)?;
        let stream = guard
            .as_ref()
            .ok_or_else(|| HyperDhtError::StreamEstablishment("stream already landed".into()))?;
        f(stream)
    }

    fn is_relay_traffic(&self, addr: SocketAddr) -> bool {
        self.relay_addr
            .lock()
            .ok()
            .is_some_and(|relay| *relay == Some(addr))
    }

    /// Node `onsocket` / relay `ondata`: the first landing connects the
    /// stream and yields the connection; a later direct landing moves the
    /// stream off the relay (`changeRemote` + `confirmDirectUpgrade`), a
    /// later relay landing is dropped.
    async fn land(
        &self,
        landing: Landing,
        noise: &NoiseWrapResult,
        is_initiator: bool,
    ) -> Result<Option<PeerConnection>, HyperDhtError> {
        let stream = self
            .stream
            .lock()
            .map_err(|_| HyperDhtError::ChannelClosed)?
            .take();
        let Some(stream) = stream else {
            match landing.relay {
                Some((control, _)) => control.abort(),
                None => self.upgrade(landing),
            }
            return Ok(None);
        };
        let relay_task = landing.relay.map(|(control, mux)| {
            if let Ok(mut relay) = self.relay.lock() {
                *relay = Some(control);
            }
            mux
        });
        stream
            .connect(&landing.socket, landing.remote_id, landing.addr)
            .await?;
        let ss = SecretStream::from_session(
            is_initiator,
            stream.into_async_stream(),
            noise.tx,
            noise.rx,
            noise.handshake_hash,
            noise.remote_public_key,
        )
        .await?;
        Ok(Some(PeerConnection::with_remote_addr(
            ss,
            noise.remote_public_key,
            landing.addr,
            landing.socket,
            relay_task,
        )))
    }

    /// Move a relayed stream onto the direct path and, once the peer is seen
    /// there, drop the relay (Node `changeRemote` + `confirmDirectUpgrade`).
    fn upgrade(&self, landing: Landing) {
        let control = self.relay.lock().ok().and_then(|mut relay| relay.take());
        let Some(control) = control else { return };
        let remote = self.remote.clone();
        tokio::spawn(async move {
            match remote
                .change_remote(&landing.socket, landing.remote_id, landing.addr)
                .await
            {
                Ok(()) => {
                    // An empty UDX message makes the peer observe the direct
                    // path without application data crossing it.
                    let _ = remote.try_send(&[]);
                    let _ = remote.remote_observed().await;
                }
                Err(err) => tracing::debug!(err = %err, "relay to direct upgrade failed"),
            }
            // Either the peer answers on the direct path or the stream is
            // gone; the relay is not needed in both cases.
            control.abort();
        });
    }
}

async fn socket_or_new(
    shared: Option<UdxSocket>,
    runtime: &UdxRuntime,
) -> Result<UdxSocket, HyperDhtError> {
    match shared {
        Some(socket) => Ok(socket),
        None => {
            let socket = runtime.create_socket().await?;
            socket
                .bind("0.0.0.0:0".parse().expect("valid addr"))
                .await?;
            Ok(socket)
        }
    }
}

fn to_socket_addr(peer: &Ipv4Peer) -> Result<SocketAddr, HyperDhtError> {
    let ip = peer.host.parse().map_err(|e| {
        HyperDhtError::StreamEstablishment(format!("invalid address {}: {e}", peer.host))
    })?;
    Ok(SocketAddr::new(ip, peer.port))
}

/// Create a UDX stream, connect it to the remote peer, and wrap with
/// [`SecretStream::from_session`] using the Noise handshake keys.
///
/// Call after [`HyperDhtHandle::connect`] to upgrade a [`ConnectResult`]
/// into an encrypted bidirectional stream.
///
/// A fresh UDX socket bound to an ephemeral port is created for the stream.
/// To reuse an existing socket (Node.js-style single-socket multiplexing),
/// use [`establish_stream_with_socket`] instead.
pub async fn establish_stream(
    result: &ConnectResult,
    runtime: &UdxRuntime,
) -> Result<PeerConnection, HyperDhtError> {
    establish_stream_with_socket(result, runtime, None).await
}

/// Call after [`HyperDhtHandle::connect`] to upgrade a [`ConnectResult`]
/// into an encrypted bidirectional stream, optionally reusing an existing socket.
///
/// When `shared_socket` is `Some`, the stream reuses that socket (matching
/// the Node.js single-socket multiplexing model). When `None`, a fresh socket
/// bound to an ephemeral port is created.
pub async fn establish_stream_with_socket(
    result: &ConnectResult,
    runtime: &UdxRuntime,
    shared_socket: Option<UdxSocket>,
) -> Result<PeerConnection, HyperDhtError> {
    let remote_udx = result
        .remote_udx
        .as_ref()
        .ok_or_else(|| HyperDhtError::StreamEstablishment("no remote UDX info".into()))?;

    let remote_id = u32::try_from(remote_udx.id)
        .map_err(|_| HyperDhtError::StreamEstablishment("remote UDX id out of u32 range".into()))?;

    let addr: SocketAddr = SocketAddr::new(
        result
            .server_address
            .host
            .parse()
            .map_err(|e| HyperDhtError::StreamEstablishment(format!("invalid address: {e}")))?,
        result.server_address.port,
    );

    tracing::debug!(local_id = result.local_stream_id, remote_id, %addr, "establishing UDX stream");
    let socket = if let Some(s) = shared_socket {
        s
    } else {
        let s = runtime.create_socket().await?;
        s.bind("0.0.0.0:0".parse().expect("valid addr")).await?;
        s
    };
    let stream = runtime.create_stream(result.local_stream_id).await?;
    stream.connect(&socket, remote_id, addr).await?;

    let async_stream = stream.into_async_stream();
    let ss = SecretStream::from_session(
        result.noise.is_initiator,
        async_stream,
        result.noise.tx,
        result.noise.rx,
        result.noise.handshake_hash,
        result.noise.remote_public_key,
    )
    .await?;
    tracing::debug!("SecretStream established");

    Ok(PeerConnection {
        remote_public_key: result.remote_public_key,
        stream: ss,
        remote_addr: Some(addr),
        socket,
        _relay_task: None,
    })
}

// ── Server handle (Node `HyperDHT#createServer`) ─────────────────────────────

/// Dial-able address of a listening [`HyperDhtServer`].
///
/// Returned by [`HyperDhtServer::address`], matching Node `server.address()`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerAddress {
    /// Server identity public key.
    pub public_key: [u8; 32],
    /// Host of the socket peers dial. This is the DHT bind host, so it can be
    /// `0.0.0.0` when the node is bound wildcard.
    pub host: String,
    /// Port of the socket peers dial.
    ///
    /// The socket carrying inbound `PEER_HANDSHAKE` requests — the DHT server
    /// socket when the node accepts unsolicited traffic, the ephemeral client
    /// socket when it runs firewalled.
    pub port: u16,
}

enum ServerCommand {
    Listen {
        key_pair: KeyPair,
        reply: oneshot::Sender<()>,
    },
    Suspend(oneshot::Sender<()>),
    Resume(oneshot::Sender<()>),
    Close(oneshot::Sender<()>),
}

/// A node that accepts peer connections for a single key pair.
///
/// Mirrors Node `HyperDHT#createServer()` → `Server`. Build it from a
/// [`HyperDhtHandle`] plus the DHT's server-event stream, then:
///
/// 1. [`listen`](Self::listen) registers `hash(public_key)` in the router so
///    inbound `PEER_HANDSHAKE` requests reach this server
///    (Node `server.listen(keyPair)`).
/// 2. [`accept`](Self::accept) yields established [`PeerConnection`]s — the
///    Rust equivalent of Node's `'connection'` event.
/// 3. [`suspend`](Self::suspend) / [`resume`](Self::resume) gate handshakes
///    without tearing down the DHT (Node parity).
/// 4. [`close`](Self::close) stops listening and unregisters the target.
///
/// Dropping the server without [`close`](Self::close) has the same effect on
/// the router; the accept task is aborted.
pub struct HyperDhtServer {
    dht: HyperDhtHandle,
    commands: mpsc::UnboundedSender<ServerCommand>,
    connections: mpsc::UnboundedReceiver<PeerConnection>,
    target: Option<[u8; 32]>,
    key_pair: Option<KeyPair>,
    address: Option<ServerAddress>,
    task: Option<JoinHandle<()>>,
    announce_task: Option<JoinHandle<()>>,
    suspended: bool,
    route_sender: Option<mpsc::UnboundedSender<ServerEvent>>,
}

impl HyperDhtServer {
    /// Create a server on `dht` and take ownership of its server-event stream.
    ///
    /// `events` is the receiver returned by [`spawn`]. Every server on one DHT
    /// shares that single stream: this server answers only the events whose
    /// target is its own `hash(public_key)` and rejects the rest, so one DHT
    /// can drive several servers only by fanning the events out itself.
    ///
    /// `config.firewall` is the fallback advertised firewall classification,
    /// used when the DHT cannot report its own (see [`listen`](Self::listen),
    /// which supplies the real key pair).
    pub fn new(
        dht: HyperDhtHandle,
        runtime: &UdxRuntime,
        config: ServerConfig,
        events: mpsc::UnboundedReceiver<ServerEvent>,
    ) -> Self {
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (connection_tx, connections) = mpsc::unbounded_channel();

        let task = tokio::spawn(run_hyperdht_server(
            dht.clone(),
            UdxRuntime::shared(runtime.handle()),
            config,
            events,
            command_rx,
            connection_tx,
        ));

        Self {
            dht,
            commands,
            connections,
            target: None,
            key_pair: None,
            address: None,
            task: Some(task),
            announce_task: None,
            suspended: false,
            route_sender: None,
        }
    }

    /// Whether the server is listening (Node `server.listening`).
    pub fn listening(&self) -> bool {
        self.key_pair.is_some()
    }

    /// The listening identity's public key, or `None` before `listen`.
    pub fn public_key(&self) -> Option<[u8; 32]> {
        self.key_pair.as_ref().map(|kp| kp.public_key)
    }

    /// The router target this server answers for (`hash(public_key)`).
    pub fn target(&self) -> Option<[u8; 32]> {
        self.target
    }

    /// The dial-able address, or `None` before `listen` and after `close`
    /// (Node `server.address()`).
    pub fn address(&self) -> Option<ServerAddress> {
        self.address.clone()
    }

    /// Start accepting connections for `key_pair` (Node `server.listen()`).
    pub async fn listen(&mut self, key_pair: &KeyPair) -> Result<(), HyperDhtError> {
        if self.key_pair.is_some() {
            return Err(HyperDhtError::AlreadyListening);
        }

        // Peers dial the socket our handshake replies leave from, so report
        // that one rather than the (possibly unused) bound server port.
        let socket = self
            .dht
            .server_socket()
            .await?
            .ok_or(HyperDhtError::ChannelClosed)?;
        let local = socket.local_addr().await?;

        let (reply, reply_rx) = oneshot::channel();
        self.commands
            .send(ServerCommand::Listen {
                key_pair: key_pair.clone(),
                reply,
            })
            .map_err(|_| HyperDhtError::ServerClosed)?;
        reply_rx.await.map_err(|_| HyperDhtError::ServerClosed)?;

        let target = hash(&key_pair.public_key);
        if let Some(sender) = &self.route_sender {
            let mut routes = self
                .dht
                .server_routes
                .lock()
                .map_err(|_| HyperDhtError::ChannelClosed)?;
            if routes.contains_key(&target) {
                return Err(HyperDhtError::AlreadyListening);
            }
            routes.insert(target, sender.clone());
        }
        self.dht.register_server(&key_pair.public_key);
        self.target = Some(target);
        self.key_pair = Some(key_pair.clone());
        self.address = Some(ServerAddress {
            public_key: key_pair.public_key,
            host: local.ip().to_string(),
            port: local.port(),
        });
        if !self.suspended {
            self.start_announcing().await;
        }
        Ok(())
    }

    /// Wait for the next established connection (Node `'connection'` event).
    ///
    /// Returns `None` once the server is closed or the DHT has shut down.
    pub async fn accept(&mut self) -> Option<PeerConnection> {
        self.connections.recv().await
    }

    /// Detach the connection receiver for an actor that also owns this server's controls.
    /// Subsequent calls to `accept` on this handle return `None`.
    pub fn take_connections(&mut self) -> mpsc::UnboundedReceiver<PeerConnection> {
        let (_, empty) = mpsc::unbounded_channel();
        std::mem::replace(&mut self.connections, empty)
    }

    /// Stop accepting and unannounce this server.
    pub async fn suspend(&mut self) -> Result<(), HyperDhtError> {
        if self.suspended {
            return Ok(());
        }
        self.suspended = true;
        let (reply, reply_rx) = oneshot::channel();
        self.commands
            .send(ServerCommand::Suspend(reply))
            .map_err(|_| HyperDhtError::ServerClosed)?;
        reply_rx.await.map_err(|_| HyperDhtError::ServerClosed)?;
        self.stop_announcing().await;
        Ok(())
    }

    /// Resume answering handshakes (Node `server.resume()`).
    pub async fn resume(&mut self) -> Result<(), HyperDhtError> {
        if !self.suspended {
            return Ok(());
        }
        let (reply, reply_rx) = oneshot::channel();
        self.commands
            .send(ServerCommand::Resume(reply))
            .map_err(|_| HyperDhtError::ServerClosed)?;
        reply_rx.await.map_err(|_| HyperDhtError::ServerClosed)?;
        self.suspended = false;
        self.start_announcing().await;
        Ok(())
    }

    /// Stop listening: unregister the target, end the accept task, and release
    /// buffered connections after they are drained (Node `server.close()`).
    ///
    /// Idempotent — closing an already-closed server is a no-op.
    pub async fn close(&mut self) {
        self.stop_announcing().await;
        self.stop_routing();

        if let Some(task) = self.task.take() {
            let (reply, reply_rx) = oneshot::channel();
            if self.commands.send(ServerCommand::Close(reply)).is_ok() {
                // The loop breaks after acknowledging; the abort is a safety
                // net for a loop stuck in a DHT round-trip.
                let _ = reply_rx.await;
            }
            task.abort();
        }
        self.connections.close();
    }

    async fn start_announcing(&mut self) {
        let (Some(target), Some(key_pair)) = (self.target, self.key_pair.clone()) else {
            return;
        };
        let dht = self.dht.clone();
        let first = dht.announce(target, &key_pair, &[]).await;
        let empty = first
            .as_ref()
            .map_or(true, |result| result.closest_nodes.is_empty());
        // HyperDHT must refresh server records before they expire.
        self.announce_task = Some(tokio::spawn(async move {
            let mut empty = empty;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(if empty { 3 } else { 300 }))
                    .await;
                empty = dht
                    .announce(target, &key_pair, &[])
                    .await
                    .map_or(true, |result| result.closest_nodes.is_empty());
            }
        }));
    }

    async fn stop_announcing(&mut self) {
        if let Some(task) = self.announce_task.take() {
            task.abort();
            let _ = task.await;
            if let (Some(target), Some(key_pair)) = (self.target, &self.key_pair) {
                let _ = self.dht.unannounce(target, key_pair).await;
            }
        }
    }

    /// Forget the listening identity and stop routing handshakes to it.
    fn stop_routing(&mut self) {
        if let Some(target) = self.target.take() {
            if self.route_sender.is_some() {
                if let Ok(mut routes) = self.dht.server_routes.lock() {
                    routes.remove(&target);
                }
            }
            self.dht.unregister_server(&target);
        }
        self.key_pair = None;
        self.address = None;
    }
}

impl Drop for HyperDhtServer {
    fn drop(&mut self) {
        if let Some(task) = self.announce_task.take() {
            task.abort();
        }
        self.stop_routing();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl HyperDhtHandle {
    /// Create a [`HyperDhtServer`] on this node (Node
    /// `HyperDHT#createServer()`).
    ///
    /// `events` is the server-event receiver returned by [`spawn`]; the DHT
    /// only has one, so the first server to claim it sees every handshake.
    pub fn create_server(
        &self,
        runtime: &UdxRuntime,
        config: ServerConfig,
        events: mpsc::UnboundedReceiver<ServerEvent>,
    ) -> HyperDhtServer {
        HyperDhtServer::new(self.clone(), runtime, config, events)
    }

    /// Create a server sharing this DHT with other servers.
    pub fn create_shared_server(
        &self,
        runtime: &UdxRuntime,
        config: ServerConfig,
    ) -> HyperDhtServer {
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut server = HyperDhtServer::new(self.clone(), runtime, config, receiver);
        server.route_sender = Some(sender);
        server
    }
}

/// One accepted handshake waiting for its passive holepunch to land.
///
/// Mirrors Node `lib/server.js::_addHandshake`'s `hs`: the puncher, the
/// SecurePayload and the listening UDX stream all persist across
/// PEER_HOLEPUNCH rounds so the same socket and NAT mapping keep probing.
struct ServerPassivePunch {
    payload: SecurePayload,
    /// Moved into the probe task on the first round that asks us to punch.
    puncher: Option<Holepuncher>,
    punch_task: Option<JoinHandle<()>>,
    /// The puncher's primary socket, kept after `puncher` is moved out.
    socket: UdxSocket,
    /// Socket our handshake and holepunch replies leave from: the puncher
    /// socket when the client is on another host, so the relay tags our
    /// replies with the address the client must punch (Node
    /// `replyFromPuncher`); `None` (the DHT socket) for a same-host client,
    /// whose LAN shortcut dials the DHT socket we advertised.
    reply_socket: Option<UdxSocket>,
    raced: Arc<RacedStream>,
    remote_id: u32,
    noise_result: NoiseWrapResult,
    round: u64,
    addresses: Vec<Ipv4Peer>,
    has_relay: bool,
    abort: tokio::task::JoinHandle<()>,
}

impl Drop for ServerPassivePunch {
    fn drop(&mut self) {
        self.abort.abort();
        if let Some(mut puncher) = self.puncher.take() {
            puncher.destroy();
        }
        if let Some(task) = self.punch_task.take() {
            task.abort();
        }
    }
}

struct ServerProbe(Option<Holepuncher>);

impl Drop for ServerProbe {
    fn drop(&mut self) {
        if let Some(mut puncher) = self.0.take() {
            puncher.destroy();
        }
    }
}

enum ServerPunchEvent {
    /// The firewall hook accepted a packet: the punch landed at `addr` on
    /// `socket` (the puncher socket, or the DHT socket when the client took
    /// hyperdht's LAN shortcut or dialled us directly).
    Punched {
        id: u64,
        addr: std::net::SocketAddr,
        socket: UdxSocket,
    },
    /// The 10 s handshake window elapsed.
    Abort { id: u64 },
    /// A handshake task finished: the reply every copy of the handshake gets
    /// (`None` rejects), and the passive punch it staged.
    Handshaken {
        noise: Vec<u8>,
        reply: Option<(Vec<u8>, Option<UdxSocket>)>,
        punch: Option<(u64, Box<ServerPassivePunch>)>,
        relay: Option<Box<RelayStart>>,
        epoch: u64,
    },
}

/// Stage the passive side of a holepunch for one accepted handshake
/// (Node `setupHolepuncher` plus the listening `rawStream` on the puncher's
/// socket).
#[allow(clippy::too_many_arguments)]
async fn stage_server_punch(
    runtime: &UdxRuntime,
    dht: &DhtHandle,
    dht_socket: Option<&UdxSocket>,
    noise_result: &NoiseWrapResult,
    client_host: &str,
    remote_firewall: u64,
    id: u64,
    raced: Arc<RacedStream>,
    remote_id: u32,
    events: &mpsc::UnboundedSender<ServerPunchEvent>,
) -> Result<ServerPassivePunch, HyperDhtError> {
    let pool = SocketPool::new("0.0.0.0".into());
    // The passive side's punch-landed signal is the firewall hook below, not
    // the puncher's Connected event.
    let (hp_tx, _hp_rx) = mpsc::unbounded_channel::<HolepunchEvent>();
    let puncher = Holepuncher::new(&pool, runtime, true, false, remote_firewall, hp_tx)
        .await
        .map_err(|e| HyperDhtError::StreamEstablishment(format!("puncher setup: {e}")))?;
    let mut probe = ServerProbe(Some(puncher));
    let puncher = probe.0.as_mut().unwrap();
    // Seeds the NAT classifier from this socket before `punch()` can run.
    puncher.auto_sample(dht).await;

    let socket = puncher
        .primary_socket()
        .ok_or_else(|| HyperDhtError::StreamEstablishment("puncher has no primary socket".into()))?
        .socket
        .clone();
    let puncher_port = socket
        .local_addr()
        .await
        .map_err(|e| HyperDhtError::StreamEstablishment(format!("puncher local_addr: {e}")))?
        .port();

    let punched = events.clone();
    let pending = Arc::downgrade(&raced);
    raced.with_stream(|stream| {
        stream.set_firewall_hook(&socket, remote_id, move |socket, port, ip| {
            let addr = SocketAddr::new(ip, port);
            if pending
                .upgrade()
                .is_none_or(|raced| raced.is_relay_traffic(addr))
            {
                return true;
            }
            let _ = punched.send(ServerPunchEvent::Punched {
                id,
                addr,
                socket: socket.clone(),
            });
            true
        })?;
        // The client may skip the punch and dial the address we advertised
        // (the DHT socket): hyperdht's same-host LAN shortcut, or a client
        // told we are open. Node's raw stream hears every socket of its UDX
        // instance.
        if let Some(dht_socket) = dht_socket {
            stream.listen_on(dht_socket)?;
        }
        Ok(())
    })?;
    let timed_out = events.clone();
    // Expire unused handshake state after Node's ten-second acceptance window.
    let abort = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        let _ = timed_out.send(ServerPunchEvent::Abort { id });
    });

    // Advertise the puncher's reachable addresses (Node
    // `holepuncher.js:221-227`), seeded before `punch()` can move the puncher.
    let addresses = puncher.punch_addresses(puncher_port);
    let same_host = addresses.iter().any(|a| a.host == client_host);

    Ok(ServerPassivePunch {
        payload: SecurePayload::new(noise_result.holepunch_secret),
        puncher: probe.0.take(),
        punch_task: None,
        reply_socket: (!same_host).then(|| socket.clone()),
        socket,
        raced,
        remote_id,
        noise_result: noise_result.clone(),
        round: 0,
        addresses,
        has_relay: false,
        abort,
    })
}

/// Answer one PEER_HOLEPUNCH round for a staged handshake
/// (Node `Server#_onpeerholepunch`).
async fn server_punch_round(
    runtime: &UdxRuntime,
    state: &mut ServerPassivePunch,
    msg: &HolepunchMessage,
    peer_address: &Ipv4Peer,
    server_firewall: u64,
) -> Option<ServerReply> {
    let remote_hp = state.payload.decrypt(&msg.payload).ok()?;

    // Node `_abort(h)`: a client that gave up stops our puncher and gets an
    // ABORTED reply from the DHT socket.
    let aborted = remote_hp.error != ERROR_NONE;
    if aborted {
        if let Some(task) = state.punch_task.take() {
            task.abort();
        }
        if let Some(mut puncher) = state.puncher.take() {
            puncher.destroy();
        }
    }

    if let Some(puncher) = state.puncher.as_mut() {
        let addrs = remote_hp.addresses.clone().unwrap_or_default();
        puncher.update_remote(
            remote_hp.punching,
            remote_hp.firewall,
            &addrs,
            Some(peer_address.host.as_str()),
        );
        state.addresses = puncher.punch_addresses(
            state
                .socket
                .local_addr()
                .await
                .ok()
                .map(|a| a.port())
                .unwrap_or(0),
        );
    }

    if remote_hp.round > state.round {
        state.round = remote_hp.round;
    }

    let try_later = remote_hp.punching
        && state
            .puncher
            .as_mut()
            .is_some_and(|puncher| !puncher.reserve_random_punch());
    let abort_for_budget = try_later && !state.has_relay;
    if abort_for_budget {
        if let Some(mut puncher) = state.puncher.take() {
            puncher.destroy();
        }
        state.raced.abort.abort();
        state.reply_socket = None;
        state.socket.shutdown().await;
    }
    // `punch()` owns the puncher for the rest of the exchange; later rounds
    // only rebuild the reply, as Node does once its probe loop is running.
    if remote_hp.punching && !try_later && state.puncher.is_some() {
        if let Some(puncher) = state.puncher.take() {
            let runtime = UdxRuntime::shared(runtime.handle());
            state.punch_task = Some(tokio::spawn(async move {
                let mut probe = ServerProbe(Some(puncher));
                let pool = SocketPool::new("0.0.0.0".into());
                probe.0.as_mut().unwrap().punch(&pool, &runtime).await;
            }));
        }
    }

    let reply = if aborted || abort_for_budget {
        HolepunchPayload {
            error: if abort_for_budget {
                ERROR_TRY_LATER
            } else {
                ERROR_ABORTED
            },
            firewall: FIREWALL_UNKNOWN,
            round: remote_hp.round,
            connected: false,
            punching: false,
            addresses: None,
            remote_address: None,
            token: None,
            remote_token: None,
        }
    } else {
        HolepunchPayload {
            error: if try_later {
                ERROR_TRY_LATER
            } else {
                ERROR_NONE
            },
            firewall: server_firewall,
            round: remote_hp.round,
            connected: false,
            punching: remote_hp.punching && !try_later,
            addresses: Some(state.addresses.clone()),
            remote_address: Some(peer_address.clone()),
            token: Some(state.payload.token(&peer_address.host)),
            remote_token: remote_hp.token,
        }
    };
    let encrypted = state.payload.encrypt(&reply).ok()?;
    let reply_mode = match msg.mode {
        MODE_FROM_RELAY | MODE_FROM_SECOND_RELAY => MODE_FROM_SERVER,
        _ => MODE_REPLY,
    };
    let value = encode_holepunch_msg_to_bytes(&HolepunchMessage {
        mode: reply_mode,
        id: msg.id,
        payload: encrypted,
        peer_address: Some(peer_address.clone()),
    })
    .ok()?;
    let socket = if aborted || abort_for_budget {
        None
    } else {
        state.reply_socket.clone()
    };
    Some(ServerReply { value, socket })
}

/// Build the reply to one copy of a handshake from the cached Noise reply.
fn server_reply(
    mode: u64,
    peer_address: Option<Ipv4Peer>,
    noise: Vec<u8>,
    socket: Option<UdxSocket>,
) -> Option<ServerReply> {
    let value = encode_server_handshake_reply(mode, peer_address, noise)?;
    Some(ServerReply { value, socket })
}

/// Preserve the swarm's bounded reply cache when its server uses this accept loop.
struct ServerReplyCache {
    ttl: std::time::Duration,
    capacity: usize,
    entries: std::collections::HashMap<[u8; 32], (Vec<u8>, Option<UdxSocket>)>,
    order: std::collections::VecDeque<(tokio::time::Instant, [u8; 32])>,
}

impl ServerReplyCache {
    fn new(ttl: std::time::Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            entries: Default::default(),
            order: Default::default(),
        }
    }

    fn prune(&mut self) {
        while self
            .order
            .front()
            .is_some_and(|(at, _)| at.elapsed() >= self.ttl)
        {
            let (_, key) = self.order.pop_front().unwrap();
            self.entries.remove(&key);
        }
        if self.entries.is_empty() {
            self.clear();
        }
    }

    fn clear(&mut self) {
        self.entries = Default::default();
        self.order = Default::default();
    }

    fn get(&mut self, noise: &[u8]) -> Option<(Vec<u8>, Option<UdxSocket>)> {
        self.prune();
        self.entries.get(&hash(noise)).cloned()
    }

    fn insert(&mut self, noise: &[u8], reply: Vec<u8>, socket: Option<UdxSocket>) {
        self.prune();
        let key = hash(noise);
        if self.capacity == 0 || self.entries.contains_key(&key) {
            return;
        }
        while self.entries.len() >= self.capacity {
            let (_, oldest) = self.order.pop_front().unwrap();
            self.entries.remove(&oldest);
        }
        self.entries.insert(key, (reply, socket));
        self.order.push_back((tokio::time::Instant::now(), key));
    }
}

/// Accept loop behind [`HyperDhtServer`].
///
/// Owns the DHT's server-event stream, so it also answers holepunches for the
/// listening key pair; established connections go to the server's `accept()`.
async fn run_hyperdht_server(
    dht: HyperDhtHandle,
    runtime: UdxRuntime,
    mut config: ServerConfig,
    mut events: mpsc::UnboundedReceiver<ServerEvent>,
    mut commands: mpsc::UnboundedReceiver<ServerCommand>,
    connection_tx: mpsc::UnboundedSender<PeerConnection>,
) {
    /// Node `server._connects`: one handshake reaches us through several
    /// relays; every copy gets the reply (and stream id) of the first.
    const HANDSHAKE_CLEAR_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
    type Waiter = (u64, Option<Ipv4Peer>, oneshot::Sender<Option<ServerReply>>);
    let mut replies = ServerReplyCache::new(HANDSHAKE_CLEAR_WAIT, 1024);
    // Copies of a handshake that is still being answered wait for its reply.
    let mut pending: std::collections::HashMap<Vec<u8>, Vec<Waiter>> =
        std::collections::HashMap::new();
    let mut punches: std::collections::HashMap<u64, Box<ServerPassivePunch>> =
        std::collections::HashMap::new();
    let (punch_tx, mut punch_rx) = mpsc::unbounded_channel::<ServerPunchEvent>();
    let mut target: Option<[u8; 32]> = None;
    let mut suspended = false;
    let mut next_holepunch_id: u64 = 0;
    let mut accepts = tokio::task::JoinSet::new();
    let mut server_generation = 0u64;
    // Cached replies must expire while idle, as the old swarm server cache did.
    let mut reply_sweep = tokio::time::interval(HANDSHAKE_CLEAR_WAIT);
    reply_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(ServerCommand::Listen { key_pair, reply }) => {
                    target = Some(hash(&key_pair.public_key));
                    config.key_pair = key_pair;
                    let _ = reply.send(());
                }
                Some(ServerCommand::Suspend(reply)) => {
                    suspended = true;
                    server_generation = server_generation.wrapping_add(1);
                    accepts.abort_all();
                    while accepts.join_next().await.is_some() {}
                    pending.clear();
                    replies.clear();
                    for (_, mut punch) in punches.drain() {
                        punch.abort.abort();
                        if let Some(mut puncher) = punch.puncher.take() {
                            puncher.destroy();
                        }
                    }
                    let _ = reply.send(());
                }
                Some(ServerCommand::Resume(reply)) => {
                    suspended = false;
                    let _ = reply.send(());
                }
                Some(ServerCommand::Close(reply)) => {
                    let _ = reply.send(());
                    break;
                }
                None => break,
            },
            event = events.recv() => match event {
                Some(ServerEvent::PeerHandshake {
                    msg,
                    from,
                    peer_address,
                    target: event_target,
                    reply_tx,
                }) => {
                    replies.prune();
                    if suspended || target.is_none() || event_target != target {
                        let _ = reply_tx.send(None);
                    } else if let Some((noise, socket)) = replies.get(&msg.noise) {
                        let _ = reply_tx.send(server_reply(msg.mode, peer_address, noise, socket));
                    } else if let Some(waiters) = pending.get_mut(&msg.noise) {
                        waiters.push((msg.mode, peer_address, reply_tx));
                    } else {
                        pending.insert(msg.noise.clone(), vec![(msg.mode, peer_address.clone(), reply_tx)]);
                        let holepunch_id = next_holepunch_id;
                        next_holepunch_id = next_holepunch_id.wrapping_add(1);
                        let dht = dht.clone();
                        let runtime = UdxRuntime::shared(runtime.handle());
                        let config = config.clone();
                        let punch_tx = punch_tx.clone();
                        let connection_tx = connection_tx.clone();
                        // Node answers every handshake as its own promise
                        // (`_addHandshake`): staging a punch samples the NAT
                        // and must not hold up the other clients.
                        let epoch = server_generation;
                        accepts.spawn(async move {
                            let accepted = accept_server_handshake(
                                &dht,
                                &runtime,
                                &config,
                                holepunch_id,
                                &punch_tx,
                                &msg,
                                &from,
                                peer_address.as_ref(),
                            )
                            .await;
                            let (reply, punch, accept, relay) = match accepted {
                                Some(a) => (Some((a.noise_reply, a.reply_socket)), a.punch, a.accept, a.relay),
                                None => (None, None, None, None),
                            };
                            let _ = punch_tx.send(ServerPunchEvent::Handshaken { noise: msg.noise, reply, punch, relay, epoch });
                            if let Some(path) = accept {
                                match server_accept_connection(&dht, path).await {
                                    Ok(Some(connection)) => {
                                        let _ = connection_tx.send(connection);
                                    }
                                    Ok(None) => {}
                                    Err(err) => tracing::debug!(err = %err, "server: connection setup failed"),
                                }
                            }
                        });
                    }
                }
                Some(ServerEvent::PeerHolepunch {
                    msg,
                    peer_address,
                    target: event_target,
                    reply_tx,
                    ..
                }) => {
                    let reply = if suspended || event_target != target {
                        None
                    } else {
                        let firewall = dht.firewalled().await.unwrap_or(config.firewall);
                        match punches.get_mut(&msg.id) {
                            Some(state) => {
                                server_punch_round(
                                    &runtime,
                                    state,
                                    &msg,
                                    &peer_address,
                                    firewall,
                                )
                                .await
                            }
                            None => None,
                        }
                    };
                    let _ = reply_tx.send(reply);
                }
                None => break,
            },
            Some(event) = punch_rx.recv() => match event {
                ServerPunchEvent::Handshaken { noise, reply, punch, relay, epoch } => {
                    if suspended || epoch != server_generation || !pending.contains_key(&noise) {
                        continue;
                    }
                    if let Some((id, punch)) = punch { punches.insert(id, punch); }
                    if let Some((noise_reply, socket)) = &reply {
                        replies.insert(
                            &noise,
                            noise_reply.clone(), socket.clone(),
                        );
                    }
                    for (mode, peer_address, reply_tx) in pending.remove(&noise).unwrap_or_default() {
                        let _ = reply_tx.send(reply.as_ref().and_then(|(noise_reply, socket)| {
                            server_reply(mode, peer_address, noise_reply.clone(), socket.clone())
                        }));
                    }
                    if let Some(relay) = relay {
                        accepts.spawn(server_relay_connection(
                            dht.clone(), UdxRuntime::shared(runtime.handle()),
                            config.key_pair.clone(), *relay, connection_tx.clone(),
                        ));
                    }
                }
                ServerPunchEvent::Punched { id, addr, socket } => {
                    // Node `isRelay`: the relay's packets reach the same
                    // hook and are not a punch.
                    if punches.get(&id).is_none_or(|punch| punch.raced.is_relay_traffic(addr)) {
                        continue;
                    }
                    let Some(punch) = punches.remove(&id) else { continue };
                    punch.abort.abort();
                    let landing = Landing { socket, remote_id: punch.remote_id, addr, relay: None };
                    match punch.raced.land(landing, &punch.noise_result, false).await {
                        Ok(Some(connection)) => {
                            let _ = connection_tx.send(connection);
                        }
                        Ok(None) => {}
                        Err(err) => tracing::debug!(err = %err, "server: holepunched stream setup failed"),
                    }
                }
                ServerPunchEvent::Abort { id } => {
                    if let Some(mut punch) = punches.remove(&id) {
                        punch.abort.abort();
                        if let Some(mut puncher) = punch.puncher.take() {
                            puncher.destroy();
                        }
                    }
                }
            },
            _ = accepts.join_next(), if !accepts.is_empty() => {}
            _ = reply_sweep.tick() => replies.prune(),
        }
    }
}

/// What a handshake task sets up once its reply is out.
struct AcceptPath {
    noise_result: NoiseWrapResult,
    raced: Arc<RacedStream>,
    remote_id: u32,
    client: Ipv4Peer,
    /// Dial the client, else wait on the DHT socket for it to dial us.
    dial: bool,
    observed: Option<mpsc::UnboundedReceiver<(UdxSocket, SocketAddr)>>,
}

/// The relay side of an accepted handshake (Node `_relayConnection`).
struct RelayStart {
    raced: Arc<RacedStream>,
    noise_result: NoiseWrapResult,
    public_key: [u8; 32],
    token: [u8; 32],
    initiator: bool,
    hints: Vec<Ipv4Peer>,
    local_stream_id: u32,
}

/// An accepted handshake: the Noise reply, the socket it leaves from, and
/// the stream setup that follows it.
struct AcceptedHandshake {
    noise_reply: Vec<u8>,
    reply_socket: Option<UdxSocket>,
    /// A staged passive punch, for the accept loop's map.
    punch: Option<(u64, Box<ServerPassivePunch>)>,
    /// A client we dial or wait for, run by the handshake task itself.
    accept: Option<AcceptPath>,
    relay: Option<Box<RelayStart>>,
}

/// Pair through the relay beside the direct path; a landing that comes first
/// is handed out, a later one only moves or drops the stream.
async fn server_relay_connection(
    dht: HyperDhtHandle,
    runtime: UdxRuntime,
    key_pair: KeyPair,
    relay: RelayStart,
    connection_tx: mpsc::UnboundedSender<PeerConnection>,
) {
    let landing = dht
        .relay_path(
            &key_pair,
            relay.public_key,
            &relay.hints,
            relay.initiator,
            &relay.token,
            relay.local_stream_id,
            &runtime,
            &relay.raced,
        )
        .await;
    let landed = match landing {
        Ok(landing) => relay.raced.land(landing, &relay.noise_result, false).await,
        Err(err) => Err(err),
    };
    match landed {
        Ok(Some(connection)) => {
            let _ = connection_tx.send(connection);
        }
        Ok(None) => {}
        Err(err) => tracing::debug!(err = %err, "server: relay connection failed"),
    }
}

/// Answer one inbound `PEER_HANDSHAKE` as a server: complete the Noise IK
/// handshake, advertise the accept socket, and describe the stream setup that
/// produces the [`PeerConnection`] for [`HyperDhtServer::accept`].
///
/// Mirrors Node `lib/server.js::_addHandshake`: a rejected or suspended
/// handshake yields no reply (`None`), which the RPC layer sends as an empty
/// REPLY; an accepted one replies with our UDX stream id before the stream is
/// established, because the client dials that id as soon as the reply lands.
#[allow(clippy::too_many_arguments)]
async fn accept_server_handshake(
    dht: &HyperDhtHandle,
    runtime: &UdxRuntime,
    config: &ServerConfig,
    holepunch_id: u64,
    punch_tx: &mpsc::UnboundedSender<ServerPunchEvent>,
    msg: &HandshakeMessage,
    from: &Ipv4Peer,
    peer_address: Option<&Ipv4Peer>,
) -> Option<AcceptedHandshake> {
    let mut nw = NoiseWrap::new_responder(config.key_pair.to_noise_keypair());
    let remote_payload = nw.recv(&msg.noise).ok()?;

    if remote_payload.error != 0 || remote_payload.version != 1 {
        return None;
    }

    let socket = dht.server_socket().await.ok().flatten()?;
    let port = socket.local_addr().await.ok()?.port();
    let firewall = dht.firewalled().await.unwrap_or(config.firewall);

    let (local_stream_id, local_stream) = runtime.create_random_stream().await.ok()?;
    dht.track_raw_stream(local_stream.abort_handle());
    let addresses4 = dht.noise_addresses4(port).await;

    // Node advertises a holepunch session only while it cannot be dialled
    // directly (`ourRemoteAddr ? null : { id, relays }`).
    let holepunch = (firewall != FIREWALL_OPEN).then(|| HolepunchInfo {
        id: holepunch_id,
        relays: dht.current_relays(),
    });

    // Node `server.js:381,689`: our relay (we initiate the pairing with a
    // fresh token) beats the client's.
    let ours = config.relay_through.filter(|_| {
        !config.relay_randomized_only || firewall == crate::hyperdht_messages::FIREWALL_RANDOM
    });
    let relay = match (ours, &remote_payload.relay_through) {
        (Some(public_key), _) => Some((public_key, random::<[u8; 32]>(), true)),
        (None, Some(theirs)) => Some((theirs.public_key, theirs.token, false)),
        (None, None) => None,
    };

    let reply_payload = NoisePayload {
        version: 1,
        error: ERROR_NONE,
        firewall,
        holepunch,
        addresses4,
        addresses6: vec![],
        udx: Some(UdxInfo {
            version: 1,
            reusable_socket: true,
            id: u64::from(local_stream_id),
            seq: 0,
        }),
        secret_stream: Some(SecretStreamInfo { version: 1 }),
        relay_through: relay
            .filter(|(_, _, ours)| *ours)
            .map(|(public_key, token, _)| RelayThroughInfo {
                version: 1,
                public_key,
                token,
            }),
        relay_addresses: (ours.is_some() && !config.relay_addresses.is_empty())
            .then(|| config.relay_addresses.clone()),
    };

    let noise_reply = nw.send(&reply_payload).ok()?;
    let noise_result = nw.finalize().ok()?;

    let mut accepted = AcceptedHandshake {
        noise_reply,
        reply_socket: None,
        punch: None,
        accept: None,
        relay: None,
    };
    let Some(remote_udx) = remote_payload.udx.clone() else {
        return Some(accepted);
    };
    let remote_id = u32::try_from(remote_udx.id).ok()?;
    let raced = RacedStream::new(local_stream);
    // Node dials a client that reached us directly or reports itself open
    // (`hs.onsocket`); an open server told a firewalled client it is open
    // and waits on the DHT socket for its dial (`prepunching`). A client we
    // dial needs no relay (`server.js:420-429`); for the rest the relay
    // runs beside the punch from here on (`_relayConnection`).
    let dial = peer_address.is_none() || remote_payload.firewall == FIREWALL_OPEN;

    // A relayed handshake from a firewalled client cannot be dialled: a
    // firewalled server stages the passive punch now and advertises its
    // stream id, exactly as Node's `_addHandshake` does before replying.
    let passive = peer_address.is_some()
        && remote_payload.firewall != FIREWALL_OPEN
        && firewall != FIREWALL_OPEN;
    if passive {
        match stage_server_punch(
            runtime,
            dht.dht(),
            Some(&socket),
            &noise_result,
            &peer_address?.host,
            remote_payload.firewall,
            holepunch_id,
            Arc::clone(&raced),
            remote_id,
            punch_tx,
        )
        .await
        {
            Ok(mut punch) => {
                punch.has_relay = relay.is_some();
                accepted.reply_socket = punch.reply_socket.clone();
                accepted.punch = Some((holepunch_id, Box::new(punch)));
            }
            Err(err) => {
                tracing::debug!(err = %err, "server: passive holepunch setup failed");
                return None;
            }
        }
    } else {
        let observed = if dial {
            None
        } else {
            let (seen_tx, seen_rx) = mpsc::unbounded_channel();
            let pending = Arc::downgrade(&raced);
            raced
                .with_stream(|stream| {
                    stream.set_firewall_hook(&socket, remote_id, move |socket, port, ip| {
                        let addr = SocketAddr::new(ip, port);
                        if pending
                            .upgrade()
                            .is_some_and(|raced| !raced.is_relay_traffic(addr))
                        {
                            let _ = seen_tx.send((socket.clone(), addr));
                        }
                        true
                    })?;
                    Ok(())
                })
                .ok()?;
            Some(seen_rx)
        };
        accepted.accept = Some(AcceptPath {
            noise_result: noise_result.clone(),
            raced: Arc::clone(&raced),
            remote_id,
            client: peer_address.cloned().unwrap_or_else(|| from.clone()),
            dial,
            observed,
        });
    }

    accepted.relay = relay
        .filter(|_| !dial)
        .map(|(public_key, token, initiator)| {
            Box::new(RelayStart {
                raced: Arc::clone(&raced),
                noise_result: noise_result.clone(),
                public_key,
                token,
                initiator,
                local_stream_id,
                hints: if initiator {
                    config.relay_addresses.clone()
                } else {
                    remote_payload.relay_addresses.clone().unwrap_or_default()
                },
            })
        });
    Some(accepted)
}

/// Establish the server side of an accepted handshake: pair the shared
/// stream with the client's (dial when `dial`, else wait on a firewall hook
/// on the DHT socket) and wrap it in a [`SecretStream`]. `None` when the
/// relay landed first and the direct path only moved the stream.
async fn server_accept_connection(
    dht: &HyperDhtHandle,
    mut path: AcceptPath,
) -> Result<Option<PeerConnection>, HyperDhtError> {
    /// Node drops unused handshake state after `handshakeClearWait`; matching
    /// that keeps a stalled peer from pinning a task and a stream forever.
    const ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    let socket = dht
        .server_socket()
        .await?
        .ok_or_else(|| HyperDhtError::StreamEstablishment("no DHT server socket".into()))?;

    let (socket, addr) = if path.dial {
        (socket, to_socket_addr(&path.client)?)
    } else {
        let mut seen_rx = path.observed.take().ok_or(HyperDhtError::ChannelClosed)?;
        let wait = async {
            loop {
                let Some((socket, addr)) = seen_rx.recv().await else {
                    return Err(HyperDhtError::StreamEstablishment("stream closed".into()));
                };
                if !path.raced.is_relay_traffic(addr) {
                    return Ok((socket, addr));
                }
            }
        };
        tokio::time::timeout(ACCEPT_TIMEOUT, wait)
            .await
            .map_err(|_| HyperDhtError::StreamEstablishment("accept timed out".into()))??
    };
    let landing = Landing {
        socket,
        remote_id: path.remote_id,
        addr,
        relay: None,
    };
    let landed = path.raced.land(landing, &path.noise_result, false);
    tokio::time::timeout(ACCEPT_TIMEOUT, landed)
        .await
        .map_err(|_| HyperDhtError::StreamEstablishment("accept timed out".into()))?
}

/// Encode a handshake reply, choosing the routing mode from the inbound one.
///
/// `peer_address` is echoed only on the relayed path (`FROM_RELAY` /
/// `FROM_SECOND_RELAY` → `FROM_SERVER`); a direct reply stays `MODE_REPLY`
/// with no peer address, which is how the client distinguishes a direct
/// connection from a relayed one.
fn encode_server_handshake_reply(
    inbound_mode: u64,
    peer_address: Option<Ipv4Peer>,
    noise: Vec<u8>,
) -> Option<Vec<u8>> {
    let (mode, peer_address) = match inbound_mode {
        MODE_FROM_RELAY | MODE_FROM_SECOND_RELAY => (MODE_FROM_SERVER, peer_address),
        _ => (MODE_REPLY, None),
    };

    encode_handshake_to_bytes(&HandshakeMessage {
        mode,
        noise,
        peer_address,
        relay_address: None,
    })
    .ok()
}

/// Build the reply to a server-side `PEER_HOLEPUNCH` and start punching when
/// the remote asked for it. Shared by [`run_server`] and the
/// [`HyperDhtServer`] accept loop.
async fn passive_holepunch_reply(
    dht: &DhtHandle,
    runtime: &UdxRuntime,
    pool: &SocketPool,
    firewall: u64,
    msg: &HolepunchMessage,
    peer_address: &Ipv4Peer,
    secret: [u8; 32],
) -> Option<Vec<u8>> {
    let (event_tx, _event_rx) = mpsc::unbounded_channel();
    let result = build_passive_holepunch_reply(
        firewall,
        pool,
        runtime,
        peer_address,
        secret,
        &msg.payload,
        msg.id,
        event_tx,
        Some(dht),
    )
    .await
    .ok()?;

    if result.remote_hp.punching && !result.puncher.destroyed {
        let pool_clone = SocketPool::new("0.0.0.0".into());
        let mut puncher = result.puncher;
        tokio::spawn(async move {
            if let Ok(rt) = UdxRuntime::new() {
                puncher.punch(&pool_clone, &rt).await;
            }
        });
    }

    Some(result.reply_bytes)
}

// ── Server-side event handler ─────────────────────────────────────────────────

/// Per-server state for pending handshake and holepunch exchanges.
pub struct ServerSession {
    /// Cached holepunch secrets indexed by remote public key.
    holepunch_secrets: std::collections::HashMap<[u8; 32], ServerPeerState>,
}

#[allow(dead_code)]
struct ServerPeerState {
    holepunch_secret: [u8; 32],
    remote_public_key: [u8; 32],
    client_address: Ipv4Peer,
    local_stream_id: u32,
    remote_udx: Option<UdxInfo>,
}

/// Run the server-side request loop for peer handshakes and holepunches.
pub async fn run_server(
    mut event_rx: mpsc::UnboundedReceiver<ServerEvent>,
    config: ServerConfig,
    runtime: UdxRuntime,
    dht: DhtHandle,
) {
    let mut session = ServerSession {
        holepunch_secrets: std::collections::HashMap::new(),
    };
    let pool = SocketPool::new("0.0.0.0".into());

    while let Some(event) = event_rx.recv().await {
        match event {
            ServerEvent::PeerHandshake {
                msg,
                from,
                peer_address: _,
                target,
                reply_tx,
            } => {
                let reply =
                    handle_server_handshake(&config, &mut session, msg, &from, target.as_ref());
                let _ = reply_tx.send(reply.map(Into::into));
            }
            ServerEvent::PeerHolepunch {
                msg,
                from: _,
                peer_address,
                target: _,
                reply_tx,
            } => {
                let holepunch_secret = session.holepunch_secrets.values().find_map(|state| {
                    let sp = SecurePayload::new(state.holepunch_secret);
                    if sp.decrypt(&msg.payload).is_ok() {
                        Some(state.holepunch_secret)
                    } else {
                        None
                    }
                });
                let reply = match holepunch_secret {
                    Some(secret) => {
                        passive_holepunch_reply(
                            &dht,
                            &runtime,
                            &pool,
                            config.firewall,
                            &msg,
                            &peer_address,
                            secret,
                        )
                        .await
                    }
                    None => None,
                };
                let _ = reply_tx.send(reply.map(Into::into));
            }
        }
    }
}

fn handle_server_handshake(
    config: &ServerConfig,
    session: &mut ServerSession,
    msg: HandshakeMessage,
    from: &Ipv4Peer,
    _target: Option<&NodeId>,
) -> Option<Vec<u8>> {
    let mut nw = NoiseWrap::new_responder(config.key_pair.to_noise_keypair());

    let remote_payload = match nw.recv(&msg.noise) {
        Ok(p) => p,
        Err(_) => return None,
    };

    if remote_payload.error != 0 {
        return None;
    }

    let local_stream_id = next_stream_id();

    let reply_payload = NoisePayload {
        version: 1,
        error: 0,
        firewall: config.firewall,
        holepunch: None,
        addresses4: vec![],
        addresses6: vec![],
        udx: Some(UdxInfo {
            version: 1,
            reusable_socket: true,
            id: u64::from(local_stream_id),
            seq: 0,
        }),
        secret_stream: Some(SecretStreamInfo { version: 1 }),
        relay_through: None,
        relay_addresses: None,
    };

    let noise_reply = match nw.send(&reply_payload) {
        Ok(b) => b,
        Err(_) => return None,
    };

    let nw_result = match nw.finalize() {
        Ok(r) => r,
        Err(_) => return None,
    };

    session.holepunch_secrets.insert(
        nw_result.remote_public_key,
        ServerPeerState {
            holepunch_secret: nw_result.holepunch_secret,
            remote_public_key: nw_result.remote_public_key,
            client_address: from.clone(),
            local_stream_id,
            remote_udx: remote_payload.udx.clone(),
        },
    );

    let reply_msg = HandshakeMessage {
        mode: crate::hyperdht_messages::MODE_REPLY,
        noise: noise_reply,
        peer_address: Some(from.clone()),
        relay_address: None,
    };

    crate::hyperdht_messages::encode_handshake_to_bytes(&reply_msg).ok()
}

/// Result returned by [`build_passive_holepunch_reply`].
#[non_exhaustive]
pub struct PassiveHolepunchReply {
    /// Fully-encoded [`HolepunchMessage`] bytes ready to send on the wire.
    pub reply_bytes: Vec<u8>,
    /// Decrypted incoming holepunch payload from the remote peer.
    pub remote_hp: HolepunchPayload,
    /// The [`SecurePayload`] instance used for this exchange; reuse it across rounds for token continuity.
    pub payload: SecurePayload,
    /// Constructed [`Holepuncher`]; caller decides whether to spawn `punch()` or retain it.
    pub puncher: Holepuncher,
}

/// Build a passive (server-side) holepunch reply from raw encrypted bytes.
///
/// Pass `dht = Some(&dht_handle)` to run the puncher's autoSample
/// before returning (required for the `coerce_firewall` revert to be
/// safe on the passive path). Tests may pass `None` to skip sampling.
#[allow(clippy::too_many_arguments)]
pub async fn build_passive_holepunch_reply(
    config_firewall: u64,
    pool: &SocketPool,
    runtime: &UdxRuntime,
    peer_address: &Ipv4Peer,
    holepunch_secret: [u8; 32],
    incoming_payload: &[u8],
    msg_id: u64,
    event_tx: mpsc::UnboundedSender<HolepunchEvent>,
    dht: Option<&crate::rpc::DhtHandle>,
) -> Result<PassiveHolepunchReply, HyperDhtError> {
    let sp = SecurePayload::new(holepunch_secret);
    let remote_hp = sp.decrypt(incoming_payload)?;

    let mut puncher = Holepuncher::new(pool, runtime, true, false, remote_hp.firewall, event_tx)
        .await
        .map_err(|_| HyperDhtError::HolepunchFailed)?;

    if let Some(addrs) = &remote_hp.addresses {
        puncher.update_remote(
            true,
            remote_hp.firewall,
            addrs,
            Some(peer_address.host.as_str()),
        );
    }

    // Seed the passive puncher's NAT classifier BEFORE the caller spawns
    // punch(). Symmetric to the initiator path — without this the passive
    // NAT stays UNKNOWN and the coerce_firewall divergence has to lie.
    // Critical: this is what makes the T8 coerce_firewall revert safe on
    // the passive path.
    if let Some(dht_handle) = dht {
        let added = puncher.auto_sample(dht_handle).await;
        tracing::debug!(
            added,
            firewall = puncher.nat.firewall,
            "passive auto_sample"
        );
    }

    // Advertise the passive puncher's reachable addresses so the initiator
    // probes back at us. Prefer autoSample-derived reflexive samples
    // (`puncher.nat.addresses`); fall back to local LAN interfaces when
    // empty. Echoing `peer_address` here would tell the initiator to
    // punch its own reflexive address. Mirrors the algorithm used on the
    // initiator side (Node `hyperdht/lib/holepuncher.js:221-227`).
    let local_punch_addrs: Vec<Ipv4Peer> = match puncher.primary_socket() {
        Some(sr) => match sr.socket.local_addr().await {
            Ok(addr) => puncher.punch_addresses(addr.port()),
            Err(_) => Vec::new(),
        },
        None => Vec::new(),
    };

    let try_later = remote_hp.punching && !puncher.reserve_random_punch();
    if try_later {
        puncher.destroy();
    }
    let reply_hp = HolepunchPayload {
        error: if try_later {
            ERROR_TRY_LATER
        } else {
            ERROR_NONE
        },
        firewall: config_firewall,
        round: remote_hp.round,
        connected: false,
        punching: remote_hp.punching && !try_later,
        addresses: Some(local_punch_addrs),
        remote_address: Some(peer_address.clone()),
        token: Some(sp.token(&peer_address.host)),
        remote_token: remote_hp.token,
    };

    let encrypted_reply = sp.encrypt(&reply_hp)?;

    let reply_msg = HolepunchMessage {
        mode: crate::hyperdht_messages::MODE_REPLY,
        id: msg_id,
        payload: encrypted_reply,
        peer_address: Some(peer_address.clone()),
    };

    let reply_bytes = crate::hyperdht_messages::encode_holepunch_msg_to_bytes(&reply_msg)?;

    Ok(PassiveHolepunchReply {
        reply_bytes,
        remote_hp,
        payload: sp,
        puncher,
    })
}

// ── Spawn ─────────────────────────────────────────────────────────────────────

/// Create a HyperDHT instance and start its background tasks.
pub async fn spawn(
    runtime: &UdxRuntime,
    config: HyperDhtConfig,
) -> Result<
    (
        JoinHandle<Result<(), HyperDhtError>>,
        HyperDhtHandle,
        mpsc::UnboundedReceiver<ServerEvent>,
    ),
    HyperDhtError,
> {
    let (dht_join, dht_handle) = crate::rpc::spawn(runtime, config.dht).await?;
    let persistent_config = config.persistent;

    let request_rx = dht_handle
        .subscribe_requests()
        .await
        .ok_or(HyperDhtError::ChannelClosed)?;

    let router = Arc::new(Mutex::new(Router::new()));
    let (server_tx, mut incoming_servers) = mpsc::unbounded_channel::<ServerEvent>();
    let (fallback_tx, server_rx) = mpsc::unbounded_channel();
    let server_routes = Arc::new(Mutex::new(std::collections::HashMap::<
        [u8; 32],
        mpsc::UnboundedSender<ServerEvent>,
    >::new()));
    let routes = Arc::clone(&server_routes);
    let dispatch = tokio::spawn(async move {
        while let Some(event) = incoming_servers.recv().await {
            let target = match &event {
                ServerEvent::PeerHandshake { target, .. }
                | ServerEvent::PeerHolepunch { target, .. } => *target,
            };
            let sender = target.and_then(|key| routes.lock().ok()?.get(&key).cloned());
            if let Some(sender) = sender {
                if let Err(error) = sender.send(event) {
                    let _ = fallback_tx.send(error.0);
                }
            } else {
                let _ = fallback_tx.send(event);
            }
        }
    });
    let (admin_tx, admin_rx) = mpsc::unbounded_channel::<AdminRequest>();

    let request_task = tokio::spawn(run_request_handler(
        request_rx,
        persistent_config,
        dht_handle.clone(),
        Arc::clone(&router),
        server_tx.clone(),
        admin_rx,
    ));

    let join = tokio::spawn(async move {
        let result = tokio::select! {
            res = dht_join => {
                match res {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(HyperDhtError::Dht(e)),
                    Err(_) => Err(HyperDhtError::ChannelClosed),
                }
            }
            res = request_task => {
                match res {
                    Ok(()) => Ok(()),
                    Err(_) => Err(HyperDhtError::ChannelClosed),
                }
            }
        };
        dispatch.abort();
        result
    });

    let handle = HyperDhtHandle {
        dht: dht_handle,
        router,
        server_tx,
        server_routes,
        admin_tx,
        current_relays: Arc::new(Mutex::new(Vec::new())),
        raw_streams: Arc::new(Mutex::new(Vec::new())),
    };
    Ok((join, handle, server_rx))
}

async fn run_request_handler(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<crate::rpc::UserRequest>,
    config: PersistentConfig,
    dht: DhtHandle,
    router: Arc<Mutex<Router>>,
    server_tx: mpsc::UnboundedSender<ServerEvent>,
    mut admin_rx: mpsc::UnboundedReceiver<AdminRequest>,
) {
    let mut storage = Persistent::new(config);

    loop {
        let mut req = tokio::select! {
            biased;
            Some(admin_req) = admin_rx.recv() => {
                match admin_req {
                    AdminRequest::PersistentStats { reply } => {
                        let _ = reply.send(storage.stats());
                    }
                    AdminRequest::LocalRecord { target, record } => {
                        storage.set_local_record(&target, record);
                    }
                }
                continue;
            }
            req = rx.recv() => match req {
                Some(r) => r,
                None => break,
            },
        };
        match req.command {
            PEER_HANDSHAKE => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: PEER_HANDSHAKE");
                handle_peer_handshake(req, &dht, &router, &server_tx);
                continue;
            }
            PEER_HOLEPUNCH => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: PEER_HOLEPUNCH");
                handle_peer_holepunch(req, &dht, &router, &server_tx);
                continue;
            }
            _ => {}
        }

        let node_id = req.id;

        let incoming = IncomingHyperRequest {
            command: req.command,
            target: req.target,
            token: req.token,
            value: req.value.clone(),
            from: req.from.clone(),
            id: node_id,
        };

        let reply = match req.command {
            FIND_PEER => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: FIND_PEER");
                storage.on_find_peer(&incoming)
            }
            LOOKUP => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: LOOKUP");
                storage.on_lookup(&incoming)
            }
            ANNOUNCE => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: ANNOUNCE");
                let own_id = dht.table_id().await.ok().flatten();
                if let Some(nid) = own_id {
                    let result = storage.on_announce(&incoming, &nid);
                    if !matches!(result, HandlerReply::Silent) {
                        if let Some(target) = incoming.target {
                            if let Ok(mut r) = router.lock() {
                                let already_server = r.get(&target).is_some_and(|e| e.has_server);
                                if !already_server {
                                    r.set(
                                        &target,
                                        ForwardEntry {
                                            relay: Some(incoming.from.clone()),
                                            has_server: false,
                                            inserted: std::time::Instant::now(),
                                        },
                                    );
                                }
                            }
                        }
                    }
                    result
                } else {
                    HandlerReply::Silent
                }
            }
            UNANNOUNCE => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: UNANNOUNCE");
                let own_id = dht.table_id().await.ok().flatten();
                if let Some(nid) = own_id {
                    storage.on_unannounce(&incoming, &nid)
                } else {
                    HandlerReply::Silent
                }
            }
            MUTABLE_PUT => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: MUTABLE_PUT");
                storage.on_mutable_put(&incoming)
            }
            MUTABLE_GET => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: MUTABLE_GET");
                storage.on_mutable_get(&incoming)
            }
            IMMUTABLE_PUT => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: IMMUTABLE_PUT");
                storage.on_immutable_put(&incoming)
            }
            IMMUTABLE_GET => {
                tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "request: IMMUTABLE_GET");
                storage.on_immutable_get(&incoming)
            }
            _ => {
                tracing::debug!(cmd = req.command, from = %format!("{}:{}", req.from.host, req.from.port), "request: unknown command");
                drop(req);
                continue;
            }
        };

        match reply {
            HandlerReply::Value(v) | HandlerReply::ValueNoToken(v) => {
                req.reply(v);
            }
            HandlerReply::Error(code) => {
                req.error(code);
            }
            HandlerReply::Silent => {
                drop(req);
            }
        }
    }
}

fn handle_peer_handshake(
    mut req: crate::rpc::UserRequest,
    dht: &DhtHandle,
    router: &Arc<Mutex<Router>>,
    server_tx: &mpsc::UnboundedSender<ServerEvent>,
) {
    let Some(value) = &req.value else {
        req.error(1);
        return;
    };

    let action = {
        let router = match router.lock() {
            Ok(r) => r,
            Err(_) => {
                req.error(1);
                return;
            }
        };
        match router.route_handshake(req.target.as_ref(), &req.from, value) {
            Ok(a) => a,
            Err(_) => {
                req.error(1);
                return;
            }
        }
    };

    match action {
        HandshakeAction::Reply(value) => {
            tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "handshake REPLY");
            req.reply(Some(value));
        }
        HandshakeAction::ForwardRequest { value, to } => {
            // FE-holder relay: forward the inbound REQUEST as a new REQUEST
            // to `to`, preserving the original requester's tid end-to-end.
            // Fire-and-forget — the eventual REPLY will reach the original
            // client directly via the tid-preserved chain (server replies
            // with `dht.relay_with_tid` back to this FE-holder, which then
            // dispatches HandshakeAction::ReplyTo to send the REPLY packet
            // straight to the client at peer_address). Mirrors Node
            // `dht-rpc::Request.relay(value, to)`.
            tracing::debug!(
                from = %format!("{}:{}", req.from.host, req.from.port),
                to = %format!("{}:{}", to.host, to.port),
                "handshake FORWARD_REQUEST — tid-preserved relay"
            );
            if let Err(e) =
                dht.relay_with_tid(PEER_HANDSHAKE, req.target, Some(value), &to, req.tid)
            {
                tracing::debug!(err = %e, "ForwardRequest: relay_with_tid send failed");
            }
            // No reply to the inbound REQUEST — the original client awaits
            // its REPLY via the preserved-tid chain, not via this hop.
            req.release();
        }
        HandshakeAction::ReplyTo { value, to } => {
            // FE-holder finalises the relay chain: send a REPLY packet
            // (Response, not Request) with the inbound tid (= original
            // client's tid) directly to the client at `to`. The REPLY
            // matches the client's outstanding inflight entry. Mirrors
            // Node `dht-rpc::Request.reply(value, { to })` as invoked from
            // `lib/server.js _addHandshake case FROM_SERVER`.
            tracing::debug!(
                from = %format!("{}:{}", req.from.host, req.from.port),
                to = %format!("{}:{}", to.host, to.port),
                "handshake REPLY_TO — finalise tid-preserved chain"
            );
            if let Err(e) = dht.send_reply_to(req.tid, req.target, &to, Some(value)) {
                tracing::debug!(err = %e, "ReplyTo: send_reply_to failed");
            }
            // The inbound REQUEST came from the server via its relay_with_tid;
            // the server is not awaiting a reply, so we do not call
            // req.reply / req.error here.
            req.release();
        }
        HandshakeAction::Relay { value, to } => {
            // Legacy variant — the router no longer emits this for handshakes.
            // Retained for forward-compatibility (non_exhaustive enum) so any
            // external producer continues to function. Treat as fire-and-forget
            // tid-preserved relay (equivalent to ForwardRequest).
            tracing::warn!(
                from = %format!("{}:{}", req.from.host, req.from.port),
                to = %format!("{}:{}", to.host, to.port),
                "handshake legacy Relay action — treating as ForwardRequest"
            );
            if let Err(e) =
                dht.relay_with_tid(PEER_HANDSHAKE, req.target, Some(value), &to, req.tid)
            {
                tracing::debug!(err = %e, "legacy Relay: relay_with_tid send failed");
            }
            req.release();
        }
        HandshakeAction::HandleLocally(msg) => {
            tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), inbound_mode = msg.mode, "handshake HANDLE_LOCALLY");
            let (reply_tx, reply_rx) = oneshot::channel();
            let from = req.from.clone();
            let target = req.target;
            let peer_address = msg.peer_address.clone();
            // FROM_CLIENT direct handshakes are answered via the inbound
            // request's REPLY channel (`req.reply`). FROM_RELAY /
            // FROM_SECOND_RELAY handshakes arrive as REQUESTs whose tid was
            // preserved by the FE-holder via `req.relay`-style forwarding;
            // we mirror Node `lib/server.js _addHandshake case FROM_RELAY`
            // by calling `dht.relay_with_tid(...)` to push a tid-preserved
            // FROM_SERVER REQUEST back to the FE-holder. The FE-holder then
            // finalises the chain by emitting the REPLY directly to the
            // original client (see HandshakeAction::ReplyTo above).
            let inbound_mode = msg.mode;
            let inbound_tid = req.tid;

            let sent = server_tx
                .send(ServerEvent::PeerHandshake {
                    msg,
                    from,
                    peer_address,
                    target,
                    reply_tx,
                })
                .is_ok();

            if sent {
                let dht = dht.clone();
                tokio::spawn(async move {
                    match reply_rx.await {
                        Ok(Some(reply)) => match inbound_mode {
                            crate::hyperdht_messages::MODE_FROM_CLIENT => {
                                req.reply(Some(reply.value))
                            }
                            crate::hyperdht_messages::MODE_FROM_RELAY
                            | crate::hyperdht_messages::MODE_FROM_SECOND_RELAY => {
                                if let Err(e) = dht.relay_with_tid_via(
                                    PEER_HANDSHAKE,
                                    target,
                                    Some(reply.value),
                                    &req.from,
                                    inbound_tid,
                                    reply.socket,
                                ) {
                                    tracing::debug!(err = %e, "relay_with_tid send failed");
                                }
                                // The FE-holder used `req.relay`-style
                                // forwarding to reach us; it is not awaiting
                                // a REPLY for this REQUEST. Release the
                                // inbound req so the deferred-reply pipeline
                                // does not emit an auto-error REPLY racing
                                // against the genuine REPLY arriving via the
                                // chain's tail.
                                req.release();
                            }
                            _ => req.reply(Some(reply.value)),
                        },
                        Ok(None) => req.reply(None),
                        Err(_) => req.error(1),
                    }
                });
            } else {
                req.reply(None);
            }
        }
        HandshakeAction::CloserNodes => {
            tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "handshake CLOSER_NODES");
            req.reply(None);
        }
        HandshakeAction::Drop => {
            tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "handshake DROP");
            drop(req);
        }
    }
}

fn handle_peer_holepunch(
    mut req: crate::rpc::UserRequest,
    dht: &DhtHandle,
    router: &Arc<Mutex<Router>>,
    server_tx: &mpsc::UnboundedSender<ServerEvent>,
) {
    let Some(value) = &req.value else {
        req.error(1);
        return;
    };

    let action = {
        let router = match router.lock() {
            Ok(r) => r,
            Err(_) => {
                req.error(1);
                return;
            }
        };
        match router.route_holepunch(req.target.as_ref(), &req.from, value) {
            Ok(a) => a,
            Err(_) => {
                req.error(1);
                return;
            }
        }
    };

    match action {
        HolepunchAction::ForwardRequest { value, to } => {
            // FE-holder relay: forward the inbound REQUEST as a new REQUEST
            // to `to`, preserving the original requester's tid end-to-end.
            // Fire-and-forget — the eventual REPLY reaches the original
            // client directly via the tid-preserved chain (server replies
            // with `dht.relay_with_tid` back to this FE-holder, which then
            // dispatches HolepunchAction::ReplyTo to send the REPLY packet
            // straight to the client at peer_address). Mirrors Node
            // `dht-rpc::Request.relay(value, to)` and item-8 for handshake.
            tracing::debug!(
                from = %format!("{}:{}", req.from.host, req.from.port),
                to = %format!("{}:{}", to.host, to.port),
                "holepunch FORWARD_REQUEST — tid-preserved relay"
            );
            if let Err(e) =
                dht.relay_with_tid(PEER_HOLEPUNCH, req.target, Some(value), &to, req.tid)
            {
                tracing::debug!(err = %e, "ForwardRequest: relay_with_tid send failed");
            }
            // No reply to the inbound REQUEST — the original client awaits
            // its REPLY via the preserved-tid chain, not via this hop.
            req.release();
        }
        HolepunchAction::ReplyTo { value, to } => {
            // FE-holder finalises the relay chain: send a REPLY packet
            // (Response, not Request) with the inbound tid (= original
            // client's tid) directly to the client at `to`. The REPLY
            // matches the client's outstanding inflight entry. Mirrors
            // Node `dht-rpc::Request.reply(value, { to })` as invoked from
            // `lib/server.js _addHolepunch case FROM_SERVER`.
            tracing::debug!(
                from = %format!("{}:{}", req.from.host, req.from.port),
                to = %format!("{}:{}", to.host, to.port),
                "holepunch REPLY_TO — finalise tid-preserved chain"
            );
            if let Err(e) = dht.send_reply_to(req.tid, req.target, &to, Some(value)) {
                tracing::debug!(err = %e, "ReplyTo: send_reply_to failed");
            }
            // The inbound REQUEST came from the server via its relay_with_tid;
            // the server is not awaiting a reply, so we do not call
            // req.reply / req.error here.
            req.release();
        }
        HolepunchAction::Relay { value, to } => {
            // Legacy variant — the router no longer emits this for holepunch.
            // Retained for forward-compatibility (non_exhaustive enum) so any
            // external producer continues to function. Treat as fire-and-forget
            // tid-preserved relay (equivalent to ForwardRequest).
            tracing::warn!(
                from = %format!("{}:{}", req.from.host, req.from.port),
                to = %format!("{}:{}", to.host, to.port),
                "holepunch legacy Relay action — treating as ForwardRequest"
            );
            if let Err(e) =
                dht.relay_with_tid(PEER_HOLEPUNCH, req.target, Some(value), &to, req.tid)
            {
                tracing::debug!(err = %e, "legacy Relay: relay_with_tid send failed");
            }
            req.release();
        }
        HolepunchAction::Reply { value, to } => {
            // Legacy variant — the router no longer emits this for holepunch.
            // Retained for forward-compatibility (non_exhaustive enum). Treat
            // as REPLY-to-arbitrary-address (equivalent to ReplyTo).
            tracing::warn!(
                from = %format!("{}:{}", req.from.host, req.from.port),
                to = %format!("{}:{}", to.host, to.port),
                "holepunch legacy Reply action — treating as ReplyTo"
            );
            if let Err(e) = dht.send_reply_to(req.tid, req.target, &to, Some(value)) {
                tracing::debug!(err = %e, "legacy Reply: send_reply_to failed");
            }
            req.release();
        }
        HolepunchAction::HandleLocally { msg, peer_address } => {
            tracing::debug!(
                from = %format!("{}:{}", req.from.host, req.from.port),
                peer = %format!("{:?}", peer_address),
                inbound_mode = msg.mode,
                "holepunch HANDLE_LOCALLY"
            );
            let (reply_tx, reply_rx) = oneshot::channel();
            let from = req.from.clone();
            let target = req.target;
            // FROM_CLIENT direct holepunch (if ever wired) is answered via
            // the inbound request's REPLY channel (`req.reply`). FROM_RELAY /
            // FROM_SECOND_RELAY holepunches arrive as REQUESTs whose tid was
            // preserved by the FE-holder via `req.relay`-style forwarding;
            // we mirror Node `lib/server.js _addHolepunch case FROM_RELAY`
            // by calling `dht.relay_with_tid(...)` to push a tid-preserved
            // FROM_SERVER REQUEST back to the FE-holder. The FE-holder then
            // finalises the chain by emitting the REPLY directly to the
            // original client (see HolepunchAction::ReplyTo above).
            let inbound_mode = msg.mode;
            let inbound_tid = req.tid;

            let sent = server_tx
                .send(ServerEvent::PeerHolepunch {
                    msg,
                    from,
                    peer_address,
                    target,
                    reply_tx,
                })
                .is_ok();

            if sent {
                let dht = dht.clone();
                tokio::spawn(async move {
                    match reply_rx.await {
                        Ok(Some(reply)) => match inbound_mode {
                            crate::hyperdht_messages::MODE_FROM_CLIENT => {
                                req.reply(Some(reply.value))
                            }
                            crate::hyperdht_messages::MODE_FROM_RELAY
                            | crate::hyperdht_messages::MODE_FROM_SECOND_RELAY => {
                                if let Err(e) = dht.relay_with_tid_via(
                                    PEER_HOLEPUNCH,
                                    target,
                                    Some(reply.value),
                                    &req.from,
                                    inbound_tid,
                                    reply.socket,
                                ) {
                                    tracing::debug!(err = %e, "relay_with_tid send failed");
                                }
                                // The FE-holder used `req.relay`-style
                                // forwarding to reach us; it is not awaiting
                                // a REPLY for this REQUEST. Release the
                                // inbound req so the deferred-reply pipeline
                                // does not emit an auto-error REPLY racing
                                // against the genuine REPLY arriving via the
                                // chain's tail.
                                req.release();
                            }
                            _ => req.reply(Some(reply.value)),
                        },
                        Ok(None) => req.reply(None),
                        Err(_) => req.error(1),
                    }
                });
            } else {
                req.reply(None);
            }
        }
        HolepunchAction::Drop => {
            tracing::debug!(from = %format!("{}:{}", req.from.host, req.from.port), "holepunch DROP");
            drop(req);
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn encode_compact_uint(v: u64) -> Vec<u8> {
    let mut state = crate::compact_encoding::State::new();
    crate::compact_encoding::preencode_uint(&mut state, v);
    state.alloc();
    crate::compact_encoding::encode_uint(&mut state, v);
    state.buffer
}

fn to_hex(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").ok();
            s
        })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyperdht_messages::{FIREWALL_CONSISTENT, FIREWALL_RANDOM};

    #[test]
    fn hyperdht_config_defaults() {
        let cfg = HyperDhtConfig::default();
        assert_eq!(cfg.dht.port, 0);
        assert_eq!(cfg.dht.host, "0.0.0.0");
        assert_eq!(cfg.dht.concurrency, 10);
        assert!(cfg.dht.bootstrap.is_empty());
        assert_eq!(
            cfg.persistent.max_records,
            PersistentConfig::default().max_records
        );
        assert_eq!(
            cfg.persistent.max_per_key,
            PersistentConfig::default().max_per_key
        );
    }

    #[test]
    fn keypair_generate_produces_unique_keys() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        assert_ne!(kp1.public_key, kp2.public_key);
    }

    #[test]
    fn keypair_from_seed_deterministic() {
        let seed = [0x42u8; 32];
        let kp1 = KeyPair::from_seed(seed);
        let kp2 = KeyPair::from_seed(seed);
        assert_eq!(kp1.public_key, kp2.public_key);
        assert_eq!(kp1.secret_key, kp2.secret_key);
    }

    #[test]
    fn keypair_public_key_matches_secret() {
        let kp = KeyPair::from_seed([0x11u8; 32]);
        assert_eq!(&kp.secret_key[32..], &kp.public_key);
    }

    #[test]
    fn keypair_sign_verify_roundtrip() {
        let kp = KeyPair::generate();
        let msg = b"test message";
        let sig = sign_detached(msg, &kp.secret_key);
        assert!(verify_detached(&sig, msg, &kp.public_key));
    }

    #[test]
    fn encode_compact_uint_round_trips() {
        use crate::compact_encoding::{State, decode_uint};
        for val in [0u64, 1, 127, 128, 255, 65535, u64::MAX / 2] {
            let bytes = encode_compact_uint(val);
            let mut s = State::from_buffer(&bytes);
            let decoded = decode_uint(&mut s).unwrap();
            assert_eq!(decoded, val, "compact uint round-trip failed for {val}");
        }
    }

    #[test]
    fn hyperdht_error_display() {
        let e = HyperDhtError::Destroyed;
        assert!(e.to_string().contains("destroyed"));
        let e2 = HyperDhtError::InvalidSignature;
        assert!(e2.to_string().contains("signature"));
    }

    #[test]
    fn keypair_debug_hides_secret() {
        let kp = KeyPair::from_seed([0x42u8; 32]);
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("KeyPair"));
        assert!(!dbg.contains("secret_key"));
    }

    #[tokio::test]
    async fn spawn_and_destroy() {
        let runtime = libudx::UdxRuntime::new().expect("runtime");
        let config = HyperDhtConfig {
            dht: DhtConfig {
                bootstrap: vec![],
                port: 0,
                ..DhtConfig::default()
            },
            persistent: PersistentConfig::default(),
        };
        let (join, handle, _server_rx) = spawn(&runtime, config).await.expect("spawn");
        handle.destroy().await.expect("destroy");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), join).await;
    }

    #[tokio::test]
    async fn wire_stats_starts_at_zero_and_is_addressable() {
        let runtime = libudx::UdxRuntime::new().expect("runtime");
        let config = HyperDhtConfig {
            dht: DhtConfig {
                bootstrap: vec![],
                port: 0,
                ..DhtConfig::default()
            },
            persistent: PersistentConfig::default(),
        };
        let (join, handle, _rx) = spawn(&runtime, config).await.expect("spawn");
        let (sent, received) = handle.wire_stats();
        assert_eq!(sent, 0, "no traffic yet");
        assert_eq!(received, 0);
        // Counters are shared via Arc — incrementing through `wire_counters()`
        // must be visible via `wire_stats()`.
        let counters = handle.wire_counters();
        counters
            .bytes_sent
            .fetch_add(123, std::sync::atomic::Ordering::Relaxed);
        counters
            .bytes_received
            .fetch_add(456, std::sync::atomic::Ordering::Relaxed);
        let (sent, received) = handle.wire_stats();
        assert_eq!(sent, 123);
        assert_eq!(received, 456);
        handle.destroy().await.expect("destroy");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), join).await;
    }

    #[test]
    fn next_stream_id_is_random_and_never_zero() {
        let ids: Vec<u32> = (0..3).map(|_| next_stream_id()).collect();
        assert!(ids.iter().all(|&id| id != 0));
        assert!(ids.windows(2).all(|w| w[0] != w[1]));
        assert!(
            ids.windows(2).any(|w| w[1] != w[0].wrapping_add(1)),
            "ids must not be guessable: {ids:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shared_server_reply_cache_is_bounded_and_expires_without_new_handshakes() {
        let mut replies = ServerReplyCache::new(std::time::Duration::from_secs(10), 2);
        replies.insert(b"first", vec![1], None);
        replies.insert(b"first", vec![9], None);
        assert_eq!(replies.get(b"first").unwrap().0, vec![1]);
        replies.insert(b"second", vec![2], None);
        replies.insert(b"third", vec![3], None);
        assert_eq!(replies.entries.len(), 2);
        assert!(replies.get(b"first").is_none());
        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        replies.prune();
        assert!(replies.entries.is_empty());
        assert_eq!(replies.entries.capacity(), 0);
        assert_eq!(replies.order.capacity(), 0);
    }

    #[tokio::test]
    async fn open_server_arms_direct_hook_before_relay_can_take_the_stream() {
        let runtime = UdxRuntime::new().unwrap();
        let config = HyperDhtConfig {
            dht: DhtConfig {
                bootstrap: vec![],
                port: 0,
                firewalled: false,
                quick_firewall: false,
                ..DhtConfig::default()
            },
            ..HyperDhtConfig::default()
        };
        let (_task, dht, _events) = spawn(&runtime, config).await.unwrap();
        let keys = KeyPair::generate();
        let client = KeyPair::generate();
        let mut noise = NoiseWrap::new_initiator(client.to_noise_keypair(), keys.public_key);
        let msg = HandshakeMessage {
            mode: MODE_FROM_RELAY,
            peer_address: None,
            relay_address: None,
            noise: noise
                .send(&NoisePayload {
                    version: 1,
                    error: 0,
                    firewall: FIREWALL_UNKNOWN,
                    holepunch: None,
                    addresses4: vec![],
                    addresses6: vec![],
                    udx: Some(UdxInfo {
                        version: 1,
                        reusable_socket: true,
                        id: 42,
                        seq: 0,
                    }),
                    secret_stream: Some(SecretStreamInfo { version: 1 }),
                    relay_through: Some(RelayThroughInfo {
                        version: 1,
                        public_key: [7; 32],
                        token: [8; 32],
                    }),
                    relay_addresses: None,
                })
                .unwrap(),
        };
        let (events, _rx) = mpsc::unbounded_channel();
        let peer = Ipv4Peer {
            host: "127.0.0.1".into(),
            port: 1234,
        };
        let mut accepted = accept_server_handshake(
            &dht,
            &runtime,
            &ServerConfig::new(keys, FIREWALL_OPEN),
            1,
            &events,
            &msg,
            &peer,
            Some(&peer),
        )
        .await
        .unwrap();
        assert!(
            accepted.relay.is_some(),
            "relay launch is deferred until the armed handshake is committed"
        );
        let local_id = noise.recv(&accepted.noise_reply).unwrap().udx.unwrap().id as u32;
        let mut path = accepted.accept.take().unwrap();
        let socket = dht.server_socket().await.unwrap().unwrap();
        let alternate = runtime.create_socket().await.unwrap();
        alternate
            .bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let sender_socket = runtime.create_socket().await.unwrap();
        sender_socket
            .bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let sender_addr = sender_socket.local_addr().await.unwrap();
        // Simulate the relay taking the stream before the direct accept future runs.
        let stream = path.raced.stream.lock().unwrap().take().unwrap();
        stream.connect(&alternate, 42, sender_addr).await.unwrap();
        let sender = runtime.create_stream(42).await.unwrap();
        let target = SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            socket.local_addr().await.unwrap().port(),
        );
        sender
            .connect(&sender_socket, local_id, target)
            .await
            .unwrap();
        let task = tokio::spawn(async move {
            let _ = sender.write(b"direct").await;
        });
        let observed = path
            .observed
            .as_mut()
            .expect("hook must be armed before relay launch");
        let (_, addr) = tokio::time::timeout(std::time::Duration::from_secs(2), observed.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(addr, sender_addr);
        stream.abort_handle().abort();
        task.abort();
        dht.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn relay_first_hook_accepts_delayed_old_path_data_without_confirming_direct() {
        let runtime = UdxRuntime::new().expect("runtime");
        let config = HyperDhtConfig {
            dht: DhtConfig {
                bootstrap: vec![],
                port: 0,
                ..DhtConfig::default()
            },
            ..HyperDhtConfig::default()
        };
        let (_task, dht, _events) = spawn(&runtime, config).await.expect("spawn");
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let direct = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old_socket = runtime.create_socket().await.unwrap();
        old_socket
            .bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let local_id = 10987;
        let raced = RacedStream::new(runtime.create_stream(local_id).await.unwrap());
        *raced.relay_addr.lock().unwrap() = Some(relay.local_addr().unwrap());
        let noise = NoiseWrapResult {
            remote_public_key: [1; 32],
            tx: [2; 32],
            rx: [3; 32],
            handshake_hash: [4; 64],
            holepunch_secret: [5; 32],
            is_initiator: false,
        };
        let (events, mut event_rx) = mpsc::unbounded_channel();
        let mut punch = stage_server_punch(
            &runtime,
            dht.dht(),
            None,
            &noise,
            "127.0.0.1",
            FIREWALL_UNKNOWN,
            1,
            Arc::clone(&raced),
            17,
            &events,
        )
        .await
        .unwrap();
        // Force relay-first ownership transfer before any direct packet arrives.
        let stream = raced.stream.lock().unwrap().take().unwrap();
        stream
            .connect(&old_socket, 17, relay.local_addr().unwrap())
            .await
            .unwrap();
        let remote = stream.remote_handle();
        let outbound = tokio::spawn(async move {
            stream.write(b"outbound").await.unwrap();
            stream
        });
        let mut packet = [0; 1500];
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let (len, _) = relay.recv_from(&mut packet).await.unwrap();
                if len > 20 && packet[2] & 1 != 0 {
                    break;
                }
            }
        })
        .await
        .unwrap();
        let migration = remote.change_remote(&punch.socket, 17, direct.local_addr().unwrap());
        tokio::pin!(migration);
        tokio::select! {
            biased;
            result = &mut migration => panic!("migration skipped outstanding relay packet: {result:?}"),
            () = std::future::ready(()) => {}
        }
        let wire = |seq: u32, payload: &[u8]| {
            let mut bytes = vec![0; 20];
            bytes[..4].copy_from_slice(&[0xff, 1, 1, 0]);
            bytes[4..8].copy_from_slice(&local_id.to_le_bytes());
            bytes[8..12].copy_from_slice(&65536u32.to_le_bytes());
            bytes[12..16].copy_from_slice(&seq.to_le_bytes());
            bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(payload);
            bytes
        };
        relay
            .send_to(&wire(0, b"late"), old_socket.local_addr().await.unwrap())
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), &mut migration)
            .await
            .unwrap()
            .unwrap();
        let mut stream = tokio::time::timeout(std::time::Duration::from_secs(2), outbound)
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                remote.remote_observed()
            )
            .await
            .is_err()
        );
        assert!(
            event_rx.try_recv().is_err(),
            "relay traffic is not a direct landing"
        );
        let target = SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            punch.socket.local_addr().await.unwrap().port(),
        );
        direct.send_to(&wire(1, b"direct"), target).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), remote.remote_observed())
            .await
            .unwrap()
            .unwrap();
        // change_remote already selected this socket; C only calls the hook for foreign sockets.
        assert!(
            event_rx.try_recv().is_err(),
            "the selected direct path must not emit another punch event"
        );
        assert_eq!(stream.read().await.unwrap().as_deref(), Some(&b"late"[..]));
        assert_eq!(
            stream.read().await.unwrap().as_deref(),
            Some(&b"direct"[..])
        );
        punch.abort.abort();
        if let Some(mut puncher) = punch.puncher.take() {
            puncher.destroy();
        }
        dht.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn slow_handshake_staging_does_not_block_another_client() {
        let runtime = UdxRuntime::new().expect("runtime");
        let local = |bootstrap, firewalled| HyperDhtConfig {
            dht: DhtConfig {
                bootstrap,
                firewalled,
                quick_firewall: false,
                port: 0,
                host: "127.0.0.1".into(),
                ..DhtConfig::default()
            },
            ..HyperDhtConfig::default()
        };
        let (_task, bootstrap, _events) = spawn(&runtime, local(vec![], false))
            .await
            .expect("bootstrap");
        let address = format!("127.0.0.1:{}", bootstrap.local_port().await.unwrap());
        let (_task, dht, _events) = spawn(&runtime, local(vec![address], true))
            .await
            .expect("server");
        dht.fully_bootstrapped().await.expect("bootstrapped");
        assert!(
            !dht.dht().recent_nodes(1).is_empty(),
            "sampling needs a known peer"
        );
        bootstrap.destroy().await.expect("stop answering samples");
        let keys = KeyPair::generate();
        let (events, incoming) = mpsc::unbounded_channel();
        let mut server = dht.create_server(
            &runtime,
            ServerConfig::new(keys.clone(), FIREWALL_UNKNOWN),
            incoming,
        );
        server.listen(&keys).await.expect("listen");
        let make_message = |with_stream: bool| {
            let client = KeyPair::generate();
            let mut noise = NoiseWrap::new_initiator(client.to_noise_keypair(), keys.public_key);
            HandshakeMessage {
                mode: MODE_FROM_RELAY,
                peer_address: None,
                relay_address: None,
                noise: noise
                    .send(&NoisePayload {
                        version: 1,
                        error: 0,
                        firewall: FIREWALL_UNKNOWN,
                        holepunch: None,
                        addresses4: vec![],
                        addresses6: vec![],
                        udx: with_stream.then_some(UdxInfo {
                            version: 1,
                            reusable_socket: true,
                            id: 42,
                            seq: 0,
                        }),
                        secret_stream: Some(SecretStreamInfo { version: 1 }),
                        relay_through: None,
                        relay_addresses: None,
                    })
                    .expect("noise"),
            }
        };
        let send = |msg| {
            let (reply_tx, reply_rx) = oneshot::channel();
            events
                .send(ServerEvent::PeerHandshake {
                    msg,
                    from: Ipv4Peer {
                        host: "127.0.0.1".into(),
                        port: 1234,
                    },
                    peer_address: Some(Ipv4Peer {
                        host: "127.0.0.1".into(),
                        port: 1235,
                    }),
                    target: Some(hash(&keys.public_key)),
                    reply_tx,
                })
                .expect("handshake");
            reply_rx
        };
        let mut slow = send(make_message(true));
        let fast = send(make_message(false));
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), fast)
                .await
                .expect("second handshake blocked on NAT sampling")
                .expect("reply channel")
                .is_some()
        );
        assert!(matches!(
            slow.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        server.close().await;
        dht.destroy().await.expect("destroy");
    }

    #[tokio::test]
    async fn busy_passive_punches_abort_without_a_relay_and_cannot_restart_after_rejection() {
        let runtime = UdxRuntime::new().unwrap();
        let (_task, dht, _events) = spawn(&runtime, HyperDhtConfig::default()).await.unwrap();
        let pool = SocketPool::new("127.0.0.1".into());
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut blocker = Holepuncher::new(&pool, &runtime, true, true, FIREWALL_RANDOM, tx)
            .await
            .unwrap();
        blocker.auto_sample(dht.dht()).await;
        assert!(blocker.reserve_random_punch());
        let noise = NoiseWrapResult {
            remote_public_key: [1; 32],
            tx: [2; 32],
            rx: [3; 32],
            handshake_hash: [4; 64],
            holepunch_secret: [5; 32],
            is_initiator: false,
        };
        let peer = Ipv4Peer {
            host: "127.0.0.1".into(),
            port: 1234,
        };
        let payload = SecurePayload::new(noise.holepunch_secret);
        let incoming = HolepunchPayload {
            error: ERROR_NONE,
            firewall: FIREWALL_RANDOM,
            round: 1,
            connected: false,
            punching: true,
            addresses: Some(vec![peer.clone()]),
            remote_address: None,
            token: Some([6; 32]),
            remote_token: None,
        };
        let message = HolepunchMessage {
            mode: MODE_FROM_RELAY,
            id: 1,
            peer_address: None,
            payload: payload.encrypt(&incoming).unwrap(),
        };
        for has_relay in [false, true] {
            let (events, _rx) = mpsc::unbounded_channel();
            let raced = RacedStream::new(runtime.create_random_stream().await.unwrap().1);
            let mut state = stage_server_punch(
                &runtime,
                dht.dht(),
                None,
                &noise,
                &peer.host,
                FIREWALL_RANDOM,
                1,
                raced,
                43,
                &events,
            )
            .await
            .unwrap();
            state.has_relay = has_relay;
            state.reply_socket = Some(state.socket.clone());
            let address = state.socket.local_addr().await.unwrap();
            let reply = server_punch_round(&runtime, &mut state, &message, &peer, FIREWALL_RANDOM)
                .await
                .unwrap();
            let message =
                crate::hyperdht_messages::decode_holepunch_msg_from_bytes(&reply.value).unwrap();
            let decoded = payload.decrypt(&message.payload).unwrap();
            assert_eq!(decoded.error, ERROR_TRY_LATER);
            assert!(!decoded.punching);
            assert!(state.punch_task.is_none());
            if has_relay {
                assert!(state.puncher.is_some());
                assert!(reply.socket.is_some());
                assert!(state.socket.local_addr().await.is_ok());
            } else {
                assert!(state.puncher.is_none());
                assert!(reply.socket.is_none());
                assert!(state.socket.local_addr().await.is_err());
                assert!(std::net::UdpSocket::bind(address).is_ok());
                assert!(!state.raced.abort.is_alive());
            }
        }
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut rejected = build_passive_holepunch_reply(
            FIREWALL_RANDOM,
            &pool,
            &runtime,
            &peer,
            noise.holepunch_secret,
            &message.payload,
            1,
            tx,
            Some(dht.dht()),
        )
        .await
        .unwrap();
        assert!(rejected.remote_hp.punching);
        assert!(rejected.puncher.destroyed);
        assert!(rejected.puncher.primary_socket().is_none());
        drop(blocker);
        assert!(
            !rejected.puncher.punch(&pool, &runtime).await,
            "TRY_LATER must remain rejected after the slot becomes free"
        );
        dht.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn client_error_destroys_the_staged_puncher() {
        let runtime = UdxRuntime::new().expect("runtime");
        let config = HyperDhtConfig {
            dht: DhtConfig {
                bootstrap: vec![],
                port: 0,
                ..DhtConfig::default()
            },
            ..HyperDhtConfig::default()
        };
        let (_task, dht, _events) = spawn(&runtime, config).await.expect("spawn");
        let noise = NoiseWrapResult {
            remote_public_key: [1; 32],
            tx: [2; 32],
            rx: [3; 32],
            handshake_hash: [4; 64],
            holepunch_secret: [5; 32],
            is_initiator: false,
        };
        let (events, _rx) = mpsc::unbounded_channel();
        let raced = RacedStream::new(runtime.create_stream(42).await.expect("stream"));
        let mut punch = stage_server_punch(
            &runtime,
            dht.dht(),
            None,
            &noise,
            "127.0.0.1",
            FIREWALL_UNKNOWN,
            1,
            raced,
            43,
            &events,
        )
        .await
        .expect("stage");
        punch.punch_task = Some(tokio::spawn(std::future::pending()));
        let running_probe = punch.punch_task.as_ref().unwrap().abort_handle();
        let payload = SecurePayload::new(noise.holepunch_secret);
        let message = HolepunchMessage {
            mode: MODE_FROM_RELAY,
            id: 1,
            peer_address: None,
            payload: payload
                .encrypt(&HolepunchPayload {
                    error: ERROR_ABORTED,
                    firewall: FIREWALL_UNKNOWN,
                    round: 1,
                    connected: false,
                    punching: true,
                    addresses: None,
                    remote_address: None,
                    token: None,
                    remote_token: None,
                })
                .expect("encrypt"),
        };
        let reply = server_punch_round(
            &runtime,
            &mut punch,
            &message,
            &Ipv4Peer {
                host: "127.0.0.1".into(),
                port: 1234,
            },
            FIREWALL_UNKNOWN,
        )
        .await
        .expect("abort reply");
        assert!(
            punch.puncher.is_none(),
            "client error must not start a probe loop"
        );
        tokio::task::yield_now().await;
        assert!(
            running_probe.is_finished(),
            "client error must cancel an already running probe"
        );
        assert!(reply.socket.is_none(), "aborts leave from the DHT socket");
        let decoded =
            crate::hyperdht_messages::decode_holepunch_msg_from_bytes(&reply.value).expect("reply");
        assert_eq!(
            payload.decrypt(&decoded.payload).expect("decrypt").error,
            ERROR_ABORTED
        );
        punch.abort.abort();
        dht.destroy().await.expect("destroy");
    }

    #[tokio::test]
    async fn raw_stream_registry_prunes_closed_streams() {
        let runtime = UdxRuntime::new().expect("runtime");
        let config = HyperDhtConfig {
            dht: DhtConfig {
                bootstrap: vec![],
                port: 0,
                ..DhtConfig::default()
            },
            ..HyperDhtConfig::default()
        };
        let (_task, dht, _events) = spawn(&runtime, config).await.expect("spawn");
        let first = dht
            .create_raw_stream(&runtime, RawStreamOptions::default())
            .await
            .expect("first");
        first.stream.abort_handle().abort();
        let second = dht
            .create_raw_stream(&runtime, RawStreamOptions::default())
            .await
            .expect("second");
        assert_eq!(dht.raw_streams.lock().unwrap().len(), 1);
        assert!(second.stream.abort_handle().is_alive());
        let third = dht
            .create_raw_stream(&runtime, RawStreamOptions::default())
            .await
            .expect("third");
        assert_eq!(
            dht.raw_streams.lock().unwrap().len(),
            2,
            "unconnected streams are still alive"
        );
        drop(second);
        let fourth = dht
            .create_raw_stream(&runtime, RawStreamOptions::default())
            .await
            .expect("fourth");
        assert_eq!(
            dht.raw_streams.lock().unwrap().len(),
            2,
            "dropped streams are pruned too"
        );
        assert!(third.stream.abort_handle().is_alive());
        third.stream.abort_handle().abort();
        fourth.stream.abort_handle().abort();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if dht.raw_streams.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("close must prune even without another insertion");
        dht.destroy().await.expect("destroy");
    }

    #[tokio::test]
    async fn establish_stream_missing_udx_info() {
        let runtime = libudx::UdxRuntime::new().expect("runtime");
        let nw_result = NoiseWrapResult {
            remote_public_key: [0xAA; 32],
            tx: [1; 32],
            rx: [2; 32],
            handshake_hash: [3; 64],
            holepunch_secret: [4; 32],
            is_initiator: true,
        };
        let result = ConnectResult {
            remote_public_key: [0xAA; 32],
            server_address: Ipv4Peer {
                host: "127.0.0.1".into(),
                port: 9999,
            },
            client_address: Ipv4Peer {
                host: "127.0.0.1".into(),
                port: 8888,
            },
            is_relayed: false,
            noise: nw_result,
            local_stream_id: 1,
            remote_udx: None,
            udx_socket: None,
        };
        let err = establish_stream(&result, &runtime).await.unwrap_err();
        assert!(matches!(err, HyperDhtError::StreamEstablishment(_)));
    }

    #[tokio::test]
    async fn establish_stream_bad_address() {
        let runtime = libudx::UdxRuntime::new().expect("runtime");
        let nw_result = NoiseWrapResult {
            remote_public_key: [0xBB; 32],
            tx: [1; 32],
            rx: [2; 32],
            handshake_hash: [3; 64],
            holepunch_secret: [4; 32],
            is_initiator: true,
        };
        let result = ConnectResult {
            remote_public_key: [0xBB; 32],
            server_address: Ipv4Peer {
                host: "not-an-ip".into(),
                port: 9999,
            },
            client_address: Ipv4Peer {
                host: "127.0.0.1".into(),
                port: 8888,
            },
            is_relayed: false,
            noise: nw_result,
            local_stream_id: next_stream_id(),
            remote_udx: Some(UdxInfo {
                version: 1,
                reusable_socket: true,
                id: 42,
                seq: 0,
            }),
            udx_socket: None,
        };
        let err = establish_stream(&result, &runtime).await.unwrap_err();
        assert!(matches!(err, HyperDhtError::StreamEstablishment(_)));
    }

    #[tokio::test]
    async fn establish_stream_remote_id_overflow() {
        let runtime = libudx::UdxRuntime::new().expect("runtime");
        let nw_result = NoiseWrapResult {
            remote_public_key: [0xCC; 32],
            tx: [1; 32],
            rx: [2; 32],
            handshake_hash: [3; 64],
            holepunch_secret: [4; 32],
            is_initiator: true,
        };
        let result = ConnectResult {
            remote_public_key: [0xCC; 32],
            server_address: Ipv4Peer {
                host: "127.0.0.1".into(),
                port: 9999,
            },
            client_address: Ipv4Peer {
                host: "127.0.0.1".into(),
                port: 8888,
            },
            is_relayed: false,
            noise: nw_result,
            local_stream_id: next_stream_id(),
            remote_udx: Some(UdxInfo {
                version: 1,
                reusable_socket: true,
                id: u64::from(u32::MAX) + 1,
                seq: 0,
            }),
            udx_socket: None,
        };
        let err = establish_stream(&result, &runtime).await.unwrap_err();
        assert!(matches!(err, HyperDhtError::StreamEstablishment(_)));
    }

    #[test]
    fn default_bootstrap_has_three_nodes() {
        assert_eq!(DEFAULT_BOOTSTRAP.len(), 3);
        for entry in &DEFAULT_BOOTSTRAP {
            assert!(entry.contains('@'), "missing @ in {entry}");
            assert!(entry.ends_with(":49737"), "wrong port in {entry}");
        }
    }

    #[test]
    fn with_public_bootstrap_populates_nodes() {
        let cfg = HyperDhtConfig::with_public_bootstrap();
        assert_eq!(cfg.dht.bootstrap.len(), 3);
        assert_eq!(cfg.dht.bootstrap[0], DEFAULT_BOOTSTRAP[0]);
        assert_eq!(cfg.dht.bootstrap[1], DEFAULT_BOOTSTRAP[1]);
        assert_eq!(cfg.dht.bootstrap[2], DEFAULT_BOOTSTRAP[2]);
        assert_eq!(cfg.dht.port, 0);
        assert!(cfg.dht.firewalled);
    }

    #[test]
    fn direct_connect_when_not_relayed() {
        assert!(should_direct_connect(false, FIREWALL_RANDOM, true, false));
    }

    #[test]
    fn direct_connect_when_firewall_open() {
        assert!(should_direct_connect(true, FIREWALL_OPEN, true, false));
    }

    #[test]
    fn direct_connect_when_not_holepunchable() {
        assert!(should_direct_connect(true, FIREWALL_RANDOM, false, false));
    }

    #[test]
    fn direct_connect_when_same_host() {
        assert!(should_direct_connect(true, FIREWALL_RANDOM, true, true));
    }

    #[test]
    fn holepunch_when_relayed_firewalled_holepunchable_different_host() {
        assert!(!should_direct_connect(true, FIREWALL_RANDOM, true, false));
        assert!(!should_direct_connect(
            true,
            FIREWALL_CONSISTENT,
            true,
            false
        ));
        assert!(!should_direct_connect(true, FIREWALL_UNKNOWN, true, false));
    }

    #[test]
    fn direct_connect_all_conditions_false_except_one() {
        assert!(should_direct_connect(false, FIREWALL_RANDOM, true, false));
        assert!(should_direct_connect(true, FIREWALL_OPEN, true, false));
        assert!(should_direct_connect(true, FIREWALL_RANDOM, false, false));
        assert!(should_direct_connect(true, FIREWALL_RANDOM, true, true));
    }

    // ── Scenario-matrix topology tests ───────────────────────────────────
    //
    // These map to the user-defined topology matrix:
    //   T1: both open
    //   T2: sender firewalled, receiver open
    //   T3: sender open, receiver firewalled
    //   T4: both firewalled, same network
    //   T5: both firewalled, different networks
    //   T6: one behind CGNAT
    //
    // For each topology we test the connection decision from the
    // *connector's* perspective (the one calling should_direct_connect).

    #[test]
    fn topology_both_open() {
        // T1: Neither side relayed, both FIREWALL_OPEN → direct connect
        assert!(should_direct_connect(false, FIREWALL_OPEN, true, false));
    }

    #[test]
    fn topology_sender_firewalled_receiver_open() {
        // T2: Sender is firewalled, discovered receiver via relay (relayed=true).
        // Receiver is FIREWALL_OPEN → direct connect (firewall==OPEN branch).
        assert!(should_direct_connect(true, FIREWALL_OPEN, true, false));
    }

    #[test]
    fn topology_sender_open_receiver_firewalled() {
        // T3: Sender is open. Found receiver via relay (relayed=true).
        // Receiver is firewalled (CONSISTENT), holepunchable → holepunch.
        assert!(!should_direct_connect(
            true,
            FIREWALL_CONSISTENT,
            true,
            false
        ));
        // If receiver is NOT holepunchable → direct connect (fallback).
        assert!(should_direct_connect(
            true,
            FIREWALL_CONSISTENT,
            false,
            false
        ));
    }

    #[test]
    fn topology_both_firewalled_same_network() {
        // T4: Both firewalled, same network (same_host=true).
        // same_host → direct connect regardless of firewall state.
        assert!(should_direct_connect(true, FIREWALL_RANDOM, true, true));
        assert!(should_direct_connect(true, FIREWALL_CONSISTENT, true, true));
    }

    #[test]
    fn topology_both_firewalled_different_networks() {
        // T5: Both firewalled, different networks.
        // When holepunchable → holepunch attempt.
        assert!(!should_direct_connect(true, FIREWALL_RANDOM, true, false));
        assert!(!should_direct_connect(
            true,
            FIREWALL_CONSISTENT,
            true,
            false
        ));
        // When NOT holepunchable → direct connect fallback (no HP relay).
        assert!(should_direct_connect(true, FIREWALL_RANDOM, false, false));
        assert!(should_direct_connect(
            true,
            FIREWALL_CONSISTENT,
            false,
            false
        ));
    }

    #[test]
    fn topology_one_behind_cgnat() {
        // T6: CGNAT peer is FIREWALL_RANDOM and holepunchable.
        // Non-CGNAT peer connects via relay → holepunch.
        assert!(!should_direct_connect(true, FIREWALL_RANDOM, true, false));
        // CGNAT peer with no holepunch support → direct connect fallback.
        assert!(should_direct_connect(true, FIREWALL_RANDOM, false, false));
    }

    #[tokio::test]
    async fn current_relay_addresses_starts_empty() {
        use libudx::UdxRuntime;

        let runtime = UdxRuntime::new().expect("runtime");
        let cfg = HyperDhtConfig {
            dht: crate::rpc::DhtConfig {
                bootstrap: vec![],
                ephemeral: Some(true),
                ..crate::rpc::DhtConfig::default()
            },
            ..HyperDhtConfig::default()
        };
        let (_task, handle, _rx) = spawn(&runtime, cfg).await.expect("spawn");

        assert!(
            handle.current_relay_addresses().is_empty(),
            "current_relay_addresses should be empty before any announce()"
        );
        assert!(
            handle.current_relays().is_empty(),
            "current_relays should be empty before any announce()"
        );

        let _ = handle.destroy().await;
    }

    #[tokio::test]
    async fn current_relay_addresses_is_shared_across_clones() {
        use libudx::UdxRuntime;

        let runtime = UdxRuntime::new().expect("runtime");
        let cfg = HyperDhtConfig {
            dht: crate::rpc::DhtConfig {
                bootstrap: vec![],
                ephemeral: Some(true),
                ..crate::rpc::DhtConfig::default()
            },
            ..HyperDhtConfig::default()
        };
        let (_task, handle, _rx) = spawn(&runtime, cfg).await.expect("spawn");

        let clone = handle.clone();

        {
            let mut guard = handle.current_relays.lock().expect("lock current_relays");
            *guard = vec![RelayInfo {
                relay_address: Ipv4Peer {
                    host: "1.2.3.4".to_string(),
                    port: 49737,
                },
                peer_address: Ipv4Peer {
                    host: "5.6.7.8".to_string(),
                    port: 61000,
                },
            }];
        }

        let via_clone = clone.current_relay_addresses();
        assert_eq!(via_clone.len(), 1);
        assert_eq!(via_clone[0].host, "1.2.3.4");
        assert_eq!(via_clone[0].port, 49737);

        let relays = clone.current_relays();
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0].relay_address, via_clone[0]);
        assert_eq!(relays[0].peer_address.host, "5.6.7.8");
        assert_eq!(relays[0].peer_address.port, 61000);

        let _ = handle.destroy().await;
    }

    /// Each relay is paired with our own address as that relay saw it (Node
    /// `Announcer.relays`), not with anyone else's: that is where it forwards
    /// a client's PEER_HOLEPUNCH.
    #[tokio::test]
    async fn current_relays_pair_each_relay_with_our_observed_address() {
        use libudx::UdxRuntime;

        // A reachable, persistent bootstrap node that accepts announces, and a
        // firewalled ephemeral node that announces through it.
        let local = |bootstrap: Vec<String>, firewalled: bool| HyperDhtConfig {
            dht: crate::rpc::DhtConfig {
                bootstrap,
                port: 0,
                host: "127.0.0.1".to_string(),
                firewalled,
                ephemeral: Some(firewalled),
                ..crate::rpc::DhtConfig::default()
            },
            ..HyperDhtConfig::default()
        };

        let runtime = UdxRuntime::new().expect("runtime");
        let (_bs_task, bs, _bs_rx) = spawn(&runtime, local(vec![], false))
            .await
            .expect("spawn bootstrap");
        let bs_port = bs.local_port().await.expect("bootstrap port");

        let bootstrap = vec![format!("127.0.0.1:{bs_port}")];
        let (_task, handle, _rx) = spawn(&runtime, local(bootstrap, true))
            .await
            .expect("spawn announcer");
        handle.bootstrapped().await.expect("bootstrapped");

        let key_pair = KeyPair::generate();
        handle
            .announce(hash(&key_pair.public_key), &key_pair, &[])
            .await
            .expect("announce");

        let relays = handle.current_relays();
        assert!(
            !relays.is_empty(),
            "the bootstrap node should accept the announce"
        );

        let ours = handle
            .server_socket()
            .await
            .expect("server socket")
            .expect("bound socket")
            .local_addr()
            .await
            .expect("local addr");
        for relay in &relays {
            assert_eq!(relay.relay_address.port, bs_port);
            assert_eq!(relay.peer_address.host, "127.0.0.1");
            assert_eq!(
                relay.peer_address.port,
                ours.port(),
                "peer_address must be our own address as the relay saw it"
            );
        }
        assert_eq!(
            handle.current_relay_addresses(),
            relays
                .iter()
                .map(|r| r.relay_address.clone())
                .collect::<Vec<_>>()
        );

        let _ = handle.destroy().await;
        let _ = bs.destroy().await;
    }
}

#[cfg(test)]
mod passive_holepunch_helper_tests {
    use super::*;
    use crate::hyperdht_messages::{
        FIREWALL_CONSISTENT, FIREWALL_OPEN, decode_holepunch_msg_from_bytes,
    };
    use crate::messages::Ipv4Peer;
    use crate::secure_payload::SecurePayload;
    use libudx::UdxRuntime;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn passive_holepunch_helper_roundtrip() {
        let holepunch_secret: [u8; 32] = [7u8; 32];

        let incoming_hp = HolepunchPayload {
            error: 0,
            firewall: FIREWALL_CONSISTENT,
            round: 0,
            connected: false,
            punching: true,
            addresses: Some(vec![Ipv4Peer {
                host: "10.0.0.1".to_string(),
                port: 5000,
            }]),
            remote_address: None,
            token: Some([0x42u8; 32]),
            remote_token: None,
        };

        let sp_sender = SecurePayload::new(holepunch_secret);
        let incoming_payload = sp_sender.encrypt(&incoming_hp).expect("encrypt incoming");

        let pool = SocketPool::new("0.0.0.0".to_string());
        let runtime = UdxRuntime::new().expect("UdxRuntime");
        let peer_addr = Ipv4Peer {
            host: "1.2.3.4".to_string(),
            port: 9876,
        };

        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let result = build_passive_holepunch_reply(
            FIREWALL_OPEN,
            &pool,
            &runtime,
            &peer_addr,
            holepunch_secret,
            &incoming_payload,
            0,
            event_tx,
            None,
        )
        .await
        .expect("build_passive_holepunch_reply should succeed");

        assert!(
            result.remote_hp.punching,
            "remote_hp.punching should be true"
        );
        assert_eq!(
            result.remote_hp.token,
            Some([0x42u8; 32]),
            "remote_hp.token should be present"
        );

        let decoded_msg =
            decode_holepunch_msg_from_bytes(&result.reply_bytes).expect("decode reply_bytes");

        let decoded_hp = result
            .payload
            .decrypt(&decoded_msg.payload)
            .expect("decrypt reply payload");

        assert!(
            !decoded_hp.connected,
            "decoded_hp.connected should be false"
        );
        assert!(decoded_hp.punching, "decoded_hp.punching should be true");
        assert_eq!(
            decoded_hp.remote_token,
            Some([0x42u8; 32]),
            "remote_token should be echoed in reply"
        );

        assert!(
            result.puncher.primary_socket().is_some(),
            "puncher should have a primary socket"
        );
    }
}
