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

/// bogon `isPrivate`: loopback, RFC 1918, link-local and carrier-grade NAT.
/// An unparsable host is not private, so it is never dialled as a neighbour.
fn is_private(host: &str) -> bool {
    let Ok(ip) = host.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let [a, b, ..] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (a == 100 && (64..=127).contains(&b))
}

/// bogon `isReserved`: "this" network, IETF and test nets, benchmarking,
/// multicast and the reserved/broadcast range.
fn is_reserved(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    a == 0
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 198 && (18..=19).contains(&b))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
}

/// bogon `isBogon` (`isPrivate || isReserved`), used where hyperdht picks
/// the first public address (`connect.js` `getFirstRemoteAddress`). An
/// unparsable host counts as a bogon.
fn is_bogon(host: &str) -> bool {
    let Ok(ip) = host.parse::<std::net::Ipv4Addr>() else {
        return true;
    };
    is_private(host) || is_reserved(ip)
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

/// The address a direct connect dials. Node `connect.js:543-545`: a
/// handshake that reached the server directly dials the exact address it
/// was sent to (`node`). Otherwise (`holepunch()`): the server's first
/// public address (`getFirstRemoteAddress`), else the server address.
fn direct_dial_address(
    relayed: bool,
    advertised: &[Ipv4Peer],
    node: &Ipv4Peer,
    server_address: &Ipv4Peer,
) -> Ipv4Peer {
    if !relayed {
        return node.clone();
    }
    advertised
        .iter()
        .find(|a| !is_bogon(&a.host))
        .cloned()
        .unwrap_or_else(|| server_address.clone())
}

/// The server address the LAN ping tries (`connect.js:252-256`): among
/// the non-reserved addresses it advertised, the one sharing the most
/// leading octets with one of `mine`, else the first.
fn lan_dial_address(advertised: &[Ipv4Peer], mine: &[Ipv4Peer]) -> Option<Ipv4Peer> {
    let candidates: Vec<Ipv4Peer> = advertised
        .iter()
        .filter(|a| {
            a.host
                .parse::<std::net::Ipv4Addr>()
                .is_ok_and(|ip| !is_reserved(ip))
        })
        .cloned()
        .collect();
    crate::holepuncher::match_address(mine, &candidates).or_else(|| candidates.first().cloned())
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
    /// No commit request (ANNOUNCE, PUT) succeeded. dht-rpc rejects the
    /// query with `Too few nodes responded` in this case.
    #[error("too few nodes responded")]
    TooFewNodesResponded,
    /// Our puncher found no punch strategy for this pair of NATs
    /// (hyperdht `REMOTE_NOT_HOLEPUNCHABLE`).
    #[error("remote not holepunchable")]
    RemoteNotHolepunchable,
    /// Probe rounds ended with our NAT class or the remote's still unknown
    /// (hyperdht `HOLEPUNCH_PROBE_TIMEOUT`).
    #[error("holepunch probe timed out")]
    HolepunchProbeTimeout,
    /// Both NATs map each destination to a new port, so no punch strategy
    /// can work (hyperdht `HOLEPUNCH_DOUBLE_RANDOMIZED_NATS`).
    #[error("holepunch double randomized NATs")]
    HolepunchDoubleRandomizedNats,
    /// A holepunch round's reply carried a non-zero error code
    /// (hyperdht `REMOTE_ABORTED`).
    #[error("remote aborted with error code {0}")]
    RemoteAborted(u64),
    /// The punch round's reply said the remote is not punching
    /// (hyperdht `REMOTE_NOT_HOLEPUNCHING`).
    #[error("remote not holepunching")]
    RemoteNotHolepunching,
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

/// Decides whether a server answers a peer's handshake (Node
/// `createServer({ firewall(remotePublicKey, remotePayload, clientAddress) })`).
///
/// `true` refuses the peer, as in Node. The hook runs after the client's
/// Noise message is verified and before any reply, puncher, relay token or
/// stream exists, so a refused peer gets no reply at all. The address is the
/// client's address as the server sees it: the relayed `peer_address`, or
/// the sender of a direct handshake. A hook that panics refuses the peer
/// (Node fails closed when its firewall throws).
pub type PeerFirewall = Arc<dyn Fn(&[u8; 32], &NoisePayload, &Ipv4Peer) -> bool + Send + Sync>;

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
    /// Refuse peers by public key before replying (Node `firewall`).
    /// `None` answers every peer.
    pub peer_firewall: Option<PeerFirewall>,
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
            peer_firewall: None,
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
            peer_firewall: None,
        }
    }

    /// Whether [`Self::peer_firewall`] refuses the client of `nw`, whose
    /// message 1 has been received. Node `server.js:269-278`: no reply when
    /// the firewall says so or throws.
    fn refuses(&self, nw: &NoiseWrap, payload: &NoisePayload, client: &Ipv4Peer) -> bool {
        let Some(firewall) = &self.peer_firewall else {
            return false;
        };
        let Some(remote_public_key) = nw.remote_public_key() else {
            return true;
        };
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            firewall(&remote_public_key, payload, client)
        }))
        .unwrap_or(true)
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

/// Keep-alive interval for every connection's secret stream, hyperdht's
/// `connectionKeepAlive` default (5000 ms).
pub const DEFAULT_CONNECTION_KEEP_ALIVE: std::time::Duration =
    std::time::Duration::from_millis(5000);

#[derive(Debug, Clone)]
/// Configuration for a HyperDHT instance.
#[non_exhaustive]
pub struct HyperDhtConfig {
    /// DHT transport and bootstrap settings.
    pub dht: DhtConfig,
    /// Persistent storage settings for stored records.
    pub persistent: PersistentConfig,
    /// Interval of the empty keep-alive message every connection made by
    /// `connect` or accepted by a server sends when it wrote nothing for
    /// that long ([`SecretStream::set_keep_alive`]). `None` turns it off
    /// (Node `connectionKeepAlive: false`). Default
    /// [`DEFAULT_CONNECTION_KEEP_ALIVE`].
    pub connection_keep_alive: Option<std::time::Duration>,
}

impl Default for HyperDhtConfig {
    fn default() -> Self {
        Self {
            dht: DhtConfig::default(),
            persistent: PersistentConfig::default(),
            connection_keep_alive: Some(DEFAULT_CONNECTION_KEEP_ALIVE),
        }
    }
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
            ..Self::default()
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
    /// [`HyperDhtConfig::connection_keep_alive`].
    connection_keep_alive: Option<std::time::Duration>,
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
        // dht-rpc runs our commit callback instead of re-sending the
        // LOOKUP, so the query itself does not commit.
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

        let closest_nodes: Vec<Ipv4Peer> = replies.iter().map(|r| r.from.clone()).collect();
        // Stored record uses caller-provided relays verbatim, matching
        // Node `_requestAnnounce`: `ann.peer.relayAddresses = relayAddresses || []`.
        // Closest-ack accumulation lives only in handle-state
        // (`current_relay_addresses` below) for *subsequent* announces
        // to consume — it is NEVER written into a stored peer record.
        // Do not "fix" this by re-adding per-record accumulation; the
        // TOPIC-close nodes don't hold FE for `hash(pk)`, so advertising
        // them as PEER_HANDSHAKE relays yields "empty reply".
        let peer = HyperPeer {
            public_key: key_pair.public_key,
            relay_addresses: relay_addresses.iter().take(3).cloned().collect(),
        };
        let peer_encoded = encode_hyper_peer_to_bytes(&peer)?;

        let mut commits = Vec::new();
        let mut committed: Vec<&QueryReply> = Vec::new();
        for reply in &replies {
            let (Some(token), Some(node_id)) = (reply.token, reply.from_id) else {
                continue;
            };
            let signable =
                ann_signable(&target, &token, &node_id, &peer_encoded, &[], &NS_ANNOUNCE);
            let signature = sign_detached(&signable, &key_pair.secret_key);

            let ann = AnnounceMessage {
                peer: Some(peer.clone()),
                refresh: None,
                signature: Some(signature),
                bump: 0,
                // hyperdht `announce`: ask again for peers when the lookup
                // reply had none, in case some arrived in between.
                lookup: reply.value.is_none(),
            };
            commits.push((
                reply.from.clone(),
                UserRequestParams {
                    token: Some(token),
                    command: ANNOUNCE,
                    target: Some(target),
                    value: Some(encode_announce_to_bytes(&ann)?),
                    timeout_ms: None,
                    retries: None,
                },
            ));
            committed.push(reply);
        }

        let results = commit_concurrently(&self.dht, commits).await;
        if !results
            .iter()
            .any(|r| matches!(r, Ok(res) if res.error == 0))
        {
            return Err(HyperDhtError::TooFewNodesResponded);
        }

        // Node `Announcer._commit` adds a node to the relays only after its
        // ANNOUNCE resolved: `relays.push({ relayAddress: msg.from,
        // peerAddress: msg.to })`, capped at 3.
        let accepted_relays: Vec<RelayInfo> = committed
            .iter()
            .zip(&results)
            .filter(|(_, r)| matches!(r, Ok(res) if res.error == 0))
            .take(3)
            .map(|(reply, _)| RelayInfo {
                relay_address: reply.from.clone(),
                peer_address: reply.to.clone(),
            })
            .collect();

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
                lookup: false,
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
                commit: false,
                concurrency: None,
            })
            .await?;

        let closest_nodes: Vec<Ipv4Peer> = replies.iter().map(|r| r.from.clone()).collect();
        let commits = replies
            .iter()
            .filter_map(|reply| {
                let token = reply.token?;
                Some((
                    reply.from.clone(),
                    UserRequestParams {
                        token: Some(token),
                        command: IMMUTABLE_PUT,
                        target: Some(target),
                        value: Some(value.to_vec()),
                        timeout_ms: None,
                        retries: None,
                    },
                ))
            })
            .collect();
        let results = commit_concurrently(&self.dht, commits).await;
        if !results
            .iter()
            .any(|r| matches!(r, Ok(res) if res.error == 0))
        {
            return Err(HyperDhtError::TooFewNodesResponded);
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
                commit: false,
                concurrency: None,
            })
            .await?;

        let closest_nodes: Vec<Ipv4Peer> = replies.iter().map(|r| r.from.clone()).collect();
        let commits = replies
            .iter()
            .filter_map(|reply| {
                let token = reply.token?;
                Some((
                    reply.from.clone(),
                    UserRequestParams {
                        token: Some(token),
                        command: MUTABLE_PUT,
                        target: Some(target),
                        value: Some(put_bytes.clone()),
                        timeout_ms: None,
                        retries: None,
                    },
                ))
            })
            .collect();
        let results = commit_concurrently(&self.dht, commits).await;
        if !results
            .iter()
            .any(|r| matches!(r, Ok(res) if res.error == 0))
        {
            return Err(HyperDhtError::TooFewNodesResponded);
        }
        let commit_timeouts = results
            .iter()
            .filter(|r| matches!(r, Err(DhtError::RequestFailed(_))))
            .count() as u32;

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
    /// are appended once [`Self::validate_local_addresses`] passes them.
    /// Order matters: the receiver iterates this list sequentially and
    /// LAN-special-cases on its side.
    pub async fn noise_addresses4(&self, port: u16) -> Vec<crate::messages::Ipv4Peer> {
        let mut out = Vec::new();
        if let Ok(Some(remote)) = self.remote_address().await {
            out.push(remote);
        }
        let bound = match self.server_socket().await {
            Ok(Some(socket)) => socket.local_addr().await.ok(),
            _ => None,
        };
        let local = match bound.map(|addr| addr.ip()) {
            Some(std::net::IpAddr::V4(ip)) if !ip.is_unspecified() => vec![Ipv4Peer {
                host: ip.to_string(),
                port,
            }],
            _ => crate::holepuncher::Holepuncher::local_addresses(port),
        };
        out.extend(self.validate_local_addresses(local).await);
        out
    }

    /// hyperdht `validateLocalAddresses`: the addresses whose host a fresh
    /// socket can bind and hear its own packet on within 500 ms. Each
    /// host's verdict is cached for the life of the node.
    pub async fn validate_local_addresses(&self, addresses: Vec<Ipv4Peer>) -> Vec<Ipv4Peer> {
        self.dht.validate_local_addresses(addresses).await
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
        let hs = self
            .start_handshake(key_pair, &remote_public_key, runtime, &opts)
            .await?;
        let mut last_err = HyperDhtError::NoRelayNodes;
        let mut tried: Vec<Ipv4Peer> = Vec::new();

        // Node `findAndConnect`: every candidate gets the same handshake,
        // up to 3 at once while relay hints are tried and 2 afterwards; the
        // first valid reply wins and only that one is punched.
        if let Some(won) = self
            .race_handshakes(&hs, relay_addresses.to_vec(), 3, &mut tried, &mut last_err)
            .await
        {
            return self.finish_connect(key_pair, hs, won, runtime, &opts).await;
        }

        // FIND_PEER responders hold the forward entry; the relays named in
        // their records come next.
        let peer_replies = self.query_find_peer(hs.target).await.unwrap_or_else(|e| {
            tracing::debug!(err = %e, "connect: FIND_PEER query failed");
            Vec::new()
        });
        let mut candidates: Vec<Ipv4Peer> = peer_replies
            .iter()
            .filter(|r| r.value.is_some())
            .map(|r| r.from.clone())
            .collect();
        for reply in &peer_replies {
            if let Some(peer) = reply
                .value
                .as_deref()
                .and_then(|v| decode_hyper_peer_from_bytes(v).ok())
            {
                candidates.extend(peer.relay_addresses);
            }
        }
        if let Some(won) = self
            .race_handshakes(&hs, candidates, 2, &mut tried, &mut last_err)
            .await
        {
            return self.finish_connect(key_pair, hs, won, runtime, &opts).await;
        }

        // Rust fallback: nodes close to the target that did not return a
        // record (e.g. mid-refresh).
        let node_replies = self
            .dht
            .find_node(hs.target)
            .await
            .map_err(HyperDhtError::Dht)?;
        if relay_addresses.is_empty() && peer_replies.is_empty() && node_replies.is_empty() {
            return Err(HyperDhtError::PeerNotFound);
        }
        let mut candidates: Vec<Ipv4Peer> = Vec::new();
        for reply in &node_replies {
            candidates.push(reply.from.clone());
            candidates.extend(reply.closer_nodes.iter().cloned());
        }
        if let Some(won) = self
            .race_handshakes(&hs, candidates, 2, &mut tried, &mut last_err)
            .await
        {
            return self.finish_connect(key_pair, hs, won, runtime, &opts).await;
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
        let opts = ConnectOpts::default();
        let hs = self
            .start_handshake(key_pair, &remote_public_key, runtime, &opts)
            .await?;
        let mut last_err = HyperDhtError::NoRelayNodes;
        let won = self
            .race_handshakes(&hs, vec![relay], 1, &mut Vec::new(), &mut last_err)
            .await
            .ok_or(last_err)?;
        self.finish_connect(key_pair, hs, won, runtime, &opts).await
    }

    /// Build the one Noise handshake every candidate node receives
    /// (Node `connectThroughNode` sends the same `c.request` to each).
    async fn start_handshake(
        &self,
        key_pair: &KeyPair,
        remote_public_key: &[u8; 32],
        runtime: &UdxRuntime,
        opts: &ConnectOpts,
    ) -> Result<ClientHandshake, HyperDhtError> {
        let target = hash(remote_public_key);
        let mut nw = NoiseWrap::new_initiator(key_pair.to_noise_keypair(), *remote_public_key);

        let (local_stream_id, local_stream) = runtime.create_random_stream().await?;
        self.track_raw_stream(local_stream.abort_handle());

        // Advertise our reflexive address (if known) + local IPv4
        // interface addresses. Mirrors Node `lib/connect.js:420-437`. The
        // receiver sequentially probes this list and applies its own
        // LAN-special-case filtering — see `hyperdht/lib/server.js:426`.
        // Node `connectThroughNode`: our address only when the DHT says it
        // is reachable (`dht.remoteAddress()` is null while firewalled), and
        // local interfaces only with `localConnection`. A firewalled client
        // that advertised its reflexive 127.0.0.1/LAN address made a
        // hyperdht 6.30 server pick its LAN shortcut, which stages no puncher
        // and answers no holepunch round.
        let reachable = self.dht.reachable().await.unwrap_or(false);
        let remote = self.remote_address().await.ok().flatten();
        let mut client_addresses4 = Vec::new();
        if opts.local_connection {
            if let Ok(port) = self.dht.local_port().await {
                client_addresses4 = self.noise_addresses4(port).await;
            }
            if !reachable {
                client_addresses4.retain(|a| Some(a) != remote.as_ref());
            }
        } else if reachable {
            client_addresses4.extend(remote.clone());
        }

        // Node `connect.js:455`: a client-chosen relay rides in the handshake
        // with a fresh pairing token.
        let relay_token: Option<[u8; 32]> = opts.relay_through.map(|_| random());
        // `connect.js:441`: OPEN when `dht.remoteAddress()` is known, which
        // it is only for a reachable node.
        let open = reachable && remote.is_some();

        let local_payload = NoisePayload {
            version: 1,
            error: 0,
            firewall: if open {
                FIREWALL_OPEN
            } else {
                FIREWALL_UNKNOWN
            },
            holepunch: None,
            addresses4: client_addresses4,
            addresses6: vec![],
            udx: Some(UdxInfo {
                version: 1,
                // No socket route table exists yet, so a cached route to
                // this socket would be dead (hyperdht `socket-pool.js`).
                reusable_socket: false,
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
        let value = Router::encode_client_handshake(noise_bytes, None, None)?;
        Ok(ClientHandshake {
            nw,
            value,
            target,
            local_stream_id,
            local_stream,
            relay_token,
            open,
        })
    }

    /// Send the handshake to `candidates`, `concurrency` at a time (Node's
    /// `Semaphore`), and return the first node whose reply passes the
    /// router check. Every other attempt is cancelled.
    async fn race_handshakes(
        &self,
        hs: &ClientHandshake,
        candidates: Vec<Ipv4Peer>,
        concurrency: usize,
        tried: &mut Vec<Ipv4Peer>,
        last_err: &mut HyperDhtError,
    ) -> Option<HandshakeWin> {
        let mut pending = candidates.into_iter();
        let mut running = tokio::task::JoinSet::new();
        loop {
            while running.len() < concurrency {
                let Some(node) = pending.next() else { break };
                if tried.contains(&node) {
                    continue;
                }
                tried.push(node.clone());
                let dht = self.dht.clone();
                let params = UserRequestParams {
                    token: None,
                    command: PEER_HANDSHAKE,
                    target: Some(hs.target),
                    value: Some(hs.value.clone()),
                    timeout_ms: Some(10000),
                    retries: Some(0),
                };
                running.spawn(async move {
                    let resp = dht.request(params, &node.host, node.port).await;
                    (node, resp)
                });
            }
            let (node, resp) = match running.join_next().await? {
                Ok(done) => done,
                Err(_) => continue,
            };
            let checked = resp.map_err(HyperDhtError::from).and_then(|resp| {
                if resp.error != 0 {
                    return Err(HyperDhtError::HandshakeFailed(format!(
                        "error code {}",
                        resp.error
                    )));
                }
                let value = resp
                    .value
                    .ok_or_else(|| HyperDhtError::HandshakeFailed("empty reply".into()))?;
                let router = self
                    .router
                    .lock()
                    .map_err(|_| HyperDhtError::ChannelClosed)?;
                let hs_result =
                    router.validate_handshake_reply(&value, &node, &resp.from, &resp.to)?;
                drop(router);
                // Each reply opens its own copy of the initiator state, so a
                // reply that fails Noise only fails its own attempt (npm
                // shares one state, so a bogus reply spoils the rest).
                let mut nw = hs.nw.clone();
                let payload = nw.recv(&hs_result.noise)?;
                Ok(HandshakeWin {
                    node: node.clone(),
                    hs_result,
                    nw,
                    payload,
                })
            });
            match checked {
                Ok(win) => {
                    running.abort_all();
                    return Some(win);
                }
                Err(err) => {
                    tracing::debug!(
                        node = %format!("{}:{}", node.host, node.port),
                        err = %err,
                        "handshake candidate failed"
                    );
                    *last_err = err;
                }
            }
        }
    }

    /// The rest of Node's `connectThroughNode` + `holepunch` once one
    /// candidate answered: open the Noise reply and race the direct path
    /// (and a relay, if any) for the stream.
    async fn finish_connect(
        &self,
        key_pair: &KeyPair,
        hs: ClientHandshake,
        won: HandshakeWin,
        runtime: &UdxRuntime,
        opts: &ConnectOpts,
    ) -> Result<PeerConnection, HyperDhtError> {
        let ClientHandshake {
            nw: _,
            target,
            local_stream_id,
            local_stream,
            relay_token,
            open,
            ..
        } = hs;
        let HandshakeWin {
            node,
            hs_result,
            nw,
            payload: remote_payload,
        } = won;
        let relay = &node;

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
        let raced = RacedStream::with_keep_alive(local_stream, self.connection_keep_alive);
        // `connect.js:243-245`: an OPEN client of a relayed, punching server
        // waits for the server to dial it (the server dials every OPEN
        // client) instead of punching.
        let server_dial = if open
            && hs_result.relayed
            && remote_payload.firewall != FIREWALL_OPEN
            && remote_payload
                .holepunch
                .as_ref()
                .is_some_and(|hp| !hp.relays.is_empty())
        {
            Some(self.arm_server_dial(&raced, remote_id).await?)
        } else {
            None
        };
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
            server_dial,
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

/// The candidate whose reply passed both the router check and Noise, with
/// the initiator state that opened it.
struct HandshakeWin {
    node: Ipv4Peer,
    hs_result: crate::router::HandshakeResult,
    nw: NoiseWrap,
    payload: NoisePayload,
}

/// The client's one Noise handshake, shared by every candidate node.
struct ClientHandshake {
    nw: NoiseWrap,
    /// Encoded PEER_HANDSHAKE request value.
    value: Vec<u8>,
    target: [u8; 32],
    local_stream_id: u32,
    local_stream: libudx::UdxStream,
    relay_token: Option<[u8; 32]>,
    /// We told the server we are OPEN (`c.firewall`).
    open: bool,
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
    /// Packets from a server dialling us (we said OPEN), from the hook on
    /// our DHT sockets; `None` when we punch instead.
    server_dial: Option<mpsc::UnboundedReceiver<(UdxSocket, SocketAddr)>>,
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
            server_dial,
        } = self;
        let this = &dht;
        let relay = &node;

        // Node `holepunch`: dial at once when the server is open, or when
        // the handshake was relayed but the server cannot punch.
        let remote_holepunchable = remote_payload
            .holepunch
            .as_ref()
            .is_some_and(|hp| !hp.relays.is_empty());

        tracing::debug!(
            relayed = hs_result.relayed,
            firewall = remote_payload.firewall,
            remote_holepunchable,
            server_address = %format!("{}:{}", hs_result.server_address.host, hs_result.server_address.port),
            "handshake complete, deciding connection path"
        );

        if should_direct_connect(
            hs_result.relayed,
            remote_payload.firewall,
            remote_holepunchable,
            false,
        ) {
            let connect_addr = direct_dial_address(
                hs_result.relayed,
                &remote_payload.addresses4,
                relay,
                &hs_result.server_address,
            );
            tracing::debug!(
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

        if let Some(mut seen) = server_dial {
            /// `connect.js:244`: `passiveConnectTimeout`.
            const PASSIVE_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
            return match tokio::time::timeout(PASSIVE_CONNECT_TIMEOUT, seen.recv()).await {
                Ok(Some((socket, addr))) => Ok(Landing {
                    socket,
                    remote_id,
                    addr,
                    relay: None,
                }),
                _ => Err(HyperDhtError::HolepunchAborted),
            };
        }

        // Node `connect.js:248-276`: behind the same public host, ping the
        // server's LAN address while the punch runs; whichever answers
        // first carries the stream. A LAN ping that fails is not fatal.
        let server_socket = this.server_socket().await?;
        let lan_addr =
            if local_connection && hs_result.client_address.host == hs_result.server_address.host {
                let mine = match &server_socket {
                    Some(socket) => match socket.local_addr().await {
                        Ok(addr) if addr.ip() == std::net::Ipv4Addr::LOCALHOST => vec![Ipv4Peer {
                            host: addr.ip().to_string(),
                            port: addr.port(),
                        }],
                        Ok(addr) => crate::holepuncher::Holepuncher::local_addresses(addr.port()),
                        Err(_) => Vec::new(),
                    },
                    None => Vec::new(),
                };
                lan_dial_address(&remote_payload.addresses4, &mine)
            } else {
                None
            };
        let lan_ping = async {
            let addr = lan_addr?;
            this.dht.ping(&addr.host, addr.port).await.ok()?;
            Some(addr)
        };
        tokio::pin!(lan_ping);
        let mut lan_pending = true;

        let server_address = hs_result.server_address.clone();
        let punch = this.run_holepunch_rounds(
            &nw_result,
            &remote_payload,
            relay,
            &target,
            &server_address,
            runtime,
            local_stream_id,
            has_relay,
        );
        tokio::pin!(punch);
        let hp_result = loop {
            tokio::select! {
                lan = &mut lan_ping, if lan_pending => {
                    lan_pending = false;
                    if let Some(addr) = lan {
                        tracing::debug!(addr = %format!("{}:{}", addr.host, addr.port), "LAN ping won");
                        return Ok(Landing {
                            socket: socket_or_new(server_socket, runtime).await?,
                            remote_id,
                            addr: to_socket_addr(&addr)?,
                            relay: None,
                        });
                    }
                }
                punched = &mut punch => break punched?,
            }
        };
        let socket = match hp_result.udx_socket.clone() {
            Some(s) => s,
            None => socket_or_new(server_socket, runtime).await?,
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
    /// Hear a server dialling us on either DHT socket (npm's raw stream
    /// `firewall` hook sees every socket of its UDX instance).
    async fn arm_server_dial(
        &self,
        raced: &Arc<RacedStream>,
        remote_id: u32,
    ) -> Result<mpsc::UnboundedReceiver<(UdxSocket, SocketAddr)>, HyperDhtError> {
        let socket = self
            .server_socket()
            .await?
            .ok_or_else(|| HyperDhtError::StreamEstablishment("no DHT server socket".into()))?;
        let listen = self.listen_socket().await.ok().flatten();
        let (seen_tx, seen_rx) = mpsc::unbounded_channel();
        let pending = Arc::downgrade(raced);
        raced.with_stream(|stream| {
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
            if let Some(listen) = &listen {
                stream.listen_on(listen)?;
            }
            Ok(())
        })?;
        Ok(seen_rx)
    }

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

    /// Node `holepunch(c, opts)` from the puncher on: `probeRound`, then
    /// `roundPunch`, then wait for the puncher to land a probe.
    #[allow(clippy::too_many_arguments)]
    async fn run_holepunch_rounds(
        &self,
        nw_result: &NoiseWrapResult,
        remote_payload: &NoisePayload,
        relay: &Ipv4Peer,
        target: &[u8; 32],
        server_address: &Ipv4Peer,
        runtime: &UdxRuntime,
        local_stream_id: u32,
        has_relay: bool,
    ) -> Result<ConnectResult, HyperDhtError> {
        /// Rust bound on the whole punch, rounds and landing included.
        /// Random-NAT punching runs up to 1750 probes at 20 ms (~35 s), plus
        /// initial probe/punch rounds, so keep the safety ceiling above that.
        const HOLEPUNCH_TOTAL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(45);

        // hyperdht's socket pool binds to the DHT host (`index.js` `SocketPool`).
        let host = match self.server_socket().await {
            Ok(Some(socket)) => socket.local_addr().await.ok().map(|a| a.ip().to_string()),
            _ => None,
        };
        let pool = SocketPool::new(host.unwrap_or_else(|| "0.0.0.0".into()));
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        // The puncher's NAT starts OPEN on a reachable node, as hyperdht
        // builds it with `dht.firewalled` (`holepuncher.js:19`).
        let firewalled = !self.dht.reachable().await.unwrap_or(false);
        let mut puncher = Holepuncher::new(
            &pool,
            runtime,
            firewalled,
            true,
            remote_payload.firewall,
            event_tx,
        )
        .await
        .map_err(|_| HyperDhtError::HolepunchFailed)?;
        // `holepuncher.js:20`: sample the puncher socket's own mapping.
        let added = puncher.auto_sample(&self.dht).await;
        tracing::debug!(
            added,
            firewall = puncher.nat.firewall,
            "initiator auto_sample"
        );

        // Every exit below drops `punch`, which destroys the puncher.
        let mut punch = ClientPunch {
            dht: self,
            sp: SecurePayload::new(nw_result.holepunch_secret),
            hp_id: remote_payload.holepunch.as_ref().map_or(0, |hp| hp.id),
            target: *target,
            round: 0,
            puncher,
            has_relay,
            deadline: tokio::time::Instant::now() + HOLEPUNCH_TOTAL_DEADLINE,
        };
        let server_relay = pick_server_relay(remote_payload, relay, server_address);
        let (token, peer_address) = punch.probe_round(server_address, &server_relay).await?;
        // `connect.js:310-317`: through the same relay, the server's newer
        // socket is where the punch round goes.
        let mut server_address = server_address.clone();
        if server_relay.relay_address == *relay && peer_address != server_address {
            server_address = peer_address;
            punch.puncher.open_session(&server_address);
        }
        punch
            .round_punch(&server_address, token, relay, &server_relay)
            .await?;
        let deadline = punch.deadline;
        let puncher = &mut punch.puncher;

        // `roundPunch`: `if (!(await c.puncher.punch())) throw
        // REMOTE_NOT_HOLEPUNCHABLE()`; the connection lands through the
        // puncher's probe hook (Connected) or the puncher gives up (Aborted).
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
                punched = punch_fut.as_mut(), if !punch_done => {
                    if !punched {
                        return Err(HyperDhtError::RemoteNotHolepunchable);
                    }
                    punch_done = true;
                    tracing::debug!("local punch loop completed, awaiting Connected event");
                }
                _ = deadline_sleep.as_mut() => {
                    tracing::debug!("punch deadline elapsed");
                    return Err(HyperDhtError::HolepunchFailed);
                }
            }
        }
    }
}

/// A relay node and the address it forwards a holepunch round to
/// (`connect.js` `serverRelay`).
struct RelayPair {
    relay_address: Ipv4Peer,
    peer_address: Ipv4Peer,
}

/// Node `pickServerRelay`: the server's announce relay we already went
/// through, else its first one. A server without relays (not
/// holepunchable, never punched by `connect`) falls back to our relay.
fn pick_server_relay(
    remote_payload: &NoisePayload,
    client_relay: &Ipv4Peer,
    server_address: &Ipv4Peer,
) -> RelayPair {
    let relays = remote_payload
        .holepunch
        .as_ref()
        .map_or(&[][..], |hp| hp.relays.as_slice());
    relays
        .iter()
        .find(|r| r.relay_address == *client_relay)
        .or_else(|| relays.first())
        .map_or_else(
            || RelayPair {
                relay_address: client_relay.clone(),
                peer_address: server_address.clone(),
            },
            |r| RelayPair {
                relay_address: r.relay_address.clone(),
                peer_address: r.peer_address.clone(),
            },
        )
}

/// One opened PEER_HOLEPUNCH reply (`connect.js` `updateHolepunch`).
struct RoundReply {
    try_later: bool,
    from: Ipv4Peer,
    to: Ipv4Peer,
    peer_address: Ipv4Peer,
    payload: HolepunchPayload,
}

/// The client's holepunch state across rounds (the `c` of `connect.js`).
struct ClientPunch<'a> {
    dht: &'a HyperDhtHandle,
    sp: SecurePayload,
    hp_id: u64,
    target: [u8; 32],
    /// `c.round`: one counter for every round we send.
    round: u64,
    puncher: Holepuncher,
    /// `c.relayToken`: a relay can carry us while the punch waits.
    has_relay: bool,
    deadline: tokio::time::Instant,
}

impl ClientPunch<'_> {
    /// A round payload with our current NAT view; `round` is `c.round++`.
    async fn payload(
        &mut self,
        punching: bool,
        remote_address: Option<Ipv4Peer>,
        token: Option<[u8; 32]>,
        remote_token: Option<[u8; 32]>,
    ) -> HolepunchPayload {
        let round = self.round;
        self.round += 1;
        let addresses = match self.puncher.socket() {
            Some(socket) => match socket.local_addr().await {
                Ok(addr) => self.puncher.advertised_addresses(addr.port()).await,
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };
        HolepunchPayload {
            error: ERROR_NONE,
            firewall: self.puncher.nat.firewall,
            round,
            connected: false,
            punching,
            addresses: Some(addresses),
            remote_address,
            token,
            remote_token,
        }
    }

    /// Node `updateHolepunch`: send one round from the puncher socket
    /// through `relay` and feed the reply to the puncher.
    async fn update_holepunch(
        &mut self,
        peer_address: &Ipv4Peer,
        relay: &Ipv4Peer,
        payload: HolepunchPayload,
    ) -> Result<RoundReply, HyperDhtError> {
        let socket = self
            .puncher
            .socket()
            .ok_or(HyperDhtError::HolepunchFailed)?;
        // Node `peerHolepunch`: the relay forwards to `peerAddress`.
        let value = Router::encode_client_holepunch(
            self.hp_id,
            self.sp.encrypt(&payload)?,
            Some(peer_address.clone()),
        )?;
        let resp = self
            .dht
            .dht
            .request_via_socket(
                UserRequestParams {
                    token: None,
                    command: PEER_HOLEPUNCH,
                    target: Some(self.target),
                    value: Some(value),
                    timeout_ms: None,
                    retries: None,
                },
                relay.clone(),
                socket,
            )
            .await?;
        if resp.error != 0 {
            return Err(HyperDhtError::HolepunchFailed);
        }
        let hp = self
            .dht
            .router
            .lock()
            .map_err(|_| HyperDhtError::ChannelClosed)?
            .validate_holepunch_reply(
                resp.value.as_deref().unwrap_or_default(),
                relay,
                &resp.from,
                &resp.to,
            )?;
        let remote = self.sp.decrypt(&hp.payload)?;
        let reply = |payload| RoundReply {
            try_later: false,
            from: hp.from.clone(),
            to: hp.to.clone(),
            peer_address: hp.peer_address.clone(),
            payload,
        };
        if remote.error == ERROR_TRY_LATER && self.has_relay && payload.punching {
            return Ok(RoundReply {
                try_later: true,
                ..reply(remote)
            });
        }
        if remote.error != ERROR_NONE {
            return Err(HyperDhtError::RemoteAborted(remote.error));
        }
        let echoed = remote.remote_token.is_some() && remote.remote_token == payload.token;
        self.puncher.update_remote(
            remote.punching,
            remote.firewall,
            remote.addresses.as_deref().unwrap_or_default(),
            echoed.then_some(peer_address.host.as_str()),
        );
        Ok(reply(remote))
    }

    /// Node `probeRound`: learn the server's NAT and token, rerolling an
    /// unstable puncher socket. Returns the server's token and the address
    /// the relay forwarded to.
    async fn probe_round(
        &mut self,
        server_address: &Ipv4Peer,
        server_relay: &RelayPair,
    ) -> Result<(Option<[u8; 32]>, Ipv4Peer), HyperDhtError> {
        let mut retry = true;
        loop {
            // A low-TTL packet opens our NAT toward the server first.
            self.puncher.open_session(server_address);
            let payload = self
                .payload(false, Some(server_address.clone()), None, None)
                .await;
            let reply = self
                .update_holepunch(
                    &server_relay.peer_address,
                    &server_relay.relay_address,
                    payload,
                )
                .await?;
            // Our own mapping as the relay saw it, never the server's.
            self.puncher.nat.add(&reply.to, &reply.from);
            // (`connect.js:627-636` reads `reply.payload.address`, a field
            // the payload does not have, so its second openSession never
            // runs.)

            // Give a server that does not know its NAT yet a moment.
            if self.puncher.remote_firewall == FIREWALL_UNKNOWN {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }

            let mut stable = self.analyze(false).await;
            if !stable {
                // Reroll the socket (mobile NATs); a stable new one probes again.
                stable = self.analyze(true).await;
                if stable {
                    retry = false;
                    continue;
                }
            }
            if (self.puncher.remote_firewall == FIREWALL_UNKNOWN || reply.payload.token.is_none())
                && retry
            {
                retry = false;
                continue;
            }
            if self.puncher.remote_firewall == FIREWALL_UNKNOWN
                || self.puncher.nat.firewall == FIREWALL_UNKNOWN
            {
                return self
                    .abort(server_relay, HyperDhtError::HolepunchProbeTimeout)
                    .await;
            }
            if self.puncher.remote_firewall >= crate::hyperdht_messages::FIREWALL_RANDOM
                && self.puncher.nat.firewall >= crate::hyperdht_messages::FIREWALL_RANDOM
            {
                return self
                    .abort(server_relay, HyperDhtError::HolepunchDoubleRandomizedNats)
                    .await;
            }
            return Ok((reply.payload.token, reply.peer_address));
        }
    }

    /// `puncher.analyze`, bounded by our deadline.
    async fn analyze(&mut self, allow_reopen: bool) -> bool {
        tokio::time::timeout_at(self.deadline, self.puncher.analyze(allow_reopen))
            .await
            .unwrap_or(false)
    }

    /// Node `abort`: tell the server we gave up, then fail with `err`.
    async fn abort<T>(
        &mut self,
        server_relay: &RelayPair,
        err: HyperDhtError,
    ) -> Result<T, HyperDhtError> {
        let round = self.round;
        self.round += 1;
        let payload = HolepunchPayload {
            error: ERROR_ABORTED,
            firewall: FIREWALL_UNKNOWN,
            round,
            connected: false,
            punching: false,
            addresses: None,
            remote_address: None,
            token: None,
            remote_token: None,
        };
        let _ = self
            .update_holepunch(
                &server_relay.peer_address,
                &server_relay.relay_address,
                payload,
            )
            .await;
        self.puncher.destroy();
        Err(err)
    }

    /// Node `roundPunch`: wait for the random-punch budget, then send the
    /// one `punching` round.
    async fn round_punch(
        &mut self,
        server_address: &Ipv4Peer,
        remote_token: Option<[u8; 32]>,
        client_relay: &Ipv4Peer,
        server_relay: &RelayPair,
    ) -> Result<(), HyperDhtError> {
        // We gossip our final NAT view now; keep it fixed.
        self.puncher.nat.freeze();
        let token = self.sp.token(&server_address.host);
        let mut delayed = false;
        loop {
            while !self.puncher.reserve_random_punch() {
                // Without a relay to carry us, waiting is pointless.
                if !self.has_relay {
                    return Err(HyperDhtError::HolepunchAborted);
                }
                if !delayed {
                    delayed = true;
                    let payload = self.payload(false, None, Some(token), remote_token).await;
                    self.update_holepunch(server_address, client_relay, payload)
                        .await?;
                }
                if !self
                    .puncher
                    .retry_random_punch(self.has_relay, self.deadline)
                    .await
                {
                    return Err(HyperDhtError::HolepunchAborted);
                }
            }
            // A delayed punch goes through the server's chosen relay.
            let (peer, relay) = if delayed {
                (&server_relay.peer_address, &server_relay.relay_address)
            } else {
                (server_address, client_relay)
            };
            let payload = self
                .payload(true, None, (!delayed).then_some(token), remote_token)
                .await;
            let reply = self.update_holepunch(peer, relay, payload).await?;
            if !reply.try_later {
                break;
            }
            if !self
                .puncher
                .retry_random_punch(self.has_relay, self.deadline)
                .await
            {
                return Err(HyperDhtError::HolepunchAborted);
            }
            delayed = true;
        }
        if !self.puncher.remote_holepunching {
            return Err(HyperDhtError::RemoteNotHolepunching);
        }
        Ok(())
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
    /// Keep-alive interval of the landed connection (Node `keepAlive:
    /// dht.connectionKeepAlive`).
    keep_alive: Option<std::time::Duration>,
}

impl RacedStream {
    #[cfg(test)]
    fn new(stream: libudx::UdxStream) -> Arc<Self> {
        Self::with_keep_alive(stream, None)
    }

    fn with_keep_alive(
        stream: libudx::UdxStream,
        keep_alive: Option<std::time::Duration>,
    ) -> Arc<Self> {
        Arc::new(Self {
            remote: stream.remote_handle(),
            abort: stream.abort_handle(),
            stream: Mutex::new(Some(stream)),
            relay: Mutex::new(None),
            relay_addr: Mutex::new(None),
            keep_alive,
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
        let ss =
            secret_stream_from_session(is_initiator, stream.into_async_stream(), noise).await?;
        ss.set_keep_alive(self.keep_alive);
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

/// A peer that completed the Noise handshake but never sends its
/// secret-stream header must not pin a stream and a task forever. Node has
/// no such bound; 15 s matches its relay pairing timeout.
async fn secret_stream_from_session(
    is_initiator: bool,
    raw: libudx::UdxAsyncStream,
    noise: &NoiseWrapResult,
) -> Result<SecretStream<libudx::UdxAsyncStream>, HyperDhtError> {
    const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
    tokio::time::timeout(
        HEADER_TIMEOUT,
        SecretStream::from_session(
            is_initiator,
            raw,
            noise.tx,
            noise.rx,
            noise.handshake_hash,
            noise.remote_public_key,
        ),
    )
    .await
    .map_err(|_| HyperDhtError::StreamEstablishment("secret stream header timed out".into()))?
    .map_err(HyperDhtError::from)
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
    let ss =
        secret_stream_from_session(result.noise.is_initiator, async_stream, &result.noise).await?;
    // `establish_stream` is the low-level half of Node `dht.connect()`,
    // which gives every stream the default `connectionKeepAlive`.
    ss.set_keep_alive(Some(DEFAULT_CONNECTION_KEEP_ALIVE));
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
    /// Returns after the first announce finished.
    pub async fn listen(&mut self, key_pair: &KeyPair) -> Result<(), HyperDhtError> {
        self.listen_inner(key_pair, true).await
    }

    /// [`Self::listen`], but the first announce runs in the background:
    /// this returns once the routes are registered, so an actor never waits
    /// on a DHT round trip.
    pub async fn listen_in_background(&mut self, key_pair: &KeyPair) -> Result<(), HyperDhtError> {
        self.listen_inner(key_pair, false).await
    }

    async fn listen_inner(
        &mut self,
        key_pair: &KeyPair,
        wait_first_announce: bool,
    ) -> Result<(), HyperDhtError> {
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
            self.start_announcing(wait_first_announce).await;
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

    /// Resume answering handshakes (Node `server.resume()`). Returns after
    /// the first announce finished.
    pub async fn resume(&mut self) -> Result<(), HyperDhtError> {
        self.resume_inner(true).await
    }

    /// [`Self::resume`], but the first announce runs in the background: this
    /// returns once handshakes are answered again.
    pub async fn resume_in_background(&mut self) -> Result<(), HyperDhtError> {
        self.resume_inner(false).await
    }

    async fn resume_inner(&mut self, wait_first_announce: bool) -> Result<(), HyperDhtError> {
        if !self.suspended {
            return Ok(());
        }
        let (reply, reply_rx) = oneshot::channel();
        self.commands
            .send(ServerCommand::Resume(reply))
            .map_err(|_| HyperDhtError::ServerClosed)?;
        reply_rx.await.map_err(|_| HyperDhtError::ServerClosed)?;
        self.suspended = false;
        self.start_announcing(wait_first_announce).await;
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

    async fn start_announcing(&mut self, wait_first: bool) {
        let (Some(target), Some(key_pair)) = (self.target, self.key_pair.clone()) else {
            return;
        };
        let dht = self.dht.clone();
        let announce = move |dht: HyperDhtHandle, key_pair: KeyPair| async move {
            dht.announce(target, &key_pair, &[])
                .await
                .map_or(true, |result| result.closest_nodes.is_empty())
        };
        let first = if wait_first {
            Some(announce(dht.clone(), key_pair.clone()).await)
        } else {
            None
        };
        // HyperDHT must refresh server records before they expire.
        self.announce_task = Some(tokio::spawn(async move {
            let mut empty = match first {
                Some(empty) => empty,
                None => announce(dht.clone(), key_pair.clone()).await,
            };
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(if empty { 3 } else { 300 }))
                    .await;
                empty = announce(dht.clone(), key_pair.clone()).await;
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
    id: u64,
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
    /// The puncher's own NAT class, reported in our punch replies
    /// (`server.js:621,648` `p.nat.firewall`); kept after `punch()` takes
    /// the puncher.
    firewall: u64,
    addresses: Vec<Ipv4Peer>,
    has_relay: bool,
    events: mpsc::UnboundedSender<ServerPunchEvent>,
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
    let firewalled = !dht.reachable().await.unwrap_or(false);
    let puncher = Holepuncher::new(&pool, runtime, firewalled, false, remote_firewall, hp_tx)
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
    // Randomized-NAT servers open up to 255 birthday sockets in `start_punch`.
    // Register the stream's firewall hook on each one before its first probe
    // leaves so the client's UDX handshake landing on any birthday port is
    // accepted (Node's raw stream hears every socket of its UDX instance).
    let birthday_remote = raced.remote.clone();
    puncher.set_on_socket(move |birthday_socket| {
        if let Err(err) = birthday_remote.listen_on(birthday_socket) {
            tracing::debug!(%err, "server: failed to arm birthday socket");
        }
    });
    let timed_out = events.clone();
    // Expire unused handshake state after Node's ten-second acceptance window.
    let abort = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        let _ = timed_out.send(ServerPunchEvent::Abort { id });
    });

    // Advertise the puncher's reachable addresses (Node
    // `holepuncher.js:221-227`), seeded before `punch()` can move the puncher.
    let addresses = puncher.advertised_addresses(puncher_port).await;
    let firewall = puncher.nat.firewall;
    let same_host = addresses.iter().any(|a| a.host == client_host);

    Ok(ServerPassivePunch {
        id,
        payload: SecurePayload::new(noise_result.holepunch_secret),
        puncher: probe.0.take(),
        punch_task: None,
        reply_socket: (!same_host).then(|| socket.clone()),
        socket,
        raced,
        remote_id,
        noise_result: noise_result.clone(),
        round: 0,
        firewall,
        addresses,
        has_relay: false,
        events: events.clone(),
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
        let port = state.socket.local_addr().await.ok().map_or(0, |a| a.port());
        state.addresses = puncher.advertised_addresses(port).await;
        state.firewall = puncher.nat.firewall;
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
    // `start_punch()` opens any birthday sockets before we reply `punching: true`
    // (Node `server.js:634` `await p.punch()`), and cancels the 10 s pre-punch
    // timeout (Node `server.js:601` `clearTimeout(h.prepunching)`) so a 35 s
    // randomized-NAT punch is not killed mid-flight.
    let mut punch_failed = false;
    if remote_hp.punching && !try_later && state.puncher.is_some() {
        state.abort.abort();
        if let Some(mut puncher) = state.puncher.take() {
            let pool = SocketPool::new("0.0.0.0".into());
            if let Some(plan) = puncher.start_punch(&pool, runtime).await {
                let id = state.id;
                let events = state.events.clone();
                state.punch_task = Some(tokio::spawn(async move {
                    let mut probe = ServerProbe(Some(puncher));
                    probe.0.as_mut().unwrap().run_punch(plan).await;
                    // Mirror Node `holepuncher.onabort`: once the probe loop
                    // finishes without landing, release the staged handshake.
                    let _ = events.send(ServerPunchEvent::Abort { id });
                }));
            } else {
                puncher.destroy();
                punch_failed = true;
            }
        }
    }

    let reply = if aborted || abort_for_budget || punch_failed {
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
            firewall: state.firewall,
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
    let socket = if aborted || abort_for_budget || punch_failed {
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
                        match punches.get_mut(&msg.id) {
                            Some(state) => {
                                server_punch_round(&runtime, state, &msg, &peer_address).await
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
    // Node `_onpeerhandshake`: the client is `peerAddress || req.from`.
    if config.refuses(&nw, &remote_payload, peer_address.unwrap_or(from)) {
        return None;
    }

    let socket = dht.server_socket().await.ok().flatten()?;
    let port = socket.local_addr().await.ok()?.port();
    // dht-rpc `firewalled` decides OPEN versus UNKNOWN in the payload
    // (`server.js:388`); the NAT class stays inside the puncher.
    let reachable = dht
        .dht()
        .reachable()
        .await
        .unwrap_or(config.firewall == FIREWALL_OPEN);
    let firewall = dht.firewalled().await.unwrap_or(config.firewall);

    let (local_stream_id, local_stream) = runtime.create_random_stream().await.ok()?;
    dht.track_raw_stream(local_stream.abort_handle());
    let addresses4 = dht.noise_addresses4(port).await;

    // Node advertises a holepunch session only while it cannot be dialled
    // directly (`ourRemoteAddr ? null : { id, relays }`).
    let holepunch = (!reachable).then(|| HolepunchInfo {
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
        firewall: if reachable {
            FIREWALL_OPEN
        } else {
            FIREWALL_UNKNOWN
        },
        holepunch,
        addresses4,
        addresses6: vec![],
        udx: Some(UdxInfo {
            version: 1,
            reusable_socket: false,
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
    let raced = RacedStream::with_keep_alive(local_stream, dht.connection_keep_alive);
    // Node dials a relayed client that reports itself open (`hs.onsocket`);
    // an open server told a firewalled client it is open and waits on the
    // DHT socket for its dial (`prepunching`). A client that reached us
    // directly dials the exact socket its handshake went to (`connect.js`
    // non-relayed `onsocket`); npm's server also dials it from that socket.
    // We do not know which of our two sockets that was, so we wait for the
    // client's dial on both instead. A direct or open client needs no relay
    // (`server.js:420-429`); for the rest the relay runs beside the punch
    // from here on (`_relayConnection`).
    let direct = peer_address.is_none();
    let dial = !direct && remote_payload.firewall == FIREWALL_OPEN;

    // A relayed handshake from a firewalled client cannot be dialled: a
    // firewalled server stages the passive punch now and advertises its
    // stream id, exactly as Node's `_addHandshake` does before replying.
    let passive = peer_address.is_some() && remote_payload.firewall != FIREWALL_OPEN && !reachable;
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
            // npm's raw stream hears every socket of its UDX instance: a
            // client that reached us directly dials the socket its handshake
            // went to (`connect.js` non-relayed `onsocket`), which for a
            // firewalled node is the listen socket, not the reply socket.
            let listen = dht.listen_socket().await.ok().flatten();
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
                    if let Some(listen) = &listen {
                        stream.listen_on(listen)?;
                    }
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
        .filter(|_| !dial && !direct)
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

// ── Deprecated legacy server ──────────────────────────────────────────────────

/// Formerly the per-server state of [`run_server`]; it holds nothing now.
#[deprecated(note = "use `HyperDhtServer` (`HyperDhtHandle::create_server`)")]
pub struct ServerSession {
    _private: (),
}

/// Answer PEER_HANDSHAKE events with a Noise reply, and nothing more.
///
/// It advertises no addresses, stages no holepunch (every PEER_HOLEPUNCH
/// gets no reply), opens no stream and keeps no per-peer state, so no
/// connection ever results. Use [`HyperDhtServer`]
/// ([`HyperDhtHandle::create_server`]), which does all of that.
#[deprecated(note = "use `HyperDhtServer` (`HyperDhtHandle::create_server`)")]
pub async fn run_server(
    mut event_rx: mpsc::UnboundedReceiver<ServerEvent>,
    config: ServerConfig,
    _runtime: UdxRuntime,
    _dht: DhtHandle,
) {
    while let Some(event) = event_rx.recv().await {
        match event {
            ServerEvent::PeerHandshake {
                msg,
                from,
                peer_address,
                reply_tx,
                ..
            } => {
                let reply = legacy_handshake_reply(&config, &msg, &from, peer_address.as_ref());
                let _ = reply_tx.send(reply.map(Into::into));
            }
            ServerEvent::PeerHolepunch { reply_tx, .. } => {
                let _ = reply_tx.send(None);
            }
        }
    }
}

/// The Noise reply [`run_server`] sends: our firewall and a stream id.
fn legacy_handshake_reply(
    config: &ServerConfig,
    msg: &HandshakeMessage,
    from: &Ipv4Peer,
    peer_address: Option<&Ipv4Peer>,
) -> Option<Vec<u8>> {
    let mut nw = NoiseWrap::new_responder(config.key_pair.to_noise_keypair());
    let remote_payload = nw.recv(&msg.noise).ok()?;
    if remote_payload.error != 0 {
        return None;
    }
    if config.refuses(&nw, &remote_payload, peer_address.unwrap_or(from)) {
        return None;
    }
    let reply_payload = NoisePayload {
        version: 1,
        error: 0,
        firewall: config.firewall,
        holepunch: None,
        addresses4: vec![],
        addresses6: vec![],
        udx: Some(UdxInfo {
            version: 1,
            reusable_socket: false,
            id: u64::from(next_stream_id()),
            seq: 0,
        }),
        secret_stream: Some(SecretStreamInfo { version: 1 }),
        relay_through: None,
        relay_addresses: None,
    };
    let noise = nw.send(&reply_payload).ok()?;
    crate::hyperdht_messages::encode_handshake_to_bytes(&HandshakeMessage {
        mode: crate::hyperdht_messages::MODE_REPLY,
        noise,
        peer_address: Some(from.clone()),
        relay_address: None,
    })
    .ok()
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

    let firewalled = match dht {
        Some(dht) => !dht.reachable().await.unwrap_or(false),
        None => true,
    };
    let mut puncher = Holepuncher::new(
        pool,
        runtime,
        firewalled,
        false,
        remote_hp.firewall,
        event_tx,
    )
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
        // The puncher's own class once sampled (`server.js:621`);
        // `config_firewall` only when the caller skipped sampling.
        firewall: if dht.is_some() {
            puncher.nat.firewall
        } else {
            config_firewall
        },
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
    let connection_keep_alive = config.connection_keep_alive;

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
        connection_keep_alive,
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
    // xache runs its gc every two thirds of `maxAge` (20 min).
    let mut router_gc = tokio::time::interval(std::time::Duration::from_secs(800));

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
            _ = router_gc.tick() => {
                if let Ok(mut r) = router.lock() {
                    r.gc();
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
                                    // dht-rpc `req.relay(.., { socket })`
                                    // defaults to the socket the round
                                    // arrived on.
                                    reply.socket.or_else(|| req.inbound_socket()),
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

/// dht-rpc `_endAfterCommit`: send every commit at once and return each
/// result in input order. The caller treats a reply whose error code is
/// nonzero as a failure, as `dht.request` rejects on it.
async fn commit_concurrently(
    dht: &DhtHandle,
    commits: Vec<(Ipv4Peer, UserRequestParams)>,
) -> Vec<Result<crate::rpc::ResponseData, DhtError>> {
    let mut set = tokio::task::JoinSet::new();
    let n = commits.len();
    for (i, (to, params)) in commits.into_iter().enumerate() {
        let dht = dht.clone();
        set.spawn(async move { (i, dht.request(params, &to.host, to.port).await) });
    }
    let mut results: Vec<Result<crate::rpc::ResponseData, DhtError>> =
        (0..n).map(|_| Err(DhtError::ChannelClosed)).collect();
    while let Some(joined) = set.join_next().await {
        if let Ok((i, res)) = joined {
            results[i] = res;
        }
    }
    results
}

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
            ..HyperDhtConfig::default()
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
            ..HyperDhtConfig::default()
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

    /// Message 1 from `client` to `server`, as a relayed firewalled client sends it.
    fn firewall_test_handshake(server: [u8; 32], client: &KeyPair) -> HandshakeMessage {
        let mut noise = NoiseWrap::new_initiator(client.to_noise_keypair(), server);
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
        }
    }

    #[tokio::test]
    async fn peer_firewall_refuses_before_any_reply() {
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
        let allowed = KeyPair::generate();
        let refused = KeyPair::generate();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut config = ServerConfig::new(keys.clone(), FIREWALL_OPEN);
        let allowed_key = allowed.public_key;
        let log = Arc::clone(&seen);
        config.peer_firewall = Some(Arc::new(move |remote, _, client| {
            log.lock().unwrap().push((*remote, client.clone()));
            *remote != allowed_key
        }));
        let from = Ipv4Peer {
            host: "10.0.0.1".into(),
            port: 49737,
        };
        let client = Ipv4Peer {
            host: "127.0.0.1".into(),
            port: 1234,
        };
        let (events, mut punch_rx) = mpsc::unbounded_channel();

        let refused_msg = firewall_test_handshake(keys.public_key, &refused);
        let reply = accept_server_handshake(
            &dht,
            &runtime,
            &config,
            1,
            &events,
            &refused_msg,
            &from,
            Some(&client),
        )
        .await;
        assert!(reply.is_none(), "a refused peer gets no Noise reply");
        assert!(
            punch_rx.try_recv().is_err(),
            "no punch staged for a refused peer"
        );

        let allowed_msg = firewall_test_handshake(keys.public_key, &allowed);
        let reply = accept_server_handshake(
            &dht,
            &runtime,
            &config,
            2,
            &events,
            &allowed_msg,
            &from,
            Some(&client),
        )
        .await
        .expect("an allowed peer is answered");
        assert!(
            reply.relay.is_some(),
            "an allowed peer still gets the relay path"
        );
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                (refused.public_key, client.clone()),
                (allowed.public_key, client.clone())
            ],
            "the hook sees the client key and the relayed peer address"
        );

        // The deprecated `run_server` path honors the hook too, and a direct
        // handshake reports the sender as the client.
        assert!(legacy_handshake_reply(&config, &refused_msg, &from, None).is_none());
        assert!(legacy_handshake_reply(&config, &allowed_msg, &from, None).is_some());
        assert_eq!(seen.lock().unwrap().last().unwrap().1, from);

        // Node fails closed when its firewall throws.
        config.peer_firewall = Some(Arc::new(|_, _, _| panic!("firewall bug")));
        let reply = accept_server_handshake(
            &dht,
            &runtime,
            &config,
            3,
            &events,
            &allowed_msg,
            &from,
            Some(&client),
        )
        .await;
        assert!(reply.is_none(), "a panicking firewall refuses the peer");
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
        let bootstrap_port = bootstrap.local_port().await.unwrap();
        let address = format!("127.0.0.1:{bootstrap_port}");
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
        // The announce query's timeouts drop the dead node from the table
        // (dht-rpc `_ontimeout`); put it back so staging samples a node that
        // never answers.
        dht.dht().insert_node_for_test(crate::routing_table::Node {
            id: rand::random(),
            host: "127.0.0.1".into(),
            port: bootstrap_port,
            token: None,
            added_tick: 0,
            seen_tick: 0,
            pinged_tick: 0,
            down_hints: 0,
        });
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
            let reply = server_punch_round(&runtime, &mut state, &message, &peer)
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
    async fn server_birthday_socket_accepts_udx_stream_and_lands() {
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

        let client_sock = runtime.create_socket().await.expect("client socket");
        client_sock
            .bind("127.0.0.1:0".parse().expect("addr"))
            .await
            .expect("bind");
        let client_addr = client_sock.local_addr().await.expect("client addr");
        let mut client_rx = client_sock.recv_start().expect("recv_start");
        let (client_id, client_stream) = runtime.create_random_stream().await.expect("client stream");
        let (server_id, server_stream) = runtime.create_random_stream().await.expect("server stream");

        let client_noise = NoiseWrapResult {
            remote_public_key: [1; 32],
            tx: [2; 32],
            rx: [3; 32],
            handshake_hash: [4; 64],
            holepunch_secret: [5; 32],
            is_initiator: true,
        };
        let server_noise = NoiseWrapResult {
            remote_public_key: [6; 32],
            tx: [3; 32],
            rx: [2; 32],
            handshake_hash: [4; 64],
            holepunch_secret: [5; 32],
            is_initiator: false,
        };

        let raced = RacedStream::new(server_stream);
        let (events, mut event_rx) = mpsc::unbounded_channel();
        let mut punch = stage_server_punch(
            &runtime,
            dht.dht(),
            None,
            &server_noise,
            "127.0.0.1",
            FIREWALL_CONSISTENT,
            7,
            Arc::clone(&raced),
            client_id,
            &events,
        )
        .await
        .expect("stage");
        let primary_port = punch.socket.local_addr().await.expect("primary addr").port();
        // Force server NAT classification to RANDOM so server_punch_round opens
        // birthday sockets and runs keep_alive_random_nat.
        punch.puncher.as_mut().expect("puncher").nat.firewall = FIREWALL_RANDOM;
        let abort_handle = punch.abort.abort_handle();

        let sp = SecurePayload::new(server_noise.holepunch_secret);
        let client_peer = Ipv4Peer {
            host: "127.0.0.1".into(),
            port: client_addr.port(),
        };
        let msg = HolepunchMessage {
            mode: MODE_FROM_RELAY,
            id: 7,
            peer_address: None,
            payload: sp
                .encrypt(&HolepunchPayload {
                    error: ERROR_NONE,
                    firewall: FIREWALL_CONSISTENT,
                    round: 1,
                    connected: false,
                    punching: true,
                    addresses: Some(vec![client_peer.clone()]),
                    remote_address: None,
                    token: None,
                    remote_token: None,
                })
                .expect("encrypt"),
        };
        let reply = server_punch_round(&runtime, &mut punch, &msg, &client_peer)
            .await
            .expect("reply");
        let decoded =
            crate::hyperdht_messages::decode_holepunch_msg_from_bytes(&reply.value).expect("msg");
        let reply_hp = sp.decrypt(&decoded.payload).expect("decrypt");
        assert_eq!(reply_hp.error, ERROR_NONE);
        assert!(reply_hp.punching);

        tokio::task::yield_now().await;
        assert!(
            abort_handle.is_finished(),
            "starting the punch must cancel the 10 s pre-punch abort timer"
        );

        // Wait for a low-TTL probe from a non-primary birthday socket.
        let birthday_addr = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let dgram = client_rx.recv().await.expect("probe");
                if dgram.data == [0u8] && dgram.addr.port() != primary_port {
                    break SocketAddr::new("127.0.0.1".parse().unwrap(), dgram.addr.port());
                }
            }
        })
        .await
        .expect("birthday socket probe");

        // Dial the non-primary birthday socket with a real UDX + SecretStream.
        let client_task = tokio::spawn(async move {
            client_stream
                .connect(&client_sock, server_id, birthday_addr)
                .await
                .expect("client connect");
            let mut ss = secret_stream_from_session(true, client_stream.into_async_stream(), &client_noise)
                .await
                .expect("client secret stream");
            ss.write(b"hello over birthday socket")
                .await
                .expect("client write");
            ss
        });

        let (landed_addr, landed_socket) =
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    match event_rx.recv().await.expect("event") {
                        ServerPunchEvent::Punched { id, addr, socket } => {
                            assert_eq!(id, 7);
                            break (addr, socket);
                        }
                        ServerPunchEvent::Abort { .. } => {
                            panic!("unexpected abort while birthday socket is live");
                        }
                        ServerPunchEvent::Handshaken { .. } => {}
                    }
                }
            })
            .await
            .expect("Punched event on birthday socket");
        assert_eq!(
            landed_socket.local_addr().await.expect("landed addr").port(),
            birthday_addr.port(),
            "firewall hook must deliver the winning birthday socket"
        );

        // Dropping ServerPassivePunch tears down the 255 unused birthday sockets
        // while `landed_socket` keeps the winning port open for the connection.
        drop(punch);
        let mut server_conn = raced
            .land(
                Landing {
                    socket: landed_socket,
                    remote_id: client_id,
                    addr: landed_addr,
                    relay: None,
                },
                &server_noise,
                false,
            )
            .await
            .expect("land")
            .expect("server conn");

        let received = tokio::time::timeout(std::time::Duration::from_secs(3), server_conn.stream.read())
            .await
            .expect("read timeout")
            .expect("read ok")
            .expect("payload");
        assert_eq!(received.as_slice(), b"hello over birthday socket");

        let _client_ss = client_task.await.expect("client task");
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

    fn lan_peer(host: &str, port: u16) -> Ipv4Peer {
        Ipv4Peer {
            host: host.into(),
            port,
        }
    }

    #[test]
    fn direct_dial_uses_the_handshake_address_when_not_relayed() {
        let node = lan_peer("192.168.1.20", 49737);
        let advertised = [lan_peer("8.8.8.8", 49737), node.clone()];
        let addr = direct_dial_address(false, &advertised, &node, &advertised[0]);
        assert_eq!((addr.host.as_str(), addr.port), ("192.168.1.20", 49737));
    }

    #[test]
    fn lan_pick_never_dials_an_unparsable_host() {
        let advertised = [lan_peer("not-an-ip", 1), lan_peer("10.0.0.5", 2)];
        let addr = lan_dial_address(&advertised, &[]).unwrap();
        assert_eq!(addr.host, "10.0.0.5");
    }

    #[test]
    fn lan_pick_prefers_the_closest_subnet_and_skips_reserved() {
        let advertised = [
            lan_peer("224.0.0.1", 1),
            lan_peer("10.0.0.5", 2),
            lan_peer("192.168.1.9", 3),
        ];
        let mine = [lan_peer("192.168.1.20", 4)];
        assert_eq!(lan_dial_address(&advertised, &mine).unwrap().port, 3);
        assert_eq!(lan_dial_address(&advertised, &[]).unwrap().port, 2);
    }

    fn client_noise(secret: [u8; 32]) -> NoiseWrapResult {
        NoiseWrapResult {
            remote_public_key: [1; 32],
            tx: [2; 32],
            rx: [3; 32],
            handshake_hash: [4; 64],
            holepunch_secret: secret,
            is_initiator: true,
        }
    }

    fn holepunchable_server_payload() -> NoisePayload {
        NoisePayload {
            version: 1,
            error: ERROR_NONE,
            firewall: FIREWALL_UNKNOWN,
            holepunch: Some(HolepunchInfo {
                id: 1,
                relays: vec![],
            }),
            addresses4: vec![],
            addresses6: vec![],
            udx: Some(UdxInfo {
                version: 1,
                reusable_socket: false,
                id: 7,
                seq: 0,
            }),
            secret_stream: Some(SecretStreamInfo { version: 1 }),
            relay_through: None,
            relay_addresses: None,
        }
    }

    fn firewalled_local_config() -> HyperDhtConfig {
        HyperDhtConfig {
            dht: DhtConfig {
                bootstrap: vec![],
                host: "127.0.0.1".into(),
                firewalled: true,
                ..DhtConfig::default()
            },
            ..HyperDhtConfig::default()
        }
    }

    /// A DHT node relaying PEER_HOLEPUNCH for a CONSISTENT server at
    /// `server`: it echoes the client's token, reports the client's
    /// reflexive address as 127.0.0.1 at the advertised puncher port, and
    /// hands every decrypted client payload to the test.
    async fn fake_holepunch_relay(
        secret: [u8; 32],
        server: Ipv4Peer,
    ) -> (
        Ipv4Peer,
        mpsc::UnboundedReceiver<HolepunchPayload>,
        JoinHandle<()>,
    ) {
        fake_holepunch_relay_with(secret, server, |_, _| {}).await
    }

    /// [`fake_holepunch_relay`] whose reply to each client payload passes
    /// through `tweak` first.
    async fn fake_holepunch_relay_with(
        secret: [u8; 32],
        server: Ipv4Peer,
        tweak: fn(&HolepunchPayload, &mut HolepunchPayload),
    ) -> (
        Ipv4Peer,
        mpsc::UnboundedReceiver<HolepunchPayload>,
        JoinHandle<()>,
    ) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let (tx, rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let sp = SecurePayload::new(secret);
            let mut buf = vec![0u8; 4096];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let Ok(crate::messages::Message::Request(req)) =
                    crate::messages::decode_message(&buf[..n])
                else {
                    continue;
                };
                let Some(Ok(msg)) = req
                    .value
                    .as_deref()
                    .map(crate::hyperdht_messages::decode_holepunch_msg_from_bytes)
                else {
                    continue;
                };
                // A relay forwards a client's round to its `peerAddress`.
                if msg.peer_address.as_ref() != Some(&server) {
                    continue;
                }
                let Ok(hp) = sp.decrypt(&msg.payload) else {
                    continue;
                };
                let puncher_port = hp
                    .addresses
                    .as_ref()
                    .and_then(|a| a.first())
                    .map_or(from.port(), |a| a.port);
                let _ = tx.send(hp.clone());
                let mut reply = HolepunchPayload {
                    error: ERROR_NONE,
                    firewall: FIREWALL_CONSISTENT,
                    round: hp.round,
                    connected: false,
                    punching: hp.punching,
                    addresses: Some(vec![server.clone()]),
                    remote_address: None,
                    token: Some([7; 32]),
                    remote_token: hp.token,
                };
                tweak(&hp, &mut reply);
                let value = encode_holepunch_msg_to_bytes(&HolepunchMessage {
                    mode: MODE_REPLY,
                    id: msg.id,
                    payload: sp.encrypt(&reply).unwrap(),
                    peer_address: Some(server.clone()),
                })
                .unwrap();
                let resp = crate::messages::Response {
                    tid: req.tid,
                    to: lan_peer("127.0.0.1", puncher_port),
                    id: None,
                    token: None,
                    closer_nodes: vec![],
                    error: 0,
                    value: Some(value),
                };
                let bytes = crate::messages::encode_response_to_bytes(&resp).unwrap();
                let _ = socket.send_to(&bytes, from).await;
            }
        });
        (lan_peer("127.0.0.1", port), rx, task)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_reply_samples_our_reflexive_address_not_the_servers() {
        let runtime = UdxRuntime::new().unwrap();
        let (_task, dht, _events) = spawn(&runtime, firewalled_local_config()).await.unwrap();
        // Two loopback nodes give the puncher's sampler two hits of its own
        // mapping; the probe reply's `to` must be the third.
        let mut nodes = Vec::new();
        for _ in 0..2 {
            let (task, node) = crate::rpc::spawn(
                &runtime,
                DhtConfig {
                    bootstrap: vec![],
                    host: "127.0.0.1".into(),
                    ephemeral: Some(true),
                    firewalled: false,
                    ..DhtConfig::default()
                },
            )
            .await
            .unwrap();
            dht.dht().insert_node_for_test(crate::routing_table::Node {
                id: rand::random(),
                host: "127.0.0.1".into(),
                port: node.local_port().await.unwrap(),
                token: None,
                added_tick: 0,
                seen_tick: 0,
                pinged_tick: 0,
                down_hints: 0,
            });
            nodes.push((task, node));
        }
        let secret = [5; 32];
        let server = lan_peer("127.0.0.1", 9);
        let (relay, mut payloads, relay_task) = fake_holepunch_relay(secret, server.clone()).await;
        let client = {
            let dht = dht.clone();
            let runtime = UdxRuntime::shared(runtime.handle());
            tokio::spawn(async move {
                dht.run_holepunch_rounds(
                    &client_noise(secret),
                    &holepunchable_server_payload(),
                    &relay,
                    &[0; 32],
                    &server,
                    &runtime,
                    1,
                    false,
                )
                .await
            })
        };
        let wait = std::time::Duration::from_secs(10);
        let first = tokio::time::timeout(wait, payloads.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.round, 0);
        let second = tokio::time::timeout(wait, payloads.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            second.firewall, FIREWALL_CONSISTENT,
            "the reply's `to` (our mapping) must settle the sampler, not the server's address"
        );
        client.abort();
        relay_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unknown_nat_rerolls_then_fails_with_probe_timeout() {
        let runtime = UdxRuntime::new().unwrap();
        let (_task, dht, _events) = spawn(&runtime, firewalled_local_config()).await.unwrap();
        let secret = [5; 32];
        let server = lan_peer("127.0.0.1", 9);
        let (relay, mut payloads, relay_task) = fake_holepunch_relay(secret, server.clone()).await;
        // No sampling nodes: our class stays UNKNOWN through every socket
        // reroll, so `probeRound` aborts with HOLEPUNCH_PROBE_TIMEOUT.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            dht.run_holepunch_rounds(
                &client_noise(secret),
                &holepunchable_server_payload(),
                &relay,
                &[0; 32],
                &server,
                &runtime,
                1,
                false,
            ),
        )
        .await
        .expect("a failed punch must not wait for the 30 s deadline");
        assert!(matches!(result, Err(HyperDhtError::HolepunchProbeTimeout)));
        // Finding 17: the server is told to drop its staged punch at once.
        let mut last = None;
        while let Ok(payload) = payloads.try_recv() {
            last = Some(payload);
        }
        let last = last.expect("rounds reached the relay");
        assert_eq!(
            last.error, ERROR_ABORTED,
            "the last round is the ABORTED payload"
        );
        relay_task.abort();
    }

    /// `n` loopback DHT nodes in `dht`'s table, so the puncher's sampler
    /// sees a consistent mapping.
    async fn sampling_nodes(
        runtime: &UdxRuntime,
        dht: &HyperDhtHandle,
        n: usize,
    ) -> Vec<(JoinHandle<Result<(), DhtError>>, DhtHandle)> {
        let mut nodes = Vec::new();
        for _ in 0..n {
            let (task, node) = crate::rpc::spawn(
                runtime,
                DhtConfig {
                    bootstrap: vec![],
                    host: "127.0.0.1".into(),
                    ephemeral: Some(true),
                    firewalled: false,
                    ..DhtConfig::default()
                },
            )
            .await
            .unwrap();
            dht.dht().insert_node_for_test(crate::routing_table::Node {
                id: rand::random(),
                host: "127.0.0.1".into(),
                port: node.local_port().await.unwrap(),
                token: None,
                added_tick: 0,
                seen_tick: 0,
                pinged_tick: 0,
                down_hints: 0,
            });
            nodes.push((task, node));
        }
        nodes
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_error_in_the_punch_reply_is_remote_aborted_without_an_abort_round() {
        let runtime = UdxRuntime::new().unwrap();
        let (_task, dht, _events) = spawn(&runtime, firewalled_local_config()).await.unwrap();
        let _nodes = sampling_nodes(&runtime, &dht, 3).await;
        let secret = [5; 32];
        let server = lan_peer("127.0.0.1", 9);
        // TRY_LATER without a relay is an error like any other (Node
        // `updateHolepunch`).
        let (relay, mut payloads, relay_task) =
            fake_holepunch_relay_with(secret, server.clone(), |hp, reply| {
                if hp.punching {
                    reply.error = ERROR_TRY_LATER;
                }
            })
            .await;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            dht.run_holepunch_rounds(
                &client_noise(secret),
                &holepunchable_server_payload(),
                &relay,
                &[0; 32],
                &server,
                &runtime,
                1,
                false,
            ),
        )
        .await
        .expect("rounds finished");
        assert!(
            matches!(result, Err(HyperDhtError::RemoteAborted(ERROR_TRY_LATER))),
            "{result:?}"
        );
        let mut sent = Vec::new();
        while let Ok(payload) = payloads.try_recv() {
            sent.push(payload);
        }
        assert!(
            sent.last().is_some_and(|p| p.punching),
            "the punch round was the last"
        );
        assert!(
            sent.iter().all(|p| p.error == ERROR_NONE),
            "no ABORTED round"
        );
        relay_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_server_that_never_learns_its_nat_gets_two_probe_rounds() {
        let runtime = UdxRuntime::new().unwrap();
        let (_task, dht, _events) = spawn(&runtime, firewalled_local_config()).await.unwrap();
        let _nodes = sampling_nodes(&runtime, &dht, 3).await;
        let secret = [5; 32];
        let server = lan_peer("127.0.0.1", 9);
        let (relay, mut payloads, relay_task) =
            fake_holepunch_relay_with(secret, server.clone(), |_, reply| {
                reply.firewall = FIREWALL_UNKNOWN;
            })
            .await;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            dht.run_holepunch_rounds(
                &client_noise(secret),
                &holepunchable_server_payload(),
                &relay,
                &[0; 32],
                &server,
                &runtime,
                1,
                false,
            ),
        )
        .await
        .expect("rounds finished");
        assert!(
            matches!(result, Err(HyperDhtError::HolepunchProbeTimeout)),
            "{result:?}"
        );
        let mut sent = Vec::new();
        while let Ok(payload) = payloads.try_recv() {
            sent.push((payload.round, payload.error, payload.punching));
        }
        // Node `probeRound(.., retry = true)` then once more, then `abort`.
        assert_eq!(
            sent,
            vec![
                (0, ERROR_NONE, false),
                (1, ERROR_NONE, false),
                (2, ERROR_ABORTED, false)
            ]
        );
        relay_task.abort();
    }

    /// A DHT node that reports a fresh port for every packet from the first
    /// socket (other than `dht_port`) that pings it, and the true port for
    /// every other socket: that first socket looks RANDOM, the rest
    /// CONSISTENT. With `first` unset every socket but `dht_port` looks
    /// RANDOM.
    async fn fake_sampling_node(
        dht_port: u16,
        first: Option<Arc<Mutex<Option<u16>>>>,
    ) -> (u16, JoinHandle<()>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let Ok(crate::messages::Message::Request(req)) =
                    crate::messages::decode_message(&buf[..n])
                else {
                    continue;
                };
                let lie = from.port() != dht_port
                    && first.as_ref().is_none_or(|first| {
                        *first.lock().unwrap().get_or_insert(from.port()) == from.port()
                    });
                let seen = if lie {
                    rand::random_range(1024..=65535)
                } else {
                    from.port()
                };
                let resp = crate::messages::Response {
                    tid: req.tid,
                    to: lan_peer("127.0.0.1", seen),
                    id: Some(crate::peer::peer_id("127.0.0.1", port)),
                    token: None,
                    closer_nodes: vec![],
                    error: 0,
                    value: None,
                };
                let bytes = crate::messages::encode_response_to_bytes(&resp).unwrap();
                let _ = socket.send_to(&bytes, from).await;
            }
        });
        (port, task)
    }

    /// Three [`fake_sampling_node`]s in `dht`'s table.
    async fn fake_sampling_nodes(
        dht: &HyperDhtHandle,
        first: Option<Arc<Mutex<Option<u16>>>>,
    ) -> Vec<JoinHandle<()>> {
        let dht_port = dht.local_port().await.unwrap();
        let mut nodes = Vec::new();
        for _ in 0..3 {
            let (port, task) = fake_sampling_node(dht_port, first.clone()).await;
            dht.dht().insert_node_for_test(crate::routing_table::Node {
                id: rand::random(),
                host: "127.0.0.1".into(),
                port,
                token: None,
                added_tick: 0,
                seen_tick: 0,
                pinged_tick: 0,
                down_hints: 0,
            });
            nodes.push(task);
        }
        nodes
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_silent_lan_address_does_not_stop_the_punch() {
        let runtime = UdxRuntime::new().unwrap();
        let (_task, dht, _events) = spawn(&runtime, firewalled_local_config()).await.unwrap();
        let _nodes = sampling_nodes(&runtime, &dht, 3).await;
        // The server's puncher: answers every probe.
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = lan_peer("127.0.0.1", echo.local_addr().unwrap().port());
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            while let Ok((n, from)) = echo.recv_from(&mut buf).await {
                if n == 1 {
                    let _ = echo.send_to(&[0], from).await;
                }
            }
        });
        // The LAN address the server advertised: bound, never answers.
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let lan = lan_peer("127.0.0.1", silent.local_addr().unwrap().port());
        let secret = [5; 32];
        let (relay, _payloads, relay_task) = fake_holepunch_relay(secret, server.clone()).await;
        let mut remote_payload = holepunchable_server_payload();
        remote_payload.holepunch = Some(HolepunchInfo {
            id: 1,
            relays: vec![RelayInfo {
                relay_address: relay.clone(),
                peer_address: server.clone(),
            }],
        });
        remote_payload.addresses4 = vec![lan];
        // Both peers behind the same public host.
        let dial = DirectDial {
            dht: dht.clone(),
            hs_result: crate::router::HandshakeResult {
                noise: vec![],
                relayed: true,
                server_address: server.clone(),
                client_address: lan_peer("127.0.0.1", 1),
            },
            remote_payload,
            nw_result: client_noise(secret),
            node: relay,
            target: [0; 32],
            local_stream_id: 1,
            remote_id: 7,
            local_connection: true,
            has_relay: false,
            server_dial: None,
        };
        let landing = tokio::time::timeout(std::time::Duration::from_secs(10), dial.run(&runtime))
            .await
            .expect("dial finished")
            .expect("the punch lands");
        assert_eq!(landing.addr, to_socket_addr(&server).unwrap());
        echo_task.abort();
        relay_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probes_go_through_the_servers_relay_when_ours_is_not_one() {
        let runtime = UdxRuntime::new().unwrap();
        let (_task, dht, _events) = spawn(&runtime, firewalled_local_config()).await.unwrap();
        let _nodes = sampling_nodes(&runtime, &dht, 3).await;
        let secret = [5; 32];
        // The server as its announce relay sees it, and as our handshake
        // node saw it.
        let seen_by_relay = lan_peer("127.0.0.1", 9);
        let server = lan_peer("127.0.0.1", 10);
        let (server_relay, mut at_server_relay, a_task) =
            fake_holepunch_relay(secret, seen_by_relay.clone()).await;
        // Not one of the server's relays: a JS server (`server.js:543-554`
        // `isServerRelay`) sends its token only through its own relays.
        let (our_relay, mut at_our_relay, b_task) =
            fake_holepunch_relay_with(secret, server.clone(), |_, reply| reply.token = None).await;
        let mut remote_payload = holepunchable_server_payload();
        remote_payload.holepunch = Some(HolepunchInfo {
            id: 1,
            relays: vec![RelayInfo {
                relay_address: server_relay,
                peer_address: seen_by_relay,
            }],
        });
        let client = {
            let dht = dht.clone();
            let runtime = UdxRuntime::shared(runtime.handle());
            tokio::spawn(async move {
                dht.run_holepunch_rounds(
                    &client_noise(secret),
                    &remote_payload,
                    &our_relay,
                    &[0; 32],
                    &server,
                    &runtime,
                    1,
                    false,
                )
                .await
            })
        };
        let wait = std::time::Duration::from_secs(10);
        let punch = tokio::time::timeout(wait, at_our_relay.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            punch.punching,
            "only the punch round goes through our relay"
        );
        assert_eq!(
            punch.remote_token,
            Some([7; 32]),
            "the server's token, from the probe through its relay"
        );
        assert!(punch.token.is_some(), "our token, for the server to echo");
        let probe = at_server_relay
            .try_recv()
            .expect("the probe used the server's relay");
        assert!(!probe.punching);
        assert!(
            at_server_relay.try_recv().is_err(),
            "one probe: it had the token"
        );
        client.abort();
        a_task.abort();
        b_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_puncher_socket_answers_dht_requests() {
        let runtime = UdxRuntime::new().unwrap();
        let (_task, dht, _events) = spawn(&runtime, firewalled_local_config()).await.unwrap();
        let pool = SocketPool::new("127.0.0.1".into());
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut puncher = Holepuncher::new(&pool, &runtime, true, true, FIREWALL_UNKNOWN, tx)
            .await
            .unwrap();
        // Hooks the socket up to the DHT, as for every puncher.
        puncher.auto_sample(dht.dht()).await;
        let port = puncher.socket().unwrap().local_addr().await.unwrap().port();
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = crate::messages::encode_request_to_bytes(&crate::messages::Request {
            tid: 4242,
            to: lan_peer("127.0.0.1", port),
            id: None,
            token: None,
            internal: true,
            command: crate::messages::Command::Ping as u64,
            target: None,
            value: None,
        })
        .unwrap();
        probe.send_to(&request, ("127.0.0.1", port)).await.unwrap();
        let mut buf = [0u8; 2048];
        let (n, from) =
            tokio::time::timeout(std::time::Duration::from_secs(2), probe.recv_from(&mut buf))
                .await
                .expect("hyperdht's pool sockets hand requests to the DHT")
                .unwrap();
        let Ok(crate::messages::Message::Response(resp)) =
            crate::messages::decode_message(&buf[..n])
        else {
            panic!("not a response");
        };
        assert_eq!(resp.tid, 4242);
        // dht-rpc replies on the socket the request arrived on.
        assert_eq!(from.port(), port, "the reply left the puncher socket");
        puncher.destroy();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_local_addresses_that_hear_themselves_are_advertised() {
        let runtime = UdxRuntime::new().unwrap();
        let (_task, dht, _events) = spawn(&runtime, firewalled_local_config()).await.unwrap();
        // 192.0.2.1 (TEST-NET-1) is no interface of ours: binding it fails.
        let candidates = vec![lan_peer("127.0.0.1", 1), lan_peer("192.0.2.1", 2)];
        let valid = dht.validate_local_addresses(candidates.clone()).await;
        assert_eq!(valid, vec![lan_peer("127.0.0.1", 1)]);
        // The verdict per host is cached: no second probe round.
        let started = std::time::Instant::now();
        assert_eq!(dht.validate_local_addresses(candidates).await, valid);
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        let port = dht.local_port().await.unwrap();
        assert_eq!(
            dht.noise_addresses4(port).await,
            vec![lan_peer("127.0.0.1", port)]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn random_nats_on_both_sides_abort_as_double_randomized() {
        let runtime = UdxRuntime::new().unwrap();
        let (_task, dht, _events) = spawn(&runtime, firewalled_local_config()).await.unwrap();
        // Every puncher socket, rerolls included, looks RANDOM.
        let nodes = fake_sampling_nodes(&dht, None).await;
        let secret = [5; 32];
        let server = lan_peer("127.0.0.1", 9);
        let (relay, mut payloads, relay_task) =
            fake_holepunch_relay_with(secret, server.clone(), |_, reply| {
                reply.firewall = crate::hyperdht_messages::FIREWALL_RANDOM;
            })
            .await;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            dht.run_holepunch_rounds(
                &client_noise(secret),
                &holepunchable_server_payload(),
                &relay,
                &[0; 32],
                &server,
                &runtime,
                1,
                false,
            ),
        )
        .await
        .expect("rounds finished");
        assert!(
            matches!(result, Err(HyperDhtError::HolepunchDoubleRandomizedNats)),
            "{result:?}"
        );
        let mut sent = Vec::new();
        while let Ok(payload) = payloads.try_recv() {
            sent.push((payload.error, payload.punching));
        }
        // One probe, then Node `abort`.
        assert_eq!(sent, vec![(ERROR_NONE, false), (ERROR_ABORTED, false)]);
        relay_task.abort();
        for task in nodes {
            task.abort();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rerolled_socket_probes_again_before_the_punch() {
        let runtime = UdxRuntime::new().unwrap();
        let (_task, dht, _events) = spawn(&runtime, firewalled_local_config()).await.unwrap();
        let nodes = fake_sampling_nodes(&dht, Some(Arc::new(Mutex::new(None)))).await;
        let secret = [5; 32];
        let server = lan_peer("127.0.0.1", 9);
        // A RANDOM server and our RANDOM first socket: unstable, so the
        // puncher rerolls to a socket the nodes see as CONSISTENT.
        let (relay, mut payloads, relay_task) =
            fake_holepunch_relay_with(secret, server.clone(), |_, reply| {
                reply.firewall = crate::hyperdht_messages::FIREWALL_RANDOM;
            })
            .await;
        let client = {
            let dht = dht.clone();
            let runtime = UdxRuntime::shared(runtime.handle());
            tokio::spawn(async move {
                dht.run_holepunch_rounds(
                    &client_noise(secret),
                    &holepunchable_server_payload(),
                    &relay,
                    &[0; 32],
                    &server,
                    &runtime,
                    1,
                    false,
                )
                .await
            })
        };
        let wait = std::time::Duration::from_secs(10);
        let first_probe = tokio::time::timeout(wait, payloads.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (first_probe.punching, first_probe.firewall),
            (false, crate::hyperdht_messages::FIREWALL_RANDOM)
        );
        let next = tokio::time::timeout(wait, payloads.recv())
            .await
            .unwrap()
            .unwrap();
        // Node re-runs `probeRound` from the new socket before `roundPunch`.
        assert_eq!(
            (next.round, next.punching, next.firewall),
            (1, false, FIREWALL_CONSISTENT)
        );
        client.abort();
        relay_task.abort();
        for task in nodes {
            task.abort();
        }
    }

    /// A DHT node that answers every request with a token and its real id,
    /// but rejects ANNOUNCE with error 1.
    async fn fake_rejecting_node() -> (String, JoinHandle<()>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let Ok(crate::messages::Message::Request(req)) =
                    crate::messages::decode_message(&buf[..n])
                else {
                    continue;
                };
                let resp = crate::messages::Response {
                    tid: req.tid,
                    to: lan_peer("127.0.0.1", from.port()),
                    id: Some(crate::peer::peer_id("127.0.0.1", port)),
                    token: Some([9; 32]),
                    closer_nodes: vec![],
                    error: u64::from(req.command == ANNOUNCE),
                    value: None,
                };
                let bytes = crate::messages::encode_response_to_bytes(&resp).unwrap();
                let _ = socket.send_to(&bytes, from).await;
            }
        });
        (format!("127.0.0.1:{port}"), task)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fast_bogus_handshake_reply_does_not_beat_the_honest_one() {
        let runtime = UdxRuntime::new().unwrap();
        let open = || HyperDhtConfig {
            dht: DhtConfig {
                bootstrap: vec![],
                host: "127.0.0.1".into(),
                ephemeral: Some(false),
                firewalled: false,
                ..DhtConfig::default()
            },
            ..HyperDhtConfig::default()
        };
        let (_s, server_dht, events) = spawn(&runtime, open()).await.unwrap();
        let (_c, client, _ce) = spawn(&runtime, open()).await.unwrap();
        let keys = KeyPair::generate();
        let mut server = server_dht.create_server(
            &runtime,
            ServerConfig::new(keys.clone(), FIREWALL_UNKNOWN),
            events,
        );
        server.listen(&keys).await.unwrap();
        let honest = lan_peer("127.0.0.1", server_dht.local_port().await.unwrap());

        // Answers every request at once with a well-formed REPLY whose
        // Noise message is garbage.
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bogus = lan_peer("127.0.0.1", socket.local_addr().unwrap().port());
        let liar = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let Ok(crate::messages::Message::Request(req)) =
                    crate::messages::decode_message(&buf[..n])
                else {
                    continue;
                };
                let value = encode_handshake_to_bytes(&HandshakeMessage {
                    mode: MODE_REPLY,
                    noise: vec![7; 96],
                    peer_address: None,
                    relay_address: None,
                })
                .unwrap();
                let resp = crate::messages::Response {
                    tid: req.tid,
                    to: lan_peer("127.0.0.1", from.port()),
                    id: None,
                    token: None,
                    closer_nodes: vec![],
                    error: 0,
                    value: Some(value),
                };
                let bytes = crate::messages::encode_response_to_bytes(&resp).unwrap();
                let _ = socket.send_to(&bytes, from).await;
            }
        });

        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.connect_with_nodes(
                &KeyPair::generate(),
                keys.public_key,
                &[bogus, honest.clone()],
                &runtime,
            ),
        )
        .await
        .expect("connect finished")
        .expect("connect through the honest node");
        assert_eq!(conn.remote_public_key, keys.public_key);
        assert_eq!(conn.remote_addr.map(|a| a.port()), Some(honest.port));
        liar.abort();
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_open_client_waits_for_the_server_to_dial_it() {
        let runtime = UdxRuntime::new().unwrap();
        let node = |bootstrap: Vec<String>, firewalled: bool| HyperDhtConfig {
            dht: DhtConfig {
                bootstrap,
                host: "127.0.0.1".into(),
                firewalled,
                quick_firewall: false,
                ephemeral: Some(firewalled),
                ..DhtConfig::default()
            },
            ..HyperDhtConfig::default()
        };
        let (_b1t, b1, _) = spawn(&runtime, node(vec![], false)).await.unwrap();
        let boot = vec![format!("127.0.0.1:{}", b1.local_port().await.unwrap())];
        let (_b2t, b2, _) = spawn(&runtime, node(boot.clone(), false)).await.unwrap();
        let (_b3t, b3, _) = spawn(&runtime, node(boot.clone(), false)).await.unwrap();
        b2.bootstrapped().await.unwrap();
        b3.bootstrapped().await.unwrap();

        let (_st, server_dht, events) = spawn(&runtime, node(boot.clone(), true)).await.unwrap();
        server_dht.fully_bootstrapped().await.unwrap();
        let keys = KeyPair::generate();
        let mut server = server_dht.create_server(
            &runtime,
            ServerConfig::new(keys.clone(), FIREWALL_UNKNOWN),
            events,
        );
        server.listen(&keys).await.unwrap();

        // A reachable client whose address the DHT knows says OPEN.
        let (_ct, client, _) = spawn(&runtime, node(boot, false)).await.unwrap();
        client.fully_bootstrapped().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while client.remote_address().await.unwrap().is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the client learns its address");

        let opts = ConnectOpts {
            local_connection: false,
            ..ConnectOpts::default()
        };
        let wait = std::time::Duration::from_secs(15);
        let mut conn = tokio::time::timeout(
            wait,
            client.connect_with_options(&KeyPair::generate(), keys.public_key, &[], &runtime, opts),
        )
        .await
        .expect("connect finished")
        .expect("the server's dial connects us");
        // The stream came from the server's DHT socket (its dial), not from
        // a puncher socket.
        let dialled_from = server_dht
            .server_socket()
            .await
            .unwrap()
            .unwrap()
            .local_addr()
            .await
            .unwrap()
            .port();
        assert_eq!(conn.remote_addr.map(|a| a.port()), Some(dialled_from));
        let mut accepted = tokio::time::timeout(wait, server.accept())
            .await
            .expect("server accepted")
            .expect("a connection");
        conn.stream.write(b"open").await.unwrap();
        let got = tokio::time::timeout(wait, accepted.stream.read())
            .await
            .expect("data arrived")
            .unwrap();
        assert_eq!(got.as_deref(), Some(&b"open"[..]));
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_direct_handshake_to_either_dht_socket_connects() {
        let runtime = UdxRuntime::new().unwrap();
        // Firewalled, so requests leave the client socket and the node
        // listens on its server socket: two sockets, two ports.
        let (_s, server_dht, events) = spawn(&runtime, firewalled_local_config()).await.unwrap();
        let (_c, client, _ce) = spawn(&runtime, firewalled_local_config()).await.unwrap();
        let keys = KeyPair::generate();
        let mut server = server_dht.create_server(
            &runtime,
            ServerConfig::new(keys.clone(), FIREWALL_UNKNOWN),
            events,
        );
        server.listen(&keys).await.unwrap();
        let mut ports = Vec::new();
        for socket in [
            server_dht.server_socket().await.unwrap(),
            server_dht.listen_socket().await.unwrap(),
        ] {
            ports.push(socket.unwrap().local_addr().await.unwrap().port());
        }
        assert_ne!(ports[0], ports[1], "the node has two DHT sockets");

        let wait = std::time::Duration::from_secs(10);
        for port in ports {
            let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
            let mut conn = tokio::time::timeout(
                wait,
                client.connect_to(&KeyPair::generate(), keys.public_key, addr, &runtime),
            )
            .await
            .expect("connect finished")
            .expect("a direct handshake connects");
            // Node `connectThroughNode`: the exact address the handshake went to.
            assert_eq!(conn.remote_addr, Some(addr));
            let mut accepted = tokio::time::timeout(wait, server.accept())
                .await
                .expect("server accepted")
                .expect("a connection");
            conn.stream.write(b"direct").await.unwrap();
            let got = tokio::time::timeout(wait, accepted.stream.read())
                .await
                .expect("data arrived")
                .unwrap();
            assert_eq!(got.as_deref(), Some(&b"direct"[..]));
        }
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn listen_in_background_does_not_wait_for_the_first_announce() {
        let runtime = UdxRuntime::new().unwrap();
        // A bootstrap node that never answers keeps the announce query busy
        // for seconds.
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = firewalled_local_config();
        config.dht.bootstrap = vec![silent.local_addr().unwrap().to_string()];
        let (_task, dht, events) = spawn(&runtime, config).await.unwrap();
        let keys = KeyPair::generate();
        let mut server = dht.create_server(
            &runtime,
            ServerConfig::new(keys.clone(), FIREWALL_UNKNOWN),
            events,
        );
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            server.listen_in_background(&keys),
        )
        .await
        .expect("listen_in_background waited on the DHT")
        .expect("listen");
        assert!(server.listening());
        server.suspend().await.expect("suspend");
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            server.resume_in_background(),
        )
        .await
        .expect("resume_in_background waited on the DHT")
        .expect("resume");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn announce_fails_when_every_write_fails() {
        let runtime = UdxRuntime::new().unwrap();
        let (node, node_task) = fake_rejecting_node().await;
        let mut config = firewalled_local_config();
        config.dht.bootstrap = vec![node];
        let (_task, dht, _events) = spawn(&runtime, config).await.unwrap();
        let keys = KeyPair::generate();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            dht.announce(hash(&keys.public_key), &keys, &[]),
        )
        .await
        .expect("announce finished");
        assert!(matches!(result, Err(HyperDhtError::TooFewNodesResponded)));
        assert!(dht.current_relays().is_empty());
        node_task.abort();
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
