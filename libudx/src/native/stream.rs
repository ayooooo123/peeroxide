use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::task::Waker;
use std::time::Instant;

use bytes::{Buf, Bytes, BytesMut};
use tokio::sync::{mpsc, oneshot, watch};

use super::congestion::CaState;
use super::congestion::filter::WinFilter;
use super::congestion::rate::Delivered;
use super::header::{
    FLAG_DATA, FLAG_DESTROY, FLAG_END, FLAG_HEARTBEAT, FLAG_MESSAGE, FLAG_SACK, HEADER_SIZE,
    Header, SackRange, decode_sack_into, encode_sack,
};
use super::receive_window::{ReadMeter, ReceiveWindow};
use crate::error::{Result, UdxError};

// ── Constants ────────────────────────────────────────────────────────────────

/// Default receive window size (4 MB, matches C libudx).
pub(crate) const DEFAULT_RWND: u32 = 4_194_304;

/// IPv4 and UDP header bytes in front of a UDX packet (C
/// `UDX_IPV4_HEADER_SIZE - UDX_HEADER_SIZE`).
const IPV4_UDP_OVERHEAD: usize = 20 + 8;

/// IPv6 and UDP header bytes in front of a UDX packet.
const IPV6_UDP_OVERHEAD: usize = 40 + 8;

/// Starting MTU — C libudx `UDX_MTU_BASE`. Like every MTU value here, an
/// IP packet size (IP + UDP + UDX headers + payload), as in C.
pub(crate) const MTU_BASE: usize = 1200;

/// Maximum payload per packet at `MTU_BASE` over IPv4 (C `udx__max_payload`).
pub(crate) const MAX_PAYLOAD: usize = MTU_BASE - IPV4_UDP_OVERHEAD - HEADER_SIZE;

/// Maximum MTU (IP packet bytes) — matches C libudx `UDX_MTU_MAX`.
pub(crate) const MTU_MAX: usize = 1500;

/// Probe size increment (bytes).
pub(crate) const MTU_STEP: usize = 32;

/// Failed probes before settling on current MTU.
pub(crate) const MTU_MAX_PROBES: u32 = 3;

/// Initial retransmission timeout (ms) — matches C libudx.
const INITIAL_RTO_MS: u32 = 1_000;

/// Maximum retransmission timeout (ms) — matches C libudx `UDX_RTO_MAX_MS`.
const MAX_RTO_MS: u32 = 30_000;

/// RTO firings without the cumulative ACK moving that a stream survives;
/// the next one ends it (C `UDX_MAX_RTO_TIMEOUTS`, checked with `>`).
const MAX_RTO_TIMEOUTS: u32 = 6;

/// Default keepalive interval: the 5 s hyperdht sets on its UDX streams.
const DEFAULT_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(5);

/// Keepalive intervals without any packet from the peer after which a
/// stream with keepalive on ends with a timeout. Peers answer every
/// heartbeat with an ACK (C `process_packet`), so silence means a dead path.
const KEEPALIVE_DEAD_INTERVALS: u32 = 6;

/// Out-of-order packets accepted ahead of the cumulative ACK: the window we
/// advertise, in packets of the smallest payload a peer uses (`MTU_BASE`
/// over IPv6). A sender honouring the window never goes further.
const RECV_WINDOW_PACKETS: u32 = DEFAULT_RWND / (MTU_BASE - IPV6_UDP_OVERHEAD - HEADER_SIZE) as u32;

/// Packets queued from the socket to one stream's processor; more are
/// dropped like any UDP overflow and recovered by retransmission.
pub(crate) const INCOMING_QUEUE: usize = 1024;

/// MESSAGE payloads held for `UdxStreamRemote::recv_message`; more are
/// dropped, like any unreliable datagram nobody reads.
const MESSAGE_QUEUE: usize = 64;

/// Added to a single-packet loss probe's timeout (C `UDX_TLP_MAX_ACK_DELAY`).
const TLP_MAX_ACK_DELAY_MS: u32 = 2;

/// Maximum number of SACK ranges to include in an ACK packet.
const MAX_SACK_RANGES: usize = 50;

/// Most in-order DATA packets one ACK covers while a receive burst is still
/// queued (C ACKs every packet; TCP every second). Halves or better the ACK
/// packets both peers handle without delaying an ACK past the burst.
const ACK_EVERY: u32 = 8;

/// Maximum accepted RTT sample (ms) — prevents outlier corruption.
const MAX_RTT_MS: u32 = 30_000;
/// Maximum accepted RTT sample (µs).
const MAX_RTT_US: u64 = 30_000_000;

/// Window of the minimum-RTT filter RACK's reorder window reads (C
/// `UDX_RTT_MIN_WINDOW_MS`, the Linux default), in microseconds.
const RTT_MIN_WINDOW_US: u32 = 300_000_000;

/// Far-future duration used to effectively disable a timer.
const FAR_FUTURE: std::time::Duration = std::time::Duration::from_secs(86_400);

/// How long a stream that ended first keeps answering for its id after it
/// closed (C `UDX_STREAM_TIMEWAIT_TIMEOUT_MS`).
const TIMEWAIT: std::time::Duration = std::time::Duration::from_millis(5_000);

/// Bytes one stream may hold queued plus sent-but-unacked before
/// `UdxAsyncStream::poll_write` applies back-pressure.
pub(crate) const SEND_BUFFER_MAX: usize = 1024 * 1024;

/// IP and UDP header bytes in front of a packet to `addr` (C picks by family;
/// no address yet means IPv4).
fn ip_overhead(addr: Option<SocketAddr>) -> usize {
    match addr {
        Some(SocketAddr::V6(_)) => IPV6_UDP_OVERHEAD,
        _ => IPV4_UDP_OVERHEAD,
    }
}

// ── MTU Probing State ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MtuState {
    Base,
    Search,
    SearchComplete,
}

// ── Sequence number comparison ───────────────────────────────────────────────

/// Returns true if sequence number `a` is strictly after `b` (handles u32 wraparound).
#[inline]
fn seq_after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b)) as i32 > 0
}

// ── Packet types ─────────────────────────────────────────────────────────────

/// One datagram routed to a stream's processor.
///
/// The socket demux decodes the header once, so the header travels beside a
/// body that holds the datagram from byte `HEADER_SIZE` on. Positions inside
/// `body` are the wire positions minus `HEADER_SIZE`: the payload starts at
/// `header.data_offset as usize`, and the SACK region is
/// `header.sack_region(HEADER_SIZE + body.len())` shifted down by
/// `HEADER_SIZE`.
pub(crate) struct IncomingPacket {
    pub header: Header,
    pub body: Bytes,
    #[allow(dead_code)]
    pub addr: SocketAddr,
    /// The socket the datagram arrived on: the firewall hook commits to it,
    /// and a stream mid-`change_remote` answers on this path when the peer
    /// still sends from the old one (C libudx routes by the `udx_socket_t`
    /// the packet arrived on).
    pub socket: super::socket::UdxSocket,
    /// Identity of the underlying `Udp` (`Arc::as_ptr(&udp) as usize`), so the
    /// stream task can check same-socket arrival without locking `UdxSocket`.
    pub udp_ptr: usize,
}

pub(crate) enum StreamEvent {
    Data(Bytes),
    End,
    /// The stream died: the peer destroyed it or it timed out. Readers see
    /// this error once; C libudx closes the stream with the same error.
    Error(std::io::ErrorKind),
}

/// Why `take_send_batch` stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendStop {
    /// Nothing left to send (or no peer yet).
    Idle,
    /// The congestion window or the peer's window is full: an ACK, the RTO or
    /// a zero-window probe moves things on, not a timer poll.
    Window,
    /// The pacer is empty for this long.
    Pacing(std::time::Duration),
}
/// Notification from the send path to the processor task.
pub(crate) enum StreamNotify {
    DataQueued,
    Shutdown,
    /// The owner dropped the stream: send what is queued, then DESTROY.
    Dropped,
    /// The keepalive interval changed.
    Keepalive,
    /// The reader took data: tell the peer the larger window.
    WindowUpdate,
}

type WriteSenders = Vec<Option<oneshot::Sender<Result<()>>>>;
type AckedRateInfo = Vec<Delivered>;

/// Payload bytes of a built packet: after the header and any MTU-probe
/// padding (`data_offset`).
fn payload_len(packet: &[u8]) -> usize {
    packet
        .len()
        .saturating_sub(HEADER_SIZE + packet.get(3).copied().unwrap_or(0) as usize)
}

/// What `on_ack_packet` did, for the processor's timers.
#[derive(Default)]
struct AckOutcome {
    /// Writes the ACK completed (populated only by the test wrapper; the
    /// processor reuses its own scratch vector).
    #[cfg(test)]
    completed: WriteSenders,
    /// The cumulative ACK moved forward.
    ack_advanced: bool,
    /// The ACK delivered at least one packet (cumulatively or by SACK).
    delivered: bool,
    /// Arm the reorder timer for this long (C `UDX_TIMER_RACK_REO`).
    reorder_timeout: Option<std::time::Duration>,
    /// Why the send pass stopped, if a send pass ran.
    send_stop: Option<SendStop>,
    /// Whether the send pass queued new data (for TLP scheduling).
    send_new_data: bool,
    /// Packets the send pass after loss detection took (populated only by the
    /// test wrapper; the processor reuses its own scratch vector).
    #[cfg(test)]
    batch: Vec<(Bytes, SocketAddr)>,
}

/// What a socket's demux holds for a stream id (C `udx_stream_entry_t`).
pub(crate) enum StreamEntry {
    /// A live stream: packets go to its processor.
    Stream(mpsc::Sender<IncomingPacket>),
    /// A stream that closed after both sides ended, having ended first
    /// (C `udx_timewait_t`): a late DATA or END is answered with the final
    /// ACK, and nothing reaches whatever owned the id.
    Timewait(Arc<Timewait>),
}

/// The final ACK of a closed stream and where to send it (C
/// `stream_timewait`). The socket is held weakly: like C, which closes
/// timewaits with their socket, a closed socket answers nothing.
pub(crate) struct Timewait {
    udp: Weak<super::udp::Udp>,
    remote_addr: SocketAddr,
    header: [u8; HEADER_SIZE],
}

impl Timewait {
    /// Answer a packet that arrived for the closed stream (C
    /// `process_timewait`): DATA and END get the final ACK, the rest nothing.
    pub(crate) fn answer(&self, type_flags: u8) {
        if type_flags & (FLAG_DATA | FLAG_END) == 0 {
            return;
        }
        if let Some(udp) = self.udp.upgrade() {
            send_now(Some((
                udp,
                self.remote_addr,
                ControlBytes::inline_header(self.header),
            )));
        }
    }
}

type StreamMap = Arc<Mutex<std::collections::HashMap<u32, StreamEntry>>>;
/// Stream maps of the sockets a stream is registered on. Shared by the
/// stream handle and its processor task.
type Registrations = Arc<Mutex<Vec<StreamMap>>>;
type FirewallHook = Box<dyn FnMut(&super::socket::UdxSocket, u16, std::net::IpAddr) -> bool + Send>;
/// Where a stream sends: `(remote_id, remote_addr, socket)`, published by
/// the stream for relay legs that forward to it. The lock is a leaf: it is
/// never held while taking another, so no `StreamInner` ever locks another.
type Endpoint = Arc<Mutex<Option<(u32, SocketAddr, Arc<super::udp::Udp>)>>>;

// ── Reliability types ────────────────────────────────────────────────────────

/// A sent packet stored in the outgoing buffer for potential retransmission.
struct SentPacket {
    /// Full wire-format packet bytes (header + payload), shared with the send
    /// batch so sending and retransmitting clone a handle instead of copying.
    packet: Bytes,
    /// Destination captured when the packet was first sent. Retransmits go
    /// here even after `change_remote` moved the stream (C libudx keeps
    /// `pkt->remote_addr` per packet).
    remote_addr: SocketAddr,
    /// When this packet was (last) sent — for RTT measurement on first send.
    time_sent: Instant,
    /// Number of times this packet has been retransmitted.
    retransmit_count: u32,
    /// Whether this packet has been selectively acknowledged via SACK.
    sacked: bool,
    /// Whether this packet was sent as an MTU probe (oversized via data_offset padding).
    is_mtu_probe: bool,
    /// Whether this packet has been detected as lost (SACK gap analysis).
    lost: bool,
    rate_info: Option<super::congestion::rate::PacketRateInfo>,
}

impl SentPacket {
    /// Counted by `inflight()`: neither SACKed nor waiting for a retransmit.
    fn is_inflight(&self) -> bool {
        !self.sacked && !self.lost
    }
}

/// Sequence-indexed ring buffer of unacknowledged sent packets.
///
/// Replaces `BTreeMap<u32, SentPacket>` on the hot path: O(1) insert, lookup,
/// cumulative pop, and SACK range walks with zero per-node heap allocations
/// once warmed up to the stream's BDP, and wrapping-safe sequence ordering.
struct OutgoingMap {
    /// Sequence number of `slots[0]` when `count > 0`.
    base: u32,
    /// Invariant: when `count > 0`, both `slots.front()` and `slots.back()` are `Some`.
    slots: VecDeque<Option<SentPacket>>,
    count: usize,
}

impl OutgoingMap {
    fn new() -> Self {
        Self {
            base: 0,
            slots: VecDeque::new(),
            count: 0,
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[inline]
    fn len(&self) -> usize {
        self.count
    }

    fn clear(&mut self) {
        self.slots.clear();
        self.count = 0;
    }

    fn insert(&mut self, seq: u32, pkt: SentPacket) -> Option<SentPacket> {
        if self.count == 0 {
            self.base = seq;
            self.slots.clear();
            self.slots.push_back(Some(pkt));
            self.count = 1;
            return None;
        }
        let delta = seq.wrapping_sub(self.base) as i32;
        if delta >= 0 {
            let idx = delta as usize;
            if idx < self.slots.len() {
                let prev = self.slots[idx].replace(pkt);
                if prev.is_none() {
                    self.count += 1;
                }
                prev
            } else {
                self.slots.resize_with(idx, || None);
                self.slots.push_back(Some(pkt));
                self.count += 1;
                None
            }
        } else {
            let pre = (-delta) as usize;
            for _ in 1..pre {
                self.slots.push_front(None);
            }
            self.slots.push_front(Some(pkt));
            self.base = seq;
            self.count += 1;
            None
        }
    }

    #[inline]
    fn get(&self, seq: &u32) -> Option<&SentPacket> {
        if self.count == 0 {
            return None;
        }
        let delta = seq.wrapping_sub(self.base) as i32;
        if delta < 0 {
            return None;
        }
        self.slots.get(delta as usize).and_then(|s| s.as_ref())
    }

    #[inline]
    fn get_mut(&mut self, seq: &u32) -> Option<&mut SentPacket> {
        if self.count == 0 {
            return None;
        }
        let delta = seq.wrapping_sub(self.base) as i32;
        if delta < 0 {
            return None;
        }
        self.slots.get_mut(delta as usize).and_then(|s| s.as_mut())
    }

    #[inline]
    fn first_key_value(&self) -> Option<(u32, &SentPacket)> {
        if self.count == 0 {
            return None;
        }
        self.slots
            .front()
            .and_then(|s| s.as_ref())
            .map(|p| (self.base, p))
    }

    #[inline]
    fn pop_first(&mut self) -> Option<(u32, SentPacket)> {
        if self.count == 0 {
            return None;
        }
        let pkt = self.slots.pop_front().flatten()?;
        let seq = self.base;
        self.base = self.base.wrapping_add(1);
        self.count -= 1;
        while matches!(self.slots.front(), Some(None)) {
            self.slots.pop_front();
            self.base = self.base.wrapping_add(1);
        }
        Some((seq, pkt))
    }

    #[inline]
    fn last_key_value(&self) -> Option<(u32, &SentPacket)> {
        if self.count == 0 {
            return None;
        }
        let seq = self.base.wrapping_add((self.slots.len() - 1) as u32);
        self.slots.back().and_then(|s| s.as_ref()).map(|p| (seq, p))
    }

    #[inline]
    fn last_seq(&self) -> Option<u32> {
        (self.count > 0).then(|| self.base.wrapping_add((self.slots.len() - 1) as u32))
    }

    fn values(&self) -> impl Iterator<Item = &SentPacket> {
        self.slots.iter().filter_map(|s| s.as_ref())
    }

    #[cfg(test)]
    fn iter(&self) -> impl Iterator<Item = (u32, &SentPacket)> {
        let base = self.base;
        self.slots
            .iter()
            .enumerate()
            .filter_map(move |(i, s)| s.as_ref().map(|p| (base.wrapping_add(i as u32), p)))
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = (u32, &mut SentPacket)> {
        let base = self.base;
        self.slots
            .iter_mut()
            .enumerate()
            .filter_map(move |(i, s)| s.as_mut().map(|p| (base.wrapping_add(i as u32), p)))
    }

    fn range_bounds(&self, range: std::ops::Range<u32>) -> (usize, usize) {
        if self.count == 0 || !seq_after(range.end, range.start) {
            return (0, 0);
        }
        let len = self.slots.len();
        let lo = if seq_after(range.start, self.base) {
            (range.start.wrapping_sub(self.base) as usize).min(len)
        } else {
            0
        };
        let hi = if seq_after(range.end, self.base) {
            (range.end.wrapping_sub(self.base) as usize).min(len)
        } else {
            0
        };
        (lo.min(hi), hi)
    }

    #[cfg(test)]
    fn range(&self, range: std::ops::Range<u32>) -> impl Iterator<Item = (u32, &SentPacket)> {
        let base = self.base;
        let (lo, hi) = self.range_bounds(range);
        self.slots
            .range(lo..hi)
            .enumerate()
            .filter_map(move |(i, s)| s.as_ref().map(|p| (base.wrapping_add((lo + i) as u32), p)))
    }

    fn range_mut(
        &mut self,
        range: std::ops::Range<u32>,
    ) -> impl Iterator<Item = (u32, &mut SentPacket)> {
        let base = self.base;
        let (lo, hi) = self.range_bounds(range);
        self.slots
            .range_mut(lo..hi)
            .enumerate()
            .filter_map(move |(i, s)| s.as_mut().map(|p| (base.wrapping_add((lo + i) as u32), p)))
    }
}

#[cfg(test)]
impl std::ops::Index<&u32> for OutgoingMap {
    type Output = SentPacket;

    fn index(&self, seq: &u32) -> &Self::Output {
        self.get(seq).expect("seq not in OutgoingMap")
    }
}

/// A received out-of-order packet buffered until gaps are filled.
struct RecvdPacket {
    payload: Bytes,
    flags: u8,
}

/// One write waiting to be cut into packets (C `udx_stream_write_buf_t`).
/// Packets are built at send time at the MTU of that moment, so a write
/// queued before an MTU change or `change_remote` goes out at the new size.
struct WriteBuf {
    data: Vec<u8>,
    /// Bytes of `data` already put into packets.
    sent: usize,
    /// The FIN (C `is_write_end`): an empty buffer, last in the queue.
    end: bool,
    /// Resolved once the packet carrying the last byte is cumulatively ACKed.
    done: Option<oneshot::Sender<Result<()>>>,
}

/// A write whose last packet is sent, awaiting the remote's cumulative ACK.
pub(crate) struct PendingWrite {
    pub(crate) ack_threshold: u32,
    pub(crate) tx: Option<oneshot::Sender<Result<()>>>,
}

/// Remove `local_id` from every socket map in `registrations` where it is
/// still this stream (`tx`; any live stream when `None`). A timewait entry
/// stays until it expires or a new stream takes the id.
fn deregister(
    local_id: u32,
    registrations: &Registrations,
    tx: Option<&mpsc::Sender<IncomingPacket>>,
) {
    let maps = std::mem::take(&mut *registrations.lock().unwrap_or_else(|e| e.into_inner()));
    for map in maps {
        let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
        let ours = match guard.get(&local_id) {
            Some(StreamEntry::Stream(existing)) => tx.is_none_or(|tx| existing.same_channel(tx)),
            _ => false,
        };
        if ours {
            guard.remove(&local_id);
        }
    }
}

// ── StreamInner ──────────────────────────────────────────────────────────────

pub(crate) struct StreamInner {
    // ── Connection identity ──
    pub(crate) remote_id: u32,
    pub(crate) remote_addr: Option<SocketAddr>,
    pub(crate) connected: bool,
    terminated: bool,
    /// True once `prepare_end()` has been called (FIN queued).
    ended: bool,
    /// The peer's END was delivered in order (C `UDX_STREAM_ENDED_REMOTE`).
    remote_ended: bool,
    /// We ended before the peer did, so a clean close leaves a timewait
    /// entry behind (C `UDX_STREAM_TIMEWAIT_WANTED`).
    timewait_wanted: bool,

    // ── Send state ──
    /// Seq of the next packet built (C `stream->seq`): everything below it
    /// was sent, so it bounds a valid cumulative ACK, and control packets
    /// carry it.
    pub(crate) next_seq: u32,
    pub(crate) pending_writes: Vec<PendingWrite>,
    /// Sent packets awaiting ACK, in a sequence-indexed ring buffer.
    outgoing: OutgoingMap,
    /// Packets in `outgoing` neither SACKed nor marked lost (`inflight()`),
    /// kept as a counter: the send and ACK paths read it once per packet.
    inflight_count: u32,
    /// `(time_sent, seq)` of every transmission, oldest first. Send times
    /// never decrease, so RACK's "sent before the newest delivered packet"
    /// rule only looks at the front; entries whose packet was ACKed, SACKed,
    /// marked lost or sent again since are skipped when reached.
    send_order: VecDeque<(Instant, u32)>,
    /// Packets marked lost, in loss order, waiting for `take_send_batch` to
    /// retransmit them under the congestion window and the pacer (C
    /// `retransmit_queue`). May hold stale seqs; those are skipped.
    lost_queue: VecDeque<u32>,
    /// Packets in `outgoing` marked SACKed (C `stream->sacks`).
    sacked_count: u32,
    /// Sorted, disjoint seq intervals some SACK block already covered (only
    /// seqs that had been sent), so `on_sack` skips what it has marked.
    sack_cover: Vec<(u32, u32)>,
    /// Bytes in `write_queue` not cut into packets yet.
    queued_bytes: usize,
    /// Payload bytes written and not yet ACKed or SACKed (C
    /// `writes_queued_bytes`), for the app-limited check.
    unacked_written: usize,
    /// Bytes in `outgoing`, sent but not cumulatively ACKed.
    unacked_bytes: usize,
    /// Writer waiting for send-buffer room (see `SEND_BUFFER_MAX`).
    write_waker: Option<Waker>,
    /// Writer waiting for everything sent to be ACKed.
    flush_waker: Option<Waker>,

    // ── Receive state ──
    pub(crate) next_remote_seq: u32,
    /// Highest cumulative ACK received from remote.
    remote_acked: u32,
    /// Send time and seq of the most recently sent packet the peer has
    /// delivered (RACK `rack.xmit_ts`/`rack.end_seq`, C `rack_time_sent`,
    /// `rack_next_seq - 1`). A retransmission counts only when its RTT is
    /// at least the minimum RTT: its ACK could be for the original copy.
    rack: Option<(Instant, u32)>,
    /// RTT (µs) of the delivery that last set `rack` (C `rack_rtt`).
    rack_rtt_us: u64,
    /// RACK RTT (µs) of the newest packet the current ACK delivered, for its
    /// rate sample; 0 for none.
    rs_rtt_us: u64,
    /// A write landed on an idle zero-window stream: probe at once.
    zwp_wanted: bool,
    /// One past the highest seq delivered so far (C `rack_fack`).
    rack_fack: u32,
    /// A never-retransmitted packet was delivered below `rack_fack`: the
    /// path reorders, so the reorder window stays open (C `reordering_seen`).
    reordering_seen: bool,
    /// Minimum RTT (µs) over `RTT_MIN_WINDOW_US`, on the `epoch` microsecond
    /// clock (C `rtt_min`); `u64::MAX` before the first sample.
    rtt_min_us: WinFilter<u64>,
    /// Origin of the microsecond clock `rtt_min_us` and BBR run on.
    epoch: Instant,
    /// Fake clock for state-machine tests (`now()`).
    #[cfg(test)]
    clock: Option<Instant>,
    /// Out-of-order receive buffer, keyed by sequence number.
    recv_buf: BTreeMap<u32, RecvdPacket>,
    /// The seqs in `recv_buf` as sorted, disjoint, non-adjacent half-open
    /// ranges (C's SACK block list), kept per packet so an ACK costs
    /// O(ranges) instead of a walk of the buffer.
    recv_ranges: Vec<(u32, u32)>,
    /// Our receive window: what the peer may still send, shared with the
    /// reader handles that count what they take.
    pub(crate) receive_window: Arc<ReceiveWindow>,

    // ── RTT estimation (Jacobson/Karels in µs, ms snapshot kept for stats/RTO) ──
    srtt: u32,
    srtt_us: u64,
    rttvar: u32,
    rttvar_us: u64,
    rto: u32,
    rto_timeouts: u32,
    retransmits: u64,

    // ── Flow control ──
    /// Remote's last advertised receive window.
    send_rwnd: u32,

    // ── Tail loss probe (C `tlp_*`, RACK §7) ──
    tlp_permitted: bool,
    tlp_in_flight: bool,
    tlp_is_retrans: bool,
    tlp_end_seq: u32,

    /// Idle heartbeat interval; `None` sends none (C `keepalive_timeout_ms`).
    keepalive: Option<std::time::Duration>,

    // ── MTU probing state ──
    pub(crate) mtu_state: MtuState,
    pub(crate) mtu: usize,
    pub(crate) mtu_probe_size: usize,
    pub(crate) mtu_probe_count: u32,
    pub(crate) mtu_probe_wanted: bool,
    pub(crate) mtu_max: usize,

    // ── IO ──
    pub(crate) udp: Option<Arc<super::udp::Udp>>,
    /// The socket `udp` belongs to. Holding it keeps the socket receiving
    /// while the stream uses it, as a C stream keeps its `udx_socket_t`:
    /// the last other handle (a holepunch pool, say) may be dropped first.
    socket: Option<super::socket::UdxSocket>,
    pub(crate) read_tx: mpsc::UnboundedSender<StreamEvent>,
    close_tx: Option<oneshot::Sender<()>>,
    close_watch_tx: watch::Sender<bool>,
    close_watch_rx: watch::Receiver<bool>,
    pub(crate) notify_tx: Option<mpsc::UnboundedSender<StreamNotify>>,

    // ── Congestion control (BBR) ──
    pub(crate) congestion: super::congestion::CongestionController,
    /// Writes not yet sent, in order (C `write_queue`).
    write_queue: VecDeque<WriteBuf>,

    // ── Relay ──
    /// Endpoint of the stream this one forwards to (C `relay_to`).
    relay_target: Option<Endpoint>,
    /// This stream's own endpoint, read by relay legs forwarding to it.
    endpoint: Endpoint,

    // ── Firewall hook (set_firewall_hook path) ──
    /// Consulted while unconnected and for packets arriving on a socket
    /// other than the stream's (C `on_firewall`, udx.c:1643).
    firewall_hook: Option<FirewallHook>,

    // ── Remote migration (`change_remote`) ──
    local_id: u32,
    /// Demux sender, so a migration can register the stream on another socket.
    incoming_tx: Option<mpsc::Sender<IncomingPacket>>,
    registrations: Registrations,
    /// First seq not sent before the change, and the waiter released once
    /// the peer has ACKed up to it (C `seq_on_remote_changed`).
    remote_change: Option<(u32, oneshot::Sender<()>)>,
    /// Released by data or a message from the current remote on this socket.
    remote_observed: Option<oneshot::Sender<()>>,
    observed_current_remote: bool,
    /// Received MESSAGE payloads (C `on_recv`); `None` once terminated.
    message_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Read side of `message_tx`, shared by `UdxStreamRemote` handles.
    message_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
    pub(crate) runtime: Option<Weak<super::runtime::RuntimeHandle>>,
    /// Slab backing newly built outbound packets so ~44 full-MTU packets share
    /// one heap allocation instead of allocating per packet.
    tx_slab: BytesMut,
    /// Scratch buffer reused by `detect_losses` across ACKs.
    lost_seqs_scratch: Vec<u32>,
    /// Scratch buffers reused by `on_sack_into` across SACKs.
    sack_delivered_scratch: Vec<(u32, Instant, bool)>,
    sack_gaps_scratch: Vec<(u32, u32)>,
    /// Pacing timer wakeups, for tests of the send loop's idle behaviour.
    #[cfg(test)]
    pacing_wakeups: u32,
}

impl StreamInner {
    // ── Stream termination ──────────────────────────────────────────────────

    /// Drain all pending writes with `StreamClosed`, wake blocked writers,
    /// mark the stream disconnected, and drop `notify_tx` so future sends
    /// fail fast. Idempotent — safe to call more than once.
    pub(crate) fn terminate(&mut self) {
        self.connected = false;
        self.terminated = true;
        self.notify_tx = None;
        // Migration waiters learn the stream died (their receivers error).
        self.remote_change = None;
        self.remote_observed = None;
        // Message readers see the end once the queue is read.
        self.message_tx = None;
        // Wake readers: an aborted stream reads as EOF instead of hanging.
        let _ = self.read_tx.send(StreamEvent::End);
        // Release the socket so a suspended DHT socket can be rebound.
        self.udp = None;
        self.socket = None;
        self.publish_endpoint();
        deregister(
            self.local_id,
            &self.registrations,
            self.incoming_tx.as_ref(),
        );
        if let Some(tx) = self.close_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.close_watch_tx.send(true);
        if let Some(rt) = self.runtime.as_ref().and_then(|w| w.upgrade()) {
            rt.unregister_stream(self.local_id);
        }
        for mut pw in self.pending_writes.drain(..) {
            if let Some(tx) = pw.tx.take() {
                let _ = tx.send(Err(UdxError::StreamClosed));
            }
        }
        // Abort handles can outlive the stream; they must not pin packet storage.
        self.write_queue = VecDeque::new();
        self.tx_slab = BytesMut::new();
        self.lost_seqs_scratch = Vec::new();
        self.sack_delivered_scratch = Vec::new();
        self.sack_gaps_scratch = Vec::new();
        self.outgoing.clear();
        self.inflight_count = 0;
        self.sacked_count = 0;
        self.send_order = VecDeque::new();
        self.lost_queue = VecDeque::new();
        self.sack_cover = Vec::new();
        self.recv_buf.clear();
        self.recv_ranges = Vec::new();
        self.receive_window.clear_out_of_order();
        self.queued_bytes = 0;
        self.unacked_written = 0;
        self.unacked_bytes = 0;
        if let Some(w) = self.write_waker.take() {
            w.wake();
        }
        if let Some(w) = self.flush_waker.take() {
            w.wake();
        }
    }

    /// End the stream with `kind` (C `close_stream(stream, err)`): pending
    /// writes and the reader see the error, then the stream terminates.
    fn fail(&mut self, kind: std::io::ErrorKind, reason: &'static str) {
        if self.terminated {
            return;
        }
        let queued = self.write_queue.iter_mut().filter_map(|w| w.done.take());
        let sent = self
            .pending_writes
            .drain(..)
            .filter_map(|mut pw| pw.tx.take());
        for tx in sent.chain(queued) {
            let _ = tx.send(Err(UdxError::Io(std::io::Error::new(kind, reason))));
        }
        let _ = self.read_tx.send(StreamEvent::Error(kind));
        self.terminate();
    }

    /// Our END is ACKed: it and everything before it reached the peer (C
    /// `UDX_STREAM_ENDED`).
    fn end_acked(&self) -> bool {
        self.ended && !self.terminated && self.all_acked()
    }

    /// Both directions have ended and everything we sent is ACKed (C
    /// `UDX_STREAM_ALL_ENDED`): the stream closes by itself.
    fn all_ended(&self) -> bool {
        self.remote_ended && self.end_acked()
    }

    /// Close a stream whose both directions ended (C `close_stream(stream,
    /// 0)`): a stream that ended first leaves a timewait entry for its id on
    /// every socket it was registered on, answering a late DATA or END with
    /// the final ACK for `TIMEWAIT` (C `stream_timewait`). The peer's data
    /// and EOF are queued for the reader (it may not have read them yet)
    /// and every write completed, so close observers fire with no error.
    fn close_ended(&mut self) {
        if self.timewait_wanted {
            self.enter_timewait();
        }
        self.terminate();
    }

    fn enter_timewait(&self) {
        let (Some(udp), Some(remote_addr), Some(tx)) =
            (&self.udp, self.remote_addr, &self.incoming_tx)
        else {
            return;
        };
        let timewait = Arc::new(Timewait {
            udp: Arc::downgrade(udp),
            remote_addr,
            header: self.control_header(0).encode(),
        });
        let local_id = self.local_id;
        let maps: Vec<_> = self
            .registrations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(Arc::downgrade)
            .collect();
        for map in maps.iter().filter_map(Weak::upgrade) {
            let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
            if matches!(guard.get(&local_id), Some(StreamEntry::Stream(ours)) if ours.same_channel(tx))
            {
                guard.insert(local_id, StreamEntry::Timewait(Arc::clone(&timewait)));
            }
        }
        // C `timewait_timeout`: the id is free again, unless a new stream
        // took it already.
        tokio::spawn(async move {
            tokio::time::sleep(TIMEWAIT).await;
            for map in maps.iter().filter_map(Weak::upgrade) {
                let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
                if matches!(guard.get(&local_id), Some(StreamEntry::Timewait(entry)) if Arc::ptr_eq(entry, &timewait))
                {
                    guard.remove(&local_id);
                }
            }
        });
    }

    /// Publish where this stream sends, for relay legs forwarding to it.
    fn publish_endpoint(&self) {
        let endpoint = match (self.connected, self.remote_addr, &self.udp) {
            (true, Some(addr), Some(udp)) => Some((self.remote_id, addr, Arc::clone(udp))),
            _ => None,
        };
        *self.endpoint.lock().unwrap_or_else(|e| e.into_inner()) = endpoint;
    }

    /// Header of a control packet (ACK, heartbeat) as C `udx_write_header`.
    fn control_header(&self, type_flags: u8) -> Header {
        Header {
            type_flags,
            data_offset: 0,
            remote_id: self.remote_id,
            recv_window: self.receive_window.advertise(),
            seq: self.next_seq,
            ack: self.next_remote_seq,
        }
    }

    pub(crate) fn set_keepalive(&mut self, interval: Option<std::time::Duration>) {
        self.keepalive = interval.filter(|interval| !interval.is_zero());
        if let Some(tx) = &self.notify_tx {
            let _ = tx.send(StreamNotify::Keepalive);
        }
    }

    pub(crate) fn close_observer(&self) -> watch::Receiver<bool> {
        self.close_watch_rx.clone()
    }

    // ── MTU ──────────────────────────────────────────────────────────────────

    /// Payload bytes per packet at the current MTU (C `udx__max_payload`).
    pub(crate) fn max_payload(&self) -> usize {
        self.mtu - ip_overhead(self.remote_addr) - HEADER_SIZE
    }

    /// Back to the base MTU, re-probing from scratch: a migrated stream is
    /// on a new path (C `reset_mtu_state_machine`).
    fn reset_mtu(&mut self) {
        self.mtu = MTU_BASE;
        self.mtu_state = MtuState::Base;
        // The first probe confirms the base size, as in C.
        self.mtu_probe_size = MTU_BASE;
        self.mtu_probe_count = 0;
        self.mtu_probe_wanted = false;
        self.mtu_max = MTU_MAX;
        let mss = self.max_payload() as u32;
        self.congestion.on_mtu_change(mss);
    }

    /// Pad a full DATA packet to the IP size `mtu_probe_size` with zeros
    /// after the header, as C `mtu_probeify_packet` (padding 0..=255; the
    /// receiver skips it through `data_offset`). Returns whether the packet
    /// became a probe.
    fn mtu_probeify_packet(&mut self, packet: &mut Vec<u8>, remote_addr: SocketAddr) -> bool {
        if packet.len() < HEADER_SIZE || packet[2] & FLAG_DATA == 0 || packet[3] != 0 {
            return false;
        }
        let ip_size = packet.len() + ip_overhead(Some(remote_addr));
        let Some(padding) = self.mtu_probe_size.checked_sub(ip_size) else {
            return false;
        };
        if padding > 255 {
            return false;
        }
        packet.splice(HEADER_SIZE..HEADER_SIZE, std::iter::repeat_n(0u8, padding));
        packet[3] = padding as u8;
        self.mtu_probe_wanted = false;
        tracing::trace!(probe_size = self.mtu_probe_size, padding, "mtu: probeify");
        true
    }

    fn on_mtu_probe_acked(&mut self) {
        let old_mtu = self.mtu;
        self.mtu = self.mtu_probe_size;
        self.mtu_probe_count = 0;
        self.mtu_probe_size += MTU_STEP;

        if self.mtu_probe_size > self.mtu_max {
            self.mtu_probe_size = self.mtu_max;
        }

        if self.mtu >= self.mtu_max {
            self.mtu_state = MtuState::SearchComplete;
        } else {
            self.mtu_probe_wanted = true;
        }

        let mss = self.max_payload() as u32;
        self.congestion.on_mtu_change(mss);
        tracing::debug!(old_mtu, new_mtu = self.mtu, state = ?self.mtu_state, "mtu: probe acked");
    }

    /// A probe was lost: strip its padding (C `mtu_unprobeify_packet`).
    /// Probes are counted when sent (`send_new`, C udx.c:858), so an
    /// old-path probe lost after `reset_mtu` costs the new path nothing.
    fn unprobeify(&mut self, seq: u32) {
        let Some(pkt) = self.outgoing.get_mut(&seq) else {
            return;
        };
        if !pkt.is_mtu_probe {
            return;
        }
        let before = pkt.packet.len();
        strip_probe_padding(&mut pkt.packet);
        pkt.is_mtu_probe = false;
        let stripped = before - pkt.packet.len();
        self.unacked_bytes = self.unacked_bytes.saturating_sub(stripped);
        tracing::debug!(probes = self.mtu_probe_count, "mtu: probe failed");
        if self.mtu_state == MtuState::Search {
            if self.mtu_probe_count >= MTU_MAX_PROBES {
                self.mtu_state = MtuState::SearchComplete;
                self.mtu_probe_wanted = false;
            } else {
                self.mtu_probe_wanted = true;
            }
        }
    }

    /// The kernel refused a GSO send of `udp_size`-byte datagrams with
    /// `EMSGSIZE`: the path MTU is below that IP size. Treat it as a failed
    /// probe that ends the search, and step the MTU back below it.
    pub(crate) fn on_send_too_big(&mut self, udp_size: usize) {
        let ip_size = udp_size + ip_overhead(self.remote_addr);
        self.mtu_state = MtuState::SearchComplete;
        self.mtu_probe_wanted = false;
        if self.mtu < ip_size {
            return;
        }
        let old_mtu = self.mtu;
        // The probe grid point below the refused size, never under the base.
        self.mtu = MTU_BASE + ip_size.saturating_sub(MTU_BASE + 1) / MTU_STEP * MTU_STEP;
        self.mtu_max = self.mtu;
        let mss = self.max_payload() as u32;
        self.congestion.on_mtu_change(mss);
        tracing::debug!(old_mtu, new_mtu = self.mtu, "mtu: send too big");
    }

    // ── Write queue ──────────────────────────────────────────────────────────

    /// Queue `data` behind earlier writes (C `udx_stream_write`). It is cut
    /// into packets when the windows and the pacer let it go, at the MTU
    /// and peer of that moment, possibly sharing a packet with neighbouring
    /// writes as in C. `done` resolves once the packet carrying the last
    /// byte is cumulatively ACKed; an empty write rides on the next packet
    /// sent, as in C. An empty write nobody waits for queues nothing.
    pub(crate) fn queue_write(
        &mut self,
        data: &[u8],
        done: Option<oneshot::Sender<Result<()>>>,
    ) -> Result<()> {
        // A hooked stream may queue before its first packet commits a peer.
        if !self.connected && self.firewall_hook.is_none() {
            return Err(UdxError::Io(std::io::Error::other("stream not connected")));
        }
        self.check_open()?;
        if data.is_empty() && done.is_none() {
            return Ok(());
        }
        self.push_write(WriteBuf {
            data: data.to_vec(),
            sent: 0,
            end: false,
            done,
        });
        Ok(())
    }

    /// Queue the FIN behind every write (C `udx_stream_write_end`); later
    /// writes are refused. `done` resolves once the peer ACKed it.
    pub(crate) fn queue_end(&mut self, done: Option<oneshot::Sender<Result<()>>>) -> Result<()> {
        if !self.connected {
            return Err(UdxError::Io(std::io::Error::other("stream not connected")));
        }
        self.check_open()?;
        self.ended = true;
        // C `udx_stream_write_end`: the side that ends first waits in
        // timewait once the stream closes.
        self.timewait_wanted = !self.remote_ended;
        self.push_write(WriteBuf {
            data: Vec::new(),
            sent: 0,
            end: true,
            done,
        });
        Ok(())
    }

    fn check_open(&self) -> Result<()> {
        if self.ended {
            return Err(UdxError::Io(std::io::Error::other(
                "stream already shut down",
            )));
        }
        // `terminate()` drops the processor's channel: nothing would ever send.
        if self.udp.is_none() || self.notify_tx.is_none() {
            return Err(UdxError::StreamClosed);
        }
        Ok(())
    }

    /// Stage a write and wake the processor. A write landing on an idle
    /// stream whose peer advertised a zero window asks for a zero-window
    /// probe at once (C `_udx_stream_write`, udx.c:2805).
    fn push_write(&mut self, write: WriteBuf) {
        let was_unsent = self.has_unsent();
        let is_end = write.end;
        if self.unacked_written == 0 && self.send_rwnd == 0 && self.connected {
            self.zwp_wanted = true;
        }
        self.queued_bytes += write.data.len();
        self.unacked_written += write.data.len();
        self.write_queue.push_back(write);
        if let Some(tx) = self
            .notify_tx
            .as_ref()
            .filter(|_| !was_unsent || is_end || self.zwp_wanted)
        {
            let _ = tx.send(StreamNotify::DataQueued);
        }
    }

    /// Send-buffer bytes still free for `UdxAsyncStream::poll_write`.
    ///
    /// Scales with twice the active send window (`min(cwnd * mss, send_rwnd)`),
    /// floored at `SEND_BUFFER_MAX` (1 MiB) and capped at 16 MiB (matching C
    /// `UDX_HIGH_WATERMARK + send_window`), so SACK recovery on lossy links and
    /// high-BDP paths do not stall `poll_write`.
    pub(crate) fn send_buffer_room(&self) -> usize {
        const SEND_BUFFER_CEILING: usize = 16 * 1024 * 1024;
        let window = (self.congestion.cwnd as usize)
            .saturating_mul(self.max_payload())
            .min(self.send_rwnd as usize);
        let limit = window
            .saturating_mul(2)
            .clamp(SEND_BUFFER_MAX, SEND_BUFFER_CEILING);
        limit.saturating_sub(self.queued_bytes + self.unacked_bytes)
    }

    pub(crate) fn set_write_waker(&mut self, waker: &Waker) {
        self.write_waker = Some(waker.clone());
    }

    pub(crate) fn set_flush_waker(&mut self, waker: &Waker) {
        self.flush_waker = Some(waker.clone());
    }

    /// True while the processor task is alive (not terminated).
    pub(crate) fn is_alive(&self) -> bool {
        self.notify_tx.is_some()
    }

    /// True once nothing is queued and everything sent has been ACKed.
    pub(crate) fn all_acked(&self) -> bool {
        self.write_queue.is_empty() && self.outgoing.is_empty()
    }

    // ── Clock ────────────────────────────────────────────────────────────────

    /// The time the state machine runs on: `Instant::now()`, or a test's
    /// fake clock.
    fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(clock) = self.clock {
            return clock;
        }
        Instant::now()
    }

    /// `now` in microseconds since `epoch`.
    fn clock_us(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch)
            .as_micros()
            .min(u128::from(u64::MAX)) as u64
    }

    // ── Outgoing packet registration ─────────────────────────────────────────

    /// Store a sent packet in the outgoing buffer for potential retransmission.
    pub(crate) fn register_sent(
        &mut self,
        seq: u32,
        packet: impl Into<Bytes>,
        remote_addr: SocketAddr,
        is_mtu_probe: bool,
    ) {
        let packet = packet.into();
        let now = self.now();
        let now_us = self.clock_us(now);
        let was_idle = self.inflight() == 0;
        let inflight_after = self.inflight_count.saturating_add(1);
        // Nothing outstanding starts a new flight.
        let rate_info =
            self.congestion
                .on_packet_sent(self.outgoing.is_empty(), inflight_after, now_us);
        tracing::trace!(
            seq,
            is_mtu_probe,
            "register_sent: packet placed in outgoing"
        );
        self.unacked_bytes += packet.len();
        let previous = self.outgoing.insert(
            seq,
            SentPacket {
                packet,
                remote_addr,
                time_sent: now,
                retransmit_count: 0,
                sacked: false,
                is_mtu_probe,
                lost: false,
                rate_info: Some(rate_info),
            },
        );
        if let Some(previous) = previous {
            self.unacked_bytes = self.unacked_bytes.saturating_sub(previous.packet.len());
            if previous.is_inflight() {
                self.inflight_count -= 1;
            }
            if previous.sacked {
                self.sacked_count -= 1;
            }
        }
        self.inflight_count += 1;
        self.send_order.push_back((now, seq));
        if was_idle {
            self.congestion
                .on_transmit_start(self.srtt_us, self.inflight_count, now_us);
        }
    }

    pub(crate) fn inflight(&self) -> u32 {
        debug_assert_eq!(
            self.inflight_count,
            self.outgoing.values().filter(|p| p.is_inflight()).count() as u32
        );
        self.inflight_count
    }

    /// A packet can be built: bytes or the FIN wait in `write_queue`. Empty
    /// writes alone wait for the next packet, as in C.
    fn has_unsent(&self) -> bool {
        self.queued_bytes > 0 || self.write_queue.back().is_some_and(|w| w.end)
    }

    /// Build the next DATA and/or END packet from the write queue at the
    /// current MTU, peer and ACK into `self.tx_slab` and freeze it as a
    /// refcounted [`Bytes`] slice (C `send_new_packet`, `_send_new_packet`).
    /// Up to `max_payload` bytes across as many writes as fit, END set on
    /// the packet that takes the FIN. Each write the packet finishes waits
    /// for this seq's cumulative ACK. Returns the seq and the packet.
    fn next_packet_bytes(&mut self) -> Option<(u32, Bytes)> {
        const TX_SLAB_BYTES: usize = 65_536;
        if !self.has_unsent() {
            return None;
        }
        let seq = self.next_seq;
        let max_payload = self.max_payload();
        let needed = HEADER_SIZE + max_payload;
        if self.tx_slab.capacity() < needed {
            self.tx_slab = BytesMut::with_capacity(TX_SLAB_BYTES.max(needed));
        }
        self.tx_slab.clear();
        self.tx_slab.resize(HEADER_SIZE, 0);
        let mut capacity = max_payload;
        let mut flags = 0;
        while capacity > 0 {
            let Some(write) = self.write_queue.front_mut() else {
                break;
            };
            let len = capacity.min(write.data.len() - write.sent);
            self.tx_slab
                .extend_from_slice(&write.data[write.sent..write.sent + len]);
            write.sent += len;
            capacity -= len;
            self.queued_bytes -= len;
            if len > 0 {
                flags |= FLAG_DATA;
            }
            if write.sent < write.data.len() {
                break;
            }
            let Some(write) = self.write_queue.pop_front() else {
                break;
            };
            if let Some(tx) = write.done {
                self.pending_writes.push(PendingWrite {
                    ack_threshold: seq.wrapping_add(1),
                    tx: Some(tx),
                });
            }
            if write.end {
                flags |= FLAG_END;
                break;
            }
        }
        Header {
            type_flags: flags,
            data_offset: 0,
            remote_id: self.remote_id,
            recv_window: self.receive_window.advertise(),
            seq,
            ack: self.next_remote_seq,
        }
        .encode_into(&mut self.tx_slab[..HEADER_SIZE]);
        self.next_seq = seq.wrapping_add(1);
        Some((seq, self.tx_slab.split().freeze()))
    }

    /// True when queued data or retransmits wait for the processor.
    fn has_pending_send(&self) -> bool {
        self.connected && (self.has_unsent() || !self.lost_queue.is_empty())
    }

    /// Everything sent is ACKed but the peer's window is zero with data
    /// waiting: only a zero-window probe can learn when it opens (C ZWP).
    fn zero_window_stalled(&self) -> bool {
        self.connected && self.send_rwnd == 0 && self.outgoing.is_empty() && self.has_unsent()
    }

    /// Front of the retransmit queue, skipping seqs ACKed, SACKed or already
    /// retransmitted since they were queued.
    fn next_lost(&mut self) -> Option<u32> {
        while let Some(&seq) = self.lost_queue.front() {
            if self.outgoing.get(&seq).is_some_and(|p| p.lost && !p.sacked) {
                return Some(seq);
            }
            self.lost_queue.pop_front();
        }
        None
    }

    /// Send `seq` again (C `retransmit_packet`): a fresh send time, back in
    /// flight if it was marked lost.
    fn retransmit(&mut self, seq: u32) -> Option<(Bytes, SocketAddr)> {
        let now = self.now();
        let now_us = self.clock_us(now);
        let was_idle = self.inflight_count == 0;
        let inflight_after = self.inflight_count.saturating_add(1);
        // Take delivery state at every transmission.
        let rate_info = self
            .congestion
            .on_packet_sent(false, inflight_after, now_us);
        let pkt = self.outgoing.get_mut(&seq)?;
        pkt.retransmit_count += 1;
        pkt.time_sent = now;
        pkt.rate_info = Some(rate_info);
        let sent = (pkt.packet.clone(), pkt.remote_addr);
        if pkt.lost {
            pkt.lost = false;
            self.inflight_count += 1;
        }
        self.send_order.push_back((now, seq));
        self.retransmits += 1;
        if was_idle {
            self.congestion
                .on_transmit_start(self.srtt_us, self.inflight_count, now_us);
        }
        Some(sent)
    }

    /// Append what the congestion window, the peer's window and the pacer
    /// allow now into `batch` (C `send_packets`): lost packets first, then
    /// queued data. Retransmits ignore the peer's window, as in C
    /// `stream_may_send`. Returns why the batch ended and whether it held new
    /// data.
    fn take_send_batch_into(&mut self, batch: &mut Vec<(Bytes, SocketAddr)>) -> (SendStop, bool) {
        let mut new_data = false;
        // A hooked stream has no peer until its first packet commits one (C
        // `udx_stream_write` is ENOTCONN before that): sending now would
        // address 0.0.0.0:0 and lose the packets for good, retransmits included.
        if !self.connected {
            return (SendStop::Idle, false);
        }
        loop {
            let lost = self.next_lost();
            if lost.is_none() && !self.has_unsent() {
                return (SendStop::Idle, new_data);
            }
            // `register_sent` already counts this batch's packets.
            let inflight = self.inflight();
            let window = if lost.is_some() {
                u32::MAX
            } else {
                self.send_rwnd
            };
            if !self.congestion.can_send(inflight, window) {
                return (SendStop::Window, new_data);
            }
            let now = self.now();
            let delay = self.congestion.pacing_delay(now);
            if delay > std::time::Duration::ZERO {
                return (SendStop::Pacing(delay), new_data);
            }
            // C `_send_packet` checks just before each send; a retransmit
            // waiting means the sender is not app-limited.
            self.congestion
                .check_app_limited(self.unacked_written, inflight, lost.is_some());
            let sent = match lost {
                Some(seq) => {
                    self.lost_queue.pop_front();
                    self.retransmit(seq)
                }
                None => self.send_new(true),
            };
            let Some((packet, to)) = sent else { continue };
            new_data |= lost.is_none();
            self.congestion.pacing.try_consume(packet.len() as u32, now);
            batch.push((packet, to));
        }
    }

    #[cfg(test)]
    fn take_send_batch(&mut self) -> (Vec<(Bytes, SocketAddr)>, SendStop, bool) {
        let mut batch = Vec::new();
        let (stop, new_data) = self.take_send_batch_into(&mut batch);
        (batch, stop, new_data)
    }

    /// Build and register the next packet (C `_send_new_packet`), as an MTU
    /// probe when one is wanted and `may_probe` (not for a loss probe).
    fn send_new(&mut self, may_probe: bool) -> Option<(Bytes, SocketAddr)> {
        let remote_addr = self.remote_addr?;
        let (seq, packet) = self.next_packet_bytes()?;
        // No probes while old-path packets are still in flight (C udx.c:846).
        let (packet, is_mtu_probe) =
            if may_probe && self.mtu_probe_wanted && self.remote_change.is_none() {
                let mut vec = packet.to_vec();
                let probed = self.mtu_probeify_packet(&mut vec, remote_addr);
                if probed {
                    self.mtu_probe_count += 1;
                    (Bytes::from(vec), true)
                } else {
                    (packet, false)
                }
            } else {
                (packet, false)
            };
        self.register_sent(seq, packet.clone(), remote_addr, is_mtu_probe);
        Some((packet, remote_addr))
    }

    /// Base tail-loss-probe timeout in ms, or `None` when no probe is due
    /// (C `schedule_loss_probe`, RACK §7.2).
    fn loss_probe_timeout(&self) -> Option<u32> {
        if self.outgoing.is_empty()
            || self.congestion.ca_state != CaState::Open
            || self.sacked_count > 0
        {
            return None;
        }
        if self.srtt == 0 {
            return Some(1_000);
        }
        let extra = if self.outgoing.len() == 1 {
            TLP_MAX_ACK_DELAY_MS
        } else {
            0
        };
        Some(self.srtt * 2 + extra)
    }

    /// The loss probe timer fired (C `udx_tlp_timeout`): send one new packet
    /// regardless of the windows, or else the last packet sent again.
    fn take_loss_probe(&mut self) -> Option<(Bytes, SocketAddr)> {
        if self.outgoing.is_empty() || self.tlp_in_flight || !self.tlp_permitted {
            return None;
        }
        // C `_send_packet` checks app-limited before every send.
        let retransmit_pending = self.next_lost().is_some();
        let inflight = self.inflight();
        self.congestion
            .check_app_limited(self.unacked_written, inflight, retransmit_pending);
        let (sent, end_seq, is_retrans) = if self.connected && self.has_unsent() {
            let seq = self.next_seq;
            (self.send_new(false)?, seq, false)
        } else {
            let (seq, pkt) = self.outgoing.last_key_value()?;
            if pkt.lost || pkt.sacked {
                return None;
            }
            (self.retransmit(seq)?, seq, true)
        };
        let now = self.now();
        self.congestion.pacing.try_consume(sent.0.len() as u32, now);
        self.tlp_in_flight = true;
        self.tlp_is_retrans = is_retrans;
        self.tlp_end_seq = end_seq;
        self.tlp_permitted = false;
        Some(sent)
    }

    /// The retransmission timer fired with data in flight (C
    /// `udx_rto_timeout`): mark lost what had time to be ACKed and cut the
    /// window to what is still in flight plus one. `rto` itself stays; only
    /// the timer backs off (`rto_fired`). The lost packets leave through
    /// `take_send_batch`.
    fn on_rto(&mut self) {
        let now = self.now();
        self.congestion.on_rto(self.next_seq);
        self.tlp_in_flight = false;
        self.tlp_is_retrans = false;
        self.lost_queue.clear();
        // Read the reorder window after entering Loss (rack 6.3), in µs.
        let wait = std::time::Duration::from_micros(
            self.rack_rtt_us.saturating_add(self.rack_reo_wnd_us()),
        );
        let mut newly_lost = Vec::new();
        for (seq, pkt) in self.outgoing.iter_mut() {
            if pkt.sacked {
                continue;
            }
            if !pkt.lost && (seq == self.remote_acked || pkt.time_sent + wait < now) {
                pkt.lost = true;
                newly_lost.push(seq);
            }
            if pkt.lost {
                self.lost_queue.push_back(seq);
            }
        }
        self.inflight_count -= newly_lost.len() as u32;
        for seq in newly_lost {
            self.unprobeify(seq);
        }
        self.congestion.cwnd = self.inflight_count + 1;
    }

    /// The RTO timer fired with data in flight (C `udx_rto_timeout`): give
    /// up (`None`) on the seventh firing without progress, else run
    /// `on_rto` and return the next timeout, `2 × rto` (C keeps `rto` and
    /// doubles only the timer, udx.c:1234).
    fn rto_fired(&mut self) -> Option<std::time::Duration> {
        self.rto_timeouts += 1;
        if self.rto_timeouts > MAX_RTO_TIMEOUTS {
            return None;
        }
        self.on_rto();
        Some(std::time::Duration::from_millis(u64::from(self.rto) * 2))
    }

    // ── RTT estimation (Jacobson/Karels) ─────────────────────────────────────

    /// Update the RTT estimator with a sample in microseconds already passed
    /// through `clamp_rtt_us` and floored at 1 µs.
    fn update_rtt_us(&mut self, rtt_us: u64) {
        if self.srtt_us == 0 {
            self.srtt_us = rtt_us;
            self.rttvar_us = rtt_us / 2;
        } else {
            let delta = self.srtt_us.abs_diff(rtt_us);
            self.rttvar_us = (3 * self.rttvar_us + delta) / 4;
            self.srtt_us = (7 * self.srtt_us + rtt_us) / 8;
        }
        self.srtt = (self.srtt_us / 1_000).clamp(1, u64::from(MAX_RTT_MS)) as u32;
        self.rttvar = (self.rttvar_us / 1_000).min(u64::from(MAX_RTT_MS)) as u32;
        self.tlp_permitted = true;
        let rto_ms =
            ((self.srtt_us + 4 * self.rttvar_us) / 1_000).clamp(1_000, u64::from(MAX_RTO_MS));
        self.rto = rto_ms as u32;
    }

    #[cfg(test)]
    fn update_rtt(&mut self, rtt_ms: u32) {
        self.update_rtt_us(u64::from(rtt_ms) * 1_000);
    }

    /// An RTT sample in microseconds as C `clamp_rtt` takes it: the first is
    /// capped at `MAX_RTT_US`; later ones only when they look like a suspend
    /// (over 5 s and over `srtt_us + 5 * rttvar_us`), down to that bound.
    fn clamp_rtt_us(&self, rtt_us: u64) -> u64 {
        if self.srtt_us == 0 {
            return rtt_us.min(MAX_RTT_US);
        }
        let outlier = self.srtt_us.saturating_add(5 * self.rttvar_us);
        if rtt_us > outlier && rtt_us > 5_000_000 {
            return outlier.min(MAX_RTT_US);
        }
        rtt_us
    }

    /// RACK §6.2 for one packet the peer delivered, cumulatively or by SACK,
    /// in microseconds.
    fn on_packet_acked(&mut self, seq: u32, time_sent: Instant, retransmitted: bool, now: Instant) {
        let elapsed_us = now
            .saturating_duration_since(time_sent)
            .as_micros()
            .min(u128::from(u64::MAX)) as u64;
        let mut rtt_us = self.clamp_rtt_us(elapsed_us);
        if !retransmitted {
            rtt_us = rtt_us.max(1);
            let t = self.clock_us(now);
            self.rtt_min_us.apply_min(RTT_MIN_WINDOW_US, t, rtt_us);
            self.update_rtt_us(rtt_us);
        }
        // Step 2: the delivered packet sent last.
        if !retransmitted || rtt_us >= self.rtt_min_us.get() {
            self.rack_rtt_us = rtt_us;
            self.rs_rtt_us = rtt_us;
            self.rack_advance(time_sent, seq);
        }
        // Step 3: a never-retransmitted packet delivered below the highest
        // delivered one was reordered.
        let next = seq.wrapping_add(1);
        if seq_after(next, self.rack_fack) {
            self.rack_fack = next;
        } else if seq_after(self.rack_fack, next) && !retransmitted {
            self.reordering_seen = true;
        }
    }

    /// RACK §6.2.4 reorder window in microseconds: closed in recovery and
    /// after three SACKed packets until reordering is seen, else a quarter of
    /// the minimum RTT, at most `srtt_us`.
    fn rack_reo_wnd_us(&self) -> u64 {
        if !self.reordering_seen
            && (self.congestion.ca_state != CaState::Open || self.sacked_count >= 3)
        {
            return 0;
        }
        (self.rtt_min_us.get() / 4).min(self.srtt_us)
    }

    // ── ACK processing ───────────────────────────────────────────────────────

    /// Process a cumulative ACK from the remote peer.
    ///
    /// Removes ACKed packets from the outgoing buffer, runs RACK's per-packet
    /// update (`on_packet_acked`) for each one not SACKed before, resets the
    /// RTO timeout counter, and returns completed write senders plus rate
    /// info for congestion control. A packet SACKed earlier was delivered
    /// then (C removes it from `outgoing` at the SACK), so it counts once.
    ///
    /// An ACK beyond the first unsent seq is ignored (C udx.c:1738): it
    /// cannot come from the peer, and accepting it would fake delivery.
    ///
    /// Congestion control is NOT called here — the caller must combine this
    /// rate info with SACK rate info and loss count, then call `congestion.on_ack`.
    fn on_cumulative_ack_into(
        &mut self,
        ack: u32,
        completed: &mut WriteSenders,
        acked_rate_info: &mut AckedRateInfo,
    ) {
        let now = self.now();
        if !seq_after(ack, self.remote_acked) || seq_after(ack, self.next_seq) {
            return;
        }

        self.remote_acked = ack;

        // Everything sent to the old remote is ACKed: the migration is done
        // (C udx.c:1754).
        if self
            .remote_change
            .as_ref()
            .is_some_and(|(seq, _)| !seq_after(*seq, ack))
        {
            if let Some((_, done)) = self.remote_change.take() {
                let _ = done.send(());
            }
        }

        self.sack_cover.retain_mut(|(start, end)| {
            *start = (*start).max(ack);
            *end > *start
        });

        // Pop acknowledged entries in O(1) per packet from the sequence ring.
        while self
            .outgoing
            .first_key_value()
            .is_some_and(|(seq, _)| seq_after(ack, seq))
        {
            let Some((seq, pkt)) = self.outgoing.pop_first() else {
                break;
            };
            self.unacked_bytes = self.unacked_bytes.saturating_sub(pkt.packet.len());
            if pkt.is_inflight() {
                self.inflight_count -= 1;
            }
            if pkt.sacked {
                self.sacked_count -= 1;
            } else {
                self.unacked_written = self
                    .unacked_written
                    .saturating_sub(payload_len(&pkt.packet));
                self.on_packet_acked(seq, pkt.time_sent, pkt.retransmit_count > 0, now);
                if let Some(info) = pkt.rate_info {
                    acked_rate_info.push(Delivered {
                        seq,
                        time_sent_us: self.clock_us(pkt.time_sent),
                        info,
                    });
                }
            }
            // C `ack_packet`: a probe counts only while probes are out on
            // this path (`mtu_probe_count > 0`).
            if pkt.is_mtu_probe && self.mtu_state == MtuState::Search && self.mtu_probe_count > 0 {
                self.on_mtu_probe_acked();
            }
            // The first delivery starts the MTU search (C `ack_packet`).
            if self.mtu_state == MtuState::Base {
                self.mtu_state = MtuState::Search;
                self.mtu_probe_wanted = true;
            }
        }

        if self.send_buffer_room() > 0 {
            if let Some(w) = self.write_waker.take() {
                w.wake();
            }
        }
        if self.all_acked() {
            if let Some(w) = self.flush_waker.take() {
                w.wake();
            }
        }

        // Successful ACK resets timeout counter
        self.rto_timeouts = 0;

        // Complete pending writes whose ack_threshold <= ack
        if !self.pending_writes.is_empty() {
            self.pending_writes.retain_mut(|pw| {
                if pw.ack_threshold <= ack {
                    completed.push(pw.tx.take());
                    false
                } else {
                    true
                }
            });
        }
    }

    #[cfg(test)]
    fn on_cumulative_ack(&mut self, ack: u32) -> (WriteSenders, AckedRateInfo) {
        let mut completed = Vec::new();
        let mut acked_rate_info = Vec::new();
        self.on_cumulative_ack_into(ack, &mut completed, &mut acked_rate_info);
        (completed, acked_rate_info)
    }

    // ── SACK processing ──────────────────────────────────────────────────────

    /// Process SACK ranges from the remote peer. Marks selectively acknowledged
    /// packets and appends rate info from newly sacked packets to
    /// `sack_rate_info` for congestion control.
    ///
    /// Ranges are untrusted input: only packets actually in `outgoing` are
    /// visited, so a block like `0..0xFFFFFFFF` costs one tree walk, not four
    /// billion lookups (C `udx_sack_is_valid` rejects it outright).
    fn on_sack_into(&mut self, ranges: &[SackRange], sack_rate_info: &mut AckedRateInfo) {
        let epoch = self.epoch;
        let mut delivered = std::mem::take(&mut self.sack_delivered_scratch);
        delivered.clear();
        let mut gaps = std::mem::take(&mut self.sack_gaps_scratch);
        let mut left_flight = 0;
        // Coverage only claims seqs already sent: a block naming unsent seqs
        // must not hide their real SACK later.
        let sent_end = self
            .outgoing
            .last_seq()
            .map_or(0, |seq| seq.saturating_add(1));
        for range in ranges {
            let (start, end) = (range.start, range.end.min(sent_end));
            if start >= end {
                continue;
            }
            // The peer repeats its blocks on every ACK: walk only what no
            // earlier block covered.
            gaps.clear();
            let mut at = start;
            for &(covered_start, covered_end) in &self.sack_cover {
                if covered_end <= at {
                    continue;
                }
                if covered_start >= end {
                    break;
                }
                if covered_start > at {
                    gaps.push((at, covered_start));
                }
                at = covered_end;
                if at >= end {
                    break;
                }
            }
            if at < end {
                gaps.push((at, end));
            }
            for &(gap_start, gap_end) in &gaps {
                for (seq, pkt) in self.outgoing.range_mut(gap_start..gap_end) {
                    if !pkt.sacked {
                        if !pkt.lost {
                            left_flight += 1;
                        }
                        pkt.sacked = true;
                        self.sacked_count += 1;
                        // C `ack_packet` counts SACKed bytes as ACKed.
                        self.unacked_written = self
                            .unacked_written
                            .saturating_sub(payload_len(&pkt.packet));
                        delivered.push((seq, pkt.time_sent, pkt.retransmit_count > 0));
                        if let Some(info) = pkt.rate_info {
                            sack_rate_info.push(Delivered {
                                seq,
                                time_sent_us: pkt
                                    .time_sent
                                    .saturating_duration_since(epoch)
                                    .as_micros()
                                    .min(u128::from(u64::MAX))
                                    as u64,
                                info,
                            });
                        }
                    }
                }
            }
            cover_insert(&mut self.sack_cover, start, end);
        }
        self.inflight_count -= left_flight;
        if left_flight > 0 && self.mtu_state == MtuState::Base {
            self.mtu_state = MtuState::Search;
            self.mtu_probe_wanted = true;
        }
        let now = self.now();
        for &(seq, time_sent, retransmitted) in &delivered {
            self.on_packet_acked(seq, time_sent, retransmitted, now);
        }
        delivered.clear();
        gaps.clear();
        self.sack_delivered_scratch = delivered;
        self.sack_gaps_scratch = gaps;
    }

    #[cfg(test)]
    fn on_sack(&mut self, ranges: &[SackRange]) -> Vec<Delivered> {
        let mut sack_rate_info = Vec::new();
        self.on_sack_into(ranges, &mut sack_rate_info);
        sack_rate_info
    }

    /// RACK §6.2 step 2: remember the delivered packet that was sent last.
    fn rack_advance(&mut self, time_sent: Instant, seq: u32) {
        let newer = match self.rack {
            None => true,
            Some((t, s)) => time_sent > t || (time_sent == t && seq_after(seq, s)),
        };
        if newer {
            self.rack = Some((time_sent, seq));
        }
    }

    // ── Loss detection ───────────────────────────────────────────────────────

    /// Detect lost packets with RACK (C `rack_detect_loss`, RFC 8985 §6.2):
    /// an unacked packet is lost once the peer has delivered a packet sent
    /// after it and `rack_rtt + reo_wnd` has passed since it was sent. A
    /// retransmission gets a fresh send time, so it is not declared lost
    /// again until something sent after it is delivered, about one RTT
    /// later; without that, every SACK arriving during a retransmission's
    /// flight would retransmit it once more.
    ///
    /// Returns the number of newly detected losses and, when a packet sent
    /// before the RACK packet is still inside the reorder window, how long
    /// until the last such packet leaves it (C's `timeout`, the reorder
    /// timer, `udx_rack_reo_timeout`).
    fn detect_losses(&mut self, now: Instant) -> (u32, Option<std::time::Duration>) {
        self.drop_finished_send_order();
        let Some((rack_time_sent, rack_seq)) = self.rack else {
            return (0, None);
        };
        let wait = std::time::Duration::from_micros(
            self.rack_rtt_us.saturating_add(self.rack_reo_wnd_us()),
        );

        // Send times never decrease along `send_order`, so the scan stops at
        // the first entry sent after the RACK packet (C breaks there too).
        let mut lost_seqs = std::mem::take(&mut self.lost_seqs_scratch);
        lost_seqs.clear();
        let mut timeout = None;
        for &(sent, seq) in &self.send_order {
            if sent > rack_time_sent {
                break;
            }
            // Sent at the same instant: the seq decides.
            if sent == rack_time_sent && !seq_after(rack_seq, seq) {
                continue;
            }
            // An entry is current while its packet still carries that send time.
            let Some(pkt) = self.outgoing.get_mut(&seq) else {
                continue;
            };
            if pkt.time_sent != sent || !pkt.is_inflight() {
                continue;
            }
            let deadline = sent + wait;
            if deadline <= now {
                pkt.lost = true;
                lost_seqs.push(seq);
            } else {
                // Later entries were sent later: this is the largest so far.
                timeout = Some(deadline - now);
            }
        }
        self.drop_finished_send_order();
        let lost_len = lost_seqs.len() as u32;
        let (lost, recovery) = if lost_len == 0 {
            self.congestion.on_losses(0, 0, self.next_seq)
        } else {
            self.inflight_count -= lost_len;
            self.lost_queue.extend(lost_seqs.iter().copied());
            let mtu_probes = lost_seqs
                .iter()
                .filter(|seq| self.outgoing.get(seq).is_some_and(|p| p.is_mtu_probe))
                .count() as u32;
            for &seq in &lost_seqs {
                self.unprobeify(seq);
            }
            // C `rack_detect_loss`: recovery lasts until the ACK passes what
            // was sent so far.
            self.congestion
                .on_losses(lost_len, mtu_probes, self.next_seq)
        };
        lost_seqs.clear();
        self.lost_seqs_scratch = lost_seqs;
        if recovery {
            // RACK §7.1 TLP_init.
            self.tlp_in_flight = false;
            self.tlp_is_retrans = false;
        }
        (lost, timeout)
    }

    /// Drop `send_order` entries at the front that loss detection is done
    /// with: the packet was ACKed, SACKed, marked lost or sent again since.
    fn drop_finished_send_order(&mut self) {
        while let Some(&(sent, seq)) = self.send_order.front() {
            if self
                .outgoing
                .get(&seq)
                .is_some_and(|p| p.time_sent == sent && p.is_inflight())
            {
                break;
            }
            self.send_order.pop_front();
        }
    }

    /// The reorder timer fired (C `udx_rack_reo_timeout`): run loss
    /// detection again with no new ACK. Packets still inside the window wait
    /// for the next ACK or the RTO, as in C. Returns the newly lost count.
    fn on_reorder_timeout(&mut self) -> u32 {
        let now = self.now();
        self.detect_losses(now).0
    }

    /// Process the ACK part of an incoming packet: window, cumulative ACK,
    /// SACK blocks, loss detection and congestion control, reusing caller
    /// scratch buffers for completed writes, delivered rate info, and outbound
    /// packets.
    fn on_ack_packet_into(
        &mut self,
        header: &Header,
        sacks: Option<&[SackRange]>,
        completed: &mut WriteSenders,
        acked_rate_info: &mut AckedRateInfo,
        batch: &mut Vec<(Bytes, SocketAddr)>,
        take_after_bbr: bool,
    ) -> AckOutcome {
        acked_rate_info.clear();
        // An ACK for data never sent is out of bounds (C udx.c:1738).
        if seq_after(header.ack, self.next_seq) {
            return AckOutcome::default();
        }
        // An older ACK must not overwrite a newer window (C send_wl2).
        if !seq_after(self.remote_acked, header.ack) {
            self.send_rwnd = header.recv_window;
        }
        // RACK §7.4.2: the loss probe repaired the tail.
        if self.tlp_in_flight
            && !seq_after(self.tlp_end_seq, header.ack)
            && (!self.tlp_is_retrans || seq_after(header.ack, self.tlp_end_seq))
        {
            self.tlp_in_flight = false;
        }
        // C `process_packet`: Recovery and Loss end once the cumulative ACK
        // passes `high_seq`, before this ACK's packets are counted.
        self.congestion.on_cumulative_ack(header.ack);
        let data_inflight = self.remote_acked != self.next_seq;
        self.rs_rtt_us = 0;
        let prev_acked = self.remote_acked;
        self.on_cumulative_ack_into(header.ack, completed, acked_rate_info);
        if let Some(ranges) = sacks {
            self.on_sack_into(ranges, acked_rate_info);
        }
        let now = self.now();
        // Loss detection runs only when the ACK delivered something (C
        // `if (delivered > 0)`, rack 6.2.5).
        let delivered = !acked_rate_info.is_empty();
        let (lost_count, reorder_timeout, mut send_stop, mut send_new_data) = if delivered {
            let (lost, timeout) = self.detect_losses(now);
            // C `rack_detect_loss` ends with `send_packets` (udx.c:1164),
            // before `bbr_main`: the lost packets leave under the window
            // they were lost from, which BBR's recovery window then covers.
            let (stop, new_data) = self.take_send_batch_into(batch);
            (lost, timeout, Some(stop), new_data)
        } else {
            (0, None, None, false)
        };
        // Run the rate sample and BBRv3 on every ACK that found data in
        // flight, whatever it delivered.
        if data_inflight {
            let inflight = self.inflight();
            let now_us = self.clock_us(now);
            self.congestion.on_ack(
                acked_rate_info,
                lost_count,
                inflight,
                self.srtt_us,
                self.rs_rtt_us,
                self.rtt_min_us.get(),
                now_us,
            );
        }
        // If `bbr_main` or a window update opened more room while packets are
        // waiting, take them into the same batch right now instead of waking
        // the pacing timer for an immediate second lock pass.
        if take_after_bbr && self.has_pending_send() {
            let (stop, more_new_data) = self.take_send_batch_into(batch);
            send_stop = Some(stop);
            send_new_data |= more_new_data;
        }
        if self.send_buffer_room() > 0 {
            if let Some(w) = self.write_waker.take() {
                w.wake();
            }
        }
        AckOutcome {
            #[cfg(test)]
            completed: Vec::new(),
            ack_advanced: self.remote_acked != prev_acked,
            delivered,
            reorder_timeout,
            send_stop,
            send_new_data,
            #[cfg(test)]
            batch: Vec::new(),
        }
    }

    #[cfg(test)]
    fn on_ack_packet(&mut self, header: &Header, sacks: Option<&[SackRange]>) -> AckOutcome {
        let mut completed = Vec::new();
        let mut acked_rate_info = Vec::new();
        let mut batch = Vec::new();
        let mut outcome = self.on_ack_packet_into(
            header,
            sacks,
            &mut completed,
            &mut acked_rate_info,
            &mut batch,
            false,
        );
        outcome.completed = completed;
        outcome.batch = batch;
        outcome
    }

    // ── Receive buffering ────────────────────────────────────────────────────

    /// Ask the processor for a window update ACK. Without a processor the
    /// request is dropped, so that a later read can ask again.
    pub(crate) fn request_window_update(&self) {
        let sent = self
            .notify_tx
            .as_ref()
            .is_some_and(|tx| tx.send(StreamNotify::WindowUpdate).is_ok());
        if !sent {
            self.receive_window.update_handled();
        }
    }

    /// Handle an incoming DATA or END packet.
    ///
    /// In-order packets are delivered immediately. Out-of-order packets are
    /// buffered. When gaps are filled, consecutive buffered packets are drained
    /// and delivered in order.
    ///
    /// A single packet may carry both FLAG_DATA and FLAG_END (C libudx combines
    /// the last data chunk with the end marker). In that case two events are
    /// produced: Data followed by End.
    ///
    /// Out-of-order packets are kept only while they fit inside the window we
    /// advertise: a sender that honours the window never has them dropped, and
    /// keeping more would let one peer grow the buffer without bound. In-order
    /// data is refused only above the window plus one starting window
    /// (`HARD_MARGIN` in `receive_window`), because a correct C sender's tail
    /// loss probe may send one packet past a closed window. C libudx bounds
    /// neither.
    fn receive_data(
        &mut self,
        seq: u32,
        payload: impl Into<Bytes>,
        flags: u8,
        events: &mut Vec<StreamEvent>,
    ) {
        let payload = payload.into();
        // After the peer's END nothing more is read (C `SHOULD_READ`,
        // udx.c:1682): readers have their EOF.
        if self.remote_ended {
            return;
        }
        let next = self.next_remote_seq;
        if seq == next {
            // In-order: deliver directly, unless the reader lets the stream
            // hold the window plus one starting window (the packet is not
            // delivered, so no ACK covers it).
            if !self.receive_window.admits_in_order(payload.len()) {
                return;
            }
            let delivered = push_events(events, payload, flags);
            self.receive_window.delivered(delivered);
            self.remote_ended |= flags & FLAG_END != 0;
            self.next_remote_seq = seq.wrapping_add(1);

            // Drain the buffered range that now continues the stream.
            if self
                .recv_ranges
                .first()
                .is_some_and(|&(start, _)| start == self.next_remote_seq)
            {
                self.recv_ranges.remove(0);
                while let Some(recvd) = self.recv_buf.remove(&self.next_remote_seq) {
                    self.receive_window
                        .released_out_of_order(recvd.payload.len());
                    let delivered = push_events(events, recvd.payload, recvd.flags);
                    self.receive_window.delivered(delivered);
                    self.remote_ended |= recvd.flags & FLAG_END != 0;
                    self.next_remote_seq = self.next_remote_seq.wrapping_add(1);
                    if self.remote_ended {
                        self.recv_buf.clear();
                        self.recv_ranges.clear();
                        self.receive_window.clear_out_of_order();
                        break;
                    }
                }
            }
            return;
        }
        // Duplicate or already-received packet, or beyond the window.
        if !seq_after(seq, next)
            || seq.wrapping_sub(next) >= RECV_WINDOW_PACKETS
            || self.recv_buf.contains_key(&seq)
        {
            return;
        }
        // Not stored, so no SACK report says it arrived; the peer resends it
        // once the window has room.
        if !self.receive_window.admits_out_of_order(payload.len()) {
            return;
        }
        self.receive_window.stored_out_of_order(payload.len());
        self.recv_buf.insert(seq, RecvdPacket { payload, flags });
        range_insert(&mut self.recv_ranges, next, seq);
    }

    // ── SACK generation ──────────────────────────────────────────────────────

    /// SACK ranges of the out-of-order receive buffer, lowest first, at most
    /// `MAX_SACK_RANGES` (C `send_ack`).
    fn sack_ranges(&self) -> Vec<SackRange> {
        self.recv_ranges
            .iter()
            .take(MAX_SACK_RANGES)
            .map(|&(start, end)| SackRange { start, end })
            .collect()
    }
}

/// Add `seq` to `ranges` (sorted, disjoint, non-adjacent half-open seq
/// ranges, ordered by distance from `base`), merging neighbours like C's
/// SACK block tree. `seq` must not be in a range yet.
fn range_insert(ranges: &mut Vec<(u32, u32)>, base: u32, seq: u32) {
    let offset = |s: u32| s.wrapping_sub(base);
    let next = seq.wrapping_add(1);
    // First range ending at or after `seq`.
    let at = ranges.partition_point(|&(_, end)| offset(end) < offset(seq));
    if at < ranges.len() && ranges[at].1 == seq {
        ranges[at].1 = next;
        if at + 1 < ranges.len() && ranges[at + 1].0 == next {
            ranges[at].1 = ranges[at + 1].1;
            ranges.remove(at + 1);
        }
    } else if at < ranges.len() && ranges[at].0 == next {
        ranges[at].0 = seq;
    } else {
        ranges.insert(at, (seq, next));
    }
}

impl Drop for StreamInner {
    fn drop(&mut self) {
        let _ = self.close_watch_tx.send(true);
        if let Some(runtime) = self.runtime.as_ref().and_then(|runtime| runtime.upgrade()) {
            runtime.unregister_stream(self.local_id);
        }
    }
}

/// Add `start..end` to the sorted, disjoint `cover`, merging what it touches.
fn cover_insert(cover: &mut Vec<(u32, u32)>, start: u32, end: u32) {
    let at = cover.partition_point(|&(_, e)| e < start);
    let mut merged = (start, end);
    let mut last = at;
    while last < cover.len() && cover[last].0 <= merged.1 {
        merged = (merged.0.min(cover[last].0), merged.1.max(cover[last].1));
        last += 1;
    }
    cover.splice(at..last, [merged]);
}

/// Strip MTU probe padding from a packet: remove zero bytes between header and payload,
/// reset data_offset to 0.
fn strip_probe_padding(packet: &mut Bytes) {
    if packet.len() < HEADER_SIZE {
        return;
    }
    let data_offset = packet[3] as usize;
    if data_offset == 0 {
        return;
    }
    let payload_start = HEADER_SIZE + data_offset;
    let mut rebuilt = BytesMut::with_capacity(packet.len().saturating_sub(data_offset));
    rebuilt.extend_from_slice(&packet[..HEADER_SIZE]);
    if payload_start <= packet.len() {
        rebuilt.extend_from_slice(&packet[payload_start..]);
    }
    rebuilt[3] = 0;
    *packet = rebuilt.freeze();
}

/// Push stream events for a received packet and return the payload bytes that
/// went to the reader. When both FLAG_DATA and FLAG_END are set (combined
/// packet), pushes Data then End.
fn push_events(events: &mut Vec<StreamEvent>, payload: Bytes, flags: u8) -> usize {
    let has_data = flags & FLAG_DATA != 0;
    let has_end = flags & FLAG_END != 0;

    let mut delivered = 0;
    if has_data && !payload.is_empty() {
        delivered = payload.len();
        events.push(StreamEvent::Data(payload));
    } else if has_data {
        // Empty data packet (e.g., keepalive DATA) — skip
    } else if !has_end {
        // Neither DATA nor END — shouldn't happen, but guard
        return 0;
    }

    if has_end {
        events.push(StreamEvent::End);
    }
    delivered
}

// ── UdxStream ────────────────────────────────────────────────────────────────

impl StreamInner {
    fn new(
        local_id: u32,
        read_tx: mpsc::UnboundedSender<StreamEvent>,
        close_tx: Option<oneshot::Sender<()>>,
        incoming_tx: Option<mpsc::Sender<IncomingPacket>>,
        registrations: Registrations,
        runtime: Option<Weak<super::runtime::RuntimeHandle>>,
    ) -> Self {
        let (close_watch_tx, close_watch_rx) = watch::channel(false);
        let (message_tx, message_rx) = mpsc::channel(MESSAGE_QUEUE);
        let epoch = Instant::now();
        Self {
            remote_id: 0,
            remote_addr: None,
            connected: false,
            terminated: false,
            ended: false,
            remote_ended: false,
            timewait_wanted: false,
            next_seq: 0,
            pending_writes: Vec::new(),
            outgoing: OutgoingMap::new(),
            inflight_count: 0,
            send_order: VecDeque::new(),
            lost_queue: VecDeque::new(),
            sacked_count: 0,
            sack_cover: Vec::new(),
            queued_bytes: 0,
            unacked_written: 0,
            unacked_bytes: 0,
            write_waker: None,
            flush_waker: None,
            next_remote_seq: 0,
            remote_acked: 0,
            rack: None,
            rack_rtt_us: 0,
            rs_rtt_us: 0,
            zwp_wanted: false,
            rack_fack: 0,
            reordering_seen: false,
            rtt_min_us: WinFilter::new(0, u64::MAX),
            epoch,
            #[cfg(test)]
            clock: None,
            recv_buf: BTreeMap::new(),
            recv_ranges: Vec::new(),
            receive_window: Arc::new(ReceiveWindow::new()),
            srtt: 0,
            srtt_us: 0,
            rttvar: 0,
            rttvar_us: 0,
            rto: INITIAL_RTO_MS,
            rto_timeouts: 0,
            retransmits: 0,
            send_rwnd: DEFAULT_RWND,
            tlp_permitted: false,
            tlp_in_flight: false,
            tlp_is_retrans: false,
            tlp_end_seq: 0,
            keepalive: Some(DEFAULT_KEEPALIVE),
            mtu_state: MtuState::Base,
            mtu: MTU_BASE,
            mtu_probe_size: MTU_BASE,
            mtu_probe_count: 0,
            mtu_probe_wanted: false,
            mtu_max: MTU_MAX,
            udp: None,
            socket: None,
            read_tx,
            close_tx,
            close_watch_tx,
            close_watch_rx,
            notify_tx: None,
            congestion: super::congestion::CongestionController::new(MAX_PAYLOAD as u32, epoch),
            write_queue: VecDeque::new(),
            relay_target: None,
            endpoint: Endpoint::default(),
            firewall_hook: None,
            local_id,
            incoming_tx,
            registrations,
            remote_change: None,
            remote_observed: None,
            observed_current_remote: false,
            message_tx: Some(message_tx),
            message_rx: Arc::new(tokio::sync::Mutex::new(message_rx)),
            runtime,
            tx_slab: BytesMut::new(),
            lost_seqs_scratch: Vec::new(),
            sack_delivered_scratch: Vec::new(),
            sack_gaps_scratch: Vec::new(),
            #[cfg(test)]
            pacing_wakeups: 0,
        }
    }
}

/// A reliable, ordered, bidirectional byte stream over UDP.
///
/// Implements the UDX protocol with BBR congestion control, SACK-based
/// recovery, and RTT-driven retransmission. Multiple streams can share
/// a single [`super::socket::UdxSocket`] via stream ID multiplexing.
pub struct UdxStream {
    local_id: u32,
    pub(crate) inner: Arc<Mutex<StreamInner>>,
    /// The same window as `inner`'s, kept outside the lock so a read can
    /// count bytes without holding it.
    receive_window: Arc<ReceiveWindow>,
    /// Measures the one reader; a fast reader doubles the window.
    read_meter: ReadMeter,
    processor: Mutex<Option<tokio::task::JoinHandle<()>>>,
    incoming_tx: Option<mpsc::Sender<IncomingPacket>>,
    incoming_rx: Mutex<Option<mpsc::Receiver<IncomingPacket>>>,
    pub(crate) read_rx: Option<mpsc::UnboundedReceiver<StreamEvent>>,
    close_rx: Option<oneshot::Receiver<()>>,
    /// Stream maps of every socket this stream is registered on, so the
    /// processor's exit and `Drop` can deregister it from all of them.
    registrations: Registrations,
}

impl UdxStream {
    pub(crate) fn new_with_runtime(
        local_id: u32,
        runtime: Option<Weak<super::runtime::RuntimeHandle>>,
    ) -> Self {
        let (read_tx, read_rx) = mpsc::unbounded_channel();
        let (close_tx, close_rx) = oneshot::channel();
        let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_QUEUE);
        let registrations = Registrations::default();

        let inner = StreamInner::new(
            local_id,
            read_tx,
            Some(close_tx),
            Some(incoming_tx.clone()),
            Arc::clone(&registrations),
            runtime,
        );
        let receive_window = Arc::clone(&inner.receive_window);

        Self {
            local_id,
            inner: Arc::new(Mutex::new(inner)),
            receive_window,
            read_meter: ReadMeter::new(),
            processor: Mutex::new(None),
            incoming_tx: Some(incoming_tx),
            incoming_rx: Mutex::new(Some(incoming_rx)),
            read_rx: Some(read_rx),
            close_rx: Some(close_rx),
            registrations,
        }
    }

    /// Return the local stream identifier assigned to this stream.
    pub fn local_id(&self) -> u32 {
        self.local_id
    }

    /// Consume this stream and return a tokio-compatible async I/O adapter.
    pub fn into_async_stream(mut self) -> super::async_stream::UdxAsyncStream {
        let processor = self
            .processor
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        // Prevent Drop from deregistering — the processor task is still
        // running and deregisters on exit through its own clone.
        self.registrations = Registrations::default();
        // `UdxStream` has a `Drop`, so the meter leaves by replacement.
        let read_meter = std::mem::replace(&mut self.read_meter, ReadMeter::new());
        let Some(read_rx) = self.read_rx.take() else {
            return super::async_stream::UdxAsyncStream::new(
                Arc::clone(&self.inner),
                read_meter,
                mpsc::unbounded_channel().1,
                None,
                self.close_rx.take(),
            );
        };
        let inner = Arc::clone(&self.inner);
        super::async_stream::UdxAsyncStream::new(
            inner,
            read_meter,
            read_rx,
            processor,
            self.close_rx.take(),
        )
    }

    /// A handle that can destroy this stream from another owner, without
    /// waiting for the owner to drop it.
    pub fn abort_handle(&self) -> UdxStreamAbort {
        UdxStreamAbort {
            inner: Arc::clone(&self.inner),
        }
    }

    /// A handle that migrates this stream to another peer from any task.
    pub fn remote_handle(&self) -> UdxStreamRemote {
        UdxStreamRemote {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Returns the current effective MTU in bytes: the IP packet size, as
    /// C libudx `udx_stream_get_mtu` reports it.
    pub fn effective_mtu(&self) -> usize {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.mtu
    }

    /// Send a heartbeat after every `interval` without traffic, and end the
    /// stream with a timeout error once the peer stays silent for six
    /// intervals (the peer answers each heartbeat). `None` turns both off
    /// (C `udx_stream_set_keepalive` with 0). The default is 5 s.
    pub fn set_keepalive(&self, interval: Option<std::time::Duration>) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_keepalive(interval);
    }

    /// Connect to a remote stream identified by `remote_id` at `remote_addr`.
    pub async fn connect(
        &self,
        socket: &super::socket::UdxSocket,
        remote_id: u32,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let udp = socket.udp_arc()?;

        // A stream primed by `set_firewall_hook` already runs its processor;
        // connecting it now only fixes the peer identity (Node
        // `createRawStream()` followed by `rawStream.connect()`).
        let processor_started = self
            .incoming_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none();
        if processor_started {
            {
                let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if inner.terminated {
                    return Err(UdxError::StreamClosed);
                }
                // Only a hooked stream may re-arm its peer; C returns EISCONN.
                if inner.connected && inner.firewall_hook.is_none() {
                    return Err(UdxError::Io(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "stream already connected",
                    )));
                }
                inner.remote_id = remote_id;
                inner.remote_addr = Some(remote_addr);
                inner.udp = Some(udp);
                inner.socket = Some(socket.clone());
                inner.connected = true;
                inner.publish_endpoint();
                // The hook stays armed: C keeps `on_firewall` for packets
                // that later arrive on another socket.
                if let Some(tx) = &inner.notify_tx {
                    let _ = tx.send(StreamNotify::DataQueued);
                }
            }
            self.register_on(socket)?;
            tracing::debug!(
                local_id = self.local_id,
                remote_id,
                ?remote_addr,
                "stream connected (primed)"
            );
            return Ok(());
        }

        let (notify_tx, notify_rx) = mpsc::unbounded_channel();

        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.terminated {
                return Err(UdxError::StreamClosed);
            }
            inner.remote_id = remote_id;
            inner.remote_addr = Some(remote_addr);
            inner.udp = Some(udp);
            inner.socket = Some(socket.clone());
            inner.connected = true;
            inner.notify_tx = Some(notify_tx);
            inner.publish_endpoint();
        }

        self.register_on(socket)?;
        self.start_processor(notify_rx)?;

        tracing::debug!(
            local_id = self.local_id,
            remote_id,
            ?remote_addr,
            "stream connected"
        );
        Ok(())
    }

    /// Write `data` reliably. Resolves when the remote peer ACKs all of it.
    /// The peer advertises only the room that its reader has left, so a write that is larger
    /// than the peer's receive window resolves only while the peer reads.
    /// An empty write resolves with the next packet sent (C semantics).
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .queue_write(data, Some(tx))?;
        rx.await.map_err(|_| UdxError::StreamClosed)?
    }

    /// Read the next message. Returns `None` on EOF or stream close, and an
    /// error once when the peer destroyed the stream or it timed out.
    pub async fn read(&mut self) -> Result<Option<Vec<u8>>> {
        let rx = self.read_rx.as_mut().ok_or(UdxError::StreamClosed)?;
        match rx.recv().await {
            Some(StreamEvent::Data(d)) => {
                if self.receive_window.taken(d.len(), &mut self.read_meter) {
                    self.inner
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .request_window_update();
                }
                Ok(Some(d.to_vec()))
            }
            Some(StreamEvent::Error(kind)) => {
                self.read_rx = None;
                Err(UdxError::Io(std::io::Error::new(kind, "UDX stream failed")))
            }
            Some(StreamEvent::End) | None => {
                self.read_rx = None;
                Ok(None)
            }
        }
    }

    /// Send a write-end (FIN) and wait for the remote peer to ACK it.
    pub async fn shutdown(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .queue_end(Some(tx))?;
        rx.await.map_err(|_| UdxError::StreamClosed)?
    }

    /// Set up packet-level relay forwarding to `destination`.
    ///
    /// Both streams must be on the same runtime. Relayed packets bypass
    /// congestion control — only the `remote_id` header field is rewritten.
    pub fn relay_to(&self, destination: &UdxStream) -> Result<()> {
        // Take the destination's endpoint first: no stream lock is held
        // while another is taken.
        let endpoint = Arc::clone(
            &destination
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .endpoint,
        );
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .relay_target = Some(endpoint);
        tracing::debug!("relay_to configured");
        Ok(())
    }

    /// Register a firewall hook for deferred socket and peer commitment.
    ///
    /// The stream receives on `socket` (and on any socket added later with
    /// [`Self::listen_on`]); the first packet the hook accepts commits both
    /// the peer address and the socket it arrived on, as C libudx's
    /// `on_firewall` lets Node bind a raw stream to whichever socket the
    /// peer reached. Returning `false` rejects only the current packet; a
    /// later packet can invoke the hook again.
    pub fn set_firewall_hook<F>(
        &self,
        socket: &super::socket::UdxSocket,
        remote_id: u32,
        hook: F,
    ) -> Result<()>
    where
        F: FnMut(&super::socket::UdxSocket, u16, std::net::IpAddr) -> bool + Send + 'static,
    {
        let udp = socket.udp_arc()?;
        let (notify_tx, notify_rx) = mpsc::unbounded_channel();

        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.terminated {
                return Err(UdxError::StreamClosed);
            }
            inner.remote_id = remote_id;
            inner.udp = Some(udp);
            inner.socket = Some(socket.clone());
            inner.notify_tx = Some(notify_tx);
            inner.firewall_hook = Some(Box::new(hook));
        }

        self.register_on(socket)?;
        self.start_processor(notify_rx)?;

        tracing::debug!(
            local_id = self.local_id,
            remote_id,
            "stream listening (firewall hook set)"
        );
        Ok(())
    }

    /// Also receive on `socket` while the firewall hook is armed, so the peer
    /// may reach this stream on more than one of our sockets (a holepunch
    /// socket and the DHT socket, say). The hook commits whichever socket
    /// the accepted packet arrives on.
    pub fn listen_on(&self, socket: &super::socket::UdxSocket) -> Result<()> {
        if self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .firewall_hook
            .is_none()
        {
            return Err(UdxError::Io(std::io::Error::other(
                "stream has no firewall hook",
            )));
        }
        self.register_on(socket)
    }

    /// Register for `socket`'s demux and remember the map for deregistration.
    fn register_on(&self, socket: &super::socket::UdxSocket) -> Result<()> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.terminated {
            return Err(UdxError::StreamClosed);
        }
        let tx = self
            .incoming_tx
            .as_ref()
            .ok_or_else(|| UdxError::Io(std::io::Error::other("stream already consumed")))?
            .clone();
        socket.register_stream(self.local_id, tx)?;
        let streams_ref = socket.streams_ref();
        let mut reg = self.registrations.lock().unwrap_or_else(|e| e.into_inner());
        if !reg
            .iter()
            .any(|existing| Arc::ptr_eq(existing, &streams_ref))
        {
            reg.push(streams_ref);
        }
        Ok(())
    }

    /// Spawn the processor task. Its guard terminates and deregisters the
    /// stream however the task ends, a panic included.
    fn start_processor(&self, notify_rx: mpsc::UnboundedReceiver<StreamNotify>) -> Result<()> {
        let incoming_rx = self
            .incoming_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| UdxError::Io(std::io::Error::other("processor already started")))?;
        let guard = ProcessorGuard {
            inner: Arc::clone(&self.inner),
            local_id: self.local_id,
            registrations: Arc::clone(&self.registrations),
            incoming_tx: self.incoming_tx.clone(),
        };
        let handle = tokio::spawn(async move {
            process_incoming(Arc::clone(&guard.inner), incoming_rx, notify_rx).await;
            drop(guard);
        });
        *self.processor.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
        Ok(())
    }

    /// Destroy the stream, sending DESTROY unless it is a relay leg (C libudx parity).
    pub async fn destroy(mut self) -> Result<()> {
        let destroy = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .destroy_packet();
        if let Some((udp, addr, packet)) = destroy {
            let _ = udp.send_to(&packet, addr).await;
        }

        let processor_handle = self.processor.lock().ok().and_then(|mut g| g.take());
        if let Some(handle) = processor_handle {
            handle.abort();
            let _ = handle.await;
        }

        let incoming_tx = self.incoming_tx.take();

        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.terminate();
        }

        deregister(self.local_id, &self.registrations, incoming_tx.as_ref());

        tracing::debug!(local_id = self.local_id, "stream destroyed");
        Ok(())
    }
}

/// Owned by the processor task: terminates and deregisters the stream when
/// the task ends, whether it returns, is aborted or panics.
struct ProcessorGuard {
    inner: Arc<Mutex<StreamInner>>,
    local_id: u32,
    registrations: Registrations,
    incoming_tx: Option<mpsc::Sender<IncomingPacket>>,
}

impl Drop for ProcessorGuard {
    fn drop(&mut self) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .terminate();
        deregister(
            self.local_id,
            &self.registrations,
            self.incoming_tx.as_ref(),
        );
    }
}

impl StreamInner {
    /// The DESTROY packet C `udx_stream_destroy` sends: only from a
    /// connected stream that is not a relay leg.
    fn destroy_packet(&self) -> Option<(Arc<super::udp::Udp>, SocketAddr, [u8; HEADER_SIZE])> {
        if !self.connected || self.relay_target.is_some() {
            return None;
        }
        let header = Header {
            type_flags: FLAG_DESTROY,
            data_offset: 0,
            remote_id: self.remote_id,
            recv_window: 0,
            seq: self.next_seq,
            ack: self.next_remote_seq,
        };
        Some((self.udp.clone()?, self.remote_addr?, header.encode()))
    }
}

/// Handle that destroys a stream from an owner other than the one holding it.
///
/// Returned by [`UdxStream::abort_handle`] and
/// [`super::async_stream::UdxAsyncStream::abort_handle`]. Used by the swarm to
/// close connections it has already handed out (Node
/// `swarm.suspend()` destroys `_allConnections`).
#[derive(Clone)]
pub struct UdxStreamAbort {
    inner: Arc<Mutex<StreamInner>>,
}

impl UdxStreamAbort {
    pub(crate) fn new(inner: Arc<Mutex<StreamInner>>) -> Self {
        Self { inner }
    }

    /// Smoothed RTT in milliseconds and packets retransmitted, as in C libudx.
    pub fn stats(&self) -> (u32, u64) {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (inner.srtt, inner.retransmits)
    }

    /// Current peer endpoint, including direct-path upgrades.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remote_addr
    }

    /// Fail pending writes and reads; send DESTROY unless this is a relay leg.
    pub fn abort(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((udp, addr, packet)) = inner.destroy_packet() {
            tokio::spawn(async move {
                let _ = udp.send_to(&packet, addr).await;
            });
        }
        // The processor only exits on Shutdown; queue it before `terminate`
        // drops the sender (the queued message still arrives), or the task
        // ticks its keepalive forever.
        if let Some(tx) = &inner.notify_tx {
            let _ = tx.send(StreamNotify::Shutdown);
        }
        inner.terminate();
    }

    /// Whether the stream is still running (not aborted, closed or dropped).
    pub fn is_alive(&self) -> bool {
        !self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .terminated
    }

    /// Asynchronously wait for the stream to close.
    ///
    /// Resolves when the stream is destroyed, aborted, or disconnected.
    /// Safe to call concurrently from multiple observers both before and
    /// after closure.
    pub async fn closed(&self) {
        let mut rx = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.terminated {
                return;
            }
            inner.close_watch_rx.clone()
        };

        while !*rx.borrow() {
            if rx.changed().await.is_err() {
                break;
            }
        }
    }
}

/// Handle that moves a connected stream to another peer and path
/// (Node `rawStream.changeRemote`), from any task holding it.
///
/// Returned by [`UdxStream::remote_handle`] and
/// [`super::async_stream::UdxAsyncStream::remote_handle`].
#[derive(Clone)]
pub struct UdxStreamRemote {
    inner: Arc<Mutex<StreamInner>>,
}

impl UdxStreamRemote {
    pub(crate) fn new(inner: Arc<Mutex<StreamInner>>) -> Self {
        Self { inner }
    }

    /// The peer address the stream currently sends to (Node
    /// `rawStream.remoteHost`/`remotePort`); moves with `change_remote`.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remote_addr
    }

    /// Also receive on `socket` while the firewall hook is armed, so a
    /// holepunch socket opened after `set_firewall_hook` (including after a
    /// relay already landed) can still deliver packets to this stream.
    pub fn listen_on(&self, socket: &super::socket::UdxSocket) -> Result<()> {
        let (local_id, tx, registrations) = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.terminated {
                return Err(UdxError::StreamClosed);
            }
            if inner.firewall_hook.is_none() {
                return Err(UdxError::Io(std::io::Error::other(
                    "stream has no firewall hook",
                )));
            }
            let tx = inner
                .incoming_tx
                .as_ref()
                .ok_or_else(|| UdxError::Io(std::io::Error::other("stream already consumed")))?
                .clone();
            (inner.local_id, tx, Arc::clone(&inner.registrations))
        };
        socket.register_stream(local_id, tx)?;
        let streams_ref = socket.streams_ref();
        let mut reg = registrations.lock().unwrap_or_else(|e| e.into_inner());
        if !reg
            .iter()
            .any(|existing| Arc::ptr_eq(existing, &streams_ref))
        {
            reg.push(streams_ref);
        }
        Ok(())
    }

    /// Send to `remote_id` at `remote_addr` over `socket` from now on
    /// (C `udx_stream_change_remote`, udx.c:2582).
    ///
    /// Packets already in flight keep their original destination; the
    /// stream keeps hearing its old socket, and the MTU search restarts on
    /// the new path. Resolves once the peer has ACKed everything sent before
    /// the change (right away when nothing was in flight). Fails on an
    /// unconnected stream, a port of 0, or while an earlier change is still
    /// pending (Node throws `Remote already changing`).
    pub async fn change_remote(
        &self,
        socket: &super::socket::UdxSocket,
        remote_id: u32,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let udp = socket.udp_arc()?;
        if remote_addr.port() == 0 {
            return Err(UdxError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "remote port is 0",
            )));
        }
        let (local_id, done) = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !inner.connected || !inner.is_alive() {
                return Err(UdxError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "stream not connected",
                )));
            }
            if inner.remote_change.is_some() {
                return Err(UdxError::Io(std::io::Error::other(
                    "remote already changing",
                )));
            }
            let incoming_tx = inner.incoming_tx.clone().ok_or(UdxError::StreamClosed)?;
            socket.register_stream(inner.local_id, incoming_tx)?;
            {
                let streams_ref = socket.streams_ref();
                let mut registrations = inner
                    .registrations
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if !registrations
                    .iter()
                    .any(|existing| Arc::ptr_eq(existing, &streams_ref))
                {
                    registrations.push(streams_ref);
                }
            }
            inner.remote_id = remote_id;
            inner.remote_addr = Some(remote_addr);
            inner.observed_current_remote = false;
            inner.udp = Some(udp);
            inner.socket = Some(socket.clone());
            // Relay legs forwarding to this stream follow it to the new path.
            inner.publish_endpoint();
            // Unsent data is cut into packets at send time, for this peer
            // at the base MTU, as in C.
            inner.reset_mtu();
            let done = inner.outgoing.last_seq().map(|last| {
                let (tx, rx) = oneshot::channel();
                inner.remote_change = Some((last.wrapping_add(1), tx));
                rx
            });
            (inner.local_id, done)
        };
        tracing::debug!(
            local_id,
            remote_id,
            ?remote_addr,
            deferred = done.is_some(),
            "change_remote"
        );
        if let Some(rx) = done {
            rx.await.map_err(|_| UdxError::StreamClosed)?;
        }
        Ok(())
    }

    /// Resolves once data or a message from the current remote arrives on the
    /// current socket, confirming the peer sends application traffic directly.
    pub async fn remote_observed(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !inner.is_alive() {
                return Err(UdxError::StreamClosed);
            }
            if inner.observed_current_remote {
                return Ok(());
            }
            inner.remote_observed = Some(tx);
        }
        rx.await.map_err(|_| UdxError::StreamClosed)
    }

    /// Send an unreliable message to the current remote (C `udx_stream_send`,
    /// Node `rawStream.trySend`). hyperdht sends an empty one so the peer
    /// notices a new path without application data crossing it.
    pub fn try_send(&self, payload: &[u8]) -> Result<()> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (Some(udp), Some(addr)) = (inner.udp.clone(), inner.remote_addr) else {
            return Err(UdxError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "stream not connected",
            )));
        };
        let header = Header {
            type_flags: FLAG_MESSAGE,
            data_offset: 0,
            remote_id: inner.remote_id,
            recv_window: inner.receive_window.advertise(),
            seq: inner.next_seq,
            ack: inner.next_remote_seq,
        };
        let mut packet = header.encode().to_vec();
        packet.extend_from_slice(payload);
        tokio::spawn(async move {
            let _ = udp.send_to(&packet, addr).await;
        });
        Ok(())
    }

    /// Next unreliable message the peer sent with `try_send` (C `on_recv`,
    /// Node `rawStream.on('message')`), in arrival order. Up to 64 unread
    /// messages are kept; more are dropped like any unread datagram.
    /// Returns `StreamClosed` once the stream has closed and every kept
    /// message was read.
    pub async fn recv_message(&self) -> Result<Vec<u8>> {
        let rx = Arc::clone(
            &self
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .message_rx,
        );
        let mut rx = rx.lock().await;
        rx.recv().await.ok_or(UdxError::StreamClosed)
    }
}

impl Drop for UdxStream {
    fn drop(&mut self) {
        if self.read_rx.is_some() {
            let incoming_tx = self.incoming_tx.take();
            self.inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .terminate();
            if let Ok(mut guard) = self.processor.lock() {
                if let Some(handle) = guard.take() {
                    handle.abort();
                }
            }
            deregister(self.local_id, &self.registrations, incoming_tx.as_ref());
        }
    }
}

// ── Processor task (reliability engine) ──────────────────────────────────────

async fn process_incoming(
    inner: Arc<Mutex<StreamInner>>,
    mut incoming_rx: mpsc::Receiver<IncomingPacket>,
    mut notify_rx: mpsc::UnboundedReceiver<StreamNotify>,
) {
    use tokio::time::{self, Duration, Instant as TokioInstant};

    /// Maximum queued incoming packets drained per wake before returning to
    /// `tokio::select!` so timers and write notifications stay responsive.
    const MAX_INCOMING_BURST: usize = 32;

    let mut shutting_down = false;
    // Set when the owner dropped the stream: DESTROY once the queue is sent.
    let mut destroy_when_sent = false;
    let mut read_events = Vec::new();
    // Reusable scratch vectors across incoming packets and send passes.
    let mut send_batch: Vec<(Bytes, SocketAddr)> = Vec::new();
    let mut completed_writes: WriteSenders = Vec::new();
    let mut acked_rate_info: AckedRateInfo = Vec::new();
    let mut sack_ranges_scratch: Vec<SackRange> = Vec::new();
    let mut incoming_burst: Vec<IncomingPacket> = Vec::with_capacity(MAX_INCOMING_BURST);
    let mut burst_acks: Vec<ControlPacket> = Vec::new();
    let mut burst_messages: Vec<(Vec<u8>, mpsc::Sender<Vec<u8>>)> = Vec::new();
    // The datagram that a relay forwards, put together again from header and
    // body. Kept between packets so that forwarding does not allocate.
    let mut relay_datagram = Vec::new();
    // In-order DATA packets received since the last ACK went out.
    let mut pending_acks = 0u32;
    // Zero-window probes sent since the peer last advertised a window.
    let mut zwp_probes = 0u32;
    // When the peer was last heard from, for the keepalive's dead-peer check.
    let mut last_heard = TokioInstant::now();
    let far = || TokioInstant::now() + FAR_FUTURE;

    // Retransmission timer, also the zero-window probe timer while
    // nothing is in flight (C keeps one stream timer for both).
    let rto_sleep = time::sleep(FAR_FUTURE);
    tokio::pin!(rto_sleep);
    let mut rto_armed = false;

    let tlp_sleep = time::sleep(FAR_FUTURE);
    tokio::pin!(tlp_sleep);
    let mut tlp_armed = false;

    // RACK reorder timer (C `UDX_TIMER_RACK_REO`). C keeps one stream timer,
    // so while this one is armed neither the loss probe nor the RTO is.
    let reo_sleep = time::sleep(FAR_FUTURE);
    tokio::pin!(reo_sleep);
    let mut reo_armed = false;

    let pacing_sleep = time::sleep(FAR_FUTURE);
    tokio::pin!(pacing_sleep);
    let mut pacing_armed = false;

    let (keepalive, read_tx) = {
        let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
        (guard.keepalive, guard.read_tx.clone())
    };
    let keepalive_sleep = time::sleep(keepalive.unwrap_or(FAR_FUTURE));
    tokio::pin!(keepalive_sleep);

    'outer: loop {
        // The burst that deferred an ACK has been processed.
        if pending_acks > 0 && incoming_rx.is_empty() {
            let ack = inner.lock().unwrap_or_else(|e| e.into_inner()).ack_packet();
            send_now(ack);
            pending_acks = 0;
        }
        tokio::select! {
            // ── Incoming packet processing ───────────────────────────
            packet = incoming_rx.recv() => {
                let Some(first_packet) = packet else { break 'outer };
                incoming_burst.clear();
                incoming_burst.push(first_packet);
                while incoming_burst.len() < MAX_INCOMING_BURST {
                    match incoming_rx.try_recv() {
                        Ok(p) => incoming_burst.push(p),
                        Err(_) => break,
                    }
                }

                let mut idx = 0usize;
                while idx < incoming_burst.len() {
                    send_batch.clear();
                    completed_writes.clear();
                    burst_acks.clear();
                    burst_messages.clear();

                    let mut should_break = false;
                    let mut any_ack_advanced = false;
                    let mut any_delivered = false;
                    let mut any_send_new_data = false;
                    let mut any_recv_window_nonzero = false;
                    let mut last_reorder_timeout: Option<Duration> = None;
                    let mut last_send_stop: Option<SendStop> = None;
                    let mut zwp_stalled = false;
                    let mut was_outgoing_empty = false;
                    let mut outgoing_empty = true;
                    let mut rto = Duration::from_millis(INITIAL_RTO_MS.into());
                    let mut tlp: Option<u32> = None;
                    let mut udp: Option<Arc<super::udp::Udp>> = None;
                    let mut did_process_fast = false;
                    let mut cold_relay: Option<(Endpoint, Header, Bytes, bool)> = None;
                    let mut cold_firewall_idx: Option<usize> = None;

                    {
                        let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        if guard.terminated {
                            should_break = true;
                        } else {
                            was_outgoing_empty = guard.outgoing.is_empty();
                            while idx < incoming_burst.len() {
                                let same = guard.udp.as_ref().is_some_and(|ours| {
                                    Arc::as_ptr(ours) as usize == incoming_burst[idx].udp_ptr
                                });
                                if !guard.connected || !same {
                                    cold_firewall_idx = Some(idx);
                                    break;
                                }
                                if let Some(ref target) = guard.relay_target {
                                    let p = &mut incoming_burst[idx];
                                    let h = p.header.clone();
                                    let body = std::mem::take(&mut p.body);
                                    let is_destroy = h.has_flag(FLAG_DESTROY);
                                    cold_relay = Some((Arc::clone(target), h, body, is_destroy));
                                    idx += 1;
                                    break;
                                }

                                let p = &mut incoming_burst[idx];
                                let header = p.header.clone();
                                let addr = p.addr;
                                let udp_ptr = p.udp_ptr;
                                let mut body = std::mem::take(&mut p.body);
                                idx += 1;

                                let is_data = header.has_flag(FLAG_DATA);
                                let is_end = header.has_flag(FLAG_END);
                                let is_destroy = header.has_flag(FLAG_DESTROY);
                                let is_heartbeat = header.has_flag(FLAG_HEARTBEAT);
                                let is_message = header.has_flag(FLAG_MESSAGE);

                                did_process_fast = true;
                                if header.recv_window > 0 {
                                    any_recv_window_nonzero = true;
                                }

                                // Peer seen on the current path (after `change_remote`).
                                if !guard.observed_current_remote || guard.remote_observed.is_some()
                                {
                                    let observed = is_message
                                        || (is_data && header.seq == guard.next_remote_seq);
                                    if observed && guard.remote_addr == Some(addr) {
                                        let same_sock = guard.udp.as_ref().is_some_and(|ours| {
                                            Arc::as_ptr(ours) as usize == udp_ptr
                                        });
                                        if same_sock {
                                            guard.observed_current_remote = true;
                                            if let Some(tx) = guard.remote_observed.take() {
                                                let _ = tx.send(());
                                            }
                                        }
                                    }
                                }

                                let has_sacks = if header.has_flag(FLAG_SACK) {
                                    header
                                        .sack_region(HEADER_SIZE + body.len())
                                        .is_some_and(|region| {
                                            decode_sack_into(
                                                &body[region.start - HEADER_SIZE
                                                    ..region.end - HEADER_SIZE],
                                                &mut sack_ranges_scratch,
                                            )
                                            .is_ok()
                                        })
                                } else {
                                    false
                                };

                                let message = (is_message
                                    && header.data_offset as usize <= body.len())
                                .then(|| body[header.data_offset as usize..].to_vec());

                                tracing::trace!(
                                    flags = header.type_flags,
                                    seq = header.seq,
                                    ack = header.ack,
                                    data_offset = header.data_offset,
                                    "process_incoming: received packet"
                                );

                                let is_last_in_burst = idx == incoming_burst.len();
                                let outcome = guard.on_ack_packet_into(
                                    &header,
                                    has_sacks.then_some(sack_ranges_scratch.as_slice()),
                                    &mut completed_writes,
                                    &mut acked_rate_info,
                                    &mut send_batch,
                                    false,
                                );
                                any_ack_advanced |= outcome.ack_advanced;
                                any_delivered |= outcome.delivered;
                                any_send_new_data |= outcome.send_new_data;
                                if outcome.reorder_timeout.is_some() {
                                    last_reorder_timeout = outcome.reorder_timeout;
                                } else if outcome.ack_advanced {
                                    last_reorder_timeout = None;
                                }
                                if outcome.send_stop.is_some() {
                                    last_send_stop = outcome.send_stop;
                                }

                                let end_acked_now = outcome.ack_advanced && guard.end_acked();
                                if end_acked_now && guard.remote_ended {
                                    for event in read_events.drain(..) {
                                        let _ = read_tx.send(event);
                                    }
                                    guard.close_ended();
                                    should_break = true;
                                    break;
                                }

                                if is_data || is_end {
                                    let skip = (header.data_offset as usize).min(body.len());
                                    if skip > 0 {
                                        body.advance(skip);
                                    }
                                    let recv_flags = (if is_data { FLAG_DATA } else { 0 })
                                        | (if is_end { FLAG_END } else { 0 });
                                    guard.receive_data(
                                        header.seq,
                                        body,
                                        recv_flags,
                                        &mut read_events,
                                    );
                                    pending_acks += 1;
                                    let ack_now = is_end
                                        || end_acked_now
                                        || !guard.recv_ranges.is_empty()
                                        || pending_acks >= ACK_EVERY
                                        || (is_last_in_burst && incoming_rx.is_empty());
                                    if ack_now {
                                        pending_acks = 0;
                                        if let Some(ack) = guard.ack_packet() {
                                            burst_acks.push(ack);
                                        }
                                    }
                                } else if end_acked_now {
                                    if let Some(ack) = guard.ack_packet() {
                                        burst_acks.push(ack);
                                    }
                                }

                                if guard.all_ended() {
                                    for event in read_events.drain(..) {
                                        let _ = read_tx.send(event);
                                    }
                                    guard.close_ended();
                                    should_break = true;
                                    break;
                                } else if is_destroy {
                                    for event in read_events.drain(..) {
                                        let _ = read_tx.send(event);
                                    }
                                    guard.fail(
                                        std::io::ErrorKind::ConnectionReset,
                                        "stream destroyed by peer",
                                    );
                                    should_break = true;
                                    break;
                                }

                                if let (Some(msg), Some(tx)) = (message, guard.message_tx.clone()) {
                                    burst_messages.push((msg, tx));
                                }
                                if is_heartbeat {
                                    if let Some(hb) = guard.ack_packet() {
                                        burst_acks.push(hb);
                                    }
                                }
                                if send_batch.len() >= 64 {
                                    break;
                                }
                            }

                            if did_process_fast {
                                if !should_break
                                    && send_batch.len() < 64
                                    && guard.has_pending_send()
                                {
                                    let (stop, more_new_data) =
                                        guard.take_send_batch_into(&mut send_batch);
                                    last_send_stop = Some(stop);
                                    any_send_new_data |= more_new_data;
                                }
                                outgoing_empty = guard.outgoing.is_empty();
                                rto = Duration::from_millis(guard.rto.into());
                                tlp = if any_ack_advanced || any_send_new_data {
                                    guard.loss_probe_timeout()
                                } else {
                                    None
                                };
                                zwp_stalled = matches!(last_send_stop, Some(SendStop::Window))
                                    && guard.zero_window_stalled();
                                if !send_batch.is_empty() {
                                    udp = guard.udp.clone();
                                }
                            }
                        }
                    }

                    if did_process_fast {
                        for tx in completed_writes.drain(..).flatten() {
                            let _ = tx.send(Ok(()));
                        }
                        if let (false, Some(udp)) = (send_batch.is_empty(), udp) {
                            if let Some(size) = udp.send_batch(&send_batch).await {
                                inner
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .on_send_too_big(size);
                            }
                        }
                        for event in read_events.drain(..) {
                            let _ = read_tx.send(event);
                        }
                        for ack in burst_acks.drain(..) {
                            send_now(Some(ack));
                        }
                        for (msg, tx) in burst_messages.drain(..) {
                            let _ = tx.try_send(msg);
                        }

                        if should_break {
                            break 'outer;
                        }

                        if any_recv_window_nonzero {
                            zwp_probes = 0;
                        }

                        let now = TokioInstant::now();
                        last_heard = now;
                        if any_ack_advanced && outgoing_empty {
                            if rto_armed {
                                rto_sleep.as_mut().reset(far());
                                rto_armed = false;
                            }
                            if tlp_armed {
                                tlp_sleep.as_mut().reset(far());
                                tlp_armed = false;
                            }
                            if reo_armed {
                                reo_sleep.as_mut().reset(far());
                                reo_armed = false;
                            }
                        } else if let Some(reorder) = last_reorder_timeout {
                            reo_sleep.as_mut().reset(now + reorder);
                            reo_armed = true;
                            if tlp_armed {
                                tlp_sleep.as_mut().reset(far());
                                tlp_armed = false;
                            }
                            rto_sleep.as_mut().reset(now + rto);
                            rto_armed = true;
                        } else if any_ack_advanced {
                            if reo_armed {
                                reo_sleep.as_mut().reset(far());
                                reo_armed = false;
                            }
                            rto_sleep.as_mut().reset(now + rto);
                            rto_armed = true;
                            if let Some(tlp_ms) = tlp {
                                let tlp_dur = Duration::from_millis(tlp_ms.into()).min(rto);
                                tlp_sleep.as_mut().reset(now + tlp_dur);
                                tlp_armed = true;
                            } else if tlp_armed {
                                tlp_sleep.as_mut().reset(far());
                                tlp_armed = false;
                            }
                        } else {
                            if any_delivered && reo_armed && !outgoing_empty {
                                rto_sleep.as_mut().reset(now + rto);
                                rto_armed = true;
                            }
                            if was_outgoing_empty && !outgoing_empty {
                                rto_sleep.as_mut().reset(now + rto);
                                rto_armed = true;
                            }
                            if any_send_new_data {
                                if let Some(tlp_ms) = tlp {
                                    let rto_left =
                                        rto_sleep.deadline().saturating_duration_since(now);
                                    tlp_sleep.as_mut().reset(
                                        now + Duration::from_millis(tlp_ms.into()).min(rto_left),
                                    );
                                    tlp_armed = true;
                                    if reo_armed {
                                        reo_sleep.as_mut().reset(far());
                                        reo_armed = false;
                                    }
                                }
                            }
                        }

                        match last_send_stop {
                            Some(SendStop::Pacing(delay)) => {
                                pacing_sleep.as_mut().reset(now + delay);
                                pacing_armed = true;
                            }
                            Some(SendStop::Window) => {
                                if pacing_armed {
                                    pacing_sleep.as_mut().reset(far());
                                    pacing_armed = false;
                                }
                                if zwp_stalled && !rto_armed {
                                    rto_sleep.as_mut().reset(now + rto);
                                    rto_armed = true;
                                }
                            }
                            Some(SendStop::Idle) if pacing_armed => {
                                pacing_sleep.as_mut().reset(far());
                                pacing_armed = false;
                            }
                            Some(SendStop::Idle) | None => {}
                        }
                    } else if should_break {
                        break 'outer;
                    }

                    if let Some((target, relay_hdr, relay_body, relay_destroy)) = cold_relay {
                        last_heard = TokioInstant::now();
                        let destination =
                            target.lock().unwrap_or_else(|e| e.into_inner()).clone();
                        if let Some((dest_remote_id, dest_addr, dest_udp)) = destination {
                            relay_datagram.clear();
                            relay_datagram.extend_from_slice(&relay_hdr.encode());
                            relay_datagram[4..8].copy_from_slice(&dest_remote_id.to_le_bytes());
                            relay_datagram.extend_from_slice(&relay_body);
                            let _ = dest_udp.send_to(&relay_datagram, dest_addr).await;
                        }
                        if relay_destroy {
                            tracing::debug!("relay: DESTROY received, closing relay stream");
                            break 'outer;
                        }
                        continue;
                    }

                    if let Some(fw_idx) = cold_firewall_idx {
                        let pkt_addr = incoming_burst[fw_idx].addr;
                        let pkt_socket = incoming_burst[fw_idx].socket.clone();
                        let (is_connected, hook) = {
                            let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                            if guard.terminated {
                                break 'outer;
                            }
                            (guard.connected, guard.firewall_hook.take())
                        };
                        let accepted = match hook {
                            Some(mut hook) => {
                                let ok = hook(&pkt_socket, pkt_addr.port(), pkt_addr.ip());
                                let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                                guard.firewall_hook = Some(hook);
                                if !ok {
                                    tracing::debug!(addr = ?pkt_addr, "firewall hook: rejected");
                                    false
                                } else {
                                    if !is_connected {
                                        guard.remote_addr = Some(pkt_addr);
                                        guard.udp = pkt_socket.udp_arc().ok();
                                        guard.socket = Some(pkt_socket);
                                        guard.connected = true;
                                        guard.publish_endpoint();
                                        if let Some(tx) = &guard.notify_tx {
                                            let _ = tx.send(StreamNotify::DataQueued);
                                        }
                                        tracing::debug!(addr = ?pkt_addr, "firewall hook: accepted");
                                    }
                                    true
                                }
                            }
                            None if !is_connected => false,
                            None => true,
                        };
                        if !accepted {
                            idx = fw_idx + 1;
                            continue;
                        }
                        // Accepted: if still on a different socket than `guard.udp`
                        // (mid-`change_remote`), process this single packet now so
                        // the next loop iteration doesn't re-invoke the firewall hook.
                        let still_different = {
                            let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                            !guard.udp.as_ref().is_some_and(|ours| {
                                Arc::as_ptr(ours) as usize == incoming_burst[fw_idx].udp_ptr
                            })
                        };
                        if still_different {
                            // Temporarily advance `idx` and process this packet via
                            // the fast path by matching its `udp_ptr`? No — simply
                            // process it cleanly right here using the same logic.
                            let p = &mut incoming_burst[fw_idx];
                            let header = p.header.clone();
                            let mut body = std::mem::take(&mut p.body);
                            idx = fw_idx + 1;
                            let is_data = header.has_flag(FLAG_DATA);
                            let is_end = header.has_flag(FLAG_END);
                            let is_destroy = header.has_flag(FLAG_DESTROY);
                            let is_heartbeat = header.has_flag(FLAG_HEARTBEAT);
                            let is_message = header.has_flag(FLAG_MESSAGE);
                            let has_sacks = if header.has_flag(FLAG_SACK) {
                                header
                                    .sack_region(HEADER_SIZE + body.len())
                                    .is_some_and(|region| {
                                        decode_sack_into(
                                            &body[region.start - HEADER_SIZE
                                                ..region.end - HEADER_SIZE],
                                            &mut sack_ranges_scratch,
                                        )
                                        .is_ok()
                                    })
                            } else {
                                false
                            };
                            let message = (is_message
                                && header.data_offset as usize <= body.len())
                            .then(|| body[header.data_offset as usize..].to_vec());
                            send_batch.clear();
                            completed_writes.clear();
                            let (ack, hb_ack, msg_tx, send_udp, brk) = {
                                let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                                if guard.terminated {
                                    (None, None, None, None, true)
                                } else {
                                    let outcome = guard.on_ack_packet_into(
                                        &header,
                                        has_sacks.then_some(sack_ranges_scratch.as_slice()),
                                        &mut completed_writes,
                                        &mut acked_rate_info,
                                        &mut send_batch,
                                        true,
                                    );
                                    let end_acked_now = outcome.ack_advanced && guard.end_acked();
                                    let mut brk = false;
                                    let mut ack = None;
                                    if end_acked_now && guard.remote_ended {
                                        guard.close_ended();
                                        brk = true;
                                    } else {
                                        if is_data || is_end {
                                            let skip =
                                                (header.data_offset as usize).min(body.len());
                                            if skip > 0 {
                                                body.advance(skip);
                                            }
                                            let recv_flags = (if is_data { FLAG_DATA } else { 0 })
                                                | (if is_end { FLAG_END } else { 0 });
                                            guard.receive_data(
                                                header.seq,
                                                body,
                                                recv_flags,
                                                &mut read_events,
                                            );
                                            pending_acks = 0;
                                            ack = guard.ack_packet();
                                        } else if end_acked_now {
                                            ack = guard.ack_packet();
                                        }
                                        if guard.all_ended() {
                                            for event in read_events.drain(..) {
                                                let _ = read_tx.send(event);
                                            }
                                            guard.close_ended();
                                            brk = true;
                                        } else if is_destroy {
                                            for event in read_events.drain(..) {
                                                let _ = read_tx.send(event);
                                            }
                                            guard.fail(
                                                std::io::ErrorKind::ConnectionReset,
                                                "stream destroyed by peer",
                                            );
                                            brk = true;
                                        }
                                    }
                                    let msg_tx = (!brk && message.is_some())
                                        .then(|| guard.message_tx.clone())
                                        .flatten();
                                    let hb_ack =
                                        (!brk && is_heartbeat).then(|| guard.ack_packet()).flatten();
                                    let send_udp = (!send_batch.is_empty())
                                        .then(|| guard.udp.clone())
                                        .flatten();
                                    (ack, hb_ack, msg_tx, send_udp, brk)
                                }
                            };
                            for tx in completed_writes.drain(..).flatten() {
                                let _ = tx.send(Ok(()));
                            }
                            if let (false, Some(send_udp)) = (send_batch.is_empty(), send_udp) {
                                if let Some(size) = send_udp.send_batch(&send_batch).await {
                                    inner
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .on_send_too_big(size);
                                }
                            }
                            for event in read_events.drain(..) {
                                let _ = read_tx.send(event);
                            }
                            send_now(ack);
                            if let (Some(msg), Some(tx)) = (message, msg_tx) {
                                let _ = tx.try_send(msg);
                            }
                            send_now(hb_ack);
                            if brk {
                                break 'outer;
                            }
                        }
                    }
                }
                incoming_burst.clear();
            }

            Some(notify) = notify_rx.recv() => {
                let mut wake_send = false;
                let mut update_keepalive = false;
                let mut window_update = false;
                let mut next_notify = Some(notify);
                while let Some(n) = next_notify {
                    match n {
                        StreamNotify::DataQueued => {
                            wake_send = true;
                        }
                        StreamNotify::Shutdown => {
                            shutting_down = true;
                            wake_send = true;
                        }
                        StreamNotify::Dropped => {
                            shutting_down = true;
                            destroy_when_sent = true;
                            wake_send = true;
                        }
                        StreamNotify::Keepalive => {
                            update_keepalive = true;
                        }
                        StreamNotify::WindowUpdate => {
                            window_update = true;
                        }
                    }
                    next_notify = notify_rx.try_recv().ok();
                }
                if update_keepalive {
                    let interval = inner.lock().unwrap_or_else(|e| e.into_inner()).keepalive;
                    last_heard = TokioInstant::now();
                    keepalive_sleep
                        .as_mut()
                        .reset(last_heard + interval.unwrap_or(FAR_FUTURE));
                }
                if window_update {
                    // C has no such ACK: its `send_ack` runs only when a
                    // packet arrives. This one lets a sender stopped on the
                    // old window start without waiting for its probe timer;
                    // the peer's zero-window probe repairs a lost update.
                    let ack = {
                        let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        guard.receive_window.update_handled();
                        if guard.remote_ended {
                            None
                        } else {
                            guard.ack_packet()
                        }
                    };
                    send_now(ack);
                }
                if wake_send && !pacing_armed {
                    // Send immediately instead of bouncing through `pacing_sleep`.
                    send_batch.clear();
                    let (stop, arm_rto, tlp, rto, udp, zwp, zwp_stalled) = {
                        let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        let was_outgoing_empty = guard.outgoing.is_empty();
                        let (stop, new_data) = guard.take_send_batch_into(&mut send_batch);
                        let arm_rto = was_outgoing_empty && !guard.outgoing.is_empty();
                        let tlp = if new_data {
                            guard.loss_probe_timeout()
                        } else {
                            None
                        };
                        let zwp = std::mem::take(&mut guard.zwp_wanted)
                            .then(|| guard.heartbeat_packet())
                            .flatten();
                        let zwp_stalled =
                            matches!(stop, SendStop::Window) && guard.zero_window_stalled();
                        (
                            stop,
                            arm_rto,
                            tlp,
                            Duration::from_millis(guard.rto.into()),
                            if !send_batch.is_empty() {
                                guard.udp.clone()
                            } else {
                                None
                            },
                            zwp,
                            zwp_stalled,
                        )
                    };
                    if zwp.is_some() {
                        send_now(zwp);
                        rto_sleep.as_mut().reset(TokioInstant::now() + rto);
                        rto_armed = true;
                    }
                    if let Some(udp) = udp {
                        if let Some(size) = udp.send_batch(&send_batch).await {
                            inner
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .on_send_too_big(size);
                        }
                    }
                    let now = TokioInstant::now();
                    if arm_rto {
                        rto_sleep.as_mut().reset(now + rto);
                        rto_armed = true;
                    }
                    if let Some(tlp) = tlp {
                        let rto_left = rto_sleep.deadline().saturating_duration_since(now);
                        tlp_sleep
                            .as_mut()
                            .reset(now + Duration::from_millis(tlp.into()).min(rto_left));
                        tlp_armed = true;
                        if reo_armed {
                            reo_sleep.as_mut().reset(far());
                            reo_armed = false;
                        }
                    }
                    match stop {
                        SendStop::Pacing(delay) => {
                            pacing_sleep.as_mut().reset(now + delay);
                            pacing_armed = true;
                        }
                        SendStop::Window => {
                            if zwp_stalled && !rto_armed {
                                rto_sleep.as_mut().reset(now + rto);
                                rto_armed = true;
                            }
                        }
                        SendStop::Idle => {}
                    }
                    if shutting_down {
                        let destroy = {
                            let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                            if guard.connected && guard.has_unsent() {
                                continue;
                            }
                            if destroy_when_sent {
                                guard.destroy_packet()
                            } else {
                                None
                            }
                        };
                        if let Some((udp, addr, packet)) = destroy {
                            let _ = udp.send_to(&packet, addr).await;
                        }
                        break 'outer;
                    }
                }
            }

            _ = &mut pacing_sleep => {
                send_batch.clear();
                let (stop, arm_rto, tlp, rto, udp, zwp, zwp_stalled) = {
                    let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    #[cfg(test)]
                    {
                        guard.pacing_wakeups += 1;
                    }
                    let was_outgoing_empty = guard.outgoing.is_empty();
                    let (stop, new_data) = guard.take_send_batch_into(&mut send_batch);
                    let arm_rto = was_outgoing_empty && !guard.outgoing.is_empty();
                    // C `arm_stream_timers`: new data (re)schedules the loss probe.
                    let tlp = if new_data { guard.loss_probe_timeout() } else { None };
                    let zwp = std::mem::take(&mut guard.zwp_wanted)
                        .then(|| guard.heartbeat_packet())
                        .flatten();
                    let zwp_stalled = matches!(stop, SendStop::Window) && guard.zero_window_stalled();
                    (
                        stop,
                        arm_rto,
                        tlp,
                        Duration::from_millis(guard.rto.into()),
                        if !send_batch.is_empty() { guard.udp.clone() } else { None },
                        zwp,
                        zwp_stalled,
                    )
                };
                // C udx.c:2806: probe the zero window now, again at the RTO.
                if zwp.is_some() {
                    send_now(zwp);
                    rto_sleep.as_mut().reset(TokioInstant::now() + rto);
                    rto_armed = true;
                }

                if let Some(udp) = udp {
                    if let Some(size) = udp.send_batch(&send_batch).await {
                        inner.lock().unwrap_or_else(|e| e.into_inner()).on_send_too_big(size);
                    }
                }

                let now = TokioInstant::now();
                if arm_rto {
                    rto_sleep.as_mut().reset(now + rto);
                    rto_armed = true;
                }
                if let Some(tlp) = tlp {
                    let rto_left = rto_sleep.deadline().saturating_duration_since(now);
                    tlp_sleep
                        .as_mut()
                        .reset(now + Duration::from_millis(tlp.into()).min(rto_left));
                    tlp_armed = true;
                    // C's single timer: the probe replaces a reorder wait.
                    if reo_armed {
                        reo_sleep.as_mut().reset(far());
                        reo_armed = false;
                    }
                }
                match stop {
                    SendStop::Pacing(delay) => {
                        pacing_sleep.as_mut().reset(now + delay);
                        pacing_armed = true;
                    }
                    // An ACK, the RTO or a zero-window probe moves things on:
                    // no timer poll while the window is full.
                    SendStop::Window => {
                        pacing_sleep.as_mut().reset(far());
                        pacing_armed = false;
                        // C udx.c:1841: probe the zero window after one RTO.
                        if zwp_stalled && !rto_armed {
                            rto_sleep.as_mut().reset(now + rto);
                            rto_armed = true;
                        }
                    }
                    SendStop::Idle => {
                        pacing_sleep.as_mut().reset(far());
                        pacing_armed = false;
                    }
                }

                if shutting_down {
                    let destroy = {
                        let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        if guard.connected && guard.has_unsent() {
                            continue;
                        }
                        if destroy_when_sent { guard.destroy_packet() } else { None }
                    };
                    // C `udx_stream_destroy`: the peer learns at once.
                    if let Some((udp, addr, packet)) = destroy {
                        let _ = udp.send_to(&packet, addr).await;
                    }
                    break 'outer;
                }
            }

            _ = &mut rto_sleep => {
                let now = TokioInstant::now();
                let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                let rto = Duration::from_millis(guard.rto.into());
                if guard.outgoing.is_empty() {
                    if !guard.zero_window_stalled() {
                        rto_sleep.as_mut().reset(far());
                        rto_armed = false;
                        continue;
                    }
                    // Zero-window probe (C `udx_zwp_timeout`): the peer's
                    // ACK to the heartbeat carries its current window.
                    zwp_probes += 1;
                    if shutting_down && zwp_probes >= MAX_RTO_TIMEOUTS {
                        tracing::debug!("stream failed: peer window stayed closed");
                        guard.fail(std::io::ErrorKind::TimedOut, "peer window stayed closed");
                        break 'outer;
                    }
                    let probe = guard.heartbeat_packet();
                    drop(guard);
                    send_now(probe);
                    rto_sleep.as_mut().reset(now + rto * 2);
                    rto_armed = true;
                    continue;
                }

                let Some(rto) = guard.rto_fired() else {
                    tracing::warn!("stream failed: exceeded max RTO timeouts");
                    guard.fail(std::io::ErrorKind::TimedOut, "RTO timeout exceeded");
                    break 'outer;
                };
                drop(guard);
                tracing::debug!(rto_ms = rto.as_millis() as u64, "rto: retransmitting");
                rto_sleep.as_mut().reset(now + rto);
                rto_armed = true;
                if tlp_armed {
                    tlp_sleep.as_mut().reset(far());
                    tlp_armed = false;
                }
                if reo_armed {
                    reo_sleep.as_mut().reset(far());
                    reo_armed = false;
                }
                pacing_sleep.as_mut().reset(now);
                pacing_armed = true;
            }

            // ── RACK reorder timer (C `udx_rack_reo_timeout`) ────────
            _ = &mut reo_sleep => {
                reo_sleep.as_mut().reset(far());
                reo_armed = false;
                let now = TokioInstant::now();
                let (send_pending, all_acked) = {
                    let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    guard.on_reorder_timeout();
                    (guard.has_pending_send(), guard.outgoing.is_empty())
                };
                if send_pending {
                    pacing_sleep.as_mut().reset(now);
                    pacing_armed = true;
                }
                // C `rearm_rto(stream, false)`: the RTO at its saved time,
                // at least 1 ms away; the loss probe is gone.
                if tlp_armed {
                    tlp_sleep.as_mut().reset(far());
                    tlp_armed = false;
                }
                if all_acked {
                    if rto_armed {
                        rto_sleep.as_mut().reset(far());
                        rto_armed = false;
                    }
                } else if rto_sleep.deadline() <= now {
                    rto_sleep.as_mut().reset(now + Duration::from_millis(1));
                    rto_armed = true;
                }
            }

            // ── Tail loss probe (C `udx_tlp_timeout`) ───────────────
            _ = &mut tlp_sleep => {
                tlp_sleep.as_mut().reset(far());
                tlp_armed = false;
                let (probe, rto, udp) = {
                    let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    (guard.take_loss_probe(), guard.rto, guard.udp.clone())
                };
                if let (Some((packet, addr)), Some(udp)) = (probe, udp) {
                    let _ = udp.send_to(&packet, addr).await;
                    rto_sleep
                        .as_mut()
                        .reset(TokioInstant::now() + Duration::from_millis(rto.into()));
                    rto_armed = true;
                }
            }

            // ── Keepalive heartbeat ──────────────────────────────────
            _ = &mut keepalive_sleep => {
                let now = TokioInstant::now();
                let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                let Some(interval) = guard.keepalive else {
                    keepalive_sleep.as_mut().reset(far());
                    continue;
                };
                keepalive_sleep.as_mut().reset(now + interval);
                // Relay legs and unconnected streams have no peer to hear.
                if !guard.connected || guard.relay_target.is_some() {
                    last_heard = now;
                    continue;
                }
                if now.duration_since(last_heard) >= interval * KEEPALIVE_DEAD_INTERVALS {
                    tracing::debug!("stream failed: peer silent through keepalives");
                    guard.fail(std::io::ErrorKind::TimedOut, "peer stopped answering keepalives");
                    break 'outer;
                }
                let probe = if guard.outgoing.is_empty() {
                    guard.heartbeat_packet()
                } else {
                    None
                };
                drop(guard);
                send_now(probe);
            }
        }
    }
}

/// A wire-format DATA packet (header + payload), for state-machine tests.
#[cfg(test)]
fn build_data_packet(remote_id: u32, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
    let header = Header {
        type_flags: FLAG_DATA,
        data_offset: 0,
        remote_id,
        recv_window: DEFAULT_RWND,
        seq,
        ack,
    };
    let mut packet = Vec::with_capacity(HEADER_SIZE + payload.len());
    packet.extend_from_slice(&header.encode());
    packet.extend_from_slice(payload);
    packet
}

// ── Control packets (ACK, heartbeat) ─────────────────────────────────────────

/// Maximum number of SACK ranges that fit inline on the stack (20 + 8*8 = 84 B).
const INLINE_SACK_RANGES: usize = 8;
const INLINE_CONTROL_CAP: usize = HEADER_SIZE + INLINE_SACK_RANGES * 8;

/// Bytes of a control packet: 20-byte plain ACKs, heartbeats, timewait replies,
/// and SACK ACKs with up to 8 ranges stay inline on the stack without allocating.
enum ControlBytes {
    Inline {
        buf: [u8; INLINE_CONTROL_CAP],
        len: u8,
    },
    Heap(Vec<u8>),
}

impl ControlBytes {
    #[inline]
    fn inline_header(header: [u8; HEADER_SIZE]) -> Self {
        let mut buf = [0u8; INLINE_CONTROL_CAP];
        buf[..HEADER_SIZE].copy_from_slice(&header);
        Self::Inline {
            buf,
            len: HEADER_SIZE as u8,
        }
    }
}

impl AsRef<[u8]> for ControlBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Inline { buf, len } => &buf[..usize::from(*len)],
            Self::Heap(buf) => buf,
        }
    }
}

/// A control packet ready to send: socket, destination, bytes.
type ControlPacket = (Arc<super::udp::Udp>, SocketAddr, ControlBytes);

impl StreamInner {
    /// An ACK for what the stream has received, with SACK blocks for the
    /// out-of-order buffer (C `send_ack`).
    ///
    /// SACK blocks follow the header. C libudx reads them from `data_offset`
    /// bytes when that is set, else from the whole body (it always sends
    /// `data_offset = 0`); we set `data_offset` while it fits in a byte so older
    /// Rust peers keep parsing, and fall back to `0` beyond 31 ranges.
    fn ack_packet(&self) -> Option<ControlPacket> {
        let (udp, addr) = (self.udp.clone()?, self.remote_addr?);
        if self.recv_ranges.is_empty() {
            let header = self.control_header(0);
            return Some((udp, addr, ControlBytes::inline_header(header.encode())));
        }
        let count = self.recv_ranges.len().min(MAX_SACK_RANGES);
        let sack_byte_len = count * 8;
        let mut header = self.control_header(FLAG_SACK);
        header.data_offset = u8::try_from(sack_byte_len).unwrap_or(0);
        if count <= INLINE_SACK_RANGES {
            let mut buf = [0u8; INLINE_CONTROL_CAP];
            header.encode_into(&mut buf[..HEADER_SIZE]);
            for (i, &(start, end)) in self.recv_ranges.iter().take(count).enumerate() {
                let off = HEADER_SIZE + i * 8;
                buf[off..off + 4].copy_from_slice(&start.to_le_bytes());
                buf[off + 4..off + 8].copy_from_slice(&end.to_le_bytes());
            }
            return Some((
                udp,
                addr,
                ControlBytes::Inline {
                    buf,
                    len: (HEADER_SIZE + sack_byte_len) as u8,
                },
            ));
        }
        let sacks = self.sack_ranges();
        let mut packet = vec![0u8; HEADER_SIZE + sack_byte_len];
        header.encode_into(&mut packet[..HEADER_SIZE]);
        encode_sack(&sacks, &mut packet[HEADER_SIZE..]);
        Some((udp, addr, ControlBytes::Heap(packet)))
    }

    /// A heartbeat (C `send_probe`); the peer answers it with an ACK.
    fn heartbeat_packet(&self) -> Option<ControlPacket> {
        let packet = ControlBytes::inline_header(self.control_header(FLAG_HEARTBEAT).encode());
        Some((self.udp.clone()?, self.remote_addr?, packet))
    }
}

/// Send a control packet without waiting: inline when the socket has room
/// (no task or scheduler round trip), else from a task.
fn send_now(packet: Option<ControlPacket>) {
    let Some((udp, addr, packet)) = packet else {
        return;
    };
    if matches!(udp.try_send_to(packet.as_ref(), addr), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    {
        let owned = packet.as_ref().to_vec();
        tokio::spawn(async move {
            let _ = udp.send_to(&owned, addr).await;
        });
    }
}

#[cfg(test)]
mod mtu_tests {
    use super::*;

    fn make_stream_inner() -> StreamInner {
        let (read_tx, _read_rx) = mpsc::unbounded_channel();
        StreamInner::new(0, read_tx, None, None, Registrations::default(), None)
    }

    #[test]
    fn stream_stats_keep_cumulative_retransmits_after_ack() {
        let mut inner = make_stream_inner();
        inner.connected = true;
        inner.update_rtt(25);
        inner.register_sent(0, vec![1; MTU_BASE], "127.0.0.1:9".parse().unwrap(), false);
        for _ in 0..2 {
            inner.on_rto();
            assert_eq!(inner.take_send_batch().0.len(), 1);
        }
        inner.outgoing.clear();
        let handle = UdxStreamAbort::new(Arc::new(Mutex::new(inner)));
        assert_eq!(handle.stats(), (25, 2));
    }

    // The send-order queue must mark exactly what RACK's full scan of `outgoing` marks,
    // across SACKs, cumulative ACKs and fast retransmits (which get a fresh send time).
    // One pacing pass fills the congestion window exactly: packets registered in
    // this pass count once, not again as part of the batch.
    #[test]
    fn send_batch_fills_the_congestion_window_exactly() {
        let mut inner = make_stream_inner();
        let addr = "127.0.0.1:9".parse().unwrap();
        inner.connected = true;
        inner.remote_addr = Some(addr);
        inner.send_rwnd = DEFAULT_RWND;
        inner.mtu_state = MtuState::SearchComplete;
        inner.congestion.cwnd = 10;
        let data = vec![0; 50 * inner.max_payload()];
        inner.push_write(WriteBuf {
            data,
            sent: 0,
            end: false,
            done: None,
        });

        assert_eq!(inner.take_send_batch().0.len(), 10);
        assert_eq!(inner.inflight(), 10);
        assert!(inner.take_send_batch().0.is_empty(), "the window is full");
        // Four ACKed packets free exactly four slots.
        inner.on_cumulative_ack(4);
        inner.congestion.cwnd = 10;
        assert_eq!(inner.take_send_batch().0.len(), 4);
    }

    #[test]
    fn incremental_rack_matches_full_scan() {
        let mut inner = make_stream_inner();
        inner.connected = true;
        inner.congestion.cwnd = 1_000_000;
        let addr = "127.0.0.1:9".parse().unwrap();
        let mut rng = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let (mut next_seq, mut acked) = (0u32, 0u32);
        let mut total_lost = 0;
        let mut now = Instant::now();
        for _ in 0..4000 {
            // A fake clock moving 0-2 ms per step, so the RACK RTT and the
            // reorder window take part.
            now += std::time::Duration::from_millis(next() % 3);
            inner.clock = Some(now);
            match next() % 6 {
                0 | 1 => {
                    inner.register_sent(next_seq, vec![0; 64], addr, false);
                    next_seq += 1;
                    inner.next_seq = next_seq;
                }
                2 if next_seq > acked => {
                    let start = acked + (next() % u64::from(next_seq - acked)) as u32;
                    let end = (start + 1 + (next() % 4) as u32).min(next_seq);
                    inner.on_sack(&[SackRange { start, end }]);
                    // Skipping covered blocks must still leave every sent packet in them SACKed.
                    assert!(inner.outgoing.range(start..end).all(|(_, p)| p.sacked));
                }
                3 if next() % 4 == 0 && next_seq > acked => {
                    acked += 1 + (next() % u64::from(next_seq - acked).min(3)) as u32;
                    inner.on_cumulative_ack(acked);
                }
                4 => {
                    let (rack_time, rack_seq) = match inner.rack {
                        Some(r) => r,
                        None => continue,
                    };
                    let wait = std::time::Duration::from_micros(
                        inner.rack_rtt_us.saturating_add(inner.rack_reo_wnd_us()),
                    );
                    let mut waiting = None;
                    let expected: Vec<u32> = inner
                        .outgoing
                        .iter()
                        .filter(|&(seq, p)| {
                            p.is_inflight()
                                && (p.time_sent < rack_time
                                    || (p.time_sent == rack_time && seq_after(rack_seq, seq)))
                        })
                        .filter(|&(_, p)| {
                            let due = p.time_sent + wait <= now;
                            if !due {
                                let left = p.time_sent + wait - now;
                                waiting = waiting.max(Some(left));
                            }
                            due
                        })
                        .map(|(seq, _)| seq)
                        .collect();
                    let (lost, timeout) = inner.detect_losses(now);
                    assert_eq!(lost as usize, expected.len());
                    assert_eq!(timeout, waiting);
                    assert!(expected.iter().all(|seq| inner.outgoing[seq].lost));
                    total_lost += expected.len();
                }
                5 => {
                    // Fast retransmit resends every packet marked lost, and nothing else.
                    let lost = inner
                        .outgoing
                        .values()
                        .filter(|p| p.lost && !p.sacked)
                        .count();
                    assert_eq!(inner.take_send_batch().0.len(), lost);
                    assert!(inner.outgoing.values().all(|p| !p.lost || p.sacked));
                }
                _ => {}
            }
            assert_eq!(
                inner.inflight(),
                inner.outgoing.values().filter(|p| p.is_inflight()).count() as u32
            );
        }
        assert!(total_lost > 0, "the sequence must exercise loss detection");
    }

    fn fill_packet_buffers(inner: &mut StreamInner) {
        let addr = "127.0.0.1:9".parse().unwrap();
        for seq in 0..1024 {
            inner.register_sent(seq, vec![1; MTU_MAX], addr, false);
            inner.recv_buf.insert(
                seq,
                RecvdPacket {
                    payload: Bytes::from(vec![2; MTU_MAX]),
                    flags: FLAG_DATA,
                },
            );
            inner.push_write(WriteBuf {
                data: vec![3; MTU_MAX],
                sent: 0,
                end: false,
                done: None,
            });
        }
    }

    #[test]
    #[ignore = "terminated-stream memory benchmark"]
    fn terminated_stream_memory_benchmark() {
        let mut retained = Vec::new();
        for _ in 0..2 {
            for _ in 0..8 {
                let mut inner = make_stream_inner();
                fill_packet_buffers(&mut inner);
                inner.terminate();
                retained.push(inner);
            }
        }
        let bytes: usize = retained
            .iter()
            .map(|inner| {
                inner
                    .outgoing
                    .values()
                    .map(|packet| packet.packet.len())
                    .sum::<usize>()
                    + inner
                        .recv_buf
                        .values()
                        .map(|packet| packet.payload.len())
                        .sum::<usize>()
                    + inner
                        .write_queue
                        .iter()
                        .map(|write| write.data.len())
                        .sum::<usize>()
            })
            .sum();
        println!(
            "TERMINATED streams={} retained_payload_bytes={bytes}",
            retained.len()
        );
        std::hint::black_box(&retained);
    }

    #[test]
    fn terminated_stream_releases_packet_buffers() {
        let mut inner = make_stream_inner();
        fill_packet_buffers(&mut inner);
        inner.terminate();
        assert!(inner.write_queue.is_empty());
        assert!(inner.outgoing.is_empty());
        assert!(inner.recv_buf.is_empty());
        assert_eq!(inner.write_queue.capacity(), 0);
        assert_eq!(inner.queued_bytes, 0);
        assert_eq!(inner.unacked_bytes, 0);
        inner.terminate();
    }

    #[test]
    fn receive_events_remain_ordered_across_gaps_and_combined_fin() {
        let mut inner = make_stream_inner();
        let mut events = Vec::new();
        inner.receive_data(1, b"second".to_vec(), FLAG_DATA | FLAG_END, &mut events);
        assert!(events.is_empty());
        inner.receive_data(0, b"first".to_vec(), FLAG_DATA, &mut events);
        assert_eq!(events.len(), 3);
        assert!(matches!(&events[0], StreamEvent::Data(bytes) if bytes.as_ref() == b"first"));
        assert!(matches!(&events[1], StreamEvent::Data(bytes) if bytes.as_ref() == b"second"));
        assert!(matches!(&events[2], StreamEvent::End));
        events.clear();
        inner.receive_data(1, b"duplicate".to_vec(), FLAG_DATA | FLAG_END, &mut events);
        assert!(events.is_empty());
    }

    // T3: MTU state starts at BASE
    #[test]
    fn mtu_initial_state_is_base() {
        let inner = make_stream_inner();
        assert_eq!(inner.mtu_state, MtuState::Base);
        assert_eq!(inner.mtu, MTU_BASE);
        assert!(!inner.mtu_probe_wanted);
        assert_eq!(inner.mtu_probe_count, 0);
        // C starts with a probe at the base size, confirming it.
        assert_eq!(inner.mtu_probe_size, MTU_BASE);
        assert_eq!(inner.mtu_max, MTU_MAX);
    }

    /// A lost probe is sent again without its padding and counts as one
    /// failed probe (C `mtu_unprobeify_packet`).
    #[test]
    fn mtu_probe_failure_fallback() {
        let mut inner = make_stream_inner();
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        inner.connected = true;
        inner.remote_addr = Some(addr);
        inner.mtu_state = MtuState::Search;
        inner.mtu_probe_size = MTU_BASE + MTU_STEP;
        let mut packet = build_data_packet(0, 0, 0, &[0xAB; MAX_PAYLOAD]);
        assert!(inner.mtu_probeify_packet(&mut packet, addr));
        inner.register_sent(0, packet, addr, true);
        // `send_new` counts a probe when it sends it (C udx.c:858).
        inner.mtu_probe_count = 1;
        inner.next_seq = 1;

        inner.on_rto();
        let retransmits = inner.take_send_batch().0;
        assert_eq!(retransmits.len(), 1);
        assert_eq!(retransmits[0].0.len(), MTU_BASE - IPV4_UDP_OVERHEAD);
        assert_eq!(inner.mtu_probe_count, 1);
        assert!(!inner.outgoing[&0].is_mtu_probe);
        assert_eq!(
            inner.outgoing[&0].packet[3], 0,
            "data_offset should be reset"
        );
        assert_eq!(inner.mtu_state, MtuState::Search);
        assert!(inner.mtu_probe_wanted);
    }

    /// MTU values are IP packet sizes as in C: at the base MTU an IPv4
    /// packet carries 1152 payload bytes (UDP datagram 1172), IPv6 1132, and
    /// a probe to 1232 pads that full packet by 32 bytes.
    #[test]
    fn mtu_is_an_ip_packet_size_like_c() {
        let mut inner = make_stream_inner();
        let v4: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let v6: SocketAddr = "[::1]:9".parse().unwrap();
        inner.remote_addr = Some(v4);
        assert_eq!(inner.max_payload(), 1152);
        inner.remote_addr = Some(v6);
        assert_eq!(inner.max_payload(), 1132);
        inner.remote_addr = Some(v4);

        let payload = vec![0xCDu8; inner.max_payload()];
        let mut packet = build_data_packet(0, 0, 0, &payload);
        assert_eq!(packet.len(), 1172);
        // The first probe confirms the base size with no padding.
        assert!(inner.mtu_probeify_packet(&mut packet.clone(), v4));
        inner.mtu_probe_size = MTU_BASE + MTU_STEP;
        assert!(inner.mtu_probeify_packet(&mut packet, v4));
        assert_eq!(packet.len() + IPV4_UDP_OVERHEAD, MTU_BASE + MTU_STEP);
        assert_eq!(packet[3] as usize, MTU_STEP);
        assert_eq!(&packet[HEADER_SIZE + MTU_STEP..], &payload[..]);
        // The search tops out at a 1500-byte IP packet: 1472-byte datagrams.
        inner.mtu = MTU_MAX;
        assert_eq!(inner.max_payload() + HEADER_SIZE, 1472);
    }

    /// `EMSGSIZE` from a GSO send of full packets steps the MTU back to the
    /// probe size below and ends the search.
    #[test]
    fn send_too_big_steps_the_mtu_back() {
        let mut inner = make_stream_inner();
        inner.remote_addr = Some("127.0.0.1:9".parse().unwrap());
        inner.mtu_state = MtuState::Search;
        inner.mtu = 1488;
        inner.on_send_too_big(1488 - IPV4_UDP_OVERHEAD);
        assert_eq!(inner.mtu, 1456);
        assert_eq!(inner.mtu_max, 1456);
        assert_eq!(inner.mtu_state, MtuState::SearchComplete);
        assert!(!inner.mtu_probe_wanted);
        // A refused probe above the MTU only ends the search.
        inner.on_send_too_big(1500);
        assert_eq!(inner.mtu, 1456);
    }

    /// M2: a cumulative ACK beyond what was sent (from anyone who guesses
    /// the stream id) must not clear the send buffer or fake delivery.
    #[test]
    fn ack_beyond_next_seq_is_ignored() {
        let mut inner = make_stream_inner();
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        for seq in 0..4 {
            inner.register_sent(seq, build_data_packet(0, seq, 0, b"x"), addr, false);
        }
        inner.next_seq = 4;
        let (tx, mut ack_rx) = oneshot::channel();
        inner.pending_writes.push(PendingWrite {
            ack_threshold: 4,
            tx: Some(tx),
        });
        let (completed, _) = inner.on_cumulative_ack(inner.next_seq + 1000);
        assert!(completed.is_empty());
        assert_eq!(inner.outgoing.len(), 4);
        assert_eq!(inner.pending_writes.len(), 1);
        assert!(ack_rx.try_recv().is_err());
        assert_eq!(inner.remote_acked, 0);
        // The real ACK still completes the write.
        let (completed, _) = inner.on_cumulative_ack(4);
        assert_eq!(completed.len(), 1);
    }

    /// S3: 100k DATA packets far ahead of the cumulative ACK leave a buffer
    /// bounded by the advertised window, and SACK generation stays cheap.
    #[test]
    fn far_future_data_keeps_the_reorder_buffer_bounded() {
        let mut inner = make_stream_inner();
        let mut events = Vec::new();
        for i in 0..100_000u32 {
            inner.receive_data(2 + i, Vec::new(), FLAG_DATA, &mut events);
            assert!(inner.sack_ranges().len() <= MAX_SACK_RANGES);
        }
        assert!(inner.recv_buf.len() < RECV_WINDOW_PACKETS as usize);
        assert_eq!(inner.recv_ranges, vec![(2, RECV_WINDOW_PACKETS)]);
        assert!(events.is_empty());
        // Filling the gap delivers the whole buffered range in order.
        inner.receive_data(0, Vec::new(), FLAG_DATA, &mut events);
        inner.receive_data(1, Vec::new(), FLAG_DATA, &mut events);
        assert_eq!(inner.next_remote_seq, RECV_WINDOW_PACKETS);
        assert!(inner.recv_buf.is_empty() && inner.recv_ranges.is_empty());
    }

    /// N1: sequence numbers wrap; `u32::MAX` must not overflow in a debug build.
    #[test]
    fn receive_side_handles_sequence_wraparound() {
        let mut inner = make_stream_inner();
        let mut events = Vec::new();
        inner.receive_data(u32::MAX, b"far".to_vec(), FLAG_DATA, &mut events);
        let _ = inner.sack_ranges();
        assert!(inner.recv_buf.is_empty(), "u32::MAX is behind seq 0");

        inner.next_remote_seq = u32::MAX - 1;
        inner.receive_data(1, b"c".to_vec(), FLAG_DATA, &mut events);
        inner.receive_data(u32::MAX, b"b".to_vec(), FLAG_DATA, &mut events);
        assert_eq!(
            inner.sack_ranges(),
            vec![
                SackRange {
                    start: u32::MAX,
                    end: 0
                },
                SackRange { start: 1, end: 2 }
            ]
        );
        inner.receive_data(0, b"x".to_vec(), FLAG_DATA, &mut events);
        assert_eq!(inner.recv_ranges, vec![(u32::MAX, 2)]);
        inner.receive_data(u32::MAX - 1, b"a".to_vec(), FLAG_DATA, &mut events);
        assert_eq!(inner.next_remote_seq, 2);
        let data: Vec<_> = events
            .iter()
            .map(|e| match e {
                StreamEvent::Data(d) => d.to_vec(),
                _ => panic!("data only"),
            })
            .collect();
        assert_eq!(
            data,
            [b"a".to_vec(), b"b".to_vec(), b"x".to_vec(), b"c".to_vec()]
        );
        // Old seqs (before the cumulative ACK) are dropped.
        inner.receive_data(u32::MAX - 5, b"old".to_vec(), FLAG_DATA, &mut events);
        assert!(inner.recv_buf.is_empty());
    }

    /// S2: an RTO with 1 MiB in flight retransmits at most `cwnd` packets in
    /// its first burst, and `cwnd` drops to what is still in flight plus one.
    #[test]
    fn rto_burst_is_bounded_by_cwnd() {
        let mut inner = make_stream_inner();
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        inner.connected = true;
        inner.remote_addr = Some(addr);
        let count = (1 << 20) / MAX_PAYLOAD as u32 + 1;
        for seq in 0..count {
            inner.register_sent(
                seq,
                build_data_packet(0, seq, 0, &[0; MAX_PAYLOAD]),
                addr,
                false,
            );
        }
        inner.next_seq = count;
        inner.congestion.cwnd = count;

        inner.on_rto();
        let cwnd = inner.congestion.cwnd;
        assert_eq!(cwnd, inner.inflight() + 1);
        let burst = inner.take_send_batch();
        assert!(burst.0.len() <= cwnd as usize, "{} > {cwnd}", burst.0.len());
        assert_eq!(burst.1, SendStop::Window);
    }

    /// A SACK block spanning the whole sequence space (one 28-byte packet
    /// from anyone who knows the stream id) must cost work proportional to
    /// the packets in flight, and inverted blocks must be ignored.
    #[test]
    fn sack_ranges_are_bounded_by_outgoing() {
        let mut inner = make_stream_inner();
        for seq in [5u32, 6, 9] {
            inner.register_sent(
                seq,
                build_data_packet(0, seq, 0, b"x"),
                "0.0.0.0:0".parse().unwrap(),
                false,
            );
        }

        let started = Instant::now();
        let sacked = inner.on_sack(&[
            SackRange { start: 9, end: 6 },
            SackRange {
                start: 0,
                end: 0xFFFF_FFFF,
            },
        ]);
        assert!(
            started.elapsed() < std::time::Duration::from_millis(100),
            "SACK walk is not bounded"
        );

        let seqs: Vec<u32> = sacked.iter().map(|d| d.seq).collect();
        assert_eq!(seqs, vec![5, 6, 9]);
        assert!(inner.outgoing.values().all(|p| p.sacked));
        assert_eq!(inner.inflight(), 0);
    }

    // T7: Probe ACK advances MTU and scales congestion window
    #[test]
    fn mtu_probe_ack_advances_mtu() {
        let mut inner = make_stream_inner();
        inner.mtu_state = MtuState::Search;
        inner.mtu = MTU_BASE;
        inner.mtu_probe_size = MTU_BASE + MTU_STEP;

        inner.on_mtu_probe_acked();

        assert_eq!(inner.mtu, MTU_BASE + MTU_STEP);
        assert_eq!(inner.mtu_probe_count, 0);
        assert_eq!(inner.mtu_probe_size, MTU_BASE + 2 * MTU_STEP);
        assert!(inner.mtu_probe_wanted, "should want next probe");
        assert_eq!(
            inner.mtu_state,
            MtuState::Search,
            "still searching — haven't reached max"
        );
    }

    // T8: MTU_MAX_PROBES consecutive failures → SearchComplete
    #[test]
    fn mtu_max_probe_failures_completes_search() {
        let mut inner = make_stream_inner();
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        inner.mtu_state = MtuState::Search;
        inner.mtu = MTU_BASE + MTU_STEP;

        for i in 0..MTU_MAX_PROBES {
            let packet = build_data_packet(0, i, 0, &[0xEF; MAX_PAYLOAD]);
            inner.mtu_probe_count += 1;
            inner.register_sent(i, packet, addr, true);
            inner.next_seq = i + 1;
            inner.on_rto();
        }

        assert_eq!(inner.mtu_state, MtuState::SearchComplete);
        assert!(!inner.mtu_probe_wanted);
        assert_eq!(
            inner.mtu,
            MTU_BASE + MTU_STEP,
            "MTU frozen at last successful value"
        );
    }

    // Catches headers that keep advertising the maximum while the reader falls
    // behind, or one that counts a taken byte twice.
    #[test]
    fn window_in_headers_follows_what_the_reader_has_not_taken() {
        let mut inner = make_stream_inner();
        let mut events = Vec::new();
        for seq in 0..3 {
            inner.receive_data(seq, vec![0u8; 1000], FLAG_DATA, &mut events);
        }
        // 3,000 held in order: 4,194,304 - 3,000 = 4,191,304.
        assert_eq!(inner.control_header(0).recv_window, DEFAULT_RWND - 3000);
        // The reader took 1,000: 2,000 held, 4,194,304 - 2,000 = 4,192,304.
        // The meter's 4,194,304-byte target is never reached, so the limit
        // stays at the starting window.
        let mut meter = ReadMeter::new();
        let _ = inner.receive_window.taken(1000, &mut meter);
        assert_eq!(inner.control_header(0).recv_window, DEFAULT_RWND - 2000);
        // 500 held out of order: 2,500 held, 4,194,304 - 2,500 = 4,191,804.
        inner.receive_data(5, vec![0u8; 500], FLAG_DATA, &mut events);
        assert_eq!(inner.control_header(0).recv_window, DEFAULT_RWND - 2500);
    }

    // Catches a receiver that refuses in-order data at the window itself (the
    // one tail-loss probe a correct sender may send would be lost), or one
    // that keeps accepting without bound.
    #[test]
    fn in_order_data_is_refused_at_twice_the_window() {
        let mut inner = make_stream_inner();
        let mut events = Vec::new();
        // 8,389 packets x 1,000 bytes, seq 0..=8388. Before the last one the
        // receiver holds 8,388 x 1,000 = 8,388,000, below 8,388,608.
        for seq in 0..8389 {
            inner.receive_data(seq, vec![0u8; 1000], FLAG_DATA, &mut events);
        }
        assert_eq!(inner.next_remote_seq, 8389);
        let events_before = events.len();
        // 8,389,000 held is past 8,388,608 (twice 4,194,304): refused, so no
        // event and no move of the cumulative ACK.
        inner.receive_data(8389, vec![0u8; 1000], FLAG_DATA, &mut events);
        assert_eq!(inner.next_remote_seq, 8389);
        assert_eq!(events.len(), events_before);
        // Held is past the maximum: 4,194,304 - min(4,194,304, 8,389,000) = 0.
        assert_eq!(inner.control_header(0).recv_window, 0);
        // An empty END needs no room; refusing it would lose the close.
        inner.receive_data(8389, Vec::new(), FLAG_END, &mut events);
        assert!(inner.remote_ended);
    }

    // Catches an out-of-order buffer that grows past the window the peer was
    // told about, and a drain that leaves the counters stale.
    #[test]
    fn out_of_order_bytes_stop_at_the_window() {
        let mut inner = make_stream_inner();
        let mut events = Vec::new();
        // Seq 0 missing. 69 packets x 60,000 = 4,140,000 fits in 4,194,304;
        // the 70th would make 4,200,000 and is refused.
        for seq in 1..=70 {
            inner.receive_data(seq, vec![0u8; 60_000], FLAG_DATA, &mut events);
        }
        assert_eq!(inner.recv_buf.len(), 69);
        assert!(!inner.recv_buf.contains_key(&70));
        assert_eq!(inner.sack_ranges(), vec![SackRange { start: 1, end: 70 }]);
        assert_eq!(inner.receive_window.out_of_order_bytes(), 4_140_000);
        // Seq 0 (60,000) drains the 69 buffered packets: 70 x 60,000 =
        // 4,200,000 unread in order, nothing out of order.
        inner.receive_data(0, vec![0u8; 60_000], FLAG_DATA, &mut events);
        assert_eq!(inner.next_remote_seq, 70);
        assert!(inner.recv_buf.is_empty());
        assert_eq!(inner.receive_window.out_of_order_bytes(), 0);
        assert_eq!(inner.receive_window.unread_bytes(), 4_200_000);
        // 4,194,304 - min(4,194,304, 4,200,000) = 0.
        assert_eq!(inner.control_header(0).recv_window, 0);
    }

    // Catches an out-of-order count that leaks bytes on a duplicate packet or
    // when the buffer is drained or cleared after the peer's END.
    #[test]
    fn out_of_order_count_matches_the_buffer() {
        let mut inner = make_stream_inner();
        let mut events = Vec::new();
        inner.receive_data(3, vec![0u8; 700], FLAG_DATA, &mut events);
        inner.receive_data(5, vec![0u8; 300], FLAG_DATA, &mut events);
        // A duplicate seq 3 is ignored before it is counted.
        inner.receive_data(3, vec![0u8; 700], FLAG_DATA, &mut events);
        // 700 + 300 = 1,000 held out of order, equal to the buffered payloads.
        assert_eq!(inner.receive_window.out_of_order_bytes(), 1000);
        assert_eq!(
            inner.receive_window.out_of_order_bytes(),
            inner
                .recv_buf
                .values()
                .map(|packet| packet.payload.len())
                .sum::<usize>()
        );
        for seq in 0..3 {
            inner.receive_data(seq, vec![0u8; 100], FLAG_DATA, &mut events);
        }
        // Seq 3 (700 bytes) was drained; seq 5 (300 bytes) is still buffered.
        assert_eq!(inner.receive_window.out_of_order_bytes(), 300);
        // Seq 4 carries the END: the drain delivers seq 5 and clears the rest.
        inner.receive_data(4, vec![0u8; 100], FLAG_DATA | FLAG_END, &mut events);
        assert!(inner.remote_ended);
        assert!(inner.recv_buf.is_empty());
        assert_eq!(inner.receive_window.out_of_order_bytes(), 0);
    }
}

#[cfg(test)]
mod abort_tests {
    use super::*;
    use std::time::Duration;

    /// Bind a runtime socket and a raw UDP peer; connect stream 5 to it.
    async fn raw_peer_stream() -> (
        crate::UdxRuntime,
        crate::UdxSocket,
        UdxStream,
        tokio::net::UdpSocket,
    ) {
        let runtime = crate::UdxRuntime::new().unwrap();
        let socket = runtime.create_socket().await.unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stream = runtime.create_stream(5).await.unwrap();
        stream
            .connect(&socket, 6, peer.local_addr().unwrap())
            .await
            .unwrap();
        (runtime, socket, stream, peer)
    }

    /// Next packet the raw peer receives within `wait`, as (header, from).
    async fn recv_header(
        peer: &tokio::net::UdpSocket,
        wait: Duration,
    ) -> Option<(Header, SocketAddr)> {
        let mut buf = [0u8; 2048];
        let (len, from) = tokio::time::timeout(wait, peer.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        Some((Header::decode(&buf[..len]).ok()?, from))
    }

    fn ack(ack: u32, recv_window: u32) -> [u8; HEADER_SIZE] {
        Header {
            type_flags: 0,
            data_offset: 0,
            remote_id: 5,
            recv_window,
            seq: 0,
            ack,
        }
        .encode()
    }

    /// S1: a peer advertising a zero window must not make the send loop poll
    /// (C probes it at the RTO instead), and a dropped stream stuck behind
    /// the zero window ends after the RTO budget of probes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_window_does_not_spin_and_dropped_stream_ends() {
        use tokio::io::AsyncWriteExt;
        let (_runtime, _socket, stream, peer) = raw_peer_stream().await;
        let inner = Arc::clone(&stream.inner);
        let abort = stream.abort_handle();
        let mut stream = stream.into_async_stream();
        // More than the initial window, so data stays queued.
        stream.write_all(&[7u8; 64 * 1024]).await.unwrap();
        let mut next = 0;
        let mut from = None;
        while let Some((header, addr)) = recv_header(&peer, Duration::from_millis(200)).await {
            next = next.max(header.seq + 1);
            from = Some(addr);
        }
        assert!(next > 0, "the first window was sent");
        peer.send_to(&ack(next, 0), from.unwrap()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let before = inner.lock().unwrap().pacing_wakeups;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let wakeups = inner.lock().unwrap().pacing_wakeups - before;
        assert!(wakeups <= 5, "{wakeups} send-loop wakeups in 500 ms");
        assert!(abort.is_alive());

        inner.lock().unwrap().rto = 20;
        drop(stream);
        for _ in 0..150 {
            if !abort.is_alive() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("dropped stream behind a zero window never ended");
    }

    /// RACK §7 tail loss probe: a lost last packet is sent again after about
    /// two RTTs, not after the 1 s RTO.
    #[tokio::test]
    async fn tail_loss_probe_resends_the_last_packet_before_the_rto() {
        use tokio::io::AsyncWriteExt;
        let (_runtime, _socket, stream, peer) = raw_peer_stream().await;
        let mut stream = stream.into_async_stream();
        stream.write_all(b"one").await.unwrap();
        let (first, from) = recv_header(&peer, Duration::from_secs(1)).await.unwrap();
        peer.send_to(&ack(first.seq + 1, DEFAULT_RWND), from)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        stream.write_all(b"two").await.unwrap();
        let (lost, _) = recv_header(&peer, Duration::from_secs(1)).await.unwrap();
        let (probe, _) = recv_header(&peer, Duration::from_millis(500))
            .await
            .expect("no loss probe before the RTO");
        assert_eq!(probe.seq, lost.seq);
        assert!(probe.has_flag(FLAG_DATA));
    }

    /// S5: with keepalive on, the stream sends heartbeats and ends with a
    /// timeout once the peer stays silent for six intervals.
    #[tokio::test]
    async fn keepalive_ends_a_stream_whose_peer_is_silent() {
        let (_runtime, _socket, mut stream, peer) = raw_peer_stream().await;
        stream.set_keepalive(Some(Duration::from_millis(30)));
        let (heartbeat, _) = recv_header(&peer, Duration::from_millis(500))
            .await
            .unwrap();
        assert!(heartbeat.has_flag(FLAG_HEARTBEAT));
        let err = tokio::time::timeout(Duration::from_secs(2), stream.read())
            .await
            .expect("silent peer was never detected")
            .expect_err("a dead peer is an error, not EOF");
        assert!(matches!(err, UdxError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut));
    }

    /// A stream keeps receiving on the socket it moved to after the caller
    /// drops its own handle of that socket (hyperdht drops the holepunch
    /// socket handle once the relay-to-direct upgrade is done). C streams
    /// hold their `udx_socket_t`.
    #[tokio::test]
    async fn stream_keeps_its_socket_open_after_change_remote() {
        let (runtime, _socket, mut stream, peer) = raw_peer_stream().await;
        let direct = runtime.create_socket().await.unwrap();
        direct.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let direct_addr = direct.local_addr().await.unwrap();
        stream
            .remote_handle()
            .change_remote(&direct, 6, peer.local_addr().unwrap())
            .await
            .unwrap();
        drop(direct);
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mut bytes = Header {
            type_flags: FLAG_DATA,
            data_offset: 0,
            remote_id: 5,
            recv_window: DEFAULT_RWND,
            seq: 0,
            ack: 0,
        }
        .encode()
        .to_vec();
        bytes.extend_from_slice(b"direct");
        peer.send_to(&bytes, direct_addr).await.unwrap();
        let data = tokio::time::timeout(Duration::from_secs(1), stream.read())
            .await
            .expect("the moved stream stopped receiving")
            .unwrap();
        assert_eq!(data.as_deref(), Some(&b"direct"[..]));
    }

    #[tokio::test]
    async fn closed_id_can_be_reused_before_old_handles_and_processor_are_dropped() {
        let runtime = crate::UdxRuntime::new().unwrap();
        let socket = runtime.create_socket().await.unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old = runtime.create_stream(77).await.unwrap();
        old.connect(&socket, 42, peer.local_addr().unwrap())
            .await
            .unwrap();
        let old_abort = old.abort_handle();
        old_abort.abort();
        assert!(matches!(
            old.connect(&socket, 42, peer.local_addr().unwrap()).await,
            Err(UdxError::StreamClosed)
        ));
        let mut fresh = runtime.create_stream(77).await.unwrap();
        fresh
            .connect(&socket, 42, peer.local_addr().unwrap())
            .await
            .unwrap();
        drop(old);
        let mut bytes = Header {
            type_flags: FLAG_DATA,
            data_offset: 0,
            remote_id: 77,
            recv_window: 65536,
            seq: 0,
            ack: 0,
        }
        .encode()
        .to_vec();
        bytes.extend_from_slice(b"fresh");
        peer.send_to(&bytes, socket.local_addr().await.unwrap())
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), fresh.read())
                .await
                .unwrap()
                .unwrap()
                .as_deref(),
            Some(&b"fresh"[..])
        );
        assert!(!old_abort.is_alive());
    }

    #[tokio::test]
    async fn destroying_relay_legs_does_not_send_destroy_to_upgraded_peers() {
        let runtime = crate::UdxRuntime::new().unwrap();
        let socket = runtime.create_socket().await.unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for id in [10, 20] {
            let leg = runtime.create_stream(id).await.unwrap();
            let other = runtime.create_stream(id + 1).await.unwrap();
            leg.connect(&socket, 42, peer.local_addr().unwrap())
                .await
                .unwrap();
            leg.relay_to(&other).unwrap();
            if id == 10 {
                leg.abort_handle().abort();
            } else {
                leg.destroy().await.unwrap();
            }
            let mut bytes = [0; 20];
            assert!(
                tokio::time::timeout(Duration::from_millis(30), peer.recv_from(&mut bytes))
                    .await
                    .is_err(),
                "C libudx closes relayed streams without a DESTROY packet"
            );
        }
    }

    /// `abort` must stop the processor task, not just disconnect the stream:
    /// the task owns a clone of `StreamInner`, so a task that keeps running
    /// (ticking its keepalive) pins the stream for the life of the process.
    #[tokio::test]
    async fn abort_ends_the_processor_task() {
        let runtime = crate::UdxRuntime::new().expect("runtime");
        let socket = runtime.create_socket().await.expect("socket");
        socket
            .bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind");
        let peer = runtime.create_socket().await.expect("peer socket");
        peer.bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("peer bind");
        let peer_addr = peer.local_addr().await.expect("peer addr");

        let stream = runtime.create_stream(1).await.expect("stream");
        stream
            .connect(&socket, 2, peer_addr)
            .await
            .expect("connect");

        let weak = Arc::downgrade(&stream.inner);
        let abort = stream.abort_handle();
        abort.abort();
        assert!(!abort.is_alive(), "aborted stream reports itself dead");
        drop(abort);
        // The async stream detaches the task instead of aborting it, which is
        // how the swarm drops a suspended connection.
        drop(stream.into_async_stream());

        for _ in 0..50 {
            if weak.upgrade().is_none() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("processor task still holds the stream one second after abort");
    }

    #[tokio::test]
    async fn close_subscription_before_and_after_abort() {
        let runtime = crate::UdxRuntime::new().expect("runtime");
        let stream = runtime.create_stream(10).await.expect("stream");
        let abort = stream.abort_handle();

        // 1. Observer subscribed BEFORE abort
        let abort_before = abort.clone();
        let before_task = tokio::spawn(async move {
            abort_before.closed().await;
        });

        tokio::task::yield_now().await;

        // Abort the stream
        abort.abort();

        // Observer subscribed before abort must resolve
        tokio::time::timeout(Duration::from_secs(1), before_task)
            .await
            .expect("before task must complete within timeout")
            .expect("before task must not panic");

        // 2. Observer subscribed AFTER abort must resolve immediately
        let abort_after = abort.clone();
        tokio::time::timeout(Duration::from_millis(50), abort_after.closed())
            .await
            .expect("after abort closed() must resolve immediately");
    }

    #[tokio::test]
    async fn multiple_concurrent_observers_all_notified_on_close() {
        let runtime = crate::UdxRuntime::new().expect("runtime");
        let stream = runtime.create_stream(20).await.expect("stream");
        let abort = stream.abort_handle();

        const NUM_OBSERVERS: usize = 5;
        let mut handles = Vec::new();

        for _ in 0..NUM_OBSERVERS {
            let abort_clone = abort.clone();
            handles.push(tokio::spawn(async move {
                abort_clone.closed().await;
            }));
        }

        tokio::task::yield_now().await;

        // Abort stream
        abort.abort();

        // All observers must resolve
        for handle in handles {
            tokio::time::timeout(Duration::from_secs(1), handle)
                .await
                .expect("observer must complete within timeout")
                .expect("observer task must not panic");
        }
    }

    #[tokio::test]
    async fn multiple_observers_notified_on_destroy() {
        let runtime = crate::UdxRuntime::new().expect("runtime");
        let stream = runtime.create_stream(30).await.expect("stream");
        let abort = stream.abort_handle();

        const NUM_OBSERVERS: usize = 3;
        let mut handles = Vec::new();

        for _ in 0..NUM_OBSERVERS {
            let abort_clone = abort.clone();
            handles.push(tokio::spawn(async move {
                abort_clone.closed().await;
            }));
        }

        tokio::task::yield_now().await;

        // Destroy stream directly
        stream.destroy().await.expect("destroy");

        for handle in handles {
            tokio::time::timeout(Duration::from_secs(1), handle)
                .await
                .expect("observer must complete within timeout")
                .expect("observer task must not panic");
        }
    }

    /// RACK reorder timer (C `udx_rack_reo_timeout`): a hole the peer SACKs
    /// around is resent when the reorder window ends, with no further ACK
    /// and long before the 1 s RTO. Seq 0 gives a 20 ms RTT sample, so the
    /// window is open (min RTT / 4 = 5 ms).
    #[tokio::test]
    async fn reorder_timer_resends_a_hole_without_another_ack() {
        use tokio::io::AsyncWriteExt;
        let (_runtime, _socket, stream, peer) = raw_peer_stream().await;
        let mut stream = stream.into_async_stream();
        stream.write_all(b"a").await.unwrap();
        let (first, from) = recv_header(&peer, Duration::from_secs(1)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        peer.send_to(&ack(first.seq + 1, DEFAULT_RWND), from)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        stream.write_all(&[1u8; 3 * MAX_PAYLOAD]).await.unwrap();
        let mut seqs = Vec::new();
        while seqs.len() < 3 {
            let (header, _) = recv_header(&peer, Duration::from_secs(1)).await.unwrap();
            seqs.push(header.seq);
        }
        let hole = seqs[0];
        tokio::time::sleep(Duration::from_millis(20)).await;
        // The peer got all but the first: ack it, SACK the other two.
        let mut sack = Header {
            type_flags: FLAG_SACK,
            data_offset: 8,
            remote_id: 5,
            recv_window: DEFAULT_RWND,
            seq: 0,
            ack: hole,
        }
        .encode()
        .to_vec();
        sack.resize(HEADER_SIZE + 8, 0);
        encode_sack(
            &[SackRange {
                start: hole + 1,
                end: hole + 3,
            }],
            &mut sack[HEADER_SIZE..],
        );
        peer.send_to(&sack, from).await.unwrap();

        let (resent, _) = recv_header(&peer, Duration::from_millis(500))
            .await
            .expect("the hole was not resent before the RTO");
        assert!(resent.has_flag(FLAG_DATA));
        assert_eq!(resent.seq, hole);
    }

    /// A DATA packet with SACK bytes in front of its payload (data_offset > 0)
    /// and one with data_offset 0 must each deliver exactly their payload.
    /// Wrong body arithmetic after the header left the buffer would leak the
    /// SACK bytes into the payload or cut its first `data_offset` bytes.
    #[tokio::test]
    async fn data_payload_starts_after_data_offset_in_the_body() {
        let (_runtime, socket, mut stream, peer) = raw_peer_stream().await;
        let to = socket.local_addr().await.unwrap();
        let packet = |seq: u32, type_flags: u8, data_offset: u8, prefix: &[u8], payload: &[u8]| {
            let mut bytes = Header {
                type_flags,
                data_offset,
                remote_id: 5,
                recv_window: DEFAULT_RWND,
                seq,
                ack: 0,
            }
            .encode()
            .to_vec();
            bytes.extend_from_slice(prefix);
            bytes.extend_from_slice(payload);
            bytes
        };
        // Seq 0 carries a SACK block before its payload.
        peer.send_to(&packet(0, FLAG_DATA | FLAG_SACK, 8, &[0; 8], b"alpha"), to)
            .await
            .unwrap();
        // Seq 1 has nothing in front of its payload.
        peer.send_to(&packet(1, FLAG_DATA, 0, &[], b"beta"), to)
            .await
            .unwrap();

        let read = tokio::time::timeout(Duration::from_secs(1), stream.read())
            .await
            .expect("seq 0 was not delivered")
            .expect("read error");
        assert_eq!(read.as_deref(), Some(&b"alpha"[..]));
        let read = tokio::time::timeout(Duration::from_secs(1), stream.read())
            .await
            .expect("seq 1 was not delivered")
            .expect("read error");
        assert_eq!(read.as_deref(), Some(&b"beta"[..]));
    }

    /// A MESSAGE packet whose data_offset runs past its body must be dropped:
    /// delivering it, or cutting the payload of a correct one, is the wrong
    /// behaviour this catches. The correct MESSAGE after it arrives whole.
    #[tokio::test]
    async fn message_with_data_offset_past_body_is_dropped() {
        let (_runtime, socket, stream, peer) = raw_peer_stream().await;
        let to = socket.local_addr().await.unwrap();
        let remote = stream.remote_handle();
        let message = |data_offset: u8, body: &[u8]| {
            let mut packet = Header {
                type_flags: FLAG_MESSAGE,
                data_offset,
                remote_id: 5,
                recv_window: DEFAULT_RWND,
                seq: 0,
                ack: 0,
            }
            .encode()
            .to_vec();
            packet.extend_from_slice(body);
            packet
        };
        // data_offset 10 with a 5-byte body runs past the packet.
        peer.send_to(&message(10, b"short"), to).await.unwrap();
        peer.send_to(&message(3, b"...whole"), to).await.unwrap();
        let first = tokio::time::timeout(Duration::from_secs(1), remote.recv_message())
            .await
            .expect("no message")
            .expect("message error");
        assert_eq!(first, b"whole");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), remote.recv_message())
                .await
                .is_err(),
            "the over-long MESSAGE was delivered"
        );
    }

    /// C `send_ack` sends SACK blocks with data_offset = 0. An ACK in that
    /// form must still mark the ranges: shifting the SACK region into the body
    /// must not read the header bytes or miss the block.
    #[tokio::test]
    async fn ack_with_sack_ranges_and_zero_data_offset_marks_them() {
        use tokio::io::AsyncWriteExt;
        let (_runtime, _socket, stream, peer) = raw_peer_stream().await;
        let inner = Arc::clone(&stream.inner);
        let mut stream = stream.into_async_stream();
        stream.write_all(&[7u8; 2 * MAX_PAYLOAD]).await.unwrap();
        let mut from = None;
        for _ in 0..2 {
            let (header, addr) = recv_header(&peer, Duration::from_secs(1))
                .await
                .expect("two DATA packets");
            assert!(header.has_flag(FLAG_DATA));
            from = Some(addr);
        }
        let mut sack = Header {
            type_flags: FLAG_SACK,
            data_offset: 0,
            remote_id: 5,
            recv_window: DEFAULT_RWND,
            seq: 0,
            ack: 0,
        }
        .encode()
        .to_vec();
        sack.resize(HEADER_SIZE + 16, 0);
        encode_sack(
            &[
                SackRange { start: 0, end: 1 },
                SackRange { start: 1, end: 2 },
            ],
            &mut sack[HEADER_SIZE..],
        );
        peer.send_to(&sack, from.unwrap()).await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let sacked = {
                    let inner = inner.lock().unwrap_or_else(|e| e.into_inner());
                    (0u32..2).all(|seq| inner.outgoing.get(&seq).is_some_and(|pkt| pkt.sacked))
                };
                if sacked {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("SACK ranges with data_offset 0 did not mark the packets");
    }

    /// C `process_packet` hands a MESSAGE payload to `on_recv`
    /// (udx.c:1699-1707): `recv_message` returns it, after skipping
    /// `data_offset` bytes, and ends with `StreamClosed` after the stream.
    #[tokio::test]
    async fn message_payloads_reach_recv_message() {
        let (_runtime, socket, stream, peer) = raw_peer_stream().await;
        let to = socket.local_addr().await.unwrap();
        let remote = stream.remote_handle();
        let message = |data_offset: u8, body: &[u8]| {
            let mut packet = Header {
                type_flags: FLAG_MESSAGE,
                data_offset,
                remote_id: 5,
                recv_window: DEFAULT_RWND,
                seq: 0,
                ack: 0,
            }
            .encode()
            .to_vec();
            packet.extend_from_slice(body);
            packet
        };
        peer.send_to(&message(0, b"hello"), to).await.unwrap();
        peer.send_to(&message(2, b"..world"), to).await.unwrap();
        let next = || async {
            tokio::time::timeout(Duration::from_secs(1), remote.recv_message())
                .await
                .expect("no message")
        };
        assert_eq!(next().await.unwrap(), b"hello");
        assert_eq!(next().await.unwrap(), b"world");
        stream.abort_handle().abort();
        assert!(matches!(next().await, Err(UdxError::StreamClosed)));
    }

    fn packet(type_flags: u8, seq: u32, ack: u32) -> [u8; HEADER_SIZE] {
        Header {
            type_flags,
            data_offset: 0,
            remote_id: 5,
            recv_window: DEFAULT_RWND,
            seq,
            ack,
        }
        .encode()
    }

    fn entry(socket: &crate::UdxSocket) -> Option<&'static str> {
        match socket.streams_ref().lock().unwrap().get(&5) {
            Some(StreamEntry::Stream(_)) => Some("stream"),
            Some(StreamEntry::Timewait(_)) => Some("timewait"),
            None => None,
        }
    }

    /// Our stream (5) ends first, the raw peer ACKs the END, then ends too.
    async fn end_first(stream: &mut UdxStream, peer: &tokio::net::UdpSocket, to: SocketAddr) {
        let peer_side = async {
            let (end, _) = recv_header(peer, Duration::from_secs(1)).await.unwrap();
            assert!(end.has_flag(FLAG_END) && end.seq == 0);
            peer.send_to(&packet(0, 0, 1), to).await.unwrap();
        };
        let (ended, ()) = tokio::join!(stream.shutdown(), peer_side);
        ended.unwrap();
        // C `send_ack` once the peer ACKed our END (udx.c:1810).
        let (state, _) = recv_header(peer, Duration::from_millis(500)).await.unwrap();
        assert_eq!((state.type_flags, state.seq, state.ack), (0, 1, 0));
        assert!(
            stream.abort_handle().is_alive(),
            "the peer has not ended yet"
        );
        peer.send_to(&packet(FLAG_END, 0, 1), to).await.unwrap();
        let (final_ack, _) = recv_header(peer, Duration::from_millis(500)).await.unwrap();
        assert_eq!(
            (final_ack.type_flags, final_ack.seq, final_ack.ack),
            (0, 1, 1)
        );
    }

    /// C `close_stream` on `UDX_STREAM_ALL_ENDED` and `stream_timewait`: the
    /// side that ended first closes by itself once both ends are ACKed; for
    /// `TIMEWAIT` its id answers a late DATA or END with the final ACK
    /// (`process_timewait`), ignores anything else, and reaches nothing.
    #[tokio::test]
    async fn stream_that_ends_first_closes_and_answers_from_timewait() {
        let (_runtime, socket, mut stream, peer) = raw_peer_stream().await;
        let to = socket.local_addr().await.unwrap();
        let abort = stream.abort_handle();
        end_first(&mut stream, &peer, to).await;

        tokio::time::timeout(Duration::from_secs(1), abort.closed())
            .await
            .expect("a stream with both ends done closes without its owner");
        assert!(!abort.is_alive());
        assert!(matches!(stream.read().await, Ok(None)));
        assert_eq!(entry(&socket), Some("timewait"));

        // The peer missed our final ACK and sends its END again.
        peer.send_to(&packet(FLAG_END, 0, 1), to).await.unwrap();
        let (answer, _) = recv_header(&peer, Duration::from_millis(500))
            .await
            .expect("timewait answers a late END");
        assert_eq!((answer.type_flags, answer.seq, answer.ack), (0, 1, 1));
        assert_eq!(answer.remote_id, 6);
        peer.send_to(&packet(FLAG_DATA, 0, 1), to).await.unwrap();
        assert!(
            recv_header(&peer, Duration::from_millis(500))
                .await
                .is_some()
        );
        peer.send_to(&packet(FLAG_HEARTBEAT, 1, 1), to)
            .await
            .unwrap();
        assert!(
            recv_header(&peer, Duration::from_millis(200))
                .await
                .is_none()
        );
        // A DESTROY for an id in timewait is ignored (C `process_timewait`).
        peer.send_to(&packet(FLAG_DESTROY, 1, 1), to).await.unwrap();
        assert!(
            recv_header(&peer, Duration::from_millis(200))
                .await
                .is_none()
        );
        assert!(!abort.is_alive());
        assert_eq!(entry(&socket), Some("timewait"));

        tokio::time::sleep(TIMEWAIT).await;
        assert_eq!(entry(&socket), None, "timewait ends after {TIMEWAIT:?}");
        peer.send_to(&packet(FLAG_END, 0, 1), to).await.unwrap();
        assert!(
            recv_header(&peer, Duration::from_millis(300))
                .await
                .is_none()
        );
    }

    /// The side that ended second closes as soon as its END is ACKed, sends
    /// nothing more and leaves no timewait (C udx.c:1803, 2848).
    #[tokio::test]
    async fn stream_that_ends_second_closes_without_timewait() {
        let (_runtime, socket, mut stream, peer) = raw_peer_stream().await;
        let to = socket.local_addr().await.unwrap();
        let abort = stream.abort_handle();
        peer.send_to(&packet(FLAG_END, 0, 0), to).await.unwrap();
        let (ack, _) = recv_header(&peer, Duration::from_millis(500))
            .await
            .unwrap();
        assert_eq!(ack.ack, 1);
        assert!(matches!(stream.read().await, Ok(None)));

        let peer_side = async {
            let (end, _) = recv_header(&peer, Duration::from_secs(1)).await.unwrap();
            assert!(end.has_flag(FLAG_END) && end.seq == 0);
            peer.send_to(&packet(0, 1, 1), to).await.unwrap();
        };
        let (ended, ()) = tokio::join!(stream.shutdown(), peer_side);
        ended.unwrap();
        tokio::time::timeout(Duration::from_secs(1), abort.closed())
            .await
            .expect("closes once its END is ACKed");
        assert!(
            recv_header(&peer, Duration::from_millis(200))
                .await
                .is_none()
        );
        assert_eq!(entry(&socket), None);
        peer.send_to(&packet(FLAG_END, 0, 1), to).await.unwrap();
        assert!(
            recv_header(&peer, Duration::from_millis(200))
                .await
                .is_none()
        );
    }

    /// C `process_timewait` answers from the stream's socket at close
    /// (`timewait->socket`) to its last remote (`timewait->remote_addr`),
    /// whichever socket and source the late packet came on. After a
    /// `change_remote` to a second socket, a late END on the old socket is
    /// answered from the new socket to the new remote, and the old source
    /// hears nothing.
    #[tokio::test]
    async fn timewait_answers_from_the_stream_socket_to_its_last_remote() {
        let (runtime, old_socket, mut stream, old_peer) = raw_peer_stream().await;
        let new_socket = runtime.create_socket().await.unwrap();
        new_socket
            .bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let old_to = old_socket.local_addr().await.unwrap();
        let new_to = new_socket.local_addr().await.unwrap();
        let new_peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        stream
            .remote_handle()
            .change_remote(&new_socket, 6, new_peer.local_addr().unwrap())
            .await
            .unwrap();
        end_first(&mut stream, &new_peer, new_to).await;
        tokio::time::timeout(Duration::from_secs(1), stream.abort_handle().closed())
            .await
            .unwrap();

        old_peer
            .send_to(&packet(FLAG_END, 0, 1), old_to)
            .await
            .unwrap();
        let (answer, from) = recv_header(&new_peer, Duration::from_millis(500))
            .await
            .expect("answered to the last remote");
        assert_eq!((answer.seq, answer.ack), (1, 1));
        assert_eq!(from.port(), new_to.port(), "from the stream's socket");
        assert!(
            recv_header(&old_peer, Duration::from_millis(200))
                .await
                .is_none()
        );

        new_peer
            .send_to(&packet(FLAG_END, 0, 1), new_to)
            .await
            .unwrap();
        let (_, from) = recv_header(&new_peer, Duration::from_millis(500))
            .await
            .expect("answered on the new socket");
        assert_eq!(from.port(), new_to.port());
    }

    /// C `_udx_stream_write` (udx.c:2805): a write landing on an idle stream
    /// behind a zero window sends a zero-window probe at once, not after
    /// one RTO (1 s here).
    #[tokio::test]
    async fn write_behind_a_zero_window_probes_at_once() {
        let (_runtime, socket, stream, peer) = raw_peer_stream().await;
        let to = socket.local_addr().await.unwrap();
        let peer_side = async {
            let (data, _) = recv_header(&peer, Duration::from_secs(1)).await.unwrap();
            peer.send_to(&ack(data.seq + 1, 0), to).await.unwrap();
        };
        let (written, ()) = tokio::join!(stream.write(b"one"), peer_side);
        written.unwrap();
        let start = tokio::time::Instant::now();
        let probe = async {
            loop {
                let (header, _) = recv_header(&peer, Duration::from_millis(300))
                    .await
                    .expect("zero-window probe within 300 ms");
                if header.has_flag(FLAG_HEARTBEAT) {
                    return start.elapsed();
                }
            }
        };
        let (_, waited) = tokio::join!(
            tokio::time::timeout(Duration::from_millis(400), stream.write(b"two")),
            probe
        );
        assert!(
            waited < Duration::from_millis(300),
            "probe after {waited:?}"
        );
    }

    /// A `UdxStream::write` future dropped after its first poll has queued
    /// the data: every byte still goes out.
    #[tokio::test]
    async fn dropped_write_future_loses_no_bytes() {
        let (_runtime, socket, stream, peer) = raw_peer_stream().await;
        let to = socket.local_addr().await.unwrap();
        let data = pattern(3_000);
        let _ = tokio::time::timeout(Duration::from_millis(1), stream.write(&data)).await;
        let mut received = Vec::new();
        let mut next = 0;
        while received.len() < data.len() {
            let (header, _, payload) = recv_data(&peer, Duration::from_secs(2))
                .await
                .expect("the dropped write's data");
            if header.seq == next {
                next += 1;
                received.extend_from_slice(&payload);
            }
            peer.send_to(&packet(0, 0, next), to).await.unwrap();
        }
        assert_eq!(received, data);
    }

    /// Keepalive keeps running on a half-closed stream (our END ACKed, the
    /// peer's not yet sent), as C keeps its keepalive timer.
    #[tokio::test]
    async fn keepalive_runs_on_a_half_closed_stream() {
        let (_runtime, socket, stream, peer) = raw_peer_stream().await;
        let to = socket.local_addr().await.unwrap();
        stream.set_keepalive(Some(Duration::from_millis(30)));
        let peer_side = async {
            loop {
                let (header, _) = recv_header(&peer, Duration::from_secs(1)).await.unwrap();
                if header.has_flag(FLAG_END) {
                    peer.send_to(&packet(0, 0, header.seq + 1), to)
                        .await
                        .unwrap();
                    return;
                }
            }
        };
        let (ended, ()) = tokio::join!(stream.shutdown(), peer_side);
        ended.unwrap();
        let heartbeat = async {
            loop {
                let (header, _) = recv_header(&peer, Duration::from_millis(500)).await?;
                if header.has_flag(FLAG_HEARTBEAT) {
                    return Some(());
                }
            }
        };
        assert!(
            heartbeat.await.is_some(),
            "heartbeats continue after our END"
        );
        assert!(stream.abort_handle().is_alive());
    }

    /// C `udx_stream_init` lets a new stream take an id in timewait; the
    /// timewait then neither answers for it nor removes it on expiry.
    #[tokio::test]
    async fn new_stream_takes_an_id_in_timewait() {
        let (runtime, socket, mut stream, peer) = raw_peer_stream().await;
        let to = socket.local_addr().await.unwrap();
        end_first(&mut stream, &peer, to).await;
        tokio::time::timeout(Duration::from_secs(1), stream.abort_handle().closed())
            .await
            .unwrap();
        assert_eq!(entry(&socket), Some("timewait"));

        let mut fresh = runtime.create_stream(5).await.unwrap();
        fresh
            .connect(&socket, 6, peer.local_addr().unwrap())
            .await
            .unwrap();
        assert_eq!(entry(&socket), Some("stream"));
        let mut data = packet(FLAG_DATA, 0, 0).to_vec();
        data.extend_from_slice(b"fresh");
        peer.send_to(&data, to).await.unwrap();
        let (ack, _) = recv_header(&peer, Duration::from_millis(500))
            .await
            .unwrap();
        assert_eq!((ack.seq, ack.ack), (0, 1), "the new stream answers");
        assert_eq!(fresh.read().await.unwrap().as_deref(), Some(&b"fresh"[..]));

        tokio::time::sleep(TIMEWAIT + Duration::from_millis(100)).await;
        assert_eq!(entry(&socket), Some("stream"));
    }

    /// Next datagram within `wait`: header, wire length, payload.
    async fn recv_data(
        peer: &tokio::net::UdpSocket,
        wait: Duration,
    ) -> Option<(Header, usize, Vec<u8>)> {
        let mut buf = [0u8; 2048];
        let (len, _) = tokio::time::timeout(wait, peer.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        let header = Header::decode(&buf[..len]).ok()?;
        let payload = buf[header.payload_offset().min(len)..len].to_vec();
        Some((header, len, payload))
    }

    /// C packetizes at send time (udx.c:2634-2636): data written before
    /// `change_remote` but not sent yet leaves at the new path's base MTU,
    /// for the new peer, in order, and the write completes.
    #[tokio::test]
    async fn change_remote_sends_queued_data_at_the_new_base_mtu() {
        let (_runtime, socket, stream, old_peer) = raw_peer_stream().await;
        let to = socket.local_addr().await.unwrap();
        let new_peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        {
            let mut inner = stream.inner.lock().unwrap();
            inner.mtu = MTU_MAX;
            inner.mtu_state = MtuState::SearchComplete;
        }
        let old_size = MTU_MAX - IPV4_UDP_OVERHEAD;
        let new_size = MTU_BASE - IPV4_UDP_OVERHEAD;
        let data = pattern(40_000);
        let remote = stream.remote_handle();

        let peers = async {
            // The first window goes to the old peer at the old MTU.
            let mut received = Vec::new();
            let mut next = 0;
            while let Some((header, len, payload)) =
                recv_data(&old_peer, Duration::from_millis(300)).await
            {
                assert!(header.has_flag(FLAG_DATA));
                assert_eq!(header.seq, next);
                assert_eq!(len, old_size);
                next += 1;
                received.extend_from_slice(&payload);
            }
            assert!(
                next > 0 && received.len() < data.len(),
                "data is still queued"
            );
            let changed = remote.change_remote(&socket, 7, new_peer.local_addr().unwrap());
            let ack_old = async {
                old_peer.send_to(&packet(0, 0, next), to).await.unwrap();
            };
            let (changed, ()) = tokio::join!(changed, ack_old);
            changed.unwrap();

            // The rest goes to the new peer, cut at the new base MTU.
            let mut flight = Vec::new();
            while let Some(sent) = recv_data(&new_peer, Duration::from_millis(300)).await {
                flight.push(sent);
            }
            assert!(!flight.is_empty(), "queued data goes to the new peer");
            for (header, len, payload) in flight {
                assert_eq!((header.remote_id, header.seq), (7, next));
                if received.len() + payload.len() < data.len() {
                    assert_eq!(len, new_size, "queued data is cut at the new MTU");
                }
                next += 1;
                received.extend_from_slice(&payload);
            }
            // ACK as packets arrive until everything is in.
            new_peer.send_to(&packet(0, 0, next), to).await.unwrap();
            while received.len() < data.len() {
                let (header, _, payload) = recv_data(&new_peer, Duration::from_secs(2))
                    .await
                    .expect("the rest of the queued data");
                if header.seq == next {
                    next += 1;
                    received.extend_from_slice(&payload);
                }
                new_peer.send_to(&packet(0, 0, next), to).await.unwrap();
            }
            received
        };
        let (written, received) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(stream.write(&data), peers)
        })
        .await
        .expect("transfer stalled");
        written.expect("the write completes once the new peer ACKed it");
        assert_eq!(received, data);
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    /// Catches a stream that keeps advertising a window it no longer has, and
    /// one that never tells a stalled peer when reading reopened the window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn acks_show_the_window_closing_and_a_read_reopens_it() {
        let (_runtime, socket, mut stream, peer) = raw_peer_stream().await;
        let to = socket.local_addr().await.unwrap();
        // Heartbeats would mix with the ACKs this test reads.
        stream.set_keepalive(None);
        for k in 0..4195u32 {
            peer.send_to(&build_data_packet(5, k, 0, &[0u8; 1000]), to)
                .await
                .unwrap();
            let (header, _) = recv_header(&peer, Duration::from_secs(5))
                .await
                .expect("no ACK for an in-order data packet");
            assert_eq!(header.ack, k + 1);
            // 1,000 * (k + 1) bytes held in order, saturating at the maximum:
            // 4,194,304 - 1,000 * (k + 1), or 0 once it passes.
            assert_eq!(
                header.recv_window,
                DEFAULT_RWND.saturating_sub(1000 * (k + 1))
            );
        }
        // Nothing read yet, and the last window advertised was 0.
        for _ in 0..2097 {
            let data = stream.read().await.unwrap().expect("queued data");
            assert_eq!(data.len(), 1000);
        }
        // 2,097,000 bytes taken: the window is 4,194,304 - 2,098,000 =
        // 2,096,304, below half the maximum (2,097,152) above the advertised 0.
        assert!(
            recv_header(&peer, Duration::from_millis(100))
                .await
                .is_none(),
            "less than half a window was not worth an ACK"
        );
        // One more read: 2,098,000 taken, window 2,097,304, at least half the
        // maximum above 0.
        let data = stream.read().await.unwrap().expect("queued data");
        assert_eq!(data.len(), 1000);
        let (update, _) = recv_header(&peer, Duration::from_millis(500))
            .await
            .expect("reading half a window did not reopen it");
        assert_eq!(update.ack, 4195);
        // 4,194,304 - (4,195,000 - 2,098,000) = 2,097,304.
        assert_eq!(update.recv_window, 2_097_304);
        // The reopened window shows in the next ACK: 1,000 more held gives
        // 4,194,304 - 2,098,000 = 2,096,304.
        peer.send_to(&build_data_packet(5, 4195, 0, &[0u8; 1000]), to)
            .await
            .unwrap();
        let (header, _) = recv_header(&peer, Duration::from_secs(5))
            .await
            .expect("no ACK for the packet the update reopened");
        assert_eq!(header.ack, 4196);
        assert_eq!(header.recv_window, 2_096_304);
    }

    /// Catches a window that stays at the starting size after the reader took
    /// a whole window: the next ACK must advertise the doubled limit minus
    /// what is held.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn acks_show_the_window_growing_when_the_reader_is_fast() {
        let (_runtime, socket, mut stream, peer) = raw_peer_stream().await;
        let to = socket.local_addr().await.unwrap();
        // Heartbeats would mix with the ACKs this test reads.
        stream.set_keepalive(None);
        // The decision must not depend on how fast the machine is: any
        // interval shorter than an hour counts as fast.
        stream.read_meter.set_period(Duration::from_secs(3600));

        for k in 0..4195u32 {
            peer.send_to(&build_data_packet(5, k, 0, &[0u8; 1000]), to)
                .await
                .unwrap();
            let (header, _) = recv_header(&peer, Duration::from_secs(5))
                .await
                .expect("no ACK for an in-order data packet");
            assert_eq!(header.ack, k + 1);
            // No whole window taken yet, so the window cannot pass 4,194,304.
            assert!(
                header.recv_window <= DEFAULT_RWND,
                "the window grew before the reader took a whole window"
            );
            // Read a packet only after its ACK, so the ACK sees 1,000 bytes
            // held, as in the neighbour test.
            let data = stream.read().await.unwrap().expect("queued data");
            assert_eq!(data.len(), 1000);
        }
        // 4,195 x 1,000 = 4,195,000 bytes taken, so the limit doubled when
        // the reader crossed 4,194,304.

        // One more packet, not read: 1,000 bytes held. The last read asked
        // for an update ACK and it may arrive before this packet's ACK.
        peer.send_to(&build_data_packet(5, 4195, 0, &[0u8; 1000]), to)
            .await
            .unwrap();
        let mut header = recv_header(&peer, Duration::from_secs(5))
            .await
            .expect("no ACK after the growth")
            .0;
        if header.ack == 4195 {
            // The update ACK from the last read: nothing held, 8,388,608.
            assert_eq!(header.recv_window, 8_388_608);
            header = recv_header(&peer, Duration::from_secs(5))
                .await
                .expect("no ACK for the unread packet")
                .0;
        }
        assert_eq!(header.ack, 4196);
        // 8,388,608 - 1,000 = 8,387,608.
        assert_eq!(header.recv_window, 8_387_608);
    }

    /// Catches an async read that frees a whole Data event instead of the
    /// bytes it copied into the caller's buffer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn async_reads_count_the_bytes_that_were_copied() {
        use tokio::io::AsyncReadExt;

        let (_runtime, socket, stream, peer) = raw_peer_stream().await;
        let to = socket.local_addr().await.unwrap();
        peer.send_to(&build_data_packet(5, 0, 0, &[0u8; 1000]), to)
            .await
            .unwrap();
        let (header, _) = recv_header(&peer, Duration::from_secs(5))
            .await
            .expect("no ACK for seq 0");
        // 1,000 bytes held in order: 4,194,304 - 1,000 = 4,193,304.
        assert_eq!(header.recv_window, DEFAULT_RWND - 1000);

        let mut stream = stream.into_async_stream();
        let mut buf = [0u8; 300];
        stream.read_exact(&mut buf).await.unwrap();
        // 300 taken, 700 of the event still buffered for the next read; the
        // next packet makes 1,700 held: 4,194,304 - 1,700 = 4,192,604.
        peer.send_to(&build_data_packet(5, 1, 0, &[0u8; 1000]), to)
            .await
            .unwrap();
        let (header, _) = recv_header(&peer, Duration::from_secs(5))
            .await
            .expect("no ACK for seq 1");
        assert_eq!(header.ack, 2);
        assert_eq!(header.recv_window, DEFAULT_RWND - 1700);
    }
}

#[cfg(test)]
mod rack_tests {
    use super::*;
    use std::time::Duration;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn ack_header(ack: u32) -> Header {
        Header {
            type_flags: 0,
            data_offset: 0,
            remote_id: 0,
            recv_window: DEFAULT_RWND,
            seq: 0,
            ack,
        }
    }

    /// A connected stream on a fake clock with one 20 ms RTT sample (`srtt`
    /// and minimum RTT 20 ms, so the reorder window is 5 ms) and seqs 1-3
    /// sent 1 ms apart from the returned instant.
    fn three_in_flight() -> (StreamInner, Instant) {
        let (read_tx, _read_rx) = mpsc::unbounded_channel();
        let mut inner = StreamInner::new(0, read_tx, None, None, Registrations::default(), None);
        let addr = "127.0.0.1:9".parse().unwrap();
        inner.connected = true;
        inner.remote_addr = Some(addr);
        let t0 = Instant::now();
        inner.clock = Some(t0);
        inner.register_sent(0, build_data_packet(1, 0, 0, b"x"), addr, false);
        inner.next_seq = 1;
        let t1 = t0 + ms(20);
        inner.clock = Some(t1);
        inner.on_ack_packet(&ack_header(1), None);
        assert_eq!((inner.srtt, inner.rtt_min_us.get()), (20, 20_000));
        for seq in 1..4u32 {
            inner.clock = Some(t1 + ms(u64::from(seq) - 1));
            inner.register_sent(seq, build_data_packet(1, seq, 0, b"x"), addr, false);
        }
        inner.next_seq = 4;
        (inner, t1)
    }

    /// Packets the peer receives out of order inside the reorder window (C
    /// `rack_update_reo_wnd`: min RTT / 4, at most srtt) are not marked lost:
    /// no retransmit, no recovery, no cwnd cut.
    #[test]
    fn reordered_packet_inside_the_window_is_not_retransmitted() {
        let (mut inner, t1) = three_in_flight();
        let cwnd = inner.congestion.cwnd;
        // Seq 3 arrives first, 20 ms after it was sent: ack 1, SACK [3, 4).
        inner.clock = Some(t1 + ms(22));
        let outcome = inner.on_ack_packet(&ack_header(1), Some(&[SackRange { start: 3, end: 4 }]));
        // Seq 2 (sent at t1 + 1) leaves the 20 + 5 ms window at t1 + 26.
        assert_eq!(outcome.reorder_timeout, Some(ms(4)));
        assert!(inner.lost_queue.is_empty());
        assert_eq!(inner.congestion.ca_state, CaState::Open);

        // Seqs 1 and 2 arrive 1 ms later.
        inner.clock = Some(t1 + ms(23));
        let outcome = inner.on_ack_packet(&ack_header(4), None);
        assert!(outcome.ack_advanced && outcome.reorder_timeout.is_none());
        assert_eq!(inner.retransmits, 0);
        assert!(inner.lost_queue.is_empty());
        assert_eq!(inner.congestion.ca_state, CaState::Open);
        assert!(
            inner.congestion.cwnd >= cwnd,
            "cwnd cut to {}",
            inner.congestion.cwnd
        );
        // Seqs 1 and 2 were delivered below seq 3 without a retransmit.
        assert!(inner.reordering_seen);
    }

    /// A real loss inside the reorder window is found by the reorder timer
    /// alone (C `udx_rack_reo_timeout`): no further ACK arrives.
    #[test]
    fn reorder_timer_detects_a_real_loss_without_another_ack() {
        let (mut inner, t1) = three_in_flight();
        inner.clock = Some(t1 + ms(22));
        let outcome = inner.on_ack_packet(&ack_header(1), Some(&[SackRange { start: 3, end: 4 }]));
        let wait = outcome.reorder_timeout.expect("a reorder wait");
        assert!(inner.lost_queue.is_empty());

        inner.clock = Some(t1 + ms(22) + wait);
        assert_eq!(inner.on_reorder_timeout(), 2);
        assert_eq!(inner.congestion.ca_state, CaState::Recovery);
        let (batch, _, _) = inner.take_send_batch();
        let resent: Vec<u32> = batch
            .iter()
            .map(|(packet, _)| Header::decode(packet).unwrap().seq)
            .collect();
        assert_eq!(resent, [1, 2]);
    }

    /// C `udx_rto_timeout` (udx.c:1225-1247): every firing re-arms the timer
    /// at `2 × rto` without changing `rto`, and the seventh firing without
    /// progress ends the stream (`rto_count > UDX_MAX_RTO_TIMEOUTS`).
    #[test]
    fn rto_backs_off_the_timer_only_and_gives_up_on_the_seventh() {
        let (mut inner, _) = three_in_flight();
        let rto = inner.rto;
        for _ in 0..MAX_RTO_TIMEOUTS {
            assert_eq!(inner.rto_fired(), Some(ms(u64::from(rto) * 2)));
            assert_eq!(inner.rto, rto);
        }
        assert_eq!(inner.rto_fired(), None);
    }

    /// C `clamp_rtt` (udx.c:1290-1303): a sample over 5 s and over
    /// `srtt + 5 × rttvar` (a suspend) counts as that bound; a 4 s one does not.
    #[test]
    fn suspend_length_rtt_sample_is_clamped() {
        let (read_tx, _read_rx) = mpsc::unbounded_channel();
        let mut inner = StreamInner::new(0, read_tx, None, None, Registrations::default(), None);
        let t0 = Instant::now();
        inner.srtt = 100;
        inner.srtt_us = 100_000;
        inner.rttvar = 50;
        inner.rttvar_us = 50_000;
        inner.on_packet_acked(0, t0, false, t0 + ms(60_000));
        // 350 ms, not 60 s (nor the 30 s cap).
        assert_eq!(
            (inner.srtt, inner.rttvar),
            ((7 * 100 + 350) / 8, (3 * 50 + 250) / 4)
        );

        inner.srtt = 100;
        inner.srtt_us = 100_000;
        inner.rttvar = 50;
        inner.rttvar_us = 50_000;
        inner.on_packet_acked(1, t0, false, t0 + ms(4_000));
        assert_eq!(inner.srtt, (7 * 100 + 4_000) / 8);
    }
}

#[cfg(test)]
mod c_order_tests {
    use super::*;
    use std::time::Duration;

    /// A connected state machine on a fake clock with one RTT sample.
    fn inner_with_rtt(rtt: u32) -> (StreamInner, Instant) {
        let (read_tx, _rx) = mpsc::unbounded_channel();
        let mut inner = StreamInner::new(0, read_tx, None, None, Registrations::default(), None);
        inner.connected = true;
        inner.remote_addr = Some("127.0.0.1:9".parse().unwrap());
        inner.mtu_state = MtuState::SearchComplete;
        let t0 = inner.epoch + Duration::from_millis(1000);
        inner.clock = Some(t0);
        inner.update_rtt(rtt);
        inner.rtt_min_us.apply_min(
            RTT_MIN_WINDOW_US,
            inner.clock_us(t0),
            u64::from(rtt) * 1_000,
        );
        (inner, t0)
    }

    fn write(inner: &mut StreamInner, packets: usize) {
        let data = vec![7; packets * inner.max_payload()];
        inner.push_write(WriteBuf {
            data,
            sent: 0,
            end: false,
            done: None,
        });
    }

    fn sack_hdr(ack: u32) -> Header {
        Header {
            type_flags: FLAG_SACK,
            data_offset: 0,
            remote_id: 0,
            recv_window: DEFAULT_RWND,
            seq: 0,
            ack,
        }
    }

    /// cwnd 10; 0-7 sent at t0, 8-9 at t0+200; at t0+300 ACK 1 with SACK
    /// 8..10 marks 1-7 lost. Leaves the stream in Recovery.
    fn enter_recovery(extra: usize) -> (StreamInner, Instant, AckOutcome) {
        let (mut inner, t0) = inner_with_rtt(100);
        inner.congestion.cwnd = 10;
        write(&mut inner, 8);
        assert_eq!(inner.take_send_batch().0.len(), 8);
        inner.clock = Some(t0 + Duration::from_millis(200));
        write(&mut inner, 2 + extra);
        assert_eq!(inner.take_send_batch().0.len(), 2);
        inner.clock = Some(t0 + Duration::from_millis(300));
        let outcome = inner.on_ack_packet(&sack_hdr(1), Some(&[SackRange { start: 8, end: 10 }]));
        assert_eq!(inner.congestion.ca_state, CaState::Recovery);
        assert_eq!(inner.congestion.high_seq, 10);
        (inner, t0, outcome)
    }

    /// C `rack_detect_loss` sends before `bbr_main` (udx.c:1164, 1877):
    /// every lost packet leaves under the pre-recovery window, which
    /// `inflight + acked` (udx_bbr.c:207) then keeps at 10.
    #[test]
    fn recovery_entry_retransmits_every_lost_packet_first() {
        let (inner, _, outcome) = enter_recovery(0);
        assert_eq!(outcome.batch.len(), 7);
        assert_eq!(inner.congestion.cwnd, 10);
    }

    /// C `process_packet`: recovery lasts until the cumulative ACK passes
    /// `high_seq` (`>`, not `>=`); the next delivering ACK restores
    /// `prior_cwnd`.
    #[test]
    fn recovery_exit_restores_prior_cwnd() {
        let (mut inner, t0, _) = enter_recovery(2);
        let prior = inner.congestion.prior_cwnd();
        assert_eq!(prior, 10);
        let mut t = 300;
        while inner.remote_acked < 10 {
            t += 100;
            inner.clock = Some(t0 + Duration::from_millis(t));
            let ack = inner.remote_acked + 1;
            inner.on_ack_packet(&sack_hdr(ack), None);
            let _ = inner.take_send_batch();
            assert_eq!(
                inner.congestion.ca_state,
                CaState::Recovery,
                "ack {ack} <= high_seq"
            );
        }
        assert!(inner.next_seq >= 11, "new data left during recovery");
        inner.clock = Some(t0 + Duration::from_millis(t + 100));
        inner.on_ack_packet(&sack_hdr(11), None);
        assert_eq!(inner.congestion.ca_state, CaState::Open);
        assert!(inner.congestion.cwnd >= prior);
    }

    /// C counts probes when sent (udx.c:858) and zeroes the count with the
    /// MTU state (udx.c:2378): an old-path probe lost after `reset_mtu`
    /// costs the new path nothing, and its late ACK raises no MTU.
    #[test]
    fn old_path_probe_costs_the_new_path_nothing() {
        let (mut inner, t0) = inner_with_rtt(100);
        inner.mtu_state = MtuState::Search;
        inner.mtu_probe_size = 1232;
        inner.mtu_probe_wanted = true;
        write(&mut inner, 1);
        assert_eq!(inner.take_send_batch().0.len(), 1);
        assert!(inner.outgoing[&0].is_mtu_probe);
        assert_eq!(inner.mtu_probe_count, 1, "counted when sent");
        inner.reset_mtu();
        inner.clock = Some(t0 + Duration::from_millis(2000));
        inner.on_rto();
        assert_eq!(inner.mtu_probe_count, 0);
        assert_eq!(inner.mtu_state, MtuState::Base);

        // A probe still in flight across the change is ACKed late.
        let (mut inner, _) = inner_with_rtt(100);
        inner.mtu_state = MtuState::Search;
        inner.mtu_probe_size = 1232;
        inner.mtu_probe_wanted = true;
        write(&mut inner, 1);
        inner.take_send_batch();
        inner.reset_mtu();
        inner.mtu_state = MtuState::Search;
        inner.on_cumulative_ack(1);
        assert_eq!(
            inner.mtu, MTU_BASE,
            "an old-path probe is no new-path proof"
        );
    }

    /// C `SHOULD_READ` (udx.c:1682): nothing is read after the peer's END.
    #[test]
    fn data_after_end_is_dropped() {
        let (mut inner, _) = inner_with_rtt(100);
        let mut events = Vec::new();
        inner.receive_data(0, Vec::new(), FLAG_END, &mut events);
        inner.receive_data(1, b"late".to_vec(), FLAG_DATA, &mut events);
        inner.receive_data(3, b"later".to_vec(), FLAG_DATA, &mut events);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], StreamEvent::End));
        assert!(inner.recv_buf.is_empty() && inner.recv_ranges.is_empty());
        assert_eq!(inner.next_remote_seq, 1);
    }

    /// C: an empty write rides on the next packet sent and completes with it.
    #[test]
    fn empty_write_completes_with_the_next_packet() {
        let (mut inner, _) = inner_with_rtt(100);
        let (tx, mut rx) = oneshot::channel();
        inner.push_write(WriteBuf {
            data: Vec::new(),
            sent: 0,
            end: false,
            done: Some(tx),
        });
        assert!(
            inner.take_send_batch().0.is_empty(),
            "nothing to send alone"
        );
        write(&mut inner, 1);
        assert_eq!(inner.take_send_batch().0.len(), 1);
        let (completed, _) = inner.on_cumulative_ack(1);
        assert_eq!(completed.len(), 1);
        completed.into_iter().flatten().for_each(|tx| {
            let _ = tx.send(Ok(()));
        });
        assert!(matches!(rx.try_recv(), Ok(Ok(()))));
    }

    /// C `udx_tlp_timeout` sends a new packet when one waits, ignoring the
    /// window.
    #[test]
    fn loss_probe_sends_new_data_when_there_is_some() {
        let (mut inner, _) = inner_with_rtt(100);
        inner.congestion.cwnd = 1;
        write(&mut inner, 2);
        assert_eq!(inner.take_send_batch().0.len(), 1);
        inner.tlp_permitted = true;
        assert!(inner.take_loss_probe().is_some());
        assert!(!inner.tlp_is_retrans);
        assert_eq!(inner.tlp_end_seq, 1);
        assert_eq!(inner.outgoing.len(), 2);
    }
}
