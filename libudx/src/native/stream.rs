use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::Waker;
use std::time::Instant;

use tokio::sync::{mpsc, oneshot};

use crate::error::{Result, UdxError};
use super::congestion::CaState;
use super::header::{
    Header, SackRange,
    FLAG_DATA, FLAG_END, FLAG_DESTROY, FLAG_MESSAGE, FLAG_SACK, FLAG_HEARTBEAT,
    HEADER_SIZE, encode_sack, decode_sack,
};

// ── Constants ────────────────────────────────────────────────────────────────

/// Default receive window size (4 MB, matches C libudx).
pub(crate) const DEFAULT_RWND: u32 = 4_194_304;

/// Maximum payload per UDP packet (1200 - 20 byte header).
pub(crate) const MAX_PAYLOAD: usize = 1200 - HEADER_SIZE;

/// Starting MTU (bytes) — matches C libudx `UDX_MTU_BASE`.
pub(crate) const MTU_BASE: usize = 1200;

/// Maximum MTU (bytes) — matches C libudx `UDX_MTU_MAX`.
pub(crate) const MTU_MAX: usize = 1500;

/// Probe size increment (bytes).
pub(crate) const MTU_STEP: usize = 32;

/// Failed probes before settling on current MTU.
pub(crate) const MTU_MAX_PROBES: u32 = 3;

/// Initial retransmission timeout (ms) — matches C libudx.
const INITIAL_RTO_MS: u32 = 1_000;

/// Maximum retransmission timeout (ms) — matches C libudx `UDX_RTO_MAX_MS`.
const MAX_RTO_MS: u32 = 30_000;

/// Maximum consecutive RTO timeouts before stream failure.
const MAX_RTO_TIMEOUTS: u32 = 6;

/// Heartbeat interval when stream is idle (ms).
const HEARTBEAT_INTERVAL_MS: u64 = 1_000;

/// Maximum number of SACK ranges to include in an ACK packet.
const MAX_SACK_RANGES: usize = 50;

/// Maximum accepted RTT sample (ms) — prevents outlier corruption.
const MAX_RTT_MS: u32 = 30_000;

/// Far-future duration used to effectively disable a timer.
const FAR_FUTURE: std::time::Duration = std::time::Duration::from_secs(86_400);

/// Bytes one stream may hold queued plus sent-but-unacked before
/// `UdxAsyncStream::poll_write` applies back-pressure.
pub(crate) const SEND_BUFFER_MAX: usize = 1024 * 1024;

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

pub(crate) struct IncomingPacket {
    pub data: Vec<u8>,
    #[allow(dead_code)]
    pub addr: SocketAddr,
    /// The socket the datagram arrived on: the firewall hook commits to it,
    /// and a stream mid-`change_remote` answers on this path when the peer
    /// still sends from the old one (C libudx routes by the `udx_socket_t`
    /// the packet arrived on).
    pub socket: super::socket::UdxSocket,
}

pub(crate) enum StreamEvent {
    Data(Vec<u8>),
    End,
}

// ── Reliability types ────────────────────────────────────────────────────────

/// A sent packet stored in the outgoing buffer for potential retransmission.
struct SentPacket {
    /// Full wire-format packet bytes (header + payload).
    packet: Vec<u8>,
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

/// A received out-of-order packet buffered until gaps are filled.
struct RecvdPacket {
    payload: Vec<u8>,
    flags: u8,
}

struct QueuedPacket {
    packet: Vec<u8>,
    seq: u32,
    remote_addr: SocketAddr,
}

/// Tracks a pending write awaiting remote acknowledgement.
pub(crate) struct PendingWrite {
    pub(crate) ack_threshold: u32,
    pub(crate) tx: Option<oneshot::Sender<Result<()>>>,
}

/// Notification from the send path to the processor task.
pub(crate) enum StreamNotify {
    DataQueued,
    Shutdown,
}

type WriteSenders = Vec<Option<oneshot::Sender<Result<()>>>>;
type AckedRateInfo = Vec<(u32, super::congestion::rate::PacketRateInfo)>;
type StreamMap = Arc<Mutex<std::collections::HashMap<u32, mpsc::UnboundedSender<IncomingPacket>>>>;
/// Stream maps of the sockets a stream is registered on. Shared by the
/// stream handle and its processor task.
type Registrations = Arc<Mutex<Vec<StreamMap>>>;
type FirewallHook =
    Box<dyn FnMut(&super::socket::UdxSocket, u16, std::net::IpAddr) -> bool + Send>;

/// Remove `local_id` from every socket map in `registrations`.
fn deregister(local_id: u32, registrations: &Registrations) {
    let maps = std::mem::take(&mut *registrations.lock().unwrap_or_else(|e| e.into_inner()));
    for map in maps {
        map.lock().unwrap_or_else(|e| e.into_inner()).remove(&local_id);
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

    // ── Send state ──
    pub(crate) next_seq: u32,
    pub(crate) pending_writes: Vec<PendingWrite>,
    /// Sent packets awaiting ACK, keyed by sequence number.
    outgoing: BTreeMap<u32, SentPacket>,
    /// Bytes staged in `send_queue`, not yet sent.
    queued_bytes: usize,
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
    /// delivered (RACK `rack.xmit_ts`/`rack.end_seq`). Retransmissions do
    /// not count: their ACK could be for the original copy.
    rack: Option<(Instant, u32)>,
    /// Out-of-order receive buffer, keyed by sequence number.
    recv_buf: BTreeMap<u32, RecvdPacket>,

    // ── RTT estimation (Jacobson/Karels, matching C libudx constants) ──
    srtt: u32,
    rttvar: u32,
    rto: u32,
    rto_timeouts: u32,

    // ── Flow control ──
    /// Remote's last advertised receive window.
    send_rwnd: u32,

    // ── MTU probing state ──
    pub(crate) mtu_state: MtuState,
    pub(crate) mtu: usize,
    pub(crate) mtu_probe_size: usize,
    pub(crate) mtu_probe_count: u32,
    pub(crate) mtu_probe_wanted: bool,
    pub(crate) mtu_max: usize,

    // ── IO ──
    pub(crate) udp: Option<Arc<tokio::net::UdpSocket>>,
    pub(crate) read_tx: mpsc::UnboundedSender<StreamEvent>,
    close_tx: Option<oneshot::Sender<()>>,
    pub(crate) notify_tx: Option<mpsc::UnboundedSender<StreamNotify>>,

    // ── Congestion control (BBR) ──
    pub(crate) congestion: super::congestion::CongestionController,
    send_queue: VecDeque<QueuedPacket>,

    // ── Relay ──
    relay_target: Option<Arc<Mutex<StreamInner>>>,

    // ── Firewall hook (set_firewall_hook path) ──
    /// Consulted while unconnected and for packets arriving on a socket
    /// other than the stream's (C `on_firewall`, udx.c:1643).
    firewall_hook: Option<FirewallHook>,

    // ── Remote migration (`change_remote`) ──
    local_id: u32,
    /// Demux sender, so a migration can register the stream on another socket.
    incoming_tx: Option<mpsc::UnboundedSender<IncomingPacket>>,
    registrations: Registrations,
    /// First seq not sent before the change, and the waiter released once
    /// the peer has ACKed up to it (C `seq_on_remote_changed`).
    remote_change: Option<(u32, oneshot::Sender<()>)>,
    /// Released by data or a message from the current remote on this socket.
    remote_observed: Option<oneshot::Sender<()>>,
    observed_current_remote: bool,
}

impl StreamInner {
    // ── Stream termination ──────────────────────────────────────────────────

    /// Drain all pending writes with `StreamClosed`, wake blocked writers,
    /// mark the stream disconnected, and drop `notify_tx` so future sends
    /// fail fast. Idempotent — safe to call more than once.
    fn terminate(&mut self) {
        self.connected = false;
        self.terminated = true;
        self.notify_tx = None;
        // Migration waiters learn the stream died (their receivers error).
        self.remote_change = None;
        self.remote_observed = None;
        // Wake readers: an aborted stream reads as EOF instead of hanging.
        let _ = self.read_tx.send(StreamEvent::End);
        // Release the socket so a suspended DHT socket can be rebound.
        self.udp = None;
        if let Some(tx) = self.close_tx.take() {
            let _ = tx.send(());
        }

        for mut pw in self.pending_writes.drain(..) {
            if let Some(tx) = pw.tx.take() {
                let _ = tx.send(Err(UdxError::StreamClosed));
            }
        }
        if let Some(w) = self.write_waker.take() {
            w.wake();
        }
        if let Some(w) = self.flush_waker.take() {
            w.wake();
        }
    }

    // ── MTU ──────────────────────────────────────────────────────────────────

    pub(crate) fn max_payload(&self) -> usize {
        self.mtu - HEADER_SIZE
    }

    /// Back to the base MTU, re-probing from scratch: a migrated stream is
    /// on a new path (C `reset_mtu_state_machine`).
    fn reset_mtu(&mut self) {
        self.mtu = MTU_BASE;
        self.mtu_state = MtuState::Base;
        self.mtu_probe_size = MTU_BASE + MTU_STEP;
        self.mtu_probe_count = 0;
        self.mtu_probe_wanted = false;
        self.mtu_max = MTU_MAX;
    }

    /// Inflate a DATA packet to `mtu_probe_size` by inserting zero padding after the header.
    /// Sets `data_offset` so the receiver skips the padding via `payload_offset()`.
    /// Returns `true` if the packet was successfully probeified.
    fn mtu_probeify_packet(&mut self, packet: &mut Vec<u8>) -> bool {
        if packet.len() < HEADER_SIZE {
            return false;
        }
        let target_size = self.mtu_probe_size;
        if target_size <= packet.len() {
            return false;
        }

        let padding = target_size - packet.len();
        // data_offset is u8 — can only pad up to 255 bytes.
        // This naturally limits probing to nearly-full packets (matching C libudx).
        if padding > 255 {
            return false;
        }
        // Insert padding between header and payload: shift payload right
        let payload = packet[HEADER_SIZE..].to_vec();
        packet.truncate(HEADER_SIZE);
        packet.extend(std::iter::repeat_n(0u8, padding));
        packet.extend_from_slice(&payload);

        // Set data_offset in header byte [3]
        packet[3] = padding as u8;

        self.mtu_probe_wanted = false;
        tracing::trace!(
            probe_size = target_size,
            padding,
            "mtu: probeify"
        );
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

        self.congestion.on_mtu_change(old_mtu, self.mtu);
        tracing::debug!(old_mtu, new_mtu = self.mtu, state = ?self.mtu_state, "mtu: probe acked");
    }

    // ── Write preparation ────────────────────────────────────────────────────

    /// Reserve sequence numbers for a write of `data_len` bytes.
    pub(crate) fn prepare_write(
        &mut self,
        data_len: usize,
    ) -> Result<WritePrep> {
        if !self.connected && self.firewall_hook.is_none() {
            return Err(UdxError::Io(std::io::Error::other("stream not connected")));
        }
        if self.ended {
            return Err(UdxError::Io(std::io::Error::other("stream already shut down")));
        }
        // `terminate()` drops the processor's channel: nothing would ever send.
        if self.udp.is_none() || self.notify_tx.is_none() {
            return Err(UdxError::StreamClosed);
        }
        // When the firewall hook hasn't fired yet, remote_addr is not known.
        // Use the unspecified sentinel (0.0.0.0:0); the processor will update
        // queued packets once the hook fires and remote_addr is resolved.
        let remote_addr = self
            .remote_addr
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        let remote_id = self.remote_id;

        let max_payload = self.max_payload();
        let chunk_count = if data_len == 0 {
            1
        } else {
            data_len.div_ceil(max_payload)
        };
        let first_seq = self.next_seq;
        let ack_threshold = first_seq + chunk_count as u32;
        self.next_seq = ack_threshold;
        let current_ack = self.next_remote_seq;

        Ok(WritePrep {
            remote_addr,
            remote_id,
            first_seq,
            ack_threshold,
            current_ack,
        })
    }

    /// Reserve the sequence number of the FIN; later writes are refused.
    pub(crate) fn prepare_end(&mut self) -> Result<WritePrep> {
        if !self.connected {
            return Err(UdxError::Io(std::io::Error::other("stream not connected")));
        }
        if self.ended {
            return Err(UdxError::Io(std::io::Error::other("stream already shut down")));
        }
        if self.udp.is_none() || self.notify_tx.is_none() {
            return Err(UdxError::StreamClosed);
        }
        let remote_addr = self.remote_addr.ok_or(UdxError::StreamClosed)?;
        self.ended = true;
        let remote_id = self.remote_id;

        let seq = self.next_seq;
        self.next_seq = seq + 1;
        let current_ack = self.next_remote_seq;

        Ok(WritePrep {
            remote_addr,
            remote_id,
            first_seq: seq,
            ack_threshold: seq + 1,
            current_ack,
        })
    }

    /// Resolves once the remote has cumulatively ACKed every seq below
    /// `ack_threshold`, or with `StreamClosed` when the stream dies first.
    pub(crate) fn watch_ack(&mut self, ack_threshold: u32) -> oneshot::Receiver<Result<()>> {
        let (tx, rx) = oneshot::channel();
        self.pending_writes.push(PendingWrite {
            ack_threshold,
            tx: Some(tx),
        });
        rx
    }

    /// Send-buffer bytes still free for `UdxAsyncStream::poll_write`.
    pub(crate) fn send_buffer_room(&self) -> usize {
        SEND_BUFFER_MAX.saturating_sub(self.queued_bytes + self.unacked_bytes)
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
        self.send_queue.is_empty() && self.outgoing.is_empty()
    }

    // ── Outgoing packet registration ─────────────────────────────────────────

    /// Store a sent packet in the outgoing buffer for potential retransmission.
    pub(crate) fn register_sent(
        &mut self,
        seq: u32,
        packet: Vec<u8>,
        remote_addr: SocketAddr,
        is_mtu_probe: bool,
    ) {
        let now = Instant::now();
        let inflight = self.inflight();
        let rate_info = self.congestion.on_packet_sent(seq, inflight, now);
        tracing::trace!(seq, is_mtu_probe, "register_sent: packet placed in outgoing");
        self.unacked_bytes += packet.len();
        self.outgoing.insert(seq, SentPacket {
            packet,
            remote_addr,
            time_sent: now,
            retransmit_count: 0,
            sacked: false,
            is_mtu_probe,
            lost: false,
            rate_info: Some(rate_info),
        });
    }

    pub(crate) fn inflight(&self) -> u32 {
        self.outgoing.values().filter(|p| !p.sacked && !p.lost).count() as u32
    }

    pub(crate) fn queue_for_send(&mut self, packets: Vec<(u32, Vec<u8>)>, remote_addr: SocketAddr) {
        let count = packets.len();
        for (seq, packet) in packets {
            self.queued_bytes += packet.len();
            self.send_queue.push_back(QueuedPacket { packet, seq, remote_addr });
        }
        tracing::trace!(count, queue_len = self.send_queue.len(), "queue_for_send: packets staged");
        if let Some(tx) = &self.notify_tx {
            let _ = tx.send(StreamNotify::DataQueued);
        }
    }

    /// Stage a write's packets, restarting the BBR transmit clock when the
    /// stream was idle.
    pub(crate) fn queue_write(&mut self, packets: Vec<(u32, Vec<u8>)>, remote_addr: SocketAddr) {
        if self.send_idle() {
            self.congestion.on_transmit_start(Instant::now());
        }
        self.queue_for_send(packets, remote_addr);
    }

    /// Take the next packet to send off the queue.
    fn pop_queued(&mut self) -> Option<QueuedPacket> {
        let queued = self.send_queue.pop_front()?;
        self.queued_bytes = self.queued_bytes.saturating_sub(queued.packet.len());
        Some(queued)
    }

    pub(crate) fn send_idle(&self) -> bool {
        self.outgoing.is_empty() && self.send_queue.is_empty()
    }

    // ── RTT estimation (Jacobson/Karels) ─────────────────────────────────────

    /// Update the RTT estimator with a new sample.
    ///
    /// Uses standard constants matching C libudx:
    ///   α = 1/8 (SRTT smoothing)
    ///   β = 1/4 (RTTVAR smoothing)
    ///   K = 4   (RTO multiplier for RTTVAR)
    ///   G = 1000ms (minimum RTO granularity)
    fn update_rtt(&mut self, rtt_ms: u32) {
        let rtt = rtt_ms.min(MAX_RTT_MS);
        if self.srtt == 0 {
            // First sample
            self.srtt = rtt;
            self.rttvar = rtt / 2;
        } else {
            let delta = self.srtt.abs_diff(rtt);
            // RTTVAR <- (3/4) * RTTVAR + (1/4) * |SRTT - R|
            self.rttvar = (3 * self.rttvar + delta) / 4;
            // SRTT <- (7/8) * SRTT + (1/8) * R
            self.srtt = (7 * self.srtt + rtt) / 8;
        }
        // RTO <- SRTT + max(G, K * RTTVAR) where K=4, G=1000ms
        self.rto = (self.srtt + 4 * self.rttvar).clamp(1_000, MAX_RTO_MS);
    }

    // ── ACK processing ───────────────────────────────────────────────────────

    /// Process a cumulative ACK from the remote peer.
    ///
    /// Removes ACKed packets from the outgoing buffer, measures RTT from the
    /// earliest non-retransmitted packet, resets the RTO timeout counter, and
    /// returns completed write senders plus rate info for congestion control.
    ///
    /// Congestion control is NOT called here — the caller must combine this
    /// rate info with SACK rate info and loss count, then call `congestion.on_ack`.
    fn on_cumulative_ack(
        &mut self,
        ack: u32,
    ) -> (WriteSenders, AckedRateInfo) {
        if !seq_after(ack, self.remote_acked) {
            return (Vec::new(), Vec::new());
        }

        self.remote_acked = ack;

        // Everything sent to the old remote is ACKed: the migration is done
        // (C udx.c:1754).
        if self.remote_change.as_ref().is_some_and(|(seq, _)| !seq_after(*seq, ack)) {
            if let Some((_, done)) = self.remote_change.take() {
                let _ = done.send(());
            }
        }

        // Efficient BTreeMap split: remove all entries with key < ack
        let to_keep = self.outgoing.split_off(&ack);
        let removed = std::mem::replace(&mut self.outgoing, to_keep);

        let mut rtt_measured = false;
        let mut acked_rate_info: Vec<(u32, super::congestion::rate::PacketRateInfo)> = Vec::new();
        for (&seq, pkt) in &removed {
            self.unacked_bytes = self.unacked_bytes.saturating_sub(pkt.packet.len());
            if pkt.retransmit_count == 0 {
                if !rtt_measured {
                    let elapsed = pkt.time_sent.elapsed().as_millis() as u32;
                    self.update_rtt(elapsed);
                    rtt_measured = true;
                }
                self.rack_advance(pkt.time_sent, seq);
            }
            if let Some(info) = &pkt.rate_info {
                acked_rate_info.push((seq, *info));
            }
            if pkt.is_mtu_probe && self.mtu_state == MtuState::Search {
                self.on_mtu_probe_acked();
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
        let mut completed = Vec::new();
        self.pending_writes.retain_mut(|pw| {
            if pw.ack_threshold <= ack {
                completed.push(pw.tx.take());
                false
            } else {
                true
            }
        });
        (completed, acked_rate_info)
    }

    // ── SACK processing ──────────────────────────────────────────────────────

    /// Process SACK ranges from the remote peer. Marks selectively acknowledged
    /// packets and returns rate info from newly sacked packets for congestion control.
    ///
    /// Ranges are untrusted input: only packets actually in `outgoing` are
    /// visited, so a block like `0..0xFFFFFFFF` costs one tree walk, not four
    /// billion lookups (C `udx_sack_is_valid` rejects it outright).
    fn on_sack(&mut self, ranges: &[SackRange]) -> Vec<(u32, super::congestion::rate::PacketRateInfo)> {
        let mut sack_rate_info = Vec::new();
        let mut delivered = Vec::new();
        for range in ranges {
            if range.start >= range.end {
                continue;
            }
            for (&seq, pkt) in self.outgoing.range_mut(range.start..range.end) {
                if !pkt.sacked {
                    pkt.sacked = true;
                    if pkt.retransmit_count == 0 {
                        delivered.push((pkt.time_sent, seq));
                    }
                    if let Some(info) = &pkt.rate_info {
                        sack_rate_info.push((seq, *info));
                    }
                }
            }
        }
        for (time_sent, seq) in delivered {
            self.rack_advance(time_sent, seq);
        }
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

    /// Detect lost packets with RACK's ordering rule (C `rack_detect_loss`,
    /// RFC 8985 §6.2): an unacked packet is lost once the peer has delivered
    /// a packet that was sent after it. A retransmission gets a fresh send
    /// time, so it is not declared lost again until something sent after it
    /// is delivered, about one RTT later; without that, every SACK arriving
    /// during a retransmission's flight would retransmit it once more.
    /// Returns the number of newly detected losses.
    ///
    /// Simplification of C: no reordering window (`reo_wnd`) and no timer;
    /// a packet is lost as soon as the ordering rule says so.
    fn detect_losses(&mut self) -> u32 {
        let Some((rack_time_sent, rack_seq)) = self.rack else {
            return 0;
        };

        let lost_seqs: Vec<u32> = self
            .outgoing
            .iter()
            .filter(|&(&seq, pkt)| {
                !pkt.sacked
                    && !pkt.lost
                    && (pkt.time_sent < rack_time_sent
                        || (pkt.time_sent == rack_time_sent && seq_after(rack_seq, seq)))
            })
            .map(|(&seq, _)| seq)
            .collect();

        for &seq in &lost_seqs {
            if let Some(pkt) = self.outgoing.get_mut(&seq) {
                pkt.lost = true;
            }
        }

        let was_open = self.congestion.ca_state == CaState::Open;

        for &seq in &lost_seqs {
            self.congestion.on_packet_lost(seq);
        }

        // Record the recovery boundary: when all packets up to high_seq
        // are ACK'd, we can exit Recovery → Open.
        if was_open && self.congestion.ca_state == CaState::Recovery {
            if let Some(&max_seq) = self.outgoing.keys().last() {
                self.congestion.high_seq = max_seq;
            }
        }

        lost_seqs.len() as u32
    }

    // ── Receive buffering ────────────────────────────────────────────────────

    /// Handle an incoming DATA or END packet.
    ///
    /// In-order packets are delivered immediately. Out-of-order packets are
    /// buffered. When gaps are filled, consecutive buffered packets are drained
    /// and delivered in order. Returns events to deliver to the application.
    ///
    /// A single packet may carry both FLAG_DATA and FLAG_END (C libudx combines
    /// the last data chunk with the end marker). In that case two events are
    /// produced: Data followed by End.
    fn receive_data(&mut self, seq: u32, payload: Vec<u8>, flags: u8) -> Vec<StreamEvent> {
        let mut events = Vec::new();

        // Duplicate or already-received packet — ignore
        if seq < self.next_remote_seq {
            return events;
        }

        if seq == self.next_remote_seq {
            // In-order: deliver directly
            push_events(&mut events, payload, flags);
            self.next_remote_seq = seq + 1;

            // Drain consecutive buffered packets
            while let Some(recvd) = self.recv_buf.remove(&self.next_remote_seq) {
                push_events(&mut events, recvd.payload, recvd.flags);
                self.next_remote_seq += 1;
            }
        } else {
            // Out-of-order: buffer for later delivery
            self.recv_buf.entry(seq).or_insert(RecvdPacket { payload, flags });
        }

        events
    }

    // ── SACK generation ──────────────────────────────────────────────────────

    /// Compute SACK ranges from the out-of-order receive buffer.
    /// Returns contiguous ranges of received sequence numbers that are
    /// beyond the cumulative ACK point.
    fn sack_ranges(&self) -> Vec<SackRange> {
        if self.recv_buf.is_empty() {
            return Vec::new();
        }

        let mut ranges = Vec::new();
        let mut iter = self.recv_buf.keys();

        if let Some(&first) = iter.next() {
            let mut start = first;
            let mut end = first + 1;

            for &seq in iter {
                if seq == end {
                    // Extend current range
                    end = seq + 1;
                } else {
                    // Gap found: close current range, start new one
                    ranges.push(SackRange { start, end });
                    if ranges.len() >= MAX_SACK_RANGES {
                        return ranges;
                    }
                    start = seq;
                    end = seq + 1;
                }
            }
            ranges.push(SackRange { start, end });
        }
        ranges
    }

    // ── Retransmission ───────────────────────────────────────────────────────

    /// Collect packets to retransmit: every un-SACKed packet (RTO), or with
    /// `only_lost` just the ones SACK gap analysis marked lost (fast retransmit).
    /// Updates retransmit_count and time_sent for each retransmitted packet.
    /// For MTU probes: strips padding, marks failure, and may transition to SearchComplete.
    fn collect_retransmits(&mut self, only_lost: bool) -> Vec<(Vec<u8>, SocketAddr)> {
        let now = Instant::now();
        let mut retransmits = Vec::new();
        let mut probe_failed = false;
        let mut stripped = 0;
        for pkt in self.outgoing.values_mut() {
            if !pkt.sacked && (pkt.lost || !only_lost) {
                if pkt.is_mtu_probe {
                    let before = pkt.packet.len();
                    strip_probe_padding(&mut pkt.packet);
                    stripped += before - pkt.packet.len();
                    pkt.is_mtu_probe = false;
                    probe_failed = true;
                }
                retransmits.push((pkt.packet.clone(), pkt.remote_addr));
                pkt.retransmit_count += 1;
                pkt.time_sent = now;
                pkt.lost = false;
            }
        }
        self.unacked_bytes = self.unacked_bytes.saturating_sub(stripped);
        if probe_failed {
            self.mtu_probe_count += 1;
            tracing::debug!(
                failures = self.mtu_probe_count,
                max = MTU_MAX_PROBES,
                only_lost,
                "mtu: probe failed (retransmit)"
            );
            if self.mtu_probe_count >= MTU_MAX_PROBES {
                self.mtu_state = MtuState::SearchComplete;
                self.mtu_probe_wanted = false;
            } else {
                self.mtu_probe_wanted = true;
            }
        }
        retransmits
    }
}

/// Strip MTU probe padding from a packet: remove zero bytes between header and payload,
/// reset data_offset to 0.
fn strip_probe_padding(packet: &mut Vec<u8>) {
    if packet.len() < HEADER_SIZE {
        return;
    }
    let data_offset = packet[3] as usize;
    if data_offset == 0 {
        return;
    }
    let payload_start = HEADER_SIZE + data_offset;
    if payload_start <= packet.len() {
        let payload = packet[payload_start..].to_vec();
        packet.truncate(HEADER_SIZE);
        packet.extend_from_slice(&payload);
    }
    packet[3] = 0;
}

/// Push stream events for a received packet. When both FLAG_DATA and FLAG_END
/// are set (combined packet), pushes Data then End.
fn push_events(events: &mut Vec<StreamEvent>, payload: Vec<u8>, flags: u8) {
    let has_data = flags & FLAG_DATA != 0;
    let has_end = flags & FLAG_END != 0;

    if has_data && !payload.is_empty() {
        events.push(StreamEvent::Data(payload));
    } else if has_data {
        // Empty data packet (e.g., keepalive DATA) — skip
    } else if !has_end {
        // Neither DATA nor END — shouldn't happen, but guard
        return;
    }

    if has_end {
        events.push(StreamEvent::End);
    }
}

// ── WritePrep ────────────────────────────────────────────────────────────────

/// Sequence numbers reserved for one write (or the FIN); `ack_threshold` is
/// one past the last reserved seq.
pub(crate) struct WritePrep {
    pub remote_addr: SocketAddr,
    pub remote_id: u32,
    pub first_seq: u32,
    pub ack_threshold: u32,
    pub current_ack: u32,
}

// ── UdxStream ────────────────────────────────────────────────────────────────

/// A reliable, ordered, bidirectional byte stream over UDP.
///
/// Implements the UDX protocol with BBR congestion control, SACK-based
/// recovery, and RTT-driven retransmission. Multiple streams can share
/// a single [`super::socket::UdxSocket`] via stream ID multiplexing.
pub struct UdxStream {
    local_id: u32,
    pub(crate) inner: Arc<Mutex<StreamInner>>,
    processor: Mutex<Option<tokio::task::JoinHandle<()>>>,
    incoming_tx: Option<mpsc::UnboundedSender<IncomingPacket>>,
    incoming_rx: Mutex<Option<mpsc::UnboundedReceiver<IncomingPacket>>>,
    pub(crate) read_rx: Option<mpsc::UnboundedReceiver<StreamEvent>>,
    close_rx: Option<oneshot::Receiver<()>>,
    /// Stream maps of every socket this stream is registered on, so the
    /// processor's exit and `Drop` can deregister it from all of them.
    registrations: Registrations,
}

impl UdxStream {
    pub(crate) fn new(local_id: u32) -> Self {
        let (read_tx, read_rx) = mpsc::unbounded_channel();
        let (close_tx, close_rx) = oneshot::channel();
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let registrations = Registrations::default();

        let inner = StreamInner {
            remote_id: 0,
            remote_addr: None,
            connected: false,
            terminated: false,
            ended: false,
            next_seq: 0,
            pending_writes: Vec::new(),
            outgoing: BTreeMap::new(),
            queued_bytes: 0,
            unacked_bytes: 0,
            write_waker: None,
            flush_waker: None,
            next_remote_seq: 0,
            remote_acked: 0,
            rack: None,
            recv_buf: BTreeMap::new(),
            srtt: 0,
            rttvar: 0,
            rto: INITIAL_RTO_MS,
            rto_timeouts: 0,
            send_rwnd: DEFAULT_RWND,
            mtu_state: MtuState::Base,
            mtu: MTU_BASE,
            mtu_probe_size: MTU_BASE + MTU_STEP,
            mtu_probe_count: 0,
            mtu_probe_wanted: false,
            mtu_max: MTU_MAX,
            udp: None,
            read_tx,
            close_tx: Some(close_tx),
            notify_tx: None,
            congestion: super::congestion::CongestionController::new(
                crate::native::stream::MAX_PAYLOAD as u32,
                INITIAL_RTO_MS,
            ),
            send_queue: VecDeque::new(),
            relay_target: None,
            firewall_hook: None,
            local_id,
            incoming_tx: Some(incoming_tx.clone()),
            registrations: Arc::clone(&registrations),
            remote_change: None,
            remote_observed: None,
            observed_current_remote: false,
        };

        Self {
            local_id,
            inner: Arc::new(Mutex::new(inner)),
            processor: Mutex::new(None),
            incoming_tx: Some(incoming_tx),
            incoming_rx: Mutex::new(Some(incoming_rx)),
            read_rx: Some(read_rx),
            close_rx: Some(close_rx),
            registrations,
        }
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
        let Some(read_rx) = self.read_rx.take() else {
            return super::async_stream::UdxAsyncStream::new(
                Arc::clone(&self.inner),
                mpsc::unbounded_channel().1,
                None,
                self.close_rx.take(),
            );
        };
        let inner = Arc::clone(&self.inner);
        super::async_stream::UdxAsyncStream::new(inner, read_rx, processor, self.close_rx.take())
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

    /// Returns the current effective MTU (Maximum Transmission Unit) in bytes.
    pub fn effective_mtu(&self) -> usize {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.mtu
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
                inner.connected = true;
                // The hook stays armed: C keeps `on_firewall` for packets
                // that later arrive on another socket.
                let sentinel: SocketAddr = "0.0.0.0:0".parse().unwrap();
                for packet in &mut inner.send_queue {
                    if packet.remote_addr == sentinel {
                        packet.remote_addr = remote_addr;
                    }
                }
                if let Some(tx) = &inner.notify_tx {
                    let _ = tx.send(StreamNotify::DataQueued);
                }
            }
            self.register_on(socket)?;
            tracing::debug!(local_id = self.local_id, remote_id, ?remote_addr, "stream connected (primed)");
            return Ok(());
        }

        let (notify_tx, notify_rx) = mpsc::unbounded_channel();

        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.remote_id = remote_id;
            inner.remote_addr = Some(remote_addr);
            inner.udp = Some(udp);
            inner.connected = true;
            inner.notify_tx = Some(notify_tx);
        }

        self.register_on(socket)?;
        self.start_processor(notify_rx)?;

        tracing::debug!(local_id = self.local_id, remote_id, ?remote_addr, "stream connected");
        Ok(())
    }

    /// Write `data` reliably. Resolves when the remote peer ACKs all packets.
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        let (prep, max_payload, ack_rx) = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let prep = inner.prepare_write(data.len())?;
            let ack_rx = inner.watch_ack(prep.ack_threshold);
            (prep, inner.max_payload(), ack_rx)
        };
        let packets = build_data_packets(&prep, data, max_payload);
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .queue_write(packets, prep.remote_addr);

        ack_rx.await.map_err(|_| UdxError::StreamClosed)?
    }

    /// Read the next message. Returns `None` on EOF or stream close.
    pub async fn read(&mut self) -> Result<Option<Vec<u8>>> {
        let rx = self.read_rx.as_mut().ok_or(UdxError::StreamClosed)?;
        match rx.recv().await {
            Some(StreamEvent::Data(d)) => Ok(Some(d)),
            Some(StreamEvent::End) => {
                self.read_rx = None;
                Ok(None)
            }
            None => {
                self.read_rx = None;
                Ok(None)
            }
        }
    }

    /// Send a write-end (FIN) and wait for the remote peer to ACK it.
    pub async fn shutdown(&self) -> Result<()> {
        let ack_rx = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let prep = inner.prepare_end()?;
            let ack_rx = inner.watch_ack(prep.ack_threshold);
            inner.queue_write(vec![(prep.first_seq, build_end_packet(&prep))], prep.remote_addr);
            ack_rx
        };

        ack_rx.await.map_err(|_| UdxError::StreamClosed)?
    }

    /// Set up packet-level relay forwarding to `destination`.
    ///
    /// Both streams must be on the same runtime. Relayed packets bypass
    /// congestion control — only the `remote_id` header field is rewritten.
    pub fn relay_to(&self, destination: &UdxStream) -> Result<()> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.relay_target = Some(Arc::clone(&destination.inner));
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
            inner.remote_id = remote_id;
            inner.udp = Some(udp);
            inner.notify_tx = Some(notify_tx);
            inner.firewall_hook = Some(Box::new(hook));
        }

        self.register_on(socket)?;
        self.start_processor(notify_rx)?;

        tracing::debug!(local_id = self.local_id, remote_id, "stream listening (firewall hook set)");
        Ok(())
    }

    /// Also receive on `socket` while the firewall hook is armed, so the peer
    /// may reach this stream on more than one of our sockets (a holepunch
    /// socket and the DHT socket, say). The hook commits whichever socket
    /// the accepted packet arrives on.
    pub fn listen_on(&self, socket: &super::socket::UdxSocket) -> Result<()> {
        if self.inner.lock().unwrap_or_else(|e| e.into_inner()).firewall_hook.is_none() {
            return Err(UdxError::Io(std::io::Error::other("stream has no firewall hook")));
        }
        self.register_on(socket)
    }

    /// Register for `socket`'s demux and remember the map for deregistration.
    fn register_on(&self, socket: &super::socket::UdxSocket) -> Result<()> {
        let tx = self
            .incoming_tx
            .as_ref()
            .ok_or_else(|| UdxError::Io(std::io::Error::other("stream already consumed")))?
            .clone();
        socket.register_stream(self.local_id, tx)?;
        self.registrations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(socket.streams_ref());
        Ok(())
    }

    /// Spawn the processor task; it deregisters the stream when it exits.
    fn start_processor(&self, notify_rx: mpsc::UnboundedReceiver<StreamNotify>) -> Result<()> {
        let incoming_rx = self
            .incoming_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| UdxError::Io(std::io::Error::other("processor already started")))?;
        let inner = Arc::clone(&self.inner);
        let registrations = Arc::clone(&self.registrations);
        let local_id = self.local_id;
        let handle = tokio::spawn(async move {
            process_incoming(inner, incoming_rx, notify_rx).await;
            deregister(local_id, &registrations);
        });
        *self.processor.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
        Ok(())
    }

    /// Destroy the stream, sending a DESTROY packet to the remote peer.
    pub async fn destroy(mut self) -> Result<()> {
        let destroy_info = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.connected {
                inner.udp.clone().zip(inner.remote_addr).map(|(udp, addr)| {
                    let header = Header {
                        type_flags: FLAG_DESTROY,
                        data_offset: 0,
                        remote_id: inner.remote_id,
                        recv_window: 0,
                        seq: inner.next_seq,
                        ack: inner.next_remote_seq,
                    };
                    (udp, addr, header)
                })
            } else {
                None
            }
        };

        if let Some((udp, addr, header)) = destroy_info {
            let _ = udp.send_to(&header.encode(), addr).await;
        }

        let processor_handle = self
            .processor
            .lock()
            .ok()
            .and_then(|mut g| g.take());
        if let Some(handle) = processor_handle {
            handle.abort();
            let _ = handle.await;
        }

        self.incoming_tx = None;

        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.terminate();
            if let Some(tx) = inner.close_tx.take() {
                let _ = tx.send(());
            }
        }

        deregister(self.local_id, &self.registrations);

        tracing::debug!(local_id = self.local_id, "stream destroyed");
        Ok(())
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

    /// Send DESTROY to the peer, fail pending writes and turn reads into EOF.
    pub fn abort(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.connected {
            if let (Some(udp), Some(addr)) = (inner.udp.clone(), inner.remote_addr) {
                let header = Header {
                    type_flags: FLAG_DESTROY,
                    data_offset: 0,
                    remote_id: inner.remote_id,
                    recv_window: 0,
                    seq: inner.next_seq,
                    ack: inner.next_remote_seq,
                };
                tokio::spawn(async move {
                    let _ = udp.send_to(&header.encode(), addr).await;
                });
            }
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
        !self.inner.lock().unwrap_or_else(|e| e.into_inner()).terminated
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
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).remote_addr
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
        let (local_id, incoming_tx, registrations, done) = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !inner.connected || !inner.is_alive() {
                return Err(UdxError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "stream not connected",
                )));
            }
            if inner.remote_change.is_some() {
                return Err(UdxError::Io(std::io::Error::other("remote already changing")));
            }
            inner.remote_id = remote_id;
            inner.remote_addr = Some(remote_addr);
            inner.observed_current_remote = false;
            inner.udp = Some(udp);
            // Not sent yet, so bound to the remote at send time as in C.
            for queued in &mut inner.send_queue {
                queued.remote_addr = remote_addr;
                queued.packet[4..8].copy_from_slice(&remote_id.to_le_bytes());
            }
            inner.reset_mtu();
            let done = inner.outgoing.keys().next_back().copied().map(|last| {
                let (tx, rx) = oneshot::channel();
                inner.remote_change = Some((last.wrapping_add(1), tx));
                rx
            });
            let incoming_tx = inner.incoming_tx.clone().ok_or(UdxError::StreamClosed)?;
            (inner.local_id, incoming_tx, Arc::clone(&inner.registrations), done)
        };
        socket.register_stream(local_id, incoming_tx)?;
        registrations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(socket.streams_ref());
        tracing::debug!(local_id, remote_id, ?remote_addr, deferred = done.is_some(), "change_remote");
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
            recv_window: DEFAULT_RWND,
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
}

impl Drop for UdxStream {
    fn drop(&mut self) {
        if self.read_rx.is_some() {
            self.inner.lock().unwrap_or_else(|e| e.into_inner()).terminate();
        }
        if let Ok(mut guard) = self.processor.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        deregister(self.local_id, &self.registrations);
    }
}

// ── Processor task (reliability engine) ──────────────────────────────────────

async fn process_incoming(
    inner: Arc<Mutex<StreamInner>>,
    mut incoming_rx: mpsc::UnboundedReceiver<IncomingPacket>,
    mut notify_rx: mpsc::UnboundedReceiver<StreamNotify>,
) {
    use tokio::time::{self, Duration, Instant as TokioInstant};

    let mut shutting_down = false;

    // RTO timer starts far in the future (no data in flight initially).
    let rto_sleep = time::sleep(FAR_FUTURE);
    tokio::pin!(rto_sleep);

    let pacing_sleep = time::sleep(FAR_FUTURE);
    tokio::pin!(pacing_sleep);

    let mut keepalive = time::interval(Duration::from_millis(HEARTBEAT_INTERVAL_MS));
    keepalive.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // ── Incoming packet processing ───────────────────────────
            packet = incoming_rx.recv() => {
                let Some(packet) = packet else { break };

                // ── Header decode (early — defense in depth) ─────────
                // The socket-layer demux (`UdxSocket::ensure_recv_loop`) only
                // routes packets whose header magic+version pass `Header::decode`,
                // so reaching this point implies a well-formed UDX header.
                let header = match Header::decode(&packet.data) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                // ── Firewall hook: commit peer and socket ───────────────
                // C libudx udx.c:1643-1650 consults the hook while the
                // stream has no socket and for packets arriving on another
                // socket than the stream's; the source address never
                // matters. An unconnected stream commits to the accepted
                // packet's socket and address; a connected one just lets the
                // packet through (the owner may `change_remote` to it).
                {
                    let (is_connected, foreign) = {
                        let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        let same = match (&guard.udp, packet.socket.udp_arc().ok()) {
                            (Some(ours), Some(arrival)) => Arc::ptr_eq(ours, &arrival),
                            _ => false,
                        };
                        (guard.connected, !guard.connected || !same)
                    };
                    if foreign {
                        let hook = inner.lock().unwrap_or_else(|e| e.into_inner()).firewall_hook.take();
                        match hook {
                            Some(mut hook) => {
                                let accepted = hook(&packet.socket, packet.addr.port(), packet.addr.ip());
                                inner.lock().unwrap_or_else(|e| e.into_inner()).firewall_hook = Some(hook);
                                if !accepted {
                                    tracing::debug!(addr = ?packet.addr, "firewall hook: rejected");
                                    continue;
                                }
                                if !is_connected {
                                    let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                                    guard.remote_addr = Some(packet.addr);
                                    guard.udp = packet.socket.udp_arc().ok();
                                    guard.connected = true;
                                    // Patch any packets queued before the hook fired
                                    // (they were staged with the 0.0.0.0:0 sentinel).
                                    let sentinel: std::net::SocketAddr =
                                        "0.0.0.0:0".parse().unwrap();
                                    for qp in &mut guard.send_queue {
                                        if qp.remote_addr == sentinel {
                                            qp.remote_addr = packet.addr;
                                        }
                                    }
                                    if let Some(tx) = &guard.notify_tx {
                                        let _ = tx.send(StreamNotify::DataQueued);
                                    }
                                    tracing::debug!(addr = ?packet.addr, "firewall hook: accepted");
                                }
                            }
                            // No hook: C processes the packet; an unconnected
                            // stream has nowhere to send replies, so drop it.
                            None if !is_connected => continue,
                            None => {}
                        }
                    }
                }

                // ── Peer seen on the current path (after `change_remote`) ──
                {
                    let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    // Out-of-order data does not prove the old path has drained.
                    let observed = header.has_flag(FLAG_MESSAGE)
                        || (header.has_flag(FLAG_DATA) && header.seq == guard.next_remote_seq);
                    if observed && guard.remote_addr == Some(packet.addr) {
                        let same = match (&guard.udp, packet.socket.udp_arc().ok()) {
                            (Some(ours), Some(arrival)) => Arc::ptr_eq(ours, &arrival),
                            _ => false,
                        };
                        if same {
                            guard.observed_current_remote = true;
                            if let Some(tx) = guard.remote_observed.take() {
                                let _ = tx.send(());
                            }
                        }
                    }
                }

                // ── Relay fast-path ──────────────────────────────
                //
                // Deliberately placed *after* the firewall-hook gate above,
                // not before it: a relay-bridged stream is typically wired
                // up with both `set_firewall_hook` (to learn its own real
                // 4-tuple from the first packet its owner sends) and
                // `relay_to` (to forward everything to its paired stream)
                // configured before any packets arrive. If this fast-path
                // ran first unconditionally, it would `continue` past the
                // firewall-hook gate on every packet forever — the hook
                // would never fire, `remote_addr`/`connected` would never
                // be set, and (since the *destination* stream in a pair has
                // the exact same problem simultaneously) neither side of a
                // relayed pairing could ever adopt its real address, so
                // nothing would ever forward (observed empirically: both
                // ends of a blind-relay pairing retransmitted until RTO
                // exhaustion with zero bytes ever bridged). Running the
                // hook gate first lets the triggering packet commit this
                // stream's 4-tuple, and *this same packet* still gets
                // relayed below rather than being absorbed into normal
                // (unread) stream processing.
                let relay_info = {
                    let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    guard.relay_target.as_ref().map(|target| {
                        let tgt = target.lock().unwrap_or_else(|e| e.into_inner());
                        (tgt.remote_id, tgt.remote_addr, tgt.udp.clone())
                    })
                };

                if let Some((dest_remote_id, dest_addr, dest_udp)) = relay_info {
                    let mut fwd = packet.data;
                    if fwd.len() >= 8 {
                        fwd[4..8].copy_from_slice(&dest_remote_id.to_le_bytes());
                    }
                    if let (Some(udp), Some(addr)) = (dest_udp, dest_addr) {
                        let _ = udp.send_to(&fwd, addr).await;
                    }
                    if fwd.len() > 2 && fwd[2] & FLAG_DESTROY != 0 {
                        tracing::debug!("relay: DESTROY received, closing relay stream");
                        let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(tx) = guard.close_tx.take() {
                            let _ = tx.send(());
                        }
                        break;
                    }
                    continue;
                }

                tracing::trace!(
                    flags = header.type_flags,
                    seq = header.seq,
                    ack = header.ack,
                    data_offset = header.data_offset,
                    "process_incoming: received packet"
                );

                // ── ACK + SACK processing ────────────────────────────
                let has_ack = header.ack > 0;
                // Decode SACK ranges from wire format (outside lock). C libudx
                // sends them with data_offset = 0, so the region is derived
                // from the packet length, not from data_offset alone.
                let sack_ranges = header
                    .sack_region(packet.data.len())
                    .and_then(|region| decode_sack(&packet.data[region]).ok());

                if has_ack || sack_ranges.is_some() {
                    let (completed, outgoing_empty, ack_advanced, fast_retransmits, udp_for_retransmit) = {
                        let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        guard.send_rwnd = header.recv_window;
                        let prev_acked = guard.remote_acked;

                        let (write_completions, mut acked_rate_info) = if has_ack {
                            guard.on_cumulative_ack(header.ack)
                        } else {
                            (Vec::new(), Vec::new())
                        };

                        if let Some(ranges) = &sack_ranges {
                            let sack_info = guard.on_sack(ranges);
                            acked_rate_info.extend(sack_info);
                        }

                        let lost_count = guard.detect_losses();

                        if !acked_rate_info.is_empty() || lost_count > 0 {
                            let inflight = guard.inflight();
                            let now = Instant::now();
                            guard.congestion.on_ack(&acked_rate_info, lost_count, inflight, now);
                        }

                        let retransmits = guard.collect_retransmits(true);
                        let udp = guard.udp.clone();

                        let empty = guard.outgoing.is_empty();
                        let advanced = guard.remote_acked != prev_acked;
                        (write_completions, empty, advanced, retransmits, udp)
                    };

                    // Notify completed writes (outside lock)
                    for tx in completed.into_iter().flatten() {
                        let _ = tx.send(Ok(()));
                    }

                    // Fast retransmit lost packets (outside lock)
                    if let Some(udp) = udp_for_retransmit {
                        for (packet_bytes, dest) in fast_retransmits {
                            let udp = Arc::clone(&udp);
                            tokio::spawn(async move {
                                let _ = udp.send_to(&packet_bytes, dest).await;
                            });
                        }
                    }

                    // Re-arm the RTO only when the cumulative ACK advanced
                    // (C `arm_rto_or_tlp = ack_advanced && data_inflight`,
                    // RFC 6298 5.3); dup/SACK-only/heartbeat ACKs leave it.
                    if outgoing_empty {
                        rto_sleep.as_mut().reset(TokioInstant::now() + FAR_FUTURE);
                    } else if ack_advanced {
                        let rto = inner.lock().unwrap_or_else(|e| e.into_inner()).rto as u64;
                        rto_sleep.as_mut().reset(
                            TokioInstant::now() + Duration::from_millis(rto),
                        );
                    }

                    {
                        let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        if !guard.send_queue.is_empty() {
                            drop(guard);
                            pacing_sleep.as_mut().reset(TokioInstant::now());
                        }
                    }
                } else {
                    // No ACK/SACK — still update recv window
                    let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    guard.send_rwnd = header.recv_window;
                }

                // ── DATA / END processing (unified — handles combined DATA+END packets) ──
                let is_data = header.has_flag(FLAG_DATA);
                let is_end = header.has_flag(FLAG_END);
                if is_data || is_end {
                    let payload_start = header.payload_offset();
                    let payload = if payload_start <= packet.data.len() {
                        packet.data[payload_start..].to_vec()
                    } else {
                        Vec::new()
                    };
                    let recv_flags = (if is_data { FLAG_DATA } else { 0 })
                        | (if is_end { FLAG_END } else { 0 });

                    let (events, read_tx, udp, remote_addr, remote_id, ack_val, sack_ranges) = {
                        let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        let events = guard.receive_data(header.seq, payload, recv_flags);
                        let sacks = guard.sack_ranges();
                        let ack_val = guard.next_remote_seq;
                        (
                            events,
                            guard.read_tx.clone(),
                            guard.udp.clone(),
                            guard.remote_addr,
                            guard.remote_id,
                            ack_val,
                            sacks,
                        )
                    };
                    for event in events {
                        let _ = read_tx.send(event);
                    }
                    send_ack(&udp, remote_addr, remote_id, ack_val, &sack_ranges);
                }

                // ── DESTROY processing ───────────────────────────────
                if header.has_flag(FLAG_DESTROY) {
                    let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    let _ = guard.read_tx.send(StreamEvent::End);
                    if let Some(tx) = guard.close_tx.take() {
                        let _ = tx.send(());
                    }
                    break;
                }

                // ── HEARTBEAT response ───────────────────────────────
                if header.has_flag(FLAG_HEARTBEAT) {
                    let (udp, remote_addr, remote_id, ack_val) = {
                        let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        (
                            guard.udp.clone(),
                            guard.remote_addr,
                            guard.remote_id,
                            guard.next_remote_seq,
                        )
                    };
                    send_ack(&udp, remote_addr, remote_id, ack_val, &[]);
                }
            }

            Some(notify) = notify_rx.recv() => {
                match notify {
                    StreamNotify::DataQueued => {
                        pacing_sleep.as_mut().reset(TokioInstant::now());
                    }
                    StreamNotify::Shutdown => {
                        shutting_down = true;
                        pacing_sleep.as_mut().reset(TokioInstant::now());
                    }
                }
            }

            _ = &mut pacing_sleep => {
                let (packets_to_send, should_arm_rto, new_rto_ms) = {
                    let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    let mut batch: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
                    let was_outgoing_empty = guard.outgoing.is_empty();
                    // A hooked stream has no peer until its first packet
                    // commits one (C `udx_stream_write` is ENOTCONN before
                    // that): sending now would address 0.0.0.0:0 and lose
                    // the packets for good, retransmits included.
                    while guard.connected && !guard.send_queue.is_empty() {
                        let inflight = guard.inflight() + batch.len() as u32;
                        let queued_bytes = guard.queued_bytes;
                        guard.congestion.check_app_limited(queued_bytes, inflight);

                        if !guard.congestion.can_send(inflight, guard.send_rwnd) {
                            break;
                        }

                        let now = std::time::Instant::now();
                        let delay = guard.congestion.pacing_delay(now);
                        if delay > std::time::Duration::ZERO {
                            pacing_sleep.as_mut().reset(TokioInstant::now() + delay);
                            break;
                        }

                        let Some(queued) = guard.pop_queued() else {
                            break;
                        };
                        let mut packet = queued.packet;

                        let is_data = packet.len() >= HEADER_SIZE && packet[2] & FLAG_DATA != 0;
                        if is_data && guard.mtu_state == MtuState::Base {
                            guard.mtu_state = MtuState::Search;
                            guard.mtu_probe_wanted = true;
                        }

                        // No probes while old-path packets are still in
                        // flight (C udx.c:846).
                        let is_mtu_probe = if is_data
                            && guard.mtu_state == MtuState::Search
                            && guard.mtu_probe_wanted
                            && guard.remote_change.is_none()
                        {
                            guard.mtu_probeify_packet(&mut packet)
                        } else {
                            false
                        };

                        guard.register_sent(queued.seq, packet.clone(), queued.remote_addr, is_mtu_probe);
                        guard.congestion.pacing.try_consume(
                            packet.len() as u32, std::time::Instant::now(),
                        );
                        batch.push((packet, queued.remote_addr));
                    }

                    let should_arm = was_outgoing_empty && !guard.outgoing.is_empty();
                    let rto = guard.rto as u64;
                    (batch, should_arm, rto)
                };

                let udp_clone = {
                    let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    guard.udp.clone()
                };
                if let Some(udp) = udp_clone {
                    for (pkt, addr) in &packets_to_send {
                        let _ = udp.send_to(pkt, *addr).await;
                    }
                }

                if should_arm_rto {
                    rto_sleep.as_mut().reset(
                        TokioInstant::now() + Duration::from_millis(new_rto_ms),
                    );
                }

                // The hook's `DataQueued` notify re-arms pacing once connected.
                let has_more = {
                    let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    guard.connected && !guard.send_queue.is_empty()
                };
                if shutting_down && !has_more {
                    break;
                }
                if has_more {
                    pacing_sleep.as_mut().reset(TokioInstant::now() + Duration::from_millis(1));
                } else {
                    pacing_sleep.as_mut().reset(TokioInstant::now() + FAR_FUTURE);
                }
            }

            _ = &mut rto_sleep => {
                let (retransmits, udp, new_rto, should_close) = {
                    let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());

                    if guard.outgoing.is_empty() {
                        // False alarm — nothing to retransmit
                        rto_sleep.as_mut().reset(TokioInstant::now() + FAR_FUTURE);
                        continue;
                    }

                    guard.rto_timeouts += 1;

                    if guard.rto_timeouts >= MAX_RTO_TIMEOUTS {
                        // Exceeded max timeouts — fail the stream
                        (Vec::new(), None, 0u64, true)
                    } else {
                        guard.congestion.on_rto();
                        if let Some(&max_seq) = guard.outgoing.keys().last() {
                            guard.congestion.high_seq = max_seq;
                        }
                        guard.rto = (guard.rto * 2).min(MAX_RTO_MS);
                        let retransmits = guard.collect_retransmits(false);
                        let rto = guard.rto as u64;
                        (retransmits, guard.udp.clone(), rto, false)
                    }
                };

                if should_close {
                    // Fail all pending writes with timeout error
                    let pending: Vec<_> = {
                        let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                        std::mem::take(&mut guard.pending_writes)
                    };
                    for mut pw in pending {
                        if let Some(tx) = pw.tx.take() {
                            let _ = tx.send(Err(UdxError::Io(
                                std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "RTO timeout exceeded",
                                ),
                            )));
                        }
                    }
                    tracing::warn!("stream failed: exceeded max RTO timeouts");
                    break;
                }

                // Retransmit unACKed/unSACKed packets
                if let Some(udp) = udp {
                    tracing::debug!(
                        count = retransmits.len(),
                        rto_ms = new_rto,
                        "retransmitting packets"
                    );
                    for (packet_bytes, dest) in retransmits {
                        let udp = Arc::clone(&udp);
                        tokio::spawn(async move {
                            let _ = udp.send_to(&packet_bytes, dest).await;
                        });
                    }
                }

                // Schedule next RTO check
                rto_sleep.as_mut().reset(
                    TokioInstant::now() + Duration::from_millis(new_rto),
                );
            }

            // ── Keepalive heartbeat ──────────────────────────────────
            _ = keepalive.tick() => {
                let (should_send, udp, addr, remote_id, ack_val) = {
                    let guard = inner.lock().unwrap_or_else(|e| e.into_inner());
                    if guard.connected && guard.outgoing.is_empty() && guard.relay_target.is_none() {
                        (
                            true,
                            guard.udp.clone(),
                            guard.remote_addr,
                            guard.remote_id,
                            guard.next_remote_seq,
                        )
                    } else {
                        (false, None, None, 0, 0)
                    }
                };

                if should_send {
                    if let (Some(udp), Some(addr)) = (udp, addr) {
                        let header = Header {
                            type_flags: FLAG_HEARTBEAT,
                            data_offset: 0,
                            remote_id,
                            recv_window: DEFAULT_RWND,
                            seq: 0,
                            ack: ack_val,
                        };
                        let packet = header.encode();
                        tokio::spawn(async move {
                            let _ = udp.send_to(&packet, addr).await;
                        });
                    }
                }
            }
        }
    }

    inner.lock().unwrap_or_else(|e| e.into_inner()).terminate();
}

// ── Packet building ──────────────────────────────────────────────────────────

/// Build a wire-format DATA packet (header + payload).
pub(crate) fn build_data_packet(
    remote_id: u32,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Vec<u8> {
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

/// Chunk `data` into the DATA packets reserved by `prep` (one empty packet
/// for an empty write).
pub(crate) fn build_data_packets(
    prep: &WritePrep,
    data: &[u8],
    max_payload: usize,
) -> Vec<(u32, Vec<u8>)> {
    let chunks: Vec<&[u8]> = if data.is_empty() {
        vec![&[]]
    } else {
        data.chunks(max_payload).collect()
    };
    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let seq = prep.first_seq + i as u32;
            (seq, build_data_packet(prep.remote_id, seq, prep.current_ack, chunk))
        })
        .collect()
}

/// Build the FIN packet reserved by `prepare_end`.
pub(crate) fn build_end_packet(prep: &WritePrep) -> Vec<u8> {
    Header {
        type_flags: FLAG_END,
        data_offset: 0,
        remote_id: prep.remote_id,
        recv_window: DEFAULT_RWND,
        seq: prep.first_seq,
        ack: prep.current_ack,
    }
    .encode()
    .to_vec()
}

// ── send_ack ─────────────────────────────────────────────────────────────────

/// Send an ACK packet, optionally including SACK ranges.
///
/// SACK blocks follow the header. C libudx reads them from `data_offset`
/// bytes when that is set, else from the whole body (it always sends
/// `data_offset = 0`); we set `data_offset` while it fits in a byte so older
/// Rust peers keep parsing, and fall back to `0` beyond 31 ranges.
fn send_ack(
    udp: &Option<Arc<tokio::net::UdpSocket>>,
    remote_addr: Option<SocketAddr>,
    remote_id: u32,
    ack: u32,
    sack_ranges: &[SackRange],
) {
    let (Some(udp), Some(addr)) = (udp.as_ref(), remote_addr) else {
        return;
    };
    let udp = Arc::clone(udp);
    let sack_byte_len = sack_ranges.len() * 8;
    let header = Header {
        type_flags: if sack_ranges.is_empty() { 0 } else { FLAG_SACK },
        data_offset: u8::try_from(sack_byte_len).unwrap_or(0),
        remote_id,
        recv_window: DEFAULT_RWND,
        seq: 0,
        ack,
    };
    let mut packet = vec![0u8; HEADER_SIZE + sack_byte_len];
    header.encode_into(&mut packet[..HEADER_SIZE]);
    encode_sack(sack_ranges, &mut packet[HEADER_SIZE..]);
    tokio::spawn(async move {
        let _ = udp.send_to(&packet, addr).await;
    });
}

#[cfg(test)]
mod mtu_tests {
    use super::*;

    fn make_stream_inner() -> StreamInner {
        let (read_tx, _read_rx) = mpsc::unbounded_channel();
        StreamInner {
            remote_id: 0,
            remote_addr: None,
            connected: false,
            terminated: false,
            next_seq: 0,
            pending_writes: Vec::new(),
            outgoing: BTreeMap::new(),
            queued_bytes: 0,
            unacked_bytes: 0,
            write_waker: None,
            flush_waker: None,
            next_remote_seq: 0,
            remote_acked: 0,
            rack: None,
            recv_buf: BTreeMap::new(),
            srtt: 0,
            rttvar: 0,
            rto: INITIAL_RTO_MS,
            rto_timeouts: 0,
            send_rwnd: DEFAULT_RWND,
            mtu_state: MtuState::Base,
            mtu: MTU_BASE,
            mtu_probe_size: MTU_BASE + MTU_STEP,
            mtu_probe_count: 0,
            mtu_probe_wanted: false,
            mtu_max: MTU_MAX,
            udp: None,
            read_tx,
            close_tx: None,
            notify_tx: None,
            congestion: crate::native::congestion::CongestionController::new(
                MAX_PAYLOAD as u32,
                INITIAL_RTO_MS,
            ),
            send_queue: VecDeque::new(),
            relay_target: None,
            ended: false,
            firewall_hook: None,
            local_id: 0,
            incoming_tx: None,
            registrations: Registrations::default(),
            remote_change: None,
            remote_observed: None,
            observed_current_remote: false,
        }
    }

    // T3: MTU state starts at BASE
    #[test]
    fn mtu_initial_state_is_base() {
        let inner = make_stream_inner();
        assert_eq!(inner.mtu_state, MtuState::Base);
        assert_eq!(inner.mtu, MTU_BASE);
        assert!(!inner.mtu_probe_wanted);
        assert_eq!(inner.mtu_probe_count, 0);
        assert_eq!(inner.mtu_probe_size, MTU_BASE + MTU_STEP);
        assert_eq!(inner.mtu_max, MTU_MAX);
    }

    // T5: MTU probe failure falls back gracefully — retransmit strips padding and increments failure count
    #[test]
    fn mtu_probe_failure_fallback() {
        let mut inner = make_stream_inner();
        inner.mtu_state = MtuState::Search;
        inner.mtu = MTU_BASE;

        let payload = vec![0xABu8; MTU_BASE - HEADER_SIZE];
        let packet = build_data_packet(0, 0, 0, &payload);
        inner.outgoing.insert(0, SentPacket {
            packet,
            remote_addr: "0.0.0.0:0".parse().unwrap(),
            time_sent: Instant::now(),
            retransmit_count: 0,
            sacked: false,
            is_mtu_probe: true,
            lost: false,
            rate_info: None,
        });

        let retransmits = inner.collect_retransmits(false);
        assert_eq!(retransmits.len(), 1);
        assert_eq!(inner.mtu_probe_count, 1);
        assert!(!inner.outgoing[&0].is_mtu_probe, "probe flag should be cleared after retransmit");
        assert_eq!(inner.outgoing[&0].packet[3], 0, "data_offset should be reset");
        assert_eq!(inner.mtu_state, MtuState::Search, "still searching after 1 failure");
        assert!(inner.mtu_probe_wanted, "should want another probe after non-terminal failure");
    }

    // T6: Probe uses data_offset padding — probeify inflates packet to probe size
    #[test]
    fn mtu_probe_uses_data_offset_padding() {
        let mut inner = make_stream_inner();
        inner.mtu_state = MtuState::Search;
        inner.mtu_probe_size = MTU_BASE + MTU_STEP;

        let payload = vec![0xCDu8; MTU_BASE - HEADER_SIZE];
        let mut packet = build_data_packet(0, 0, 0, &payload);
        let original_len = packet.len();
        assert_eq!(original_len, MTU_BASE);

        let ok = inner.mtu_probeify_packet(&mut packet);
        assert!(ok, "probeify should succeed for nearly-full packet");
        assert_eq!(packet.len(), MTU_BASE + MTU_STEP, "packet should be inflated to probe size");
        assert_eq!(packet[3] as usize, MTU_STEP, "data_offset should equal padding size");

        let payload_start = HEADER_SIZE + MTU_STEP;
        assert_eq!(&packet[payload_start..], &payload[..], "original payload should be intact after padding");
    }

    /// A SACK block spanning the whole sequence space (one 28-byte packet
    /// from anyone who knows the stream id) must cost work proportional to
    /// the packets in flight, and inverted blocks must be ignored.
    #[test]
    fn sack_ranges_are_bounded_by_outgoing() {
        let mut inner = make_stream_inner();
        for seq in [5u32, 6, 9] {
            inner.register_sent(seq, build_data_packet(0, seq, 0, b"x"), "0.0.0.0:0".parse().unwrap(), false);
        }

        let started = Instant::now();
        let sacked = inner.on_sack(&[
            SackRange { start: 9, end: 6 },
            SackRange { start: 0, end: 0xFFFF_FFFF },
        ]);
        assert!(started.elapsed() < std::time::Duration::from_millis(100), "SACK walk is not bounded");

        let seqs: Vec<u32> = sacked.iter().map(|(seq, _)| *seq).collect();
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
        assert_eq!(inner.mtu_state, MtuState::Search, "still searching — haven't reached max");
    }

    // T8: MTU_MAX_PROBES consecutive failures → SearchComplete
    #[test]
    fn mtu_max_probe_failures_completes_search() {
        let mut inner = make_stream_inner();
        inner.mtu_state = MtuState::Search;
        inner.mtu = MTU_BASE + MTU_STEP;

        for i in 0..MTU_MAX_PROBES {
            let payload = vec![0xEFu8; MTU_BASE - HEADER_SIZE];
            let packet = build_data_packet(0, i, 0, &payload);
            inner.outgoing.insert(i, SentPacket {
                packet,
                remote_addr: "0.0.0.0:0".parse().unwrap(),
                time_sent: Instant::now(),
                retransmit_count: 0,
                sacked: false,
                is_mtu_probe: true,
                lost: false,
                rate_info: None,
            });

            let _ = inner.collect_retransmits(false);
        }

        assert_eq!(inner.mtu_state, MtuState::SearchComplete);
        assert!(!inner.mtu_probe_wanted);
        assert_eq!(inner.mtu, MTU_BASE + MTU_STEP, "MTU frozen at last successful value");
    }
}

#[cfg(test)]
mod abort_tests {
    use super::*;
    use std::time::Duration;

    /// `abort` must stop the processor task, not just disconnect the stream:
    /// the task owns a clone of `StreamInner`, so a task that keeps running
    /// (ticking its keepalive) pins the stream for the life of the process.
    #[tokio::test]
    async fn abort_ends_the_processor_task() {
        let runtime = crate::UdxRuntime::new().expect("runtime");
        let socket = runtime.create_socket().await.expect("socket");
        socket.bind("127.0.0.1:0".parse().unwrap()).await.expect("bind");
        let peer = runtime.create_socket().await.expect("peer socket");
        peer.bind("127.0.0.1:0".parse().unwrap()).await.expect("peer bind");
        let peer_addr = peer.local_addr().await.expect("peer addr");

        let stream = runtime.create_stream(1).await.expect("stream");
        stream.connect(&socket, 2, peer_addr).await.expect("connect");

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
}

