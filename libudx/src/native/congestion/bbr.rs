//! BBRv3 congestion control state machine (`draft-ietf-ccwg-bbr`) with
//! microsecond resolution.
//!
//! Wire-compatible with UDX v1 peers (pure sender-side congestion control):
//! - Microsecond RTT, delivery-rate, and pacing calculations so sub-ms LAN
//!   paths and high-BDP WAN paths are modeled accurately.
//! - Loss-aware `inflight_hi` and short-term lower bounds (`bw_lo`,
//!   `inflight_lo`, `beta = 0.7`, `loss_thresh = 2%`, `headroom = 15%`) so
//!   shallow-buffer bottlenecks do not suffer standing queues and chronic
//!   retransmit storms, while ignoring isolated <2% random loss.
//! - Startup exits early on high loss (>= 2% with >= 6 losses in a round)
//!   instead of overflowing bottleneck buffers for three full RTTs.
//! - Four-phase `ProbeBW` (`Down`, `Cruise`, `Refill`, `Up`) with gentler
//!   0.90 drain gain and bounded probe wait so coexistence with both CUBIC
//!   and stock BBRv1 peers stays fair.
//! - `ProbeRTT` keeps `max(4, 0.5 * BDP)` packets in flight instead of
//!   crushing cwnd to 4 packets, avoiding periodic stalls during video streams.

use super::{
    BBR_BETA, BBR_BW_FILTER_ROUNDS, BBR_CWND_GAIN, BBR_CWND_MIN_TARGET, BBR_DRAIN_GAIN,
    BBR_EXTRA_ACKED_GAIN, BBR_EXTRA_ACKED_MAX_US, BBR_EXTRA_ACKED_WIN_RTTS, BBR_FULL_BW_COUNT,
    BBR_FULL_BW_THRESH, BBR_FULL_LOSS_CNT, BBR_HEADROOM, BBR_LOSS_THRESH, BBR_MIN_RTT_INTERVAL_US,
    BBR_PACING_MARGIN_PERCENT, BBR_PROBE_BW_CRUISE_GAIN, BBR_PROBE_BW_DOWN_GAIN,
    BBR_PROBE_BW_REFILL_GAIN, BBR_PROBE_BW_UP_GAIN, BBR_PROBE_RTT_CWND_GAIN,
    BBR_PROBE_RTT_INTERVAL_US, BBR_PROBE_RTT_MODE_US, BBR_STARTUP_CWND_GAIN,
    BBR_STARTUP_PACING_GAIN, BbrMode, CaState, filter::WinFilter, rate::RateSample,
};

/// Probe wait bounds in `ProbeBwCruise` (microseconds). Keeps probing on an
/// ~6–8 RTT cadence (150–400 ms) so queues stay shallow on constrained paths
/// without letting loss-ignoring BBRv1 peers starve the flow.
const PROBE_WAIT_MIN_US: u64 = 150_000;
const PROBE_WAIT_MAX_US: u64 = 400_000;

/// Four phases of BBRv3's `ProbeBW` state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeBwPhase {
    /// Drain excess queue at `0.90x` pacing gain.
    Down,
    /// Cruise at `1.0x` pacing gain with headroom below `inflight_hi`.
    Cruise,
    /// Refill pipe for 1 RTT at `1.0x` before probing upward.
    Refill,
    /// Probe for higher bandwidth at `1.25x` pacing gain.
    Up,
}

/// The stream state BBR reads and the window it writes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Link {
    /// Congestion window in packets; BBR may change it.
    pub(crate) cwnd: u32,
    /// Payload bytes per packet.
    pub(crate) mss: u32,
    /// Packets delivered so far.
    pub(crate) delivered: u32,
    /// When `delivered` last grew (µs).
    pub(crate) delivered_ts_us: u64,
    /// Smoothed RTT in microseconds, 0 before a sample.
    pub(crate) srtt_us: u64,
    /// Packets in flight.
    pub(crate) inflight: u32,
    pub(crate) ca_state: CaState,
    /// Now, in microseconds on the stream clock.
    pub(crate) now_us: u64,
}

/// Full BBRv3 state machine.
///
/// Unit conventions: BW = packets/µs, CWND = packets, pacing = bytes/sec.
#[derive(Debug, Clone)]
pub(crate) struct BbrState {
    mode: BbrMode,
    probe_bw_phase: ProbeBwPhase,
    prev_ca_state: CaState,

    // Bandwidth model (windowed max filter + short-term lower bound)
    bw_filter: WinFilter<f64>,
    bw_latest: f64,
    bw_lo: f64,

    // Inflight bounds (loss-aware)
    inflight_hi: u32,
    inflight_lo: u32,
    inflight_latest: u32,
    loss_in_round: bool,
    loss_events_in_round: u32,
    loss_round_delivered: u32,
    loss_round_start: bool,

    // Round tracking
    round_count: u32,
    round_start: bool,
    next_rtt_delivered: u32,

    // Startup
    full_bw: f64,
    full_bw_count: u32,
    full_bw_reached: bool,

    // ProbeBW timing & upward probing
    cycle_stamp_us: u64,
    bw_probe_wait_us: u64,
    bw_probe_up_rounds: u32,
    bw_probe_up_cnt: u32,
    bw_probe_up_acks: u32,
    bw_probe_samples: bool,
    cycle_count: u32,

    // Min-RTT and ProbeRTT (`u64::MAX` = no sample)
    min_rtt_us: u64,
    min_rtt_stamp_us: u64,
    probe_rtt_min_us: u64,
    probe_rtt_min_stamp_us: u64,
    probe_rtt_done_time_us: u64,
    probe_rtt_round_done: bool,
    probe_rtt_expired: bool,
    idle_restart: bool,

    // Gains (current)
    pacing_gain: f64,
    cwnd_gain: f64,

    // Pacing rate in bytes/sec
    pacing_rate_bps: u64,
    has_seen_rtt: bool,

    // Recovery
    prior_cwnd: u32,
    packet_conservation: bool,

    // Ack aggregation
    extra_acked: [u32; 2],
    extra_acked_win_rtts: u32,
    extra_acked_idx: usize,
    ack_epoch_acked: u32,
    ack_epoch_start_us: u64,
}

impl BbrState {
    /// Initialize in Startup with no RTT sample and an initial pacing rate
    /// seeded from `cwnd` over a 1 ms RTT.
    pub(crate) fn new(now_us: u64, cwnd: u32, mss: u32) -> Self {
        let mut state = Self {
            mode: BbrMode::Startup,
            probe_bw_phase: ProbeBwPhase::Cruise,
            prev_ca_state: CaState::Open,
            bw_filter: WinFilter::new(0, 0.0),
            bw_latest: 0.0,
            bw_lo: f64::INFINITY,
            inflight_hi: u32::MAX,
            inflight_lo: u32::MAX,
            inflight_latest: 0,
            loss_in_round: false,
            loss_events_in_round: 0,
            loss_round_delivered: 0,
            loss_round_start: false,
            round_count: 0,
            round_start: false,
            next_rtt_delivered: 0,
            full_bw: 0.0,
            full_bw_count: 0,
            full_bw_reached: false,
            cycle_stamp_us: now_us,
            bw_probe_wait_us: PROBE_WAIT_MIN_US,
            bw_probe_up_rounds: 0,
            bw_probe_up_cnt: u32::MAX,
            bw_probe_up_acks: 0,
            bw_probe_samples: false,
            cycle_count: 0,
            min_rtt_us: u64::MAX,
            min_rtt_stamp_us: now_us,
            probe_rtt_min_us: u64::MAX,
            probe_rtt_min_stamp_us: now_us,
            probe_rtt_done_time_us: 0,
            probe_rtt_round_done: false,
            probe_rtt_expired: false,
            idle_restart: false,
            pacing_gain: BBR_STARTUP_PACING_GAIN,
            cwnd_gain: BBR_STARTUP_CWND_GAIN,
            pacing_rate_bps: 0,
            has_seen_rtt: false,
            prior_cwnd: 0,
            packet_conservation: false,
            extra_acked: [0; 2],
            extra_acked_win_rtts: 0,
            extra_acked_idx: 0,
            ack_epoch_acked: 0,
            ack_epoch_start_us: now_us,
        };
        state.init_pacing_rate_from_rtt(0, cwnd, mss);
        state
    }

    pub(crate) fn mode(&self) -> BbrMode {
        self.mode
    }

    /// Pacing rate in bytes per second.
    pub(crate) fn pacing_rate_bps(&self) -> u64 {
        self.pacing_rate_bps.max(1_200)
    }

    /// Run one BBRv3 update on an ACK while data was in flight. Returns true
    /// while in `ProbeRTT`, signaling the caller to mark the stream app-limited.
    pub(crate) fn main(&mut self, rs: &RateSample, link: &mut Link) -> bool {
        let probe_rtt = self.update_model(rs, link);
        let bw = self.bw();
        self.set_pacing_rate(bw, self.pacing_gain, link);
        self.set_cwnd(rs, rs.acked_sacked, bw, self.cwnd_gain, link);
        probe_rtt
    }

    /// RTO fired: reset short-term lower bounds and force a new round, keeping
    /// `full_bw_reached` and `inflight_hi`.
    pub(crate) fn on_rto(&mut self) {
        self.prev_ca_state = CaState::Loss;
        self.full_bw = 0.0;
        self.round_start = true;
        self.reset_lower_bounds();
    }

    /// A packet leaves with nothing in flight: an app-limited sender restarts
    /// from idle.
    pub(crate) fn on_transmit_start(&mut self, app_limited: bool, link: &mut Link) {
        if !app_limited {
            return;
        }
        self.idle_restart = true;
        self.ack_epoch_start_us = link.now_us;
        self.ack_epoch_acked = 0;
        match self.mode {
            BbrMode::ProbeBw => self.set_pacing_rate(self.bw(), 1.0, link),
            BbrMode::ProbeRtt => self.check_probe_rtt_done(link),
            _ => {}
        }
    }

    /// Remember `cwnd` to restore after recovery or ProbeRTT.
    pub(crate) fn save_cwnd(&mut self, cwnd: u32) {
        if self.prev_ca_state < CaState::Recovery && self.mode != BbrMode::ProbeRtt {
            self.prior_cwnd = cwnd;
        } else {
            self.prior_cwnd = self.prior_cwnd.max(cwnd);
        }
    }

    #[cfg(test)]
    pub(crate) fn prior_cwnd(&self) -> u32 {
        self.prior_cwnd
    }

    /// Effective operating bandwidth in packets/µs: `min(max_bw, bw_lo)`.
    pub(crate) fn bw(&self) -> f64 {
        let max_bw = self.max_bw();
        if self.bw_lo.is_finite() {
            max_bw.min(self.bw_lo)
        } else {
            max_bw
        }
    }

    /// Long-term windowed maximum bandwidth in packets/µs.
    fn max_bw(&self) -> f64 {
        self.bw_filter.get()
    }

    #[cfg(test)]
    pub(crate) fn min_rtt_us(&self) -> u64 {
        self.min_rtt_us
    }
}

// ─── Private BBRv3 pipeline ──────────────────────────────────────────────────

impl BbrState {
    fn update_model(&mut self, rs: &RateSample, link: &mut Link) -> bool {
        self.update_latest_delivery_signals(rs, link);
        self.update_round(rs, link.delivered);
        self.update_congestion_signals(rs, link);
        self.update_ack_aggregation(rs, link);
        self.check_startup_done(rs, link);
        self.check_drain(link);
        self.update_probe_bw_cycle_phase(rs, link);
        let probe_rtt = self.update_min_rtt(rs, link);
        self.update_gains();
        self.advance_latest_delivery_signals(rs, link);
        probe_rtt
    }

    /// Track per-round peak delivery rate and inflight delivered.
    fn update_latest_delivery_signals(&mut self, rs: &RateSample, link: &Link) {
        self.loss_round_start = false;
        if rs.delivered == 0 || rs.interval_us == 0 {
            return;
        }
        let bw = f64::from(rs.delivered) / (rs.interval_us as f64);
        if bw > self.bw_latest {
            self.bw_latest = bw;
        }
        if rs.delivered > self.inflight_latest {
            self.inflight_latest = rs.delivered;
        }
        if rs.prior_delivered.wrapping_sub(self.loss_round_delivered) as i32 >= 0 {
            self.loss_round_delivered = link.delivered;
            self.loss_round_start = true;
        }
    }

    fn advance_latest_delivery_signals(&mut self, rs: &RateSample, _link: &Link) {
        if self.loss_round_start {
            self.bw_latest = if rs.delivered > 0 && rs.interval_us > 0 {
                f64::from(rs.delivered) / (rs.interval_us as f64)
            } else {
                0.0
            };
            self.inflight_latest = rs.delivered;
            self.loss_in_round = false;
            self.loss_events_in_round = 0;
        }
    }

    fn update_round(&mut self, rs: &RateSample, delivered: u32) {
        self.round_start = false;
        if rs.delivered == 0 || rs.interval_us == 0 {
            return;
        }
        if rs.prior_delivered.wrapping_sub(self.next_rtt_delivered) as i32 >= 0 {
            self.next_rtt_delivered = delivered;
            self.round_count = self.round_count.wrapping_add(1);
            self.round_start = true;
            self.packet_conservation = false;
        }
    }

    /// True when standing queueing delay is at least `0.8 * min_rtt` on a
    /// non-loopback path (`min_rtt >= 2 ms`). This identifies deep bottleneck
    /// queues filled by competing loss-agnostic flows (such as stock BBRv1
    /// peers), where capping `inflight_hi` below `2 * BDP` starves this flow;
    /// shallow queues (`queue < 0.5 * BDP`) and normal single-flow links still
    /// get full BBRv3 loss bounding.
    fn in_deep_queue(&self, link: &Link) -> bool {
        self.min_rtt_us < u64::MAX
            && self.min_rtt_us >= 2_000
            && link.srtt_us >= self.min_rtt_us.saturating_mul(9) / 5
    }

    /// Update `bw_filter`, `inflight_hi`, and lower bounds (`bw_lo`, `inflight_lo`).
    fn update_congestion_signals(&mut self, rs: &RateSample, link: &Link) {
        if rs.delivered > 0 && rs.interval_us > 0 {
            let bw = f64::from(rs.delivered) / (rs.interval_us as f64);
            if !rs.is_app_limited || bw >= self.max_bw() {
                self.bw_filter
                    .apply_max(BBR_BW_FILTER_ROUNDS, u64::from(self.round_count), bw);
            }
        }
        if rs.losses > 0 {
            self.loss_in_round = true;
            self.loss_events_in_round = self.loss_events_in_round.saturating_add(1);
        }
        if self.in_deep_queue(link) {
            self.inflight_hi = u32::MAX;
            self.reset_lower_bounds();
            return;
        }
        if !self.loss_round_start {
            return;
        }
        // Adapt short-term lower bounds on sustained >3% loss outside Startup/Up.
        if self.mode == BbrMode::ProbeBw
            && self.probe_bw_phase != ProbeBwPhase::Up
            && self.loss_in_round
            && self.is_inflight_too_high(rs)
        {
            self.adapt_lower_bounds(link);
        }
    }

    /// BBRv3 `is_inflight_too_high`: true when the flight experienced more than
    /// `BBR_LOSS_THRESH` (3%) packet loss (with at least 3 lost packets so 1%
    /// random loss variance does not falsely cap the path).
    fn is_inflight_too_high(&self, rs: &RateSample) -> bool {
        if rs.lost_in_flight < 3 || rs.tx_in_flight == 0 {
            return false;
        }
        (rs.lost_in_flight as f64) > (rs.tx_in_flight as f64) * BBR_LOSS_THRESH
    }

    /// Gentle short-term lower-bound backoff (`beta = 0.85`), floored at the
    /// latest delivery signals and 1.0×BDP / 0.75×max_bw so loss-ignoring
    /// BBRv1 peers sharing a drop-tail queue cannot collapse this flow.
    fn adapt_lower_bounds(&mut self, link: &Link) {
        let max_bw = self.max_bw();
        if !self.bw_lo.is_finite() {
            self.bw_lo = max_bw;
        }
        self.bw_lo = (self.bw_lo * BBR_BETA)
            .max(self.bw_latest)
            .max(max_bw * 0.75);

        let bdp_floor = self.bdp(max_bw, 1.0).max(BBR_CWND_MIN_TARGET);
        if self.inflight_lo == u32::MAX {
            self.inflight_lo = link.cwnd;
        }
        let beta_inflight = ((f64::from(self.inflight_lo) * BBR_BETA) as u32)
            .max(self.inflight_latest)
            .max(bdp_floor);
        self.inflight_lo = beta_inflight;
    }

    fn reset_lower_bounds(&mut self) {
        self.bw_lo = f64::INFINITY;
        self.inflight_lo = u32::MAX;
    }

    /// `inflight_hi` reduced by `BBR_HEADROOM` (15%) to leave room in shallow
    /// queues during Cruise/Down.
    fn inflight_with_headroom(&self) -> u32 {
        if self.inflight_hi == u32::MAX {
            return u32::MAX;
        }
        let headroom = ((f64::from(self.inflight_hi) * BBR_HEADROOM) as u32).max(1);
        self.inflight_hi
            .saturating_sub(headroom)
            .max(BBR_CWND_MIN_TARGET)
    }

    /// ACK-aggregation estimator in microseconds.
    fn update_ack_aggregation(&mut self, rs: &RateSample, link: &Link) {
        if rs.acked_sacked == 0 || rs.delivered == 0 || rs.interval_us == 0 {
            return;
        }
        if self.round_start {
            self.extra_acked_win_rtts = (self.extra_acked_win_rtts + 1).min(0xff);
            if self.extra_acked_win_rtts >= BBR_EXTRA_ACKED_WIN_RTTS {
                self.extra_acked_win_rtts = 0;
                self.extra_acked_idx ^= 1;
                self.extra_acked[self.extra_acked_idx] = 0;
            }
        }
        let epoch_us = link
            .delivered_ts_us
            .saturating_sub(self.ack_epoch_start_us);
        let mut expected_acked = (self.bw() * (epoch_us as f64)) as u32;
        if self.ack_epoch_acked <= expected_acked
            || u64::from(self.ack_epoch_acked) + u64::from(rs.acked_sacked) >= u64::from(u32::MAX)
        {
            self.ack_epoch_acked = 0;
            self.ack_epoch_start_us = link.delivered_ts_us;
            expected_acked = 0;
        }
        self.ack_epoch_acked += rs.acked_sacked;
        let extra_acked = (self.ack_epoch_acked - expected_acked).min(link.cwnd);
        if extra_acked > self.extra_acked[self.extra_acked_idx] {
            self.extra_acked[self.extra_acked_idx] = extra_acked;
        }
    }

    /// Startup exit: either bandwidth plateaued for 3 rounds OR loss exceeded
    /// 2% across >= 6 loss events in a round (BBRv3 startup loss exit).
    fn check_startup_done(&mut self, rs: &RateSample, link: &Link) {
        if self.mode != BbrMode::Startup || self.full_bw_reached {
            return;
        }
        // Full bandwidth plateau check.
        if self.round_start && !rs.is_app_limited {
            if self.max_bw() >= self.full_bw * BBR_FULL_BW_THRESH {
                self.full_bw = self.max_bw();
                self.full_bw_count = 0;
            } else {
                self.full_bw_count += 1;
                if self.full_bw_count >= BBR_FULL_BW_COUNT {
                    self.full_bw_reached = true;
                }
            }
        }
        // BBRv3 high-loss startup exit: avoid overflowing shallow queues for 3 RTTs.
        if self.loss_round_start
            && !self.in_deep_queue(link)
            && self.loss_events_in_round >= BBR_FULL_LOSS_CNT
            && self.is_inflight_too_high(rs)
        {
            self.full_bw_reached = true;
            let safe_hi = self
                .bdp(self.max_bw(), 1.0)
                .max(self.inflight_latest)
                .max(BBR_CWND_MIN_TARGET);
            self.inflight_hi = safe_hi;
        }
    }

    fn check_drain(&mut self, link: &Link) {
        if self.mode == BbrMode::Startup && self.full_bw_reached {
            tracing::debug!(from = ?BbrMode::Startup, to = ?BbrMode::Drain, "bbr3: mode transition");
            self.mode = BbrMode::Drain;
        }
        if self.mode == BbrMode::Drain && link.inflight <= self.bdp(self.bw(), 1.0) {
            tracing::debug!(from = ?BbrMode::Drain, to = ?BbrMode::ProbeBw, "bbr3: mode transition");
            self.start_probe_bw_down(link);
        }
    }

    /// Pick the wait duration in `ProbeBwCruise` before probing upward again.
    fn pick_probe_wait_us(&self) -> u64 {
        if self.min_rtt_us < 2_000 {
            // Sub-ms loopback/LAN path: probe every ~8 RTTs (floored at 2 ms)
            // instead of stalling 150 ms between probes.
            return self.min_rtt_us.saturating_mul(8).max(2_000);
        }
        let rtt_based = if self.min_rtt_us < u64::MAX {
            self.min_rtt_us.saturating_mul(6)
        } else {
            PROBE_WAIT_MIN_US
        };
        // Small deterministic phase jitter across cycles to desynchronize
        // flows sharing one queue.
        let jitter = u64::from(self.cycle_count.wrapping_mul(2_654_435_761) % 100_000);
        rtt_based.clamp(PROBE_WAIT_MIN_US, PROBE_WAIT_MAX_US) + jitter
    }

    fn start_probe_bw_down(&mut self, link: &Link) {
        self.mode = BbrMode::ProbeBw;
        self.probe_bw_phase = ProbeBwPhase::Down;
        self.cycle_stamp_us = link.now_us;
        self.bw_probe_wait_us = self.pick_probe_wait_us();
        self.bw_probe_up_cnt = u32::MAX;
        self.bw_probe_samples = false;
        self.reset_lower_bounds();
    }

    fn start_probe_bw_cruise(&mut self) {
        self.probe_bw_phase = ProbeBwPhase::Cruise;
        self.reset_lower_bounds();
    }

    fn start_probe_bw_refill(&mut self, link: &Link) {
        self.reset_lower_bounds();
        self.bw_probe_up_rounds = 0;
        self.bw_probe_up_acks = 0;
        self.probe_bw_phase = ProbeBwPhase::Refill;
        self.next_rtt_delivered = link.delivered;
        self.cycle_stamp_us = link.now_us;
    }

    fn start_probe_bw_up(&mut self, link: &Link) {
        self.cycle_count = self.cycle_count.wrapping_add(1);
        self.probe_bw_phase = ProbeBwPhase::Up;
        self.cycle_stamp_us = link.now_us;
        self.next_rtt_delivered = link.delivered;
        self.bw_probe_up_rounds = 0;
        self.bw_probe_up_acks = 0;
        self.bw_probe_samples = true;
        self.raise_inflight_hi_slope(link);
    }

    fn raise_inflight_hi_slope(&mut self, link: &Link) {
        let growth_this_round = 1u32.checked_shl(self.bw_probe_up_rounds.min(20)).unwrap_or(u32::MAX);
        self.bw_probe_up_cnt = (link.cwnd / growth_this_round).max(1);
    }

    fn probe_inflight_hi_upward(&mut self, rs: &RateSample, link: &Link) {
        if self.inflight_hi == u32::MAX || rs.acked_sacked == 0 {
            return;
        }
        if link.inflight < self.inflight_hi && link.cwnd < self.inflight_hi {
            return;
        }
        self.bw_probe_up_acks = self.bw_probe_up_acks.saturating_add(rs.acked_sacked);
        if self.bw_probe_up_acks >= self.bw_probe_up_cnt {
            let delta = self.bw_probe_up_acks / self.bw_probe_up_cnt;
            self.bw_probe_up_acks -= delta * self.bw_probe_up_cnt;
            self.inflight_hi = self.inflight_hi.saturating_add(delta);
        }
        if self.round_start {
            self.bw_probe_up_rounds = self.bw_probe_up_rounds.saturating_add(1);
            self.raise_inflight_hi_slope(link);
        }
    }

    /// Four-phase ProbeBW cycle transitions (`Down` -> `Cruise` -> `Refill` -> `Up`).
    fn update_probe_bw_cycle_phase(&mut self, rs: &RateSample, link: &Link) {
        if self.mode != BbrMode::ProbeBw {
            return;
        }
        let elapsed_us = link.now_us.saturating_sub(self.cycle_stamp_us);
        let target_inflight = self.bdp(self.bw(), 1.0);

        match self.probe_bw_phase {
            ProbeBwPhase::Down => {
                // Exit Down once queue has drained to BDP or headroom ceiling,
                // or after 1 min_rtt if inflight has not drained yet.
                let drained = link.inflight <= target_inflight
                    || link.inflight <= self.inflight_with_headroom();
                let timed_out =
                    self.min_rtt_us < u64::MAX && elapsed_us >= self.min_rtt_us;
                if drained || timed_out {
                    self.start_probe_bw_cruise();
                }
            }
            ProbeBwPhase::Cruise => {
                // Probe upward once the wait interval has elapsed and we are
                // not app-limited.
                if !rs.is_app_limited && elapsed_us >= self.bw_probe_wait_us {
                    self.start_probe_bw_refill(link);
                }
            }
            ProbeBwPhase::Refill => {
                // Spend one round refilling the pipe before pushing above 1.0x.
                if self.round_start {
                    self.start_probe_bw_up(link);
                }
            }
            ProbeBwPhase::Up => {
                let deep_queue = self.in_deep_queue(link);
                let half_rtt_done =
                    self.min_rtt_us == u64::MAX || elapsed_us >= self.min_rtt_us / 2;
                // Hit loss ceiling on a shallow queue -> pin `inflight_hi` and
                // drain immediately, once Up's own packets have landed.
                if !deep_queue
                    && (half_rtt_done || link.inflight >= target_inflight)
                    && self.is_inflight_too_high(rs)
                {
                    let safe = rs
                        .tx_in_flight
                        .saturating_sub(rs.lost_in_flight)
                        .max(target_inflight)
                        .max(BBR_CWND_MIN_TARGET);
                    self.inflight_hi = safe;
                    self.start_probe_bw_down(link);
                    return;
                }
                self.probe_inflight_hi_upward(rs, link);
                let min_rtt_done =
                    self.min_rtt_us < u64::MAX && elapsed_us > self.min_rtt_us;
                let probe_target = self.bdp(self.max_bw(), BBR_PROBE_BW_UP_GAIN);
                let done_probing = if deep_queue {
                    min_rtt_done && self.round_start
                } else {
                    min_rtt_done && (link.inflight >= probe_target || rs.losses > 0)
                };
                if done_probing {
                    if !self.loss_in_round
                        && self.inflight_hi < u32::MAX
                        && link.inflight >= self.inflight_hi
                    {
                        self.inflight_hi = u32::MAX;
                    }
                    self.start_probe_bw_down(link);
                }
            }
        }
    }

    /// Min-RTT filter (10 s) and BBRv3 ProbeRTT (5 s interval, `0.5 * BDP` cwnd).
    fn update_min_rtt(&mut self, rs: &RateSample, link: &mut Link) -> bool {
        let now = link.now_us;
        let probe_expired = now.saturating_sub(self.probe_rtt_min_stamp_us) > BBR_PROBE_RTT_INTERVAL_US;
        if rs.rtt_us > 0 && (rs.rtt_us < self.probe_rtt_min_us || probe_expired) {
            self.probe_rtt_min_us = rs.rtt_us;
            self.probe_rtt_min_stamp_us = now;
        }
        let min_expired = now.saturating_sub(self.min_rtt_stamp_us) > BBR_MIN_RTT_INTERVAL_US;
        if rs.rtt_us > 0 && (rs.rtt_us < self.min_rtt_us || min_expired) {
            self.min_rtt_us = rs.rtt_us;
            self.min_rtt_stamp_us = now;
        }

        if probe_expired {
            self.probe_rtt_expired = true;
        }

        if self.probe_rtt_expired && !self.idle_restart && self.mode != BbrMode::ProbeRtt {
            tracing::debug!(from = ?self.mode, to = ?BbrMode::ProbeRtt, "bbr3: mode transition");
            self.mode = BbrMode::ProbeRtt;
            self.save_cwnd(link.cwnd);
            self.probe_rtt_done_time_us = 0;
            self.probe_rtt_expired = false;
        }

        let probe_rtt = self.mode == BbrMode::ProbeRtt;
        if probe_rtt {
            let probe_cwnd = self.probe_rtt_cwnd();
            if self.probe_rtt_done_time_us == 0 && link.inflight <= probe_cwnd {
                let dwell = if self.min_rtt_us < u64::MAX {
                    self.min_rtt_us.min(BBR_PROBE_RTT_MODE_US)
                } else {
                    BBR_PROBE_RTT_MODE_US
                };
                self.probe_rtt_done_time_us = now.saturating_add(dwell);
                self.probe_rtt_round_done = false;
                self.next_rtt_delivered = link.delivered;
            } else if self.probe_rtt_done_time_us != 0 {
                if self.round_start {
                    self.probe_rtt_round_done = true;
                }
                if self.probe_rtt_round_done {
                    self.check_probe_rtt_done(link);
                }
            }
        }
        if rs.delivered > 0 {
            self.idle_restart = false;
        }
        probe_rtt
    }

    fn probe_rtt_cwnd(&self) -> u32 {
        self.bdp(self.bw(), BBR_PROBE_RTT_CWND_GAIN)
            .max(BBR_CWND_MIN_TARGET)
    }

    fn check_probe_rtt_done(&mut self, link: &mut Link) {
        if self.probe_rtt_done_time_us == 0 || link.now_us <= self.probe_rtt_done_time_us {
            return;
        }
        self.probe_rtt_min_stamp_us = link.now_us;
        self.min_rtt_us = self.min_rtt_us.min(self.probe_rtt_min_us);
        link.cwnd = link.cwnd.max(self.prior_cwnd);
        if self.full_bw_reached {
            self.start_probe_bw_down(link);
        } else {
            self.mode = BbrMode::Startup;
        }
    }

    fn update_gains(&mut self) {
        (self.pacing_gain, self.cwnd_gain) = match self.mode {
            BbrMode::Startup => (BBR_STARTUP_PACING_GAIN, BBR_STARTUP_CWND_GAIN),
            BbrMode::Drain => (BBR_DRAIN_GAIN, BBR_STARTUP_CWND_GAIN),
            BbrMode::ProbeBw => {
                let pg = match self.probe_bw_phase {
                    ProbeBwPhase::Down => BBR_PROBE_BW_DOWN_GAIN,
                    ProbeBwPhase::Cruise => BBR_PROBE_BW_CRUISE_GAIN,
                    ProbeBwPhase::Refill => BBR_PROBE_BW_REFILL_GAIN,
                    ProbeBwPhase::Up => BBR_PROBE_BW_UP_GAIN,
                };
                (pg, BBR_CWND_GAIN)
            }
            BbrMode::ProbeRtt => (1.0, BBR_PROBE_RTT_CWND_GAIN),
        };
    }

    /// Convert `bw` (packets/µs) to pacing rate in bytes/sec.
    fn bw_to_pacing_rate_bps(bw: f64, mss: u32, gain: f64) -> u64 {
        let bps = bw * 1_000_000.0 * f64::from(mss) * gain * BBR_PACING_MARGIN_PERCENT;
        if !bps.is_finite() || bps < 1_200.0 {
            1_200
        } else if bps >= (u64::MAX as f64) {
            u64::MAX
        } else {
            bps as u64
        }
    }

    fn init_pacing_rate_from_rtt(&mut self, srtt_us: u64, cwnd: u32, mss: u32) {
        let srtt_us = if srtt_us > 0 {
            self.has_seen_rtt = true;
            srtt_us
        } else {
            1_000
        };
        let bw = f64::from(cwnd) / (srtt_us as f64);
        self.pacing_rate_bps = Self::bw_to_pacing_rate_bps(bw, mss, BBR_STARTUP_PACING_GAIN);
    }

    fn set_pacing_rate(&mut self, bw: f64, gain: f64, link: &Link) {
        // Sub-millisecond loopback / local IPC paths with no loss are CPU-bound:
        // pacing at 0.99x measured BW introduces spurious sub-ms async timer
        // sleeps without preventing any network queue. Let cwnd bound inflight
        // unless loss engages `inflight_hi`.
        if self.min_rtt_us < 1_000 && self.inflight_hi == u32::MAX && !self.loss_in_round {
            self.pacing_rate_bps = u64::MAX;
            return;
        }
        // In a deep shared queue already held full by competing loss-agnostic
        // peers, draining at 0.90x or applying the 1% pacing haircut only hands
        // queue occupancy to the competitor without emptying the bottleneck.
        let (eff_gain, margin) = if self.in_deep_queue(link) && self.mode == BbrMode::ProbeBw {
            let g = if self.probe_bw_phase == ProbeBwPhase::Down {
                1.0
            } else {
                gain
            };
            (g, 1.0)
        } else {
            (gain, BBR_PACING_MARGIN_PERCENT)
        };
        let bps = bw * 1_000_000.0 * f64::from(link.mss) * eff_gain * margin;
        let rate = if !bps.is_finite() || bps < 1_200.0 {
            1_200
        } else if bps >= (u64::MAX as f64) {
            u64::MAX
        } else {
            bps as u64
        };
        if !self.has_seen_rtt && link.srtt_us > 0 {
            self.init_pacing_rate_from_rtt(link.srtt_us, link.cwnd, link.mss);
        }
        if self.full_bw_reached || rate > self.pacing_rate_bps {
            self.pacing_rate_bps = rate;
        }
    }

    fn set_cwnd_to_recover_or_restore(
        &mut self,
        rs: &RateSample,
        acked: u32,
        cwnd: &mut u32,
        link: &Link,
    ) -> bool {
        if rs.losses > 0 {
            *cwnd = cwnd.saturating_sub(rs.losses).max(1);
        }
        if link.ca_state == CaState::Recovery && self.prev_ca_state != CaState::Recovery {
            self.packet_conservation = true;
            self.next_rtt_delivered = link.delivered;
            *cwnd = link.inflight.saturating_add(acked);
        } else if self.prev_ca_state >= CaState::Recovery && link.ca_state == CaState::Open {
            *cwnd = (*cwnd).max(self.prior_cwnd);
            self.packet_conservation = false;
        }
        self.prev_ca_state = link.ca_state;
        if self.packet_conservation {
            *cwnd = (*cwnd).max(link.inflight.saturating_add(acked));
            return true;
        }
        false
    }

    /// Cap `cwnd` by BBRv3's loss-aware `inflight_hi` (with headroom in
    /// Cruise/Down) and short-term `inflight_lo`.
    fn bound_cwnd_for_model(&self, cwnd: u32) -> u32 {
        let mut cap = u32::MAX;
        if self.mode == BbrMode::ProbeBw {
            match self.probe_bw_phase {
                ProbeBwPhase::Cruise | ProbeBwPhase::Down => {
                    cap = self.inflight_with_headroom();
                }
                ProbeBwPhase::Refill | ProbeBwPhase::Up => {
                    cap = self.inflight_hi;
                }
            }
        }
        cap = cap.min(self.inflight_lo);
        cwnd.min(cap).max(BBR_CWND_MIN_TARGET)
    }

    fn set_cwnd(&mut self, rs: &RateSample, acked: u32, bw: f64, gain: f64, link: &mut Link) {
        let mut cwnd = link.cwnd;
        if acked > 0 && !self.set_cwnd_to_recover_or_restore(rs, acked, &mut cwnd, link) {
            let target = self
                .cwnd_bdp(bw, gain)
                .saturating_add(self.ack_aggregation_cwnd());
            if self.full_bw_reached {
                cwnd = cwnd.saturating_add(acked).min(target);
            } else if cwnd < target || link.delivered < 10 {
                cwnd = cwnd.saturating_add(acked);
            }
            cwnd = cwnd.max(BBR_CWND_MIN_TARGET);
        }
        cwnd = self.bound_cwnd_for_model(cwnd);
        if self.mode == BbrMode::ProbeRtt {
            cwnd = cwnd.min(self.probe_rtt_cwnd());
        }
        link.cwnd = cwnd;
    }

    /// BDP × gain in packets; initial window (10) before a min-RTT sample.
    fn bdp(&self, bw: f64, gain: f64) -> u32 {
        if self.min_rtt_us == u64::MAX {
            return 10;
        }
        let packets = bw * (self.min_rtt_us as f64) * gain;
        if !packets.is_finite() || packets < 1.0 {
            1
        } else if packets >= f64::from(u32::MAX) {
            u32::MAX
        } else {
            packets as u32
        }
    }

    /// BDP × gain for cwnd sizing, flooring RTT at 1 ms so sub-millisecond
    /// loopback/LAN paths keep deep pipelining across async wakeups while
    /// pacing and RACK keep exact microsecond resolution.
    fn cwnd_bdp(&self, bw: f64, gain: f64) -> u32 {
        if self.min_rtt_us == u64::MAX {
            return 10;
        }
        let rtt_us = self.min_rtt_us.max(1_000);
        let packets = bw * (rtt_us as f64) * gain;
        if !packets.is_finite() || packets < 1.0 {
            1
        } else if packets >= f64::from(u32::MAX) {
            u32::MAX
        } else {
            packets as u32
        }
    }

    fn ack_aggregation_cwnd(&self) -> u32 {
        if BBR_EXTRA_ACKED_GAIN == 0.0 || !self.full_bw_reached {
            return 0;
        }
        let max_aggr_cwnd = (self.bw() * (BBR_EXTRA_ACKED_MAX_US as f64)) as u32;
        let extra = self.extra_acked[0].max(self.extra_acked[1]);
        ((BBR_EXTRA_ACKED_GAIN * f64::from(extra)) as u32).min(max_aggr_cwnd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: u32 = 1180;

    fn make_rs(
        delivered: u32,
        interval_us: u64,
        prior_delivered: u32,
        app_limited: bool,
    ) -> RateSample {
        let mut rs = RateSample::new(interval_us);
        rs.delivered = delivered;
        rs.interval_us = interval_us;
        rs.acked_sacked = delivered;
        rs.prior_delivered = prior_delivered;
        rs.is_app_limited = app_limited;
        rs.tx_in_flight = delivered;
        rs
    }

    fn link(cwnd: u32, delivered: u32, inflight: u32, now_us: u64) -> Link {
        Link {
            cwnd,
            mss: MSS,
            delivered,
            delivered_ts_us: now_us,
            srtt_us: 0,
            inflight,
            ca_state: CaState::Open,
            now_us,
        }
    }

    #[test]
    fn startup_exits_early_on_high_loss() {
        let mut state = BbrState::new(0, 10, MSS);
        let mut l = link(100, 100, 100, 50_000);
        // First ACK starts loss round 1 (delivered = 100).
        let rs0 = make_rs(100, 50_000, 0, false);
        state.main(&rs0, &mut l);
        // Six loss events within the SAME round (prior_delivered < 100) with 5% flight loss.
        for i in 1..=6u32 {
            let mut rs = make_rs(10, 50_000, i * 10, false);
            rs.losses = 1;
            rs.tx_in_flight = 100;
            rs.lost_in_flight = 5;
            l.delivered = 100 + i * 10;
            state.main(&rs, &mut l);
        }
        // Round completes (prior_delivered >= 100) with high loss -> exits Startup with inflight_hi set.
        // Keep inflight above 1.0 * BDP so BBR enters Drain before ProbeBW.
        let mut rs = make_rs(20, 50_000, 100, false);
        rs.losses = 1;
        rs.tx_in_flight = 100;
        rs.lost_in_flight = 5;
        l.delivered = 180;
        l.inflight = 200;
        state.main(&rs, &mut l);
        assert!(state.full_bw_reached);
        assert_eq!(state.mode, BbrMode::Drain);
        assert!(state.inflight_hi < u32::MAX);
    }

    #[test]
    fn one_percent_random_loss_does_not_trigger_inflight_hi_cap() {
        let mut state = BbrState::new(0, 10, MSS);
        let mut rs = make_rs(99, 50_000, 0, false);
        rs.tx_in_flight = 100;
        rs.lost_in_flight = 1;
        assert!(!state.is_inflight_too_high(&rs));
        // 3% exact is NOT strictly greater than 3%.
        rs.lost_in_flight = 3;
        assert!(!state.is_inflight_too_high(&rs));
        // 4% IS strictly greater than 3%.
        rs.lost_in_flight = 4;
        assert!(state.is_inflight_too_high(&rs));
        // Even with 1% loss, state stays unbounded in startup.
        let mut l = link(100, 100, 50, 50_000);
        rs.lost_in_flight = 1;
        rs.losses = 1;
        state.main(&rs, &mut l);
        assert_eq!(state.inflight_hi, u32::MAX);
    }

    #[test]
    fn probe_rtt_keeps_half_bdp_instead_of_four_packets() {
        let mut state = BbrState::new(0, 10, MSS);
        state.min_rtt_us = 50_000;
        // 1 pkt / 1000 us = 1000 pkt/s -> BDP = 50 packets -> 0.5 * BDP = 25 packets.
        state.bw_filter.apply_max(BBR_BW_FILTER_ROUNDS, 0, 0.001);
        state.full_bw_reached = true;
        state.mode = BbrMode::ProbeBw;
        let mut l = link(100, 200, 60, BBR_PROBE_RTT_INTERVAL_US + 1);
        state.main(&RateSample::new(0), &mut l);
        assert_eq!(state.mode, BbrMode::ProbeRtt);
        assert_eq!(l.cwnd, 25);
    }

    #[test]
    fn probe_bw_up_pins_inflight_hi_and_drains_on_high_loss() {
        let mut state = BbrState::new(0, 10, MSS);
        state.min_rtt_us = 20_000;
        state.bw_filter.apply_max(BBR_BW_FILTER_ROUNDS, 0, 0.005); // BDP = 100 pkts
        state.full_bw_reached = true;
        state.mode = BbrMode::ProbeBw;
        state.probe_bw_phase = ProbeBwPhase::Up;
        state.cycle_stamp_us = 100_000;

        let mut rs = make_rs(100, 20_000, 0, false);
        rs.tx_in_flight = 130;
        rs.lost_in_flight = 10;
        rs.losses = 10;
        let mut l = link(130, 100, 120, 130_000);
        state.main(&rs, &mut l);

        assert_eq!(state.probe_bw_phase, ProbeBwPhase::Down);
        assert_eq!(state.inflight_hi, 120);
        // Cruise/Down applies 10% headroom: 120 - 12 = 108.
        assert!(l.cwnd <= 108, "expected cwnd <= 108, got {}", l.cwnd);
    }

    #[test]
    fn sub_millisecond_rtt_produces_accurate_bdp_and_pacing() {
        let mut state = BbrState::new(0, 10, 1452);
        // 300 us RTT, 50 packets delivered in 300 us => ~166,667 pkt/s (~242 MB/s).
        let rs = make_rs(50, 300, 0, false);
        let mut l = link(50, 50, 50, 300);
        l.srtt_us = 300;
        state.main(&rs, &mut l);
        assert_eq!(state.min_rtt_us(), 300);
        assert_eq!(state.bdp(state.bw(), 1.0), 50);
        // cwnd_bdp floors RTT at 1 ms so sub-ms loopback keeps full pipelining.
        assert!(state.cwnd_bdp(state.bw(), 2.0) >= 300);
        assert!(state.pacing_rate_bps() > 200_000_000);
    }

    #[test]
    fn deep_queue_clears_inflight_hi_to_avoid_bbrv1_starvation() {
        let mut state = BbrState::new(0, 10, MSS);
        state.min_rtt_us = 50_000;
        state.bw_filter.apply_max(BBR_BW_FILTER_ROUNDS, 0, 0.001); // BDP = 50 pkts
        state.full_bw_reached = true;
        state.mode = BbrMode::ProbeBw;
        state.probe_bw_phase = ProbeBwPhase::Up;
        state.inflight_hi = 60;
        state.cycle_stamp_us = 100_000;

        // Standing queue pushes srtt to 120 ms (2.4x min_rtt >= 1.5x): deep queue.
        let mut rs = make_rs(50, 120_000, 0, false);
        rs.tx_in_flight = 80;
        rs.lost_in_flight = 8;
        rs.losses = 8;
        let mut l = link(80, 100, 80, 180_000);
        l.srtt_us = 120_000;
        state.main(&rs, &mut l);

        assert_eq!(state.inflight_hi, u32::MAX);
        assert_eq!(state.inflight_lo, u32::MAX);
        assert!(state.bw_lo.is_infinite());
    }
}
