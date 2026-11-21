//! BBR congestion control state machine, ported from C libudx `udx_bbr.c`
//! (the version udx-native 1.22.1 pins).
//!
//! Matches C, including: the bandwidth filter (`win_filter_f64.c`, with its
//! ¼/½-window aging), rounds counted only on rate samples C keeps
//! (`bbr_update_bw`), `bbr_bdp`, `bbr_set_cwnd` (startup growth capped at
//! the target once ten packets are delivered, ACK-aggregation allowance only
//! once the pipe is full), recovery/restore, the pacing rate (seeded from
//! the initial window at `bbr_init`, so the first flight is paced; floored
//! at 1 byte/ms; re-seeded at the first RTT sample; only growing until the
//! pipe is full), `bbr_on_rto` (keeps `full_bw_reached`),
//! `bbr_on_transmit_start` (re-paces ProbeBW at gain 1, checks ProbeRTT
//! done), ProbeRTT (200 ms dwell from the first ACK with at most 4 packets
//! in flight plus one round, exit through `bbr_reset_mode` restoring
//! `prior_cwnd`), and cycle phase and ACK-aggregation epochs on the
//! stream's `delivered_ts`. The minimum RTT starts at `u32::MAX` (C `~0`).
//! Times are whole milliseconds on the stream clock (C `uv_now`).
//!
//! The rate sample (`rate.rs`, `udx_rate.c`) carries the RACK RTT of the
//! newest delivered packet and is discarded against the stream's RACK
//! minimum RTT; the stream ends recovery when the cumulative ACK passes
//! `high_seq` (C `process_packet`). Those parts live in `rate.rs`,
//! `mod.rs` and `stream.rs`.
//!
//! No known differences from C remain in this module.

use super::{
    BBR_BW_FILTER_CYCLES, BBR_CWND_GAIN, BBR_CWND_MIN_TARGET, BBR_CYCLE_LEN, BBR_DRAIN_GAIN,
    BBR_EXTRA_ACKED_GAIN, BBR_EXTRA_ACKED_MAX_MS, BBR_EXTRA_ACKED_WIN_RTTS, BBR_FULL_BW_COUNT,
    BBR_FULL_BW_THRESH, BBR_HIGH_GAIN, BBR_MIN_PROBE_RTT_MODE_MS, BBR_MIN_RTT_INTERVAL_MS,
    BBR_PACING_GAIN, BBR_PACING_MARGIN_PERCENT, BbrMode, CaState, filter::WinFilter,
    rate::RateSample,
};

/// The stream state BBR reads and the window it writes (C reads these off
/// `udx_stream_t`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Link {
    /// Congestion window in packets; BBR may change it.
    pub(crate) cwnd: u32,
    /// Payload bytes per packet (C `udx__max_payload`).
    pub(crate) mss: u32,
    /// Packets delivered so far (C `stream->delivered`).
    pub(crate) delivered: u32,
    /// When `delivered` last grew (C `stream->delivered_ts`).
    pub(crate) delivered_ts: u64,
    /// Smoothed RTT in ms, 0 before a sample.
    pub(crate) srtt: u32,
    /// Packets in flight (C `inflight_queue.len`).
    pub(crate) inflight: u32,
    pub(crate) ca_state: CaState,
    /// Now, in ms on the stream clock (C `uv_now`).
    pub(crate) now_ms: u64,
}

/// C `time_delta_ms`: `t1 - t0` as C computes it (a negative difference
/// wraps, as the C cast does).
fn time_delta_ms(t1: u64, t0: u64) -> u32 {
    (t1 as i64).wrapping_sub(t0 as i64) as u32
}

/// Full BBR state machine.
///
/// Unit conventions: BW = packets/ms, CWND = packets, pacing = bytes/ms.
#[derive(Debug, Clone)]
pub(crate) struct BbrState {
    mode: BbrMode,
    prev_ca_state: CaState,
    // Bandwidth estimation
    bw_filter: WinFilter<f64>,
    // Round tracking
    round_count: u32,
    round_start: bool,
    next_rtt_delivered: u32,
    // Startup
    full_bw: f64,
    full_bw_count: u32,
    full_bw_reached: bool,
    // PROBE_BW
    cycle_index: u32,
    cycle_timestamp: u64,
    // PROBE_RTT; `u32::MAX` is "no sample" (C `~0`).
    min_rtt_ms: u32,
    min_rtt_stamp: u64,
    /// End of the ProbeRTT dwell; 0 until it starts.
    probe_rtt_done_time: u64,
    probe_rtt_round_done: bool,
    idle_restart: bool,
    // Gains (current)
    pacing_gain: f64,
    cwnd_gain: f64,
    // Pacing (C `pacing_bytes_per_ms`, `has_seen_rtt`).
    pacing_rate: u64,
    has_seen_rtt: bool,
    // Recovery
    prior_cwnd: u32,
    packet_conservation: bool,
    // Ack aggregation
    extra_acked: [u32; 2],
    extra_acked_win_rtts: u32,
    extra_acked_idx: usize,
    ack_epoch_acked: u32,
    ack_epoch_start: u64,
}

impl BbrState {
    /// C `bbr_init`: startup, no minimum RTT, and a pacing rate seeded from
    /// the initial window `cwnd` over a 1 ms RTT.
    pub(crate) fn new(now_ms: u64, cwnd: u32, mss: u32) -> Self {
        let mut state = Self {
            mode: BbrMode::Startup,
            prev_ca_state: CaState::Open,
            bw_filter: WinFilter::new(0, 0.0),
            round_count: 0,
            round_start: false,
            next_rtt_delivered: 0,
            full_bw: 0.0,
            full_bw_count: 0,
            full_bw_reached: false,
            cycle_index: 0,
            cycle_timestamp: 0,
            min_rtt_ms: u32::MAX,
            min_rtt_stamp: now_ms,
            probe_rtt_done_time: 0,
            probe_rtt_round_done: false,
            idle_restart: false,
            pacing_gain: BBR_HIGH_GAIN,
            cwnd_gain: BBR_HIGH_GAIN,
            pacing_rate: 0,
            has_seen_rtt: false,
            prior_cwnd: 0,
            packet_conservation: false,
            extra_acked: [0; 2],
            extra_acked_win_rtts: 0,
            extra_acked_idx: 0,
            ack_epoch_acked: 0,
            ack_epoch_start: now_ms,
        };
        state.init_pacing_rate_from_rtt(0, cwnd, mss);
        state
    }

    /// Returns the current BBR mode.
    pub(crate) fn mode(&self) -> BbrMode {
        self.mode
    }

    /// Pacing rate in bytes/ms, at least 1.
    pub(crate) fn pacing_rate(&self) -> u32 {
        u32::try_from(self.pacing_rate).unwrap_or(u32::MAX)
    }

    /// C `bbr_main`, once per ACK while data was in flight: update the
    /// model, the pacing rate and `link.cwnd`. Returns true while in
    /// ProbeRTT, where C marks the stream app-limited
    /// (`bbr_update_min_rtt`).
    pub(crate) fn main(&mut self, rs: &RateSample, link: &mut Link) -> bool {
        let probe_rtt = self.update_model(rs, link);
        let bw = self.bw();
        self.set_pacing_rate(bw, self.pacing_gain, link);
        self.set_cwnd(rs, rs.acked_sacked, bw, self.cwnd_gain, link);
        probe_rtt
    }

    /// C `bbr_on_rto`: a dummy loss sample.
    pub(crate) fn on_rto(&mut self) {
        self.prev_ca_state = CaState::Loss;
        self.full_bw = 0.0;
        self.round_start = true;
    }

    /// C `bbr_on_transmit_start`, when a packet leaves with nothing in
    /// flight: an app-limited sender restarts from idle.
    pub(crate) fn on_transmit_start(&mut self, app_limited: bool, link: &mut Link) {
        if !app_limited {
            return;
        }
        self.idle_restart = true;
        self.ack_epoch_start = link.now_ms;
        self.ack_epoch_acked = 0;
        match self.mode {
            BbrMode::ProbeBw => self.set_pacing_rate(self.bw(), 1.0, link),
            BbrMode::ProbeRtt => self.check_probe_rtt_done(link),
            _ => {}
        }
    }

    /// C `bbr_save_cwnd`: remember the window to restore after recovery.
    pub(crate) fn save_cwnd(&mut self, cwnd: u32) {
        if self.prev_ca_state < CaState::Recovery && self.mode != BbrMode::ProbeRtt {
            self.prior_cwnd = cwnd;
        } else {
            self.prior_cwnd = self.prior_cwnd.max(cwnd);
        }
    }

    /// Window saved for after recovery.
    #[cfg(test)]
    pub(crate) fn prior_cwnd(&self) -> u32 {
        self.prior_cwnd
    }

    /// C `bbr_bw`: the windowed maximum bandwidth, packets/ms.
    pub(crate) fn bw(&self) -> f64 {
        self.bw_filter.get()
    }

    /// Minimum RTT in ms (`u32::MAX` before a sample).
    #[cfg(test)]
    pub(crate) fn min_rtt_ms(&self) -> u32 {
        self.min_rtt_ms
    }
}

// ─── Private update pipeline ─────────────────────────────────────────────────

impl BbrState {
    /// C `bbr_update_model`.
    fn update_model(&mut self, rs: &RateSample, link: &mut Link) -> bool {
        self.update_bw(rs, link.delivered);
        self.update_ack_aggregation(rs, link);
        self.update_cycle_phase(rs, link);
        self.check_full_bw_reached(rs);
        self.check_drain(link);
        let probe_rtt = self.update_min_rtt(rs, link);
        self.update_gains();
        probe_rtt
    }

    /// C `bbr_update_bw`: bandwidth filter and round counter.
    fn update_bw(&mut self, rs: &RateSample, delivered: u32) {
        self.round_start = false;
        // A discarded sample neither starts a round nor updates the filter.
        if rs.delivered == 0 || rs.interval_ms == 0 {
            return;
        }
        if rs.prior_delivered.wrapping_sub(self.next_rtt_delivered) as i32 >= 0 {
            self.next_rtt_delivered = delivered;
            self.round_count = self.round_count.wrapping_add(1);
            self.round_start = true;
            self.packet_conservation = false;
        }
        let bw = f64::from(rs.delivered) / f64::from(rs.interval_ms);
        if !rs.is_app_limited || bw >= self.bw() {
            self.bw_filter
                .apply_max(BBR_BW_FILTER_CYCLES, u64::from(self.round_count), bw);
        }
    }

    /// C `bbr_update_ack_aggregation`, with epochs on `delivered_ts`.
    fn update_ack_aggregation(&mut self, rs: &RateSample, link: &Link) {
        if rs.acked_sacked == 0 || rs.delivered == 0 || rs.interval_ms == 0 {
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
        let epoch_ms = time_delta_ms(link.delivered_ts, self.ack_epoch_start);
        let mut expected_acked = (self.bw() * f64::from(epoch_ms)) as u32;
        // A slower ACK rate than expected, or a counter about to overflow
        // (C `bbr_ack_epoch_acked_reset_thresh`), starts a new epoch.
        if self.ack_epoch_acked <= expected_acked
            || u64::from(self.ack_epoch_acked) + u64::from(rs.acked_sacked) >= u64::from(u32::MAX)
        {
            self.ack_epoch_acked = 0;
            self.ack_epoch_start = link.delivered_ts;
            expected_acked = 0;
        }
        self.ack_epoch_acked += rs.acked_sacked;
        let extra_acked = (self.ack_epoch_acked - expected_acked).min(link.cwnd);
        if extra_acked > self.extra_acked[self.extra_acked_idx] {
            self.extra_acked[self.extra_acked_idx] = extra_acked;
        }
    }

    /// C `bbr_update_cycle_phase` / `bbr_is_next_cycle_phase`.
    fn update_cycle_phase(&mut self, rs: &RateSample, link: &Link) {
        if self.mode != BbrMode::ProbeBw {
            return;
        }
        let is_full_length =
            time_delta_ms(link.delivered_ts, self.cycle_timestamp) > self.min_rtt_ms;
        let next = if self.pacing_gain == 1.0 {
            is_full_length
        } else if self.pacing_gain > 1.0 {
            is_full_length
                && (rs.losses > 0 || link.inflight > self.bdp(self.bw(), self.pacing_gain))
        } else {
            is_full_length || link.inflight <= self.bdp(self.bw(), 1.0)
        };
        if next {
            self.advance_cycle_phase(link.delivered_ts);
        }
    }

    /// C `bbr_check_full_bw_reached`.
    fn check_full_bw_reached(&mut self, rs: &RateSample) {
        if self.full_bw_reached || !self.round_start || rs.is_app_limited {
            return;
        }
        if self.bw() >= self.full_bw * BBR_FULL_BW_THRESH {
            self.full_bw = self.bw();
            self.full_bw_count = 0;
            return;
        }
        self.full_bw_count += 1;
        self.full_bw_reached = self.full_bw_count >= BBR_FULL_BW_COUNT;
    }

    /// C `bbr_check_drain`.
    fn check_drain(&mut self, link: &Link) {
        if self.mode == BbrMode::Startup && self.full_bw_reached {
            tracing::debug!(from = ?BbrMode::Startup, to = ?BbrMode::Drain, "bbr: mode transition");
            self.mode = BbrMode::Drain;
        }
        if self.mode == BbrMode::Drain && link.inflight <= self.bdp(self.bw(), 1.0) {
            tracing::debug!(from = ?BbrMode::Drain, to = ?BbrMode::ProbeBw, "bbr: mode transition");
            self.reset_probe_bw_mode(link.delivered_ts);
        }
    }

    /// C `bbr_update_min_rtt`: the minimum-RTT filter and ProbeRTT. Returns
    /// true while in ProbeRTT.
    fn update_min_rtt(&mut self, rs: &RateSample, link: &mut Link) -> bool {
        let now = link.now_ms;
        let filter_expired = now > self.min_rtt_stamp + BBR_MIN_RTT_INTERVAL_MS;
        if rs.rtt_ms > 0 && (rs.rtt_ms < self.min_rtt_ms || filter_expired) {
            self.min_rtt_ms = rs.rtt_ms;
            self.min_rtt_stamp = now;
        }
        if filter_expired && !self.idle_restart && self.mode != BbrMode::ProbeRtt {
            tracing::debug!(from = ?self.mode, to = ?BbrMode::ProbeRtt, "bbr: mode transition");
            self.mode = BbrMode::ProbeRtt;
            self.save_cwnd(link.cwnd);
            self.probe_rtt_done_time = 0;
        }
        let probe_rtt = self.mode == BbrMode::ProbeRtt;
        if probe_rtt {
            if self.probe_rtt_done_time == 0 && link.inflight <= BBR_CWND_MIN_TARGET {
                self.probe_rtt_done_time = now + BBR_MIN_PROBE_RTT_MODE_MS;
                self.probe_rtt_round_done = false;
                self.next_rtt_delivered = link.delivered;
            } else if self.probe_rtt_done_time != 0 {
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

    /// C `bbr_check_probe_rtt_done`: after the dwell, restore the window
    /// and go back to Startup or ProbeBW.
    fn check_probe_rtt_done(&mut self, link: &mut Link) {
        if self.probe_rtt_done_time == 0 || link.now_ms <= self.probe_rtt_done_time {
            return;
        }
        self.min_rtt_stamp = link.now_ms;
        link.cwnd = link.cwnd.max(self.prior_cwnd);
        self.reset_mode(link.delivered_ts);
    }

    /// C `bbr_reset_mode`.
    fn reset_mode(&mut self, delivered_ts: u64) {
        if self.full_bw_reached {
            self.reset_probe_bw_mode(delivered_ts);
        } else {
            tracing::debug!(from = ?self.mode, to = ?BbrMode::Startup, "bbr: mode transition");
            self.mode = BbrMode::Startup;
        }
    }

    /// C `bbr_reset_probe_bw_mode`: ProbeBW from cycle phase 4.
    fn reset_probe_bw_mode(&mut self, delivered_ts: u64) {
        self.mode = BbrMode::ProbeBw;
        self.cycle_index = 3;
        self.advance_cycle_phase(delivered_ts);
    }

    /// C `bbr_advance_cycle_phase`.
    fn advance_cycle_phase(&mut self, delivered_ts: u64) {
        self.cycle_index = (self.cycle_index + 1) % BBR_CYCLE_LEN;
        self.cycle_timestamp = delivered_ts;
    }

    /// C `bbr_update_gains`.
    fn update_gains(&mut self) {
        (self.pacing_gain, self.cwnd_gain) = match self.mode {
            BbrMode::Startup => (BBR_HIGH_GAIN, BBR_HIGH_GAIN),
            BbrMode::Drain => (BBR_DRAIN_GAIN, BBR_HIGH_GAIN),
            BbrMode::ProbeBw => (BBR_PACING_GAIN[self.cycle_index as usize], BBR_CWND_GAIN),
            BbrMode::ProbeRtt => (1.0, 1.0),
        };
    }

    /// C `bbr_bw_to_pacing_rate`: bytes/ms for `bw` packets/ms, never 0.
    fn bw_to_pacing_rate(bw: f64, mss: u32, gain: f64) -> u64 {
        ((bw * f64::from(mss) * gain * BBR_PACING_MARGIN_PERCENT) as u64).max(1)
    }

    /// C `bbr_init_pacing_rate_from_rtt`: the window over the smoothed RTT
    /// (1 ms before a sample) at the startup gain.
    fn init_pacing_rate_from_rtt(&mut self, srtt: u32, cwnd: u32, mss: u32) {
        let srtt = if srtt > 0 {
            self.has_seen_rtt = true;
            srtt
        } else {
            1
        };
        let bw = f64::from(cwnd) / f64::from(srtt);
        self.pacing_rate = Self::bw_to_pacing_rate(bw, mss, BBR_HIGH_GAIN);
    }

    /// C `bbr_set_pacing_rate`: the first RTT sample re-seeds the rate from
    /// the window; until the pipe is full the rate only grows.
    fn set_pacing_rate(&mut self, bw: f64, gain: f64, link: &Link) {
        let rate = Self::bw_to_pacing_rate(bw, link.mss, gain);
        if !self.has_seen_rtt && link.srtt > 0 {
            self.init_pacing_rate_from_rtt(link.srtt, link.cwnd, link.mss);
        }
        if self.full_bw_reached || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    /// C `bbr_set_cwnd_to_recover_or_restore`: adjusts the window for
    /// losses and recovery; true while packet conservation holds it.
    fn set_cwnd_to_recover_or_restore(
        &mut self,
        rs: &RateSample,
        acked: u32,
        cwnd: &mut u32,
        link: &Link,
    ) -> bool {
        // An ACK for p packets releases at most 2p: deduct the losses first.
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

    /// C `bbr_set_cwnd`.
    fn set_cwnd(&mut self, rs: &RateSample, acked: u32, bw: f64, gain: f64, link: &mut Link) {
        let mut cwnd = link.cwnd;
        if acked > 0 && !self.set_cwnd_to_recover_or_restore(rs, acked, &mut cwnd, link) {
            let target = self
                .bdp(bw, gain)
                .saturating_add(self.ack_aggregation_cwnd());
            if self.full_bw_reached {
                cwnd = cwnd.saturating_add(acked).min(target);
            } else if cwnd < target || link.delivered < 10 {
                // Startup grows by what was ACKed, but only toward the
                // target once the first ten packets are delivered.
                cwnd = cwnd.saturating_add(acked);
            }
            cwnd = cwnd.max(BBR_CWND_MIN_TARGET);
        }
        // In ProbeRtt, enforce a tiny window to obtain a fresh RTT sample.
        if self.mode == BbrMode::ProbeRtt {
            cwnd = cwnd.min(BBR_CWND_MIN_TARGET);
        }
        link.cwnd = cwnd;
    }

    /// C `bbr_bdp` (also `bbr_inflight`): BDP × gain in packets; the initial
    /// window (10) before a minimum-RTT sample, else at least 1.
    fn bdp(&self, bw: f64, gain: f64) -> u32 {
        if self.min_rtt_ms == u32::MAX {
            return 10;
        }
        ((bw * f64::from(self.min_rtt_ms) * gain) as u32).max(1)
    }

    /// C `bbr_ack_aggregation_cwnd`: once the pipe is full, the recent ACK
    /// aggregation in packets, at most 100 ms worth at the current rate.
    fn ack_aggregation_cwnd(&self) -> u32 {
        if BBR_EXTRA_ACKED_GAIN == 0.0 || !self.full_bw_reached {
            return 0;
        }
        let max_aggr_cwnd = (self.bw() * BBR_EXTRA_ACKED_MAX_MS as f64) as u32;
        // C `bbr_extra_acked` returns a `uint16_t`.
        let extra = self.extra_acked[0].max(self.extra_acked[1]) as u16;
        ((BBR_EXTRA_ACKED_GAIN * f64::from(extra)) as u32).min(max_aggr_cwnd)
    }
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: u32 = 1180;

    fn make_rs(
        delivered: u32,
        interval_ms: u32,
        prior_delivered: u32,
        app_limited: bool,
    ) -> RateSample {
        let mut rs = RateSample::new(interval_ms);
        rs.delivered = delivered;
        rs.interval_ms = interval_ms;
        rs.acked_sacked = delivered;
        rs.prior_delivered = prior_delivered;
        rs.is_app_limited = app_limited;
        rs
    }

    fn link(cwnd: u32, delivered: u32, inflight: u32, now_ms: u64) -> Link {
        Link {
            cwnd,
            mss: MSS,
            delivered,
            delivered_ts: now_ms,
            srtt: 0,
            inflight,
            ca_state: CaState::Open,
            now_ms,
        }
    }

    /// Four rounds at a constant rate: full bandwidth, then Drain, then
    /// ProbeBW once inflight is under the BDP.
    fn into_probe_bw(state: &mut BbrState) {
        for i in 0_u32..4 {
            let rs = make_rs(10, 10, i * 10, false);
            state.main(&rs, &mut link(10, (i + 1) * 10, 100, 0));
        }
        assert_eq!(state.mode, BbrMode::Drain);
        let rs = make_rs(10, 10, 40, false);
        state.main(&rs, &mut link(10, 50, 1, 0));
        assert_eq!(state.mode, BbrMode::ProbeBw);
    }

    #[test]
    fn new_state_starts_up() {
        let state = BbrState::new(0, 10, MSS);
        assert_eq!(state.mode, BbrMode::Startup);
        assert_eq!(state.pacing_gain, BBR_HIGH_GAIN);
        assert_eq!(state.min_rtt_ms, u32::MAX);
    }

    #[test]
    fn full_bw_is_reached_after_three_flat_rounds() {
        let mut state = BbrState::new(0, 10, MSS);
        let rs = make_rs(10, 10, 0, false);
        state.main(&rs, &mut link(10, 10, 5, 0));
        for i in 1_u32..=3 {
            let rs = make_rs(10, 10, i * 10, false);
            state.main(&rs, &mut link(10, (i + 1) * 10, 5, 0));
        }
        assert_eq!(state.full_bw_count, BBR_FULL_BW_COUNT);
        assert!(state.full_bw_reached);
    }

    #[test]
    fn probe_bw_cycle_advances_after_min_rtt() {
        let mut state = BbrState::new(0, 10, MSS);
        into_probe_bw(&mut state);
        let before = state.cycle_index;
        let later = u64::from(state.min_rtt_ms) + 5;
        let rs = make_rs(10, 10, 50, false);
        state.main(&rs, &mut link(10, 60, 1, later));
        assert_eq!(state.cycle_index, (before + 1) % BBR_CYCLE_LEN);
    }

    #[test]
    fn save_cwnd_keeps_the_larger_window_in_probe_rtt() {
        let mut state = BbrState::new(0, 10, MSS);
        state.save_cwnd(42);
        assert_eq!(state.prior_cwnd, 42);
        state.mode = BbrMode::ProbeRtt;
        state.save_cwnd(30);
        assert_eq!(state.prior_cwnd, 42);
    }

    #[test]
    fn pacing_rate_applies_the_margin() {
        let mut state = BbrState::new(0, 10, MSS);
        state.full_bw_reached = true;
        // 1.0 packets/ms × 1180 bytes × 1.0 × 0.99 = 1168.2.
        state.set_pacing_rate(1.0, 1.0, &link(10, 0, 0, 0));
        assert_eq!(state.pacing_rate, 1168);
    }

    #[test]
    fn cwnd_never_goes_below_the_minimum_target() {
        let mut state = BbrState::new(0, 10, MSS);
        let rs = make_rs(1, 10, 0, false);
        let mut l = link(0, 0, 0, 0);
        state.set_cwnd(&rs, 1, 0.0, BBR_CWND_GAIN, &mut l);
        assert_eq!(l.cwnd, BBR_CWND_MIN_TARGET);
    }

    /// C `bbr_set_cwnd` (udx_bbr.c:239): in startup the window grows only
    /// while below the target or before ten packets are delivered.
    #[test]
    fn startup_cwnd_stops_at_the_target_after_ten_delivered() {
        let mut state = BbrState::new(0, 10, MSS);
        state.min_rtt_ms = 10;
        let rs = make_rs(5, 10, 0, false);
        // Target: bdp(0.5 pkt/ms × 10 ms × 2.885) = 14 packets; cwnd is 20.
        let mut l = link(20, 5, 10, 0);
        state.set_cwnd(&rs, 5, 0.5, BBR_HIGH_GAIN, &mut l);
        assert_eq!(l.cwnd, 25, "under ten delivered it still grows");
        let mut l = link(20, 50, 10, 0);
        state.set_cwnd(&rs, 5, 0.5, BBR_HIGH_GAIN, &mut l);
        assert_eq!(l.cwnd, 20);
    }

    /// C `bbr_update_bw` (udx_bbr.c:323-335): a discarded rate sample
    /// starts no round.
    #[test]
    fn discarded_sample_starts_no_round() {
        let mut state = BbrState::new(0, 10, MSS);
        state.update_bw(&make_rs(5, 0, 5, false), 10);
        assert!(!state.round_start);
        assert_eq!(state.round_count, 0);
        state.update_bw(&make_rs(5, 10, 5, false), 10);
        assert!(state.round_start);
        assert_eq!((state.round_count, state.next_rtt_delivered), (1, 10));
    }

    /// C `bbr_bw_to_pacing_rate` / `bbr_set_pacing_rate`: the rate is at
    /// least 1 byte/ms, the first RTT re-seeds it from the window, and in
    /// startup it only grows.
    #[test]
    fn pacing_rate_is_floored_seeded_and_only_grows_in_startup() {
        let mut state = BbrState::new(0, 10, MSS);
        state.pacing_rate = 1;
        let mut l = link(10, 0, 0, 0);
        l.srtt = 20;
        // Seeded from cwnd 10 / srtt 20 ms: 0.5 × 1180 × 2.88539 × 0.99.
        state.set_pacing_rate(0.1, BBR_HIGH_GAIN, &l);
        assert_eq!(state.pacing_rate, 1685);
        state.set_pacing_rate(1.0, BBR_HIGH_GAIN, &l);
        assert_eq!(state.pacing_rate, 3370);
        state.set_pacing_rate(0.1, BBR_HIGH_GAIN, &l);
        assert_eq!(state.pacing_rate, 3370);
        state.full_bw_reached = true;
        state.set_pacing_rate(0.1, BBR_HIGH_GAIN, &l);
        assert_eq!(state.pacing_rate, 337);
        state.set_pacing_rate(0.0, 1.0, &l);
        assert_eq!(state.pacing_rate, 1);
    }

    /// C `win_filter_f64_apply_common`: when the best bandwidth sample ages
    /// out, the estimate falls to the runner-up kept after a quarter window.
    #[test]
    fn bandwidth_filter_falls_back_to_the_aged_runner_up() {
        let mut state = BbrState::new(0, 10, MSS);
        for (round, bw) in [(1, 10.0), (4, 8.0), (7, 7.0), (12, 1.0)] {
            state.round_count = round - 1;
            state.next_rtt_delivered = 0;
            state.update_bw(&make_rs((bw * 10.0) as u32, 10, 0, false), 0);
            assert_eq!(state.round_count, round);
        }
        assert_eq!(state.bw(), 8.0);
    }

    // ── The former differences from C, one state-machine test each ──────────

    /// C `bbr_init` seeds the pacing rate from the initial window over a
    /// 1 ms RTT, so the first flight is paced (it was 0, "unpaced").
    #[test]
    fn first_flight_is_paced_from_the_initial_window() {
        let state = BbrState::new(0, 10, 1152);
        // 10 packets/ms × 1152 bytes × 2.88539 × 0.99 = 32907.3.
        assert_eq!(state.pacing_rate(), 32907);
    }

    /// C `bbr_on_rto` keeps `full_bw_reached` and `full_bw_count`.
    #[test]
    fn rto_keeps_full_bandwidth_reached() {
        let mut state = BbrState::new(0, 10, MSS);
        state.full_bw = 5.0;
        state.full_bw_count = 3;
        state.full_bw_reached = true;
        state.on_rto();
        assert!(state.full_bw_reached);
        assert_eq!(state.full_bw_count, 3);
        assert_eq!(state.full_bw, 0.0);
        assert!(state.round_start);
        assert_eq!(state.prev_ca_state, CaState::Loss);
    }

    /// C `bbr_on_transmit_start`: an app-limited restart in ProbeBW paces
    /// at gain 1, and in ProbeRTT it ends a finished dwell.
    #[test]
    fn transmit_start_repaces_probe_bw_and_ends_probe_rtt() {
        let mut state = BbrState::new(0, 10, MSS);
        state.bw_filter.apply_max(BBR_BW_FILTER_CYCLES, 0, 1.0);
        state.mode = BbrMode::ProbeBw;
        state.full_bw_reached = true;
        state.pacing_rate = 5000;
        let mut l = link(10, 0, 0, 0);
        state.on_transmit_start(false, &mut l);
        assert_eq!(state.pacing_rate, 5000, "not app-limited: unchanged");
        state.on_transmit_start(true, &mut l);
        assert_eq!(state.pacing_rate, 1168, "1 packet/ms × 1180 × 0.99");

        state.mode = BbrMode::ProbeRtt;
        state.probe_rtt_done_time = 100;
        state.prior_cwnd = 40;
        let mut l = link(4, 0, 0, 150);
        state.on_transmit_start(true, &mut l);
        assert_eq!(state.mode, BbrMode::ProbeBw);
        assert_eq!(l.cwnd, 40);
        assert_eq!(state.min_rtt_stamp, 150);
    }

    /// C `bbr_update_min_rtt` / `bbr_check_probe_rtt_done`: the dwell ends
    /// 200 ms after the first ACK with at most 4 in flight, whatever comes
    /// in flight later, once a round has passed; the window goes back to
    /// `prior_cwnd`, the mode to Startup unless the pipe was full, and the
    /// minimum-RTT stamp is not refreshed meanwhile.
    #[test]
    fn probe_rtt_dwell_exit_and_restore() {
        let mut state = BbrState::new(0, 10, MSS);
        state.min_rtt_ms = 10;
        state.full_bw_count = 1; // not reached: back to Startup
        let mut l = link(40, 100, 30, 10_001);
        state.main(&RateSample::new(0), &mut l);
        assert_eq!(state.mode, BbrMode::ProbeRtt);
        assert_eq!(state.prior_cwnd, 40);
        assert_eq!(l.cwnd, 4);
        assert_eq!(
            state.probe_rtt_done_time, 0,
            "dwell waits for <= 4 in flight"
        );

        let mut l = link(4, 100, 3, 10_050);
        state.main(&RateSample::new(0), &mut l);
        assert_eq!(state.probe_rtt_done_time, 10_250);
        assert_eq!(state.next_rtt_delivered, 100);
        assert_eq!(state.min_rtt_stamp, 0, "no refresh while probing");

        // More in flight does not restart the dwell.
        let mut l = link(4, 105, 10, 10_100);
        // App-limited samples leave `full_bw_count` alone.
        state.main(&make_rs(5, 20, 100, true), &mut l);
        assert_eq!(state.probe_rtt_done_time, 10_250);
        assert!(state.probe_rtt_round_done);

        let mut l = link(4, 110, 3, 10_251);
        state.main(&make_rs(5, 20, 105, true), &mut l);
        assert_eq!(state.mode, BbrMode::Startup);
        assert_eq!(l.cwnd, 40, "prior_cwnd restored");
    }

    /// C advances the ProbeBW cycle on `delivered_ts`: an ACK that only
    /// reports a loss, long after the last delivery, does not.
    #[test]
    fn cycle_phase_runs_on_delivered_ts() {
        let mut state = BbrState::new(0, 10, MSS);
        into_probe_bw(&mut state);
        state.cycle_index = 2; // gain 1.0
        state.update_gains();
        state.cycle_timestamp = 0;
        let mut rs = RateSample::new(0);
        rs.losses = 1;
        let mut l = link(10, 50, 1, 1_000);
        l.delivered_ts = 0;
        state.main(&rs, &mut l);
        assert_eq!(state.cycle_index, 2);
        l.delivered_ts = 1_000;
        state.main(&rs, &mut l);
        assert_eq!(state.cycle_index, 3);
    }

    /// C measures the ACK-aggregation epoch on `delivered_ts`.
    #[test]
    fn ack_aggregation_epoch_starts_at_delivered_ts() {
        let mut state = BbrState::new(0, 10, MSS);
        state.ack_epoch_acked = 0;
        let rs = make_rs(4, 10, 0, false);
        let mut l = link(10, 4, 0, 500);
        l.delivered_ts = 200;
        state.update_ack_aggregation(&rs, &l);
        assert_eq!(state.ack_epoch_start, 200);
        assert_eq!(state.ack_epoch_acked, 4);
    }
}
