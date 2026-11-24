pub(crate) mod bbr;
pub(crate) mod filter;
pub(crate) mod pacing;
pub(crate) mod rate;

use std::time::{Duration, Instant};

/// Minimum interval between min-RTT filter expirations, in microseconds (10 s).
pub(crate) const BBR_MIN_RTT_INTERVAL_US: u64 = 10_000_000;
/// Interval between ProbeRTT entries, in microseconds (10 s, matching BBRv1
/// cadence so flows sharing a queue with stock peers do not yield twice as often).
pub(crate) const BBR_PROBE_RTT_INTERVAL_US: u64 = 10_000_000;
/// Maximum time spent in ProbeRTT, in microseconds (200 ms).
pub(crate) const BBR_PROBE_RTT_MODE_US: u64 = 200_000;
/// BBRv3 ProbeRTT cwnd gain (`0.5 * BDP`, min 4 packets).
pub(crate) const BBR_PROBE_RTT_CWND_GAIN: f64 = 0.5;
/// Bandwidth filter window length in ProbeBW cycles (BBRv3 `max_bw` spans 2
/// full ProbeBW cycles so `max_bw` never expires during `ProbeBwCruise`).
pub(crate) const BBR_BW_FILTER_CYCLES: u32 = 2;
/// Default pacing margin (1% headroom below estimated delivery rate).
pub(crate) const BBR_PACING_MARGIN_PERCENT: f64 = 0.99;
/// Startup pacing gain (BBRv3).
pub(crate) const BBR_STARTUP_PACING_GAIN: f64 = 2.77;
/// Startup cwnd gain (BBRv3).
pub(crate) const BBR_STARTUP_CWND_GAIN: f64 = 2.0;
/// Drain pacing gain (BBRv3).
pub(crate) const BBR_DRAIN_GAIN: f64 = 0.35;
/// Steady-state ProbeBW cwnd gain.
pub(crate) const BBR_CWND_GAIN: f64 = 2.0;
/// ProbeBW phase pacing gains (BBRv3).
pub(crate) const BBR_PROBE_BW_DOWN_GAIN: f64 = 0.90;
pub(crate) const BBR_PROBE_BW_CRUISE_GAIN: f64 = 1.0;
pub(crate) const BBR_PROBE_BW_REFILL_GAIN: f64 = 1.0;
pub(crate) const BBR_PROBE_BW_UP_GAIN: f64 = 1.25;
/// Loss-aware short-term backoff factor (tuned for BBRv1 peer coexistence).
pub(crate) const BBR_BETA: f64 = 0.85;
/// Headroom fraction reserved below `inflight_hi` in Cruise/Down (`10%`).
pub(crate) const BBR_HEADROOM: f64 = 0.10;
/// Flight loss-rate threshold above which BBRv3 bounds inflight (`3%`,
/// avoiding false caps under 1% random loss while catching queue overflow).
pub(crate) const BBR_LOSS_THRESH: f64 = 0.03;
/// Loss events in one round that exit Startup when loss exceeds `BBR_LOSS_THRESH`.
pub(crate) const BBR_FULL_LOSS_CNT: u32 = 6;
/// Minimum BBR cwnd target.
pub(crate) const BBR_CWND_MIN_TARGET: u32 = 4;
/// Threshold for declaring full bandwidth.
pub(crate) const BBR_FULL_BW_THRESH: f64 = 1.25;
/// Consecutive flat rounds required for full bandwidth.
pub(crate) const BBR_FULL_BW_COUNT: u32 = 3;
/// Extra-acked gain.
pub(crate) const BBR_EXTRA_ACKED_GAIN: f64 = 1.0;
/// Window length for extra-acked accounting, in RTTs.
pub(crate) const BBR_EXTRA_ACKED_WIN_RTTS: u32 = 5;
/// Maximum extra-acked allowance, in microseconds (100 ms).
pub(crate) const BBR_EXTRA_ACKED_MAX_US: u64 = 100_000;

/// BBR operating mode, mirroring the four phases of the BBR algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BbrMode {
    /// Exponential bandwidth probing at startup.
    Startup = 0,
    /// Drain inflight back to BDP after startup overshoot.
    Drain = 1,
    /// Steady-state cycling through pacing gains.
    ProbeBw = 2,
    /// Periodic min-RTT measurement phase.
    ProbeRtt = 3,
}

/// Congestion avoidance state, tracking loss/recovery transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub(crate) enum CaState {
    /// Normal operation — no loss detected.
    Open = 1,
    /// Fast recovery after partial loss.
    Recovery = 2,
    /// RTO-triggered loss state.
    Loss = 3,
}

/// Congestion control of one stream: BBRv3, microsecond rate sampling, and
/// deficit-tracking pacing.
pub(crate) struct CongestionController {
    bbr: bbr::BbrState,
    rate: rate::RateState,
    /// Token-bucket pacer gating outbound transmissions.
    pub(crate) pacing: pacing::TokenBucket,
    /// Current congestion-avoidance state (open / recovery / loss).
    pub(crate) ca_state: CaState,
    /// First unsent seq when recovery or loss began (C `high_seq`).
    pub(crate) high_seq: u32,
    /// Current congestion window in packets.
    pub(crate) cwnd: u32,
    /// Payload bytes per packet.
    mss: u32,
}

impl CongestionController {
    /// Initial congestion window in packets — C `udx_stream_init`.
    const INITIAL_CWND: u32 = 10;

    /// A controller for a stream created at `epoch` (µs 0 of its clock).
    pub(crate) fn new(mss: u32, epoch: Instant) -> Self {
        let bbr = bbr::BbrState::new(0, Self::INITIAL_CWND, mss);
        let pacing = pacing::TokenBucket::new(bbr.pacing_rate_bps(), mss, epoch);
        Self {
            bbr,
            rate: rate::RateState::new(0),
            pacing,
            ca_state: CaState::Open,
            high_seq: 0,
            cwnd: Self::INITIAL_CWND,
            mss,
        }
    }

    fn link(&self, srtt_us: u64, inflight: u32, now_us: u64) -> bbr::Link {
        bbr::Link {
            cwnd: self.cwnd,
            mss: self.mss,
            delivered: self.rate.delivered,
            delivered_ts_us: self.rate.delivered_ts,
            srtt_us,
            inflight,
            ca_state: self.ca_state,
            now_us,
        }
    }

    /// Record delivery and inflight state for a packet (re)sent now.
    pub(crate) fn on_packet_sent(
        &mut self,
        nothing_outstanding: bool,
        inflight_after: u32,
        now_us: u64,
    ) -> rate::PacketRateInfo {
        self.rate
            .pkt_sent(nothing_outstanding, inflight_after, now_us)
    }

    /// Process an ACK that arrived with data in flight: generate a microsecond
    /// rate sample and advance BBRv3.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_ack(
        &mut self,
        delivered: &[rate::Delivered],
        lost: u32,
        inflight: u32,
        srtt_us: u64,
        rtt_us: u64,
        rtt_min_us: u64,
        now_us: u64,
    ) {
        let count = delivered.len() as u32;
        self.rate.delivered = self.rate.delivered.wrapping_add(count);
        let mut rs = rate::RateSample::new(rtt_us);
        for packet in delivered {
            self.rate.pkt_delivered(packet, &mut rs);
        }
        self.rate
            .generate(count, lost, rtt_min_us, now_us, &mut rs);
        let mut link = self.link(srtt_us, inflight, now_us);
        if self.bbr.main(&rs, &mut link) {
            self.rate.app_limited = match self.rate.delivered.wrapping_add(inflight) {
                0 => 1,
                mark => mark,
            };
        }
        self.cwnd = link.cwnd;
        self.pacing.set_rate_bps(self.bbr.pacing_rate_bps());
        tracing::trace!(
            mode = ?self.bbr.mode(),
            cwnd = self.cwnd,
            pacing_bps = self.bbr.pacing_rate_bps(),
            inflight,
            "bbr3: on_ack update"
        );
    }

    /// The cumulative ACK passed the recovery point (`ack > high_seq` ends Recovery or Loss).
    pub(crate) fn on_cumulative_ack(&mut self, ack: u32) {
        if self.ca_state != CaState::Open && (ack.wrapping_sub(self.high_seq) as i32) > 0 {
            self.ca_state = CaState::Open;
        }
    }

    /// `resending` packets were marked lost, `mtu_probes` of them MTU probes.
    /// An isolated MTU probe loss signals the path MTU, not congestion (RFC 4821).
    pub(crate) fn on_losses(
        &mut self,
        resending: u32,
        mtu_probes: u32,
        next_seq: u32,
    ) -> (u32, bool) {
        let counted = if resending == mtu_probes {
            0
        } else {
            resending
        };
        let recovery = resending > mtu_probes && self.ca_state == CaState::Open;
        if recovery {
            self.ca_state = CaState::Recovery;
            self.bbr.save_cwnd(self.cwnd);
            self.high_seq = next_seq;
        }
        (counted, recovery)
    }

    /// RTO fired: remember the window to restore and enter Loss.
    pub(crate) fn on_rto(&mut self, next_seq: u32) {
        self.bbr.save_cwnd(self.cwnd);
        self.high_seq = next_seq;
        self.ca_state = CaState::Loss;
        self.bbr.on_rto();
    }

    /// A packet left with nothing in flight.
    pub(crate) fn on_transmit_start(&mut self, srtt_us: u64, inflight: u32, now_us: u64) {
        let mut link = self.link(srtt_us, inflight, now_us);
        self.bbr
            .on_transmit_start(self.rate.app_limited != 0, &mut link);
        self.cwnd = link.cwnd;
        self.pacing.set_rate_bps(self.bbr.pacing_rate_bps());
    }

    /// Returns whether sending is allowed given current inflight and remote receive window.
    pub(crate) fn can_send(&self, inflight: u32, send_rwnd: u32) -> bool {
        let rwnd_pkts = if send_rwnd == 0 {
            0
        } else {
            (send_rwnd / self.mss).max(1)
        };
        inflight < self.cwnd.min(rwnd_pkts)
    }

    /// Delay before the next packet may be sent.
    pub(crate) fn pacing_delay(&mut self, now: Instant) -> Duration {
        self.pacing.refill(now);
        self.pacing.delay()
    }

    #[cfg(test)]
    pub(crate) fn prior_cwnd(&self) -> u32 {
        self.bbr.prior_cwnd()
    }

    pub(crate) fn on_mtu_change(&mut self, mss: u32) {
        self.mss = mss;
        self.pacing.set_mss(mss);
    }

    /// Mark the stream app-limited when less than a packet is queued/unacked,
    /// the window has room, and no retransmit is waiting.
    pub(crate) fn check_app_limited(
        &mut self,
        unacked_written: usize,
        inflight: u32,
        retransmit_pending: bool,
    ) {
        if unacked_written < self.mss as usize && inflight < self.cwnd && !retransmit_pending {
            self.rate.app_limited = match self.rate.delivered.wrapping_add(inflight) {
                0 => 1,
                mark => mark,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::rate::{Delivered, PacketRateInfo};
    use super::*;

    #[test]
    fn new_controller_opens_with_the_initial_window() {
        let controller = CongestionController::new(1200, Instant::now());
        assert_eq!(controller.ca_state, CaState::Open);
        assert_eq!(controller.cwnd, CongestionController::INITIAL_CWND);
        assert!(controller.can_send(0, 4_194_304));
    }

    fn delivered(seq: u32, time_sent_us: u64, info: PacketRateInfo) -> Delivered {
        Delivered {
            seq,
            time_sent_us,
            info,
        }
    }

    #[test]
    fn rate_sample_rtt_is_the_rack_rtt_in_microseconds() {
        let mut c = CongestionController::new(1180, Instant::now());
        let info = c.on_packet_sent(true, 1, 0);
        c.on_ack(
            &[delivered(0, 33_000, info)],
            0,
            0,
            7_500,
            7_500,
            7_500,
            40_000,
        );
        assert_eq!(c.bbr.min_rtt_us(), 7_500);
    }

    #[test]
    fn app_limited_reads_written_unacked_bytes() {
        let mut c = CongestionController::new(1180, Instant::now());
        c.rate.app_limited = 0;
        c.rate.delivered = 20;
        c.check_app_limited(0, 3, true);
        assert_eq!(c.rate.app_limited, 0);
        c.check_app_limited(1180, 3, false);
        assert_eq!(c.rate.app_limited, 0);
        c.check_app_limited(1179, 3, false);
        assert_eq!(c.rate.app_limited, 23);
    }
}
