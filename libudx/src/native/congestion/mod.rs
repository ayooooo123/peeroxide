pub(crate) mod bbr;
pub(crate) mod filter;
pub(crate) mod pacing;
pub(crate) mod rate;

use std::time::{Duration, Instant};

/// BBR cycle length.
pub(crate) const BBR_CYCLE_LEN: u32 = 8;
/// Number of cycles used by the bandwidth filter.
pub(crate) const BBR_BW_FILTER_CYCLES: u32 = BBR_CYCLE_LEN + 2;
/// Minimum interval between min-RTT samples, in milliseconds.
pub(crate) const BBR_MIN_RTT_INTERVAL_MS: u64 = 10_000;
/// Minimum time spent in ProbeRTT, in milliseconds.
pub(crate) const BBR_MIN_PROBE_RTT_MODE_MS: u64 = 200;
/// Default pacing margin.
pub(crate) const BBR_PACING_MARGIN_PERCENT: f64 = 0.99;
/// Startup/high gain constant.
pub(crate) const BBR_HIGH_GAIN: f64 = 2.885_39;
/// Drain gain constant.
pub(crate) const BBR_DRAIN_GAIN: f64 = 1.0 / 2.885_39;
/// Congestion window gain constant.
pub(crate) const BBR_CWND_GAIN: f64 = 2.0;
/// Per-cycle pacing gain table.
pub(crate) const BBR_PACING_GAIN: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
/// Minimum BBR cwnd target.
pub(crate) const BBR_CWND_MIN_TARGET: u32 = 4;
/// Threshold for declaring full bandwidth.
pub(crate) const BBR_FULL_BW_THRESH: f64 = 1.25;
/// Consecutive rounds required for full bandwidth.
pub(crate) const BBR_FULL_BW_COUNT: u32 = 3;
/// Extra-acked gain.
pub(crate) const BBR_EXTRA_ACKED_GAIN: f64 = 1.0;
/// Window length for extra-acked accounting, in RTTs.
pub(crate) const BBR_EXTRA_ACKED_WIN_RTTS: u32 = 5;
/// Maximum extra-acked sample age, in milliseconds.
pub(crate) const BBR_EXTRA_ACKED_MAX_MS: u64 = 100;

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

/// Congestion control of one stream: BBR, rate sampling and pacing, with
/// the C stream fields they read (`cwnd`, `ca_state`, `high_seq`).
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
    /// Payload bytes per packet (C `udx__max_payload`).
    mss: u32,
}

impl CongestionController {
    /// Initial congestion window in packets — C `udx_stream_init`.
    const INITIAL_CWND: u32 = 10;

    /// A controller for a stream created at `epoch` (ms 0 of its clock).
    pub(crate) fn new(mss: u32, epoch: Instant) -> Self {
        let bbr = bbr::BbrState::new(0, Self::INITIAL_CWND, mss);
        let pacing = pacing::TokenBucket::new(bbr.pacing_rate(), epoch);
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

    fn link(&self, srtt: u32, inflight: u32, now_ms: u64) -> bbr::Link {
        bbr::Link {
            cwnd: self.cwnd,
            mss: self.mss,
            delivered: self.rate.delivered,
            delivered_ts: self.rate.delivered_ts,
            srtt,
            inflight,
            ca_state: self.ca_state,
            now_ms,
        }
    }

    /// C `udx__rate_pkt_sent` for a packet (re)sent now.
    pub(crate) fn on_packet_sent(
        &mut self,
        nothing_outstanding: bool,
        now_ms: u64,
    ) -> rate::PacketRateInfo {
        self.rate.pkt_sent(nothing_outstanding, now_ms)
    }

    /// C `process_packet` tail: `udx__rate_gen` and `bbr_main` for an ACK
    /// that arrived with data in flight. `delivered` are the packets it
    /// delivered, `lost` the losses it revealed, `rtt_ms` the RACK RTT of
    /// its newest delivered packet (0 for none) and `rtt_min` the stream's
    /// RACK minimum RTT.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_ack(
        &mut self,
        delivered: &[rate::Delivered],
        lost: u32,
        inflight: u32,
        srtt: u32,
        rtt_ms: u32,
        rtt_min: u32,
        now_ms: u64,
    ) {
        let count = delivered.len() as u32;
        self.rate.delivered = self.rate.delivered.wrapping_add(count);
        let mut rs = rate::RateSample::new(rtt_ms);
        for packet in delivered {
            self.rate.pkt_delivered(packet, &mut rs);
        }
        self.rate.generate(count, lost, rtt_min, now_ms, &mut rs);
        let mut link = self.link(srtt, inflight, now_ms);
        if self.bbr.main(&rs, &mut link) {
            // C `bbr_update_min_rtt`: ProbeRTT keeps the sender app-limited.
            self.rate.app_limited = match self.rate.delivered.wrapping_add(inflight) {
                0 => 1,
                mark => mark,
            };
        }
        self.cwnd = link.cwnd;
        self.pacing.set_rate(self.bbr.pacing_rate());
        tracing::trace!(
            mode = ?self.bbr.mode(),
            cwnd = self.cwnd,
            pacing = self.bbr.pacing_rate(),
            inflight,
            "bbr: on_ack update"
        );
    }

    /// The cumulative ACK passed the recovery point (C `process_packet`:
    /// `ack > high_seq` ends Recovery or Loss).
    pub(crate) fn on_cumulative_ack(&mut self, ack: u32) {
        if self.ca_state != CaState::Open && (ack.wrapping_sub(self.high_seq) as i32) > 0 {
            self.ca_state = CaState::Open;
        }
    }

    /// C `rack_detect_loss` tail: `resending` packets were marked lost,
    /// `mtu_probes` of them MTU probes. An isolated MTU probe loss signals
    /// the path MTU, not congestion (RFC 4821): it counts no loss and opens
    /// no recovery. Returns the losses counted and whether recovery began
    /// (until the ACK passes `next_seq`).
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

    /// C `udx_rto_timeout`: remember the window to restore, enter Loss
    /// until the ACK passes `next_seq`. The caller sets `cwnd`.
    pub(crate) fn on_rto(&mut self, next_seq: u32) {
        self.bbr.save_cwnd(self.cwnd);
        self.high_seq = next_seq;
        self.ca_state = CaState::Loss;
        self.bbr.on_rto();
    }

    /// C `bbr_on_transmit_start`: a packet left with nothing in flight.
    pub(crate) fn on_transmit_start(&mut self, srtt: u32, inflight: u32, now_ms: u64) {
        let mut link = self.link(srtt, inflight, now_ms);
        self.bbr
            .on_transmit_start(self.rate.app_limited != 0, &mut link);
        self.cwnd = link.cwnd;
        self.pacing.set_rate(self.bbr.pacing_rate());
    }

    /// Returns whether sending is allowed given current inflight and remote receive window.
    /// Matches C `send_window_in_packets`: `min(cwnd, send_rwnd / max_payload)`,
    /// where any non-zero window allows at least one packet.
    pub(crate) fn can_send(&self, inflight: u32, send_rwnd: u32) -> bool {
        let rwnd_pkts = if send_rwnd == 0 {
            0
        } else {
            (send_rwnd / self.mss).max(1)
        };
        inflight < self.cwnd.min(rwnd_pkts)
    }

    /// Delay before the next packet may be sent (C `stream_may_send`).
    pub(crate) fn pacing_delay(&mut self, now: Instant) -> Duration {
        self.pacing.refill(now);
        self.pacing.delay()
    }

    /// BBR's window saved for after recovery.
    #[cfg(test)]
    pub(crate) fn prior_cwnd(&self) -> u32 {
        self.bbr.prior_cwnd()
    }

    /// The payload size changed with the MTU; C reads it afresh, and keeps
    /// the window in packets.
    pub(crate) fn on_mtu_change(&mut self, mss: u32) {
        self.mss = mss;
    }

    /// C `udx__rate_check_app_limited`, before each (re)send: less than a
    /// packet written and not yet ACKed (`unacked_written`, C
    /// `writes_queued_bytes`), room in the window and no retransmit waiting.
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

    /// C `udx_stream_init` + `bbr_init`: a 25000-byte bucket refilled at
    /// the rate seeded from the initial window, so the first flight is
    /// paced from the start (it used to be unpaced until the first ACK).
    #[test]
    fn first_flight_is_paced() {
        let epoch = Instant::now();
        let mut c = CongestionController::new(1152, epoch);
        assert_eq!(c.bbr.pacing_rate(), 32_907);
        assert!(c.pacing.try_consume(25_000, epoch));
        assert_eq!(c.pacing_delay(epoch), Duration::from_millis(1));
        assert_eq!(
            c.pacing_delay(epoch + Duration::from_millis(1)),
            Duration::ZERO
        );
    }

    fn delivered(seq: u32, time_sent: u64, info: PacketRateInfo) -> Delivered {
        Delivered {
            seq,
            time_sent,
            info,
        }
    }

    /// C `ack_packet` sets `rs->rtt_ms` to the RACK RTT of the delivered
    /// packet: BBR's minimum RTT follows it, not the time since the flight
    /// began (here 40 ms).
    #[test]
    fn rate_sample_rtt_is_the_rack_rtt() {
        let mut c = CongestionController::new(1180, Instant::now());
        let info = c.on_packet_sent(true, 0);
        c.on_ack(&[delivered(0, 33, info)], 0, 0, 7, 7, 7, 40);
        assert_eq!(c.bbr_min_rtt(), 7);
    }

    /// C `udx__rate_gen` discards a sample shorter than the stream's RACK
    /// minimum RTT, not BBR's: a 8 ms interval counts while the stream saw
    /// 5 ms, though BBR's minimum is 20 ms.
    #[test]
    fn rate_sample_is_discarded_against_the_stream_minimum_rtt() {
        let mut c = CongestionController::new(1180, Instant::now());
        let mut link = c.link(0, 0, 0);
        c.bbr.main(&rate::RateSample::new(20), &mut link);
        assert_eq!(c.bbr_min_rtt(), 20);
        let info = c.on_packet_sent(true, 100);
        c.on_ack(&[delivered(0, 100, info)], 0, 0, 20, 0, 5, 108);
        assert!(c.bbr_bw() > 0.0, "the 8 ms sample was kept");
        let mut d = CongestionController::new(1180, Instant::now());
        let info = d.on_packet_sent(true, 100);
        d.on_ack(&[delivered(0, 100, info)], 0, 0, 20, 0, 9, 108);
        assert_eq!(d.bbr_bw(), 0.0, "shorter than the stream's 9 ms: discarded");
    }

    /// C `udx__rate_check_app_limited` (udx_rate.c:113-118): a sender with a
    /// retransmit waiting, or a packet's worth written and unACKed, is not
    /// app-limited.
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

    impl CongestionController {
        fn bbr_min_rtt(&self) -> u32 {
            self.bbr.min_rtt_ms()
        }
        fn bbr_bw(&self) -> f64 {
            self.bbr.bw()
        }
    }
}
