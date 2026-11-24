//! Microsecond rate sampling for BBRv3 congestion control.
//!
//! Tracks per-packet delivery state, microsecond send/ack intervals, and
//! per-flight loss counts (`tx_in_flight`, `lost`) needed by BBRv3's
//! loss-aware `inflight_hi` and lower-bound adaptation.

/// Per-packet delivery state captured at each (re)transmission.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PacketRateInfo {
    pub(crate) first_sent_ts: u64,
    pub(crate) delivered_ts: u64,
    pub(crate) delivered: u32,
    pub(crate) is_app_limited: bool,
    /// Packets in flight (including this packet) when it was sent.
    pub(crate) tx_in_flight: u32,
    /// Cumulative stream loss count when this packet was sent.
    pub(crate) lost_at_send: u32,
}

/// A packet the peer delivered, as fed to `pkt_delivered`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Delivered {
    pub(crate) seq: u32,
    /// Last (re)transmission time in microseconds since stream epoch.
    pub(crate) time_sent_us: u64,
    pub(crate) info: PacketRateInfo,
}

/// One ACK's rate sample (fresh per ACK). Zero means "none" for `delivered`,
/// `interval_us`, and `rtt_us`.
#[derive(Debug, Clone, Default)]
pub(crate) struct RateSample {
    pub(crate) delivered: u32,
    pub(crate) interval_us: u64,
    pub(crate) rtt_us: u64,
    /// Losses newly declared by this ACK.
    pub(crate) losses: u32,
    /// Packets delivered by this ACK (cumulative + SACK).
    pub(crate) acked_sacked: u32,
    pub(crate) is_app_limited: bool,
    pub(crate) prior_delivered: u32,
    pub(crate) prior_timestamp: Option<u64>,
    /// Packets in flight when the sampled packet was sent (`rs.tx_in_flight`).
    pub(crate) tx_in_flight: u32,
    /// Packets lost between when the sampled packet was sent and now (`rs.lost`).
    pub(crate) lost_in_flight: u32,
    /// Seq of the packet the sample is taken from.
    seq: u32,
}

impl RateSample {
    /// A sample for one ACK; `rtt_us` is the RACK RTT of the ACK's newest
    /// delivered packet in microseconds (0 for none).
    pub(crate) fn new(rtt_us: u64) -> Self {
        Self {
            rtt_us,
            ..Self::default()
        }
    }
}

/// Stream-level delivery state in microseconds.
#[derive(Debug, Clone)]
pub(crate) struct RateState {
    /// Packets delivered so far.
    pub(crate) delivered: u32,
    /// When `delivered` last grew, or a flight started from nothing outstanding (µs).
    pub(crate) delivered_ts: u64,
    /// Send time of the newest delivered packet, or the start of a flight (µs).
    first_sent_ts: u64,
    /// `delivered` mark until which the sender is app-limited; 0 = not.
    pub(crate) app_limited: u32,
    /// Cumulative packets marked lost on this stream (for `rs.lost_in_flight`).
    pub(crate) lost_total: u32,
    rate_delivered: u32,
    rate_interval_us: u64,
}

/// `(t1, seq1)` was sent after `(t2, seq2)`.
fn sent_after(t1: u64, seq1: u32, t2: u64, seq2: u32) -> bool {
    t1 > t2 || (t1 == t2 && (seq1.wrapping_sub(seq2) as i32) > 0)
}

impl RateState {
    pub(crate) fn new(now_us: u64) -> Self {
        Self {
            delivered: 0,
            delivered_ts: now_us,
            first_sent_ts: now_us,
            // Initially app-limited, as C `udx_stream_init` (`~0`).
            app_limited: u32::MAX,
            lost_total: 0,
            rate_delivered: 0,
            rate_interval_us: 0,
        }
    }

    /// Record the delivery state for a packet about to be (re)sent.
    /// `inflight_after` is the number of packets in flight including this one.
    pub(crate) fn pkt_sent(
        &mut self,
        nothing_outstanding: bool,
        inflight_after: u32,
        now_us: u64,
    ) -> PacketRateInfo {
        if nothing_outstanding {
            self.first_sent_ts = now_us;
            self.delivered_ts = now_us;
        }
        PacketRateInfo {
            first_sent_ts: self.first_sent_ts,
            delivered_ts: self.delivered_ts,
            delivered: self.delivered,
            is_app_limited: self.app_limited != 0,
            tx_in_flight: inflight_after.max(1),
            lost_at_send: self.lost_total,
        }
    }

    /// The most recently sent delivered packet gives the sample's prior state,
    /// its send interval, and its flight-level `tx_in_flight` / `lost` counts.
    pub(crate) fn pkt_delivered(&mut self, pkt: &Delivered, rs: &mut RateSample) {
        if rs.prior_delivered == 0
            || sent_after(pkt.time_sent_us, pkt.seq, self.first_sent_ts, rs.seq)
        {
            rs.prior_delivered = pkt.info.delivered;
            rs.prior_timestamp = Some(pkt.info.delivered_ts);
            rs.is_app_limited = pkt.info.is_app_limited;
            rs.tx_in_flight = pkt.info.tx_in_flight;
            rs.lost_in_flight = self.lost_total.wrapping_sub(pkt.info.lost_at_send);
            rs.seq = pkt.seq;
            self.first_sent_ts = pkt.time_sent_us;
            rs.interval_us = self.first_sent_ts.saturating_sub(pkt.info.first_sent_ts);
        }
    }

    /// Complete `rs` after `delivered` packets were counted into
    /// `self.delivered` and `lost` packets were newly declared lost.
    /// An interval shorter than the stream's minimum RTT (`rtt_min_us`) is
    /// discarded (`interval_us = 0`).
    pub(crate) fn generate(
        &mut self,
        delivered: u32,
        lost: u32,
        rtt_min_us: u64,
        now_us: u64,
        rs: &mut RateSample,
    ) {
        self.lost_total = self.lost_total.wrapping_add(lost);
        // Include losses declared on this ACK in the flight's loss count.
        if rs.prior_timestamp.is_some() {
            rs.lost_in_flight = rs.lost_in_flight.saturating_add(lost);
        }
        // The app-limited bubble is ACKed and gone.
        if self.app_limited != 0 && (self.delivered.wrapping_sub(self.app_limited) as i32) > 0 {
            self.app_limited = 0;
        }
        if delivered > 0 {
            self.delivered_ts = now_us;
        }
        rs.acked_sacked = delivered;
        rs.losses = lost;
        let Some(prior_timestamp) = rs.prior_timestamp else {
            rs.delivered = 0;
            rs.interval_us = 0;
            return;
        };
        rs.delivered = self.delivered.wrapping_sub(rs.prior_delivered);
        let snd_us = rs.interval_us;
        let ack_us = now_us.saturating_sub(prior_timestamp);
        rs.interval_us = snd_us.max(ack_us);
        if rs.interval_us < rtt_min_us || rs.interval_us == 0 {
            rs.interval_us = 0;
            return;
        }
        if !rs.is_app_limited
            || u128::from(rs.delivered) * u128::from(self.rate_interval_us)
                >= u128::from(self.rate_delivered) * u128::from(rs.interval_us)
        {
            self.rate_delivered = rs.delivered;
            self.rate_interval_us = rs.interval_us;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(first_sent_ts: u64, delivered_ts: u64, delivered: u32) -> PacketRateInfo {
        PacketRateInfo {
            first_sent_ts,
            delivered_ts,
            delivered,
            is_app_limited: false,
            tx_in_flight: 10,
            lost_at_send: 0,
        }
    }

    #[test]
    fn pkt_sent_starts_a_flight_only_from_nothing_outstanding() {
        let mut rate = RateState::new(0);
        rate.delivered = 5;
        let first = rate.pkt_sent(true, 1, 10_000);
        assert_eq!(
            (
                first.first_sent_ts,
                first.delivered_ts,
                first.delivered,
                first.tx_in_flight
            ),
            (10_000, 10_000, 5, 1)
        );
        let next = rate.pkt_sent(false, 2, 12_000);
        assert_eq!(
            (next.first_sent_ts, next.delivered_ts, next.tx_in_flight),
            (10_000, 10_000, 2)
        );
    }

    #[test]
    fn newest_sent_packet_gives_the_sample() {
        let mut rate = RateState::new(0);
        let mut rs = RateSample::new(5_000);
        let late = Delivered {
            seq: 4,
            time_sent_us: 30_000,
            info: info(10_000, 10_000, 7),
        };
        let early = Delivered {
            seq: 3,
            time_sent_us: 20_000,
            info: info(10_000, 10_000, 6),
        };
        rate.pkt_delivered(&late, &mut rs);
        rate.pkt_delivered(&early, &mut rs);
        assert_eq!((rs.prior_delivered, rs.interval_us), (7, 20_000));
    }

    #[test]
    fn sub_millisecond_interval_is_preserved_in_microseconds() {
        let mut rate = RateState::new(0);
        let mut rs = RateSample::new(300);
        rate.pkt_delivered(
            &Delivered {
                seq: 0,
                time_sent_us: 100,
                info: info(0, 0, 0),
            },
            &mut rs,
        );
        rate.delivered = 10;
        rate.generate(10, 0, 300, 400, &mut rs);
        assert_eq!((rs.delivered, rs.interval_us), (10, 400));
    }

    #[test]
    fn short_interval_is_discarded_but_keeps_delivered() {
        let mut rate = RateState::new(0);
        let mut rs = RateSample::new(1_000);
        rate.pkt_delivered(
            &Delivered {
                seq: 0,
                time_sent_us: 0,
                info: info(0, 0, 0),
            },
            &mut rs,
        );
        rate.delivered = 1;
        rate.generate(1, 0, 5_000, 2_000, &mut rs);
        assert_eq!((rs.delivered, rs.interval_us), (1, 0));
    }

    #[test]
    fn flight_losses_accumulate_into_rate_sample() {
        let mut rate = RateState::new(0);
        let pkt_info = rate.pkt_sent(true, 50, 0);
        rate.lost_total = 2;
        let mut rs = RateSample::new(10_000);
        rate.pkt_delivered(
            &Delivered {
                seq: 1,
                time_sent_us: 5_000,
                info: pkt_info,
            },
            &mut rs,
        );
        rate.delivered = 47;
        rate.generate(47, 1, 10_000, 15_000, &mut rs);
        assert_eq!(rs.tx_in_flight, 50);
        assert_eq!(rs.lost_in_flight, 3);
    }
}
