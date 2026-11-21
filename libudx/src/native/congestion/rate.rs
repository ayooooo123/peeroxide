//! Rate sampling for BBR congestion control.
//!
//! Port of `udx_rate.c` (the version udx-native 1.22.1 pins). Each packet
//! carries the delivery state at its (re)transmission; when packets are
//! delivered, the most recently sent one gives the sample's interval.
//! Times are whole milliseconds on the stream's clock, like C's `uv_now`.

/// Per-packet delivery state taken at each (re)transmission (C
/// `pkt->first_sent_ts`, `delivered_ts`, `delivered`, `is_app_limited`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct PacketRateInfo {
    pub(crate) first_sent_ts: u64,
    pub(crate) delivered_ts: u64,
    pub(crate) delivered: u32,
    pub(crate) is_app_limited: bool,
}

/// A packet the peer delivered, as `udx__rate_pkt_delivered` reads it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Delivered {
    pub(crate) seq: u32,
    /// Last (re)transmission time (C `pkt->time_sent`).
    pub(crate) time_sent: u64,
    pub(crate) info: PacketRateInfo,
}

/// One ACK's rate sample (C `udx_rate_sample_t`, fresh per ACK). C's `-1`
/// ("none") is 0 for `delivered`, `interval_ms` and `rtt_ms`: a real
/// delivery count or RTT is never 0 there.
#[derive(Debug, Clone, Default)]
pub(crate) struct RateSample {
    pub(crate) delivered: u32,
    pub(crate) interval_ms: u32,
    pub(crate) rtt_ms: u32,
    pub(crate) losses: u32,
    pub(crate) acked_sacked: u32,
    pub(crate) is_app_limited: bool,
    pub(crate) prior_delivered: u32,
    pub(crate) prior_timestamp: Option<u64>,
    /// Seq of the packet the sample is taken from.
    seq: u32,
}

impl RateSample {
    /// A sample for one ACK; `rtt_ms` is the RACK RTT of the ACK's newest
    /// delivered packet (C `rs->rtt_ms`), 0 for none.
    pub(crate) fn new(rtt_ms: u32) -> Self {
        Self {
            rtt_ms,
            ..Self::default()
        }
    }
}

/// Stream-level delivery state (C `stream->delivered`, `delivered_ts`,
/// `first_sent_ts`, `app_limited`, `rate_*`).
#[derive(Debug, Clone)]
pub(crate) struct RateState {
    /// Packets delivered so far.
    pub(crate) delivered: u32,
    /// When `delivered` last grew, or a flight started from nothing outstanding.
    pub(crate) delivered_ts: u64,
    /// Send time of the newest delivered packet, or the start of a flight.
    first_sent_ts: u64,
    /// `delivered` mark until which the sender is app-limited; 0 = not.
    pub(crate) app_limited: u32,
    rate_delivered: u32,
    rate_interval_ms: u32,
}

/// C `rack_sent_after`: `(t1, seq1)` was sent after `(t2, seq2)`.
fn sent_after(t1: u64, seq1: u32, t2: u64, seq2: u32) -> bool {
    t1 > t2 || (t1 == t2 && (seq1.wrapping_sub(seq2) as i32) > 0)
}

/// C `stamp_ms_delta`: `t1 - t0`, at least 0.
fn ms_delta(t1: u64, t0: u64) -> u32 {
    t1.saturating_sub(t0).min(u64::from(u32::MAX)) as u32
}

impl RateState {
    pub(crate) fn new(now_ms: u64) -> Self {
        Self {
            delivered: 0,
            delivered_ts: now_ms,
            first_sent_ts: now_ms,
            // Initially app-limited, as C `udx_stream_init` (`~0`).
            app_limited: u32::MAX,
            rate_delivered: 0,
            rate_interval_ms: 0,
        }
    }

    /// C `udx__rate_pkt_sent`: the delivery state for a packet about to be
    /// (re)sent. With nothing outstanding, a new flight starts now.
    pub(crate) fn pkt_sent(&mut self, nothing_outstanding: bool, now_ms: u64) -> PacketRateInfo {
        if nothing_outstanding {
            self.first_sent_ts = now_ms;
            self.delivered_ts = now_ms;
        }
        PacketRateInfo {
            first_sent_ts: self.first_sent_ts,
            delivered_ts: self.delivered_ts,
            delivered: self.delivered,
            is_app_limited: self.app_limited != 0,
        }
    }

    /// C `udx__rate_pkt_delivered`: the most recently sent delivered packet
    /// gives the sample's prior state and its send interval.
    pub(crate) fn pkt_delivered(&mut self, pkt: &Delivered, rs: &mut RateSample) {
        if rs.prior_delivered == 0 || sent_after(pkt.time_sent, pkt.seq, self.first_sent_ts, rs.seq)
        {
            rs.prior_delivered = pkt.info.delivered;
            rs.prior_timestamp = Some(pkt.info.delivered_ts);
            rs.is_app_limited = pkt.info.is_app_limited;
            rs.seq = pkt.seq;
            self.first_sent_ts = pkt.time_sent;
            rs.interval_ms = ms_delta(self.first_sent_ts, pkt.info.first_sent_ts);
        }
    }

    /// C `udx__rate_gen`, after `delivered` packets were counted into
    /// `self.delivered` and `lost` declared lost: completes `rs`. An
    /// interval shorter than the stream's minimum RTT (`rtt_min`, C
    /// `udx_rtt_min`) is discarded (`interval_ms` 0).
    pub(crate) fn generate(
        &mut self,
        delivered: u32,
        lost: u32,
        rtt_min: u32,
        now_ms: u64,
        rs: &mut RateSample,
    ) {
        // The app-limited bubble is ACKed and gone.
        if self.app_limited != 0 && (self.delivered.wrapping_sub(self.app_limited) as i32) > 0 {
            self.app_limited = 0;
        }
        if delivered > 0 {
            self.delivered_ts = now_ms;
        }
        rs.acked_sacked = delivered;
        rs.losses = lost;
        let Some(prior_timestamp) = rs.prior_timestamp else {
            rs.delivered = 0;
            rs.interval_ms = 0;
            return;
        };
        rs.delivered = self.delivered.wrapping_sub(rs.prior_delivered);
        let snd_ms = rs.interval_ms;
        let ack_ms = ms_delta(now_ms, prior_timestamp);
        rs.interval_ms = snd_ms.max(ack_ms);
        if rs.interval_ms < rtt_min {
            rs.interval_ms = 0;
            return;
        }
        if !rs.is_app_limited
            || u64::from(rs.delivered) * u64::from(self.rate_interval_ms)
                >= u64::from(self.rate_delivered) * u64::from(rs.interval_ms)
        {
            self.rate_delivered = rs.delivered;
            self.rate_interval_ms = rs.interval_ms;
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
        }
    }

    #[test]
    fn pkt_sent_starts_a_flight_only_from_nothing_outstanding() {
        let mut rate = RateState::new(0);
        rate.delivered = 5;
        let first = rate.pkt_sent(true, 10);
        assert_eq!(
            (first.first_sent_ts, first.delivered_ts, first.delivered),
            (10, 10, 5)
        );
        let next = rate.pkt_sent(false, 12);
        assert_eq!((next.first_sent_ts, next.delivered_ts), (10, 10));
    }

    /// C `udx__rate_pkt_delivered`: the most recently *sent* packet wins,
    /// and the send interval runs from its flight's start to its send time.
    #[test]
    fn newest_sent_packet_gives_the_sample() {
        let mut rate = RateState::new(0);
        let mut rs = RateSample::new(5);
        let late = Delivered {
            seq: 4,
            time_sent: 30,
            info: info(10, 10, 7),
        };
        let early = Delivered {
            seq: 3,
            time_sent: 20,
            info: info(10, 10, 6),
        };
        rate.pkt_delivered(&late, &mut rs);
        rate.pkt_delivered(&early, &mut rs);
        assert_eq!((rs.prior_delivered, rs.interval_ms), (7, 20));
    }

    #[test]
    fn gen_takes_the_longer_of_send_and_ack_intervals() {
        let mut rate = RateState::new(0);
        let mut rs = RateSample::new(5);
        rate.pkt_delivered(
            &Delivered {
                seq: 0,
                time_sent: 2,
                info: info(0, 0, 0),
            },
            &mut rs,
        );
        rate.delivered = 1;
        rate.generate(1, 0, 5, 10, &mut rs);
        assert_eq!((rs.delivered, rs.interval_ms), (1, 10));
        assert_eq!(rate.delivered_ts, 10);
    }

    /// A short interval is discarded, but the sample keeps its delivered
    /// count (C clears only `interval_ms`), which ends BBR's idle restart.
    #[test]
    fn short_interval_is_discarded_but_keeps_delivered() {
        let mut rate = RateState::new(0);
        let mut rs = RateSample::new(1);
        rate.pkt_delivered(
            &Delivered {
                seq: 0,
                time_sent: 0,
                info: info(0, 0, 0),
            },
            &mut rs,
        );
        rate.delivered = 1;
        rate.generate(1, 0, 5, 2, &mut rs);
        assert_eq!((rs.delivered, rs.interval_ms), (1, 0));
    }

    #[test]
    fn no_delivered_packet_means_no_sample() {
        let mut rate = RateState::new(0);
        let mut rs = RateSample::new(0);
        rate.generate(0, 1, 5, 10, &mut rs);
        assert_eq!((rs.delivered, rs.interval_ms, rs.losses), (0, 0, 1));
    }
}
