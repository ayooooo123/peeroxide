//! Token-bucket pacer for BBR send-rate gating.

use std::time::{Duration, Instant};

/// Bytes in the bucket of a new stream (C `UDX_INIT_PACING_RATE`).
const INITIAL_BUCKET: u32 = 25_000;

/// Token bucket pacing for BBR congestion control.
/// Matches C libudx's `tb_available` / `tb_last_refill_ms` fields and
/// `update_pacing_time`: once a whole millisecond has passed the bucket is
/// set to `elapsed_ms * rate` (the burst is bounded by cwnd, not here).
/// Pure computation — no tokio timers.
#[derive(Debug, Clone)]
pub(crate) struct TokenBucket {
    /// Bytes currently available to send.
    available: u32,
    /// Last time tokens were refilled, advanced in whole milliseconds so
    /// sub-millisecond polling never discards elapsed time.
    last_refill: Instant,
    /// Pacing rate set by BBR (bytes per millisecond, at least 1).
    rate_bytes_per_ms: u32,
}

impl TokenBucket {
    /// A full initial bucket at BBR's initial rate, as C `udx_stream_init`.
    pub(crate) fn new(rate_bytes_per_ms: u32, now: Instant) -> Self {
        Self {
            available: INITIAL_BUCKET,
            last_refill: now,
            rate_bytes_per_ms,
        }
    }

    /// Set the pacing rate (called when BBR updates pacing).
    pub(crate) fn set_rate(&mut self, bytes_per_ms: u32) {
        self.rate_bytes_per_ms = bytes_per_ms;
    }

    /// Refill tokens for the whole milliseconds elapsed since the last refill.
    pub(crate) fn refill(&mut self, now: Instant) {
        let elapsed_ms = now.saturating_duration_since(self.last_refill).as_millis() as u32;
        if elapsed_ms == 0 {
            return;
        }
        self.available = elapsed_ms.saturating_mul(self.rate_bytes_per_ms);
        self.last_refill += Duration::from_millis(u64::from(elapsed_ms));
    }

    /// Spend `bytes` on a packet. Refills first. The bucket floors at zero,
    /// so any positive balance lets one packet out even when it is smaller
    /// than the packet (C `_send_packet`): the pacer never sends less than
    /// one packet per millisecond. Returns false when the bucket is empty.
    pub(crate) fn try_consume(&mut self, bytes: u32, now: Instant) -> bool {
        self.refill(now);
        if self.available == 0 {
            return false;
        }
        self.available = self.available.saturating_sub(bytes);
        true
    }

    /// Delay before the next packet may go out: zero while the bucket holds
    /// anything, else C's 1 ms refill timer (`stream_may_send` /
    /// `refill_pacing_timer`).
    pub(crate) fn delay(&self) -> Duration {
        if self.available > 0 {
            Duration::ZERO
        } else {
            Duration::from_millis(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_bucket_holds_c_initial_burst() {
        let tb = TokenBucket::new(100, Instant::now());
        assert_eq!(tb.available, 25_000);
        assert_eq!(tb.delay(), Duration::ZERO);
    }

    /// A packet larger than the balance still goes out; the bucket floors
    /// at zero instead of refusing (C `_send_packet`).
    #[test]
    fn try_consume_floors_at_zero() {
        let now = Instant::now();
        let mut tb = TokenBucket::new(100, now);
        assert!(tb.try_consume(25_001, now));
        assert_eq!(tb.available, 0);
        assert!(!tb.try_consume(1, now));
        assert_eq!(tb.delay(), Duration::from_millis(1));
    }

    #[test]
    fn refill_sets_elapsed_times_rate() {
        let now = Instant::now();
        let mut tb = TokenBucket::new(100, now);
        assert!(tb.try_consume(25_000, now));
        tb.refill(now + Duration::from_millis(10));
        assert_eq!(tb.available, 1000);
    }

    /// Polling faster than once per millisecond must not lose elapsed time.
    #[test]
    fn refill_keeps_sub_millisecond_remainder() {
        let now = Instant::now();
        let mut tb = TokenBucket::new(20_000, now);
        assert!(tb.try_consume(25_000, now));
        tb.refill(now + Duration::from_micros(600));
        assert_eq!(tb.available, 0);
        tb.refill(now + Duration::from_micros(1200));
        assert_eq!(tb.available, 20_000);
        assert_eq!(tb.last_refill, now + Duration::from_millis(1));
    }

    /// Drive the bucket the way the stream's send loop does (a tick every
    /// millisecond, send while `delay()` is zero). At 625 B/ms, below one
    /// 1200-byte packet per tick, C still sends one packet per tick; a gate
    /// that waits for a whole packet's worth of tokens would send nothing.
    #[test]
    fn low_rate_sends_one_packet_per_tick() {
        let now = Instant::now();
        let mut tb = TokenBucket::new(625, now);
        assert!(tb.try_consume(25_000, now));
        let mut sent = 0;
        for ms in 1..=100 {
            let tick = now + Duration::from_millis(ms);
            tb.refill(tick);
            while tb.delay() == Duration::ZERO {
                assert!(tb.try_consume(1200, tick));
                sent += 1;
            }
        }
        assert!(
            (95..=105).contains(&sent),
            "sent {sent} packets in 100 ms at 625 B/ms"
        );
    }
}
