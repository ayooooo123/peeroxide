//! Token-bucket pacer for BBR send-rate gating.

use std::time::{Duration, Instant};

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
    last_refill: Option<Instant>,
    /// Pacing rate set by BBR (bytes per millisecond).
    rate_bytes_per_ms: u32,
    /// Burst allowed before the first rate is known and after `reset`.
    initial_burst: u32,
}

impl TokenBucket {
    /// Create a new token bucket with initial burst of 2 * MSS.
    pub(crate) fn new(mss: u32) -> Self {
        Self {
            available: 2 * mss,
            last_refill: None,
            rate_bytes_per_ms: 0,
            initial_burst: 2 * mss,
        }
    }

    /// Set the pacing rate (called when BBR updates pacing).
    pub(crate) fn set_rate(&mut self, bytes_per_ms: u32) {
        self.rate_bytes_per_ms = bytes_per_ms;
    }

    /// Refill tokens for the whole milliseconds elapsed since the last refill.
    pub(crate) fn refill(&mut self, now: Instant) {
        let Some(last) = self.last_refill else {
            self.last_refill = Some(now);
            return;
        };
        let elapsed_ms = now.duration_since(last).as_millis() as u32;
        if elapsed_ms == 0 || self.rate_bytes_per_ms == 0 {
            return;
        }
        self.available = elapsed_ms.saturating_mul(self.rate_bytes_per_ms);
        self.last_refill = Some(last + Duration::from_millis(elapsed_ms as u64));
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
    /// anything (or no rate is known yet), else C's 1 ms refill timer
    /// (`stream_may_send` / `refill_pacing_timer`).
    pub(crate) fn delay(&self) -> Duration {
        if self.rate_bytes_per_ms == 0 || self.available > 0 {
            Duration::ZERO
        } else {
            Duration::from_millis(1)
        }
    }

    /// Reset the bucket (initial burst available).
    pub(crate) fn reset(&mut self, now: Instant) {
        self.available = self.initial_burst;
        self.last_refill = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_has_initial_burst() {
        let tb = TokenBucket::new(1180);
        assert_eq!(tb.available, 2360);
    }

    #[test]
    fn test_try_consume_success() {
        let mut tb = TokenBucket::new(1180);
        let now = Instant::now();

        assert!(tb.try_consume(2360, now));
        assert_eq!(tb.available, 0);
    }

    /// A packet larger than the balance still goes out; the bucket floors
    /// at zero instead of refusing (C `_send_packet`).
    #[test]
    fn test_try_consume_floors_at_zero() {
        let mut tb = TokenBucket::new(1180);
        let now = Instant::now();

        assert!(tb.try_consume(2361, now));
        assert_eq!(tb.available, 0);
        assert!(!tb.try_consume(1, now));
    }

    #[test]
    fn test_set_rate_and_refill() {
        let mut tb = TokenBucket::new(1180);
        let now = Instant::now();
        assert!(tb.try_consume(1000, now));

        tb.set_rate(100);
        let later = now + Duration::from_millis(10);
        tb.refill(later);

        assert_eq!(tb.available, 1000);
    }

    /// Polling faster than once per millisecond must not lose elapsed time
    /// (the old refill reset `last_refill` on every call, so a busy sender
    /// never earned tokens).
    #[test]
    fn test_refill_keeps_sub_millisecond_remainder() {
        let mut tb = TokenBucket::new(1180);
        let now = Instant::now();
        assert!(tb.try_consume(2360, now));
        tb.set_rate(20_000);

        tb.refill(now + Duration::from_micros(600));
        assert_eq!(tb.available, 0);
        tb.refill(now + Duration::from_micros(1200));
        assert_eq!(tb.available, 20_000);
        assert_eq!(tb.last_refill, Some(now + Duration::from_millis(1)));
    }

    #[test]
    fn test_delay_one_ms_when_exhausted() {
        let mut tb = TokenBucket::new(1180);
        let now = Instant::now();
        assert!(tb.try_consume(2360, now));

        tb.set_rate(100);
        assert_eq!(tb.delay(), Duration::from_millis(1));
    }

    #[test]
    fn test_delay_zero_when_available() {
        let tb = TokenBucket::new(1180);
        assert_eq!(tb.delay(), Duration::ZERO);
    }

    #[test]
    fn test_delay_zero_when_rate_zero() {
        let mut tb = TokenBucket::new(1180);
        let now = Instant::now();
        assert!(tb.try_consume(2360, now));

        assert_eq!(tb.delay(), Duration::ZERO);
    }

    /// Drive the bucket the way the stream's send loop does (a tick every
    /// millisecond, send while `delay()` is zero). At 625 B/ms, below one
    /// 1200-byte packet per tick, C still sends one packet per tick; a gate
    /// that waits for a whole packet's worth of tokens would send nothing.
    #[test]
    fn test_low_rate_sends_one_packet_per_tick() {
        let mut tb = TokenBucket::new(1180);
        let now = Instant::now();
        assert!(tb.try_consume(2360, now));
        tb.set_rate(625);

        let mut sent = 0;
        for ms in 1..=100 {
            let tick = now + Duration::from_millis(ms);
            tb.refill(tick);
            while tb.delay() == Duration::ZERO {
                assert!(tb.try_consume(1200, tick));
                sent += 1;
            }
        }
        assert!((95..=105).contains(&sent), "sent {sent} packets in 100 ms at 625 B/ms");
    }

    #[test]
    fn test_reset() {
        let mut tb = TokenBucket::new(1180);
        let now = Instant::now();
        assert!(tb.try_consume(500, now));

        tb.reset(now + Duration::from_millis(1));

        assert_eq!(tb.available, 2360);
        assert!(tb.last_refill.is_some());
    }
}
