//! Deficit-tracking microsecond pacer for BBR send-rate gating.
//!
//! Replaces the 1 ms reset bucket (which enforced a minimum of one full packet
//! per millisecond, ~11.6 Mbit/s, overshot film-rate pacing by ~45%, and dumped
//! ~125 KiB bursts at 1 Gbit/s) with exact nanosecond token accrual and deficit
//! carry-over. Burst capacity scales with the pacing rate up to one UDP GSO
//! send (`65_507` bytes), keeping GSO batching intact at high rates while pacing
//! smoothly down to low bitrates.

use std::time::{Duration, Instant};

/// Bytes in the bucket of a new stream (C `UDX_INIT_PACING_RATE`).
const INITIAL_BUCKET_BYTES: u64 = 25_000;

/// Largest burst the pacer accumulates while idle: one max UDP GSO send.
const MAX_BURST_BYTES: u64 = 65_507;

/// Minimum pacing rate (bytes/s) to prevent division by zero or infinite waits.
const MIN_RATE_BPS: u64 = 1_200;

/// Fixed-point scale: 1 byte = `MICRO_BYTES` micro-bytes, avoiding floating-point
/// drift while preserving exact sub-microsecond remainders.
const MICRO_BYTES: i128 = 1_000_000;

/// Minimum non-zero pacing delay returned to the async timer, avoiding spin
/// wakeups on sub-50 µs deficits while keeping multi-Gbit/s pacing accurate.
const MIN_SLEEP_NS: u64 = 50_000;

/// Maximum pacing delay cap (1 s).
const MAX_SLEEP_NS: u64 = 1_000_000_000;

/// Deficit-tracking microsecond token bucket for BBR congestion control.
/// Pure computation — no tokio timers.
#[derive(Debug, Clone)]
pub(crate) struct TokenBucket {
    /// Available budget in micro-bytes (`bytes * 1_000_000`). May go negative
    /// when a packet consumes more than the current balance; the deficit is
    /// paid back before the next packet leaves, eliminating rate overshoot.
    tokens_ub: i128,
    /// Last timestamp at which tokens were refilled.
    last_refill: Instant,
    /// Pacing rate set by BBR, in bytes per second (at least [`MIN_RATE_BPS`]).
    rate_bps: u64,
    /// Current payload size (for minimum burst sizing).
    mss: u32,
}

impl TokenBucket {
    /// A full initial bucket at BBR's initial rate (bytes/s).
    pub(crate) fn new(rate_bps: u64, mss: u32, now: Instant) -> Self {
        Self {
            tokens_ub: i128::from(INITIAL_BUCKET_BYTES) * MICRO_BYTES,
            last_refill: now,
            rate_bps: rate_bps.max(MIN_RATE_BPS),
            mss: mss.max(1),
        }
    }

    /// Set the pacing rate in bytes per second.
    pub(crate) fn set_rate_bps(&mut self, rate_bps: u64) {
        self.rate_bps = rate_bps.max(MIN_RATE_BPS);
    }

    /// Update MSS after a PMTU step.
    pub(crate) fn set_mss(&mut self, mss: u32) {
        self.mss = mss.max(1);
    }

    /// Maximum burst credit in bytes: ~1 ms of traffic at the current rate,
    /// floored at 2 packets (so low rates stay smooth without overshooting)
    /// and capped at one max UDP GSO burst (`65_507` bytes).
    fn burst_cap_bytes(&self) -> u64 {
        let one_ms = self.rate_bps / 1_000;
        let min_burst = u64::from(self.mss).saturating_mul(2);
        one_ms.clamp(min_burst, MAX_BURST_BYTES)
    }

    /// Refill tokens for the exact nanoseconds elapsed since the last refill.
    pub(crate) fn refill(&mut self, now: Instant) {
        let elapsed_ns = now.saturating_duration_since(self.last_refill).as_nanos();
        if elapsed_ns == 0 {
            return;
        }
        // `bytes * 1e6 = elapsed_ns * rate_bps / 1e3` (since 1 s = 1e9 ns).
        let added_ub = (elapsed_ns.saturating_mul(u128::from(self.rate_bps)) / 1_000)
            .min(i128::MAX as u128) as i128;
        if added_ub == 0 {
            // Very tiny elapsed time at a low rate: leave `last_refill` alone
            // so sub-microbyte time accumulates cleanly on the next call.
            return;
        }
        self.last_refill = now;
        let cap_ub = i128::from(self.burst_cap_bytes()) * MICRO_BYTES;
        // Preserve the larger initial burst until it has been spent, and cap
        // idle accumulation at `burst_cap_bytes`.
        let ceiling = self.tokens_ub.max(cap_ub);
        self.tokens_ub = self.tokens_ub.saturating_add(added_ub).min(ceiling);
    }

    /// Spend `bytes` on a packet. Refills first. Returns false when no positive
    /// credit is available; otherwise subtracts `bytes` (carrying any deficit
    /// forward) and returns true.
    pub(crate) fn try_consume(&mut self, bytes: u32, now: Instant) -> bool {
        self.refill(now);
        if self.tokens_ub <= 0 {
            return false;
        }
        self.tokens_ub -= i128::from(bytes) * MICRO_BYTES;
        true
    }

    /// Target send burst in bytes for UDP GSO batching: ~1 ms of traffic at
    /// rates above 2 packets/ms (~3 MB/s), capped at `MAX_BURST_BYTES`. Below
    /// that rate returns 0 so low-bitrate pacing stays smooth packet-by-packet.
    fn gso_quantum_bytes(&self) -> u64 {
        let one_ms = self.rate_bps / 1_000;
        let min_gso = u64::from(self.mss).saturating_mul(2);
        if one_ms >= min_gso {
            one_ms.min(MAX_BURST_BYTES)
        } else {
            0
        }
    }

    /// Delay before the next packet may go out: zero while credit is positive,
    /// otherwise the time to pay back the deficit plus (at high rates) accrue
    /// one ~1 ms GSO burst quantum so UDP GSO batching stays intact.
    pub(crate) fn delay(&self) -> Duration {
        if self.tokens_ub > 0 {
            return Duration::ZERO;
        }
        let target_ub = i128::from(self.gso_quantum_bytes()) * MICRO_BYTES;
        let needed_ub = target_ub.saturating_sub(self.tokens_ub).max(1) as u128;
        let wait_ns = needed_ub
            .saturating_mul(1_000)
            .div_ceil(u128::from(self.rate_bps));
        let clamped = (wait_ns.min(u128::from(MAX_SLEEP_NS)) as u64).max(MIN_SLEEP_NS);
        Duration::from_nanos(clamped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_bucket_holds_initial_burst() {
        let tb = TokenBucket::new(100_000, 1200, Instant::now());
        assert_eq!(tb.tokens_ub, i128::from(INITIAL_BUCKET_BYTES) * MICRO_BYTES);
        assert_eq!(tb.delay(), Duration::ZERO);
    }

    /// Sending a packet larger than the remaining balance carries the exact
    /// deficit forward instead of discarding it.
    #[test]
    fn try_consume_carries_deficit_and_computes_exact_delay() {
        let now = Instant::now();
        // 1,000,000 B/s = 1 byte/us.
        let mut tb = TokenBucket::new(1_000_000, 1200, now);
        assert!(tb.try_consume(25_000, now));
        assert!(!tb.try_consume(1, now));

        // After 500 us, 500 bytes are available; sending 1500 leaves a 1000-byte deficit.
        let t1 = now + Duration::from_micros(500);
        assert!(tb.try_consume(1_500, t1));
        assert_eq!(tb.tokens_ub, -1_000 * MICRO_BYTES);
        // 1000 bytes at 1 byte/us = 1000 us.
        let d = tb.delay();
        assert!(
            d >= Duration::from_micros(1_000) && d <= Duration::from_micros(1_002),
            "expected ~1000us delay, got {d:?}"
        );
    }

    /// At 2 MB/s (film rate), deficit pacing keeps the delivered rate within 2%
    /// of target (the old 1 ms bucket overshot by +45%).
    #[test]
    fn film_rate_pacing_matches_target_without_overshoot() {
        let start = Instant::now();
        let rate_bps = 2_000_000;
        let pkt_size = 1_452u32;
        let mut tb = TokenBucket::new(rate_bps, pkt_size, start);
        // Drain initial burst first.
        assert!(tb.try_consume(INITIAL_BUCKET_BYTES as u32, start));

        let mut now = start;
        let end = start + Duration::from_secs(1);
        let mut bytes_sent = 0u64;
        while now < end {
            tb.refill(now);
            let d = tb.delay();
            if d.is_zero() {
                assert!(tb.try_consume(pkt_size, now));
                bytes_sent += u64::from(pkt_size);
            } else {
                now += d;
            }
        }
        // Within 2% of 2,000,000 B/s.
        assert!(
            (1_960_000..=2_040_000).contains(&bytes_sent),
            "expected ~2,000,000 B/s, sent {bytes_sent} B"
        );
    }

    /// At 8 Mbit/s (1 MB/s), below the old 11.6 Mbit/s 1-packet-per-ms floor,
    /// the pacer accurately paces to 1 MB/s instead of running unpaced.
    #[test]
    fn low_rate_below_one_packet_per_ms_is_accurately_paced() {
        let start = Instant::now();
        let rate_bps = 1_000_000;
        let pkt_size = 1_452u32;
        let mut tb = TokenBucket::new(rate_bps, pkt_size, start);
        assert!(tb.try_consume(INITIAL_BUCKET_BYTES as u32, start));

        let mut now = start;
        let end = start + Duration::from_secs(1);
        let mut bytes_sent = 0u64;
        while now < end {
            tb.refill(now);
            let d = tb.delay();
            if d.is_zero() {
                assert!(tb.try_consume(pkt_size, now));
                bytes_sent += u64::from(pkt_size);
            } else {
                now += d;
            }
        }
        assert!(
            (980_000..=1_020_000).contains(&bytes_sent),
            "expected ~1,000,000 B/s, sent {bytes_sent} B"
        );
    }

    /// At 1 Gbit/s, the burst cap stays bounded at MAX_BURST_BYTES (65,507 B)
    /// rather than dumping 125 KiB bursts, while allowing full UDP GSO batches.
    #[test]
    fn high_rate_caps_burst_to_one_gso_send() {
        let start = Instant::now();
        let mut tb = TokenBucket::new(125_000_000, 1452, start);
        assert!(tb.try_consume(INITIAL_BUCKET_BYTES as u32, start));
        tb.refill(start + Duration::from_millis(10));
        let mut burst = 0u32;
        while tb.try_consume(1452, start + Duration::from_millis(10)) {
            burst += 1452;
        }
        assert!(burst >= 64_000 && burst <= MAX_BURST_BYTES as u32 + 1452);
    }

    /// At 100 Mbit/s (12.5 MB/s), delay() sleeps until a ~1 ms UDP GSO quantum
    /// accrues (~12.5 KB) rather than waking after 50 us for a single packet.
    #[test]
    fn high_rate_delay_accumulates_gso_quantum() {
        let start = Instant::now();
        let mut tb = TokenBucket::new(12_500_000, 1452, start);
        assert!(tb.try_consume(INITIAL_BUCKET_BYTES as u32, start));
        let d = tb.delay();
        assert!(
            d >= Duration::from_micros(950) && d <= Duration::from_micros(1_050),
            "expected ~1 ms GSO quantum delay at 12.5 MB/s, got {d:?}"
        );
    }
}
