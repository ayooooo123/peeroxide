//! The receive window: `limit` minus the payload bytes the receiver holds.
//! `limit` starts at `DEFAULT_RWND` and doubles up to `MAX_RWND` while the
//! reader takes a whole window in less than a second. Every header advertises
//! that value, so a peer that honours it never outruns the reader. C libudx
//! computes the same number when the application gives a read-buffer callback
//! (`get_recv_rwnd`, udx.c:273-284); stock `udx-native` never gives one, so C
//! always advertises the maximum.
//!
//! In-order data is accepted up to the window plus one starting window so
//! that the one packet a correct C sender may put beyond a closed window
//! cannot stop the stream for good; `HARD_MARGIN` has the details.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::stream::DEFAULT_RWND;

/// The window never grows above this: four times the starting window.
pub(crate) const MAX_RWND: u32 = 4 * DEFAULT_RWND;

/// The reader must take one whole window of new bytes within this time for the
/// window to double.
const GROWTH_PERIOD: Duration = Duration::from_secs(1);

/// In-order data is refused above this: the window plus one starting window.
///
/// A correct C sender may send one new packet beyond a closed window: its
/// tail loss probe skips the window check (C `send_new_packet(stream, true)`,
/// udx.c:902-904, called from `udx_tlp_timeout`), and any window above 0
/// permits one whole packet (C `send_rwnd_in_packets`). A receiver that
/// refused that packet while its reader pauses would make the sender time
/// out and close the stream (C `udx_rto_timeout` counts timeouts until the
/// cumulative ACK moves).
const HARD_MARGIN: usize = DEFAULT_RWND as usize;

/// How much the peer may still send, in payload bytes.
///
/// The counters are independent and every access is `Relaxed`: a stale value
/// makes the window a little smaller or an update ACK one step late, never
/// wrong in a way that matters, because the next ACK carries the fresh value.
pub(crate) struct ReceiveWindow {
    /// In-order payload bytes the reader has not taken.
    unread: AtomicUsize,
    /// Payload bytes held out of order.
    out_of_order: AtomicUsize,
    /// The window in the last header that was built.
    advertised: AtomicU32,
    /// A window update is on its way to the stream task.
    update_requested: AtomicBool,
    /// The maximum window: `DEFAULT_RWND`, doubled by a fast reader. Only
    /// the reader writes it.
    limit: AtomicU32,
}

impl ReceiveWindow {
    pub(crate) fn new() -> Self {
        Self {
            unread: AtomicUsize::new(0),
            out_of_order: AtomicUsize::new(0),
            advertised: AtomicU32::new(DEFAULT_RWND),
            update_requested: AtomicBool::new(false),
            limit: AtomicU32::new(DEFAULT_RWND),
        }
    }

    /// Payload bytes held: unread in order plus buffered out of order.
    fn held(&self) -> usize {
        self.unread
            .load(Ordering::Relaxed)
            .saturating_add(self.out_of_order.load(Ordering::Relaxed))
    }

    /// The window to advertise now.
    pub(crate) fn current(&self) -> u32 {
        let limit = self.limit.load(Ordering::Relaxed);
        limit.saturating_sub(self.held().min(limit as usize) as u32)
    }

    /// `current()`, also remembered as the value the peer was told.
    pub(crate) fn advertise(&self) -> u32 {
        let window = self.current();
        self.advertised.store(window, Ordering::Relaxed);
        window
    }

    /// In-order data is refused only above the window plus one starting window.
    pub(crate) fn admits_in_order(&self, len: usize) -> bool {
        len == 0 || self.held() < self.limit.load(Ordering::Relaxed) as usize + HARD_MARGIN
    }

    /// Out-of-order data is kept only while it fits inside the window.
    pub(crate) fn admits_out_of_order(&self, len: usize) -> bool {
        let limit = self.limit.load(Ordering::Relaxed) as usize;
        len <= limit && self.held() <= limit - len
    }

    /// `len` payload bytes were queued for the reader, in order.
    pub(crate) fn delivered(&self, len: usize) {
        self.unread.fetch_add(len, Ordering::Relaxed);
    }

    /// `len` payload bytes were buffered out of order.
    pub(crate) fn stored_out_of_order(&self, len: usize) {
        self.out_of_order.fetch_add(len, Ordering::Relaxed);
    }

    /// `len` out-of-order bytes left the buffer.
    pub(crate) fn released_out_of_order(&self, len: usize) {
        subtract_to_zero(&self.out_of_order, len);
    }

    /// The out-of-order buffer was cleared.
    pub(crate) fn clear_out_of_order(&self) {
        self.out_of_order.store(0, Ordering::Relaxed);
    }

    /// The reader took `len` bytes. Returns true when the window grew by at
    /// least half of `limit` above what the peer was last told and no update
    /// is on its way: the caller asks the stream task for one ACK.
    pub(crate) fn taken(&self, len: usize, meter: &mut ReadMeter) -> bool {
        self.taken_at(len, meter, Instant::now)
    }

    /// `taken` with the clock supplied only when the measurement completes.
    fn taken_at(&self, len: usize, meter: &mut ReadMeter, now: impl FnOnce() -> Instant) -> bool {
        if len == 0 {
            return false;
        }
        subtract_to_zero(&self.unread, len);

        // A whole target taken inside the period doubles the maximum. The
        // bytes that already waited when the measurement started say nothing
        // about the link, so the target includes them.
        meter.taken += len as u64;
        if meter.taken >= meter.target {
            let now = now();
            if now.duration_since(meter.since) < meter.period {
                let limit = self.limit.load(Ordering::Relaxed);
                self.limit
                    .store((limit * 2).min(MAX_RWND), Ordering::Relaxed);
            }
            meter.since = now;
            meter.taken = 0;
            meter.target = self.limit.load(Ordering::Relaxed) as u64
                + self.unread.load(Ordering::Relaxed) as u64;
        }

        let limit = self.limit.load(Ordering::Relaxed);
        let grown = self
            .current()
            .saturating_sub(self.advertised.load(Ordering::Relaxed))
            >= limit / 2;
        grown && !self.update_requested.swap(true, Ordering::Relaxed)
    }

    /// The stream task handled the update request (or dropped it).
    pub(crate) fn update_handled(&self) {
        self.update_requested.store(false, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn limit_bytes(&self) -> u32 {
        self.limit.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn unread_bytes(&self) -> usize {
        self.unread.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn out_of_order_bytes(&self) -> usize {
        self.out_of_order.load(Ordering::Relaxed)
    }
}

/// Subtracts `len` from `counter` and stops at zero. The loop is what
/// `fetch_update` does; that method is deprecated on new compilers and its
/// replacement `try_update` is newer than the minimum Rust version of the crate.
fn subtract_to_zero(counter: &AtomicUsize, len: usize) {
    let mut held = counter.load(Ordering::Relaxed);
    while let Err(now) = counter.compare_exchange_weak(
        held,
        held.saturating_sub(len),
        Ordering::Relaxed,
        Ordering::Relaxed,
    ) {
        held = now;
    }
}

/// Measures how fast the reader takes bytes. The one reader of a stream owns it.
pub(crate) struct ReadMeter {
    /// When the current measurement started.
    since: Instant,
    /// Payload bytes the reader took since then.
    taken: u64,
    /// Bytes to take before the window may double: one limit plus the bytes
    /// that already waited when the measurement started.
    target: u64,
    /// How long taking the target may last and still count as fast.
    period: Duration,
}

impl ReadMeter {
    pub(crate) fn new() -> Self {
        Self {
            since: Instant::now(),
            taken: 0,
            target: DEFAULT_RWND as u64,
            period: GROWTH_PERIOD,
        }
    }

    /// A test of the stream sets a long period, so that its result does not
    /// depend on the speed of the machine.
    #[cfg(test)]
    pub(crate) fn set_period(&mut self, period: Duration) {
        self.period = period;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A meter for a test, started at a prepared instant.
    fn meter_at(t0: Instant) -> ReadMeter {
        ReadMeter {
            since: t0,
            taken: 0,
            target: DEFAULT_RWND as u64,
            period: GROWTH_PERIOD,
        }
    }

    /// Takes bytes at an instant far past the growth period, so the window
    /// keeps its size: tests 1 to 6 were written for a fixed window.
    fn taken_fixed(window: &ReceiveWindow, meter: &mut ReadMeter, len: usize) -> bool {
        let now = Instant::now();
        window.taken_at(len, meter, || now + Duration::from_secs(3_600))
    }

    /// A window whose limit doubled once, with nothing held.
    fn doubled_window(t0: Instant) -> ReceiveWindow {
        let window = ReceiveWindow::new();
        let mut meter = meter_at(t0);
        window.delivered(DEFAULT_RWND as usize);
        // 4,194,304 taken at 1 ms, inside the period: limit 8,388,608.
        let _ = window.taken_at(DEFAULT_RWND as usize, &mut meter, || {
            t0 + Duration::from_millis(1)
        });
        assert_eq!(window.limit_bytes(), 8_388_608);
        window
    }

    // Catches a window that ignores held bytes, or that counts a released
    // out-of-order byte twice.
    #[test]
    fn window_is_the_maximum_minus_what_the_receiver_holds() {
        let window = ReceiveWindow::new();
        let mut meter = ReadMeter::new();
        assert_eq!(window.current(), DEFAULT_RWND);
        // 1,000 + 500 = 1,500 held: 4,194,304 - 1,500 = 4,192,804.
        window.delivered(1000);
        window.stored_out_of_order(500);
        assert_eq!(window.current(), 4_192_804);
        // 1,000 taken: 500 held, 4,194,304 - 500 = 4,193,804.
        let _ = taken_fixed(&window, &mut meter, 1000);
        assert_eq!(window.current(), 4_193_804);
        // The out-of-order buffer released 500: nothing held.
        window.released_out_of_order(500);
        assert_eq!(window.current(), DEFAULT_RWND);
    }

    // Catches a window below zero wrapping around to nearly 4 GB.
    #[test]
    fn window_never_wraps_below_zero() {
        let window = ReceiveWindow::new();
        // 4,194,304 + 5,000 held: 4,194,304 - min(4,194,304, 4,199,304) = 0.
        window.delivered(DEFAULT_RWND as usize + 5000);
        assert_eq!(window.current(), 0);
        assert_eq!(window.advertise(), 0);
    }

    // Catches a receiver that refuses in-order data at the window itself: the
    // one tail-loss probe a correct sender may send would be lost.
    #[test]
    fn in_order_data_is_refused_only_at_twice_the_window() {
        let window = ReceiveWindow::new();
        // 2 * 4,194,304 - 1 = 8,388,607, one byte below the limit of 8,388,608.
        window.delivered(2 * DEFAULT_RWND as usize - 1);
        assert!(window.admits_in_order(60_000));
        // One more byte reaches 8,388,608, the limit itself.
        window.delivered(1);
        assert!(!window.admits_in_order(60_000));
        // An empty packet (a bare END) needs no room.
        assert!(window.admits_in_order(0));
    }

    // Catches an out-of-order buffer that accepts data beyond the window the
    // peer was told about.
    #[test]
    fn out_of_order_data_fits_only_inside_the_window() {
        let window = ReceiveWindow::new();
        // Nothing held: 4,194,304 bytes fit exactly, one more does not.
        assert!(window.admits_out_of_order(DEFAULT_RWND as usize));
        assert!(!window.admits_out_of_order(DEFAULT_RWND as usize + 1));
        // 1,000 held in order: 4,193,304 more fit exactly, one more does not.
        window.delivered(1000);
        assert!(window.admits_out_of_order(DEFAULT_RWND as usize - 1000));
        assert!(!window.admits_out_of_order(DEFAULT_RWND as usize - 999));
    }

    // Catches an update ACK for every read (a packet flood), for a read that
    // frees too little, or a second one while the first is on its way.
    #[test]
    fn one_update_for_each_half_window_that_the_reader_frees() {
        let window = ReceiveWindow::new();
        let mut meter = ReadMeter::new();
        // 4,194,304 held: the advertised window is 0.
        window.delivered(DEFAULT_RWND as usize);
        assert_eq!(window.advertise(), 0);
        // After 2,097,151 taken the window is 2,097,151, one below half of
        // 4,194,304 (2,097,152).
        assert!(!taken_fixed(
            &window,
            &mut meter,
            DEFAULT_RWND as usize / 2 - 1
        ));
        // The next byte reaches exactly half the maximum: one update.
        assert!(taken_fixed(&window, &mut meter, 1));
        // Another 1,000 read leaves 2,096,152 held, still at least half the
        // maximum above the advertised 0, but the request is still pending.
        assert!(!taken_fixed(&window, &mut meter, 1000));
        // The task handled it; 2,098,152 bytes were taken, so the window is
        // 4,194,304 - 2,096,152 = 2,098,152.
        window.update_handled();
        assert_eq!(window.advertise(), 2_098_152);
        // Only 1,000 bytes above that, so no new update yet.
        assert!(!taken_fixed(&window, &mut meter, 1000));
    }

    // Catches an unread counter that wraps when a reader takes more than the
    // buffer holds, or an out-of-order counter that underflows.
    #[test]
    fn taking_more_than_is_held_does_not_wrap() {
        let window = ReceiveWindow::new();
        let mut meter = ReadMeter::new();
        window.delivered(10);
        // 10 - 1,000 saturates at 0, so the full window is advertised again.
        let _ = taken_fixed(&window, &mut meter, 1000);
        assert_eq!(window.current(), DEFAULT_RWND);
        // Releasing from an empty buffer leaves it empty.
        window.released_out_of_order(5);
        assert_eq!(window.out_of_order_bytes(), 0);
    }

    // Catches a window that never grows: a reader that takes a whole window
    // inside the period must double the maximum.
    #[test]
    fn window_doubles_when_the_reader_takes_a_whole_window_in_time() {
        let window = ReceiveWindow::new();
        let t0 = Instant::now();
        let mut meter = meter_at(t0);
        // Four pieces of 1,048,576 = 4,194,304 in total. The last piece is
        // taken at 999 ms, one millisecond inside the period.
        for millis in [1, 1, 1, 999] {
            window.delivered(1_048_576);
            let _ = window.taken_at(1_048_576, &mut meter, || t0 + Duration::from_millis(millis));
        }
        // A whole starting window taken in time: 2 * 4,194,304 = 8,388,608.
        assert_eq!(window.limit_bytes(), 8_388_608);
        // Nothing held, so the advertised window is the new limit.
        assert_eq!(window.current(), 8_388_608);
    }

    // Catches a window that grows for a slow reader, or one that reads the
    // clock before the target is reached.
    #[test]
    fn window_keeps_its_size_for_a_slow_reader() {
        let window = ReceiveWindow::new();
        let t0 = Instant::now();
        let mut meter = meter_at(t0);
        // The same four pieces, the last piece at 1,000 ms: not less than
        // the period, so the limit stays 4,194,304.
        for millis in [1, 1, 1, 1000] {
            window.delivered(1_048_576);
            let _ = window.taken_at(1_048_576, &mut meter, || t0 + Duration::from_millis(millis));
        }
        assert_eq!(window.limit_bytes(), 4_194_304);

        // One byte short of the 4,194,304 target: no growth and no clock read.
        let window = ReceiveWindow::new();
        let mut meter = meter_at(t0);
        window.delivered(4_194_304);
        let calls = Cell::new(0);
        let _ = window.taken_at(4_194_303, &mut meter, || {
            calls.set(calls.get() + 1);
            t0 + Duration::from_millis(1)
        });
        assert_eq!(window.limit_bytes(), 4_194_304);
        assert_eq!(calls.get(), 0);
    }

    // Catches bytes that already waited counting as new speed: the reader must
    // take them and one whole window more.
    #[test]
    fn bytes_that_waited_do_not_count_as_speed() {
        let window = ReceiveWindow::new();
        let t0 = Instant::now();
        let mut meter = meter_at(t0);
        // 6,291,456 = 4,194,304 + 2,097,152, below the 8,388,608 in-order bound.
        window.delivered(6_291_456);
        // 4,194,304 taken at 2,000 ms: too slow, no growth. The new target is
        // the limit plus the 2,097,152 still waiting: 4,194,304 + 2,097,152 =
        // 6,291,456.
        let _ = window.taken_at(4_194_304, &mut meter, || t0 + Duration::from_millis(2000));
        assert_eq!(window.limit_bytes(), 4_194_304);
        assert_eq!(meter.target, 6_291_456);
        // The waiting 2,097,152 taken at 2,001 ms: 2,097,152 of 6,291,456.
        let _ = window.taken_at(2_097_152, &mut meter, || t0 + Duration::from_millis(2001));
        assert_eq!(window.limit_bytes(), 4_194_304);
        // 4,194,303 more at 2,002 ms: 2,097,152 + 4,194,303 = 6,291,455, one
        // byte short of the target.
        window.delivered(4_194_303);
        let _ = window.taken_at(4_194_303, &mut meter, || t0 + Duration::from_millis(2002));
        assert_eq!(window.limit_bytes(), 4_194_304);
        // One more byte reaches 6,291,456 at 2,003 ms: the doubling is
        // 4,194,304 * 2 = 8,388,608.
        window.delivered(1);
        let _ = window.taken_at(1, &mut meter, || t0 + Duration::from_millis(2003));
        assert_eq!(window.limit_bytes(), 8_388_608);
    }

    // Catches a limit that keeps doubling past the four starting windows.
    #[test]
    fn window_stops_growing_at_the_maximum() {
        let window = ReceiveWindow::new();
        let t0 = Instant::now();
        let mut meter = meter_at(t0);

        // First measurement: 4,194,304 taken in 1 ms -> limit 8,388,608.
        // Delivered in 1,048,576-byte pieces, all inside the 8,388,608
        // in-order bound (4,194,304 + 4,194,304).
        for _ in 0..4 {
            assert!(window.admits_in_order(1_048_576));
            window.delivered(1_048_576);
        }
        let _ = window.taken_at(4_194_304, &mut meter, || t0 + Duration::from_millis(1));
        assert_eq!(window.limit_bytes(), 8_388_608);

        // Second measurement: 8,388,608 taken in 1 ms -> limit 16,777,216.
        // The in-order bound is 8,388,608 + 4,194,304 = 12,582,912.
        for _ in 0..8 {
            assert!(window.admits_in_order(1_048_576));
            window.delivered(1_048_576);
        }
        let _ = window.taken_at(8_388_608, &mut meter, || t0 + Duration::from_millis(2));
        assert_eq!(window.limit_bytes(), 16_777_216);

        // Third measurement: 16,777,216 taken in 1 ms -> 33,554,432 would be
        // past MAX_RWND, so the limit stays 16,777,216.
        for _ in 0..16 {
            assert!(window.admits_in_order(1_048_576));
            window.delivered(1_048_576);
        }
        let _ = window.taken_at(16_777_216, &mut meter, || t0 + Duration::from_millis(3));
        assert_eq!(window.limit_bytes(), MAX_RWND);
        assert_eq!(window.current(), MAX_RWND);
    }

    // Catches rules that keep the starting window after the limit doubles.
    #[test]
    fn the_rules_follow_the_grown_window() {
        let t0 = Instant::now();
        let window = doubled_window(t0);
        // Nothing held: 8,388,608 out-of-order bytes fit, one more does not.
        assert!(window.admits_out_of_order(8_388_608));
        assert!(!window.admits_out_of_order(8_388_609));
        // 8,388,608 + 4,194,304 = 12,582,912 is the in-order bound.
        window.delivered(12_582_911);
        assert!(window.admits_in_order(1000));
        window.delivered(1);
        assert!(!window.admits_in_order(1000));

        // An empty update slot and 8,388,608 held in order: advertise 0.
        let window = doubled_window(t0);
        window.update_handled();
        window.delivered(8_388_608);
        assert_eq!(window.advertise(), 0);
        let mut meter = meter_at(t0);
        // 4,194,303 taken leaves 4,194,305 held: window 8,388,608 - 4,194,305
        // = 4,194,303, one below half the limit (4,194,304).
        assert!(!window.taken_at(4_194_303, &mut meter, || { t0 + Duration::from_secs(2) }));
        // One more byte: window 8,388,608 - 4,194,304 = 4,194,304, exactly
        // half the limit.
        assert!(window.taken_at(1, &mut meter, || { t0 + Duration::from_secs(2) }));
    }
}
