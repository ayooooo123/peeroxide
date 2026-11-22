//! The receive window: `DEFAULT_RWND` minus the payload bytes the receiver
//! holds. Every header advertises that value, so a peer that honours it never
//! outruns the reader. C libudx computes the same number when the application
//! gives a read-buffer callback (`get_recv_rwnd`, udx.c:273-284); stock
//! `udx-native` never gives one, so C always advertises the maximum.
//!
//! In-order data is accepted up to twice the window so that the one packet a
//! correct C sender may put beyond a closed window cannot wedge the stream;
//! `HARD_LIMIT` has the details.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use super::stream::DEFAULT_RWND;

/// In-order data is refused above this: twice the advertised maximum.
///
/// A correct C sender may send one new packet beyond a closed window: its
/// tail loss probe skips the window check (C `send_new_packet(stream, true)`,
/// udx.c:902-904, called from `udx_tlp_timeout`), and any window above 0
/// permits one whole packet (C `send_rwnd_in_packets`). A receiver that
/// refused that packet while its reader pauses would make the sender time
/// out and close the stream (C `udx_rto_timeout` counts timeouts until the
/// cumulative ACK moves).
const HARD_LIMIT: usize = 2 * DEFAULT_RWND as usize;

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
}

impl ReceiveWindow {
    pub(crate) fn new() -> Self {
        Self {
            unread: AtomicUsize::new(0),
            out_of_order: AtomicUsize::new(0),
            advertised: AtomicU32::new(DEFAULT_RWND),
            update_requested: AtomicBool::new(false),
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
        DEFAULT_RWND.saturating_sub(self.held().min(DEFAULT_RWND as usize) as u32)
    }

    /// `current()`, also remembered as the value the peer was told.
    pub(crate) fn advertise(&self) -> u32 {
        let window = self.current();
        self.advertised.store(window, Ordering::Relaxed);
        window
    }

    /// In-order data is refused only at twice the window.
    pub(crate) fn admits_in_order(&self, len: usize) -> bool {
        len == 0 || self.held() < HARD_LIMIT
    }

    /// Out-of-order data is kept only while it fits inside the window.
    pub(crate) fn admits_out_of_order(&self, len: usize) -> bool {
        let limit = DEFAULT_RWND as usize;
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
        let _ = self
            .out_of_order
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                Some(held.saturating_sub(len))
            });
    }

    /// The out-of-order buffer was cleared.
    pub(crate) fn clear_out_of_order(&self) {
        self.out_of_order.store(0, Ordering::Relaxed);
    }

    /// The reader took `len` bytes. Returns true when the window grew by at
    /// least half of `DEFAULT_RWND` above what the peer was last told and no
    /// update is on its way: the caller asks the stream task for one ACK.
    pub(crate) fn taken(&self, len: usize) -> bool {
        if len == 0 {
            return false;
        }
        let _ = self
            .unread
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                Some(held.saturating_sub(len))
            });
        let grown = self
            .current()
            .saturating_sub(self.advertised.load(Ordering::Relaxed))
            >= DEFAULT_RWND / 2;
        grown && !self.update_requested.swap(true, Ordering::Relaxed)
    }

    /// The stream task handled the update request (or dropped it).
    pub(crate) fn update_handled(&self) {
        self.update_requested.store(false, Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::*;

    // Catches a window that ignores held bytes, or that counts a released
    // out-of-order byte twice.
    #[test]
    fn window_is_the_maximum_minus_what_the_receiver_holds() {
        let window = ReceiveWindow::new();
        assert_eq!(window.current(), DEFAULT_RWND);
        // 1,000 + 500 = 1,500 held: 4,194,304 - 1,500 = 4,192,804.
        window.delivered(1000);
        window.stored_out_of_order(500);
        assert_eq!(window.current(), 4_192_804);
        // 1,000 taken: 500 held, 4,194,304 - 500 = 4,193,804.
        let _ = window.taken(1000);
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
        // 4,194,304 held: the advertised window is 0.
        window.delivered(DEFAULT_RWND as usize);
        assert_eq!(window.advertise(), 0);
        // After 2,097,151 taken the window is 2,097,151, one below half of
        // 4,194,304 (2,097,152).
        assert!(!window.taken(DEFAULT_RWND as usize / 2 - 1));
        // The next byte reaches exactly half the maximum: one update.
        assert!(window.taken(1));
        // Another 1,000 read leaves 2,096,152 held, still at least half the
        // maximum above the advertised 0, but the request is still pending.
        assert!(!window.taken(1000));
        // The task handled it; 2,098,152 bytes were taken, so the window is
        // 4,194,304 - 2,096,152 = 2,098,152.
        window.update_handled();
        assert_eq!(window.advertise(), 2_098_152);
        // Only 1,000 bytes above that, so no new update yet.
        assert!(!window.taken(1000));
    }

    // Catches an unread counter that wraps when a reader takes more than the
    // buffer holds, or an out-of-order counter that underflows.
    #[test]
    fn taking_more_than_is_held_does_not_wrap() {
        let window = ReceiveWindow::new();
        window.delivered(10);
        // 10 - 1,000 saturates at 0, so the full window is advertised again.
        let _ = window.taken(1000);
        assert_eq!(window.current(), DEFAULT_RWND);
        // Releasing from an empty buffer leaves it empty.
        window.released_out_of_order(5);
        assert_eq!(window.out_of_order_bytes(), 0);
    }
}
