//! Windowed min/max filter: port of C libudx `win_filter.c` and
//! `win_filter_f64.c` (Kathleen Nichols' algorithm, from Linux
//! `lib/minmax.c`).
//!
//! Keeps the best, second-best and third-best value with their times; the
//! n'th best is never older than the (n-1)'th. Besides expiring entries
//! older than the window, it ages the runners-up after a quarter and half
//! window so the estimate never jumps by more than one entry at once.

/// Three-entry windowed min or max of `T` over a window of `t` units (C
/// `win_filter_t`; BBR uses rounds, the RTT minimum milliseconds).
#[derive(Debug, Clone)]
pub(crate) struct WinFilter<T> {
    entries: [(u64, T); 3],
}

impl<T: Copy + PartialOrd> WinFilter<T> {
    /// A filter holding `v` at time `t` in every entry (C `win_filter_reset`).
    pub(crate) fn new(t: u64, v: T) -> Self {
        Self {
            entries: [(t, v); 3],
        }
    }

    /// The current best value.
    pub(crate) fn get(&self) -> T {
        self.entries[0].1
    }

    /// C `win_filter_reset`.
    pub(crate) fn reset(&mut self, t: u64, v: T) -> T {
        self.entries = [(t, v); 3];
        v
    }

    /// Add sample `v` at time `t` to a max filter (C `win_filter_apply_max`).
    pub(crate) fn apply_max(&mut self, win: u32, t: u64, v: T) -> T {
        // New maximum, or nothing left in the window.
        if v >= self.entries[0].1 || t.wrapping_sub(self.entries[2].0) > u64::from(win) {
            return self.reset(t, v);
        }
        if v >= self.entries[1].1 {
            self.entries[2] = (t, v);
            self.entries[1] = (t, v);
        } else if v >= self.entries[2].1 {
            self.entries[2] = (t, v);
        }
        self.apply_common(win, t, v)
    }

    /// Add sample `v` at time `t` to a min filter (C `win_filter_apply_min`).
    pub(crate) fn apply_min(&mut self, win: u32, t: u64, v: T) -> T {
        // New minimum, or nothing left in the window.
        if v <= self.entries[0].1 || t.wrapping_sub(self.entries[2].0) > u64::from(win) {
            return self.reset(t, v);
        }
        if v <= self.entries[1].1 {
            self.entries[2] = (t, v);
            self.entries[1] = (t, v);
        } else if v <= self.entries[2].1 {
            self.entries[2] = (t, v);
        }
        self.apply_common(win, t, v)
    }

    /// C `win_filter_apply_common`: expire the best entry once it is older
    /// than the window, and age the runners-up after a quarter and a half
    /// window.
    fn apply_common(&mut self, win: u32, t: u64, v: T) -> T {
        // C computes `dt` as a uint32_t.
        let dt = t.wrapping_sub(self.entries[0].0) as u32;
        let new = (t, v);
        if dt > win {
            // Past the window: bump off entries[0].
            self.entries[0] = self.entries[1];
            self.entries[1] = self.entries[2];
            self.entries[2] = new;
            if t.wrapping_sub(self.entries[0].0) > u64::from(win) {
                // Bump off entries[1] too.
                self.entries[0] = self.entries[1];
                self.entries[1] = self.entries[2];
                self.entries[2] = new;
            }
        } else if self.entries[1].0 == self.entries[0].0 && dt > win / 4 {
            // A quarter of the window passed with no second choice: take one.
            self.entries[2] = new;
            self.entries[1] = new;
        } else if self.entries[2].0 == self.entries[1].0 && dt > win / 2 {
            // Half the window passed with no third choice: take one.
            self.entries[2] = new;
        }
        self.entries[0].1
    }
}

#[cfg(test)]
mod tests {
    use super::WinFilter;

    #[test]
    fn max_tracks_new_maximum_and_expires() {
        let mut f = WinFilter::new(0, 0.0);
        assert_eq!(f.apply_max(10, 0, 5.0), 5.0);
        assert_eq!(f.apply_max(10, 1, 10.0), 10.0);
        // Older than the window: the best and its copies expire.
        assert_eq!(f.apply_max(10, 12, 3.0), 3.0);
    }

    #[test]
    fn min_tracks_new_minimum_and_expires() {
        let mut f = WinFilter::new(0, u32::MAX);
        assert_eq!(f.apply_min(300, 0, 20), 20);
        assert_eq!(f.apply_min(300, 10, 30), 20);
        assert_eq!(f.apply_min(300, 20, 10), 10);
        assert_eq!(f.apply_min(300, 400, 50), 50);
    }

    /// C `win_filter_f64_apply_common` ages the runners-up: a lower sample
    /// taken after a quarter window becomes the second choice, so when the
    /// best expires the estimate falls to it, not to whatever came last.
    #[test]
    fn max_ages_runners_up_after_a_quarter_and_half_window() {
        let mut f = WinFilter::new(0, 0.0);
        f.apply_max(10, 0, 10.0);
        // dt = 3 > 10/4 with no second choice: 8.0 becomes the second and third.
        f.apply_max(10, 3, 8.0);
        // dt = 6 > 10/2 with the third choice as old as the second: 7.0
        // becomes the third.
        f.apply_max(10, 6, 7.0);
        // At t=11 the best (t=0) expires: 8.0 (t=3) takes over.
        assert_eq!(f.apply_max(10, 11, 1.0), 8.0);
        // At t=14 the t=3 entry expires too: 7.0 (t=6) takes over.
        assert_eq!(f.apply_max(10, 14, 1.0), 7.0);
    }
}
