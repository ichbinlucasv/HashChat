//! Warn when the system clock reads earlier than it did on a previous run.
//!
//! The dead-man switch and local message expiry both trust the wall clock. A
//! clock set back delays the dead-man wipe and keeps expired messages around,
//! and that is easy to do on a seized or borrowed machine. Each save of the
//! encrypted state records the latest time seen, rounded down to ten minutes,
//! and the next unlock compares it with the current clock.
//!
//! The mark sits inside `state.enc`, so it cannot be lowered without the
//! passphrase. It only detects a rollback across saves; it cannot tell a wrong
//! clock from a right one on first use, and a clock set far forward raises the
//! mark until the user accepts the current time with `:clock-reset`.

/// Granularity of the stored mark. Coarse on purpose: it only needs to catch
/// a rollback, not record when the profile was last used.
pub const CLOCK_MARK_STEP_SECS: u64 = 600;

/// How far behind the mark the clock may read before we warn. Covers normal
/// NTP corrections and a machine that booted with a slightly stale clock.
pub const CLOCK_ROLLBACK_TOLERANCE_SECS: u64 = 3_600;

/// New mark to store: never lower than the previous one.
pub fn advance_clock_mark(previous: u64, now_unix: u64) -> u64 {
    let rounded = now_unix - now_unix % CLOCK_MARK_STEP_SECS;
    previous.max(rounded)
}

/// Seconds the clock reads behind the stored mark, if past the tolerance.
pub fn clock_rollback_secs(mark: u64, now_unix: u64) -> Option<u64> {
    let behind = mark.saturating_sub(now_unix);
    (behind > CLOCK_ROLLBACK_TOLERANCE_SECS).then_some(behind)
}

/// Short human label for a rollback, in whole hours or days.
pub fn format_rollback(secs: u64) -> String {
    let hours = secs / 3_600;
    if hours >= 48 {
        format!("about {} days", hours / 24)
    } else {
        format!("about {} h", hours.max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_is_rounded_down_and_never_moves_back() {
        assert_eq!(advance_clock_mark(0, 1_234), 1_200);
        assert_eq!(advance_clock_mark(5_000, 1_234), 5_000);
        assert_eq!(advance_clock_mark(1_200, 1_799), 1_200);
        assert_eq!(advance_clock_mark(1_200, 1_800), 1_800);
    }

    #[test]
    fn small_corrections_do_not_warn() {
        let mark = 100_000;
        assert_eq!(clock_rollback_secs(mark, mark), None);
        assert_eq!(clock_rollback_secs(mark, mark + 9_999), None);
        assert_eq!(clock_rollback_secs(mark, mark - 3_600), None);
    }

    #[test]
    fn rollback_past_tolerance_warns() {
        let mark = 100_000;
        assert_eq!(clock_rollback_secs(mark, mark - 3_601), Some(3_601));
        assert_eq!(clock_rollback_secs(mark, 0), Some(mark));
    }

    #[test]
    fn unset_mark_never_warns() {
        assert_eq!(clock_rollback_secs(0, 0), None);
        assert_eq!(clock_rollback_secs(0, 1_000_000), None);
    }

    #[test]
    fn rollback_labels() {
        assert_eq!(format_rollback(3_601), "about 1 h");
        assert_eq!(format_rollback(5 * 3_600), "about 5 h");
        assert_eq!(format_rollback(3 * 86_400), "about 3 days");
    }
}
