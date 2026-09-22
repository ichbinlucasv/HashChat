//! Local unlock-attempt backoff helpers (TUI passphrase gate).
//!
//! These delays slow online guessing against a **live unlocked UI**. They are
//! **not** remote authentication and do **not** stop offline attacks on the
//! encrypted `state.enc` blob (Argon2id still dominates there). See THREATMODEL.

/// Policy knobs for consecutive wrong-passphrase backoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnlockBackoffPolicy {
    /// Consecutive failures required before a delay is imposed.
    pub fail_threshold: u32,
    /// Delay (seconds) applied on the first delayed attempt (`failures == threshold`).
    pub initial_delay_secs: u64,
    /// Cap on exponential growth.
    pub max_delay_secs: u64,
}

impl UnlockBackoffPolicy {
    /// Standard posture: delay starts after 5 failures (2s, 4s, 8s… capped at 60s).
    pub const fn standard() -> Self {
        Self {
            fail_threshold: 5,
            initial_delay_secs: 2,
            max_delay_secs: 60,
        }
    }

    /// Extreme posture: earlier gate (3) and longer cap (120s).
    pub const fn extreme() -> Self {
        Self {
            fail_threshold: 3,
            initial_delay_secs: 2,
            max_delay_secs: 120,
        }
    }

    pub fn for_extreme(is_extreme: bool) -> Self {
        if is_extreme {
            Self::extreme()
        } else {
            Self::standard()
        }
    }
}

/// Seconds to wait before the **next** unlock attempt after `failures` consecutive
/// wrong-passphrase outcomes (successful unlock resets the counter to 0).
///
/// - `failures < threshold` → `0` (immediate retry)
/// - `failures == threshold` → `initial_delay_secs`
/// - then doubles each additional failure, capped at `max_delay_secs`
pub fn unlock_backoff_delay_secs(failures: u32, policy: &UnlockBackoffPolicy) -> u64 {
    if failures == 0 || failures < policy.fail_threshold {
        return 0;
    }
    let step = failures - policy.fail_threshold; // 0 → initial
    // Cap shift so 2^step cannot overflow u64 multiply path absurdly.
    let shift = step.min(31);
    let delay = policy
        .initial_delay_secs
        .saturating_mul(1u64 << shift);
    delay.min(policy.max_delay_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_no_delay_before_threshold() {
        let p = UnlockBackoffPolicy::standard();
        assert_eq!(unlock_backoff_delay_secs(0, &p), 0);
        assert_eq!(unlock_backoff_delay_secs(1, &p), 0);
        assert_eq!(unlock_backoff_delay_secs(4, &p), 0);
    }

    #[test]
    fn standard_exponential_then_cap() {
        let p = UnlockBackoffPolicy::standard();
        assert_eq!(unlock_backoff_delay_secs(5, &p), 2);
        assert_eq!(unlock_backoff_delay_secs(6, &p), 4);
        assert_eq!(unlock_backoff_delay_secs(7, &p), 8);
        assert_eq!(unlock_backoff_delay_secs(8, &p), 16);
        assert_eq!(unlock_backoff_delay_secs(9, &p), 32);
        assert_eq!(unlock_backoff_delay_secs(10, &p), 60); // 64 capped
        assert_eq!(unlock_backoff_delay_secs(11, &p), 60);
        assert_eq!(unlock_backoff_delay_secs(20, &p), 60);
    }

    #[test]
    fn extreme_starts_earlier_and_higher_cap() {
        let p = UnlockBackoffPolicy::extreme();
        assert_eq!(unlock_backoff_delay_secs(2, &p), 0);
        assert_eq!(unlock_backoff_delay_secs(3, &p), 2);
        assert_eq!(unlock_backoff_delay_secs(4, &p), 4);
        assert_eq!(unlock_backoff_delay_secs(5, &p), 8);
        assert_eq!(unlock_backoff_delay_secs(9, &p), 120); // 128 capped at 120
        assert_eq!(unlock_backoff_delay_secs(15, &p), 120);
    }

    #[test]
    fn for_extreme_selects_policy() {
        assert_eq!(
            UnlockBackoffPolicy::for_extreme(false),
            UnlockBackoffPolicy::standard()
        );
        assert_eq!(
            UnlockBackoffPolicy::for_extreme(true),
            UnlockBackoffPolicy::extreme()
        );
    }
}
