//! Optional random delay between pressing enter and handing a frame to Tor.
//!
//! Without it, the moment a frame leaves the machine matches the moment the
//! user typed it, which helps someone who can watch both the user and the
//! network line them up. The delay is drawn uniformly from `0..=max` with the
//! OS random source each time.
//!
//! Limits: this blurs timing, it does not hide that a message was sent. The
//! frame is committed to the encrypted outgoing queue before the wait, so a
//! crash or lock during the wait leaves it for `:retry`. There is no cover
//! traffic yet.

use crate::disappearing::{format_ttl, parse_ttl_token};
use std::time::Duration;

/// Upper bound accepted for the setting. Longer waits make chat unusable and
/// widen the window in which a locked or crashed client delays delivery.
pub const MAX_SEND_JITTER_SECS: u32 = 120;

/// Parse a `:jitter` argument: `off`, plain seconds, or `Ns` / `Nm`.
pub fn parse_jitter_token(raw: &str) -> Result<u32, &'static str> {
    let secs = parse_ttl_token(raw).map_err(|_| "bad jitter (use off|5s|30s|2m or seconds)")?;
    if secs > MAX_SEND_JITTER_SECS {
        return Err("jitter too long (max 2m)");
    }
    Ok(secs)
}

/// Short label for status lines.
pub fn format_jitter(secs: u32) -> String {
    if secs == 0 {
        "off".into()
    } else {
        format!("0-{}", format_ttl(secs))
    }
}

/// Pick a delay in `0..=max_secs` seconds at millisecond resolution.
pub fn sample_send_delay(max_secs: u32) -> Duration {
    delay_from_source(max_secs, || {
        let mut b = [0u8; 4];
        // A failed read falls back to the full delay rather than none.
        if getrandom::getrandom(&mut b).is_err() {
            return u32::MAX;
        }
        u32::from_le_bytes(b)
    })
}

/// Uniform pick from `next` with rejection sampling, so no value is favoured
/// by the modulo. `u32::MAX` from the source maps to the full delay.
fn delay_from_source(max_secs: u32, mut next: impl FnMut() -> u32) -> Duration {
    let max_secs = max_secs.min(MAX_SEND_JITTER_SECS);
    if max_secs == 0 {
        return Duration::ZERO;
    }
    let span = max_secs * 1000 + 1;
    let zone = u32::MAX - (u32::MAX % span);
    for _ in 0..64 {
        let v = next();
        if v == u32::MAX {
            break;
        }
        if v < zone {
            return Duration::from_millis(u64::from(v % span));
        }
    }
    Duration::from_secs(u64::from(max_secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_off_and_bounded_values() {
        assert_eq!(parse_jitter_token("off").unwrap(), 0);
        assert_eq!(parse_jitter_token("0").unwrap(), 0);
        assert_eq!(parse_jitter_token("10").unwrap(), 10);
        assert_eq!(parse_jitter_token("30s").unwrap(), 30);
        assert_eq!(parse_jitter_token("2m").unwrap(), 120);
    }

    #[test]
    fn parse_rejects_junk_and_long_values() {
        assert!(parse_jitter_token("").is_err());
        assert!(parse_jitter_token("soon").is_err());
        assert!(parse_jitter_token("3m").is_err());
        assert!(parse_jitter_token("1h").is_err());
    }

    #[test]
    fn labels() {
        assert_eq!(format_jitter(0), "off");
        assert_eq!(format_jitter(30), "0-30s");
        assert_eq!(format_jitter(120), "0-2m");
    }

    #[test]
    fn zero_means_no_delay() {
        assert_eq!(delay_from_source(0, || 12345), Duration::ZERO);
        assert_eq!(sample_send_delay(0), Duration::ZERO);
    }

    #[test]
    fn delay_maps_source_into_range() {
        assert_eq!(delay_from_source(10, || 0), Duration::ZERO);
        assert_eq!(
            delay_from_source(10, || 10_000),
            Duration::from_millis(10_000)
        );
        assert_eq!(delay_from_source(10, || 10_001), Duration::ZERO);
        assert_eq!(
            delay_from_source(10, || 2_500),
            Duration::from_millis(2_500)
        );
    }

    #[test]
    fn delay_rejects_biased_tail() {
        let span = 10 * 1000 + 1;
        let zone = u32::MAX - (u32::MAX % span);
        let mut calls = 0;
        let d = delay_from_source(10, || {
            calls += 1;
            if calls == 1 {
                zone
            } else {
                7
            }
        });
        assert_eq!(d, Duration::from_millis(7));
        assert_eq!(calls, 2);
    }

    #[test]
    fn failed_source_uses_full_delay() {
        assert_eq!(delay_from_source(5, || u32::MAX), Duration::from_secs(5));
    }

    #[test]
    fn values_are_clamped_and_stay_in_range() {
        for _ in 0..200 {
            let d = sample_send_delay(3);
            assert!(d <= Duration::from_secs(3));
        }
        assert!(delay_from_source(9999, || 200_000) <= Duration::from_secs(120));
    }
}
