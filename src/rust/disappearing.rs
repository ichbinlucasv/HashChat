//! Local disappearing-message TTL helpers (TUI / session prefs).
//!
//! Wire frames do **not** carry a TTL today. Expiry is a **local** policy:
//! erase UI plaintext after N seconds and call [`crate::DoubleRatchet::wipe_skipped_key`]
//! when a ratchet message number is known. Peers are **not** forced to erase —
//! document that honesty limit in THREATMODEL / SECURITY.

/// Extreme posture default when enabling Extreme with TTL still off (1 hour).
pub const EXTREME_DEFAULT_TTL_SECS: u32 = 3600;

/// Parse a user TTL token into seconds. `0` / `off` disables.
///
/// Accepts: `off`, `none`, `0`, bare seconds (`30`), or `30s` / `5m` / `1h` / `1d`.
pub fn parse_ttl_token(raw: &str) -> Result<u32, &'static str> {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Err("empty TTL (use off|30s|5m|1h|…)");
    }
    if matches!(
        s.as_str(),
        "off" | "none" | "disable" | "disabled" | "never" | "0"
    ) {
        return Ok(0);
    }

    // Bare unsigned integer → seconds.
    if let Ok(n) = s.parse::<u32>() {
        return Ok(n);
    }

    let (num_s, mult) = if let Some(rest) = s.strip_suffix('s') {
        (rest, 1u32)
    } else if let Some(rest) = s.strip_suffix('m') {
        (rest, 60)
    } else if let Some(rest) = s.strip_suffix('h') {
        (rest, 3600)
    } else if let Some(rest) = s.strip_suffix('d') {
        (rest, 86400)
    } else {
        return Err("bad TTL (use off|30s|5m|1h|1d or seconds)");
    };

    let num_s = num_s.trim();
    if num_s.is_empty() {
        return Err("bad TTL number");
    }
    let n: u32 = num_s.parse().map_err(|_| "bad TTL number")?;
    n.checked_mul(mult).ok_or("TTL overflow")
}

/// Short human label for status / `:disappear` (no secrets).
pub fn format_ttl(secs: u32) -> String {
    if secs == 0 {
        return "off".into();
    }
    if secs % 86400 == 0 {
        return format!("{}d", secs / 86400);
    }
    if secs % 3600 == 0 {
        return format!("{}h", secs / 3600);
    }
    if secs % 60 == 0 {
        return format!("{}m", secs / 60);
    }
    format!("{secs}s")
}

/// Apply Extreme default TTL when posture is Extreme and TTL is still off.
/// Returns the (possibly updated) TTL.
pub fn extreme_default_ttl(is_extreme: bool, current: u32) -> u32 {
    if is_extreme && current == 0 {
        EXTREME_DEFAULT_TTL_SECS
    } else {
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_off_and_units() {
        assert_eq!(parse_ttl_token("off").unwrap(), 0);
        assert_eq!(parse_ttl_token("OFF").unwrap(), 0);
        assert_eq!(parse_ttl_token("none").unwrap(), 0);
        assert_eq!(parse_ttl_token("0").unwrap(), 0);
        assert_eq!(parse_ttl_token("30").unwrap(), 30);
        assert_eq!(parse_ttl_token("30s").unwrap(), 30);
        assert_eq!(parse_ttl_token("5m").unwrap(), 300);
        assert_eq!(parse_ttl_token("1h").unwrap(), 3600);
        assert_eq!(parse_ttl_token("2d").unwrap(), 172_800);
        assert_eq!(parse_ttl_token(" 10M ").unwrap(), 600);
    }

    #[test]
    fn parse_rejects_junk() {
        assert!(parse_ttl_token("").is_err());
        assert!(parse_ttl_token("abc").is_err());
        assert!(parse_ttl_token("s").is_err());
        assert!(parse_ttl_token("-5").is_err());
    }

    #[test]
    fn format_round_trip_labels() {
        assert_eq!(format_ttl(0), "off");
        assert_eq!(format_ttl(30), "30s");
        assert_eq!(format_ttl(300), "5m");
        assert_eq!(format_ttl(3600), "1h");
        assert_eq!(format_ttl(86400), "1d");
    }

    #[test]
    fn extreme_default_only_when_off() {
        assert_eq!(extreme_default_ttl(true, 0), EXTREME_DEFAULT_TTL_SECS);
        assert_eq!(extreme_default_ttl(true, 30), 30);
        assert_eq!(extreme_default_ttl(false, 0), 0);
    }
}

/// Default idle auto-lock timeout (5 minutes). Local UI defense only.
pub const DEFAULT_LOCK_TIMEOUT_SECS: u32 = 300;

/// Extreme posture shorter default when timeout is off or longer than this (1 minute).
pub const EXTREME_DEFAULT_LOCK_TIMEOUT_SECS: u32 = 60;

/// Parse `:lock-timeout` token into seconds. Reuses TTL grammar (`off|1m|5m|…`).
///
/// `0` / `off` disables idle auto-lock (manual `:lock` still works).
pub fn parse_lock_timeout_token(raw: &str) -> Result<u32, &'static str> {
    parse_ttl_token(raw).map_err(|_| "bad lock-timeout (use off|1m|5m|15m|30m or seconds)")
}

/// Short label for status / `:lock-timeout` (no secrets).
pub fn format_lock_timeout(secs: u32) -> String {
    format_ttl(secs)
}

/// Under Extreme, shorten idle lock when currently off or longer than the Extreme default.
pub fn extreme_default_lock_timeout(is_extreme: bool, current: u32) -> u32 {
    if !is_extreme {
        return current;
    }
    if current == 0 || current > EXTREME_DEFAULT_LOCK_TIMEOUT_SECS {
        EXTREME_DEFAULT_LOCK_TIMEOUT_SECS
    } else {
        current
    }
}

#[cfg(test)]
mod lock_timeout_tests {
    use super::*;

    #[test]
    fn parse_lock_timeout_tokens() {
        assert_eq!(parse_lock_timeout_token("off").unwrap(), 0);
        assert_eq!(parse_lock_timeout_token("1m").unwrap(), 60);
        assert_eq!(parse_lock_timeout_token("5m").unwrap(), 300);
        assert_eq!(parse_lock_timeout_token("15m").unwrap(), 900);
        assert_eq!(parse_lock_timeout_token("30m").unwrap(), 1800);
        assert!(parse_lock_timeout_token("").is_err());
        assert!(parse_lock_timeout_token("xyz").is_err());
    }

    #[test]
    fn extreme_shortens_off_or_longer() {
        assert_eq!(
            extreme_default_lock_timeout(true, 0),
            EXTREME_DEFAULT_LOCK_TIMEOUT_SECS
        );
        assert_eq!(
            extreme_default_lock_timeout(true, 300),
            EXTREME_DEFAULT_LOCK_TIMEOUT_SECS
        );
        assert_eq!(extreme_default_lock_timeout(true, 30), 30);
        assert_eq!(extreme_default_lock_timeout(false, 0), 0);
        assert_eq!(extreme_default_lock_timeout(false, 300), 300);
    }

    #[test]
    fn format_lock_timeout_labels() {
        assert_eq!(format_lock_timeout(0), "off");
        assert_eq!(format_lock_timeout(60), "1m");
        assert_eq!(format_lock_timeout(300), "5m");
    }
}
