//! Dead-man switch: wipe the local store if it was not unlocked for N days.
//!
//! The setting and the last-unlock time live in a small plain file, `deadman`,
//! next to `state.enc`. It has to be readable before the passphrase is known,
//! so it is not encrypted; it holds a day count and a timestamp, nothing else.
//!
//! Limits: the check only runs when HashChat starts. If the program is never
//! launched, nothing happens, and a copy of the data directory made earlier is
//! not affected. A clock set far forward triggers the wipe early; a clock set
//! back only delays it.

use crate::private_fs::{self, PrivateFsError};
use std::fs;
use std::path::Path;

const DEADMAN_FILE: &str = "deadman";
const MAGIC: &str = "HCDM1";
const MAX_FILE_BYTES: u64 = 128;

pub const MIN_DEADMAN_DAYS: u32 = 1;
pub const MAX_DEADMAN_DAYS: u32 = 365;
const SECS_PER_DAY: u64 = 86_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadmanConfig {
    pub days: u32,
    pub last_unlock_unix: u64,
}

impl DeadmanConfig {
    /// Seconds left before the wipe fires, 0 if already due.
    pub fn remaining_secs(&self, now_unix: u64) -> u64 {
        let deadline = self
            .last_unlock_unix
            .saturating_add(u64::from(self.days) * SECS_PER_DAY);
        deadline.saturating_sub(now_unix)
    }

    /// Due once `days` full days have passed since the last unlock. A clock
    /// that reads earlier than the recorded time never counts as due.
    pub fn is_due(&self, now_unix: u64) -> bool {
        now_unix >= self.last_unlock_unix && self.remaining_secs(now_unix) == 0
    }
}

fn encode(cfg: &DeadmanConfig) -> Vec<u8> {
    format!("{MAGIC} {} {}\n", cfg.days, cfg.last_unlock_unix).into_bytes()
}

fn decode(raw: &[u8]) -> Option<DeadmanConfig> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut parts = text.trim_end().split(' ');
    if parts.next()? != MAGIC {
        return None;
    }
    let days: u32 = parts.next()?.parse().ok()?;
    let last_unlock_unix: u64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(MIN_DEADMAN_DAYS..=MAX_DEADMAN_DAYS).contains(&days) {
        return None;
    }
    Some(DeadmanConfig {
        days,
        last_unlock_unix,
    })
}

/// Current setting, or `None` if unset or unreadable.
pub fn deadman_config(data_dir: &Path) -> Option<DeadmanConfig> {
    let raw = private_fs::read_private_file(data_dir, DEADMAN_FILE, MAX_FILE_BYTES).ok()?;
    decode(&raw)
}

/// True if a dead-man file exists at all (even a damaged one).
pub fn deadman_present(data_dir: &Path) -> bool {
    fs::symlink_metadata(data_dir.join(DEADMAN_FILE)).is_ok()
}

/// Enable the switch for `days` days, counting from `now_unix`.
pub fn set_deadman(data_dir: &Path, days: u32, now_unix: u64) -> Result<(), &'static str> {
    if !(MIN_DEADMAN_DAYS..=MAX_DEADMAN_DAYS).contains(&days) {
        return Err("days must be between 1 and 365");
    }
    let cfg = DeadmanConfig {
        days,
        last_unlock_unix: now_unix,
    };
    private_fs::write_private_file(data_dir, DEADMAN_FILE, &encode(&cfg))
        .map_err(PrivateFsError::as_str)
}

/// Record a successful unlock. Does nothing when the switch is off.
pub fn touch_deadman(data_dir: &Path, now_unix: u64) {
    if let Some(cfg) = deadman_config(data_dir) {
        let _ = set_deadman(data_dir, cfg.days, now_unix);
    }
}

/// Turn the switch off. Missing file is fine.
pub fn clear_deadman(data_dir: &Path) {
    let _ = fs::remove_file(data_dir.join(DEADMAN_FILE));
    private_fs::remove_stale_temps(data_dir, DEADMAN_FILE);
}

/// Startup check: run `wipe` and return true if the switch is set and due.
/// A damaged file is treated as due, since an attacker could otherwise defeat
/// the switch by corrupting it.
pub fn wipe_if_deadman_due(data_dir: &Path, now_unix: u64, wipe: impl FnOnce()) -> bool {
    if !deadman_present(data_dir) {
        return false;
    }
    let due = match deadman_config(data_dir) {
        Some(cfg) => cfg.is_due(now_unix),
        None => true,
    };
    if due {
        wipe();
    }
    due
}

/// Seconds since the Unix epoch; 0 if the clock is before it.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut b = [0u8; 6];
        getrandom::getrandom(&mut b).unwrap();
        let suffix: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("hashchat-deadman-{tag}-{suffix}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    const DAY: u64 = SECS_PER_DAY;

    #[test]
    fn set_and_read_back() {
        let dir = tmp_dir("roundtrip");
        assert!(deadman_config(&dir).is_none());
        set_deadman(&dir, 14, 1_000).unwrap();
        let cfg = deadman_config(&dir).unwrap();
        assert_eq!(cfg.days, 14);
        assert_eq!(cfg.last_unlock_unix, 1_000);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_out_of_range_days() {
        let dir = tmp_dir("range");
        assert!(set_deadman(&dir, 0, 1).is_err());
        assert!(set_deadman(&dir, 366, 1).is_err());
        assert!(!deadman_present(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn due_only_after_the_full_period() {
        let cfg = DeadmanConfig {
            days: 7,
            last_unlock_unix: 10_000,
        };
        assert!(!cfg.is_due(10_000));
        assert!(!cfg.is_due(10_000 + 7 * DAY - 1));
        assert!(cfg.is_due(10_000 + 7 * DAY));
        assert!(cfg.is_due(10_000 + 30 * DAY));
        assert_eq!(cfg.remaining_secs(10_000 + 6 * DAY), DAY);
    }

    #[test]
    fn clock_before_last_unlock_is_not_due() {
        let cfg = DeadmanConfig {
            days: 1,
            last_unlock_unix: 50 * DAY,
        };
        assert!(!cfg.is_due(10 * DAY));
    }

    #[test]
    fn wipe_runs_only_when_due() {
        let dir = tmp_dir("trigger");
        let mut ran = false;
        assert!(!wipe_if_deadman_due(&dir, 99 * DAY, || ran = true));
        assert!(!ran, "switch is off");

        set_deadman(&dir, 3, 100).unwrap();
        assert!(!wipe_if_deadman_due(&dir, 100 + 2 * DAY, || ran = true));
        assert!(!ran);
        assert!(wipe_if_deadman_due(&dir, 100 + 3 * DAY, || ran = true));
        assert!(ran);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn touch_pushes_the_deadline_out() {
        let dir = tmp_dir("touch");
        set_deadman(&dir, 2, 0).unwrap();
        touch_deadman(&dir, 5 * DAY);
        let mut ran = false;
        assert!(!wipe_if_deadman_due(&dir, 6 * DAY, || ran = true));
        assert!(!ran);
        assert!(wipe_if_deadman_due(&dir, 7 * DAY, || ran = true));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn touch_does_not_enable_a_disabled_switch() {
        let dir = tmp_dir("touch-off");
        touch_deadman(&dir, 123);
        assert!(!deadman_present(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn damaged_file_counts_as_due() {
        let dir = tmp_dir("damaged");
        private_fs::write_private_file(&dir, DEADMAN_FILE, b"garbage").unwrap();
        let mut ran = false;
        assert!(wipe_if_deadman_due(&dir, 1, || ran = true));
        assert!(ran);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_turns_it_off_and_disk_wipe_removes_it() {
        let dir = tmp_dir("clear");
        set_deadman(&dir, 5, 1).unwrap();
        clear_deadman(&dir);
        assert!(!deadman_present(&dir));
        set_deadman(&dir, 5, 1).unwrap();
        crate::session_persist::wipe_disk(&dir).unwrap();
        assert!(!deadman_present(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decode_rejects_extra_fields_and_bad_magic() {
        assert!(decode(b"HCDM1 7 100\n").is_some());
        assert!(decode(b"HCDM1 7 100 9\n").is_none());
        assert!(decode(b"HCDM2 7 100\n").is_none());
        assert!(decode(b"HCDM1 0 100\n").is_none());
    }
}
