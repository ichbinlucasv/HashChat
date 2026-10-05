//! Wipe after N failed unlock attempts, counted across restarts.
//!
//! The limit and the running count live in a small plain file, `failwipe`,
//! because they have to be readable before the passphrase is known. The count
//! is raised and saved before each attempt is checked and cleared on success,
//! so killing the process mid-attempt does not give a free guess.
//!
//! Limits: it slows an attacker who types guesses into this program. It does
//! nothing against someone who copies `state.enc` and attacks it elsewhere,
//! and the file shows the feature is in use. Whoever can read and write the
//! data directory can also reset the counter by restoring the file.

use crate::private_fs::{self, PrivateFsError};
use std::fs;
use std::path::Path;

const FILE: &str = "failwipe";
const MAGIC: &str = "HCFW1";
const MAX_FILE_BYTES: u64 = 64;

pub const MIN_FAIL_LIMIT: u32 = 3;
pub const MAX_FAIL_LIMIT: u32 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailWipeConfig {
    pub limit: u32,
    pub count: u32,
}

fn encode(cfg: &FailWipeConfig) -> Vec<u8> {
    format!("{MAGIC} {} {}\n", cfg.limit, cfg.count).into_bytes()
}

fn decode(raw: &[u8]) -> Option<FailWipeConfig> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut parts = text.trim_end().split(' ');
    if parts.next()? != MAGIC {
        return None;
    }
    let limit: u32 = parts.next()?.parse().ok()?;
    let count: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(MIN_FAIL_LIMIT..=MAX_FAIL_LIMIT).contains(&limit) {
        return None;
    }
    Some(FailWipeConfig { limit, count })
}

fn write(data_dir: &Path, cfg: &FailWipeConfig) -> Result<(), &'static str> {
    private_fs::write_private_file(data_dir, FILE, &encode(cfg)).map_err(PrivateFsError::as_str)
}

/// True if the file exists at all, even a damaged one.
pub fn failwipe_present(data_dir: &Path) -> bool {
    fs::symlink_metadata(data_dir.join(FILE)).is_ok()
}

/// Current setting, or `None` if unset or damaged.
pub fn failwipe_config(data_dir: &Path) -> Option<FailWipeConfig> {
    decode(&private_fs::read_private_file(data_dir, FILE, MAX_FILE_BYTES).ok()?)
}

/// Enable the limit, with the counter at zero.
pub fn set_failwipe(data_dir: &Path, limit: u32) -> Result<(), &'static str> {
    if !(MIN_FAIL_LIMIT..=MAX_FAIL_LIMIT).contains(&limit) {
        return Err("limit must be between 3 and 100");
    }
    write(data_dir, &FailWipeConfig { limit, count: 0 })
}

pub fn clear_failwipe(data_dir: &Path) {
    let _ = fs::remove_file(data_dir.join(FILE));
    private_fs::remove_stale_temps(data_dir, FILE);
}

/// What the unlock path should do before checking a passphrase.
#[derive(Debug, PartialEq, Eq)]
pub enum Attempt {
    /// The limit is not set; nothing was recorded.
    Off,
    /// An attempt was recorded; carry on and call [`attempt_succeeded`] or
    /// [`attempt_failed`] with the result.
    Allowed,
    /// The limit was already used up (or the file is damaged): wipe now.
    WipeNow,
}

/// Record that an attempt is starting. The count is saved before any
/// passphrase is checked.
pub fn begin_attempt(data_dir: &Path) -> Attempt {
    if !failwipe_present(data_dir) {
        return Attempt::Off;
    }
    let Some(cfg) = failwipe_config(data_dir) else {
        return Attempt::WipeNow;
    };
    if cfg.count >= cfg.limit {
        return Attempt::WipeNow;
    }
    let next = FailWipeConfig {
        limit: cfg.limit,
        count: cfg.count + 1,
    };
    // If the count cannot be saved, fail closed: an attacker could otherwise
    // make the directory read-only to get unlimited guesses.
    match write(data_dir, &next) {
        Ok(()) => Attempt::Allowed,
        Err(_) => Attempt::WipeNow,
    }
}

/// The passphrase was right: reset the counter.
pub fn attempt_succeeded(data_dir: &Path) {
    if let Some(cfg) = failwipe_config(data_dir) {
        let _ = write(data_dir, &FailWipeConfig { count: 0, ..cfg });
    }
}

/// The passphrase was wrong. Returns true if this used up the limit, in which
/// case the caller wipes.
pub fn attempt_failed(data_dir: &Path) -> bool {
    match failwipe_config(data_dir) {
        Some(cfg) => cfg.count >= cfg.limit,
        None => failwipe_present(data_dir),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut b = [0u8; 6];
        getrandom::getrandom(&mut b).unwrap();
        let suffix: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("hashchat-failwipe-{tag}-{suffix}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn off_by_default_and_rejects_bad_limits() {
        let dir = tmp_dir("off");
        assert_eq!(begin_attempt(&dir), Attempt::Off);
        assert!(set_failwipe(&dir, 2).is_err());
        assert!(set_failwipe(&dir, 101).is_err());
        assert!(!failwipe_present(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_nth_failure_triggers_the_wipe() {
        let dir = tmp_dir("nth");
        set_failwipe(&dir, 3).unwrap();
        for i in 1..=3 {
            assert_eq!(begin_attempt(&dir), Attempt::Allowed);
            assert_eq!(attempt_failed(&dir), i == 3, "attempt {i}");
        }
        // Even if the caller somehow carried on, the next attempt wipes.
        assert_eq!(begin_attempt(&dir), Attempt::WipeNow);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn success_resets_the_count() {
        let dir = tmp_dir("reset");
        set_failwipe(&dir, 3).unwrap();
        for _ in 0..2 {
            assert_eq!(begin_attempt(&dir), Attempt::Allowed);
            assert!(!attempt_failed(&dir));
        }
        assert_eq!(begin_attempt(&dir), Attempt::Allowed);
        attempt_succeeded(&dir);
        assert_eq!(failwipe_config(&dir).unwrap().count, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_killed_attempt_still_counts_after_restart() {
        let dir = tmp_dir("kill");
        set_failwipe(&dir, 3).unwrap();
        // Three attempts begin and the process dies before any result is recorded.
        for _ in 0..3 {
            assert_eq!(begin_attempt(&dir), Attempt::Allowed);
        }
        assert_eq!(begin_attempt(&dir), Attempt::WipeNow);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn damaged_file_wipes() {
        let dir = tmp_dir("damaged");
        private_fs::write_private_file(&dir, FILE, b"nonsense").unwrap();
        assert_eq!(begin_attempt(&dir), Attempt::WipeNow);
        assert!(attempt_failed(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_wipe_removes_the_file() {
        let dir = tmp_dir("diskwipe");
        set_failwipe(&dir, 5).unwrap();
        crate::session_persist::wipe_disk(&dir).unwrap();
        assert!(!failwipe_present(&dir));
        let _ = fs::remove_dir_all(&dir);
    }
}
