//! Warn when the wipe settings changed while the profile was locked.
//!
//! The dead-man switch, the failed-unlock limit and the duress verifier live
//! in plain files next to `state.enc`, because they are needed before the
//! passphrase is known. Deleting one of them quietly turns the protection off,
//! and `:deadman off`, `:wipe-after off` and `:duress clear` work at the
//! locked screen. So each change made from an unlocked session records the
//! settings inside `state.enc`, and the next unlock compares that record with
//! the files on disk.
//!
//! Only the settings are compared: the dead-man day count, the unlock limit
//! and a digest of `duress.enc`. The dead-man timestamp and the failed-unlock
//! count change on their own and are left out, so a counter reset by
//! restoring an old `failwipe` file is not caught. Someone who can write the
//! data directory can still remove the files; this makes it visible at the
//! next unlock, nothing more.

use crate::deadman::deadman_config;
use crate::duress::{DURESS_FILE, MAX_DURESS_FILE_BYTES};
use crate::failwipe::failwipe_config;
use crate::private_fs;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Digest used for "no duress verifier".
const NO_DURESS: [u8; 32] = [0u8; 32];
/// Digest used for a duress file that exists but cannot be read.
const UNREADABLE_DURESS: [u8; 32] = [0xFFu8; 32];

/// Serialized size inside the session blob.
pub const WIPE_SETTINGS_BYTES: usize = 4 + 4 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WipeSettings {
    /// Dead-man switch days, 0 when off.
    pub deadman_days: u32,
    /// Failed-unlock limit, 0 when off.
    pub failwipe_limit: u32,
    /// SHA-256 of `duress.enc`, all zero when there is none.
    pub duress_digest: [u8; 32],
}

impl WipeSettings {
    /// Read the settings from the files in `data_dir`.
    pub fn from_disk(data_dir: &Path) -> Self {
        Self {
            deadman_days: deadman_config(data_dir).map_or(0, |c| c.days),
            failwipe_limit: failwipe_config(data_dir).map_or(0, |c| c.limit),
            duress_digest: duress_digest(data_dir),
        }
    }

    /// Names of the settings that differ from `recorded`, for the warning.
    pub fn changes_since(&self, recorded: &WipeSettings) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.deadman_days != recorded.deadman_days {
            out.push("dead-man switch");
        }
        if self.failwipe_limit != recorded.failwipe_limit {
            out.push("wipe after failed unlocks");
        }
        if self.duress_digest != recorded.duress_digest {
            out.push("duress passphrase");
        }
        out
    }

    pub fn to_bytes(&self) -> [u8; WIPE_SETTINGS_BYTES] {
        let mut out = [0u8; WIPE_SETTINGS_BYTES];
        out[..4].copy_from_slice(&self.deadman_days.to_be_bytes());
        out[4..8].copy_from_slice(&self.failwipe_limit.to_be_bytes());
        out[8..].copy_from_slice(&self.duress_digest);
        out
    }

    pub fn from_bytes(b: &[u8; WIPE_SETTINGS_BYTES]) -> Self {
        Self {
            deadman_days: u32::from_be_bytes(b[..4].try_into().unwrap()),
            failwipe_limit: u32::from_be_bytes(b[4..8].try_into().unwrap()),
            duress_digest: b[8..].try_into().unwrap(),
        }
    }
}

fn duress_digest(data_dir: &Path) -> [u8; 32] {
    if fs::symlink_metadata(data_dir.join(DURESS_FILE)).is_err() {
        return NO_DURESS;
    }
    match private_fs::read_private_file(data_dir, DURESS_FILE, MAX_DURESS_FILE_BYTES) {
        Ok(env) => Sha256::digest(&env).into(),
        Err(_) => UNREADABLE_DURESS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deadman::{clear_deadman, set_deadman};
    use crate::failwipe::{clear_failwipe, set_failwipe};
    use std::path::PathBuf;

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut b = [0u8; 6];
        getrandom::getrandom(&mut b).unwrap();
        let suffix: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("hashchat-wipeset-{tag}-{suffix}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn empty_dir_reads_as_all_off() {
        let dir = tmp_dir("empty");
        let s = WipeSettings::from_disk(&dir);
        assert_eq!(s.deadman_days, 0);
        assert_eq!(s.failwipe_limit, 0);
        assert_eq!(s.duress_digest, NO_DURESS);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn removed_files_are_reported() {
        let dir = tmp_dir("removed");
        set_deadman(&dir, 7, 1_000).unwrap();
        set_failwipe(&dir, 5).unwrap();
        private_fs::write_private_file(&dir, DURESS_FILE, b"verifier").unwrap();
        let recorded = WipeSettings::from_disk(&dir);
        assert_eq!(recorded.deadman_days, 7);
        assert_eq!(recorded.failwipe_limit, 5);
        assert_ne!(recorded.duress_digest, NO_DURESS);
        assert!(WipeSettings::from_disk(&dir)
            .changes_since(&recorded)
            .is_empty());

        clear_deadman(&dir);
        clear_failwipe(&dir);
        fs::remove_file(dir.join(DURESS_FILE)).unwrap();
        assert_eq!(
            WipeSettings::from_disk(&dir).changes_since(&recorded),
            vec![
                "dead-man switch",
                "wipe after failed unlocks",
                "duress passphrase"
            ]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn timestamp_and_counter_do_not_count_as_changes() {
        let dir = tmp_dir("noise");
        set_deadman(&dir, 3, 1_000).unwrap();
        set_failwipe(&dir, 4).unwrap();
        let recorded = WipeSettings::from_disk(&dir);
        set_deadman(&dir, 3, 99_000).unwrap();
        assert_eq!(
            crate::failwipe::begin_attempt(&dir),
            crate::failwipe::Attempt::Allowed
        );
        assert!(WipeSettings::from_disk(&dir)
            .changes_since(&recorded)
            .is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn replaced_duress_file_is_reported() {
        let dir = tmp_dir("duress");
        private_fs::write_private_file(&dir, DURESS_FILE, b"first").unwrap();
        let recorded = WipeSettings::from_disk(&dir);
        private_fs::write_private_file(&dir, DURESS_FILE, b"second").unwrap();
        assert_eq!(
            WipeSettings::from_disk(&dir).changes_since(&recorded),
            vec!["duress passphrase"]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_duress_file_differs_from_none() {
        let dir = tmp_dir("symlink");
        let target = dir.join("elsewhere");
        fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, dir.join(DURESS_FILE)).unwrap();
        assert_eq!(duress_digest(&dir), UNREADABLE_DURESS);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bytes_roundtrip() {
        let s = WipeSettings {
            deadman_days: 30,
            failwipe_limit: 10,
            duress_digest: [0x42u8; 32],
        };
        assert_eq!(WipeSettings::from_bytes(&s.to_bytes()), s);
    }
}
