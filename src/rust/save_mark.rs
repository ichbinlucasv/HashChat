//! Notice a `state.enc` that is not the one this data directory last wrote.
//!
//! Every save picks a fresh random 16-byte id, stores it inside the encrypted
//! blob and then writes the same id to `state.mark` next to it. At unlock the
//! two are compared. If someone swaps in an older copy of `state.enc` (from a
//! backup, a disk image or a sync tool), its id no longer matches the mark, and
//! the TUI warns before the next save overwrites the mark.
//!
//! Limits: an attacker who restores the whole data directory, mark included,
//! is not detected; nothing stored on the same disk can catch that. A crash
//! between writing `state.enc` and `state.mark` gives one false warning on the
//! next unlock. The mark is random bytes, so it says nothing about how often
//! or when the profile was used beyond the file's own timestamps.

use std::path::Path;

use crate::private_fs::{self, PrivateFsError};

pub const SAVE_MARK_FILE: &str = "state.mark";
pub const SAVE_ID_BYTES: usize = 16;

pub type SaveId = [u8; SAVE_ID_BYTES];

/// Result of comparing the id inside `state.enc` with `state.mark`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveMarkStatus {
    /// The blob predates save ids; nothing to compare yet.
    Unrecorded,
    /// The blob is the last one written here.
    Match,
    /// The blob carries an id but the mark is missing or unreadable.
    MarkMissing,
    /// The blob is not the last one written here.
    Mismatch,
}

impl SaveMarkStatus {
    pub fn is_warning(self) -> bool {
        matches!(self, SaveMarkStatus::MarkMissing | SaveMarkStatus::Mismatch)
    }

    /// Token for `:evidence`.
    pub fn token(self) -> &'static str {
        match self {
            SaveMarkStatus::Unrecorded => "unrecorded",
            SaveMarkStatus::Match => "ok",
            SaveMarkStatus::MarkMissing => "mark-missing",
            SaveMarkStatus::Mismatch => "older-copy",
        }
    }
}

pub fn new_save_id() -> Result<SaveId, &'static str> {
    let mut id = [0u8; SAVE_ID_BYTES];
    getrandom::getrandom(&mut id).map_err(|_| "csprng failed")?;
    Ok(id)
}

pub fn write_save_mark(data_dir: &Path, id: &SaveId) -> Result<(), &'static str> {
    private_fs::write_private_file(data_dir, SAVE_MARK_FILE, id).map_err(PrivateFsError::as_str)
}

/// The recorded id, or `None` when the file is missing, malformed or refused.
pub fn read_save_mark(data_dir: &Path) -> Option<SaveId> {
    let bytes =
        private_fs::read_private_file(data_dir, SAVE_MARK_FILE, SAVE_ID_BYTES as u64).ok()?;
    bytes.as_slice().try_into().ok()
}

pub fn save_mark_status(in_blob: Option<&SaveId>, on_disk: Option<&SaveId>) -> SaveMarkStatus {
    match (in_blob, on_disk) {
        (None, _) => SaveMarkStatus::Unrecorded,
        (Some(_), None) => SaveMarkStatus::MarkMissing,
        (Some(a), Some(b)) if a == b => SaveMarkStatus::Match,
        (Some(_), Some(_)) => SaveMarkStatus::Mismatch,
    }
}

/// Compare a loaded blob's id with the mark in `data_dir`.
pub fn check_save_mark(data_dir: &Path, in_blob: Option<&SaveId>) -> SaveMarkStatus {
    save_mark_status(in_blob, read_save_mark(data_dir).as_ref())
}

pub fn clear_save_mark(data_dir: &Path) {
    crate::shred::shred_file(&data_dir.join(SAVE_MARK_FILE));
    private_fs::remove_stale_temps(data_dir, SAVE_MARK_FILE);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("hashchat-mark-{tag}-{n}"));
        let _ = std::fs::remove_dir_all(&p);
        private_fs::ensure_private_dir(&p).unwrap();
        p
    }

    #[test]
    fn status_table() {
        let a = [1u8; SAVE_ID_BYTES];
        let b = [2u8; SAVE_ID_BYTES];
        assert_eq!(save_mark_status(None, None), SaveMarkStatus::Unrecorded);
        assert_eq!(save_mark_status(None, Some(&a)), SaveMarkStatus::Unrecorded);
        assert_eq!(
            save_mark_status(Some(&a), None),
            SaveMarkStatus::MarkMissing
        );
        assert_eq!(save_mark_status(Some(&a), Some(&a)), SaveMarkStatus::Match);
        assert_eq!(
            save_mark_status(Some(&a), Some(&b)),
            SaveMarkStatus::Mismatch
        );
        assert!(!SaveMarkStatus::Unrecorded.is_warning());
        assert!(!SaveMarkStatus::Match.is_warning());
        assert!(SaveMarkStatus::MarkMissing.is_warning());
        assert!(SaveMarkStatus::Mismatch.is_warning());
    }

    #[test]
    fn ids_are_random() {
        assert_ne!(new_save_id().unwrap(), new_save_id().unwrap());
    }

    #[test]
    fn mark_roundtrip_and_clear() {
        let dir = tmp_dir("rt");
        assert_eq!(read_save_mark(&dir), None);
        let id = new_save_id().unwrap();
        write_save_mark(&dir, &id).unwrap();
        assert_eq!(read_save_mark(&dir), Some(id));
        assert_eq!(check_save_mark(&dir, Some(&id)), SaveMarkStatus::Match);
        clear_save_mark(&dir);
        assert_eq!(read_save_mark(&dir), None);
        assert_eq!(
            check_save_mark(&dir, Some(&id)),
            SaveMarkStatus::MarkMissing
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_mark_reads_as_missing() {
        let dir = tmp_dir("bad");
        private_fs::write_private_file(&dir, SAVE_MARK_FILE, b"short").unwrap();
        assert_eq!(read_save_mark(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
