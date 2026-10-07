//! Duress passphrase: a second passphrase that wipes the local store.
//!
//! The verifier is a small Argon2id + AES-GCM envelope in `duress.enc` next to
//! `state.enc`. It holds a fixed marker and nothing else, so it cannot decrypt
//! any user data. The unlock path tries the real passphrase first and only
//! consults this file after that fails.
//!
//! The marker also records what to do after the wipe: report a failed unlock
//! ([`DuressAction::Wipe`]) or open a fresh, empty profile sealed with the
//! duress passphrase ([`DuressAction::Decoy`]). The choice is inside the
//! envelope, so it cannot be read without the duress passphrase.
//!
//! Limits: the file is visible to anyone who can read the data directory, and
//! an attacker who copied `state.enc` is not affected by it. It helps against
//! a coerced unlock at the keyboard, nothing more. A decoy profile has no
//! contacts and a new onion address, and the unlock takes noticeably longer
//! (three Argon2id runs instead of one), so it will not survive a careful look.

use crate::envelope::{self, StoreKey};
use crate::private_fs::{self, PrivateFsError};
use crate::session_persist::passphrase_opens_state;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

pub(crate) const DURESS_FILE: &str = "duress.enc";
/// Marker for a plain wipe. Older verifiers only ever used this one.
const DURESS_MARKER: &[u8] = b"HashChat-duress-v1";
/// Marker for wipe followed by a fresh decoy profile.
const DURESS_MARKER_DECOY: &[u8] = b"HashChat-duress-decoy-v1";
/// The verifier is a few dozen bytes; anything larger is not ours.
pub(crate) const MAX_DURESS_FILE_BYTES: u64 = 4096;

/// What happens after the duress passphrase wipes the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuressAction {
    /// Wipe and report an ordinary failed unlock.
    Wipe,
    /// Wipe, then create and open a new empty profile under the duress passphrase.
    Decoy,
}

impl DuressAction {
    fn marker(self) -> &'static [u8] {
        match self {
            DuressAction::Wipe => DURESS_MARKER,
            DuressAction::Decoy => DURESS_MARKER_DECOY,
        }
    }
}

/// True if a duress verifier is present (symlinks count, like `state.enc`).
pub fn duress_configured(data_dir: &Path) -> bool {
    fs::symlink_metadata(data_dir.join(DURESS_FILE)).is_ok()
}

/// Store a verifier for `duress_pass`.
///
/// Refuses an empty passphrase and one that also opens `state.enc`, since the
/// unlock path would then never reach the duress check.
pub fn set_duress_passphrase(data_dir: &Path, duress_pass: &[u8]) -> Result<(), &'static str> {
    set_duress_passphrase_with(data_dir, duress_pass, DuressAction::Wipe)
}

/// Like [`set_duress_passphrase`], with an explicit action after the wipe.
pub fn set_duress_passphrase_with(
    data_dir: &Path,
    duress_pass: &[u8],
    action: DuressAction,
) -> Result<(), &'static str> {
    if duress_pass.is_empty() {
        return Err("empty passphrase refused");
    }
    if passphrase_opens_state(data_dir, duress_pass) {
        return Err("duress passphrase must differ from the unlock passphrase");
    }
    let env = envelope::seal(duress_pass, action.marker())?;
    private_fs::write_private_file(data_dir, DURESS_FILE, &env).map_err(PrivateFsError::as_str)
}

/// True if `pass` matches the stored duress verifier. A missing, unreadable or
/// malformed file is simply "no".
pub fn is_duress_passphrase(data_dir: &Path, pass: &[u8]) -> bool {
    duress_action(data_dir, pass).is_some()
}

/// The configured action if `pass` matches the stored verifier, else `None`.
pub fn duress_action(data_dir: &Path, pass: &[u8]) -> Option<DuressAction> {
    if pass.is_empty() {
        return None;
    }
    let env = private_fs::read_private_file(data_dir, DURESS_FILE, MAX_DURESS_FILE_BYTES).ok()?;
    let key = StoreKey::derive_for_envelope(pass, &env).ok()?;
    let mut plain = envelope::open_with_key(&key, &env).ok()?;
    let action = if bytes_eq(&plain, DURESS_MARKER) {
        Some(DuressAction::Wipe)
    } else if bytes_eq(&plain, DURESS_MARKER_DECOY) {
        Some(DuressAction::Decoy)
    } else {
        None
    };
    plain.zeroize();
    action
}

/// Called after a failed unlock: if `pass` is the duress passphrase, run
/// `wipe` and return true. Does nothing when no verifier is configured.
pub fn wipe_if_duress(data_dir: &Path, pass: &[u8], wipe: impl FnOnce()) -> bool {
    wipe_on_duress(data_dir, pass, wipe).is_some()
}

/// Like [`wipe_if_duress`], but returns the configured action so the caller
/// can open a decoy profile after the wipe.
pub fn wipe_on_duress(data_dir: &Path, pass: &[u8], wipe: impl FnOnce()) -> Option<DuressAction> {
    if !duress_configured(data_dir) {
        return None;
    }
    let action = duress_action(data_dir, pass)?;
    wipe();
    Some(action)
}

/// Remove the verifier. Missing file is fine.
pub fn clear_duress(data_dir: &Path) {
    let _ = fs::remove_file(data_dir.join(DURESS_FILE));
    private_fs::remove_stale_temps(data_dir, DURESS_FILE);
}

fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::longterm_identity::LongTermIdentity;
    use crate::session_persist::{save_session, IdentityOnionState, PersistMode, SessionState};
    use std::path::PathBuf;

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut b = [0u8; 6];
        getrandom::getrandom(&mut b).unwrap();
        let suffix: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("hashchat-duress-{tag}-{suffix}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn store_with(dir: &Path, pass: &[u8]) {
        let id = LongTermIdentity::from_seed([0x51u8; 32]);
        let session =
            SessionState::from_identity(IdentityOnionState::from_identity(&id, "me.onion", vec![]));
        save_session(dir, PersistMode::Passphrase, pass, &session).unwrap();
    }

    #[test]
    fn set_then_match_only_the_duress_passphrase() {
        let dir = tmp_dir("roundtrip");
        store_with(&dir, b"real passphrase one");
        assert!(!duress_configured(&dir));
        set_duress_passphrase(&dir, b"under duress two").unwrap();
        assert!(duress_configured(&dir));
        assert!(is_duress_passphrase(&dir, b"under duress two"));
        assert!(!is_duress_passphrase(&dir, b"real passphrase one"));
        assert!(!is_duress_passphrase(&dir, b"something else"));
        assert!(!is_duress_passphrase(&dir, b""));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_empty_and_unlock_passphrase() {
        let dir = tmp_dir("refuse");
        store_with(&dir, b"real passphrase one");
        assert!(set_duress_passphrase(&dir, b"").is_err());
        assert!(set_duress_passphrase(&dir, b"real passphrase one").is_err());
        assert!(!duress_configured(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_or_garbage_file_never_matches() {
        let dir = tmp_dir("garbage");
        store_with(&dir, b"real passphrase one");
        assert!(!is_duress_passphrase(&dir, b"anything"));
        private_fs::write_private_file(&dir, DURESS_FILE, &[0u8; 64]).unwrap();
        assert!(!is_duress_passphrase(&dir, b"anything"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_runs_only_for_the_duress_passphrase() {
        let dir = tmp_dir("trigger");
        store_with(&dir, b"real passphrase one");

        let mut ran = false;
        assert!(!wipe_if_duress(&dir, b"under duress two", || ran = true));
        assert!(!ran, "no verifier configured");

        set_duress_passphrase(&dir, b"under duress two").unwrap();
        assert!(!wipe_if_duress(&dir, b"wrong guess", || ran = true));
        assert!(!ran);
        assert!(wipe_if_duress(&dir, b"under duress two", || ran = true));
        assert!(ran);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decoy_action_round_trips() {
        let dir = tmp_dir("decoy");
        store_with(&dir, b"real passphrase one");
        set_duress_passphrase_with(&dir, b"under duress two", DuressAction::Decoy).unwrap();
        assert_eq!(
            duress_action(&dir, b"under duress two"),
            Some(DuressAction::Decoy)
        );
        assert_eq!(duress_action(&dir, b"real passphrase one"), None);

        let mut ran = false;
        assert_eq!(wipe_on_duress(&dir, b"wrong guess", || ran = true), None);
        assert!(!ran);
        assert_eq!(
            wipe_on_duress(&dir, b"under duress two", || ran = true),
            Some(DuressAction::Decoy)
        );
        assert!(ran);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plain_set_keeps_the_wipe_action() {
        let dir = tmp_dir("plain");
        store_with(&dir, b"real passphrase one");
        set_duress_passphrase(&dir, b"under duress two").unwrap();
        assert_eq!(
            duress_action(&dir, b"under duress two"),
            Some(DuressAction::Wipe)
        );
        // Switching to decoy replaces the verifier rather than adding a second one.
        set_duress_passphrase_with(&dir, b"under duress two", DuressAction::Decoy).unwrap();
        assert_eq!(
            duress_action(&dir, b"under duress two"),
            Some(DuressAction::Decoy)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_marker_is_not_a_match() {
        let dir = tmp_dir("marker");
        store_with(&dir, b"real passphrase one");
        let env = envelope::seal(b"under duress two", b"HashChat-duress-v9").unwrap();
        private_fs::write_private_file(&dir, DURESS_FILE, &env).unwrap();
        assert_eq!(duress_action(&dir, b"under duress two"), None);
        assert!(!wipe_if_duress(&dir, b"under duress two", || panic!(
            "must not wipe"
        )));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_removes_the_verifier() {
        let dir = tmp_dir("clear");
        store_with(&dir, b"real passphrase one");
        set_duress_passphrase(&dir, b"under duress two").unwrap();
        clear_duress(&dir);
        assert!(!duress_configured(&dir));
        assert!(!is_duress_passphrase(&dir, b"under duress two"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_wipe_removes_the_verifier() {
        let dir = tmp_dir("wipe");
        store_with(&dir, b"real passphrase one");
        set_duress_passphrase(&dir, b"under duress two").unwrap();
        crate::session_persist::wipe_disk(&dir).unwrap();
        assert!(!duress_configured(&dir));
        let _ = fs::remove_dir_all(&dir);
    }
}
