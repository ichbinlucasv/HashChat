//! Duress passphrase: a second passphrase that wipes the local store.
//!
//! The verifier is a small Argon2id + AES-GCM envelope in `duress.enc` next to
//! `state.enc`. It holds a fixed marker and nothing else, so it cannot decrypt
//! any user data. The unlock path tries the real passphrase first and only
//! consults this file after that fails.
//!
//! Limits: the file is visible to anyone who can read the data directory, and
//! an attacker who copied `state.enc` is not affected by it. It helps against
//! a coerced unlock at the keyboard, nothing more.

use crate::envelope::{self, StoreKey};
use crate::private_fs::{self, PrivateFsError};
use crate::session_persist::passphrase_opens_state;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

const DURESS_FILE: &str = "duress.enc";
const DURESS_MARKER: &[u8] = b"HashChat-duress-v1";
/// The verifier is a few dozen bytes; anything larger is not ours.
const MAX_DURESS_FILE_BYTES: u64 = 4096;

/// True if a duress verifier is present (symlinks count, like `state.enc`).
pub fn duress_configured(data_dir: &Path) -> bool {
    fs::symlink_metadata(data_dir.join(DURESS_FILE)).is_ok()
}

/// Store a verifier for `duress_pass`.
///
/// Refuses an empty passphrase and one that also opens `state.enc`, since the
/// unlock path would then never reach the duress check.
pub fn set_duress_passphrase(data_dir: &Path, duress_pass: &[u8]) -> Result<(), &'static str> {
    if duress_pass.is_empty() {
        return Err("empty passphrase refused");
    }
    if passphrase_opens_state(data_dir, duress_pass) {
        return Err("duress passphrase must differ from the unlock passphrase");
    }
    let env = envelope::seal(duress_pass, DURESS_MARKER)?;
    private_fs::write_private_file(data_dir, DURESS_FILE, &env).map_err(PrivateFsError::as_str)
}

/// True if `pass` matches the stored duress verifier. A missing, unreadable or
/// malformed file is simply "no".
pub fn is_duress_passphrase(data_dir: &Path, pass: &[u8]) -> bool {
    if pass.is_empty() {
        return false;
    }
    let Ok(env) = private_fs::read_private_file(data_dir, DURESS_FILE, MAX_DURESS_FILE_BYTES)
    else {
        return false;
    };
    let Ok(key) = StoreKey::derive_for_envelope(pass, &env) else {
        return false;
    };
    match envelope::open_with_key(&key, &env) {
        Ok(mut plain) => {
            let ok = bytes_eq(&plain, DURESS_MARKER);
            plain.zeroize();
            ok
        }
        Err(_) => false,
    }
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
