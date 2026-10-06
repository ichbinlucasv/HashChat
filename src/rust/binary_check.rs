//! Warn when the program that opens a profile is not the one that last saved it.
//!
//! A swapped `hashchat-tui` binary is the simplest way to steal a passphrase
//! from a machine someone else had access to. Each save of the encrypted state
//! records the SHA-256 of the running executable, and the next unlock compares
//! it with the binary doing the unlock.
//!
//! This is a tripwire, not a defence. A modified binary can skip the check,
//! and it only runs after the passphrase was typed. It does catch a binary
//! replaced by someone who did not also patch the check out, and it makes an
//! update the user did not do visible. The digest lives inside `state.enc`, so
//! it cannot be rewritten without the passphrase.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

/// All-zero digest: nothing recorded yet (pre-v10 blob or unknown binary).
pub const NO_BINARY_DIGEST: [u8; 32] = [0u8; 32];

/// Executables larger than this are not hashed (the release binary is ~10 MiB).
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;

static RUNNING_DIGEST: OnceLock<Option<[u8; 32]>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryStatus {
    /// Same digest as the one stored at the last save.
    Same,
    /// The stored digest differs from the running binary.
    Changed,
    /// Nothing stored yet; the next save records the running binary.
    Unrecorded,
    /// The running binary could not be read, so no comparison is possible.
    Unavailable,
}

impl BinaryStatus {
    pub fn as_token(self) -> &'static str {
        match self {
            BinaryStatus::Same => "ok",
            BinaryStatus::Changed => "changed",
            BinaryStatus::Unrecorded => "unrecorded",
            BinaryStatus::Unavailable => "unavailable",
        }
    }
}

/// SHA-256 of a file, refusing anything that is not a regular file or is
/// above the size cap.
pub fn file_digest(path: &Path) -> Option<[u8; 32]> {
    let mut file = File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_BINARY_BYTES {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_BINARY_BYTES {
            return None;
        }
        hasher.update(&buf[..n]);
    }
    Some(hasher.finalize().into())
}

fn hash_running_binary() -> Option<[u8; 32]> {
    // /proc/self/exe is the file actually mapped, even if the path on disk
    // was replaced after start.
    #[cfg(target_os = "linux")]
    if let Some(d) = file_digest(Path::new("/proc/self/exe")) {
        return Some(d);
    }
    let exe = std::env::current_exe().ok()?;
    file_digest(&exe)
}

/// Digest of the running executable, computed once per process. Call it early
/// so the hash reflects the binary as started.
pub fn running_binary_digest() -> Option<[u8; 32]> {
    *RUNNING_DIGEST.get_or_init(hash_running_binary)
}

/// Compare the digest stored in the profile with the running binary.
pub fn binary_status(stored: &[u8; 32], running: Option<&[u8; 32]>) -> BinaryStatus {
    match running {
        None => BinaryStatus::Unavailable,
        Some(_) if *stored == NO_BINARY_DIGEST => BinaryStatus::Unrecorded,
        Some(cur) if cur == stored => BinaryStatus::Same,
        Some(_) => BinaryStatus::Changed,
    }
}

/// Lowercase hex, for comparing with a published checksum.
pub fn digest_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn status_covers_each_case() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(binary_status(&a, Some(&a)), BinaryStatus::Same);
        assert_eq!(binary_status(&a, Some(&b)), BinaryStatus::Changed);
        assert_eq!(
            binary_status(&NO_BINARY_DIGEST, Some(&a)),
            BinaryStatus::Unrecorded
        );
        assert_eq!(binary_status(&a, None), BinaryStatus::Unavailable);
        assert_eq!(
            binary_status(&NO_BINARY_DIGEST, None),
            BinaryStatus::Unavailable
        );
    }

    #[test]
    fn file_digest_matches_known_sha256() {
        let dir = std::env::temp_dir().join(format!("hc_bin_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("abc");
        File::create(&path).unwrap().write_all(b"abc").unwrap();
        let d = file_digest(&path).unwrap();
        assert_eq!(
            digest_hex(&d),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(file_digest(&dir).is_none(), "directories are not hashed");
        assert!(file_digest(&dir.join("missing")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn running_binary_is_hashed_and_stable() {
        let first = running_binary_digest().expect("test binary is readable");
        assert_ne!(first, NO_BINARY_DIGEST);
        assert_eq!(running_binary_digest(), Some(first));
    }
}
