//! Best-effort overwrite before unlink for the nuclear wipe.
//!
//! Each regular file is overwritten once with random bytes and synced, then
//! removed. Symlinks are unlinked, never followed. This helps on plain
//! overwrite-in-place filesystems. It does not help on SSD wear levelling,
//! copy-on-write filesystems, snapshots or journals, so the encrypted state
//! file remains the real protection; the point here is the Tor hidden service
//! key, which Tor stores unencrypted.

use std::fs;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

/// Files larger than this are only unlinked; nothing HashChat writes is near it.
const MAX_OVERWRITE_BYTES: u64 = 64 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;

/// Overwrite the contents of one regular file in place with random bytes.
pub fn overwrite_file(path: &Path) -> io::Result<()> {
    let md = fs::symlink_metadata(path)?;
    if !md.is_file() || md.len() > MAX_OVERWRITE_BYTES {
        return Ok(());
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut f = opts.open(path)?;
    f.seek(SeekFrom::Start(0))?;
    let mut left = md.len();
    let mut buf = vec![0u8; CHUNK];
    while left > 0 {
        let n = left.min(CHUNK as u64) as usize;
        getrandom::getrandom(&mut buf[..n]).map_err(|_| io::Error::other("csprng failed"))?;
        f.write_all(&buf[..n])?;
        left -= n as u64;
    }
    f.sync_all()
}

/// Overwrite and remove everything under `dir`, then `dir` itself. A missing
/// directory is fine. Errors on individual entries do not stop the sweep.
pub fn shred_dir(dir: &Path) {
    let Ok(md) = fs::symlink_metadata(dir) else {
        return;
    };
    if md.file_type().is_symlink() {
        let _ = fs::remove_file(dir);
        return;
    }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => shred_dir(&p),
                Ok(t) if t.is_file() => {
                    let _ = overwrite_file(&p);
                    let _ = fs::remove_file(&p);
                }
                _ => {
                    let _ = fs::remove_file(&p);
                }
            }
        }
    }
    let _ = fs::remove_dir(dir);
}

/// Overwrite and remove a single file; missing is fine.
pub fn shred_file(path: &Path) {
    let _ = overwrite_file(path);
    let _ = fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut b = [0u8; 6];
        getrandom::getrandom(&mut b).unwrap();
        let suffix: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("hashchat-shred-{tag}-{suffix}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn overwrite_changes_contents_and_keeps_length() {
        let dir = tmp_dir("overwrite");
        let p = dir.join("hs_ed25519_secret_key");
        let original = vec![0x5Au8; 100_000];
        fs::write(&p, &original).unwrap();
        overwrite_file(&p).unwrap();
        let after = fs::read(&p).unwrap();
        assert_eq!(after.len(), original.len());
        assert_ne!(after, original);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn shred_dir_removes_tree_and_spares_symlink_targets() {
        let root = tmp_dir("tree");
        let outside = root.join("outside.txt");
        fs::write(&outside, b"keep me").unwrap();

        let victim = root.join("victim");
        fs::create_dir_all(victim.join("nested")).unwrap();
        fs::write(victim.join("a.key"), b"secret").unwrap();
        fs::write(victim.join("nested").join("b.key"), b"secret too").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, victim.join("link")).unwrap();

        shred_dir(&victim);
        assert!(!victim.exists());
        assert_eq!(fs::read(&outside).unwrap(), b"keep me");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn shred_dir_on_missing_path_is_a_no_op() {
        let root = tmp_dir("missing");
        shred_dir(&root.join("nope"));
        shred_file(&root.join("nope.db"));
        let _ = fs::remove_dir_all(&root);
    }
}
