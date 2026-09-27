//! Owner-only file helpers for at-rest state (`hashchat_data/`).
//!
//! Policy (Unix):
//! - The state directory must be a real directory (not a symlink) owned by the
//!   effective uid. Group/other permission bits on it are cleared to 0700 via
//!   `fchmod` on an `O_NOFOLLOW` handle. Older installs created it 0755 under the
//!   default umask; the files inside were already 0600, so tightening in place is
//!   safe and keeps upgrades working.
//! - State files are opened with `O_NOFOLLOW | O_NONBLOCK` and validated on the
//!   open descriptor (`fstat`): regular file, owned by the effective uid, no
//!   group/other bits, below a size cap. A loose file is **refused**, not
//!   silently fixed: it may already have been read, and the user should know.
//!   `O_NONBLOCK` keeps a planted FIFO from blocking the open.
//! - Writes go to a fresh `O_EXCL` temp file in the same directory (mode 0600,
//!   re-applied with `fchmod` so an unusual umask cannot leave it unreadable),
//!   are `fsync`ed, then `rename`d over the target, followed by a best-effort
//!   directory `fsync`. A crash leaves either the old or the new file, never a
//!   truncated one, and an existing loose-mode file is replaced rather than
//!   rewritten in place with its old mode.
//!
//! Residual risk (documented): only the final directory component is checked.
//! Parent components may legitimately be symlinks (e.g. `/home -> /var/home`).
//! An attacker who can rename entries in the *parent* of the data directory
//! between our check and our open can still race us; that attacker already
//! controls the user's working tree. Root is out of scope.
//!
//! Error strings never contain paths, file contents, or key material.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Upper bound for any single state file we will read or write (256 MiB).
/// Prevents a planted huge file from exhausting memory at unlock.
pub const MAX_PRIVATE_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Temp-file infix used by atomic writes; [`remove_stale_temps`] sweeps it.
const TMP_INFIX: &str = ".tmp-";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateFsError {
    NotFound,
    Symlink,
    NotRegular,
    NotDirectory,
    WrongOwner,
    TooPermissive,
    TooLarge,
    BadName,
    Io,
}

impl PrivateFsError {
    pub fn as_str(self) -> &'static str {
        match self {
            PrivateFsError::NotFound => "state file missing",
            PrivateFsError::Symlink => "state path is a symlink (refused)",
            PrivateFsError::NotRegular => "state path is not a regular file (refused)",
            PrivateFsError::NotDirectory => "state dir is not a directory (refused)",
            PrivateFsError::WrongOwner => "state path not owned by current user (refused)",
            PrivateFsError::TooPermissive => {
                "state file accessible by group/other (refused; chmod 600)"
            }
            PrivateFsError::TooLarge => "state file exceeds size cap (refused)",
            PrivateFsError::BadName => "invalid state file name",
            PrivateFsError::Io => "state file I/O error",
        }
    }
}

fn validate_name(name: &str) -> Result<(), PrivateFsError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(PrivateFsError::BadName);
    }
    Ok(())
}

fn map_open_err(e: &io::Error) -> PrivateFsError {
    if e.kind() == io::ErrorKind::NotFound {
        return PrivateFsError::NotFound;
    }
    #[cfg(unix)]
    {
        match e.raw_os_error() {
            Some(libc::ELOOP) => return PrivateFsError::Symlink,
            Some(libc::ENOTDIR) => return PrivateFsError::NotDirectory,
            _ => {}
        }
    }
    PrivateFsError::Io
}

#[cfg(unix)]
fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Open `dir` without following a final-component symlink, verify ownership, and
/// clear group/other bits. Returns the directory handle (used for `fsync`).
#[cfg(unix)]
fn open_private_dir(dir: &Path, create: bool) -> Result<fs::File, PrivateFsError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    if create {
        match fs::symlink_metadata(dir) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)
                    .map_err(|_| PrivateFsError::Io)?;
            }
            Err(_) => return Err(PrivateFsError::Io),
        }
    }

    let d = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)
        .map_err(|e| {
            // With O_DIRECTORY, Linux reports a final-component symlink as ENOTDIR
            // rather than ELOOP; disambiguate with lstat for a clear refusal.
            match fs::symlink_metadata(dir) {
                Ok(m) if m.file_type().is_symlink() => PrivateFsError::Symlink,
                _ => map_open_err(&e),
            }
        })?;
    let md = d.metadata().map_err(|_| PrivateFsError::Io)?;
    if !md.is_dir() {
        return Err(PrivateFsError::NotDirectory);
    }
    if md.uid() != euid() {
        return Err(PrivateFsError::WrongOwner);
    }
    if md.mode() & 0o077 != 0 {
        d.set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|_| PrivateFsError::Io)?;
    }
    Ok(d)
}

#[cfg(not(unix))]
fn open_private_dir(dir: &Path, create: bool) -> Result<(), PrivateFsError> {
    let md = match fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
            fs::create_dir_all(dir).map_err(|_| PrivateFsError::Io)?;
            fs::symlink_metadata(dir).map_err(|_| PrivateFsError::Io)?
        }
        Err(e) => return Err(map_open_err(&e)),
    };
    if md.file_type().is_symlink() {
        return Err(PrivateFsError::Symlink);
    }
    if !md.is_dir() {
        return Err(PrivateFsError::NotDirectory);
    }
    Ok(())
}

/// Create (if needed) and harden the state directory. See module docs.
pub fn ensure_private_dir(dir: &Path) -> Result<(), PrivateFsError> {
    open_private_dir(dir, true).map(|_| ())
}

/// Open `dir/name` read-only and validate it on the descriptor.
#[cfg(unix)]
fn open_checked(dir: &Path, name: &str, max_len: u64) -> Result<(fs::File, u64), PrivateFsError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    validate_name(name)?;
    open_private_dir(dir, false)?;
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(dir.join(name))
        .map_err(|e| map_open_err(&e))?;
    let md = f.metadata().map_err(|_| PrivateFsError::Io)?;
    if !md.is_file() {
        return Err(PrivateFsError::NotRegular);
    }
    if md.uid() != euid() {
        return Err(PrivateFsError::WrongOwner);
    }
    if md.mode() & 0o077 != 0 {
        return Err(PrivateFsError::TooPermissive);
    }
    if md.len() > max_len {
        return Err(PrivateFsError::TooLarge);
    }
    Ok((f, md.len()))
}

#[cfg(not(unix))]
fn open_checked(dir: &Path, name: &str, max_len: u64) -> Result<(fs::File, u64), PrivateFsError> {
    validate_name(name)?;
    open_private_dir(dir, false)?;
    let p = dir.join(name);
    let lmd = fs::symlink_metadata(&p).map_err(|e| map_open_err(&e))?;
    if lmd.file_type().is_symlink() {
        return Err(PrivateFsError::Symlink);
    }
    if !lmd.is_file() {
        return Err(PrivateFsError::NotRegular);
    }
    let f = fs::File::open(&p).map_err(|e| map_open_err(&e))?;
    let len = f.metadata().map_err(|_| PrivateFsError::Io)?.len();
    if len > max_len {
        return Err(PrivateFsError::TooLarge);
    }
    Ok((f, len))
}

/// Validate `dir` and, if present, `dir/name` without reading contents.
/// A missing directory or file is `Ok(())` (nothing to refuse yet).
pub fn check_private_file(dir: &Path, name: &str) -> Result<(), PrivateFsError> {
    match open_checked(dir, name, MAX_PRIVATE_FILE_BYTES) {
        Ok(_) | Err(PrivateFsError::NotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Read `dir/name` after the ownership / mode / type / size checks.
pub fn read_private_file(dir: &Path, name: &str, max_len: u64) -> Result<Vec<u8>, PrivateFsError> {
    let max_len = max_len.min(MAX_PRIVATE_FILE_BYTES);
    let (f, len) = open_checked(dir, name, max_len)?;
    let mut buf = Vec::with_capacity(len as usize);
    // Bound the read even if the file grows after fstat.
    let res = f.take(max_len + 1).read_to_end(&mut buf);
    if res.is_err() {
        buf.zeroize();
        return Err(PrivateFsError::Io);
    }
    if buf.len() as u64 > max_len {
        buf.zeroize();
        return Err(PrivateFsError::TooLarge);
    }
    Ok(buf)
}

fn random_suffix() -> Result<String, PrivateFsError> {
    let mut r = [0u8; 8];
    getrandom::getrandom(&mut r).map_err(|_| PrivateFsError::Io)?;
    Ok(r.iter().map(|b| format!("{b:02x}")).collect())
}

fn tmp_path(dir: &Path, name: &str) -> Result<PathBuf, PrivateFsError> {
    Ok(dir.join(format!(".{name}{TMP_INFIX}{}", random_suffix()?)))
}

/// Atomically replace `dir/name` with `data` (owner-only). See module docs.
pub fn write_private_file(dir: &Path, name: &str, data: &[u8]) -> Result<(), PrivateFsError> {
    validate_name(name)?;
    if data.len() as u64 > MAX_PRIVATE_FILE_BYTES {
        return Err(PrivateFsError::TooLarge);
    }
    #[allow(clippy::let_unit_value)]
    let dir_handle = open_private_dir(dir, true)?;
    let target = dir.join(name);

    // Never replace something that is not a plain file (symlink, dir, FIFO, ...).
    match fs::symlink_metadata(&target) {
        Ok(md) if md.file_type().is_symlink() => return Err(PrivateFsError::Symlink),
        Ok(md) if !md.is_file() => return Err(PrivateFsError::NotRegular),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(PrivateFsError::Io),
    }

    let tmp = tmp_path(dir, name)?;
    let result = (|| -> Result<(), PrivateFsError> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut f = opts.open(&tmp).map_err(|e| map_open_err(&e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| PrivateFsError::Io)?;
        }
        f.write_all(data).map_err(|_| PrivateFsError::Io)?;
        f.sync_all().map_err(|_| PrivateFsError::Io)?;
        drop(f);
        fs::rename(&tmp, &target).map_err(|_| PrivateFsError::Io)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        return result;
    }
    // Persist the rename. Some filesystems reject directory fsync; not fatal.
    #[cfg(unix)]
    {
        let _ = dir_handle.sync_all();
    }
    #[cfg(not(unix))]
    {
        let _ = dir_handle;
    }
    Ok(())
}

/// Best-effort removal of leftover `.{name}.tmp-*` files (e.g. after a crash
/// mid-write). Only names we generate are touched; symlinks are unlinked, not followed.
pub fn remove_stale_temps(dir: &Path, name: &str) {
    if validate_name(name).is_err() {
        return;
    }
    let prefix = format!(".{name}{TMP_INFIX}");
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for ent in rd.flatten() {
        let fname = ent.file_name();
        let Some(s) = fname.to_str() else {
            continue;
        };
        if !s.starts_with(&prefix) {
            continue;
        }
        if let Ok(ft) = ent.file_type() {
            if ft.is_dir() {
                continue;
            }
        }
        let _ = fs::remove_file(ent.path());
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root(tag: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("hashchat-pfs-{tag}-{n}"));
        let _ = fs::remove_dir_all(&p);
        p
    }

    fn mode_of(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().mode() & 0o7777
    }

    #[test]
    fn write_creates_owner_only_dir_and_file() {
        let root = tmp_root("create");
        let dir = root.join("nested").join("data");
        write_private_file(&dir, "state.enc", b"abc").unwrap();
        assert_eq!(mode_of(&dir), 0o700);
        assert_eq!(mode_of(&dir.join("state.enc")), 0o600);
        assert_eq!(read_private_file(&dir, "state.enc", 1024).unwrap(), b"abc");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn loose_dir_is_tightened() {
        let dir = tmp_root("loosedir");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&dir).unwrap();
        assert_eq!(mode_of(&dir), 0o700);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn group_or_world_accessible_file_is_refused_on_read() {
        let dir = tmp_root("loosefile");
        write_private_file(&dir, "state.enc", b"x").unwrap();
        for m in [0o644, 0o640, 0o604, 0o620, 0o602] {
            fs::set_permissions(dir.join("state.enc"), fs::Permissions::from_mode(m)).unwrap();
            assert_eq!(
                read_private_file(&dir, "state.enc", 1024).unwrap_err(),
                PrivateFsError::TooPermissive,
                "mode {m:o}"
            );
            assert_eq!(
                check_private_file(&dir, "state.enc").unwrap_err(),
                PrivateFsError::TooPermissive
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rewrite_replaces_loose_file_with_0600() {
        let dir = tmp_root("rewrite");
        write_private_file(&dir, "state.enc", b"old").unwrap();
        fs::set_permissions(dir.join("state.enc"), fs::Permissions::from_mode(0o644)).unwrap();
        write_private_file(&dir, "state.enc", b"new").unwrap();
        assert_eq!(mode_of(&dir.join("state.enc")), 0o600);
        assert_eq!(read_private_file(&dir, "state.enc", 1024).unwrap(), b"new");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlinked_state_file_is_refused_for_read_and_write() {
        let dir = tmp_root("symfile");
        ensure_private_dir(&dir).unwrap();
        let outside = tmp_root("symfile-target");
        write_private_file(&outside, "real", b"secret-ish").unwrap();
        std::os::unix::fs::symlink(outside.join("real"), dir.join("state.enc")).unwrap();

        assert_eq!(
            read_private_file(&dir, "state.enc", 1024).unwrap_err(),
            PrivateFsError::Symlink
        );
        assert_eq!(
            check_private_file(&dir, "state.enc").unwrap_err(),
            PrivateFsError::Symlink
        );
        assert_eq!(
            write_private_file(&dir, "state.enc", b"overwrite").unwrap_err(),
            PrivateFsError::Symlink
        );
        // Target untouched, link still a link.
        assert_eq!(
            read_private_file(&outside, "real", 1024).unwrap(),
            b"secret-ish"
        );
        assert!(fs::symlink_metadata(dir.join("state.enc"))
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn dangling_symlink_is_not_written_through() {
        let dir = tmp_root("dangling");
        ensure_private_dir(&dir).unwrap();
        let outside = tmp_root("dangling-target");
        std::os::unix::fs::symlink(outside.join("planted"), dir.join("state.enc")).unwrap();
        assert_eq!(
            write_private_file(&dir, "state.enc", b"data").unwrap_err(),
            PrivateFsError::Symlink
        );
        assert!(!outside.join("planted").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlinked_state_dir_is_refused() {
        let real = tmp_root("realdir");
        ensure_private_dir(&real).unwrap();
        write_private_file(&real, "state.enc", b"x").unwrap();
        let link = tmp_root("linkdir");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(
            read_private_file(&link, "state.enc", 1024).unwrap_err(),
            PrivateFsError::Symlink
        );
        assert_eq!(
            write_private_file(&link, "state.enc", b"y").unwrap_err(),
            PrivateFsError::Symlink
        );
        assert_eq!(
            ensure_private_dir(&link).unwrap_err(),
            PrivateFsError::Symlink
        );
        assert_eq!(read_private_file(&real, "state.enc", 1024).unwrap(), b"x");
        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&real);
    }

    #[test]
    fn non_regular_targets_are_refused() {
        let dir = tmp_root("nonreg");
        ensure_private_dir(&dir).unwrap();
        fs::create_dir(dir.join("state.enc")).unwrap();
        assert_eq!(
            read_private_file(&dir, "state.enc", 1024).unwrap_err(),
            PrivateFsError::NotRegular
        );
        assert_eq!(
            write_private_file(&dir, "state.enc", b"x").unwrap_err(),
            PrivateFsError::NotRegular
        );
        fs::remove_dir(dir.join("state.enc")).unwrap();

        // FIFO: must not block the open, must be refused.
        let c =
            std::ffi::CString::new(dir.join("state.enc").as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: valid NUL-terminated path.
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0);
        assert_eq!(
            read_private_file(&dir, "state.enc", 1024).unwrap_err(),
            PrivateFsError::NotRegular
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn regular_file_in_place_of_dir_is_refused() {
        let root = tmp_root("filedir");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("data"), b"").unwrap();
        assert_eq!(
            ensure_private_dir(&root.join("data")).unwrap_err(),
            PrivateFsError::NotDirectory
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn size_cap_enforced() {
        let dir = tmp_root("cap");
        write_private_file(&dir, "state.enc", &[7u8; 64]).unwrap();
        assert_eq!(
            read_private_file(&dir, "state.enc", 63).unwrap_err(),
            PrivateFsError::TooLarge
        );
        assert_eq!(read_private_file(&dir, "state.enc", 64).unwrap().len(), 64);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_reports_not_found_and_check_is_ok() {
        let dir = tmp_root("missing");
        assert_eq!(check_private_file(&dir, "state.enc"), Ok(()));
        ensure_private_dir(&dir).unwrap();
        assert_eq!(
            read_private_file(&dir, "state.enc", 1024).unwrap_err(),
            PrivateFsError::NotFound
        );
        assert_eq!(check_private_file(&dir, "state.enc"), Ok(()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_names_rejected() {
        let dir = tmp_root("names");
        for n in ["", ".", "..", "a/b", "../x", "a\\b", "a\0b"] {
            assert_eq!(
                write_private_file(&dir, n, b"x").unwrap_err(),
                PrivateFsError::BadName,
                "{n:?}"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_temps_swept_and_no_temp_left_after_write() {
        let dir = tmp_root("temps");
        write_private_file(&dir, "state.enc", b"x").unwrap();
        fs::write(dir.join(".state.enc.tmp-deadbeef"), b"junk").unwrap();
        fs::write(dir.join("unrelated"), b"keep").unwrap();
        remove_stale_temps(&dir, "state.enc");
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"state.enc".to_string()));
        assert!(names.contains(&"unrelated".to_string()));
        assert!(!names.iter().any(|n| n.contains(".tmp-")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn error_strings_carry_no_path() {
        for e in [
            PrivateFsError::NotFound,
            PrivateFsError::Symlink,
            PrivateFsError::NotRegular,
            PrivateFsError::NotDirectory,
            PrivateFsError::WrongOwner,
            PrivateFsError::TooPermissive,
            PrivateFsError::TooLarge,
            PrivateFsError::BadName,
            PrivateFsError::Io,
        ] {
            let s = e.as_str();
            assert!(!s.contains("/tmp") && !s.contains("/home"), "{s}");
            assert!(!s.contains("hashchat_data") && !s.contains(".enc"), "{s}");
        }
    }
}
