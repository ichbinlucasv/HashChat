#![allow(static_mut_refs)] // Intentional global store for FFI ratchet handles (safe in our single-threaded usage)

use ed25519_dalek::SigningKey;
use ring::hmac;
use std::fs;
use std::os::raw::c_void;
use std::ptr;
use subtle::ConstantTimeEq; // OPSEC: audited constant-time comparison (replaces deprecated ring internal API)
use zeroize::Zeroize;

mod contact_link;
mod disappearing;
mod emergency_scrub;
mod envelope;
mod hidden_service;
mod longterm_identity;
mod net_mode;
mod private_fs;
mod ratchet;
mod session_persist;
mod term_sanitize;
mod tor_socks;
mod unlock_backoff;
mod wire;

pub use contact_link::{
    bootstrap_ratchet_from_signed_link, canonical_payload, format_signed_contact_link,
    parse_signed_contact_link, parse_unsigned_contact_link_insecure, sas_fingerprint,
    sas_for_signed, ContactLinkError, SignedContact,
};
pub use disappearing::{
    extreme_default_lock_timeout, extreme_default_ttl, format_lock_timeout, format_ttl,
    parse_lock_timeout_token, parse_ttl_token, DEFAULT_LOCK_TIMEOUT_SECS,
    EXTREME_DEFAULT_LOCK_TIMEOUT_SECS, EXTREME_DEFAULT_TTL_SECS,
};
pub use emergency_scrub::{
    clear_scrub_callback, emergency_scrub, install_panic_scrub_hook, install_terminate_signal_flag,
    register_scrub_callback, scrub_bytes, take_terminate_signal, terminate_signal_pending,
};
pub use envelope::{
    check_new_passphrase, StoreKey, MIN_NEW_PASSPHRASE_CHARS, MIN_NEW_PASSPHRASE_CHARS_EXTREME,
};
pub use hidden_service::{
    cookie_path_from_protocolinfo, start_hidden_service_with_key, HiddenService,
    HS_INBOUND_QUEUE_CAP, MAX_HS_INBOUND_FRAME,
};
pub use longterm_identity::LongTermIdentity;
pub use longterm_identity::{
    export_encrypted as longterm_export_encrypted, import_encrypted as longterm_import_encrypted,
};
pub use net_mode::{DnsPreference, NetConfig, NetModeError, NetworkMode, PostureProfile};
pub use ratchet::{
    build_wire_aad, decrypt_with_key, encrypt_with_key, take_zeroizing_vec, DoubleRatchet,
    WIRE_VERSION_V2,
};
pub use private_fs::MAX_PRIVATE_FILE_BYTES;
pub use session_persist::{
    check_state_storage, commit_outgoing, commit_outgoing_with_key, load_disk, load_session,
    load_session_with_key, save_disk, save_session, save_session_with_key, unlock_session,
    state_exists, validate_display_name, wipe_disk, ContactUpsert, IdentityOnionState,
    InboundDenyPolicy, PersistMode, PersistedContact, SessionState, MAX_DISPLAY_NAME_LEN,
};
pub use term_sanitize::{is_terminal_safe, sanitize_for_terminal};
pub use unlock_backoff::{unlock_backoff_delay_secs, UnlockBackoffPolicy};
pub use tor_socks::{
    is_loopback_host, is_onion_destination, probe as tor_probe, read_framed_u16,
    read_framed_u16_max, socks5_connect_with_auth, socks5_send, socks_isolation_credentials,
    socks_isolation_for_contact, socks_isolation_for_onion, write_framed_u16, SocksIsolationCreds,
    TorProbe, MAX_SOCKS_FRAME,
};
pub use wire::{
    check_plaintext_send_size, frame_v2, unframe_v2, MAX_FRAMED_SEND_BYTES,
    MAX_PLAINTEXT_SEND_BYTES,
};

// long-13: gated quantum module. Only compiled with `cargo build --features quantum`.
// The module itself documents the strict constant-time / zeroize / side-channel
// requirements that any future real implementation must meet.
#[cfg(feature = "quantum")]
mod quantum;
#[cfg(feature = "quantum")]
pub use quantum::{hybrid_ratchet_new, QuantumHybridRatchet};

#[no_mangle]
pub extern "C" fn rust_init_profile() -> *mut c_void {
    let mut secret = [0u8; 32];
    if getrandom::getrandom(&mut secret).is_err() {
        // M2: never silently proceed with an all-zero profile seed
        return std::ptr::null_mut();
    }
    let _signing = SigningKey::from_bytes(&secret);
    let boxed = Box::new(secret);
    Box::into_raw(boxed) as *mut c_void
}

#[no_mangle]
pub extern "C" fn rust_secure_erase(ptr: *mut c_void) {
    unsafe {
        let mut secret: Box<[u8; 32]> = Box::from_raw(ptr as *mut [u8; 32]);
        secret.zeroize();
        drop(secret);
    }
}

#[no_mangle]
pub extern "C" fn rust_hmac_verify(msg: *const u8, len: usize) -> bool {
    let slice = unsafe { std::slice::from_raw_parts(msg, len) };
    let key = hmac::Key::new(hmac::HMAC_SHA512, b"hashchat-extra-key");
    hmac::verify(&key, slice, slice).is_ok()
}

/// Wipe local sensitive material on disk (session blob, Tor HS dir, legacy db).
///
/// Safe Rust entry used by the FFI wipe and the Rust TUI.
/// Callers holding a live [`session_persist::SessionState`] must also call
/// [`session_persist::SessionState::wipe_memory_secure`] (TUI `:wipe-confirm` does this).
///
/// Honest limits: does not defeat kernel implants, prior memory exfiltration,
/// swap/core residues, or forensic copies already taken — see THREATMODEL.md.
pub fn wipe_local_sensitive() {
    let _ = fs::remove_dir_all("tor/hidden_service");
    let _ = fs::remove_file("hashchat.db");
    // H2/H3: wipe passphrase-wrapped session blob (identity, contacts, ratchets, pending)
    let _ = session_persist::wipe_disk(std::path::Path::new("hashchat_data"));
    let _ = fs::remove_dir_all("hashchat_data");
}

#[no_mangle]
pub extern "C" fn rust_wipe_files() {
    wipe_local_sensitive();
}

#[no_mangle]
pub extern "C" fn rust_secure_random(buf: *mut u8, len: usize) -> bool {
    if buf.is_null() || len == 0 {
        return false;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    // M2: propagate CSPRNG failure; do not leave uninitialized/zero as "success"
    getrandom::getrandom(slice).is_ok()
}

#[no_mangle]
pub extern "C" fn rust_constant_time_eq(a: *const u8, b: *const u8, len: usize) -> bool {
    let a_slice = unsafe { std::slice::from_raw_parts(a, len) };
    let b_slice = unsafe { std::slice::from_raw_parts(b, len) };
    // OPSEC: Constant-time comparison using the audited subtle crate.
    // This removes dependency on ring's deprecated internal API (no side-channel guarantees).
    a_slice.ct_eq(b_slice).into()
}

#[no_mangle]
pub extern "C" fn rust_wipe_slice(ptr: *mut u8, len: usize) {
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    slice.zeroize();
    unsafe {
        ptr::write_bytes(ptr, 0, len);
    }
}

#[no_mangle]
pub extern "C" fn rust_wipe_memory(ptr: *mut u8, len: usize) {
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    slice.zeroize();
    unsafe {
        ptr::write_bytes(ptr, 0, len);
    }
}

#[no_mangle]
pub extern "C" fn rust_secure_copy(src: *const u8, dst: *mut u8, len: usize) {
    let src_slice = unsafe { std::slice::from_raw_parts(src, len) };
    let dst_slice = unsafe { std::slice::from_raw_parts_mut(dst, len) };
    dst_slice.copy_from_slice(src_slice);
}

#[no_mangle]
pub extern "C" fn rust_secure_zero(ptr: *mut u8, len: usize) {
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    slice.zeroize();
    unsafe {
        ptr::write_bytes(ptr, 0, len);
    }
}

#[no_mangle]
pub extern "C" fn rust_secure_compare(a: *const u8, b: *const u8, len: usize) -> bool {
    let a_slice = unsafe { std::slice::from_raw_parts(a, len) };
    let b_slice = unsafe { std::slice::from_raw_parts(b, len) };
    // OPSEC: Constant-time comparison using the audited subtle crate.
    // This removes dependency on ring's deprecated internal API (no side-channel guarantees).
    a_slice.ct_eq(b_slice).into()
}

// ==================== Double Ratchet FFI (for message system) ====================

static mut RATCHET_STORE: Vec<DoubleRatchet> = Vec::new();

#[no_mangle]
pub extern "C" fn rust_ratchet_new() -> u32 {
    unsafe {
        let id = RATCHET_STORE.len() as u32;
        RATCHET_STORE.push(DoubleRatchet::new());
        id
    }
}

#[no_mangle]
pub extern "C" fn rust_ratchet_init(
    state_id: u32,
    remote_pub: *const u8,
    shared_secret: *const u8,
) {
    unsafe {
        if let Some(r) = RATCHET_STORE.get_mut(state_id as usize) {
            let rp = x25519_dalek::PublicKey::from(
                *<&[u8; 32]>::try_from(std::slice::from_raw_parts(remote_pub, 32)).unwrap(),
            );
            let sh = *<&[u8; 32]>::try_from(std::slice::from_raw_parts(shared_secret, 32)).unwrap();
            r.init_from_shared(rp, &sh);
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_ratchet_send(state_id: u32, out_key: *mut u8, out_count: *mut u32) {
    unsafe {
        if let Some(r) = RATCHET_STORE.get_mut(state_id as usize) {
            let (key, count) = r.ratchet_send();
            std::ptr::copy_nonoverlapping(key.as_ptr(), out_key, 32);
            *out_count = count;
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_ratchet_recv(
    state_id: u32,
    remote_pub: *const u8,
    out_key: *mut u8,
    out_count: *mut u32,
) {
    unsafe {
        if let Some(r) = RATCHET_STORE.get_mut(state_id as usize) {
            let rp = x25519_dalek::PublicKey::from(
                *<&[u8; 32]>::try_from(std::slice::from_raw_parts(remote_pub, 32)).unwrap(),
            );
            let (key, count) = r.ratchet_recv(&rp);
            std::ptr::copy_nonoverlapping(key.as_ptr(), out_key, 32);
            *out_count = count;
        }
    }
}

/// Wipe a skipped key for disappearing message support.
/// Called when a message expires so the corresponding ratchet material is erased.
#[no_mangle]
pub extern "C" fn rust_ratchet_wipe_skipped_key(state_id: u32, msg_number: u32) {
    unsafe {
        if let Some(r) = RATCHET_STORE.get_mut(state_id as usize) {
            r.wipe_skipped_key(msg_number);
        }
    }
}

// ==================== Encrypt/Decrypt with raw ratchet key (critical for real messages) ====================

#[no_mangle]
pub extern "C" fn rust_encrypt_with_key(
    key: *const u8,
    plaintext: *const u8,
    plaintext_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> bool {
    if key.is_null() || plaintext.is_null() || out.is_null() || out_len.is_null() {
        return false;
    }
    if aad_len > 0 && aad.is_null() {
        return false;
    }
    unsafe {
        let key_arr: [u8; 32] = match std::slice::from_raw_parts(key, 32).try_into() {
            Ok(k) => k,
            Err(_) => return false,
        };
        let pt = std::slice::from_raw_parts(plaintext, plaintext_len);
        let aad_slice = if aad_len == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(aad, aad_len)
        };
        match crate::ratchet::encrypt_with_key(&key_arr, pt, aad_slice) {
            Ok(buf) => {
                // *out_len is the caller's capacity on input (as in the other FFI calls).
                if buf.len() > *out_len {
                    *out_len = buf.len();
                    return false;
                }
                std::ptr::copy_nonoverlapping(buf.as_ptr(), out, buf.len());
                *out_len = buf.len();
                true
            }
            Err(_) => false,
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_decrypt_with_key(
    key: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> bool {
    if key.is_null() || ciphertext.is_null() || out.is_null() || out_len.is_null() {
        return false;
    }
    if aad_len > 0 && aad.is_null() {
        return false;
    }
    unsafe {
        let key_arr: [u8; 32] = match std::slice::from_raw_parts(key, 32).try_into() {
            Ok(k) => k,
            Err(_) => return false,
        };
        let ct = std::slice::from_raw_parts(ciphertext, ciphertext_len);
        let aad_slice = if aad_len == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(aad, aad_len)
        };
        match crate::ratchet::decrypt_with_key(&key_arr, ct, aad_slice) {
            Ok(mut plain) => {
                // *out_len is the caller's capacity on input (as in the other FFI calls).
                if plain.len() > *out_len {
                    *out_len = plain.len();
                    plain.zeroize();
                    return false;
                }
                std::ptr::copy_nonoverlapping(plain.as_ptr(), out, plain.len());
                *out_len = plain.len();
                plain.zeroize();
                true
            }
            Err(_) => false,
        }
    }
}

/// Current ratchet ephemeral public key (32 bytes) for wire v2 sender_dh.
#[no_mangle]
pub extern "C" fn rust_ratchet_public_key(state_id: u32, out: *mut u8) -> bool {
    if out.is_null() {
        return false;
    }
    unsafe {
        if let Some(r) = RATCHET_STORE.get(state_id as usize) {
            let pk = *r.public_key().as_bytes();
            std::ptr::copy_nonoverlapping(pk.as_ptr(), out, 32);
            true
        } else {
            false
        }
    }
}

/// C1: speculative ratchet_recv + AEAD open; commits only on success.
#[no_mangle]
pub extern "C" fn rust_ratchet_recv_decrypt(
    state_id: u32,
    remote_pub: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut u8,
    out_len: *mut usize,
    out_step: *mut u32,
) -> bool {
    if remote_pub.is_null()
        || ciphertext.is_null()
        || out.is_null()
        || out_len.is_null()
        || out_step.is_null()
    {
        return false;
    }
    if aad_len > 0 && aad.is_null() {
        return false;
    }
    unsafe {
        let rp_bytes: [u8; 32] = match std::slice::from_raw_parts(remote_pub, 32).try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let rp = x25519_dalek::PublicKey::from(rp_bytes);
        let ct = std::slice::from_raw_parts(ciphertext, ciphertext_len);
        let aad_slice = if aad_len == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(aad, aad_len)
        };
        if let Some(r) = RATCHET_STORE.get_mut(state_id as usize) {
            match r.try_recv_decrypt(&rp, ct, aad_slice) {
                Ok((plain, step)) => {
                    if plain.len() > *out_len {
                        *out_len = plain.len();
                        return false;
                    }
                    std::ptr::copy_nonoverlapping(plain.as_ptr(), out, plain.len());
                    *out_len = plain.len();
                    *out_step = step;
                    true
                }
                Err(_) => false,
            }
        } else {
            false
        }
    }
}

// === Raw Ratchet State Persistence FFI (transitional / fail-closed) ===
//
// DANGER / OPSEC: `rust_ratchet_to_bytes` / `rust_ratchet_from_bytes` export and
// import **raw plaintext** Double Ratchet state. Production code (TUI, Android)
// MUST use `rust_ratchet_export_encrypted` / `rust_ratchet_import_encrypted`
// (Argon2id + AES-256-GCM). The raw path exists only for the transitional
// Haskell desktop and is refuse-by-default: both exports require the exact env
// `HASHCHAT_ALLOW_RAW_RATCHET_FFI=1` (same fail-closed pattern as
// `HASHCHAT_INSECURE_DEV_PERSIST`). Any other value, empty, or unset → return
// false without touching out buffers / the store.

/// Env that opts in to raw plaintext ratchet FFI (exact value `1` only).
const RAW_RATCHET_FFI_ENV: &str = "HASHCHAT_ALLOW_RAW_RATCHET_FFI";

/// Only the exact value `1` opts in to raw ratchet export/import.
fn raw_ratchet_ffi_allowed() -> bool {
    std::env::var_os(RAW_RATCHET_FFI_ENV).is_some_and(|v| v == "1")
}

#[no_mangle]
pub extern "C" fn rust_ratchet_to_bytes(state_id: u32, out: *mut u8, out_len: *mut usize) -> bool {
    // Fail closed: refuse without reading the store or writing out buffers.
    if !raw_ratchet_ffi_allowed() {
        return false;
    }
    unsafe {
        if let Some(r) = RATCHET_STORE.get(state_id as usize) {
            let bytes = r.to_bytes();
            if bytes.len() > *out_len {
                *out_len = bytes.len();
                return false;
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
            *out_len = bytes.len();
            true
        } else {
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_ratchet_from_bytes(state_id: u32, data: *const u8, len: usize) -> bool {
    // Fail closed: refuse without touching the store.
    if !raw_ratchet_ffi_allowed() {
        return false;
    }
    unsafe {
        let bytes = std::slice::from_raw_parts(data, len);
        match DoubleRatchet::from_bytes(bytes) {
            Ok(r) => {
                if (state_id as usize) < RATCHET_STORE.len() {
                    RATCHET_STORE[state_id as usize] = r;
                } else {
                    RATCHET_STORE.push(r);
                }
                true
            }
            Err(_) => false,
        }
    }
}

// ============================================================================
// ENCRYPTED RATCHET STATE PERSISTENCE (Argon2id + AES-256-GCM)
// This is the production path. The TUI and Android must use these, never raw to_bytes.
// ============================================================================

// Passphrase envelopes for the FFI below use crate::envelope (Argon2id +
// AES-256-GCM, OS CSPRNG salts/nonces, zeroized keys); same format as before.

#[no_mangle]
pub extern "C" fn rust_ratchet_export_encrypted(
    state_id: u32,
    passphrase: *const u8,
    pass_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> bool {
    if passphrase.is_null() || out.is_null() || out_len.is_null() || pass_len == 0 {
        return false;
    }
    unsafe {
        let Some(ratchet) = RATCHET_STORE.get(state_id as usize) else {
            return false;
        };
        let pass = std::slice::from_raw_parts(passphrase, pass_len);
        // Same envelope format as before: [version | salt | nonce | ct+tag].
        let mut plaintext = ratchet.to_bytes();
        let sealed = crate::envelope::seal(pass, &plaintext);
        plaintext.zeroize();
        let Ok(envelope) = sealed else {
            return false;
        };
        let needed = envelope.len();
        if needed > *out_len {
            *out_len = needed;
            return false;
        }
        std::ptr::copy_nonoverlapping(envelope.as_ptr(), out, needed);
        *out_len = needed;
        true
    }
}

#[no_mangle]
pub extern "C" fn rust_ratchet_import_encrypted(
    state_id: u32,
    passphrase: *const u8,
    pass_len: usize,
    data: *const u8,
    data_len: usize,
) -> bool {
    if passphrase.is_null() || data.is_null() || pass_len == 0 {
        return false;
    }
    unsafe {
        let envelope = std::slice::from_raw_parts(data, data_len);
        let pass = std::slice::from_raw_parts(passphrase, pass_len);
        let Ok(mut plain) = crate::envelope::open(pass, envelope) else {
            return false;
        };
        let restored = DoubleRatchet::from_bytes(&plain);
        plain.zeroize();
        match restored {
            Ok(r) => {
                if (state_id as usize) < RATCHET_STORE.len() {
                    RATCHET_STORE[state_id as usize] = r;
                } else {
                    RATCHET_STORE.push(r);
                }
                true
            }
            Err(_) => false,
        }
    }
}

// === Ultra Paranoid Kernel-Level Security Primitives ===
//
// Safe Rust wrappers for the desktop/TUI path. FFI below delegates to these.
// Android keeps its own weaker best-effort stub in `android/src/main/rust`
// (no reliable MCL_CURRENT|MCL_FUTURE for unprivileged apps) — do not weaken
// or replace that path from here.
//
// Honesty: mlock/mlockall are best-effort. Unprivileged users often lack
// RLIMIT_MEMLOCK / CAP_IPC_LOCK; failure must never abort a session.
// Tails/Qubes (RAM-backed / disposable) remain stronger than desktop mlock.
// Per-buffer mlock on a `String`/`Vec` is imperfect if the allocation later
// reallocates — prefer mlockall(MCL_FUTURE) when it succeeds, and always
// zeroize on wipe (munlock is unnecessary).

/// Best-effort `mlockall(MCL_CURRENT | MCL_FUTURE)` (Linux only).
///
/// Returns `true` on success. Never panics. Non-Linux returns `false`.
/// Callers (TUI) must treat `false` as non-fatal.
pub fn mlockall_current() -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: mlockall with MCL_CURRENT|MCL_FUTURE is a process-wide hint;
        // errno on failure is ignored — caller gets `false`.
        unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Best-effort `mlock` on a contiguous byte slice (Linux only).
///
/// Returns `true` on success (empty slices succeed). Never panics.
///
/// **Imperfection:** if `buf` is backed by a growable `String`/`Vec` that later
/// reallocates, only the old pages stay locked. Prefer calling after the buffer
/// is finalized for the session, and/or rely on [`mlockall_current`] with
/// `MCL_FUTURE` when available.
pub fn mlock_bytes(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `buf` is a valid Rust slice for `buf.len()` bytes.
        unsafe { libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len()) == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Append `ch` to a secret `String` without letting it reallocate beyond `cap`
/// bytes. A reallocation would free the old buffer with the secret prefix still
/// in it. If `buf` has less than `cap` capacity it is moved once into a
/// `cap`-sized allocation and the old buffer is zeroized. Returns `false` (buffer
/// unchanged) if `ch` does not fit.
pub fn push_char_no_realloc(buf: &mut String, ch: char, cap: usize) -> bool {
    if buf.capacity() < cap {
        if buf.len() + ch.len_utf8() > cap {
            return false;
        }
        let mut bigger = String::with_capacity(cap);
        bigger.push_str(buf);
        buf.zeroize();
        *buf = bigger;
    }
    if buf.len() + ch.len_utf8() > buf.capacity() {
        return false;
    }
    buf.push(ch);
    true
}

/// Outcome of [`disable_core_dumps_best_effort`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DumpHardening {
    /// `RLIMIT_CORE` set to 0 (soft and hard).
    pub core_limit_zero: bool,
    /// `PR_SET_DUMPABLE` cleared: no core file even via a core pipe handler, and
    /// same-uid ptrace / `/proc/<pid>/mem` access is refused (root excepted).
    pub non_dumpable: bool,
}

impl DumpHardening {
    pub fn all(self) -> bool {
        self.core_limit_zero && self.non_dumpable
    }
}

/// Best-effort: keep secrets out of core files and away from same-uid debuggers.
///
/// Linux only; other targets return both flags `false`. Never panics; callers
/// treat failure as non-fatal and may surface it as a posture note.
pub fn disable_core_dumps_best_effort() -> DumpHardening {
    #[cfg(target_os = "linux")]
    {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: plain syscalls with valid arguments; no memory is shared.
        let core_limit_zero = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) == 0 };
        let non_dumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 };
        DumpHardening {
            core_limit_zero,
            non_dumpable,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        DumpHardening {
            core_limit_zero: false,
            non_dumpable: false,
        }
    }
}

/// FFI: lock all current and future memory (delegates to [`mlockall_current`]).
#[no_mangle]
pub extern "C" fn rust_mlockall_current() -> bool {
    mlockall_current()
}

/// FFI: lock a specific allocation (delegates to [`mlock_bytes`]).
///
/// Null + non-zero len → `false`. Empty len → `true`.
#[no_mangle]
pub extern "C" fn rust_mlock(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if ptr.is_null() {
        return false;
    }
    // SAFETY: caller guarantees `ptr` is valid for `len` bytes (FFI contract).
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    mlock_bytes(slice)
}

// Aggressive zero + drop hint
#[no_mangle]
pub extern "C" fn rust_madvise_dontneed(ptr: *mut u8, len: usize) {
    unsafe {
        #[cfg(target_os = "linux")]
        {
            libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTNEED);
        }
        std::ptr::write_bytes(ptr, 0, len);
    }
}

// Basic seccomp skeleton (Linux only).
// For a real production filter, add `seccomp = "0.6"` (or libseccomp-sys) to Cargo.toml and use:
//   use seccomp::{SeccompFilter, SeccompAction, SeccompCmpOp, SeccompCondition};
// Then build an allow-list (open/read/write/close/poll, mprotect for allocator, etc. but deny execve, ptrace, etc.).
// Example skeleton (compile-gated):
//
// #[cfg(feature = "seccomp")]
// fn real_seccomp() -> bool {
//     // deny exec, fork in most cases, etc.
//     true
// }
//
// For now we keep a strong mlockall + documentation-first approach (Tails/Qubes already apply heavy filters).
#[no_mangle]
pub extern "C" fn rust_apply_basic_seccomp() -> bool {
    #[cfg(target_os = "linux")]
    {
        // No filter is installed yet, so report that honestly; callers must
        // not treat this as "sandboxed". Use systemd SystemCallFilter etc.
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

// Attempt to mlock the current sensitive ratchet heap allocations (best-effort).
// Called after ratchet creation/import so the DoubleRatchet Vec data stays out of swap.
#[no_mangle]
pub extern "C" fn rust_mlock_sensitive_ratchets() -> bool {
    // Extra belt-and-suspenders for the global ratchet store; same best-effort
    // semantics as mlockall_current (non-fatal on failure / non-Linux).
    mlockall_current()
}

// === Dedicated Passphrase-based Blob Encryption (for message logs, etc.) ===
// This is cleaner than reusing ratchet IDs for non-ratchet data.

#[no_mangle]
pub extern "C" fn rust_encrypt_blob_with_passphrase(
    passphrase: *const u8,
    pass_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> bool {
    if passphrase.is_null() || out.is_null() || out_len.is_null() || pass_len == 0 {
        return false; // H2: refuse empty passphrase on secure blob path
    }
    if data.is_null() && data_len > 0 {
        return false;
    }
    unsafe {
        let pass = std::slice::from_raw_parts(passphrase, pass_len);
        let plaintext = if data_len == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(data, data_len)
        };
        let Ok(envelope) = crate::envelope::seal(pass, plaintext) else {
            return false;
        };
        if envelope.len() > *out_len {
            *out_len = envelope.len();
            return false;
        }
        std::ptr::copy_nonoverlapping(envelope.as_ptr(), out, envelope.len());
        *out_len = envelope.len();
        true
    }
}

#[no_mangle]
pub extern "C" fn rust_decrypt_blob_with_passphrase(
    passphrase: *const u8,
    pass_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> bool {
    if passphrase.is_null() || data.is_null() || out.is_null() || out_len.is_null() || pass_len == 0
    {
        return false; // H2: refuse empty passphrase on secure blob path
    }
    unsafe {
        let envelope = std::slice::from_raw_parts(data, data_len);
        let pass = std::slice::from_raw_parts(passphrase, pass_len);
        let Ok(mut plain) = crate::envelope::open(pass, envelope) else {
            return false;
        };
        if plain.len() > *out_len {
            *out_len = plain.len();
            plain.zeroize();
            return false;
        }
        std::ptr::copy_nonoverlapping(plain.as_ptr(), out, plain.len());
        *out_len = plain.len();
        plain.zeroize();
        true
    }
}

// =============================================================================
// H1: Signed contact-link FFI (Haskell / TUI)
// =============================================================================

use std::ffi::CStr;
use std::os::raw::c_char;

/// Generate a fresh long-term identity seed into `out_seed` (32 bytes).
#[no_mangle]
pub extern "C" fn rust_longterm_generate(out_seed: *mut u8) -> bool {
    if out_seed.is_null() {
        return false;
    }
    match LongTermIdentity::generate() {
        Ok(id) => {
            let seed = id.seed_bytes();
            unsafe {
                std::ptr::copy_nonoverlapping(seed.as_ptr(), out_seed, 32);
            }
            true
        }
        Err(_) => false,
    }
}

/// Create a signed contact link.
/// `out` receives UTF-8 bytes (NOT NUL-terminated length in out_len); caller provides capacity via *out_len.
/// Returns false if buffer too small (then *out_len = needed) or on error.
#[no_mangle]
pub extern "C" fn rust_contact_link_sign(
    seed: *const u8,
    onion: *const c_char,
    out: *mut u8,
    out_len: *mut usize,
) -> bool {
    if seed.is_null() || onion.is_null() || out_len.is_null() {
        return false;
    }
    let seed_arr: [u8; 32] = unsafe {
        match std::slice::from_raw_parts(seed, 32).try_into() {
            Ok(a) => a,
            Err(_) => return false,
        }
    };
    let onion_str = unsafe {
        match CStr::from_ptr(onion).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    let id = LongTermIdentity::from_seed(seed_arr);
    let link = match format_signed_contact_link(&id, onion_str) {
        Ok(l) => l,
        Err(_) => return false,
    };
    let bytes = link.as_bytes();
    unsafe {
        if out.is_null() || *out_len < bytes.len() {
            *out_len = bytes.len();
            return false;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
        *out_len = bytes.len();
    }
    true
}

/// Verify + parse signed link. Writes onion CString to out_onion (capacity *onion_len),
/// x25519 (32), ed25519 (32), sas CString to out_sas (capacity *sas_len).
#[no_mangle]
pub extern "C" fn rust_contact_link_verify(
    link: *const c_char,
    out_onion: *mut u8,
    onion_len: *mut usize,
    out_x25519: *mut u8,
    out_ed25519: *mut u8,
    out_sas: *mut u8,
    sas_len: *mut usize,
) -> bool {
    if link.is_null() || onion_len.is_null() || sas_len.is_null() {
        return false;
    }
    if out_x25519.is_null() || out_ed25519.is_null() {
        return false;
    }
    let link_str = unsafe {
        match CStr::from_ptr(link).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    let parsed = match parse_signed_contact_link(link_str) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sas = sas_for_signed(&parsed);
    let onion_bytes = parsed.onion.as_bytes();
    let sas_bytes = sas.as_bytes();
    unsafe {
        if out_onion.is_null() || *onion_len < onion_bytes.len() + 1 {
            *onion_len = onion_bytes.len() + 1;
            return false;
        }
        if out_sas.is_null() || *sas_len < sas_bytes.len() + 1 {
            *sas_len = sas_bytes.len() + 1;
            return false;
        }
        std::ptr::copy_nonoverlapping(onion_bytes.as_ptr(), out_onion, onion_bytes.len());
        *out_onion.add(onion_bytes.len()) = 0;
        *onion_len = onion_bytes.len();
        std::ptr::copy_nonoverlapping(parsed.x25519.as_ptr(), out_x25519, 32);
        std::ptr::copy_nonoverlapping(parsed.ed25519.as_ptr(), out_ed25519, 32);
        std::ptr::copy_nonoverlapping(sas_bytes.as_ptr(), out_sas, sas_bytes.len());
        *out_sas.add(sas_bytes.len()) = 0;
        *sas_len = sas_bytes.len();
    }
    true
}

/// Verify signed link, static-DH with local seed, init_symmetric on ratchet `state_id`.
/// Writes SAS string to out_sas. Returns false on any verify/DH failure (ratchet untouched).
#[no_mangle]
pub extern "C" fn rust_contact_bootstrap(
    state_id: u32,
    local_seed: *const u8,
    link: *const c_char,
    out_sas: *mut u8,
    sas_len: *mut usize,
) -> bool {
    if local_seed.is_null() || link.is_null() || sas_len.is_null() {
        return false;
    }
    let seed_arr: [u8; 32] = unsafe {
        match std::slice::from_raw_parts(local_seed, 32).try_into() {
            Ok(a) => a,
            Err(_) => return false,
        }
    };
    let link_str = unsafe {
        match CStr::from_ptr(link).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    let local = LongTermIdentity::from_seed(seed_arr);
    let (ratchet, sas) = match bootstrap_ratchet_from_signed_link(&local, link_str) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sas_bytes = sas.as_bytes();
    unsafe {
        if out_sas.is_null() || *sas_len < sas_bytes.len() + 1 {
            *sas_len = sas_bytes.len() + 1;
            return false;
        }
        // Only commit ratchet after verify+DH succeeded
        if (state_id as usize) < RATCHET_STORE.len() {
            RATCHET_STORE[state_id as usize] = ratchet;
        } else if (state_id as usize) == RATCHET_STORE.len() {
            RATCHET_STORE.push(ratchet);
        } else {
            return false;
        }
        std::ptr::copy_nonoverlapping(sas_bytes.as_ptr(), out_sas, sas_bytes.len());
        *out_sas.add(sas_bytes.len()) = 0;
        *sas_len = sas_bytes.len();
    }
    true
}

/// SAS for identity material already verified/stored (ed25519||x25519||onion).
#[no_mangle]
pub extern "C" fn rust_contact_sas(
    ed25519: *const u8,
    x25519: *const u8,
    onion: *const c_char,
    out_sas: *mut u8,
    sas_len: *mut usize,
) -> bool {
    if ed25519.is_null() || x25519.is_null() || onion.is_null() || sas_len.is_null() {
        return false;
    }
    let ed: [u8; 32] = unsafe {
        match std::slice::from_raw_parts(ed25519, 32).try_into() {
            Ok(a) => a,
            Err(_) => return false,
        }
    };
    let x: [u8; 32] = unsafe {
        match std::slice::from_raw_parts(x25519, 32).try_into() {
            Ok(a) => a,
            Err(_) => return false,
        }
    };
    let onion_str = unsafe {
        match CStr::from_ptr(onion).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    let sas = sas_fingerprint(&ed, &x, onion_str);
    let sas_bytes = sas.as_bytes();
    unsafe {
        if out_sas.is_null() || *sas_len < sas_bytes.len() + 1 {
            *sas_len = sas_bytes.len() + 1;
            return false;
        }
        std::ptr::copy_nonoverlapping(sas_bytes.as_ptr(), out_sas, sas_bytes.len());
        *out_sas.add(sas_bytes.len()) = 0;
        *sas_len = sas_bytes.len();
    }
    true
}

// =============================================================================
// H2: Passphrase-wrapped identity + onion at-rest persistence FFI
// =============================================================================

use std::path::Path;

/// Export long-term identity seed under Argon2id passphrase envelope.
#[no_mangle]
pub extern "C" fn rust_longterm_export_encrypted(
    seed: *const u8,
    passphrase: *const u8,
    pass_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> bool {
    if seed.is_null() || passphrase.is_null() || out_len.is_null() {
        return false;
    }
    unsafe {
        let seed_arr: [u8; 32] = match std::slice::from_raw_parts(seed, 32).try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let pass = std::slice::from_raw_parts(passphrase, pass_len);
        let id = LongTermIdentity::from_seed(seed_arr);
        match longterm_export_encrypted(&id, pass) {
            Ok(blob) => {
                if out.is_null() || *out_len < blob.len() {
                    *out_len = blob.len();
                    return false;
                }
                std::ptr::copy_nonoverlapping(blob.as_ptr(), out, blob.len());
                *out_len = blob.len();
                true
            }
            Err(_) => false,
        }
    }
}

/// Import long-term identity from Argon2id envelope into out_seed (32 bytes).
#[no_mangle]
pub extern "C" fn rust_longterm_import_encrypted(
    passphrase: *const u8,
    pass_len: usize,
    data: *const u8,
    data_len: usize,
    out_seed: *mut u8,
) -> bool {
    if passphrase.is_null() || data.is_null() || out_seed.is_null() {
        return false;
    }
    unsafe {
        let pass = std::slice::from_raw_parts(passphrase, pass_len);
        let envelope = std::slice::from_raw_parts(data, data_len);
        match longterm_import_encrypted(envelope, pass) {
            Ok(id) => {
                let seed = id.seed_bytes();
                std::ptr::copy_nonoverlapping(seed.as_ptr(), out_seed, 32);
                true
            }
            Err(_) => false,
        }
    }
}

/// Save identity+onion state under passphrase wrap (default) or insecure-dev machine.key.
/// `insecure_dev != 0` enables PersistMode::InsecureDevMachineKey.
/// `onion` / `onion_key` are length-prefixed buffers (may be empty / null if len 0).
#[no_mangle]
pub extern "C" fn rust_identity_state_save(
    data_dir: *const c_char,
    insecure_dev: u8,
    passphrase: *const u8,
    pass_len: usize,
    seed: *const u8,
    onion: *const u8,
    onion_len: usize,
    onion_key: *const u8,
    onion_key_len: usize,
) -> bool {
    if data_dir.is_null() || seed.is_null() {
        return false;
    }
    if passphrase.is_null() && pass_len != 0 {
        return false;
    }
    unsafe {
        let dir = match CStr::from_ptr(data_dir).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let pass = if pass_len == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(passphrase, pass_len)
        };
        let seed_arr: [u8; 32] = match std::slice::from_raw_parts(seed, 32).try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let onion_s = if onion_len == 0 || onion.is_null() {
            String::new()
        } else {
            match std::str::from_utf8(std::slice::from_raw_parts(onion, onion_len)) {
                Ok(s) => s.to_string(),
                Err(_) => return false,
            }
        };
        let okey = if onion_key_len == 0 || onion_key.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(onion_key, onion_key_len).to_vec()
        };
        let state = IdentityOnionState {
            seed: seed_arr,
            onion: onion_s,
            onion_key: okey,
        };
        let mode = PersistMode::from_flags(insecure_dev != 0);
        save_disk(Path::new(dir), mode, pass, &state).is_ok()
    }
}

/// Load identity+onion state. Writes seed(32), onion into out_onion (*onion_len capacity),
/// onion_key into out_onion_key (*onion_key_len capacity). Updates lengths to actual.
#[no_mangle]
pub extern "C" fn rust_identity_state_load(
    data_dir: *const c_char,
    insecure_dev: u8,
    passphrase: *const u8,
    pass_len: usize,
    out_seed: *mut u8,
    out_onion: *mut u8,
    onion_len: *mut usize,
    out_onion_key: *mut u8,
    onion_key_len: *mut usize,
) -> bool {
    if data_dir.is_null() || out_seed.is_null() || onion_len.is_null() || onion_key_len.is_null() {
        return false;
    }
    unsafe {
        let dir = match CStr::from_ptr(data_dir).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let pass = if pass_len == 0 {
            &[][..]
        } else {
            if passphrase.is_null() {
                return false;
            }
            std::slice::from_raw_parts(passphrase, pass_len)
        };
        let mode = PersistMode::from_flags(insecure_dev != 0);
        let state = match load_disk(Path::new(dir), mode, pass) {
            Ok(s) => s,
            Err(_) => return false,
        };
        std::ptr::copy_nonoverlapping(state.seed.as_ptr(), out_seed, 32);
        let ob = state.onion.as_bytes();
        if out_onion.is_null() || *onion_len < ob.len() {
            *onion_len = ob.len();
            *onion_key_len = state.onion_key.len();
            return false;
        }
        if out_onion_key.is_null() || *onion_key_len < state.onion_key.len() {
            *onion_len = ob.len();
            *onion_key_len = state.onion_key.len();
            return false;
        }
        std::ptr::copy_nonoverlapping(ob.as_ptr(), out_onion, ob.len());
        *onion_len = ob.len();
        if !state.onion_key.is_empty() {
            std::ptr::copy_nonoverlapping(
                state.onion_key.as_ptr(),
                out_onion_key,
                state.onion_key.len(),
            );
        }
        *onion_key_len = state.onion_key.len();
        true
    }
}

/// Returns true if hashchat_data/state.enc (or given dir) exists.
#[no_mangle]
pub extern "C" fn rust_identity_state_exists(data_dir: *const c_char) -> bool {
    if data_dir.is_null() {
        return false;
    }
    unsafe {
        match CStr::from_ptr(data_dir).to_str() {
            Ok(s) => state_exists(Path::new(s)),
            Err(_) => false,
        }
    }
}

// =============================================================================
// H3: Full session persist (contacts + ratchet bytes + pending) FFI
// Packed section formats match session_persist v2 blob sections (count + records).
// =============================================================================

fn pack_contacts_section(contacts: &[PersistedContact]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(contacts.len() as u32).to_be_bytes());
    for c in contacts {
        let id = c.id.as_bytes();
        out.extend_from_slice(&(id.len() as u32).to_be_bytes());
        out.extend_from_slice(id);
        let dn = c.display_name.as_bytes();
        out.extend_from_slice(&(dn.len() as u32).to_be_bytes());
        out.extend_from_slice(dn);
        let on = c.onion.as_bytes();
        out.extend_from_slice(&(on.len() as u32).to_be_bytes());
        out.extend_from_slice(on);
        out.extend_from_slice(&c.x25519);
        out.extend_from_slice(&c.ed25519);
    }
    out
}

fn unpack_contacts_section(buf: &[u8]) -> Result<Vec<PersistedContact>, &'static str> {
    if buf.len() < 4 {
        return Err("short contacts");
    }
    let n = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
    let mut pos = 4;
    // Each contact needs >= 12 length bytes + 64 key bytes; bound the prealloc.
    let mut out = Vec::with_capacity(n.min((buf.len() - 4) / 76));
    for _ in 0..n {
        let id = read_ffi_len_str(buf, &mut pos)?;
        let display_name = read_ffi_len_str(buf, &mut pos)?;
        let onion = read_ffi_len_str(buf, &mut pos)?;
        if buf.len().saturating_sub(pos) < 64 {
            return Err("short contact keys");
        }
        let mut x25519 = [0u8; 32];
        let mut ed25519 = [0u8; 32];
        x25519.copy_from_slice(&buf[pos..pos + 32]);
        pos += 32;
        ed25519.copy_from_slice(&buf[pos..pos + 32]);
        pos += 32;
        out.push(PersistedContact {
            id,
            display_name,
            onion,
            x25519,
            ed25519,
        });
    }
    Ok(out)
}

fn pack_kv_section(items: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for (k, v) in items {
        let kb = k.as_bytes();
        out.extend_from_slice(&(kb.len() as u32).to_be_bytes());
        out.extend_from_slice(kb);
        out.extend_from_slice(&(v.len() as u32).to_be_bytes());
        out.extend_from_slice(v);
    }
    out
}

fn unpack_kv_section(buf: &[u8]) -> Result<Vec<(String, Vec<u8>)>, &'static str> {
    if buf.len() < 4 {
        return Err("short kv");
    }
    let n = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
    let mut pos = 4;
    // Each entry needs >= 8 length bytes; bound the prealloc.
    let mut out = Vec::with_capacity(n.min((buf.len() - 4) / 8));
    for _ in 0..n {
        let k = read_ffi_len_str(buf, &mut pos)?;
        let v = read_ffi_len_bytes(buf, &mut pos)?;
        out.push((k, v));
    }
    Ok(out)
}

fn read_ffi_len_bytes(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>, &'static str> {
    if *pos + 4 > buf.len() {
        return Err("truncated len");
    }
    let n = u32::from_be_bytes(buf[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    let end = pos.checked_add(n).ok_or("truncated bytes")?;
    if end > buf.len() {
        return Err("truncated bytes");
    }
    let out = buf[*pos..end].to_vec();
    *pos = end;
    Ok(out)
}

fn read_ffi_len_str(buf: &[u8], pos: &mut usize) -> Result<String, &'static str> {
    let b = read_ffi_len_bytes(buf, pos)?;
    String::from_utf8(b).map_err(|_| "utf8")
}

fn copy_out(dst: *mut u8, capacity: *mut usize, src: &[u8]) -> bool {
    unsafe {
        if dst.is_null() || *capacity < src.len() {
            *capacity = src.len();
            return false;
        }
        if !src.is_empty() {
            std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        }
        *capacity = src.len();
        true
    }
}

/// Save full session (identity + contacts + ratchets + pending) into state.enc.
/// Section blobs use v2 on-disk packing (u32be count + records).
#[no_mangle]
pub extern "C" fn rust_session_state_save(
    data_dir: *const c_char,
    insecure_dev: u8,
    passphrase: *const u8,
    pass_len: usize,
    seed: *const u8,
    onion: *const u8,
    onion_len: usize,
    onion_key: *const u8,
    onion_key_len: usize,
    contacts_blob: *const u8,
    contacts_len: usize,
    ratchets_blob: *const u8,
    ratchets_len: usize,
    pending_blob: *const u8,
    pending_len: usize,
) -> bool {
    if data_dir.is_null() || seed.is_null() {
        return false;
    }
    if passphrase.is_null() && pass_len != 0 {
        return false;
    }
    unsafe {
        let dir = match CStr::from_ptr(data_dir).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let pass = if pass_len == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(passphrase, pass_len)
        };
        let seed_arr: [u8; 32] = match std::slice::from_raw_parts(seed, 32).try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let onion_s = if onion_len == 0 || onion.is_null() {
            String::new()
        } else {
            match std::str::from_utf8(std::slice::from_raw_parts(onion, onion_len)) {
                Ok(s) => s.to_string(),
                Err(_) => return false,
            }
        };
        let okey = if onion_key_len == 0 || onion_key.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(onion_key, onion_key_len).to_vec()
        };
        let cblob = if contacts_len == 0 || contacts_blob.is_null() {
            &[][..]
        } else {
            std::slice::from_raw_parts(contacts_blob, contacts_len)
        };
        let rblob = if ratchets_len == 0 || ratchets_blob.is_null() {
            &[][..]
        } else {
            std::slice::from_raw_parts(ratchets_blob, ratchets_len)
        };
        let pblob = if pending_len == 0 || pending_blob.is_null() {
            &[][..]
        } else {
            std::slice::from_raw_parts(pending_blob, pending_len)
        };
        let contacts = if cblob.is_empty() {
            Vec::new()
        } else {
            match unpack_contacts_section(cblob) {
                Ok(c) => c,
                Err(_) => return false,
            }
        };
        let ratchets = if rblob.is_empty() {
            Vec::new()
        } else {
            match unpack_kv_section(rblob) {
                Ok(r) => r,
                Err(_) => return false,
            }
        };
        let pending = if pblob.is_empty() {
            Vec::new()
        } else {
            match unpack_kv_section(pblob) {
                Ok(p) => p,
                Err(_) => return false,
            }
        };
        let state = SessionState {
            identity: IdentityOnionState {
                seed: seed_arr,
                onion: onion_s,
                onion_key: okey,
            },
            contacts,
            ratchets,
            pending,
            net: NetConfig::default(),
            disappear_ttl_secs: 0,
            blocked_ids: Vec::new(),
            muted_ids: Vec::new(),
            verified_ids: Vec::new(),
            lock_timeout_secs: crate::disappearing::DEFAULT_LOCK_TIMEOUT_SECS,
        };
        let mode = PersistMode::from_flags(insecure_dev != 0);
        save_session(Path::new(dir), mode, pass, &state).is_ok()
    }
}

/// Load full session. Writes identity fields + packed contacts/ratchets/pending sections.
/// On undersized buffers, writes required sizes into the length pointers and returns false.
#[no_mangle]
pub extern "C" fn rust_session_state_load(
    data_dir: *const c_char,
    insecure_dev: u8,
    passphrase: *const u8,
    pass_len: usize,
    out_seed: *mut u8,
    out_onion: *mut u8,
    onion_len: *mut usize,
    out_onion_key: *mut u8,
    onion_key_len: *mut usize,
    out_contacts: *mut u8,
    contacts_len: *mut usize,
    out_ratchets: *mut u8,
    ratchets_len: *mut usize,
    out_pending: *mut u8,
    pending_len: *mut usize,
) -> bool {
    if data_dir.is_null()
        || out_seed.is_null()
        || onion_len.is_null()
        || onion_key_len.is_null()
        || contacts_len.is_null()
        || ratchets_len.is_null()
        || pending_len.is_null()
    {
        return false;
    }
    unsafe {
        let dir = match CStr::from_ptr(data_dir).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let pass = if pass_len == 0 {
            &[][..]
        } else {
            if passphrase.is_null() {
                return false;
            }
            std::slice::from_raw_parts(passphrase, pass_len)
        };
        let mode = PersistMode::from_flags(insecure_dev != 0);
        let state = match load_session(Path::new(dir), mode, pass) {
            Ok(s) => s,
            Err(_) => return false,
        };
        std::ptr::copy_nonoverlapping(state.identity.seed.as_ptr(), out_seed, 32);
        let cblob = pack_contacts_section(&state.contacts);
        let rblob = pack_kv_section(&state.ratchets);
        let pblob = pack_kv_section(&state.pending);
        let onion_ok = copy_out(out_onion, onion_len, state.identity.onion.as_bytes());
        let key_ok = copy_out(out_onion_key, onion_key_len, &state.identity.onion_key);
        let contacts_ok = copy_out(out_contacts, contacts_len, &cblob);
        let ratchets_ok = copy_out(out_ratchets, ratchets_len, &rblob);
        let pending_ok = copy_out(out_pending, pending_len, &pblob);
        onion_ok && key_ok && contacts_ok && ratchets_ok && pending_ok
    }
}

/// Durable outgoing commit: upsert ratchet bytes + append pending frame, then save.
/// Prefer calling this after encrypt and before Tor send (audit H3).
#[no_mangle]
pub extern "C" fn rust_session_commit_outgoing(
    data_dir: *const c_char,
    insecure_dev: u8,
    passphrase: *const u8,
    pass_len: usize,
    contact_id: *const c_char,
    ratchet_bytes: *const u8,
    ratchet_len: usize,
    dest_onion: *const c_char,
    frame: *const u8,
    frame_len: usize,
) -> bool {
    if data_dir.is_null()
        || contact_id.is_null()
        || dest_onion.is_null()
        || ratchet_bytes.is_null()
        || frame.is_null()
    {
        return false;
    }
    if passphrase.is_null() && pass_len != 0 {
        return false;
    }
    unsafe {
        let dir = match CStr::from_ptr(data_dir).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let cid = match CStr::from_ptr(contact_id).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let onion = match CStr::from_ptr(dest_onion).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let pass = if pass_len == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(passphrase, pass_len)
        };
        let rb = std::slice::from_raw_parts(ratchet_bytes, ratchet_len).to_vec();
        let fr = std::slice::from_raw_parts(frame, frame_len).to_vec();
        let mode = PersistMode::from_flags(insecure_dev != 0);
        commit_outgoing(Path::new(dir), mode, pass, cid, rb, onion, fr).is_ok()
    }
}

#[cfg(test)]
mod memlock_tests {
    use super::{mlock_bytes, mlockall_current, rust_mlock, rust_mlockall_current};

    #[test]
    fn push_char_no_realloc_keeps_one_allocation() {
        let mut s = String::with_capacity(16);
        let ptr = s.as_ptr();
        for _ in 0..16 {
            assert!(super::push_char_no_realloc(&mut s, 'x', 16));
        }
        assert!(!super::push_char_no_realloc(&mut s, 'x', 16), "full");
        assert_eq!(s.len(), 16);
        assert_eq!(s.as_ptr(), ptr, "no reallocation");
        // Multi-byte char that does not fit is refused whole.
        let mut t = String::with_capacity(4);
        assert!(super::push_char_no_realloc(&mut t, 'a', 4));
        assert!(super::push_char_no_realloc(&mut t, 'ä', 4));
        assert!(!super::push_char_no_realloc(&mut t, '€', 4));
        assert_eq!(t, "aä");
        // Undersized buffer is moved once to full capacity.
        let mut u = String::new();
        assert!(super::push_char_no_realloc(&mut u, 'z', 64));
        assert!(u.capacity() >= 64);
        let p = u.as_ptr();
        for _ in 0..63 {
            assert!(super::push_char_no_realloc(&mut u, 'z', 64));
        }
        assert_eq!(u.as_ptr(), p);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn disable_core_dumps_sets_limit_and_flag() {
        let h = super::disable_core_dumps_best_effort();
        assert!(h.all(), "{h:?}");
        let mut lim = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: valid out-pointer.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) }, 0);
        assert_eq!((lim.rlim_cur, lim.rlim_max), (0, 0));
        // SAFETY: no arguments besides the option.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    }

    /// Smoke: wrappers return a bool and must not panic (no CAP_IPC_LOCK required).
    #[test]
    fn mlock_wrappers_return_bool_without_panic() {
        let _ = mlockall_current();
        let sample = b"hashchat-mlock-smoke";
        let _ = mlock_bytes(sample);
        let _ = mlock_bytes(&[]);
        let _ = rust_mlockall_current();
        let _ = rust_mlock(sample.as_ptr(), sample.len());
        let _ = rust_mlock(std::ptr::null(), 0);
        let _ = rust_mlock(std::ptr::null(), 1); // null+nonzero → false, no panic
    }
}

#[cfg(test)]
mod ffi_bounds_tests {
    use super::{
        rust_decrypt_blob_with_passphrase, rust_decrypt_with_key,
        rust_encrypt_blob_with_passphrase, rust_encrypt_with_key,
    };

    #[test]
    fn pack_parsers_refuse_huge_counts_without_prealloc() {
        let mut buf = u32::MAX.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0xff; 8]);
        assert!(super::unpack_kv_section(&buf).is_err());
        assert!(super::unpack_contacts_section(&buf).is_err());
        let mut pos = 0usize;
        assert!(super::read_ffi_len_bytes(&[0xff, 0xff, 0xff, 0xff, 1], &mut pos).is_err());
    }

    #[test]
    fn passphrase_blob_ffi_uses_shared_envelope() {
        let pass = b"blob pass phrase";
        let data = b"local log bytes";
        let mut out = vec![0u8; 256];
        let mut out_len = out.len();
        assert!(rust_encrypt_blob_with_passphrase(
            pass.as_ptr(),
            pass.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            &mut out_len,
        ));
        out.truncate(out_len);
        // Readable by the shared envelope module (format unchanged).
        assert_eq!(crate::envelope::open(pass, &out).unwrap(), data);

        let mut back = vec![0u8; 64];
        let mut back_len = back.len();
        assert!(rust_decrypt_blob_with_passphrase(
            pass.as_ptr(),
            pass.len(),
            out.as_ptr(),
            out.len(),
            back.as_mut_ptr(),
            &mut back_len,
        ));
        assert_eq!(&back[..back_len], data);

        // Null / empty inputs refused without touching memory.
        let mut l = 0usize;
        assert!(!rust_encrypt_blob_with_passphrase(
            std::ptr::null(),
            0,
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            &mut l,
        ));
        assert!(!rust_decrypt_blob_with_passphrase(
            pass.as_ptr(),
            pass.len(),
            std::ptr::null(),
            10,
            back.as_mut_ptr(),
            &mut back_len,
        ));
    }

    #[test]
    fn encrypt_decrypt_respect_output_capacity() {
        let key = [7u8; 32];
        let pt = [0x41u8; 100];
        let aad = b"aad";

        // Too small: refuse, report needed size, leave the buffer untouched.
        let mut small = [0xEEu8; 64];
        let mut cap = small.len();
        let ok = rust_encrypt_with_key(
            key.as_ptr(),
            pt.as_ptr(),
            pt.len(),
            aad.as_ptr(),
            aad.len(),
            small.as_mut_ptr(),
            &mut cap,
        );
        assert!(!ok);
        assert!(cap > small.len());
        assert!(small.iter().all(|&b| b == 0xEE));

        // Exact capacity: succeeds.
        let mut ct = vec![0u8; cap];
        let mut ct_len = ct.len();
        assert!(rust_encrypt_with_key(
            key.as_ptr(),
            pt.as_ptr(),
            pt.len(),
            aad.as_ptr(),
            aad.len(),
            ct.as_mut_ptr(),
            &mut ct_len,
        ));
        ct.truncate(ct_len);

        let mut tiny = [0xEEu8; 10];
        let mut tiny_len = tiny.len();
        assert!(!rust_decrypt_with_key(
            key.as_ptr(),
            ct.as_ptr(),
            ct.len(),
            aad.as_ptr(),
            aad.len(),
            tiny.as_mut_ptr(),
            &mut tiny_len,
        ));
        assert_eq!(tiny_len, pt.len());
        assert!(tiny.iter().all(|&b| b == 0xEE));

        let mut out = vec![0u8; pt.len()];
        let mut out_len = out.len();
        assert!(rust_decrypt_with_key(
            key.as_ptr(),
            ct.as_ptr(),
            ct.len(),
            aad.as_ptr(),
            aad.len(),
            out.as_mut_ptr(),
            &mut out_len,
        ));
        assert_eq!(&out[..out_len], &pt[..]);
    }
}

#[cfg(test)]
mod raw_ratchet_ffi_gate_tests {
    use super::{
        raw_ratchet_ffi_allowed, rust_ratchet_export_encrypted, rust_ratchet_from_bytes,
        rust_ratchet_import_encrypted, rust_ratchet_new, rust_ratchet_to_bytes,
        RAW_RATCHET_FFI_ENV,
    };

    fn clear_raw_env() {
        std::env::remove_var(RAW_RATCHET_FFI_ENV);
    }

    #[test]
    fn raw_ratchet_ffi_refused_without_exact_env() {
        clear_raw_env();
        assert!(!raw_ratchet_ffi_allowed());

        let id = rust_ratchet_new();
        let mut out = vec![0xAAu8; 4096];
        let mut out_len = out.len();
        // Sentinel: must remain untouched when refused.
        assert!(!rust_ratchet_to_bytes(id, out.as_mut_ptr(), &mut out_len));
        assert!(out.iter().all(|&b| b == 0xAA));
        assert_eq!(out_len, out.len());

        // Non-exact values also refuse.
        for bad in ["", "0", "true", "yes", "2", "1 "] {
            std::env::set_var(RAW_RATCHET_FFI_ENV, bad);
            assert!(
                !raw_ratchet_ffi_allowed(),
                "unexpected allow for {bad:?}"
            );
            let mut buf = [0xBBu8; 64];
            let mut n = buf.len();
            assert!(!rust_ratchet_to_bytes(id, buf.as_mut_ptr(), &mut n));
            assert!(buf.iter().all(|&b| b == 0xBB));
        }
        clear_raw_env();

        // from_bytes must also refuse without env (no store mutation).
        let junk = [0u8; 8];
        assert!(!rust_ratchet_from_bytes(id, junk.as_ptr(), junk.len()));
        clear_raw_env();
    }

    #[test]
    fn raw_ratchet_ffi_roundtrip_when_allowed_encrypted_still_works() {
        clear_raw_env();
        std::env::set_var(RAW_RATCHET_FFI_ENV, "1");
        assert!(raw_ratchet_ffi_allowed());

        let id = rust_ratchet_new();
        let mut raw = vec![0u8; 4096];
        let mut raw_len = raw.len();
        assert!(rust_ratchet_to_bytes(id, raw.as_mut_ptr(), &mut raw_len));
        assert!(raw_len > 0);
        raw.truncate(raw_len);

        // Encrypted path remains usable (preferred for production).
        let pass = b"test-passphrase-raw-gate";
        let mut enc = vec![0u8; 8192];
        let mut enc_len = enc.len();
        assert!(rust_ratchet_export_encrypted(
            id,
            pass.as_ptr(),
            pass.len(),
            enc.as_mut_ptr(),
            &mut enc_len,
        ));
        enc.truncate(enc_len);
        assert!(enc_len > raw_len, "encrypted envelope larger than raw");

        // Fresh slot + raw import roundtrip.
        let id2 = rust_ratchet_new();
        assert!(rust_ratchet_from_bytes(id2, raw.as_ptr(), raw.len()));

        // Encrypted import into another slot still works.
        let id3 = rust_ratchet_new();
        assert!(rust_ratchet_import_encrypted(
            id3,
            pass.as_ptr(),
            pass.len(),
            enc.as_ptr(),
            enc.len(),
        ));

        clear_raw_env();
        assert!(!raw_ratchet_ffi_allowed());
        // After clear, raw path refuses again.
        let mut again = vec![0xCCu8; 64];
        let mut again_len = again.len();
        assert!(!rust_ratchet_to_bytes(id, again.as_mut_ptr(), &mut again_len));
        assert!(again.iter().all(|&b| b == 0xCC));
    }
}
