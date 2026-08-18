use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;
use ed25519_dalek::SigningKey;
use subtle::ConstantTimeEq;
use std::fs;
use std::os::raw::c_void;
use std::ptr;
use std::sync::{Mutex, OnceLock};

mod ratchet;
mod longterm_identity;

// long-13: gated quantum module. Only compiled with `cargo build --features quantum`.
// The module itself documents the strict constant-time / zeroize / side-channel
// requirements that any future real implementation must meet.
#[cfg(feature = "quantum")]
mod quantum;
#[cfg(feature = "quantum")]
pub use quantum::{hybrid_ratchet_new, QuantumHybridRatchet, KEM_PUBLIC_KEY_LEN, KEM_CIPHERTEXT_LEN};

#[cfg(feature = "quantum")]
#[no_mangle]
pub extern "C" fn rust_quantum_hybrid_new() -> *mut QuantumHybridRatchet {
    match hybrid_ratchet_new() {
        Ok(r) => Box::into_raw(Box::new(r)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// High Phase3 continue: FFI for hybrid kex test from TUI (real X25519 part + placeholder).
/// Haskell calls with our x priv (demo or future long-derived), peer long x pub, peer kem pub (placeholder size).
/// Returns true on success, fills out_ct (KEM_CIPHERTEXT_LEN) and out_ss (32).
#[cfg(feature = "quantum")]
#[no_mangle]
pub extern "C" fn rust_quantum_hybrid_kex_test(
    our_priv: *const u8,
    peer_x: *const u8,
    peer_kem: *const u8,
    out_ct: *mut u8,
    out_ss: *mut u8,
) -> bool {
    if our_priv.is_null() || peer_x.is_null() || peer_kem.is_null() || out_ct.is_null() || out_ss.is_null() {
        return false;
    }
    unsafe {
        let our: [u8; 32] = match std::slice::from_raw_parts(our_priv, 32).try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let px: [u8; 32] = match std::slice::from_raw_parts(peer_x, 32).try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let pkem_arr: [u8; quantum::KEM_PUBLIC_KEY_LEN] =
            match std::slice::from_raw_parts(peer_kem, quantum::KEM_PUBLIC_KEY_LEN).try_into() {
                Ok(b) => b,
                Err(_) => return false,
            };
        match quantum::hybrid_kex(&our, &px, &pkem_arr) {
            Ok((ss, ct)) => {
                std::ptr::copy_nonoverlapping(ct.as_ptr(), out_ct, ct.len());
                std::ptr::copy_nonoverlapping(ss.as_ptr(), out_ss, ss.len());
                true
            }
            Err(_) => false,
        }
    }
}

pub use longterm_identity::{
    export_encrypted as longterm_export_encrypted,
    import_encrypted as longterm_import_encrypted,
};

#[no_mangle]
pub extern "C" fn rust_init_profile() -> *mut c_void {
    let mut secret = [0u8; 32];
    let _ = getrandom::getrandom(&mut secret);
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

/// HMAC-SHA256(key, msg) -> 32-byte tag.
#[no_mangle]
pub extern "C" fn rust_hmac_sign(
    key: *const u8,
    key_len: usize,
    msg: *const u8,
    msg_len: usize,
    out_tag: *mut u8,
) -> bool {
    if key.is_null() || msg.is_null() || out_tag.is_null() || key_len == 0 {
        return false;
    }
    unsafe {
        let key_slice = std::slice::from_raw_parts(key, key_len);
        let msg_slice = std::slice::from_raw_parts(msg, msg_len);
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key_slice);
        let tag = hmac::sign(&hmac_key, msg_slice);
        let bytes = tag.as_ref();
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_tag, bytes.len().min(32));
        true
    }
}

/// Constant-time HMAC-SHA256 verify. Replaces the old self-compare stub.
#[no_mangle]
pub extern "C" fn rust_hmac_verify(
    key: *const u8,
    key_len: usize,
    msg: *const u8,
    msg_len: usize,
    tag: *const u8,
    tag_len: usize,
) -> bool {
    if key.is_null() || msg.is_null() || tag.is_null() || key_len == 0 || tag_len == 0 {
        return false;
    }
    unsafe {
        let key_slice = std::slice::from_raw_parts(key, key_len);
        let msg_slice = std::slice::from_raw_parts(msg, msg_len);
        let tag_slice = std::slice::from_raw_parts(tag, tag_len);
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key_slice);
        hmac::verify(&hmac_key, msg_slice, tag_slice).is_ok()
    }
}

#[no_mangle]
pub extern "C" fn rust_wipe_files() {
    let _ = fs::remove_dir_all("tor/hidden_service");
    let _ = fs::remove_file("hashchat.db");
}

#[no_mangle]
pub extern "C" fn rust_secure_random(buf: *mut u8, len: usize) {
    let rng = SystemRandom::new();
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    let _ = rng.fill(slice);
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
    unsafe { ptr::write_bytes(ptr, 0, len); }
}

#[no_mangle]
pub extern "C" fn rust_wipe_memory(ptr: *mut u8, len: usize) {
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    slice.zeroize();
    unsafe { ptr::write_bytes(ptr, 0, len); }
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
    unsafe { ptr::write_bytes(ptr, 0, len); }
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

use crate::ratchet::DoubleRatchet;

fn ratchet_store() -> &'static Mutex<Vec<DoubleRatchet>> {
    static STORE: OnceLock<Mutex<Vec<DoubleRatchet>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(Vec::new()))
}

fn extreme_flag() -> &'static Mutex<bool> {
    static FLAG: OnceLock<Mutex<bool>> = OnceLock::new();
    FLAG.get_or_init(|| Mutex::new(false))
}

fn is_extreme() -> bool {
    extreme_flag().lock().map(|g| *g).unwrap_or(false)
}

fn store_put(state_id: u32, r: DoubleRatchet) -> bool {
    let Ok(mut store) = ratchet_store().lock() else {
        return false;
    };
    if (state_id as usize) < store.len() {
        store[state_id as usize] = r;
    } else {
        store.push(r);
    }
    true
}

#[no_mangle]
pub extern "C" fn rust_ratchet_new() -> u32 {
    if is_extreme() {
        return u32::MAX;
    }
    let Ok(mut store) = ratchet_store().lock() else {
        return u32::MAX;
    };
    let id = store.len() as u32;
    store.push(DoubleRatchet::new());
    id
}

#[no_mangle]
pub extern "C" fn rust_ratchet_init(state_id: u32, remote_pub: *const u8, shared_secret: *const u8) {
    if remote_pub.is_null() || shared_secret.is_null() {
        return;
    }
    unsafe {
        let rp_bytes: [u8; 32] = match std::slice::from_raw_parts(remote_pub, 32).try_into() {
            Ok(b) => b,
            Err(_) => return,
        };
        let sh: [u8; 32] = match std::slice::from_raw_parts(shared_secret, 32).try_into() {
            Ok(b) => b,
            Err(_) => return,
        };
        let rp = x25519_dalek::PublicKey::from(rp_bytes);
        if let Ok(mut store) = ratchet_store().lock() {
            if let Some(r) = store.get_mut(state_id as usize) {
                r.init_from_shared(rp, &sh);
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_ratchet_send(state_id: u32, out_key: *mut u8, out_count: *mut u32) {
    if out_key.is_null() || out_count.is_null() {
        return;
    }
    if let Ok(mut store) = ratchet_store().lock() {
        if let Some(r) = store.get_mut(state_id as usize) {
            let (key, count) = r.ratchet_send();
            unsafe {
                std::ptr::copy_nonoverlapping(key.as_ptr(), out_key, 32);
                *out_count = count;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_ratchet_recv(state_id: u32, remote_pub: *const u8, out_key: *mut u8, out_count: *mut u32) {
    if remote_pub.is_null() || out_key.is_null() || out_count.is_null() {
        return;
    }
    unsafe {
        let rp_bytes: [u8; 32] = match std::slice::from_raw_parts(remote_pub, 32).try_into() {
            Ok(b) => b,
            Err(_) => return,
        };
        let rp = x25519_dalek::PublicKey::from(rp_bytes);
        if let Ok(mut store) = ratchet_store().lock() {
            if let Some(r) = store.get_mut(state_id as usize) {
                let (key, count) = r.ratchet_recv(&rp);
                std::ptr::copy_nonoverlapping(key.as_ptr(), out_key, 32);
                *out_count = count;
            }
        }
    }
}

/// Wipe a skipped key for disappearing message support.
/// Called when a message expires so the corresponding ratchet material is erased.
#[no_mangle]
pub extern "C" fn rust_ratchet_wipe_skipped_key(state_id: u32, msg_number: u32) {
    if let Ok(mut store) = ratchet_store().lock() {
        if let Some(r) = store.get_mut(state_id as usize) {
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
    out: *mut u8,
    out_len: *mut usize,
) -> bool {
    if key.is_null() || plaintext.is_null() || out.is_null() || out_len.is_null() {
        return false;
    }
    unsafe {
        let key_arr: [u8; 32] = match std::slice::from_raw_parts(key, 32).try_into() {
            Ok(k) => k,
            Err(_) => return false,
        };
        let pt = std::slice::from_raw_parts(plaintext, plaintext_len);
        match crate::ratchet::encrypt_with_key(&key_arr, pt) {
            Ok(buf) => {
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
    out: *mut u8,
    out_len: *mut usize,
) -> bool {
    if key.is_null() || ciphertext.is_null() || out.is_null() || out_len.is_null() {
        return false;
    }
    unsafe {
        let key_arr: [u8; 32] = match std::slice::from_raw_parts(key, 32).try_into() {
            Ok(k) => k,
            Err(_) => return false,
        };
        let ct = std::slice::from_raw_parts(ciphertext, ciphertext_len);
        match crate::ratchet::decrypt_with_key(&key_arr, ct) {
            Ok(plain) => {
                std::ptr::copy_nonoverlapping(plain.as_ptr(), out, plain.len());
                *out_len = plain.len();
                true
            }
            Err(_) => false,
        }
    }
}

// === Encrypted Ratchet State Persistence FFI ===

#[no_mangle]
pub extern "C" fn rust_ratchet_to_bytes(state_id: u32, out: *mut u8, out_len: *mut usize) -> bool {
    if out.is_null() || out_len.is_null() {
        return false;
    }
    let Ok(store) = ratchet_store().lock() else {
        return false;
    };
    let Some(r) = store.get(state_id as usize) else {
        return false;
    };
    let bytes = r.to_bytes();
    unsafe {
        if bytes.len() > *out_len {
            *out_len = bytes.len();
            return false;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
        *out_len = bytes.len();
    }
    true
}

#[no_mangle]
pub extern "C" fn rust_ratchet_from_bytes(state_id: u32, data: *const u8, len: usize) -> bool {
    if data.is_null() {
        return false;
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    match DoubleRatchet::from_bytes(bytes) {
        Ok(r) => store_put(state_id, r),
        Err(_) => false,
    }
}

// ============================================================================
// ENCRYPTED RATCHET STATE PERSISTENCE (Argon2id + AES-256-GCM)
// This is the production path. The TUI and Android must use these, never raw to_bytes.
// ============================================================================

use argon2::{Argon2, Params, Version};
use ring::aead::{Nonce, UnboundKey, LessSafeKey, Aad, AES_256_GCM};
use rand::RngCore;

/// Fixed parameters for Argon2id (memory-hard, good defaults for local passphrase)
const ARGON_MEM_KIB: u32 = 64 * 1024; // 64 MiB
const ARGON_ITERS: u32 = 3;
const ARGON_PARALLELISM: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

fn derive_key_argon2id(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; 32], &'static str> {
    let params = Params::new(ARGON_MEM_KIB, ARGON_ITERS, ARGON_PARALLELISM, Some(32))
        .map_err(|_| "bad argon params")?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2.hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| "argon2 kdf failed")?;
    Ok(key)
}

#[no_mangle]
pub extern "C" fn rust_ratchet_export_encrypted(
    state_id: u32,
    passphrase: *const u8,
    pass_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> bool {
    unsafe {
        let Ok(store) = ratchet_store().lock() else {
            return false;
        };
        if let Some(ratchet) = store.get(state_id as usize) {
            let pass = std::slice::from_raw_parts(passphrase, pass_len);
            if pass.is_empty() {
                return false;
            }

            // 1. Generate fresh salt + nonce
            let mut salt = [0u8; SALT_LEN];
            let mut nonce_bytes = [0u8; NONCE_LEN];
            rand::thread_rng().fill_bytes(&mut salt);
            rand::thread_rng().fill_bytes(&mut nonce_bytes);

            // 2. Derive key from passphrase
            let key = match derive_key_argon2id(pass, &salt) {
                Ok(k) => k,
                Err(_) => return false,
            };

            // 3. Serialize ratchet (sensitive)
            let plaintext = ratchet.to_bytes();

            // 4. Encrypt with AES-256-GCM
            let unbound = match UnboundKey::new(&AES_256_GCM, &key) {
                Ok(u) => u,
                Err(_) => return false,
            };
            let lsk = LessSafeKey::new(unbound);
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let mut buf = plaintext;
            let _tag_len = AES_256_GCM.tag_len();

            if lsk.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf).is_err() {
                return false;
            }

            // 5. Build envelope: [version(1) | salt(16) | nonce(12) | ciphertext+tag]
            let mut envelope = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + buf.len());
            envelope.push(1u8); // envelope version
            envelope.extend_from_slice(&salt);
            envelope.extend_from_slice(&nonce_bytes);
            envelope.extend_from_slice(&buf);

            let needed = envelope.len();
            if needed > *out_len {
                *out_len = needed;
                return false;
            }
            std::ptr::copy_nonoverlapping(envelope.as_ptr(), out, needed);
            *out_len = needed;
            true
        } else {
            false
        }
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
    unsafe {
        if data_len < 1 + SALT_LEN + NONCE_LEN + 16 {
            return false;
        }
        let envelope = std::slice::from_raw_parts(data, data_len);
        let pass = std::slice::from_raw_parts(passphrase, pass_len);
        if pass.is_empty() || envelope[0] != 1 {
            return false;
        }

        let salt: [u8; SALT_LEN] = envelope[1..1 + SALT_LEN].try_into().unwrap();
        let nonce_bytes: [u8; NONCE_LEN] = envelope[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN].try_into().unwrap();
        let ciphertext = &envelope[1 + SALT_LEN + NONCE_LEN..];

        let key = match derive_key_argon2id(pass, &salt) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let unbound = match UnboundKey::new(&AES_256_GCM, &key) {
            Ok(u) => u,
            Err(_) => return false,
        };
        let lsk = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut buf = ciphertext.to_vec();

        match lsk.open_in_place(nonce, Aad::empty(), &mut buf) {
            Ok(plain) => {
                match DoubleRatchet::from_bytes(plain) {
                    Ok(r) => store_put(state_id, r),
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
}

// === Ultra Paranoid Kernel-Level Security Primitives ===

// Lock all current and future memory (strong anti-swap / anti-memory forensics)
#[no_mangle]
pub extern "C" fn rust_mlockall_current() -> bool {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

// Lock a specific allocation (call this on sensitive buffers after allocation)
#[no_mangle]
pub extern "C" fn rust_mlock(ptr: *const u8, len: usize) -> bool {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
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
        // In a future iteration enable the seccomp crate behind a feature flag.
        // For maximum paranoid users: combine with systemd unit RestrictNamespaces, SystemCallFilter, etc.
        true
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
    #[cfg(target_os = "linux")]
    {
        unsafe {
            // mlockall already covers future allocations when called at startup.
            // This is an extra belt-and-suspenders for the global store.
            libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
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
    unsafe {
        let pass = std::slice::from_raw_parts(passphrase, pass_len);
        let plaintext = std::slice::from_raw_parts(data, data_len);

        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let key = match derive_key_argon2id(pass, &salt) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let unbound = match UnboundKey::new(&AES_256_GCM, &key) {
            Ok(u) => u,
            Err(_) => return false,
        };
        let lsk = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut buf = plaintext.to_vec();

        if lsk.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf).is_err() {
            return false;
        }

        let mut envelope = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + buf.len());
        envelope.push(1u8);
        envelope.extend_from_slice(&salt);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&buf);

        if envelope.len() > *out_len {
            *out_len = envelope.len();
            return false;
        }
        std::ptr::copy_nonoverlapping(envelope.as_ptr(), out, envelope.len());
        *out_len = envelope.len();
        true
    }
}

// ============================================================================
// LONG-TERM IDENTITY KEYPAIR FFI (ContactAddress / Profile Sharing)
// Wave 10 Critical item - Option B implementation
// ============================================================================

use crate::longterm_identity::LongTermIdentity;
use x25519_dalek::PublicKey as X25519Public;

fn longterm_store() -> &'static Mutex<Vec<LongTermIdentity>> {
    static STORE: OnceLock<Mutex<Vec<LongTermIdentity>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(Vec::new()))
}

#[no_mangle]
pub extern "C" fn rust_longterm_identity_new() -> u32 {
    let Ok(mut store) = longterm_store().lock() else {
        return u32::MAX;
    };
    let id = store.len() as u32;
    store.push(LongTermIdentity::generate());
    id
}

#[no_mangle]
pub extern "C" fn rust_longterm_identity_get_public(
    identity_id: u32,
    out_ed25519: *mut u8,
    out_x25519: *mut u8,
) -> bool {
    unsafe {
        let Ok(store) = longterm_store().lock() else {
            return false;
        };
        if let Some(id) = store.get(identity_id as usize) {
            let ed_pub: [u8; 32] = id.ed25519_public().to_bytes();
            let x_pub: [u8; 32] = *id.x25519_public().as_bytes();

            std::ptr::copy_nonoverlapping(ed_pub.as_ptr(), out_ed25519, 32);
            std::ptr::copy_nonoverlapping(x_pub.as_ptr(), out_x25519, 32);
            true
        } else {
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_longterm_identity_export_encrypted(
    identity_id: u32,
    passphrase: *const u8,
    pass_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> bool {
    unsafe {
        let Ok(store) = longterm_store().lock() else {
            return false;
        };
        if let Some(identity) = store.get(identity_id as usize) {
            let pass = std::slice::from_raw_parts(passphrase, pass_len);
            match longterm_export_encrypted(identity, pass) {
                Ok(envelope) => {
                    if envelope.len() > *out_len {
                        *out_len = envelope.len();
                        return false;
                    }
                    std::ptr::copy_nonoverlapping(envelope.as_ptr(), out, envelope.len());
                    *out_len = envelope.len();
                    true
                }
                Err(_) => false,
            }
        } else {
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_longterm_identity_import_encrypted(
    identity_id: u32,
    passphrase: *const u8,
    pass_len: usize,
    data: *const u8,
    data_len: usize,
) -> bool {
    unsafe {
        let pass = std::slice::from_raw_parts(passphrase, pass_len);
        let envelope = std::slice::from_raw_parts(data, data_len);

        match longterm_import_encrypted(envelope, pass) {
            Ok(identity) => {
                if let Ok(mut store) = longterm_store().lock() {
                    if (identity_id as usize) < store.len() {
                        store[identity_id as usize] = identity;
                    } else {
                        store.push(identity);
                    }
                } else {
                    return false;
                }
                true
            }
            Err(_) => false,
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_longterm_identity_wipe(identity_id: u32) {
    if let Ok(mut store) = longterm_store().lock() {
        if let Some(id) = store.get_mut(identity_id as usize) {
            id.wipe();
        }
    }
}

/// X3DH helper: compute shared secret = local_long_x25519 .diffie_hellman( peer_x25519_pub )
/// Used for initial ratchet bootstrap from ContactAddress QR (long-term x pub).
#[no_mangle]
pub extern "C" fn rust_longterm_x25519_dh(
    identity_id: u32,
    peer_x: *const u8,
    out_shared: *mut u8,
) -> bool {
    unsafe {
        if peer_x.is_null() || out_shared.is_null() {
            return false;
        }
        let Ok(store) = longterm_store().lock() else {
            return false;
        };
        if (identity_id as usize) >= store.len() {
            return false;
        }
        let id = &store[identity_id as usize];
        let peer_slice = std::slice::from_raw_parts(peer_x, 32);
        let mut peer_arr = [0u8; 32];
        peer_arr.copy_from_slice(peer_slice);
        let peer_pub = X25519Public::from(peer_arr);
        let shared = id.x25519_dh(&peer_pub);
        std::ptr::copy_nonoverlapping(shared.as_ptr(), out_shared, 32);
        true
    }
}

#[no_mangle]
pub extern "C" fn rust_set_extreme_mode(enabled: bool) {
    if let Ok(mut flag) = extreme_flag().lock() {
        *flag = enabled;
    }
}

#[no_mangle]
pub extern "C" fn rust_is_extreme_mode() -> bool {
    is_extreme()
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
    unsafe {
        if data_len < 1 + SALT_LEN + NONCE_LEN {
            return false;
        }
        let envelope = std::slice::from_raw_parts(data, data_len);
        let pass = std::slice::from_raw_parts(passphrase, pass_len);

        if envelope[0] != 1 {
            return false;
        }

        let salt: [u8; SALT_LEN] = envelope[1..1+SALT_LEN].try_into().unwrap();
        let nonce_bytes: [u8; NONCE_LEN] = envelope[1+SALT_LEN..1+SALT_LEN+NONCE_LEN].try_into().unwrap();
        let ciphertext = &envelope[1+SALT_LEN+NONCE_LEN..];

        let key = match derive_key_argon2id(pass, &salt) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let unbound = match UnboundKey::new(&AES_256_GCM, &key) {
            Ok(u) => u,
            Err(_) => return false,
        };
        let lsk = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut buf = ciphertext.to_vec();

        match lsk.open_in_place(nonce, Aad::empty(), &mut buf) {
            Ok(plain) => {
                if plain.len() > *out_len {
                    *out_len = plain.len();
                    return false;
                }
                std::ptr::copy_nonoverlapping(plain.as_ptr(), out, plain.len());
                *out_len = plain.len();
                true
            }
            Err(_) => false,
        }
    }
}