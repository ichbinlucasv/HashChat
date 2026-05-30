use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;
use ed25519_dalek::SigningKey;
use std::fs;
use std::os::raw::c_void;
use std::ptr;

mod ratchet;

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

#[no_mangle]
pub extern "C" fn rust_hmac_verify(msg: *const u8, len: usize) -> bool {
    let slice = unsafe { std::slice::from_raw_parts(msg, len) };
    let key = hmac::Key::new(hmac::HMAC_SHA512, b"hashchat-extra-key");
    hmac::verify(&key, slice, slice).is_ok()
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
    ring::constant_time::verify_slices_are_equal(a_slice, b_slice).is_ok()
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
    ring::constant_time::verify_slices_are_equal(a_slice, b_slice).is_ok()
}

// ==================== Double Ratchet FFI (for message system) ====================

use crate::ratchet::DoubleRatchet;

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
pub extern "C" fn rust_ratchet_init(state_id: u32, remote_pub: *const u8, shared_secret: *const u8) {
    unsafe {
        if let Some(r) = RATCHET_STORE.get_mut(state_id as usize) {
            let rp = x25519_dalek::PublicKey::from(*<&[u8; 32]>::try_from(std::slice::from_raw_parts(remote_pub, 32)).unwrap());
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
pub extern "C" fn rust_ratchet_recv(state_id: u32, remote_pub: *const u8, out_key: *mut u8, out_count: *mut u32) {
    unsafe {
        if let Some(r) = RATCHET_STORE.get_mut(state_id as usize) {
            let rp = x25519_dalek::PublicKey::from(*<&[u8; 32]>::try_from(std::slice::from_raw_parts(remote_pub, 32)).unwrap());
            let (key, count) = r.ratchet_recv(&rp);
            std::ptr::copy_nonoverlapping(key.as_ptr(), out_key, 32);
            *out_count = count;
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
    unsafe {
        let key_slice = std::slice::from_raw_parts(key, 32);
        let pt = std::slice::from_raw_parts(plaintext, plaintext_len);

        let unbound = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key_slice).unwrap();
        let lsk = ring::aead::LessSafeKey::new(unbound);

        let nonce = ring::aead::Nonce::assume_unique_for_key([0u8; 12]);
        let mut buf = vec![0u8; plaintext_len + ring::aead::AES_256_GCM.tag_len()];
        buf[..plaintext_len].copy_from_slice(pt);

        match lsk.seal_in_place_append_tag(nonce, ring::aead::Aad::empty(), &mut buf) {
            Ok(_) => {
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
    unsafe {
        let key_slice = std::slice::from_raw_parts(key, 32);
        let ct = std::slice::from_raw_parts(ciphertext, ciphertext_len);

        let unbound = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key_slice).unwrap();
        let lsk = ring::aead::LessSafeKey::new(unbound);

        let nonce = ring::aead::Nonce::assume_unique_for_key([0u8; 12]);
        let mut buf = ct.to_vec();

        match lsk.open_in_place(nonce, ring::aead::Aad::empty(), &mut buf) {
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