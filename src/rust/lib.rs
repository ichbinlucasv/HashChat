use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;
use ed25519_dalek::{Keypair, Signer};
use std::fs;
use std::os::raw::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

#[no_mangle]
pub extern "C" fn rust_init_profile() -> *mut c_void {
    let mut rng = rand::thread_rng();
    let keypair = Keypair::generate(&mut rng);
    let boxed = Box::new(keypair);
    Box::into_raw(boxed) as *mut c_void
}

#[no_mangle]
pub extern "C" fn rust_secure_erase(ptr: *mut c_void) {
    unsafe {
        let mut keypair: Box<Keypair> = Box::from_raw(ptr as *mut Keypair);
        keypair.zeroize();
        drop(keypair);
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
    ptr::write_bytes(ptr, 0, len);
}

#[no_mangle]
pub extern "C" fn rust_wipe_memory(ptr: *mut u8, len: usize) {
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    slice.zeroize();
    ptr::write_bytes(ptr, 0, len);
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
    ptr::write_bytes(ptr, 0, len);
}

#[no_mangle]
pub extern "C" fn rust_secure_compare(a: *const u8, b: *const u8, len: usize) -> bool {
    let a_slice = unsafe { std::slice::from_raw_parts(a, len) };
    let b_slice = unsafe { std::slice::from_raw_parts(b, len) };
    ring::constant_time::verify_slices_are_equal(a_slice, b_slice).is_ok()
}