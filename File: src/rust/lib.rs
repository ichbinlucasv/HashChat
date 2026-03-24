use ring::hmac;
use zeroize::Zeroize;
use ed25519_dalek::{Keypair, Signer};
use std::fs;
use std::os::raw::c_void;

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