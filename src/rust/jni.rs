// JNI bridge for Android
// Build with: cargo ndk -t arm64-v8a -o ../android/app/src/main/jniLibs build --release

#[cfg(target_os = "android")]
use jni::JNIEnv;
#[cfg(target_os = "android")]
use jni::objects::JClass;
#[cfg(target_os = "android")]
use jni::sys::jstring;

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_chat_hashchat_HashChatNative_wipeAll(
    _env: JNIEnv,
    _class: JClass,
) {
    // Calls the existing rust_wipe_files + secure erase
    unsafe { crate::rust_wipe_files(); }
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_chat_hashchat_HashChatNative_ratchetNew(
    _env: JNIEnv,
    _class: JClass,
) -> i32 {
    crate::rust_ratchet_new() as i32
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_chat_hashchat_HashChatNative_sendMessage(
    env: JNIEnv,
    _class: JClass,
    ratchet_id: i32,
    message: jstring,
) -> jstring {
    // In a full implementation this would call the Haskell message system via FFI
    // and return the encrypted blob or status.
    let msg: String = env.get_string(message).unwrap().into();
    env.new_string(format!("Sent via ratchet {}: {}", ratchet_id, msg))
        .expect("Couldn't create java string")
        .into_raw()
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_chat_hashchat_HashChatNative_receiveMessage(
    env: JNIEnv,
    _class: JClass,
    ratchet_id: i32,
    ciphertext: jstring,
) -> jstring {
    env.new_string("Decrypted message (stub)")
        .expect("Couldn't create java string")
        .into_raw()
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_chat_hashchat_HashChatNative_saveRatchetState(
    _env: JNIEnv,
    _class: JClass,
    ratchet_id: i32,
) {
    // Call rust_ratchet_to_bytes then encrypt with user passphrase before writing to secure storage (e.g. Android Keystore + EncryptedFile)
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_chat_hashchat_HashChatNative_loadRatchetState(
    _env: JNIEnv,
    _class: JClass,
    ratchet_id: i32,
) {
    // Decrypt from secure storage then call rust_ratchet_from_bytes
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_chat_hashchat_HashChatNative_getOnion(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    // Stub - real version would return the persisted onion
    env.new_string("hashchatxxxxxxxxxxxxxxxx.onion")
        .expect("Couldn't create java string")
        .into_raw()
}
