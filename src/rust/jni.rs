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
pub extern "system" fn Java_chat_hashchat_HashChatNative_getOnion(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    // Stub - real version would return the persisted onion
    env.new_string("hashchatxxxxxxxxxxxxxxxx.onion")
        .expect("Couldn't create java string")
        .into_raw()
}
