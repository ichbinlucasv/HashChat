// Android JNI bridge skeleton for HashChat
// This will expose the same Rust crypto (ratchet, blob encryption, wipe) to Kotlin.

use jni::JNIEnv;
use jni::objects::JClass;

#[no_mangle]
pub extern "C" fn Java_chat_hashchat_HashChatNative_init(env: JNIEnv, class: JClass) {
    // Initialize Rust side (similar to desktop)
}

#[no_mangle]
pub extern "C" fn Java_chat_hashchat_HashChatNative_wipeAll(env: JNIEnv, class: JClass) {
    // Call the same secure wipe logic
}