#!/bin/bash
# Build the single hashchat-rust crate as an Android JNI cdylib.
# Requires: rustup target add aarch64-linux-android && cargo install cargo-ndk && NDK
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v cargo-ndk >/dev/null 2>&1; then
  echo "ERROR: cargo-ndk not in PATH. Install: cargo install cargo-ndk"
  exit 1
fi

OUT="android/src/main/jniLibs"
mkdir -p "$OUT"

echo "Building hashchat-rust --features android (arm64-v8a, armeabi-v7a)..."
cargo ndk -t arm64-v8a -t armeabi-v7a -o "$OUT" build --release --no-default-features --features android

if [ ! -f "$OUT/arm64-v8a/libhashchat_rust.so" ]; then
  echo "ERROR: libhashchat_rust.so was not written to $OUT"
  exit 1
fi

echo "OK: $OUT/*/libhashchat_rust.so"
echo "Kotlin loads: System.loadLibrary(\"hashchat_rust\")"
