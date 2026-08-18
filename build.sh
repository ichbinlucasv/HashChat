#!/usr/bin/env bash
#
# HashChat Build Script (Pure Bash) - Reproducible Edition
#
# Goals:
# - Maximum reproducibility and auditability
# - No Python (only Bash + tools the user controls)
# - Strong use of lockfiles
#
# Recommended for high-security builds:
#   - Build inside Tails or a Qubes disposable VM
#   - Pin the Rust toolchain (rustup)
#
# Usage:
#   ./build.sh
#   ./build.sh tui
#

set -euo pipefail

echo "=== Building HashChat (Rust) - Reproducible Mode ==="
echo "Platform: $(uname -s)"
echo ""

echo "[1/5] Building Rust library + TUI (release, locked)..."
cargo build --release --locked --features tui --bin hashchat-tui

# Stage the Rust library
echo "[2/5] Staging Rust library..."
mkdir -p rust-lib

LIB_NAME="libhashchat_rust.so"
if [[ "$(uname -s)" == "Darwin" ]]; then
    LIB_NAME="libhashchat_rust.dylib"
fi

if [[ -f "target/release/${LIB_NAME}" ]]; then
    cp "target/release/${LIB_NAME}" rust-lib/
    echo "  → Copied ${LIB_NAME} to rust-lib/"
else
    echo "  Warning: ${LIB_NAME} not found in target/release/"
fi

echo "[3/5] Rust TUI is the desktop app (hashchat-tui)."
echo "[4/5] Haskell Brick leftover is not built. Use cabal only if you need the old UI."
echo "[5/5] Android JNI: ./build-android.sh (same crate, --features android)"

echo ""
echo "=== Build completed ==="
echo "Run: ./run-tui"
echo ""
echo "For maximum security: Build inside Tails or a Qubes disposable VM."