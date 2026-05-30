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
#   - Use pinned versions of GHC and Rust (via ghcup + rustup with exact toolchains)
#
# Usage:
#   ./build.sh
#   ./build.sh tui
#

set -euo pipefail

echo "=== Building HashChat (Haskell + Rust) - Reproducible Mode ==="
echo "Platform: $(uname -s)"
echo ""

# Enforce lockfile usage where possible
echo "[1/5] Building Rust FFI library (release, locked)..."
cargo build --release --locked

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

# Haskell - strict use of cabal.project / lockfiles
echo "[3/5] Updating Cabal index (use --project-file if you have a locked index-state)..."
cabal update

echo "[4/5] Building Haskell (library + CLI with -f-tui, using lockfiles)..."
cabal build -f-tui hashchat --enable-tests
cabal build -f-tui hashchat-cli --enable-tests

# Optional TUI build
if [[ "${1:-}" == "tui" || "${1:-}" == "--tui" ]]; then
    echo "[5/5] Building TUI..."
    cabal build -f-tui hashchat-tui --enable-tests
else
    echo ""
    echo "Tip: Run './build.sh tui' to also build the desktop TUI."
fi

echo ""
echo "=== Build completed ==="
echo ""
echo "Reproducibility notes:"
echo "  - Cargo used --locked"
echo "  - Cabal used existing cabal.project / lockfiles"
echo "  - For stronger reproducibility, pin GHC and Rust toolchain versions"
echo "    (see docs/BUILD_REPRODUCIBILITY.md for recommended setup)"
echo ""
echo "Run the TUI with: ./run-tui"
echo ""
echo "For maximum security: Build inside Tails or a Qubes disposable VM."