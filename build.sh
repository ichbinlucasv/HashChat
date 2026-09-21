#!/usr/bin/env bash
#
# HashChat Build Script (Pure Bash) — Rust-first
#
# Recommended desktop path:
#   ./build.sh          # Rust library (release, locked)
#   ./build.sh tui      # Rust hashchat-tui --features tui
#
# Transitional Haskell (not recommended; kept compiling if present):
#   ./build.sh --haskell
#   ./build.sh tui --haskell
#
# High-security builds: Tails or a Qubes disposable; pin toolchains.
#
# OPSEC: does not print secrets, passphrases, Tor cookies, or key material.
#

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

WANT_TUI=0
WANT_HASKELL=0
for arg in "$@"; do
  case "$arg" in
    tui|--tui) WANT_TUI=1 ;;
    --haskell|haskell) WANT_HASKELL=1 ;;
    -h|--help)
      echo "Usage: ./build.sh [tui] [--haskell]"
      echo "  (default)  cargo build --release --locked"
      echo "  tui        cargo build --release --locked --bin hashchat-tui --features tui"
      echo "  --haskell  also build transitional Cabal targets (not recommended)"
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown argument: $arg (try --help)"
      exit 1
      ;;
  esac
done

if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

echo "=== Building HashChat (Rust recommended) ==="
echo "Platform: $(uname -s)"
echo "Branch tip expected: codeberg-primary"
echo ""

if ! command -v cargo >/dev/null 2>&1; then
  echo "[ERROR] cargo not found. Install Rust via rustup, then re-run."
  exit 1
fi

echo "[1/3] Building Rust FFI / library (release, locked)..."
cargo build --release --locked

echo "[2/3] Staging Rust library..."
mkdir -p rust-lib
LIB_NAME="libhashchat_rust.so"
if [[ "$(uname -s)" == "Darwin" ]]; then
  LIB_NAME="libhashchat_rust.dylib"
fi
if [[ -f "target/release/${LIB_NAME}" ]]; then
  cp -f "target/release/${LIB_NAME}" rust-lib/
  echo "  → Copied ${LIB_NAME} to rust-lib/"
else
  echo "  Warning: ${LIB_NAME} not found in target/release/"
fi

if [[ "$WANT_TUI" -eq 1 ]]; then
  echo "[3/3] Building native Rust TUI (hashchat-tui --features tui)..."
  cargo build --release --locked --bin hashchat-tui --features tui
else
  echo "[3/3] Skipping Rust TUI (pass 'tui' to build hashchat-tui)."
fi

if [[ "$WANT_HASKELL" -eq 1 ]]; then
  echo ""
  echo "[WARN] Building transitional Haskell (not recommended for desktop)."
  echo "       Tree kept compiling for parity checks; see INSTALL.md removal criteria."
  if ! command -v cabal >/dev/null 2>&1; then
    echo "[ERROR] cabal not found; cannot build --haskell path."
    exit 1
  fi
  cabal update
  cabal build -f-tui hashchat --enable-tests
  cabal build -f-tui hashchat-cli --enable-tests
  if [[ "$WANT_TUI" -eq 1 ]]; then
    cabal build -f-tui hashchat-tui --enable-tests
  fi
fi

echo ""
echo "=== Build completed ==="
echo "Recommended run: ./run-tui   (or: make tui)"
echo "  Primary binary: target/release/hashchat-tui"
echo "Haskell desktop is transitional / not recommended."
echo "For maximum security: build inside Tails or a Qubes disposable VM."
