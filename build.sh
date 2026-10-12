#!/usr/bin/env bash
#
# HashChat Build Script (Pure Bash) — Rust-only
#
# Recommended desktop path:
#   ./build.sh          # Rust library (release, locked)
#   ./build.sh tui      # Rust hashchat-tui --features tui
#
# High-security builds: Tails or a Qubes disposable; pin toolchains.
#
# OPSEC: does not print secrets, passphrases, Tor cookies, or key material.
#

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

WANT_TUI=0
for arg in "$@"; do
  case "$arg" in
    tui|--tui) WANT_TUI=1 ;;
    -h|--help)
      echo "Usage: ./build.sh [tui]"
      echo "  (default)  cargo build --release --locked"
      echo "  tui        cargo build --release --locked --bin hashchat-tui --features tui"
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

echo "=== Building HashChat (Rust) ==="
echo "Platform: $(uname -s)"
echo "Branch tip expected: codeberg-primary"
echo ""

if ! command -v cargo >/dev/null 2>&1; then
  echo "[ERROR] cargo not found. Install Rust via rustup, then re-run."
  exit 1
fi

echo "[1/2] Building Rust library (release, locked)..."
cargo build --release --locked

if [[ "$WANT_TUI" -eq 1 ]]; then
  echo "[2/2] Building native Rust TUI (hashchat-tui --features tui)..."
  cargo build --release --locked --bin hashchat-tui --features tui
else
  echo "[2/2] Skipping Rust TUI (pass 'tui' to build hashchat-tui)."
fi

echo ""
echo "=== Build completed ==="
echo "Recommended run: ./run-tui   (or: make tui)"
echo "  Primary binary: target/release/hashchat-tui"
echo "For maximum security: build inside Tails or a Qubes disposable VM."
