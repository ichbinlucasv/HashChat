#!/usr/bin/env bash
#
# HashChat — Fedora installer (Rust-first desktop)
#
# Builds the native Rust TUI:
#   cargo build --release --bin hashchat-tui --features tui
#
# Haskell desktop path remains available as a transitional fallback
# (see INSTALL.md). Prefer Rust for new installs.
#
# Usage:
#   ./install-fedora.sh
# Then:
#   ./run-tui
#
# OPSEC: does not print secrets, passphrases, Tor cookies, or key material.
#

set -euo pipefail

echo "=== HashChat Installer for Fedora (Rust-first) ==="
echo "Branch tip: codeberg-primary (Codeberg primary repo)"
echo ""

# Ensure rustup env if present
if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

echo "[1/6] Updating system packages..."
sudo dnf update -y

echo "[2/6] Installing build + Tor dependencies..."
sudo dnf install -y \
  gcc \
  make \
  pkg-config \
  openssl-devel \
  ncurses-devel \
  libffi-devel \
  zlib-devel \
  git \
  curl \
  tor

if ! command -v cargo >/dev/null 2>&1; then
  echo "Installing Rust via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

echo "[3/6] Toolchain ready (cargo=$(command -v cargo))."

echo "[4/6] Building Rust library (release, locked)..."
cargo build --release --locked

echo "[5/6] Building Rust desktop TUI (hashchat-tui --features tui)..."
cargo build --release --locked --bin hashchat-tui --features tui

mkdir -p rust-lib
if [ -f target/release/libhashchat_rust.so ]; then
  cp -f target/release/libhashchat_rust.so rust-lib/
fi

echo "[6/6] Optional transitional Haskell path (skipped by default)."
echo "      To build the legacy Brick TUI later: install ghc/cabal, then"
echo "      cabal update && cabal build -f-tui hashchat-tui"
echo "      ./run-tui falls back to Haskell only if the Rust binary is missing."

echo ""
echo "=== How to run ==="
echo "  ./run-tui"
echo "  # or: ./target/release/hashchat-tui"
echo ""
echo "=== Tor (required for the default anonymity path) ==="
echo "1. Enable ControlPort in /etc/tor/torrc (add; do not paste cookies here):"
echo "     ControlPort 9051"
echo "     CookieAuthentication 1"
echo "2. sudo systemctl enable --now tor"
echo "3. sudo systemctl restart tor"
echo ""
echo "Stronger OPSEC: Tails (amnesic) or Qubes + Whonix. See THREATMODEL.md / SECURITY.md"
echo "Done."
