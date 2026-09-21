#!/usr/bin/env bash
#
# HashChat — Ubuntu/Debian installer (Rust-first desktop)
#
# Builds: cargo build --release --locked --bin hashchat-tui --features tui
# Haskell remains a transitional fallback (INSTALL.md).
#
# Usage:
#   ./install-ubuntu.sh
# Then:
#   ./run-tui
#
# OPSEC: does not print secrets, passphrases, Tor cookies, or key material.
#

set -euo pipefail

echo "=== HashChat Installer for Ubuntu/Debian (Rust-first) ==="
echo "Branch tip: codeberg-primary (Codeberg primary repo)"
echo ""

if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

echo "[1/6] Updating system packages..."
sudo apt update -y
sudo apt upgrade -y

echo "[2/6] Installing build + Tor dependencies..."
sudo apt install -y \
  build-essential \
  pkg-config \
  libssl-dev \
  libncurses5-dev \
  libffi-dev \
  zlib1g-dev \
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
echo "      Legacy Brick TUI: ghcup + cabal build -f-tui hashchat-tui"
echo "      ./run-tui uses Haskell only if the Rust binary is missing."

echo ""
echo "=== How to run ==="
echo "  ./run-tui"
echo "  # or: ./target/release/hashchat-tui"
echo ""
echo "=== Tor (required for the default anonymity path) ==="
echo "1. Edit /etc/tor/torrc — add SocksPort 9050, ControlPort 9051, CookieAuthentication 1"
echo "2. sudo systemctl enable --now tor && sudo systemctl restart tor"
echo "3. Cookie typically /run/tor/control.authcookie; add yourself to group debian-tor and re-login if needed."
echo "   Never cat/hexdump/paste cookie contents. HashChat discovers COOKIEFILE via PROTOCOLINFO."
echo "4. Safe check: systemctl is-active tor; ss -ltn | grep -E '9050|9051'; test -r /run/tor/control.authcookie"
echo ""
echo "Voice (optional): sudo apt install pipewire pipewire-pulse wireplumber alsa-utils"
echo "Stronger OPSEC: Tails or Qubes. See INSTALL.md / THREATMODEL.md"
echo "Done."
