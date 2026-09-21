#!/usr/bin/env bash
#
# HashChat — Arch Linux installer (Rust-first desktop)
#
# Builds: cargo build --release --locked --bin hashchat-tui --features tui
# Prefer Nix/Flatpak when you need bit-for-bit reproducibility.
# Haskell remains a transitional fallback (INSTALL.md).
#
# Usage:
#   ./install-arch.sh
# Then:
#   ./run-tui
#
# OPSEC: does not print secrets, passphrases, Tor cookies, or key material.
#

set -euo pipefail

echo "=== HashChat Installer for Arch Linux (Rust-first) ==="
echo "Branch tip: codeberg-primary (Codeberg primary repo)"
echo ""

if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

echo "[1/6] Updating system packages..."
sudo pacman -Syu --noconfirm

echo "[2/6] Installing build + Tor dependencies..."
sudo pacman -S --noconfirm --needed \
  base-devel \
  pkg-config \
  openssl \
  ncurses \
  libffi \
  zlib \
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
echo "      Rolling Arch: prefer ghcup if you still need the Brick TUI."
echo "      ./run-tui uses Haskell only if the Rust binary is missing."

echo ""
echo "=== How to run ==="
echo "  ./run-tui"
echo "  # or: ./target/release/hashchat-tui"
echo ""
echo "=== Tor (required for the default anonymity path) ==="
echo "1. Edit /etc/tor/torrc — add SocksPort 9050, ControlPort 9051, CookieAuthentication 1"
echo "2. sudo systemctl enable --now tor && sudo systemctl restart tor"
echo "3. Cookie typically /run/tor/control.authcookie; ensure your user can read it (tor group as needed)."
echo "   Never cat/hexdump/paste cookie contents. HashChat discovers COOKIEFILE via PROTOCOLINFO."
echo "4. Safe check: systemctl is-active tor; ss -ltn | grep -E '9050|9051'; test -r /run/tor/control.authcookie"
echo ""
echo "Voice (optional): sudo pacman -S pipewire pipewire-pulse wireplumber alsa-utils"
echo "Reproducible path: nix build .#hashchat-flatpak"
echo "Stronger OPSEC: Tails or Qubes. See INSTALL.md / THREATMODEL.md"
echo "Done."
