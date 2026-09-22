#!/usr/bin/env bash
#
# HashChat — Fedora installer (Rust-first desktop)
#
# Builds the native Rust TUI:
#   cargo build --release --locked --bin hashchat-tui --features tui
#
# Haskell desktop is transitional / not recommended
# (see INSTALL.md). Installers never build or prefer cabal.
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

echo "[6/6] Done. Haskell desktop is transitional / not recommended (skipped)."
echo "      Opt-in parity only: see INSTALL.md § Transitional Haskell desktop"
echo "      (HASHCHAT_ALLOW_HASKELL=1 / ./build.sh --haskell). Not a release path."

echo ""
echo "=== How to run ==="
echo "  ./run-tui"
echo "  # or: ./target/release/hashchat-tui"
echo ""
echo "=== Tor (required for the default anonymity path) ==="
echo "1. Edit /etc/tor/torrc (add; do not paste cookies here):"
echo "     SocksPort 9050"
echo "     ControlPort 9051"
echo "     CookieAuthentication 1"
echo "2. sudo systemctl enable --now tor && sudo systemctl restart tor"
echo "3. Cookie file is typically /run/tor/control.authcookie (HashChat reads COOKIEFILE via PROTOCOLINFO)."
echo "   Your user must be able to read it (often: usermod -aG tor \$USER, then re-login)."
echo "   Never cat/hexdump/paste cookie contents."
echo "4. Safe check: systemctl is-active tor; ss -ltn | grep -E '9050|9051'; test -r /run/tor/control.authcookie"
echo ""
echo "Stronger OPSEC: Tails (amnesic) or Qubes + Whonix. See INSTALL.md / THREATMODEL.md / SECURITY.md"
echo "Done."
