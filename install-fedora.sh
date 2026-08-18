#!/usr/bin/env bash
# HashChat installer — Fedora. Rust only.
set -e
echo "=== HashChat Installer for Fedora (Rust) ==="
sudo dnf install -y gcc make pkg-config openssl-devel git curl
if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck source=/dev/null
  source "$HOME/.cargo/env"
fi
cargo build --release --locked --features tui --bin hashchat-tui
echo "Done. Run: ./run-tui"
echo "Audio (optional): sudo dnf install pipewire-utils alsa-utils"
