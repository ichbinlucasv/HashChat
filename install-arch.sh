#!/usr/bin/env bash
# HashChat installer — Arch. Rust only.
set -e
echo "=== HashChat Installer for Arch Linux (Rust) ==="
sudo pacman -S --noconfirm --needed base-devel pkg-config openssl git curl
if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck source=/dev/null
  source "$HOME/.cargo/env"
fi
cargo build --release --locked --features tui --bin hashchat-tui
echo "Done. Run: ./run-tui"
echo "Audio (optional): sudo pacman -S pipewire pipewire-pulse wireplumber alsa-utils"
