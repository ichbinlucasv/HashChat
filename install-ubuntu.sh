#!/usr/bin/env bash
# HashChat installer — Ubuntu/Debian. Rust only.
set -e
echo "=== HashChat Installer for Ubuntu (Rust) ==="
sudo apt-get update -y
sudo apt-get install -y build-essential pkg-config libssl-dev git curl
if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck source=/dev/null
  source "$HOME/.cargo/env"
fi
cargo build --release --locked --features tui --bin hashchat-tui
echo "Done. Run: ./run-tui"
echo "Audio (optional): sudo apt install pipewire pipewire-pulse wireplumber alsa-utils"
