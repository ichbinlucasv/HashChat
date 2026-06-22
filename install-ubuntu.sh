#!/usr/bin/env bash
#
# HashChat - Easy installation script for Ubuntu (22.04+ / 24.04+ recommended)
# Adapted for normal users. See INSTALL.md for Tails/Qubes/Arch/Fedora notes.
# Unified entry: chmod +x ../install.sh && ../install.sh  (from repo root)
#
# Usage:
#   chmod +x install-ubuntu.sh
#   ./install-ubuntu.sh
#
# After installation:
#   ./run-tui
#

set -e

echo "=== HashChat Installer for Ubuntu ==="
echo ""

# 1. Update system
echo "[1/7] Updating system packages..."
sudo apt update -y
sudo apt upgrade -y

# 2. Install build dependencies
echo "[2/7] Installing build dependencies (Rust, Haskell, system libs)..."
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libncurses5-dev \
    libffi-dev \
    zlib1g-dev \
    git \
    curl

# Install Rust (if not present)
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Install Haskell via ghcup (recommended over apt ghc for this project)
if ! command -v ghc &> /dev/null; then
    echo "Installing GHC and Cabal via ghcup (recommended)..."
    curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org | sh
    source "$HOME/.ghcup/env"
fi

echo "[3/7] Rust and Haskell toolchains ready."

# 4. Build Rust library
echo "[4/7] Building Rust FFI library (release)..."
cargo build --release

# 5. Stage the Rust library
echo "[5/7] Staging Rust library..."
mkdir -p rust-lib
cp target/release/libhashchat_rust.so rust-lib/ || true

# 6. Build Haskell parts
echo "[6/7] Building Haskell components..."
cabal update
cabal build -f-tui hashchat-cli
cabal build -f-tui hashchat-tui || echo "[WARN] TUI build may need extra steps. Try ./run-tui later."

echo "[7/7] Installation complete!"

echo ""
echo "=== How to run HashChat ==="
echo "  ./run-tui                 # Recommended launcher (shows audio/Tor status)"
echo "After: n=burner, v=voice, :filter term=search contacts, :status, :my-contact for shareable QR link"
echo ""
echo "=== Important for your OS ==="
echo "- Ubuntu: Use ./run-tui first — it will show PipeWire/Pulse/ALSA status for voice."
echo "- For audio (voice): sudo apt install pipewire pipewire-pulse wireplumber alsa-utils"
echo "- See INSTALL.md for full per-OS notes (Tails/Qubes/Arch/Fedora too)."
echo ""
echo "For maximum security: Run inside Tails or Qubes OS."
