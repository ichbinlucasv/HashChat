#!/usr/bin/env bash
#
# HashChat - Easy installation script for Arch Linux
# Adapted for normal users on rolling release. Prefer Nix when possible for reproducibility.
#
# Usage:
#   chmod +x install-arch.sh
#   ./install-arch.sh
#
# After installation:
#   ./run-tui
#

set -e

echo "=== HashChat Installer for Arch Linux ==="
echo ""

# 1. Update system
echo "[1/7] Updating system packages..."
sudo pacman -Syu --noconfirm

# 2. Install build dependencies
echo "[2/7] Installing build dependencies (Rust, Haskell, system libs)..."
sudo pacman -S --noconfirm --needed \
    base-devel \
    pkg-config \
    openssl \
    ncurses \
    libffi \
    zlib \
    git \
    curl

# Install Rust (if not present)
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Install Haskell via ghcup (strongly recommended on Arch over pacman ghc)
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
cabal build -f-tui hashchat-tui || echo "[WARN] TUI build may need extra steps on Arch. Try ./run-tui later."

echo "[7/7] Installation complete!"

echo ""
echo "=== How to run HashChat ==="
echo "  ./run-tui                 # Recommended launcher (shows audio/Tor status)"
echo ""
echo "=== Important for Arch ==="
echo "- Rolling release: Use ghcup for stable GHC/Cabal pins (pacman ghc can be too new/old)."
echo "- Audio for voice: sudo pacman -S pipewire pipewire-pulse wireplumber alsa-utils"
echo "- For reproducibility: Strongly prefer nix build .#hashchat-flatpak"
echo "- See INSTALL.md for full per-OS notes (especially Tails/Qubes)."
echo ""
echo "For maximum security: Run inside Tails or Qubes OS."
