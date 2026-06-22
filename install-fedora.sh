#!/usr/bin/env bash
#
# HashChat - Easy installation script for Fedora
# (Also useful as reference for Ubuntu/Arch users — adapt package names)
#
# For normal users on other distros:
# - Prefer the unified: chmod +x install.sh && ./install.sh   (detects + recommends Nix)
# - Ubuntu: See INSTALL.md "Normal User Quick Path" + the new audio one-liners
# - Arch:   Prefer Nix or adapt this script (pacman equivalents)
# - Tails/Qubes: Use the dedicated qubes-build.sh or copy a pre-built Flatpak
#
# Usage:
#   chmod +x install-fedora.sh
#   ./install-fedora.sh
#
# After installation:
#   ./run-tui
#

set -e

echo "=== HashChat Installer for Fedora ==="
echo ""

# 1. Update system
echo "[1/7] Updating system packages..."
sudo dnf update -y

# 2. Install build dependencies
echo "[2/7] Installing build dependencies (Rust, Haskell, system libs)..."
sudo dnf install -y \
    gcc \
    make \
    pkg-config \
    openssl-devel \
    ncurses-devel \
    libffi-devel \
    zlib-devel \
    git \
    curl

# Install Rust (if not present)
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Install Haskell (GHC + Cabal)
if ! command -v ghc &> /dev/null; then
    echo "Installing GHC and Cabal via dnf..."
    sudo dnf install -y ghc ghc-Cabal cabal-install
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
cabal build -f-tui hashchat-cli || echo "[WARN] CLI build had issues (may still work for TUI)"
cabal build -f-tui hashchat-tui || {
  echo "[WARN] TUI build had issues."
  echo "       For best results on Fedora use the Nix path: nix build .#hashchat-flatpak"
  echo "       Or ensure ghc/cabal are recent and vty/brick are resolvable."
}

echo "[7/7] Installation complete!"

echo ""
echo "=== How to run HashChat ==="
echo "  ./run-tui                 # Recommended launcher (sets LD_LIBRARY_PATH)"
echo "After run: 'n' burner, 'v' voice (real), :filter alice (search contacts), :status , :my-contact (QR link)"
echo ""
echo "=== Important: Tor Setup (Required for full anonymity) ==="
echo "1. Install Tor:"
echo "   sudo dnf install tor"
echo ""
echo "2. Enable ControlPort (edit /etc/tor/torrc):"
echo "   Add these lines:"
echo "   ControlPort 9051"
echo "   CookieAuthentication 1"
echo ""
echo "3. Restart Tor:"
echo "   sudo systemctl enable --now tor"
echo ""
echo "4. (Optional but recommended) Run HashChat inside Tails or Qubes OS for maximum security."
echo ""
echo "After Tor is running, start HashChat with: ./run-tui"
echo ""
echo "For the most paranoid setup, see THREATMODEL.md and SECURITY.md"
echo ""
echo "=== For Fedora Marketplace / Flathub screenshots (your request) ==="
echo "  HASHCHAT_DEMO=1 ./scripts/screenshot-prep-fedora.sh"
echo "  (Pops demo state with posture banner, groups, voice cues in black+gold. Use grim/gnome-screenshot for 4-5 shots per docs/SCREENSHOTS.md)"
echo "  Then raster icons: rsvg-convert -w 512 -h 512 flatpak/icons/hicolor/scalable/apps/org.hashchat.HashChat.svg > flatpak/icons/hicolor/512x512/apps/org.hashchat.HashChat.png (and 64/128/256)"
echo "  Update flatpak/org.hashchat.HashChat.metainfo.xml with your real image URLs."
echo "  Test Flatpak: nix build .#hashchat-flatpak ; flatpak install --user result/hashchat-tui.flatpak"
echo "  Submit to Flathub (Fedora users get it); for other distros use AppStream or package."
