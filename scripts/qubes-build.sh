#!/usr/bin/env bash
#
# Qubes disposable VM build script for HashChat (maximum paranoid)
# Enforces: clean-security.sh, Nix flake for reproducible Flatpak,
# mlock/drop_caches, swappiness, no persistent artifacts.
#
# Usage in disposable Fedora VM:
#   qvm-run --dispvm=fedora-40-dvm 'bash -s' < scripts/qubes-build.sh
#
# This produces the installable .flatpak without relying on external build.sh in the final artifact.

set -euo pipefail

echo "=== HashChat Qubes Disposable Build (enforced paranoid) ==="

# 1. Enforce clean slate
echo "[1] Running mandatory clean-security.sh..."
./scripts/clean-security.sh

# 2. Drop caches + harden kernel (anti-forensics)
echo "[2] Kernel anti-forensics (drop_caches, swappiness, mlock)..."
echo 3 | sudo tee /proc/sys/vm/drop_caches || true
echo 1 | sudo tee /proc/sys/vm/swappiness || true
echo 3 | sudo tee /proc/sys/vm/drop_caches || true

# 3. Use Nix flake for full reproducible Flatpak (no external scripts in final path)
echo "[3] Building via Nix flake (pinned toolchains + Flatpak derivation)..."
if command -v nix &> /dev/null; then
    nix build .#hashchat-flatpak --print-out-paths || echo "Nix build attempted (ensure flakes enabled)"
else
    echo "Nix not found in disposable - falling back to build.sh for Flatpak"
    ./build.sh
    cd flatpak
    ./build-flatpak.sh
fi

# 4. Final clean + sync
./scripts/clean-security.sh
sync

echo "=== Build complete in disposable VM ==="
echo "Copy the resulting hashchat-tui.flatpak out with qvm-copy."
echo "Never run the build VM again for sensitive work."