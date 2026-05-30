#!/usr/bin/env bash
# Build HashChat as Flatpak (Fedora-first, then other distros)
# This is the recommended long-term easy & sandboxed distribution method.

set -e

echo "=== Building HashChat Flatpak (Fedora first) ==="

if ! command -v flatpak-builder &> /dev/null; then
    echo "Please install flatpak-builder:"
    echo "  sudo dnf install flatpak-builder"
    exit 1
fi

# Ensure we have the required runtimes (one-time)
flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo 2>/dev/null || true
flatpak install -y flathub org.freedesktop.Platform//23.08 org.freedesktop.Sdk//23.08 2>/dev/null || true

cd "$(dirname "$0")/.."

flatpak-builder --force-clean build-dir flatpak/org.hashchat.HashChat.yml

echo ""
echo "=== Building distributable .flatpak bundle (installable) ==="
flatpak build-export --force export-dir build-dir
flatpak build-bundle --arch=$(uname -m) export-dir hashchat-tui.flatpak org.hashchat.HashChat

echo ""
echo "Build complete."
echo ""
echo "Installable bundle created: hashchat-tui.flatpak"
echo ""
echo "To install the bundle:"
echo "  flatpak install --user hashchat-tui.flatpak"
echo ""
echo "Run with: flatpak run org.hashchat.HashChat"
echo ""
echo "For repo-style install (after build):"
echo "  flatpak-builder --user --install build-dir flatpak/org.hashchat.HashChat.yml"
echo ""
echo "Fedora-first. For Qubes/Tails: copy the .flatpak into the target qube and install there."
echo "Full reproducible (pinned GHC + rustup inside sandbox) is the next hardening step."
