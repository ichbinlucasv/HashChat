#!/usr/bin/env bash
#
# HashChat - Unified Normal User Installer (one entry point)
# Detects OS and runs the right steps or gives exact one-liners.
# Primary: Nix for reproducibility (recommended for all).
# Falls back to per-distro install-*.sh .
#
# Usage (from cloned repo):
#   chmod +x install.sh
#   ./install.sh
#
# After:
#   ./run-tui
#
# Supports: Fedora, Ubuntu, Arch + guidance for Tails/Qubes.
# Always run clean-security.sh --strict for paranoid sessions.
# See INSTALL.md for full per-OS Desktop Runtime Notes.

set -e

echo "=== HashChat Unified Installer for Normal Users ==="
echo "Primary repo: https://codeberg.org/ichbinlucasv/HashChat (GitHub is mirror only)"
echo "Goal: Make it usable on Fedora / Ubuntu / Arch / Tails / Qubes with minimal expertise."
echo ""

# Detect
if [ -f /etc/os-release ]; then
  . /etc/os-release
  DISTRO_ID="${ID:-unknown}"
  DISTRO_LIKE="${ID_LIKE:-}"
else
  DISTRO_ID="unknown"
fi

echo "Detected: $DISTRO_ID (like: $DISTRO_LIKE)"
echo ""

# 1. Strongly recommend Nix path (reproducible, same on all)
echo "=== RECOMMENDED FOR ALL (reproducible, sandboxed) ==="
echo "  nix build .#hashchat-flatpak"
echo "  flatpak install --user result/hashchat-tui.flatpak"
echo "  flatpak run org.hashchat.HashChat"
echo ""
echo "Or for TUI only:"
echo "  nix build .#hashchat-tui"
echo "  ./result/bin/hashchat-tui   # or use the run-tui launcher"
echo ""

# Per OS fast path
case "$DISTRO_ID" in
  fedora)
    echo "=== Fedora fast path (normal user) ==="
    if [ -x ./install-fedora.sh ]; then
      echo "Running ./install-fedora.sh ..."
      chmod +x ./install-fedora.sh
      ./install-fedora.sh
    fi
    echo "Quick audio (voice): sudo dnf install pipewire-utils alsa-utils && systemctl --user restart pipewire"
    ;;
  ubuntu|debian)
    echo "=== Ubuntu/Debian fast path (normal user) ==="
    if [ -x ./install-ubuntu.sh ]; then
      echo "Running ./install-ubuntu.sh ..."
      chmod +x ./install-ubuntu.sh
      ./install-ubuntu.sh
    fi
    echo "Quick audio (voice): sudo apt install pipewire pipewire-pulse wireplumber alsa-utils && systemctl --user restart pipewire"
    ;;
  arch)
    echo "=== Arch fast path (normal user) ==="
    if [ -x ./install-arch.sh ]; then
      echo "Running ./install-arch.sh ..."
      chmod +x ./install-arch.sh
      ./install-arch.sh
    fi
    echo "Quick audio (voice): sudo pacman -S pipewire pipewire-pulse wireplumber alsa-utils && systemctl --user enable --now pipewire"
    ;;
  *)
    echo "=== Unknown / Tails / Qubes / other ==="
    echo "Use the per-OS notes in INSTALL.md"
    echo "Tails: Tor preconfigured. Use arecord fallback. No persist."
    echo "Qubes: Run in dedicated qube (Fedora template best). qvm-service audio. Use :set-proxy 127.0.0.1 9050 to sys-whonix."
    echo "Manual:"
    echo "  ./run-tui   # always try this first - it gives diagnostics"
    ;;
esac

echo ""
echo "=== Next steps for any OS (Normal User Quick Path) ==="
echo "1. Tor (critical):"
echo "   Fedora/Ubuntu/Arch: sudo systemctl start tor ; edit /etc/tor/torrc for ControlPort 9051 + CookieAuth ; restart"
echo "   Tails: preconfigured"
echo "   Qubes: sys-whonix + :set-proxy inside HashChat qube"
echo ""
echo "2. Run:"
echo "   ./run-tui"
echo "   It will print your audio backends (pw-record best) and Tor status."
echo ""
echo "3. Inside TUI (keyboard only, black+gold, explicit OPSEC):"
echo "   n           → new burner profile"
echo "   v           → record+send real voice (per-chunk ratchet + wipe)"
echo "   :filter foo → search / narrow contact list (NEW)"
echo "   /           → clear filter"
echo "   :status     → quick view (Proxy / Voice recorder / Posture)"
echo "   :my-contact → share link (then qrencode for QR if you want)"
echo "   ?           → full help + normal user quickstart"
echo "   w           → nuclear panic wipe (use it!)"
echo "   a           → contact actions (block, report, delete, disappear...)"
echo ""
echo "For maximum security: Tails live USB or Qubes disposable + full disk encryption + no swap."
echo "See INSTALL.md (detailed per-OS one-liners + hardening) and README.md (honest TUI vs Simplex GUI assessment)."
echo ""
echo "After any changes or before sensitive use: ./scripts/clean-security.sh --strict"
echo ""
echo "Done. Now run ./run-tui"
