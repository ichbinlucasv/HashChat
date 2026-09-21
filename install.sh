#!/usr/bin/env bash
#
# HashChat — unified normal-user installer (Rust-first)
#
# Detects Fedora / Ubuntu / Arch and delegates to install-*.sh.
# Prints guidance for Tails / Qubes / other.
#
# Preferred desktop binary:
#   cargo build --release --bin hashchat-tui --features tui
#
# Usage (from repo root, branch codeberg-primary recommended):
#   ./install.sh
# Then:
#   ./run-tui
#
# OPSEC: does not print secrets, passphrases, Tor cookies, or key material.
#

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "=== HashChat Unified Installer (Rust-first) ==="
echo "Primary: https://codeberg.org/ichbinlucasv/HashChat"
echo "Active tip branch: codeberg-primary"
echo "Desktop: Rust TUI (hashchat-tui --features tui); Haskell is transitional fallback."
echo ""

if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO_ID="${ID:-unknown}"
  DISTRO_LIKE="${ID_LIKE:-}"
else
  DISTRO_ID="unknown"
  DISTRO_LIKE=""
fi

echo "Detected: ${DISTRO_ID} (like: ${DISTRO_LIKE})"
echo ""

echo "=== Recommended on all distros (reproducible Flatpak via Nix) ==="
echo "  nix build .#hashchat-flatpak"
echo "  flatpak install --user result/hashchat-tui.flatpak"
echo "  flatpak run org.hashchat.HashChat"
echo "Host Tor with ControlPort 9051 + CookieAuthentication is still required."
echo ""

run_distro() {
  local script="$1"
  chmod +x "$script"
  exec "$script"
}

case "$DISTRO_ID" in
  fedora)
    echo "=== Fedora path ==="
    run_distro ./install-fedora.sh
    ;;
  ubuntu|debian|linuxmint|pop)
    echo "=== Ubuntu/Debian family path ==="
    run_distro ./install-ubuntu.sh
    ;;
  arch|endeavouros|manjaro|garuda)
    echo "=== Arch family path ==="
    run_distro ./install-arch.sh
    ;;
  *)
    # ID_LIKE heuristics
    if echo " ${DISTRO_LIKE} " | grep -q ' fedora\| rhel\| centos '; then
      echo "=== Fedora-like path ==="
      run_distro ./install-fedora.sh
    elif echo " ${DISTRO_LIKE} " | grep -q ' debian\| ubuntu '; then
      echo "=== Debian-like path ==="
      run_distro ./install-ubuntu.sh
    elif echo " ${DISTRO_LIKE} " | grep -q ' arch '; then
      echo "=== Arch-like path ==="
      run_distro ./install-arch.sh
    fi

    echo "=== Tails / Qubes / other ==="
    echo "Tails: Tor is usually preconfigured. Prefer a copied Flatpak; avoid persistence."
    echo "Qubes: Build in a disposable (scripts/qubes-build.sh) or install Flatpak in the app qube;"
    echo "       route via sys-whonix; enable audio in the template if you need voice."
    echo ""
    echo "Manual Rust-first build (any Linux with cargo):"
    echo "  cargo build --release --locked --bin hashchat-tui --features tui"
    echo "  ./run-tui"
    echo ""
    echo "See INSTALL.md for per-OS Tor, audio, and hardening notes."
    echo "After sensitive work: ./scripts/clean-security.sh --strict"
    ;;
esac
