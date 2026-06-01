#!/bin/bash
# HashChat Fedora Desktop Screenshot Prep Helper
# For marketplace / Flathub / AppStream screenshots (black+gold theme, live posture, demos).
# Run on Fedora with Tor for authenticity, or HASHCHAT_DEMO=1 for pure UI shots.
#
# Usage:
#   chmod +x scripts/screenshot-prep-fedora.sh
#   HASHCHAT_DEMO=1 ./scripts/screenshot-prep-fedora.sh
#
# Then capture with:
#   grim -g "$(slurp)" hashchat-tui-main.png   # or gnome-screenshot -a
# Follow exact shots in docs/SCREENSHOTS.md

set -e

echo "=== HashChat Fedora Screenshot Prep ==="
echo "Theme: Black (#000) + Gold (#FFD700). Live Security Posture. Explicit OPSEC cues."
echo ""

# Ensure Tor (for real shots; demo skips full connect)
if ! systemctl is-active --quiet tor; then
  echo "Starting Tor (ControlPort 9051 required)..."
  sudo dnf install -y tor 2>/dev/null || true
  sudo systemctl enable --now tor || true
  # Quick torrc patch if needed (idempotent)
  if ! grep -q "ControlPort 9051" /etc/tor/torrc 2>/dev/null; then
    echo "ControlPort 9051" | sudo tee -a /etc/tor/torrc > /dev/null
    echo "CookieAuthentication 1" | sudo tee -a /etc/tor/torrc > /dev/null
    sudo systemctl restart tor || true
  fi
  sleep 3
fi

echo "Building TUI (Nix preferred for repro, or source)..."
if command -v nix &>/dev/null; then
  nix build .#hashchat-tui --no-link 2>/dev/null || echo "Nix build skipped (using source)"
else
  echo "Nix not found; using source build (ensure deps from install-fedora.sh)"
  ./build.sh tui || echo "Build may need manual deps"
fi

echo ""
echo "=== Screenshot Mode ==="
echo "Run with: HASHCHAT_DEMO=1 ./run-tui"
echo "This populates demo contacts (Alice/Bob/Support), messages showing posture/gold, active group, for clean marketplace shots."
echo ""
echo "Recommended Fedora capture (Wayland GNOME common):"
echo "  1. Run: HASHCHAT_DEMO=1 ./run-tui   (resize term to ~120x40+)"
echo "  2. For main shot: grim -g \"\$(slurp -o)\" hashchat-tui-main.png"
echo "  3. Trigger refusal (in low posture or edit temp): capture posture-refusal.png"
echo "  4. Voice: 'v' then playback -> voice-wipe.png"
echo "  5. Groups/QR: 'g' -> groups-qr.png"
echo "  6. Actions: 'a' -> actions-menu.png"
echo ""
echo "Optimize: optipng *.png or pngcrush"
echo "Upload to Codeberg releases or your host, then update flatpak/org.hashchat.HashChat.metainfo.xml <screenshots> with real https://... URLs."
echo "See docs/SCREENSHOTS.md for exact captions + OPSEC (burner, clean-security.sh before/after)."
echo ""
echo "For marketplace (Flathub/Fedora):"
echo "  - Submit Flatpak: nix build .#hashchat-flatpak ; flatpak install --user result/..."
echo "  - Icons: Rasterize scalable SVG (rsvg-convert -w 512 -h 512 ... > 512x512/apps/org.hashchat.HashChat.png)"
echo "  - Test on Fedora: dnf install flatpak; flatpak remote-add --if-not-exists flathub ..."
echo ""
echo "After shots: ./scripts/clean-security.sh --strict ; git add screenshots ; commit as Lucas to Codeberg."

# Optional: auto-run in demo for quick test (user can ctrl-c)
if [ "${AUTO_RUN:-0}" = "1" ]; then
  echo "Auto-running demo TUI (resize your terminal now)..."
  HASHCHAT_DEMO=1 ./run-tui || true
fi
