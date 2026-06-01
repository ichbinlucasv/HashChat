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
echo "=== Screenshot Mode (perfect for your Fedora photos) ==="
echo "Use these envs for exact shots per docs/SCREENSHOTS.md:"
echo "  HASHCHAT_DEMO=main     ./run-tui   # Main chat with posture banner, demo messages (Alice/Bob)"
echo "  HASHCHAT_DEMO=refusal  ./run-tui   # Low posture + refusal banner (edit temp if needed for 'v'/'g')"
echo "  HASHCHAT_DEMO=voice    ./run-tui   # Input shows voice recording, ready for playback + wipe demo"
echo "  HASHCHAT_DEMO=groups   ./run-tui   # Active group + member list + QR hint"
echo "  HASHCHAT_DEMO=actions  ./run-tui   # actionPending=true for 'a' menu visible"
echo ""
echo "Run: HASHCHAT_DEMO=main ./run-tui   (resize term ~120x40+ for best shots)"
echo ""
echo "Recommended Fedora capture (Wayland GNOME):"
echo "  grim -g \"\$(slurp -o)\" hashchat-tui-main.png"
echo "  grim -g \"\$(slurp -o)\" hashchat-tui-posture-refusal.png"
echo "  grim -g \"\$(slurp -o)\" hashchat-tui-voice-wipe.png"
echo "  grim -g \"\$(slurp -o)\" hashchat-tui-groups-qr.png"
echo "  grim -g \"\$(slurp -o)\" hashchat-tui-actions.png"
echo ""
echo "Optimize: optipng *.png"
echo "Upload to Codeberg releases (or your host), then replace example.com in flatpak/org.hashchat.HashChat.metainfo.xml with real URLs."
echo "See docs/SCREENSHOTS.md for exact captions + OPSEC (run ./scripts/clean-security.sh --strict before/after)."
echo ""
echo "Icons for marketplace (Flathub/Fedora + other distros - critical for submission):"
echo "  sudo dnf install -y librsvg2-tools"
echo "  mkdir -p flatpak/icons/hicolor/{64x64,128x128,256x256,512x512}/apps"
echo "  for s in 64 128 256 512; do rsvg-convert -w \$s -h \$s flatpak/icons/hicolor/scalable/apps/org.hashchat.HashChat.svg > flatpak/icons/hicolor/\${s}x\${s}/apps/org.hashchat.HashChat.png; done"
echo "  (The SVG is black+gold lock design; test PNGs on light/dark themes)"
echo ""
echo "For marketplace (Flathub primary for Fedora + other distros):"
echo "  1. Icons as above."
echo "  2. Screenshots using the HASHCHAT_DEMO= modes + grim (see capture commands above)."
echo "  3. Upload PNGs (to Codeberg releases or your host), then update flatpak/org.hashchat.HashChat.metainfo.xml <screenshots> with real https://... URLs (we prepped good Fedora-focused captions)."
echo "  4. Build/test: nix build .#hashchat-flatpak ; flatpak install --user result/hashchat-tui.flatpak ; flatpak run org.hashchat.HashChat"
echo "  5. Submit to Flathub (flathub.org/submit) — this gets it into Fedora (via Flathub) and many other distros. For native distro packages: the metainfo provides AppStream data."
echo "  See docs/SCREENSHOTS.md + flatpak/ICONS.md for full guidelines + OPSEC (always run ./scripts/clean-security.sh --strict before/after captures)."
echo ""
echo "After shots: ./scripts/clean-security.sh --strict ; git add your-screenshots ; git commit -m 'marketplace: add Fedora desktop screenshots' ; git push (as Lucas to Codeberg)."

# Optional: auto-run in demo for quick test (user can ctrl-c)
if [ "${AUTO_RUN:-0}" = "1" ]; then
  echo "Auto-running demo TUI (resize your terminal now)..."
  HASHCHAT_DEMO=1 ./run-tui || true
fi
