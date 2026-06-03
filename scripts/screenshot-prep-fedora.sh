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
echo "Use these envs for exact shots per docs/SCREENSHOTS.md (Phase 1: queues, I2P, file, Extreme):"
echo "  HASHCHAT_DEMO=main     ./run-tui   # Main chat with posture banner, demo messages (Alice/Bob), proxy/queue cues"
echo "  HASHCHAT_DEMO=refusal  ./run-tui   # Low posture + refusal banner (edit temp if needed for 'v'/'g')"
echo "  HASHCHAT_DEMO=voice    ./run-tui   # Input shows voice recording, ready for playback + wipe demo"
echo "  HASHCHAT_DEMO=groups   ./run-tui   # Active group + member list + QR hint"
echo "  HASHCHAT_DEMO=actions  ./run-tui   # actionPending=true for 'a' menu visible"
echo "  HASHCHAT_DEMO=extreme  ./run-tui   # [EXTREME] title, refusals, stripped (set via :extreme on before shot)"
echo "  HASHCHAT_DEMO=i2p      ./run-tui   # Proxy: 127.0.0.1:4444 (I2P after i2pd), multi-path note"
echo "  HASHCHAT_DEMO=file     ./run-tui   # :file active or file progress in chat (ratchet-chunked XFTP)"
echo "  HASHCHAT_DEMO=mesh     ./run-tui   # Phase2: local mesh peers visible, queue fallback, 'i' shows mesh queues"
echo "  HASHCHAT_DEMO=email    ./run-tui   # Phase2: :email inbox/send demo, I2P proxy note if set, ratchet persist"
echo "  HASHCHAT_DEMO=relay    ./run-tui   # Phase3: :relay announce/discover (self-host relay stub, queue sync)"
echo "  HASHCHAT_DEMO=channel  ./run-tui   # Phase3: public channel stub ( :channel or groups public, DHT/relay)"
echo "  # Phase1/2/3 queue observe (in any state): after ~60 sends or mesh/relay, press 'i' -> sendQ=... recvQ=... lastRot=... (rotation active, QROT processed)"
echo "  # X3DH: :add-contact with long-term link -> real bootstrap (queues init, ratchet from shared)"
echo "  # Starlink: :set-proxy or status shows Phase3 detect + failover; quantum feature for hybrid stubs; relay server: cabal run hashchat-relay"
echo "  # TABLE EXACT FOR PHOTOS (Critical blocker): HASHCHAT_DEMO=relay ./run-tui ; grim for relay/channel/Starlink/Tauri states; test nix build .#hashchat-tui ; run hashchat-relay in bg"
echo ""
echo "OPSEC: Run clean-security.sh --strict before/after. Resize terminal to 80x24 or consistent for repro shots. Use grim -g \"\$(slurp -o)\" or gnome-screenshot -a. Raster icons with rsvg-convert if needed (see flatpak/ICONS.md)."
echo "For real-device evidence: Use scripts/real-device-test.sh on Fedora/Tails (covers voice, groups, QR, posture/Extreme, proxy/I2P, file, wipe). Log dated results."
echo ""
echo "Run: HASHCHAT_DEMO=main ./run-tui   (resize term ~120x40+ for best shots)"
echo ""
echo "Recommended Fedora capture (Wayland GNOME):"
echo "  grim -g \"\$(slurp -o)\" hashchat-tui-main.png"
echo "  grim -g \"\$(slurp -o)\" hashchat-tui-posture-refusal.png"
echo "  grim -g \"\$(slurp -o)\" hashchat-tui-voice-wipe.png"
echo "  grim -g \"\$(slurp -o)\" hashchat-tui-groups-qr.png"
echo "  grim -g \"\$(slurp -o)\" hashchat-tui-actions.png"
echo "  grim -g \"\$(slurp -o)\" hashchat-tui-mesh.png   # Phase2 mesh peers + queue in 'i'"
echo "  grim -g \"\$(slurp -o)\" hashchat-tui-email.png  # Phase2 :email inbox + I2P note"
echo "  # For Phase1/2: after :file or many sends/mesh, capture with 'i' queue info visible (sendQ/recvQ/lastRot)"
echo ""
echo "In shots, look for [E2EE] badges on messages, live 'MAX PARANOID' posture, gold accents, proxy in title/status (shows E2EE + per-profile transport for marketplace)."
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

echo ""
echo "=== CRITICAL #1: EXACT COPY-PASTE COMMANDS TO GENERATE THE REQUIRED FEDORA PHOTOS/EVIDENCE LOGS (to unblock v0.2 signed tag + marketplace) ==="
echo "Run this on your real Fedora (with Tor/i2pd if possible). This covers ALL states from the priority table (main, refusal, voice, groups, actions, extreme, i2p, file, queues in 'i', Phase3: relay, channel, Starlink, quantum, Tauri, nix builds, relay server)."
echo ""
echo "STEP 1: Clean + build"
echo "  ./scripts/clean-security.sh --strict"
echo "  nix build .#hashchat-tui   # or ./build.sh tui"
echo ""
echo "STEP 2: Capture the exact marketplace photos (use grim or gnome-screenshot)"
echo "  # Resize terminal ~120x40 for consistent shots"
echo "  HASHCHAT_DEMO=main ./run-tui     # then grim -g \"\$(slurp -o)\" docs/evidence/hashchat-tui-main.png"
echo "  HASHCHAT_DEMO=refusal ./run-tui  # grim ... hashchat-tui-posture-refusal.png"
echo "  HASHCHAT_DEMO=voice ./run-tui    # grim ... hashchat-tui-voice-wipe.png"
echo "  HASHCHAT_DEMO=groups ./run-tui   # grim ... hashchat-tui-groups-qr.png"
echo "  HASHCHAT_DEMO=actions ./run-tui  # grim ... hashchat-tui-actions.png"
echo "  HASHCHAT_DEMO=extreme ./run-tui  # grim ... hashchat-tui-extreme.png"
echo "  HASHCHAT_DEMO=i2p ./run-tui      # grim ... hashchat-tui-i2p.png"
echo "  HASHCHAT_DEMO=file ./run-tui     # grim ... hashchat-tui-file.png"
echo "  HASHCHAT_DEMO=relay ./run-tui    # grim ... hashchat-tui-relay.png"
echo "  HASHCHAT_DEMO=channel ./run-tui  # grim ... hashchat-tui-channel.png"
echo "  # After ~60 msgs or mesh/relay: press 'i' in any demo and capture queue info visible"
echo "  grim -g \"\$(slurp -o)\" docs/evidence/hashchat-tui-queues-i.png"
echo ""
echo "STEP 3: Test Nix repro builds (Critical #2)"
echo "  nix build .#hashchat-tui"
echo "  nix build .#hashchat-flatpak"
echo "  # Capture: grim for nix build output if desired"
echo ""
echo "STEP 4: Test relay server (Phase3 table)"
echo "  cabal run hashchat-relay &   # in bg"
echo "  # Then in another term: HASHCHAT_DEMO=relay ./run-tui ; capture"
echo ""
echo "STEP 5: Run full real-device evidence log (covers table items + hardware tests)"
echo "  ./scripts/real-device-test.sh | tee docs/evidence/real-fedora-$(date +%Y-%m-%d).log"
echo "  # While running, also do the grim captures above for the photos."
echo ""
echo "STEP 6: Icons (if not done)"
echo "  sudo dnf install -y librsvg2-tools"
echo "  mkdir -p flatpak/icons/hicolor/{64x64,128x128,256x256,512x512}/apps"
echo "  for s in 64 128 256 512; do rsvg-convert -w \$s -h \$s flatpak/icons/hicolor/scalable/apps/org.hashchat.HashChat.svg > flatpak/icons/hicolor/\${s}x\${s}/apps/org.hashchat.HashChat.png; done"
echo ""
echo "STEP 7: Commit as Lucas (after clean)"
echo "  ./scripts/clean-security.sh --strict"
echo "  git add docs/evidence/ flatpak/org.hashchat.HashChat.metainfo.xml flatpak/icons/ screenshots/ 2>/dev/null || true"
echo "  git config user.name \"Lucas\""
echo "  git config user.email \"ichbinlucasv@noreply.codeberg.org\""
echo "  git commit -m 'Critical evidence: Fedora photos + logs for v0.2 unblock + marketplace (table states incl Phase3). Clean --strict. Lucas.'"
echo "  git push origin main"
echo ""
echo "STEP 8: Auto-generate evidence log template (run this to pre-fill with table items)"
echo "  ./scripts/real-device-test.sh | tee docs/evidence/real-fedora-$(date +%Y-%m-%d).log"
echo "  # Then manually fill the table section 18 with your observations from the grim captures above."
echo ""
echo "After you run the above on real hardware and commit/push the photos + logs, the Critical blocker is unblocked. Then we can mark the row 'DONE AND STABLE' and move to High items."
echo "See docs/REAL_DEVICE_TESTING.md and docs/SCREENSHOTS.md for more details."
echo "=== END EXACT COMMANDS ==="
echo "  2. Phase2 shots (mesh/email) after user 'continue' work: use HASHCHAT_DEMO=mesh/email + 'i' for queues visible + :email cmd in TUI for live ratchet/persist proof."
echo "  3. After capture: commit PNGs + logs to docs/evidence/ as Lucas, edit metainfo.xml with real URLs/captions, nix build + flatpak test, submit."
echo "  2. Screenshots using the HASHCHAT_DEMO= modes + grim (see capture commands above)."
echo "  3. Upload PNGs (to Codeberg releases or your host), then update flatpak/org.hashchat.HashChat.metainfo.xml <screenshots> with real https://... URLs (we prepped good Fedora-focused captions)."
echo "  4. Build/test: nix build .#hashchat-flatpak ; flatpak install --user result/hashchat-tui.flatpak ; flatpak run org.hashchat.HashChat"
echo "  5. Submit to Flathub (flathub.org/submit) — this gets it into Fedora (via Flathub) and many other distros. For native distro packages: the metainfo provides AppStream data."
echo "  See docs/SCREENSHOTS.md + flatpak/ICONS.md for full guidelines + OPSEC (always run ./scripts/clean-security.sh --strict before/after captures)."
echo ""
echo "After shots: ./scripts/clean-security.sh --strict ; git add your-screenshots ; git commit -m 'marketplace: add Fedora desktop screenshots' ; git push (as Lucas to Codeberg)."
echo ""
echo "For metainfo update snippet (copy to flatpak/org.hashchat.HashChat.metainfo.xml <screenshots>):"
echo "  Use your uploaded URLs for the 4 desktop + 1 Android (we prepped captions in the file)."
echo "  Example:"
echo "  <screenshot type=\"default\">"
echo "    <caption>Desktop TUI main chat (Fedora) with live Security Posture (MAX PARANOID) in black + #FFD700 gold theme. Demo contacts + explicit Tor v3 / Double Ratchet cues.</caption>"
echo "    <image>https://your-host/hashchat-tui-main.png</image>"
echo "  </screenshot>"
echo "  ... (add the others from the file)"
echo ""
echo "Then commit the metainfo update and push as Lucas."

# Optional: auto-run in demo for quick test (user can ctrl-c)
if [ "${AUTO_RUN:-0}" = "1" ]; then
  echo "Auto-running demo TUI (resize your terminal now)..."
  HASHCHAT_DEMO=1 ./run-tui || true
fi
