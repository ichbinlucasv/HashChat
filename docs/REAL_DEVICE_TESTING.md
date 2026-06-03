# Real Device & Paranoid Environment Testing Guide

**Status**: Active — Required for v0.2  
**Critical for**: Signed v0.2 tag (see RELEASE_PROCESS.md and TESTING_EVIDENCE logs)

This document provides **concrete procedures** for the hard requirement of real hardware + Tails/Qubes testing before any v0.2 release.

## Why This Matters

Emulators and developer machines are insufficient for a maximum-paranoid messenger. Real testing on:
- Tails (live USB)
- Qubes OS
- Hardened Android (GrapheneOS / CalyxOS on physical Pixels)
- Airgapped or near-airgapped setups

...is mandatory to validate posture, wipe, voice, and metadata resistance under realistic conditions.

## Minimum Required Test Environments (Before v0.2)

1. **Tails 6.x** (live USB, disposable) — at least one full session
2. **Qubes OS 4.2+** — dedicated AppVM for testing
3. **Physical Android device** (GrapheneOS or CalyxOS preferred, no Google services)
4. Optional but recommended: One airgapped/offline machine for wipe + ratchet export tests

## How to Generate Required Evidence (Fedora photos / marketplace + Phase 1)

**Verbatim exact commands for "user Fedora photos/evidence via scripts" (Critical for v0.2 signed tag + Flathub/Fedora Apps marketplace)**:

```bash
# 1. Prep + icons (black+gold SVG raster for all sizes)
sudo dnf install -y grim slurp gnome-screenshot librsvg2-tools optipng tor
./scripts/clean-security.sh --strict
HASHCHAT_DEMO=main ./scripts/screenshot-prep-fedora.sh   # or direct build/run

# 2. Capture 5+ exact demo states (resize terminal ~120x40+ for repro; black bg + gold accents + live posture/proxy/Extreme/queue visible)
HASHCHAT_DEMO=main ./run-tui     # main chat: posture 'MAX PARANOID', Proxy: if set, gold bubbles, Tor/Double Ratchet cues
# in TUI: 'i' for security info -> observe "sendQ=... recvQ=... lastRot=..." (Phase1 simplex queue rotation)
grim -g "$(slurp -o)" hashchat-tui-main-fedora.png

HASHCHAT_DEMO=refusal ./run-tui  # posture refusal banner for 'v'/'g' (LOW or forced)
grim -g "$(slurp -o)" hashchat-tui-refusal-fedora.png

HASHCHAT_DEMO=voice ./run-tui    # 'v' record (demo), playback, wipe feedback visible
grim -g "$(slurp -o)" hashchat-tui-voice-wipe-fedora.png

HASHCHAT_DEMO=groups ./run-tui   # 'g' groups + QR long-term ed25519 (from :my-contact real LongTerm)
grim -g "$(slurp -o)" hashchat-tui-groups-qr-fedora.png

HASHCHAT_DEMO=actions ./run-tui  # 'a' or extreme: actions + [EXTREME] title + refusals visible
# or inside: :extreme on ; :set-proxy 127.0.0.1 4444 (I2P Phase1); :file /tmp/test.bin (XFTP chunks)
grim -g "$(slurp -o)" hashchat-tui-actions-extreme-i2p-file-fedora.png

# 3. Real evidence log (Phase1 coverage: I2P, queue rot, file, Extreme, QR, voice, wipe, posture on Fedora/Tails + Android)
./scripts/real-device-test.sh | tee "docs/evidence/real-fedora-$(date +%Y-%m-%d)-$(git rev-parse --short HEAD).log"
# Inside guided: test :set-proxy for I2P, send ~60 msgs to rotate (see QROT + 'i' queues), :file XFTP, :extreme on + refusals, voice, :my-contact QR (longterm), 'w' wipe, posture, on physical + Tails/Qubes. Power clean.

# 4. Icons (for Flathub/Fedora marketplace)
mkdir -p flatpak/icons/hicolor/{64x64,128x128,256x256,512x512}/apps
for s in 64 128 256 512; do
  rsvg-convert -w $s -h $s flatpak/icons/hicolor/scalable/apps/org.hashchat.HashChat.svg > flatpak/icons/hicolor/${s}x${s}/apps/org.hashchat.HashChat.png
done

# 5. Post-capture (user): upload PNGs (Codeberg releases / your host), edit flatpak/org.hashchat.HashChat.metainfo.xml (replace example.com + use captions), test Flatpak, submit Flathub (for Fedora Apps + other distros)
# Then: git add docs/evidence/ *.png flatpak/...metainfo.xml flatpak/icons/... ; ./scripts/clean-security.sh --strict ; git config user.name "Lucas"; git config user.email "ichbinlucasv@noreply.codeberg.org"; git commit -m 'marketplace: Fedora photos + evidence logs via scripts (Phase1 I2P/file/queues/Extreme)'; git push origin main
```

Use the helper script for guided log:

```bash
./scripts/real-device-test.sh
```

This creates a dated evidence log in `docs/evidence/`. (Now includes Phase1 I2P/queue/file/Extreme steps in the REAL doc + script guidance.)

**Every real test run must produce one of these logs** with:
- Exact date + commit hash
- Environment description
- Pass/fail per test area
- Honest observations and issues found

These logs are part of the pre-tag audit trail.

## Detailed Test Procedures

### Tails Live USB Session (High Value)

1. Boot Tails from USB (persistent storage disabled for max paranoia test).
2. Connect to Tor.
3. Clone or copy HashChat.
4. Run `./scripts/clean-security.sh --strict`.
5. Build or install the TUI.
6. Run `./run-tui`.
7. Perform the test areas from the evidence template (especially voice recording, nuclear wipe, posture, groups).
8. After session, power off the machine without saving persistence if possible.

**Key things to verify on Tails**:
- No data survives clean reboot + shutdown.
- Tor hidden service starts and works.
- Wipe is fast and thorough.
- No obvious logs left in `/tmp`, `~/.cache`, or `~/.local`.

### GrapheneOS / CalyxOS on Physical Pixel (Highest Value)

**Preparation**:
- Use a dedicated test device if possible (not your daily driver).
- Enable USB debugging + `adb`.
- Install HashChat debug build.

**Critical tests on real Android**:
- Voice recording + playback + post-playback wipe (check with `adb shell` or file manager for leftover audio).
- Biometric + Keystore ratchet unlock behavior.
- Posture detection (attach debugger, enable airplane mode, test refusals).
- Nuclear wipe button — verify `groups.enc`, ratchet blobs, and temp voice files are gone.
- Group creation + QR join from another device.
- Cross-device ratchet export (if testing that feature).

**Verification commands**:
```bash
adb logcat | grep -i hashchat

### Phase 1 Additions: I2P / Queues / File / Extreme (Fedora/Tails + Android)

### Phase 2 Additions (post "continue" mesh full + email full): Mesh peer sync + Email DHT (Fedora/Tails + Android)
- Run on real Fedora (or Tails): start i2pd for email if testing I2P, local net for mesh (UDP 12345).
- TUI:
  - Mesh: discoverLocalMeshPeers (or :discover), send msg (fallback + QROT over mesh), press 'i' after sends to see sendQ/recvQ/lastRot for mesh contact, simulate reconnect (profile switch or restart) to observe drain + ratchet advance.
  - Email: :email inbox (see load/poll + ratchet), :email send pseudo msg (ratchet + persist to emails/*.enc), set I2P proxy first for garlic note.
  - Observe: queues persist across, QROT in mesh/email paths, Extreme refusals for DHT.
- Android: actions "Mesh local peers" + "Email inbox" + "Add contact (X3DH)" - verify queues init, processor feeds, FFI ratchet calls.
- Log: use real-device-test.sh (now has sections 14/15) | tee docs/evidence/real-fedora-YYYY-MM-DD.log
- Photos (screenshot-prep-fedora.sh): HASHCHAT_DEMO=mesh ./run-tui + grim for mesh+ 'i' queues; HASHCHAT_DEMO=email for :email.
- Commit: logs + PNGs + metainfo update as Lucas.
- This unblocks v0.2 signed tag + Flathub/Fedora marketplace (Critical blocker).

See scripts/ for exact cmds, ROADMAP for "continue" status.
- I2P: On Fedora (after i2pd), :set-proxy 127.0.0.1 4444 ; send message; verify "Proxy: ...4444" in title + garlic routing (no Tor leak if configured). Log proxy use.
- Queues (simplex): In TUI, send ~60 msgs to trigger rotate (see [QUEUE] logs + QROT frames in receive); check 'i' for queue ids + lastRot; verify decoys + announcements in logs without breaking ratchet.
- File (XFTP): :file /tmp/test.bin (large demo); verify ratchet-chunked send (per-chunk logs, framed cts), progress, receive side reassemble + wipe. On Android: use file send demo, check FFI chunks + proxy if set.
- Extreme: :extreme on ; verify [EXTREME] title, refusals for groups/voice/export/decoy/QR, cleared state, Tor-only. Test on Tails (strict posture).
- Cross: On real device, test I2P proxy set + file send + queue rotate (if visible in logs) + Extreme toggle. Use real-device-test.sh sequences.

Update your dated log with these (template in docs/evidence/). Power off clean. Run clean-security.sh --strict before/after.
adb shell pm clear <package>
adb shell ls /data/data/<package>/files/   # check what survives wipe
```

### Qubes OS Testing

- Use a disposable or dedicated AppVM.
- Route all network through a TorVM or sys-whonix.
- Test both the Flatpak and native build paths.
- Verify that the app cannot see host filesystem or other VMs without explicit permission.

## Test Area Priority (v0.2 Focus)

1. **Voice completeness** (highest priority)
2. **Nuclear wipe effectiveness**
3. **Posture refusals in real environments**
4. **Groups + QR join under Strict/Extreme mode**
5. **Contact QR / ContactAddress flows**
6. **Cross-device ratchet export + source wipe** (if applicable)
7. **Profile switching + decoy behavior**

## Evidence Log Requirements (Hard Gate)

Before any signed `v0.2` tag, there must exist at least one dated evidence log showing:
- Successful run on **Tails or Qubes**
- Successful run on **physical Android device**
- Honest notes on what worked / what still needs work

The `scripts/real-device-test.sh` tool exists to make this easy and consistent.

## Updating This Document

When you complete a real test session:
1. Fill the generated evidence log.
2. If you discover better commands or procedures, update this file.
3. Commit both the evidence log and any doc improvements.

---

**This document + the helper script directly address the expert requirement for regular, documented real-hardware testing.**