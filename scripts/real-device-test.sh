#!/bin/bash
# HashChat Real Device + Tails/Qubes Testing Helper
# Critical for v0.2: This helps generate the required dated evidence logs.
#
# Usage:
#   ./scripts/real-device-test.sh
#
# This script does NOT run tests automatically (too dangerous on real hardware).
# It guides you through the required test areas and creates a dated evidence log.

set -e

EVIDENCE_DIR="docs/evidence"
mkdir -p "$EVIDENCE_DIR"

DATE=$(date +%Y-%m-%d)
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LOG_FILE="$EVIDENCE_DIR/real-hardware-${DATE}-${COMMIT}.md"

echo "=== HashChat Real Hardware Testing Evidence Log ==="
echo "Date: $DATE"
echo "Commit: $COMMIT"
echo ""
echo "This will create: $LOG_FILE"
echo ""
read -p "Press Enter to begin guided test session (or Ctrl+C to cancel)..."

cat > "$LOG_FILE" << EOF
# HashChat Real Hardware Test Evidence
**Date:** $DATE  
**HashChat Commit:** $COMMIT  
**Tester:** $(whoami)  
**Environment:**

- OS / Distro: 
- Device (phone model / laptop):
- Security context (Tails live, Qubes AppVM, GrapheneOS, stock, etc.):
- Tor version / status:
- HashChat build method (Flatpak, nix, ./build.sh, etc.):

---

## Test Areas Performed

### 1. Voice Completeness (Critical)
- [ ] Real mic recording works
- [ ] Audio sent over Tor (if possible)
- [ ] Playback with seek bar works
- [ ] Voice file wiped after playback (check cache)
- Observations / timing:
- Issues found:

### 2. Posture Refusals (High)
- [ ] Strict mode blocks voice / groups / export when expected
- [ ] Airplane mode / debugger / container detection works
- Observations:
- Issues found:

### 3. Nuclear Wipe (Critical)
- [ ] Panic wipe ('w' key or button) completes
- [ ] Ratchet state destroyed (memory + storage)
- [ ] groups.enc and other sensitive files gone
- [ ] Tor hidden service keys wiped
- Time taken:
- Observations:

### 4. Groups + QR (High)
- [ ] Create group + add member via QR
- [ ] Sender-key forward secrecy observed (if testable)
- [ ] Group persistence survives restart (with real Keystore)
- Issues found:

### 5. Contact QR / ContactAddress
- [ ] Generate and share contact link
- [ ] Other side can connect
- [ ] No private material leaks in QR
- Observations:

### 6. Cross-device Ratchet Export (if applicable)
- [ ] Export ratchet to second device
- [ ] Import works and forward secrecy preserved
- [ ] Source device wipes after export
- Observations:

### 7. General OPSEC / Cleanup
- [ ] Ran \`./scripts/clean-security.sh\` before session
- [ ] No obvious sensitive data left in /tmp or cache
- [ ] App behaves correctly after profile switch / decoy

### 8. Extreme Mode (if tested - Critical/Strategic)
- [ ] Extreme enabled (via :extreme on or Android toggle)
- [ ] Groups/voice/export/decoy refused (hard, no menu or error)
- [ ] Posture shows EXTREME, no long-term contact/QR exposure
- [ ] Aggressive wipes, no history persistence
- Observations:

### 9. Per-profile Proxy (High #4 - if tested)
- [ ] :set-proxy <host> <port> (e.g. I2P 4444)
- [ ] Persisted (check hashchat_data/proxies/)
- [ ] Used in send (visible in title/status)
- [ ] Extreme refuses custom
- Observations:

### 10. I2P (High #5 - if tested)
- [ ] i2pd running, :set-proxy 127.0.0.1 4444
- [ ] Send works over I2P SOCKS
- Observations:

### 11. Fedora Desktop Test (for marketplace photos + evidence)
- [ ] Run with HASHCHAT_DEMO=1 ./run-tui or prep script
- [ ] Capture shots: main (E2EE badges, posture, proxy), refusal, voice wipe, groups, actions
- [ ] Icons rasterized with rsvg-convert
- [ ] OPSEC: clean-security before/after
- Observations / photos taken:

### 12. Phase 1 Simplex Queues + Rotation (TUI + Android - Critical for metadata win)
- [ ] In TUI: send ~55-70 messages; observe [QUEUE] rotate logs + QROT: announce frames
- [ ] Press 'i' (security info): verify sendQ=... recvQ=... lastRot=... visible and advancing
- [ ] Decoys injected (padding correlation resistance)
- [ ] On receive: "Peer rotated queues (simplex announce)" or QROT processed
- [ ] Android: send multiple, check logs for rotateQueueForContact + QROT in general processor
- [ ] Extreme: queues still gated/refused when on
- Observations:

### 13. Phase 1 XFTP File Transfer (ratchet-chunked resumable E2EE >1GB path)
- [ ] TUI: :file /tmp/test.bin (or large); observe per-chunk ratchet encrypt + frame + progress + send
- [ ] Receive side: chunks reassembled, decrypt, final wipe notes
- [ ] Android: actions file send demo; verify encryptFileChunk FFI calls + framed + proxyNote
- [ ] Proxy/I2P: file send uses current proxy (if set)
- [ ] Extreme gate: file refused or noted when Extreme on
- Observations / sizes tested:

### 14. Phase 2 Mesh full peer sync + queue drain (UDP local discovery, Briar-style, QROT over mesh)
- [ ] TUI: peers <- discoverLocalMeshPeers (UDP 12345 bcast/recv exercised)
- [ ] Send msg when mesh peer visible: fallback sendOverMesh + queue rotate + QROT announce over mesh
- [ ] Drain: receiveFromMeshPeers + processMeshIncoming (unframe, ratchet recv, QROT handling, queue persist, messages saved)
- [ ] Reconnect/profile switch: syncMeshQueues called, queues drain to ratchets
- [ ] 'i' shows queues advancing for mesh contact; Extreme gates mesh if on
- [ ] Android: mesh action discovers + rotate/getSend for mesh-peer + note on sync/drain parity
- Observations (local net / BT sim / WiFi Direct):

### 15. Phase 2 Email DHT MVP (I2P-Bote style, real ratchet + persist, unlimited pseudos)
- [ ] TUI: :email inbox (loads persisted, polls with real receiveEmail ratchet path)
- [ ] :email send <pseudo> <msg> (real ratchet or contact, sendEmailOverRatchet, outbox persist)
- [ ] I2P: after :set-proxy 127.0.0.1 4444 + i2pd, poll/send uses hybrid note
- [ ] Persist: hashchat_data/emails/<pseudo>.log.enc exists (Argon2+AES like ratchets)
- [ ] Android: email action uses ratchetNew + receive FFI + feeds general processor (QROT/text parity)
- [ ] Extreme: refuses or notes high surface for DHT
- Observations (ratchet steps, files created, I2P if tested):

### 16. Phase 3 Starlink / Resilience + Self-host Relay (offline-first, paid hosting)
- [ ] Tor: detectStarlinkOrPreferred called (scans for sat interfaces)
- [ ] :relay announce / discover / send (uses Relay module, queue tie-in, stub cts)
- [ ] Relay self-host: announce presence, queue sync for mesh/Tor failover
- [ ] Extreme: refuses relay/Starlink surface (Tor primary only)
- [ ] Observations (Starlink detect log, relay peers, paid notes in help)

### 17. Phase 3 Quantum + Public Channels (gated, stubs)
- [ ] Quantum: --features quantum builds, hybrid_kex/hybrid_ratchet_new available (FFI stub)
  - :quantum cmd in TUI: test hybrid kex (real X25519 part now), observe FFI call + output (Extreme refuses)
- [ ] Public channels: :channel or group public mode (DHT/relay stub, observer/broadcast)
- [ ] Notes in security info or help
- Observations (feature gate, stubs functional)

### 18. High Priority Table Items (Deeper Phase3 from user table) - EXACT CMDS FOR YOUR FEDORA RUN
- [ ] Nix/Flake repro: nix develop ; nix build .#hashchat-flatpak ; nix build .#hashchat-tui (test full repro builds, Android .so via android/build-android.sh if NDK)
- [ ] Relay server binary: cabal run hashchat-relay (test announce/queue sync, self-host for paid)
- [ ] Starlink failover: :set-proxy or send msgs; check logs for [STARLINK] detect + failover in send/voice/file (Extreme disables)
- [ ] Public channel UI: :channel create testchan ; :channel post ... ; observe in TUI + Group
- [ ] Tauri GUI: cd tauri/src-tauri ; cargo tauri dev (or build; test FFI for Phase3 features, strict caps)
- [ ] Full Tauri app notes: test FFI calls for send/recv/wipe/posture/quantum/Extreme/relay (no direct net/fs in JS)
- CAPTURE FOR PHOTOS/EVIDENCE (CRITICAL - MUST DO FOR v0.2 UNBLOCK + MARKETPLACE):
  Follow EXACT the big "CRITICAL #1: EXACT COPY-PASTE COMMANDS..." section at the end of scripts/screenshot-prep-fedora.sh
  (includes grim for main/refusal/voice/groups/actions/extreme/i2p/file/relay/channel/queues-i + nix builds + relay server test + 'i' queue observe)
  While running the tests below, also run the grim captures listed there.
- Observations (builds, binary, failover logs, UI cmds, Tauri notes) - LOG DATES + ENV + "ran on real Fedora/Tails + physical Android" FOR v0.2 BLOCKER UNBLOCK

---

## Overall Result

**Status:** [ ] PASS   [ ] FAIL   [ ] PARTIAL (with limitations noted)

**Key Strengths Observed:**

**Critical Issues / Limitations Found:**

**Recommendations for next test run:**

---

## Sign-off
Test performed by: _______________________  
Date: $DATE  
Commit: $COMMIT

This log satisfies the hard pre-v0.2 requirement for real hardware + Tails/Qubes evidence.
EOF

echo ""
echo "Evidence log created: $LOG_FILE"
echo ""
echo "Please fill in the sections above with your real test results."
echo "When finished, commit this file (it is meant to be part of the audit trail)."
echo ""
echo "Next recommended: Run this on Tails + physical Android (GrapheneOS) + Fedora before v0.2 tag. THIS IS THE CRITICAL #1 BLOCKER."
echo "Concrete sequences (from priority table Critical #1 - EXACT for unblock + marketplace):"
echo "  - Tails: live USB no persist, ./run-tui, clean-security, test voice/wipe/posture/Extreme, power off."
echo "  - Android: adb logcat | grep hashchat ; adb shell pm clear ; test mic/wipe/biometric + Phase3 relay/channel/Starlink actions + X3DH."
echo "  - Fedora (MUST DO FOR PHOTOS + LOG TO UNBLOCK v0.2): "
echo "      1. Follow the FULL 'CRITICAL #1: EXACT COPY-PASTE COMMANDS...' section at the END of scripts/screenshot-prep-fedora.sh"
echo "         (includes all grim captures for table states: main/refusal/voice/groups/actions/extreme/i2p/file/relay/channel/queues-i + nix builds + relay server)"
echo "      2. ./scripts/real-device-test.sh | tee docs/evidence/real-fedora-$(date +%Y-%m-%d).log"
echo "  - Phase3/table focus: test :relay, :channel, Starlink failover, quantum, Tauri (if built), relay server binary, nix repro builds while capturing.
  - Threat sim (High OPSEC): ./scripts/threat-correlation-sim.sh | tee -a \$LOG_FILE   # feeds findings to THREATMODEL for audits."
echo "  - Always: clean-security before/after, document dates + 'real Fedora/Tails + physical Android' + commit the photos + log + update metainfo as Lucas."
echo "This + the grim photos is exactly what satisfies the Critical v0.2 evidence blocker and allows Flathub/Fedora Apps marketplace submission."
echo ""
echo "To auto-append a pre-filled table template to your log (for Critical #1):"
echo "  cat >> $LOG_FILE << 'TABLEEOF'
### Critical Table Items - Fill after captures
- [ ] User evidence photos: grim for main, refusal, voice, groups, actions, extreme, i2p, file, relay, channel, queues-i (from screenshot-prep)
- [ ] Nix/Flake: nix build .#hashchat-tui ; nix build .#hashchat-flatpak succeeded
TABLEEOF
echo "Log updated with table template. Fill [x] after your runs."