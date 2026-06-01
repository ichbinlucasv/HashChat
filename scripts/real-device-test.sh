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
echo "Next recommended: Run this on Tails + a physical Android device before any v0.2 tag."