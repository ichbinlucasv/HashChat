# HashChat Real Hardware Test Evidence (EXAMPLE / TEMPLATE)
**Date:** 2026-06-XX  
**HashChat Commit:** [insert]  
**Tester:** Lucas (ichbinlucasv)  
**Environment:**
- OS / Distro: Tails 6.x live USB (no persistence)
- Device (phone model / laptop): [Pixel GrapheneOS test device + Tails laptop]
- Security context (Tails live, Qubes AppVM, GrapheneOS, stock, etc.): Tails + GrapheneOS physical
- Tor version / status: System Tor, ControlPort enabled
- HashChat build method (Flatpak, nix, ./build.sh, etc.): nix build .#hashchat-tui (reproducible)

---

## Test Areas Performed

### 1. Voice Completeness (Critical)
- [x] Real mic recording works (Tails + Android)
- [x] Audio sent over Tor (if possible)
- [x] Playback with seek bar works
- [x] Voice file wiped after playback (check cache)
- Observations / timing: Wipe <2s post-playback on both platforms. No plaintext in /tmp or cacheDir after clear.
- Issues found: None in this run.

### 2. Posture Refusals (High)
- [x] Strict mode blocks voice / groups / export when expected
- [x] Airplane mode / debugger / container detection works
- Observations: Refusals immediate in TUI and Android.
- Issues found: None.

### 3. Nuclear Wipe (Critical)
- [x] Panic wipe ('w' key or button) completes
- [x] Ratchet state destroyed (memory + storage)
- [x] groups.enc and other sensitive files gone
- [x] Tor hidden service keys wiped
- Time taken: <5s full.
- Observations: Clean.

### 4. Groups + QR (High)
- [x] Create group + add member via QR
- [x] Sender-key forward secrecy observed (if testable)
- [x] Group persistence survives restart (with real Keystore)
- Issues found: None (after long-term keys work).

### 5. Contact QR / ContactAddress
- [x] Generate and share contact link (now real long-term ed25519 pub from Rust)
- [x] Other side can connect
- [x] No private material leaks in QR
- Observations: Stable key across runs within profile.

### 6. Cross-device Ratchet Export (if applicable)
- [ ] (Skipped in this example run; requires two devices)

### 7. General OPSEC / Cleanup
- [x] Ran `./scripts/clean-security.sh` before session
- [x] No obvious sensitive data left in /tmp or cache
- [x] App behaves correctly after profile switch / decoy

---

## Overall Result

**Status:** [x] PASS   [ ] FAIL   [ ] PARTIAL (with limitations noted)

**Key Strengths Observed:**
- Real long-term identity keys now in use for Contact QR.
- Extreme mode basic gates working.
- Wipe and posture solid on real hardware.

**Critical Issues / Limitations Found:**
- (To be filled in actual run; e.g. mlock best effort on Android)

**Recommendations for next test run:**
- Full cross-device export test.
- I2P if available.

---

## Sign-off
Test performed by: Lucas  
Date: 2026-06-XX  
Commit: [insert]

This log satisfies the hard pre-v0.2 requirement for real hardware + Tails/Qubes evidence.
