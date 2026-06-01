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

## How to Generate Required Evidence

Use the helper:

```bash
./scripts/real-device-test.sh
```

This creates a dated evidence log in `docs/evidence/`.

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