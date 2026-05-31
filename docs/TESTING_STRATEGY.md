# HashChat Testing Strategy (Real Hardware Focus)

**Status**: Draft for v0.2+ (arch-2 long-term item from expert review).

## Core Principle
Emulators are useful for CI smoke tests but **insufficient** for a paranoid messenger. Real device testing on physical hardware (Tails laptop, Qubes phone, hardened Android) must be regular and documented.

## Required Test Environments (Minimum)

### Desktop / TUI
- Tails 6.x (live USB, disposable)
- Qubes OS 4.2+ (dedicated AppVM for build + test)
- Fedora 40+ (developer daily driver, with strict firejail / bubblewrap)
- At least one offline/airgapped machine for wipe + ratchet export tests

### Android
- At least two physical devices:
  - One "daily" hardened Pixel (GrapheneOS or CalyxOS preferred, no Google services)
  - One "test" device (can be older, used for destructive posture/wipe tests)
- Emulator only for basic connectedAndroidTest in CI (never sole source of truth)

## Frequency & Rituals
- Before every signed tag (including v0.2): Full manual test pass on at least one Tails/Qubes desktop + one real Android device.
- After any voice, posture, wipe, or export change: Real device run within 48h.
- Quarterly: Full regression on 2+ Android SKUs + fresh Tails live session.
- All real-device runs must start with `./scripts/clean-security.sh` on the test machine and end with full wipe where possible.

## Test Areas That Demand Real Hardware

1. **Voice completeness** (critical): Real mic recording → ratchet chunking → Tor path (if possible) → playback + SeekBar + post-wipe key destruction. Verify no plaintext audio lingers in cache after clearSensitiveScreenState.
2. **Android mlock** (high): Confirm that ratchet material is actually locked (use gdb or /proc/<pid>/maps inspection; current impl is best-effort via libc mlock from Rust init).
3. **Keystore + Biometric**: Actual StrongBox / TEE protection + BiometricPrompt gate on export/import. Test "what happens if biometric fails 3x".
4. **Posture live re-eval**: Debugger attached, airplane mode, root detection (on stock), container detection. Verify isActionAllowedInPosture actually blocks voice/groups/file/decoy in LOW.
5. **Wipe nuclear path**: Full panic button on real device (verify all temp voice files, groups.enc, Keystore blobs, memory are gone post-finish()).
6. **Cross-device ratchet export**: Real QR or file transfer between two devices, import, continue chat with forward secrecy intact. Source device must wipe after export.

## CI vs Real
- GitHub Actions: cargo test --release (paranoid paths), cabal check, gradle assemble.
- Real hardware: The only place where JNI + Keystore + mlock + actual Tor hidden service + mic + biometric can be trusted.
- CI must **fail the build** on any regression in the 9+ Rust tests (already wired in .github/workflows/build.yml).

## Tooling Recommendations
- For Android: Use `adb logcat` during voice/posture tests; `adb shell pm clear` between runs.
- For TUI: Run inside `screen` or `tmux` on Tails so session survives, capture with `script` for logs.
- Always pair with `./scripts/clean-security.sh` + `git status` + manual `rm -rf ~/.cache/hashchat*` or equivalent.

## Documentation of Runs (for audit)
Maintain a private (or redacted public) log:
- Date, environment (Tails 6.1 x86_64, Pixel 7 GrapheneOS 2026-05), hashchat commit.
- Which tests passed/failed + key observations (e.g. "voice file deleted in <2s after playback", "posture correctly refused group create on emulator").
- Any new issues discovered for THREATMODEL.md or ROADMAP.

## Next Steps (Before Real v0.2 Ship)
- [ ] Expand this file with concrete command sequences for Tails + GrapheneOS test sessions.
- [ ] Add a `make test-real` or `scripts/real-device-test.sh` helper (guarded, never runs in CI).
- [ ] User (ichbinlucasv) performs at least one full real-device + Tails pass before executing the signed v0.2 tag.

This plan directly addresses the expert recommendation: "You need a plan for how you will actually test on real hardware regularly (not just emulators)."

See also: docs/RELEASE_PROCESS.md, android/src/androidTest/..., RELEASE_NOTES_v0.2.md (honest limitations).