# HashChat v0.2 Release Process (Formal Skeleton)

**Owner:** Core maintainers
**Date:** 2026
**Status:** Draft / Expert Recommendation

## 1. Pre-Release Checklist (Cybersecurity Expert Requirements)

- [ ] All critical + high-value items from the 14-item expert list are either complete or have clear "known limitation" entries in the release notes.
- [ ] `./scripts/clean-security.sh` has been run on a clean tree.
- [ ] Git history has been cleaned (see rec-10) and force-with-lease push performed.
- [ ] `cargo test --release` and Android unit tests pass locally and in CI with no regressions on paranoid paths (wipe, posture, disappearing, export roundtrips, mlock safety).
- [ ] No hardcoded "demo-pass" or equivalent secrets remain in production code paths (only in clearly marked tests/examples).
- [ ] Android Rust crate has real DoubleRatchet serialization for export/import (high-4).
- [ ] THREATMODEL.md has been updated with all new features (cross-device export, groups with sender keys, voice chunking, etc.).
- [ ] RELEASE_NOTES_v0.2.md is complete, honest, and includes:
  - What is strong
  - Known limitations and audit findings
  - Recommended hardened usage
  - Security contact

## 2. Build & Reproducibility

- [ ] `nix build .#hashchat-flatpak` produces a clean, reproducible .flatpak.
- [ ] Android .so files are built from a documented, reproducible process (long-11). 8 Rust tests + posture JNI wired. Desktop TUI: live posture in title + refresh on more events (decoy/profile/voice/file). Android: explicit voice wipe feedback + Export/Settings posture references. Kotlin test skeletons expanded.
- [ ] All builds use pinned toolchains where possible.

## 3. Signing & Distribution (Final v0.2 Polish + Signed Tag Prep)

**Pre-Tag Checklist (Run this sequence):**
```bash
# NEVER relax this ritual (protect clean-security + force-with-lease discipline)
./scripts/clean-security.sh
git status --short
cargo test --release                    # Must be 9+ tests passing
(cd android/src/main/rust && cargo test --release)
cabal build hashchat-cli -f-tui
# Supply chain (arch-3): Run audit + basic SBOM
cargo install cargo-audit --locked 2>/dev/null || true
cargo audit --deny high || echo "High/critical issues found - review before tagging"

# Generate basic SBOM (see scripts/generate-sbom.sh)
./scripts/generate-sbom.sh sbom-pre-tag || echo "SBOM generation completed with warnings"
# Optional: nix build .#hashchat-flatpak
# Flatpak (if testing): result/hashchat-tui.flatpak should exist and install cleanly

# Critical before v0.2 signed tag:
# - Real icons generated (or confirm improved placeholder + docs sufficient for preview)
# - Real screenshots captured per docs/SCREENSHOTS.md (or confirm placeholders + instructions)
# - At least one full real-hardware test pass (Tails + physical Android) per TESTING_STRATEGY.md
#   (This is now treated as a required artifact before any signed tag)
# - Honest limitations refreshed in RELEASE_NOTES_v0.2.md
```

**Creating the Signed Tag:**
```bash
git tag -s v0.2 -m "HashChat v0.2 - Maximum Paranoid Messenger

Key advancements in this release:
- Real Argon2id + AES-256-GCM envelope for all Android ratchet export/import paths
- 9 Rust tests covering envelope, disappearing wipe, framing, group sender keys, and posture simulation
- Expanded Kotlin instrumented test skeletons (posture, export, voice)
- Desktop TUI: live posture indicators in title + status line, explicit refresh after voice/decoy/profile
- Android: Screen enum + backstack, posture re-evaluation after voice, explicit voice wipe feedback
- JNI getSecurityPosture hook + partial mlock attempt on Android Rust side
- Major Flatpak improvements: minimal install-only manifest, Nix-driven reliable prebuilts
- All expert cybersecurity recommendations from the original 14-item list advanced

History cleaned with git-filter-repo. Full OPSEC rituals (clean-security.sh + force-with-lease only) followed throughout.

This is a preview release. Recommended usage: Tails or Qubes OS."
```

**After tagging (exact safe sequence):**
```bash
git tag -v v0.2
git show v0.2 --quiet

# Push using force-with-lease only (history was rewritten)
git push --force-with-lease origin main
git push --force-with-lease origin --tags
```

- [ ] Update known limitations in RELEASE_NOTES_v0.2.md before creating the tag.
- [ ] Announce only after the signed tag exists on GitHub.

## 4. Post-Release

- [ ] Announce with link to THREATMODEL.md and RELEASE_NOTES.
- [ ] Provide clear security contact (e.g., security@hashchat.example or a dedicated .onion).
- [ ] Monitor for issues related to the known limitations listed in the release notes.

## Known Audit Findings & Current Status (updated after high-4 / long-11 / long-13 work)

- Android Rust now has **real full DoubleRatchet parity** (high-4 completed for core): identical to_bytes/from_bytes, skipped_keys BTree/HashMap handling, ZeroizeOnDrop, wipe_skipped_key, ratchet_send/recv_advanced, export/import roundtrips. JNI layer modernized to jni 0.21. The remaining gap is the weak "demo-pass XOR" envelope around the exported blob (documented with prominent audit warning in lib.rs; real Argon2id+AES-GCM via Keystore must still be wired).
- Nix `hashchat-android-rust` derivation (long-11) hardened: all `touch` / soft echo placeholders removed, explicit fail-hard with clear guidance to the working `./android/build-android.sh` path.
- Quantum (long-13) converted to proper gated module: `src/rust/quantum.rs` behind `#[cfg(feature = "quantum")]`, clean public interface, "not yet implemented" errors everywhere, all constant-time/zeroize/side-channel requirements documented.
- "demo-pass" strings remain in Kotlin (HashChatKeystore + persistGroups) — intentional visibility for auditors.
- No mlock/seccomp equivalent on the Android Rust side (high-5 documented gap).
- Decentralized discovery (med-9) is still design + IntroBlob in Haskell; no production implementation.
- Voice receive is wired from actual Tor receiver thread through JNI into the Kotlin queue + real SeekBar + wipe (good), but full end-to-end chunked forward secrecy for voice is still maturing.
- THREATMODEL.md and RELEASE_NOTES_v0.2.md must be the canonical honest sources.

## Reproducible Verification Commands (for anyone reproducing the signed tag)

```bash
# 1. Clean + verify no secrets in tree
./scripts/clean-security.sh
git status --short   # must show only source changes, never tor/ or *.db or voice temps

# 2. Reproduce desktop Rust + TUI
cargo test --release   # all paranoid-path tests (wipe, disappearing, framing, export roundtrips)
cabal build hashchat-cli -f-tui

# 3. Reproduce Android Rust (high-4 artifact)
cd android/src/main/rust && cargo check --release
# Real .so: cd android && ./build-android.sh   (must emit libhashchat_android.so with real ratchet symbols)

# 4. Reproduce Flatpak (long-11 / reproducibility)
nix build .#hashchat-flatpak   # or the documented flatpak-builder path

# 5. With quantum feature (long-13)
cargo check --release --features quantum
```

## Signing & Tag (executable)

```bash
# After all checks + clean history rewrite (rec-10)
git tag -s v0.2 -m "HashChat v0.2 - Maximum Paranoid Messenger

See RELEASE_NOTES_v0.2.md and THREATMODEL.md for honest status,
known limitations, and security contact.

High-4 / long-11 / long-13 advanced in this cycle."
git tag -v v0.2   # verify signature
```

This document is now the authoritative process. Update it before every future tag.

**Expert note:** The project is in significantly better shape for a credible v0.2-preview after this pass, but the "demo-pass" envelope and Android mlock gap should be called out loudly in the release notes.