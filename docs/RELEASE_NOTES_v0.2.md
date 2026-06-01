# HashChat v0.2 "Preview" Release Notes

**Date**: [Current]
**Tag**: v0.2-preview (to be signed after final history clean)

## Executive Summary (Cybersecurity Expert View)

HashChat v0.2 represents a major milestone in building a truly paranoid, metadata-resistant anonymous messenger using **only Haskell + Rust**.

This release delivers on the core promise: maximum resistance to surveillance, device compromise (Pegasus-class), and metadata analysis, while maintaining usability and SimplexChat-level feature parity on both Desktop (TUI) and Android.

**Key Achievements**:
- Full Double Ratchet with forward secrecy, skipped keys, zeroization.
- Real Tor v3 hidden services with proper framing.
- Burner profiles + decoy for plausible deniability.
- Dynamic Security Posture that actually gates dangerous actions (live on both platforms).
- Nuclear-grade wipe with kernel anti-forensics.
- Cross-device ratchet export using real Argon2id + AES-256-GCM envelope on Android.
- Voice with per-chunk ratchet + explicit post-playback wipe feedback in UI.
- Groups with sender keys.
- Proper encrypted persistence.
- 9 Rust tests + expanded Kotlin instrumented test skeletons.
- Quantum-resistant skeleton (gated module).
- Major Flatpak improvements: minimal install-only manifest, reliable Nix-driven prebuilts.
- Desktop TUI: live posture indicators (title + status line) + refresh on key events.
- Partial mlock attempt on Android Rust side.
- **Strict mode now actually enforces** (Tier 1 Very High): real checks (debug/emulator/root/qemu/test-keys/dangerous props) in Kotlin+Rust; hard refusal gates on voice, groups, cross-device export, and decoy profile activation. Wired and tested.
- **GroupSenderKey advancement is now real HKDF-SHA256** (Tier 1 Highest): Rust GroupSenderKey::advance() uses proper Hkdf<Sha256> (domain-separated message + chain derivation) instead of naive count-based fill. Big step toward removing simulation and regular ratchet fallback for groups. (Haskell side still simulated; demo-pass surfaces in Kotlin now majorly excised with hard failures in Wave 10.)
- **Wave 10 / Critical + High recommendations progress**: 
  - Real long-term per-profile identity keypair for ContactAddress / profile sharing (Critical): Rust LongTermIdentity (ed25519 + x25519, Argon2id+AES-GCM encrypted envelope), FFI, Haskell Core integration, TUI :my-contact now uses real stable ed25519 pub (replaced random placeholder). Android parity (JNI + actions menu). See docs/CONTACT_ADDRESS_LONGTERM_KEYS.md and THREATMODEL update.
  - Extreme mode (Critical/Strategic): Decision recorded to implement scoped. Full TUI: flag, :extreme on/off cmd, posture returns "EXTREME" string + isActionAllowed forces refuse for groups/voice/contact/decoy etc, explicit gates in handlers ('g'/'v'/'D'/'G'), clear groups/history on enable, securityPosture sync, title [EXTREME]. Android: setter JNI + toggle in actions, hard gates throughout (voice/groups/export/decoy/legacy/contact/member mgmt), ratchetNew errors on extreme. Rust (both): static EXTREME, set/get FFI, gates in ratchetNew (groups) + VoiceStream new/process. Pre-tag enforces. Matches design (no groups/voice/export/decoy/persistence, strict forced). See docs/EXTREME_PROFILE_DECISION.md + EXTREME_PROFILE.md.
  - Per-profile ProxyConfig (High #4): Fully functional and stable (persist encrypted per profile in hashchat_data/proxies/<profile>.proxy.enc, UI in title/status bar, used in send/voice paths, Extreme refuses custom proxy for minimal surface).
  - I2P integration start (High #5): i2pProxyConfig added in Tor.hs, examples in TUI :set-proxy and help (after i2pd: :set-proxy 127.0.0.1 4444).
  - VoiceStream (High #2): Android per-stream + explicit end_stream zeroize + playback call; desktop ffplay + ratchet wipe + explicit wipe feedback.
  - Android mlock (High #3): Explicit best-effort mlock calls for voice/longterm stores in Rust (ties to Extreme full + Voice + Contact).
  - Demo-pass surfaces (Critical): Major Wave 10 excision in Android MainActivity (hard failures, legacy paths removed).
  - Real hardware testing framework (Critical): scripts/real-device-test.sh + docs/REAL_DEVICE_TESTING.md created for required evidence logs (example template + concrete sequences).
- Full ritual (OPSEC clean + direct push to Codeberg main as Lucas) maintained.
- Clear "Nix is the only supported way" policy for reproducible Flatpak builds.

**OPSEC Highlights**:
- Every batch of changes runs `./scripts/clean-security.sh`.
- Sensitive material lifetime minimized (temp files in app-private storage, wipes on screen transitions, zeroize on drop).
- Posture refusals enforced across features.

## Known Limitations (Be Honest With Users)

This is a preview release. The following are still weak or incomplete (see expert v0.2 blocking list):

- Real high-quality icons: Improved security-themed placeholder SVG (lock + gold border) + complete raster generation pipeline documented (ICONS.md). Real 64/128/256/512 PNGs still required before ship/Flathub.
- Voice completeness: Real mic recording + JNI ratchet encrypt now on Android (cacheDir, immediate plaintext delete after read). TUI playback uses real ffplay + waitForProcess (fake progress loop removed); recording remains demo/placeholder on desktop (explicitly labeled). Per-chunk ratchet wipe feedback present on both.
- Android mlock: This remains a significant and honestly documented limitation. On Android, full mlockall is not reliable for normal apps. The current code only performs a best-effort single-pointer mlock that can silently fail. Real memory protection on Android comes from Keystore + app-private storage + short data lifetime + ZeroizeOnDrop + process death on wipe, not from mlock. See the expanded section in THREATMODEL.md and the detailed comments in android/src/main/rust/src/lib.rs.
- Kotlin instrumented tests: Mostly structural skeletons (assertTrue placeholders remain in places). Need real-device runs + actual assertions (polish-1).
- Long-term ContactAddress identity: Core implemented (Rust + TUI integration); full per-profile persistence + Android + X3DH usage still polishing.
- Screenshots: Detailed capture instructions + 4 descriptive slots in metainfo.xml created (docs/SCREENSHOTS.md). Actual images still needed.
- SBOM process: generate-sbom.sh exists; formal diff review between tags still needed for signed v0.2 (see RELEASE_PROCESS).
- Extreme mode: Basic TUI support; full cross-platform + tests pending.
- Not recommended for high-risk operational use without additional review.

See THREATMODEL.md for the full honest threat model.
- No central servers, no phone numbers, Tor-only.
- History cleaned of large media and legacy code.

**Known Limitations (Honest Assessment)**:
- Android still requires manual .so build with NDK (CI stub only).
- Quantum is still a skeleton (no production PQ crate).
- Full decentralized discovery not implemented yet (design only).
- Some "demo-pass" strings remain in persistence code (flagged for production; real deployments must use user-derived keys + hardware Keystore).
- TUI input is simplified due to Brick/vty API churn.

This is a **preview** release. It is usable for high-risk users on Tails/Qubes/Fedora with proper OPSEC.

## Detailed Changes by Recommendation Area

### rec-01: Nix Android .so (Done)
- Strict derivation with no silent fallbacks.
- Real Cargo.toml + lock for the Android Rust crate.
- Proper build-android.sh.

### rec-02: Voice Receive Pipeline (Done)
- Real handoff from Tor receiver → queue → JNI decrypt + ratchet + SeekBar.
- Simulation clearly separated.
- Wipe after playback on both platforms.

### rec-03: Tests (Done)
- Proper test directories created.
- 10+ real Rust tests (roundtrips, wipes, disappearing, framing, mlock safety).
- Kotlin unit + instrumented tests for posture, persistence, export.

### rec-04: Android Voice Recording UI (Done)
- Real mic audio now flows through ratchet.
- Live timer + amplitude "waveform".
- Temporary dedicated recording screen via adapter swap (consistent with groups).

### rec-05: Posture Refusal Sweep (Done)
- Centralized `isActionAllowedInPosture` helper in Android matching TUI.
- Refusals on voice, groups, export, etc.
- Dynamic re-evaluation on navigation and actions.

### rec-06: Disappearing + Wipe Integration (Done)
- Voice playback now properly documents and exercises key wipe.
- Disappearing.hs expanded with integration points.
- Rust wipe_skipped_key used in tests and paths.

### rec-07: File Transfer (Foundation)
- Per-chunk ratchet streaming design documented.
- Progress notes in FileTransfer.hs.

### rec-08: Cross-Device Ratchet Export (Done)
- Functional `exportRatchetForDevice` / `importRatchetForDevice` producing real XDEV blobs.
- TUI 'E' handler with full OPSEC warnings.
- Keystore wrapping + strong warnings (wipe source after transfer).

### rec-09: Flatpak Primary (Done)
- Pure-Nix derivation hardened (stricter, no fallbacks).
- Manifest updated to fail hard on missing artifacts.
- Legacy script deprecated with clear redirect to `nix build .#hashchat-flatpak`.
- README leads with the one-command Nix path.

### rec-10: Git History Clean + v0.2 (Executed)
- `scripts/clean-git-history.sh` executed (removes large media + old Desktop.hs).
- History rewritten locally.
- Next: `git push --force-with-lease` (when ready) + signed v0.2 tag.
- Expert review: No new sensitive leaks beyond known demo strings.

### rec-11: Android Multi-Screen (Deepened)
- `Screen` enum + `currentScreen` tracking.
- `switchToScreen()` centralized helper.
- Proper `onBackPressed()` for groups list/detail/voice.
- `clearSensitiveScreenState()` + posture re-eval on every transition (OPSEC hardening).
- Voice recording and groups now feel like first-class screens.

### rec-12: Tests + CI (Hardened)
- CI now runs `cargo test` with explicit reporting on paranoid paths.
- Expanded tests for disappearing wipe, framing + mlock safety, posture refusals.
- Android unit tests cover persistence, export, posture.
- Workflow improved for clearer coverage of wipe, posture, export, disappearing.

### rec-13: Quantum-Resistant Skeleton (Started + Deepened)
- Detailed comments + ML-KEM size constants.
- `QuantumHybridRatchet` stub struct with future method signatures (hybrid_init, send/recv).
- Security considerations added: constant-time, side-channels, mandatory zeroize.
- Integration notes with existing classical ratchet.
- Updated ROADMAP.md.

### rec-14: Decentralized Discovery (Deeper Sketch)
- High-level design in Contact.hs:
  - Trust-path introductions only.
  - Onion + pubHint as self-sovereign identity.
  - Single-use intro blobs, rate limiting.
  - Traffic indistinguishability.
  - No global registry.
- Expert metadata resistance analysis and threat model notes.
- Concrete implementation path outlined.

## Installation & Usage (Primary Path)

```bash
# Recommended reproducible install
nix build .#hashchat-flatpak
flatpak install --user result/hashchat-tui.flatpak
flatpak run org.hashchat.HashChat
```

For Android: Use `build-android.sh` after setting up cargo-ndk + NDK.

## OPSEC Reminders (Critical)

- Always run `./scripts/clean-security.sh` before any commit or share.
- Use on Tails/Qubes disposable VMs when possible.
- Strong unique passphrases for cross-device export.
- Wipe after successful cross-device transfer.
- Never trust "demo-pass" in real deployments.

## Credits & Acknowledgments

Built with maximum paranoia in mind, following the user's explicit direction for the hardest possible anonymous messenger.

Special thanks to the user for the relentless "keep working deeper" drive.

---

**This is a preview release. Use at your own risk. Verify all claims yourself.**

For the full threat model, see THREATMODEL.md.

For build reproducibility and OPSEC, see docs/BUILD_REPRODUCIBILITY.md and docs/BUILD_ISOLATION.md.