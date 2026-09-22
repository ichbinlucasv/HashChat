# HashChat v0.2 "Preview" Release Notes

**Date**: 2026  
**Tag**: v0.2-preview (to be signed after final history clean + hardware evidence)  
**Desktop product surface:** Rust TUI (`hashchat-tui --features tui`)  
**Haskell desktop:** transitional / not recommended  

## Executive summary

HashChat v0.2 is a **preview** milestone for a Tor-only, metadata-resistant messenger with a **Rust-first** stack (crypto, Tor, persistence, wipe) and a **Rust TUI** desktop client. Legacy Haskell Brick desktop remains in-tree for parity only and is **not** the release path.

It ships Double Ratchet crypto, Tor v3 transport (host Tor; fail-closed cookie auth), burner/decoy profiles, and desktop/Android UX features listed below. It does **not** defeat full device compromise (e.g. Pegasus-class implants); see THREATMODEL.md. This is **not** a production-readiness claim.

**Hardware / two-peer Tor evidence:** follow [`docs/TWO_PEER_VALIDATION.md`](TWO_PEER_VALIDATION.md) (OPSEC-safe; do not record cookies, keys, onions, passphrases, SAS, or message bodies). Fill-in: `scripts/validation-evidence-template.txt`.

**Key Achievements** (honest / tip-aligned):
- Full Double Ratchet with forward secrecy, skipped keys, zeroization (Rust).
- Real Tor v3 hidden services with proper framing; SOCKS + ControlPort **cookie** auth; **fail-closed** (no silent clearnet fallback).
- Burner profiles + decoy for plausible deniability (where wired).
- Dynamic Security Posture that gates dangerous actions (live on both platforms where implemented).
- Panic wipe of local sensitive state.
- Cross-device ratchet export using real Argon2id + AES-256-GCM envelope on Android (where completed; remaining gaps stay loud below).
- Voice with per-chunk ratchet + explicit post-playback wipe feedback in UI (desktop recording may still be limited — see limitations).
- Groups with sender keys (advancement improved on Rust; see limitations for Haskell-side leftovers).
- Encrypted persistence for identity / contacts / ratchets / pending queue on the Rust path.
- Expanded Rust tests + Kotlin instrumented test skeletons.
- Quantum-resistant skeleton (gated module — not production PQ).
- Flatpak: install-only manifest, Nix-driven `hashchat-tui` prebuilts; **host Tor required**; `command` / desktop `Exec=hashchat-tui`.
- Desktop TUI: live posture indicators + refresh on key events (Rust TUI).
- Strict / Extreme posture gates expanded where documented in-tree.
- Clear "Nix is the supported way" policy for reproducible Flatpak builds.

**OPSEC Highlights**:
- Every batch of changes should run `./scripts/clean-security.sh`.
- Sensitive material lifetime minimized (temp files in app-private storage, wipes on screen transitions, zeroize on drop).
- Posture refusals enforced across features where wired.
- Never paste ControlPort cookies, onion private keys, SAS, or message bodies into tickets or release artifacts.

## Known Limitations (Be Honest With Users)

This is a **preview** release. The following are still weak or incomplete:

- Real high-quality icons: pipeline + rasters improved; confirm Flathub-ready assets before public store submission (see `flatpak/ICONS.md`).
- Voice completeness: Android mic → ratchet path advanced; desktop recording may remain limited / explicitly labeled. Verify current tip before claiming parity.
- Android mlock: best-effort only; real memory protection relies on Keystore + short lifetime + ZeroizeOnDrop + wipe — see THREATMODEL.md.
- Kotlin instrumented tests: many still structural; need real-device runs + stronger assertions.
- Screenshots: slots/instructions in metainfo + `docs/SCREENSHOTS.md`; real images still needed before Flathub.
- SBOM / formal supply-chain auditing still maturing (arch-3).
- Quantum remains a skeleton (no production PQ crate).
- Full decentralized discovery not implemented (design only).
- Some "demo-pass" strings may remain in Kotlin persistence (auditor-visible; never for real deployments — use user-derived keys + hardware Keystore).
- Haskell Brick TUI is **transitional**; do not treat Brick/vty UX limits as the Rust TUI product surface.
- Flatpak does **not** bundle Tor; misconfigured host Tor / unreadable cookie fails closed (expected).

See THREATMODEL.md for the full honest threat model.

**Positioning:** Tor-only by default, no central servers, no phone numbers. Preview for careful testing on Tails/Qubes/Fedora with proper OPSEC — **not** an endorsement for unaudited high-risk operational use.

## Detailed Changes by Recommendation Area

### rec-01: Nix Android .so (Done / hardening)
- Strict derivation with no silent fallbacks where claimed.
- Real Cargo.toml + lock for the Android Rust crate.
- Proper `build-android.sh`.

### rec-02: Voice Receive Pipeline (Done / maturing)
- Handoff from Tor receiver → queue → JNI decrypt + ratchet + SeekBar (Android).
- Simulation clearly separated where still present.
- Wipe after playback documented on both platforms.

### rec-03: Tests (Done / expanding)
- Proper test directories created.
- Multiple real Rust tests (roundtrips, wipes, disappearing, framing, mlock safety).
- Kotlin unit + instrumented skeletons for posture, persistence, export.

### rec-04: Android Voice Recording UI (Done / maturing)
- Mic audio flows through ratchet where wired.
- Live timer + amplitude UI notes.

### rec-05: Posture Refusal Sweep (Done / expanding)
- Centralized posture helpers on Android matching TUI intent.
- Refusals on voice, groups, export, etc., where implemented.
- Dynamic re-evaluation on navigation and actions.

### rec-06: Disappearing + Wipe Integration (Done / hardening)
- Voice playback documents and exercises key wipe.
- Rust wipe helpers used in tests and paths.

### rec-07: File Transfer (Foundation)
- Per-chunk ratchet streaming design documented.
- Implementation still foundational — do not overclaim.

### rec-08: Cross-Device Ratchet Export (Done / hardening)
- Functional export/import producing real XDEV blobs where completed.
- TUI export path with OPSEC warnings.
- Keystore wrapping + strong warnings (wipe source after transfer).

### rec-09: Flatpak Primary (Done — tip-aligned)
- Pure-Nix derivation; install-only manifest; fail hard on missing `prebuilt/hashchat-tui`.
- App command / desktop **`Exec=hashchat-tui`** (Rust TUI).
- **Host Tor required**; cookie auth; **fail-closed** (no silent clearnet fallback).
- Docs: `flatpak/README.md`, Flatpak section of `INSTALL.md`, metainfo description.
- Legacy `flatpak/build-flatpak.sh` redirects maintainers to `nix build .#hashchat-flatpak`.

### rec-10: Git History Clean + v0.2 (Executed / publish when ready)
- History clean scripts exist; rewrite only with deliberate OPSEC ritual.
- Next: signed v0.2 tag after checklist + `docs/TWO_PEER_VALIDATION.md` evidence.
- Prefer Codeberg primary; GitHub is mirror.

### rec-11: Android Multi-Screen (Deepened)
- Screen enum + backstack / transition helpers.
- Sensitive screen state clear + posture re-eval notes.

### rec-12: Tests + CI (Hardened)
- CI runs `cargo test` with reporting on paranoid paths where configured.
- Expanded wipe / framing / posture coverage notes.

### rec-13: Quantum-Resistant Skeleton (Started)
- Gated module + size constants + security considerations.
- Not production PQ — skeleton only.

### rec-14: Decentralized Discovery (Design)
- Trust-path introductions only; no global registry.
- Design / threat-model notes — not a shipping discovery network.

## Installation & Usage (Primary Path)

```bash
# Recommended reproducible Flatpak (Rust TUI)
nix build .#hashchat-flatpak
flatpak install --user result/hashchat-tui.flatpak
flatpak run org.hashchat.HashChat
```

**After install:** ensure host Tor is running (loopback SOCKS + ControlPort cookie auth). The Flatpak does not bundle Tor. Transport is fail-closed.

From source (same binary the Flatpak packs):

```bash
cargo build --release --locked --bin hashchat-tui --features tui
./run-tui
```

For Android: use `build-android.sh` after setting up `cargo-ndk` + NDK.

Maintainer two-peer validation: [`docs/TWO_PEER_VALIDATION.md`](TWO_PEER_VALIDATION.md).

## OPSEC Reminders (Critical)

- Always run `./scripts/clean-security.sh` before any commit or share.
- Prefer Tails / Qubes disposable VMs when testing sensitive flows.
- Strong unique passphrases for cross-device export; wipe after successful transfer.
- Never trust "demo-pass" in real deployments.
- Never record Tor cookies, onion private keys, full onions, SAS, or message bodies in evidence logs.

## Credits & Acknowledgments

Built with maximum paranoia in mind, following explicit direction for a hard anonymous messenger — with honest documentation of what is still preview-grade.

---

**This is a preview release. Use at your own risk. Verify all claims yourself.**

For the full threat model, see THREATMODEL.md.  
For two-peer hardware evidence process, see [`docs/TWO_PEER_VALIDATION.md`](TWO_PEER_VALIDATION.md).  
For build reproducibility and OPSEC, see docs/BUILD_REPRODUCIBILITY.md and docs/BUILD_ISOLATION.md.
