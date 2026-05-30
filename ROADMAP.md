# HashChat Roadmap — Towards the Best Private Messenger

Goal: Build a SimplexChat-level (or better) anonymous messenger using only **Haskell + Rust**, with strong focus on security, forward secrecy, and metadata resistance.

**We have moved from "build the foundations" to "polish to production".**

## What Is Actually Done (as of this build)

### Paranoid Core (Implemented)
- Real Double Ratchet in Rust (KDF chains, DH ratcheting, skipped keys, zeroize on drop)
- Bidirectional Tor v3 hidden services with proper sender-header framing
- Encrypted persistence (Argon2id + AES-GCM) for ratchets, messages, and groups
- Nuclear Panic Wipe (7-pass + Rust zeroize + kernel anti-forensics + mlock)
- Dynamic Security Posture with real environment inspection + action refusals
- Burner profiles + plausible deniability decoy profiles with automatic wipe on switch
- Disappearing messages tied to ratchet key erasure

### SimplexChat-Level UX Parity (both platforms)
- Full contact actions: Block, Mute, Delete, Report, View security info, Disappearing timer
- Multi-member groups with sender-key forward secrecy + member management + QR join
- Voice messages: per-chunk ratchet streaming + playback with seek bars (Android RecyclerView + TUI)
- Burner switching (p/n), decoy mode (D), prominent nuclear wipe (w)
- Black + #FFD700 gold theme on both TUI and Android

### Android (Production Direction)
- RecyclerView chat + dedicated group member management screen
- Hardware-backed Android Keystore + optional BiometricPrompt for ratchet unlock
- QR scanning + group join flow
- Background Tor receiver thread

### Distribution & Reproducibility
- Pure-Nix reproducible Flatpak (`nix build .#hashchat-flatpak`)
- Nix cross-compile path for Android Rust libraries
- Qubes/Tails disposable VM build scripts that enforce `clean-security.sh` + anti-forensics

## Current Phase: Polish to "Feels Complete" (High Priority)

### Immediate Polish Items
1. **Android group persistence** — Real encrypted load/save (Keystore + JNI ratchet export/import) so groups survive app restarts.
2. **Voice with real seek bars everywhere** — Wire chunk receive → JNI decrypt → MediaPlayer with proper SeekBar + progress in RecyclerView bubbles. Improve TUI ffplay integration.
3. **Nix Android toolchain** — Turn the current skeleton into a working derivation so `nix build` actually produces usable .so files for aarch64 + armv7.
4. **Docs** — Finish full README/ROADMAP/INSTALL refresh (already in progress).

### Credibility & Hardening
- Add basic tests (ratchet roundtrips, group sender-key, voice framing).
- More disappearing-message key wipe integration across the stack.
- One more posture refusal pass for groups/voice/QR features.

## Medium Term (Next 1-2 Months)

- Make Flatpak the primary distribution method (signed, one-command via Nix).
- One final git history clean + v0.2 / "preview" tag.
- Android: Proper multi-screen navigation (dedicated Group list screen, improved voice recording UI).
- Next "wow" technical feature: proper streaming file transfer or secure cross-device ratchet export.

## Longer Term / Stretch Goals

- Real test suite + CI that exercises the paranoid paths.
- Quantum-resistant options (post-quantum KEMs as noted in earlier roadmap).
- Decentralized discovery without leaking metadata.

We are building this the right way: small trusted computing base, Haskell for correctness, Rust for performance/crypto, Tor-only, and SimplexChat-level respect for the user.

Contributions are very welcome — especially in the remaining polish areas above.
