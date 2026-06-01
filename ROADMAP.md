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
- Wave 8: Simplex-style ContactAddress + ConnectionRequest (public-only QR links hashchat://contact/v1/...), full TUI wiring (:my-contact / :add-contact in Brick TUI + CLI), safer parser, export of helpers
- Wave 8: Generalized SOCKS5/ProxyConfig transport (sendOverProxy) with I2P + bridge/pluggable notes + call-site updates; hardened CI audit (no || true) + pre-tag demo-pass scan
- Wave 8: Brutal honest THREATMODEL update on all remaining gaps (placeholder pubkey in QR, last gated demo-pass surface, no per-profile proxy yet, evidence logs required for tags)

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

## Current Phase: Polish to "Feels Complete" (High Priority) - Updated after deep expert pass

**Note (Cybersecurity Expert Update):** Significant progress has been made on most items below. This document is being kept honest and up-to-date.

### Immediate Polish Items (Critical Remaining)
1. **Remove legacy dead code** — Massive stubFunction block in Main.hs removed (done in this pass).
2. **Android "demo-pass" hardening** — Hardcoded passphrase in group persistence flagged with expert warnings + scoped constant. Must be replaced with user-derived + Keystore in production.
3. **Honest docs** — ROADMAP + README refresh in progress (this update).

### High-Value OPSEC / Hardening (Expert Priority - Active)
- Android Rust: Port real DoubleRatchet logic (in progress - major gap for cross-device).
- Add mlock + seccomp to Android Rust side.
- Make CI fail on missing paranoid test coverage (in progress).
- Side-channel / constant-time review of export, groups, voice (in progress).
- Full multi-screen navigation hardening on Android (significant improvements made).
- Expand decentralized discovery into concrete protocol with message formats (skeleton expanded).

### Credibility & Hardening (Mostly Complete)
- Basic + expanded tests for ratchet, wipe, disappearing, posture, export (strong progress).
- More disappearing-message key wipe integration (improved across stack).
- Posture refusal pass (centralized helper + dynamic re-eval added).

### Medium / Longer Term
- Reproducible Android .so in Nix.
- Update THREATMODEL.md with all new features.
- Quantum skeleton moved to gated module.
- Formal v0.2 release process with signed tag and limitations document.

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

---

## Transport Expansion (Wave 7+)

Major ongoing work to give users strong anonymity flexibility:

- SOCKS5 proxy support (foundation) — allows routing through user Tor, I2P, Proton, Mullvad, IVPN, etc.
- I2P as first-class transport (high strategic value).
- Better Tor bridge / pluggable transport support.

These features are being built in a way that preserves the core metadata-resistant model and integrates with the Extreme profile.

## Post-v0.2 Philosophy Decision Required (Tier 3)

Before the next major phase we must explicitly decide the Android vs Desktop TUI strategy:

**Option A (Recommended by current direction):** "Make Android as strong as the desktop TUI."
- Continue aggressive Rust migration on Android (voice full ratchet, group persistence 100% in Rust, full strict mode everywhere, mlock best-effort + Keystore as primary).
- Accept that Android will always be slightly weaker than a Tails/Qubes TUI but make the gap as small as technically possible.
- Result: one product with two high-quality surfaces.

**Option B:** "Accept Android will always be meaningfully weaker and design accordingly."
- Android becomes a "companion" or "burner-only" client with deliberately reduced feature surface (no groups, no voice, no cross-device export, minimal persistence).
- Desktop TUI becomes the "serious" paranoid tool.
- Extreme users get Option C (see below).

We must make this decision explicitly in the next 4-6 weeks and document it so the entire team and users know the intended threat model per platform.

## Second Ultra-Stripped "Extreme" Profile (Tier 3)

Some users (journalists in the most hostile environments, high-value targets) may want an even smaller attack surface than the current burner + decoy model.

Proposed "Extreme" profile (disabled by default, user must explicitly enable):

- Groups completely disabled
- Voice recording/playback disabled
- Cross-device ratchet export disabled
- Decoy profile disabled (only one burner)
- No persistent contacts or history beyond current session
- Strict mode forced on at all times with no bypass
- Even more aggressive memory wiping + shorter key lifetimes
- Smaller APK / binary surface (if we ever split builds)

This would be a separate launch mode or compile-time flag. It trades almost all usability for the smallest possible trusted computing base and metadata surface.

Implementation sketch: a top-level `ExtremeMode` flag that gates entire feature paths in both TUI and Android, plus a dedicated THREATMODEL section.

**Decision needed:** Do we want this as a real supported mode post-v0.2, or is the current burner + decoy + strict mode sufficient?

Document owner: keep this section updated after the philosophy decision.
