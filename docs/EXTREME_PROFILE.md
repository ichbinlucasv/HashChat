# Extreme Profile — Ultra-Stripped Mode (Tier 3 Design Document)

**Status**: Basic runtime implementation complete in TUI (flag + gates for groups/voice/contact QR). Rust/Haskell core ready. Android pending. Decision recorded in EXTREME_PROFILE_DECISION.md as "Implement scoped".

## Philosophy
For the most hostile environments, users may want to trade almost all features for the smallest possible attack surface and metadata footprint.

This is **not** a "better" profile for normal users. It is a deliberate extreme for people who are willing to lose groups, voice, cross-device export, and most persistence in exchange for radically reduced code paths and data lifetime.

## Disabled / Restricted in Extreme Mode
- All group functionality (creation, joining, sender keys, persistence)
- Voice recording and playback
- Cross-device ratchet export / import
- Decoy / plausible deniability profiles (only one identity allowed)
- Long-term contact lists or message history
- Any background services beyond minimal Tor receiver for the current contact
- Biometric / Keystore unlock (forces manual passphrase every time if possible)

## Forced On
- Strict mode at all times with no way to disable
- Aggressive memory wiping after every message
- Shortest possible ratchet lifetimes
- No persistent files beyond the current session (everything in cacheDir or memory only)
- Minimal UI surface

## Implementation Sketch (Post-v0.2)
1. Top-level compile-time or runtime flag `EXTREME_MODE`.
2. In both TUI and Android:
   - Gate entire feature branches behind the flag (fail hard or hide UI).
   - Use a completely separate (smaller) set of Rust entry points if we split crates later.
3. Dedicated build variant or separate binary for extreme users (smaller attack surface at the binary level).
4. Separate section in THREATMODEL.md and TESTING_STRATEGY.md.

## Trade-offs
- Much smaller trusted computing base and data lifetime.
- Extremely poor usability for anything beyond 1:1 text with a single contact.
- Still subject to all Android limitations (mlock, supply chain, etc.).

## Decision Required
See ROADMAP.md "Post-v0.2 Philosophy Decision".

If we choose "Accept Android is weaker", this Extreme profile becomes a first-class supported mode for the highest-risk users.

**Wave 5 Implementation Progress**:
- Android: `EXTREME_MODE` flag + hard gates now active on voice recording, group QR/join, cross-device export, and remaining demo-pass group paths.
- Decoy profile fully disabled under Extreme.
- TUI: Consistency notes added for future gating.
- pre-tag-check and CI notes reference Extreme requirements.
- Real zeroize added to VoiceStream as part of minimal surface work.

This is no longer pure design — first real code enforcement exists.

**Owner**: Continue expanding gates in subsequent waves. Update after philosophy decision.

Wave 7 Simplex-style Contact Sharing update:
- ContactAddress + ConnectionRequest types added (public onion + public key model, Simplex-inspired).
- Extreme mode awareness: profile sharing should be disabled by default when EXTREME_MODE is active.

New recommendations (using Simplex as reference while leveraging HashChat strengths):
- Contact QR = public data only (onion + public identity key). Private key never leaves device.
- Primary way to add friends should be scanning/sharing these contact QRs (not manual entry).
- After scanning a contact QR, the app should initiate a secure introduction using the existing Double Ratchet system.
- In Extreme mode, generating or scanning contact QRs must be hard-disabled.
- TUI: At minimum show the text link for the contact address; later generate real QR image.
- Android: Add full generate + scan flow for individual contact QRs (similar to existing group QR).
- Consider making contact addresses rotatable for stronger metadata resistance over time.
- Clearly document in THREATMODEL the risks of the QR itself being a metadata vector when shared.

Last updated: Wave 7 deep implementation of Simplex-style profile sharing on top of HashChat architecture.
