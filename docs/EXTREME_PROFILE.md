# Extreme Profile — Ultra-Stripped Mode (Tier 3 Design Document)

**Status**: Design doc + active runtime gates (Android + Rust TUI). Not a separate stripped binary.

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

**Wave 5+ Implementation Progress**:
- Android: `EXTREME_MODE` flag + hard gates on voice recording, group QR/join, cross-device export, and remaining demo-pass group paths; decoy disabled under Extreme.
- Rust TUI (overnight Extreme-as-first-class pass): `NetConfig` helpers (`extreme_blocks_contact_export`, groups/voice) drive consistent refusals. Under Extreme: Tor-only; `:my-contact` refused; `:sas` allowed as short local verification (no signed URI echo; onion tails avoided in scrollback); `:listen` / send / `:retry` stay Tor-gated; `:group`/`:voice` stubs refuse; `:status`/`:help` announce locks. Onion listen still exists — this is **not** the full design-doc strip (no compile-time Extreme binary).
- **Extreme durable footprint (Rust TUI / `session_persist`)**: under Extreme, `save_session` keeps identity + onion + net prefs + disappear TTL but writes **empty** contacts / ratchets / pending (blob stays v4). Trade-off: no multi-session contact continuity — re-add contacts after restart. Load still accepts legacy blobs that contain contacts into RAM for the current session; the next Extreme save strips them. Switching *to* Extreme clears the in-memory chat transcript (zeroize bodies). Standard posture unchanged (full H3). **Not** Android Extreme persistence parity.
- pre-tag-check and CI notes reference Extreme requirements.
- Real zeroize added to VoiceStream as part of minimal surface work.

This is no longer pure design — real code enforcement exists on both platforms for the surfaces above.

**Owner**: Android contact-QR / disappear / persistence parity remain open. Update after philosophy decision.

Contact sharing (Simplex-inspired):
- Contact links = public data only (onion + public identity key). Private key never leaves device.
- Extreme: Rust TUI refuses exporting/displaying the signed contact link (`:my-contact`). Peer add via `:add-contact` with an out-of-band link remains possible (operator judgment). Android QR generate/scan must stay hard-disabled under Extreme.
- Document in THREATMODEL that the QR/link itself is a metadata vector when shared.

Last updated: overnight Extreme persistence minimization (contacts/queue not durable).
