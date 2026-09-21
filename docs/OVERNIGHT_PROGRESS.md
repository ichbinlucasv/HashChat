# Overnight Progress

**Snapshot:** 22 September 2026 (Europe/Zurich)  
**Branch:** `codeberg-primary`  
**Tip:** `5420e6439ffe3dff36825fad985679f72b5980a2`

## Executive summary

The Rust desktop path moved from scaffold to a usable, Tor-first two-peer TUI. The recommended desktop client is now `hashchat-tui`; the Haskell desktop remains in-tree only as a transitional, non-recommended path. The work keeps the security posture explicit: Tor is the default and fail-closed, sensitive UI status is metadata-safe, and no clearnet fallback is opened silently.

## Shipped since the previous checkpoint

- **Branding — `950cd8c`, `d8e9c1c`:** adopted the black-and-gold chat-bubble/hash mark and marked the lockup as the canonical logo; refreshed the packaged icon assets.
- **Native Rust TUI — `a626d05`:** added the `ratatui`/`crossterm` desktop path with passphrase unlock/create, encrypted session persistence, contacts, SAS display, Tor status, and wipe entry points.
- **Tor transport — `63bbb4f`:** added cookie-authenticated ControlPort use, `ADD_ONION` listening, loopback-only SOCKS, `.onion` destination policy, framed wire transport, and durable outgoing-queue handling. No bare ControlPort authentication or clearnet fallback.
- **Linux packaging — `ce8af2d`, `fd78d23`:** installers and `run-tui` prefer the Rust binary on Fedora, Ubuntu/Debian, and Arch; Flatpak metadata/icons and Tails/Qubes guidance were aligned with the Rust/Tor path.
- **Two-peer messaging — `7d116c8`:** fixed listen/decrypt and send flow, signed-contact upsert, pending-message acknowledgement, and the initial bootstrap ratchet synchronization issue.
- **Explicit network modes — `b067d48`:** added Tor/I2P/clearnet mode selection, DNS preference, and Extreme Tor-only locking. Non-Tor modes currently refuse messenger send/listen rather than opening an unintended socket.
- **Nuclear wipe hardening — `958327a`:** added in-memory zeroization for session material and a prominent TUI confirmation flow; the threat-model limits of wipe remain documented.
- **Mid-session DH forward secrecy — `893a85c`:** restored periodic send-side DH ratcheting after bootstrap without desynchronizing peers; persisted ratchet format v2 remains backward-loadable from v1, with the Android ratchet copy synchronized.
- **TUI polish — `c542aff`:** added contact selection and short SAS presentation, selected-peer context, `:sas`, clearer `:help`, and Tor/SOCKS-gated `:retry` behavior without exposing plaintext bodies in status text.
- **Durable NetConfig — `5420e64`:** session blob v3 stores mode / DNS preference / posture inside the passphrase wrap; TUI `:mode` / `:mode extreme` changes survive restart. Env still seeds cold start / new identity; loaded blob wins after unlock. `:my-contact` / listen / send remain transport-gated (fail-closed).

## How to run

From a checkout of `codeberg-primary`, with a compatible Rust toolchain and a local Tor service configured for SOCKS plus cookie-authenticated ControlPort:

```bash
# Recommended Make target
make tui
./run-tui
```

Equivalent Cargo path:

```bash
cargo build --release --locked --bin hashchat-tui --features tui
./target/release/hashchat-tui
```

Inside the TUI, unlock or create an identity, use `:listen`, then exchange signed `hashchat://` contacts with the other peer. The default transport is Tor and the application fails closed if the required Tor path is unavailable. Do not copy Tor cookies, onion private material, passphrases, or message bodies into logs, tickets, or chat.

The tip commit records `cargo test --lib` passing with 60 tests and a successful `cargo build --bin hashchat-tui --features tui`.

## Remaining backlog

### Release and validation

- Complete real-hardware two-peer/Tor validation, capture non-sensitive evidence and screenshots, and prepare the signed v0.2/preview release.
- Keep CI/pre-tag security gates strict; finish reproducible Android `.so` output and SBOM/diff automation.

### Rust/TUI and posture

- Extreme profile remains first-class; further metadata-surface gating beyond contact-link / listen / send can be tightened as needed.
- Complete the Haskell retirement criteria; keep it transitional and non-recommended until removal is deliberate and documented.

### Android and cross-device parity

- Finish Android production hardening around Keystore-backed identity state, lifecycle/memory limits, voice end-to-end handling, and full Rust/TUI behavioral parity. Android `mlock` remains inherently best-effort for an unprivileged app.

### Transport and product scope

- Implement an actual I2P start path and per-profile proxy configuration; bridge/pluggable transports remain primarily local-Tor configuration today. Non-Tor modes must continue to fail closed until their paths are implemented and tested.
- Longer-term: secure streaming file transfer, further UX polish, and the remaining threat-model/release-documentation updates.

## Handoff status

No push was made. This note is an OPSEC-safe progress handoff; it contains no credentials, private onion material, passphrases, or message content.
