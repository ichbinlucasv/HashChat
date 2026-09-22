# Overnight Progress

**Snapshot:** 22 September 2026 (Europe/Zurich)  
**Branch:** `codeberg-primary`  
**Tip:** `a07a06be18e5f05691e1e825a0785519c4f163b5`

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
- **Durable NetConfig — `c36caa2`:** session blob v3 stores mode / DNS preference / posture inside the passphrase wrap; TUI `:mode` / `:mode extreme` changes survive restart. Env still seeds cold start / new identity; loaded blob wins after unlock. `:my-contact` / listen / send remain transport-gated (fail-closed).
- **Extreme TUI metadata gates — `5c932fb`:** `NetConfig::extreme_blocks_contact_export` (plus groups/voice helpers) centralize Extreme refusals. Rust TUI refuses `:my-contact` under Extreme, keeps short `:sas`, shortens onion display in `:status`/listen status, announces locks in `:help`/`:status`, and refuses `:group`/`:voice` stubs. Docs: THREATMODEL + EXTREME_PROFILE honesty pass; INSTALL Haskell removal criteria marked MET/MET/OPEN (criterion 2 closed this pass); ROADMAP item 0 one-line status.
- **Haskell removal criterion 2 MET — `56326daf2f4f012024609f07a2b61245cb1d9ac0`:** Distro installers no longer print Cabal recipes on the happy path; `flake.nix` default package/`devShell` are Rust-only with opt-in `haskellDev`; Forgejo CI builds Rust TUI without requiring Cabal (manual `haskell-parity` only); SBOM/Flatpak notes demote Cabal. INSTALL criterion 2 → MET; opt-in hatch kept (`HASHCHAT_ALLOW_HASKELL=1`, `./build.sh --haskell`).

- **CI security gate (fail-closed, offline) — `a07a06b`:** Forgejo required `build` job runs `scripts/ci-security-gate.sh` before Rust tests/TUI build (ripgrep + policy anchors: ClearnetRefused/I2pNotImplemented + TUI `require_messenger_transport`, `HASHCHAT_INSECURE_DEV_PERSIST` opt-in only, cookie-only Tor AUTHENTICATE). Extra `tor_socks` unit tests refuse non-onion IP/short onion without network. No clippy introduced; no push.

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

The tip commit records `cargo test --lib` passing with 64 tests and a successful `cargo build --bin hashchat-tui --features tui`, plus offline `./scripts/ci-security-gate.sh`.

## Remaining backlog

### Release and validation

- Complete real-hardware two-peer/Tor validation, capture non-sensitive evidence and screenshots, and prepare the signed v0.2/preview release.
- Offline `ci-security-gate.sh` now required in Forgejo `build`; keep pre-tag gates strict; finish reproducible Android `.so` output and SBOM/diff automation.

### Rust/TUI and posture

- Extreme TUI metadata surfaces gated (contact export / groups / voice stubs / short SAS). Remaining: deeper Extreme persistence minimization and Android contact-QR parity — not claimed done here.
- Haskell retirement: criteria 1+2+3 met; 4+5 open (INSTALL.md). Keep transitional / non-recommended opt-in hatch; do not delete.

### Android and cross-device parity

- Finish Android production hardening around Keystore-backed identity state, lifecycle/memory limits, voice end-to-end handling, and full Rust/TUI behavioral parity. Android `mlock` remains inherently best-effort for an unprivileged app.

### Transport and product scope

- Implement an actual I2P start path and per-profile proxy configuration; bridge/pluggable transports remain primarily local-Tor configuration today. Non-Tor modes must continue to fail closed until their paths are implemented and tested.
- Longer-term: secure streaming file transfer, further UX polish, and the remaining threat-model/release-documentation updates.

## Handoff status

No push was made. This note is an OPSEC-safe progress handoff; it contains no credentials, private onion material, passphrases, or message content.
