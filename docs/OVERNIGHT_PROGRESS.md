# Overnight Progress

**Snapshot:** 22 September 2026 (Europe/Zurich)  
**Branch:** `codeberg-primary`  
**Tip:** `b4c7d9d`

## Executive summary

HashChat now has a usable Rust two-peer TUI with fail-closed Tor transport, encrypted session blob v7, 111 passing library tests, and an offline CI security gate. Shipped controls include local disappearing TTL, Extreme minimal persistence, block/mute/delete with ratchet wipe, a SAS verification gate, idle/manual lock, unlock-attempt backoff, `:clear` transcript scrub, best-effort `mlock`, panic/signal secret scrubbing, and contact display-name rename (`:rename`). The Haskell desktop remains transitional and non-recommended; this is a hardened preview path, not a claim of production readiness.

## Shipped since the previous checkpoint

- **SOCKS IsolateSOCKSAuth — `b4c7d9d`:** outbound `socks5_connect` / `socks5_send` use RFC1929 username/password tags derived per destination onion (`socks_isolation_credentials`) so Tor’s default `IsolateSOCKSAuth` keeps distinct circuits per peer. Tags are never logged; `:evidence` prints `socks_isol=per-dest` only. Fail-closed loopback + onion policy unchanged. Inbound HS accept remains a single local listener.
- **Branding — `950cd8c`, `d8e9c1c`:** adopted the black-and-gold chat-bubble/hash mark, marked the lockup as canonical, and refreshed packaged icons.
- **Native Rust TUI — `a626d05`:** added the `ratatui`/`crossterm` desktop path with passphrase unlock/create, encrypted session persistence, contacts, SAS display, Tor status, and wipe entry points.
- **Tor transport — `63bbb4f`:** added cookie-authenticated ControlPort use, `ADD_ONION` listening, loopback-only SOCKS, `.onion` destination policy, framed transport, and a durable outgoing queue. There is no bare ControlPort authentication or silent clearnet fallback.
- **Linux packaging — `ce8af2d`, `fd78d23`:** installers and `run-tui` prefer Rust on Fedora, Ubuntu/Debian, and Arch; Flatpak metadata/icons and Tails/Qubes guidance align with the Rust/Tor path.
- **Two-peer messaging — `7d116c8`:** fixed listen/decrypt and send flow, signed-contact upsert, pending-message acknowledgement, and bootstrap ratchet synchronization.
- **Explicit network modes — `b067d48`:** added Tor/I2P/clearnet selection, DNS preference, and Extreme Tor-only locking. Non-Tor modes refuse messenger send/listen rather than opening an unintended socket.
- **Nuclear wipe hardening — `958327a`:** added in-memory session zeroization and a prominent TUI confirmation flow; wipe threat-model limits remain documented.
- **Mid-session DH forward secrecy — `893a85c`:** restored periodic send-side DH ratcheting after bootstrap; persisted ratchet v2 remains backward-loadable from v1, with the Android copy synchronized.
- **TUI polish — `c542aff`:** added contact selection, short SAS, selected-peer context, `:sas`, clearer `:help`, and Tor/SOCKS-gated `:retry` without plaintext in status text.
- **Durable NetConfig — `c36caa2`:** encrypted session blob v3 stores mode, DNS preference, and posture; `:mode` changes survive restart, loaded state wins after unlock, and contact/listen/send remain fail-closed.
- **Extreme metadata gates — `5c932fb`:** centralized refusal helpers for contact export, groups, and voice; Extreme shortens onion/SAS displays and exposes lock status without claiming Android parity. Haskell removal criterion 2 was initially closed in this pass.
- **Haskell removal criterion 2 — `56326da`:** removed Cabal from normal distro, Nix, Flatpak, and Forgejo CI paths while retaining explicit transitional opt-ins (`HASHCHAT_ALLOW_HASKELL=1`, `./build.sh --haskell`, `nix develop .#haskellDev`).
- **Offline CI security gate — `a07a06b`:** the required Forgejo `build` job runs `scripts/ci-security-gate.sh` before Rust tests/build, checking fail-closed network policy, persistence opt-in, cookie-only Tor authentication, and focused transport tests.
- **Disappearing messages — `43eeae6`:** added local `:disappear`/`:ttl`; blob v4 stores TTL, expired plaintext and known skipped keys are wiped, and Extreme defaults an unset TTL to 1h. TTL is not carried on the wire, so peer erasure is not enforced.
- **Extreme persistence minimization — `e917681`:** Extreme disk state retains identity, onion, network preferences, TTL, and lock timeout; contacts, ratchets, pending messages, deny lists, and verification state remain memory-only and are stripped on save.
- **Contact block/mute — `1cd057d`:** added durable Standard-mode block/mute lists in blob v5. Block refuses send and drops inbound before decrypt/display; mute keeps ratchet synchronization while suppressing UI.
- **Contact delete — `50a10e5`:** added confirmed `:delete-contact`/`:rm-contact`, wiping ratchet bytes, pending frames, related transcript, deny-list entries, and selection. Local deletion is not remote wipe.
- **Hidden-service backpressure — `fc46840`:** bounded inbound frames to 16 KiB, the accept queue to 64, and each connection to 64 frames; oversize/overflow input is dropped without exposing contents. Tor-level availability remains out of scope.
- **Best-effort TUI `mlock` — `d84e1df`:** after unlock/create, the TUI attempts `mlockall` plus passphrase-buffer locking without aborting on failure. Allocator copies and Android limits remain explicit.
- **SAS verification gate — `4b7bd57`:** new contacts start unverified; blob v6 stores Standard-mode verification, while pre-v6 contacts load verified for continuity. Send refuses unverified peers, and `:send-unverified` is unavailable in Extreme. This is a TOFU aid, not additional cryptographic binding.
- **Idle auto-lock and `:lock` — `76cd1aa`:** default 5m idle/manual lock scrubs live secrets and stops Tor listening; blob v7 stores the timeout, and Extreme caps it at 1m. Disk state remains encrypted and untouched.
- **Panic/signal scrub — `0e4ae16`:** normal drop, quit, Ctrl-C, SIGINT/SIGTERM, and unwind paths best-effort scrub passphrase, ratchet/session state, transcript, draft, SAS, and displayed contact data while restoring the terminal. Hard abort/kill and allocator copies cannot be guaranteed.
- **Unlock backoff + `:clear` — `3aa0659`:** after consecutive wrong passphrases (Standard **5** / Extreme **3**), unlock imposes exponential cooldown (2s, 4s, 8s… capped **60s** Standard / **120s** Extreme); success resets the counter; failure status stays opaque. `:clear` / `:cls` zeroize and drop the in-memory transcript only. THREATMODEL: local UI rate-limit — not remote auth; disk `state.enc` remains offline-attackable.
- **OPSEC-safe `:evidence` — `7caf285`:** `:evidence` / `:audit-status` prints unlock state, net mode/DNS/posture **tokens**, TTL/lock-timeout labels, contact/blocked/muted/unverified **counts**, Tor socks/control ok/fail, and HS listening/drops — never onions, links, SAS, passphrases, or bodies. Checklist: `docs/TWO_PEER_VALIDATION.md`; fill-in: `scripts/validation-evidence-template.txt`. Metadata about posture, not a proof of E2EE.
- **Contact display rename — `2b4a0df`:** `:rename` / `:rename-contact` set `PersistedContact.display_name` only (never id/onion/keys). Validate: trim non-empty, max 64 chars, no control chars, reject `hashchat://` lookalikes. Resolve like `:block` (selected or id/SAS/display prefix). Standard durable `save_session`; Extreme in-RAM until exit (`for_disk` still strips). Contact list shows the new label; success status omits onions/SAS. `:sas`/resolve still use recomputed fingerprints so rename cannot clobber compare material. `:evidence` unchanged (counts only).

## How to run

From `codeberg-primary`, with a compatible Rust toolchain and local Tor configured for SOCKS plus cookie-authenticated ControlPort:

```bash
make tui
./run-tui
```

Equivalent Cargo path:

```bash
cargo build --release --locked --bin hashchat-tui --features tui
./target/release/hashchat-tui
```

Unlock or create an identity, run `:listen`, exchange signed `hashchat://` contacts, compare SAS out of band, then `:verify` before sending. Use `:evidence` for posture metadata. Never copy Tor cookies, onion private material, passphrases, SAS values, or message bodies into evidence.

Recorded validation at tip `b4c7d9d`: `cargo test --lib` passed 111 tests, `cargo build --bin hashchat-tui --features tui` succeeded, and `./scripts/ci-security-gate.sh` passed offline.

## When Lucas wakes

Follow **`docs/TWO_PEER_VALIDATION.md`** (fill-in: `scripts/validation-evidence-template.txt`; in-TUI `:evidence` / `:audit-status`).

1. On two separate physical hosts using real local Tor services, check out the tip below; create disposable identities, exchange signed contacts, compare SAS out of band, `:verify`, and test bidirectional send/receive, restart/retry, TTL expiry, lock/unlock, block/mute/delete, `:rename` labels, and fail-closed behavior with Tor unavailable.
2. Record only non-sensitive evidence: tip SHA, host/OS/Tor versions, UTC-offset timestamps, `:evidence` lines, commands and pass/fail results, redacted screenshots, and observed failure modes—never cookies, keys, onions, passphrases, SAS values, or message bodies.
3. If that validation passes, prepare the v0.2 preview checklist, release notes, SBOM/diff artifacts, and signing plan; keep the release labeled preview until hardware findings are reviewed.

## Remaining backlog

- **Android parity/Keystore:** complete Keystore-backed identity/state handling, lifecycle and memory hardening, reproducible `.so`/SBOM output, and parity for contact QR, TTL, block/mute/delete, verification, lock, and persistence. Android parity is not claimed.
- **I2P:** implement and test an actual I2P start/send/listen path plus per-profile proxy configuration. Until then, non-Tor messenger modes must fail closed.
- **Disappearing messages:** wire TTL is not implemented; local expiry cannot enforce peer deletion and needs a deliberate format/protocol change.
- **Haskell retirement:** criteria 1–3 are met; criterion 4 requires a dedicated deletion PR and criterion 5 requires explicit maintainer approval. Keep the transitional tree until both occur.
- **Release scope:** complete real-hardware Tor evidence, reproducible Android artifacts, pre-tag/SBOM checks, and remaining threat-model/release-documentation review before making stronger readiness claims.

## Handoff status

This OPSEC-safe handoff contains no credentials, private onion material, passphrases, SAS values, or message content.
