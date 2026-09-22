# Overnight Progress

**Snapshot:** 22 September 2026 (Europe/Zurich)  
**Branch:** `codeberg-primary`  
**Tip:** `0e4ae16`

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

- **Disappearing messages (Rust TUI) — `43eeae6`:** Local TTL via `:disappear` / `:ttl` (off|30s|5m|1h|…). Session blob **v4** stores `disappear_ttl_secs` (0=off); v1–v3 load TTL=0. In-memory chat lines carry `expires_at` + optional ratchet msg number; on tick, expired plaintext is zeroized/dropped and `DoubleRatchet::wipe_skipped_key` runs when msg_number is known. Extreme defaults TTL to 1h when still off. **Honesty:** TTL is not on the wire — peer erase is not enforced. Message bodies stay in-memory transcript only (no durable body log). Tor-first / fail-closed unchanged.

- **Extreme persistence minimization (Rust TUI) — `e917681`:** Under Extreme posture, `SessionState::for_disk` / `save_session` persist identity + onion + net prefs + disappear TTL only; contacts / ratchets / pending are written empty (blob stays v4). Load keeps legacy contacts in RAM for the current session; next Extreme save strips them. Switching *to* Extreme clears in-memory chat transcript (zeroize). `:status`/`:help` note contacts/queue are not durable and do not claim Android Extreme parity. Standard H3 round-trip unchanged. Tests: Extreme save→load empty contacts/pending; Standard keeps contacts; legacy Extreme-with-contacts then Extreme save strips.


- **Contact block / mute (Rust TUI) — `1cd057d`:** `:block` / `:unblock` / `:blocked` plus optional `:mute` / `:unmute`. Session blob **v5** stores blocked/muted contact-id lists under Standard (v1–v4 load empty lists). Block = refuse send + drop inbound without decrypt/display (fail-closed; no plaintext in status). Mute = decrypt for ratchet sync, suppress UI. Extreme `for_disk` strips deny lists with contacts/queue. Tests: v5 round-trip, v4→empty deny lists, SAS-prefix resolve + refuse helpers, Extreme strip. THREATMODEL + EXTREME_PROFILE honesty. No push.

- **Contact delete + ratchet wipe (Rust TUI) — `50a10e5`:** `:delete-contact` / `:rm-contact` with two-step `:delete-contact-confirm` (wipe-style OPSEC). Resolves like `:block` (id / onion / unique SAS or id prefix / selected). On confirm: zeroize ratchet bytes + pending frames for that dest, drop mute/block entries, remove contact, durable `save_session`, zeroize related chat lines, clear selection if needed. Status: "Contact removed and ratchet wiped" (no onion/plaintext). Extreme: same in-RAM wipe; save still strips lists. Tests for `SessionState::delete_contact_secure`. THREATMODEL note: local delete ≠ remote wipe. No push.

- **HS accept backpressure — `fc46840`:** App-side bounds on Tor HS local accept path: `MAX_HS_INBOUND_FRAME` = 16 KiB (≤ `MAX_SOCKS_FRAME`), bounded inbound `sync_channel` (`HS_INBOUND_QUEUE_CAP` = 64; full → drop + count, never unbounded), soft per-connection frame budget (64). Oversize length closes stream without reading/queuing body. Drop counter exposed (no frame contents in status/logs). Unit tests for oversize rejection + queue-full drops (local TCP, no Tor). **Honesty:** local HS still depends on Tor for real availability; this is process memory/queue backpressure only. THREATMODEL DDoS note updated. No push.

- **Best-effort TUI mlock — `d84e1df`:** After successful unlock/create, Rust TUI calls `mlockall(MCL_CURRENT|MCL_FUTURE)` + `mlock` on the live passphrase `String` bytes (safe wrappers `mlockall_current` / `mlock_bytes` in lib; FFI unchanged for Android stubs). Failure never aborts; status notes once “mlock unavailable (best-effort)”. Unit smoke: wrappers return bool without panicking (no CAP_IPC_LOCK). **Honesty:** mlock is best-effort; String reallocation makes per-buffer lock imperfect; Tails/Qubes stronger; Android still weaker. CI gate optional anchor that TUI references `mlockall_current`. No push.

- **SAS verify gate before send — `4b7bd57`:** New `:add-contact` entries start **unverified**; session blob **v6** stores `verified_ids` (Standard durable). Pre-v6 contacts load as verified for continuity. `:verify` / `:unverify` after short SAS compare (Extreme: short SAS only). Send refuses unverified; `:send-unverified` Standard-only (Extreme: no bypass). Contact list shows `[unverified]`. Extreme `for_disk` strips verified set with contacts/queue/deny lists. **Honesty:** TOFU helper on Ed25519 link verify — not extra cryptographic binding. Tests: v6 round-trip, pre-v6 continuity, Extreme strip, refuse helpers. THREATMODEL + EXTREME_PROFILE. No push.





- **Idle auto-lock + `:lock` (Rust TUI) — `76cd1aa`:** After N minutes without input (default **5m**; `:lock-timeout off|1m|5m|15m|30m|…`) or on manual `:lock`, the TUI zeroizes passphrase + chat lines + contact-link display strings, drops `SessionState` from RAM (`wipe_memory_secure`), and stops the HS accept / Tor listen path. Disk `state.enc` untouched; re-unlock via existing `load_session` (onion key stays inside the passphrase wrap only). Session blob **v7** stores `lock_timeout_secs` (pre-v7 loads default 300). Extreme shortens to **1m** when timeout is off or longer. `:status`/`:help`/header document; no plaintext in lock messages. Tests: timeout parse + prefs round-trip + pre-v7 default; TUI build; `ci-security-gate` `lock_ui` anchor. **Honesty:** local UI defense only — not remote wipe. THREATMODEL + EXTREME_PROFILE. No push.


- **Panic / signal best-effort scrub — `0e4ae16`:** Rust TUI now scrubs the live passphrase, session/ratchet state, transcript, draft, SAS, and contact-link display buffers on normal drop, quit, Ctrl-C, and polled SIGINT/SIGTERM paths; panic unwinding restores the terminal and reaches the same `Drop` scrub. The CI security gate checks hook installation. **Honesty:** this does not erase disk, allocator copies may remain, and hard abort/kill paths cannot be guaranteed.

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

The tip commit records `cargo test --lib` passing with 100 tests (including panic/signal scrub, idle lock/v7 blob, SAS verify/v6, mlock wrapper smoke, HS backpressure, and framed limits) and a successful `cargo build --bin hashchat-tui --features tui`, plus offline `./scripts/ci-security-gate.sh` (TUI mlockall_current + lock_ui anchors).

## Remaining backlog

### Release and validation

- Complete real-hardware two-peer/Tor validation, capture non-sensitive evidence and screenshots, and prepare the signed v0.2/preview release.
- Offline `ci-security-gate.sh` now required in Forgejo `build`; keep pre-tag gates strict; finish reproducible Android `.so` output and SBOM/diff automation.

### Rust/TUI and posture

- Extreme TUI metadata surfaces gated (contact export / groups / voice stubs / short SAS). Local disappearing TTL enabled (default 1h under Extreme when previously off). Extreme durable footprint minimized (contacts/queue/deny lists not written; identity/onion/prefs/TTL still persist). Contact block/mute + delete-contact (ratchet wipe) + SAS verify gate (v6) + idle auto-lock / `:lock` (v7) shipped on Rust TUI. Remaining: wire-enforced TTL (not planned without format bump), and Android contact-QR / disappear / block / persistence parity — not claimed done here.
- Haskell retirement: criteria 1+2+3 met; 4+5 open (INSTALL.md). Keep transitional / non-recommended opt-in hatch; do not delete.

### Android and cross-device parity

- Finish Android production hardening around Keystore-backed identity state, lifecycle/memory limits, voice end-to-end handling, and full Rust/TUI behavioral parity. Android `mlock` remains inherently best-effort for an unprivileged app.

### Transport and product scope

- Implement an actual I2P start path and per-profile proxy configuration; bridge/pluggable transports remain primarily local-Tor configuration today. Non-Tor modes must continue to fail closed until their paths are implemented and tested. HS accept path now has app-side frame/queue bounds; Tor-level DoS / circuit availability remains out of app scope.
- Longer-term: secure streaming file transfer, further UX polish, and the remaining threat-model/release-documentation updates.

## Handoff status

No push was made. This note is an OPSEC-safe progress handoff; it contains no credentials, private onion material, passphrases, or message content.
