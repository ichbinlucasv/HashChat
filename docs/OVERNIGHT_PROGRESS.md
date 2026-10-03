# Overnight Progress

**Snapshot:** 3 October 2026 (Europe/Zurich)  
**Branch:** `codeberg-primary`  
**Tip:** `98baebc`

## Executive summary

HashChat now has a usable Rust two-peer TUI with fail-closed Tor transport, encrypted session blob v7, 186 passing library tests (185 without `tui`), and an offline CI security gate. Shipped controls include local disappearing TTL, Extreme minimal persistence, block/mute/delete with ratchet wipe, a SAS verification gate, idle/manual lock, unlock-attempt backoff, `:clear` transcript scrub, best-effort `mlock`, panic/signal secret scrubbing, and contact display-name rename (`:rename`). The Haskell desktop remains transitional and non-recommended; this is a hardened preview path, not a claim of production readiness.

## Shipped since the previous checkpoint

- **Security review fixes (review at `fcf01dd`, `/workspace/reviews/hashchat-security-review.md`):**
  - **H-1 — `6d275b5`:** peer text is sanitised before render (`term_sanitize::sanitize_for_terminal`): control characters and bidi/line-separator format characters become U+FFFD, tab/newline become a space. Applied when decrypted text is produced, when any transcript line is stored, and again at render for labels, title, input and status lines.
  - **H-2 — `0629290`:** ControlPort auth is now SAFECOOKIE. HashChat checks the server's proof before answering and never sends the cookie itself. The advertised cookie path is used only if it resolves to a system Tor location (`/run/tor/control.authcookie`, `/var/run/tor/…`, `/var/lib/tor/control_auth_cookie`, `/var/lib/tor/control.authcookie`). **Non-standard Tor layouts must set `HASHCHAT_TOR_COOKIE_FILE=/abs/path`**, which then becomes the only accepted path. Also: the cookie must be a 32-byte regular file, control replies are bounded, and the stored onion key is validated before `ADD_ONION`. `docs/TOR_HOST_SETUP.md` should mention the override (not edited here).
  - **H-3 — `11c933d`:** `SessionState::upsert_contact_from_link` drops SAS verification and resets the label when onion, X25519 or Ed25519 change; the TUI prints a SAFETY NUMBER CHANGED notice with old/new SAS. A byte-identical re-import keeps trust and label. New contact ids never reuse an id still referenced by verified/blocked/muted/ratchet lists.
  - **M-4 + M-6 — `8b5e1cd`:** FFI encrypt/decrypt honour the caller's output capacity; `HASHCHAT_INSECURE_DEV_PERSIST` only opts in when exactly `1`.
  - **M-7 — `149b878`:** new-store passphrase floor: 12 characters (16 under Extreme), at least 5 distinct characters. Existing stores are not re-checked.
  - **M-8 + part of M-9 — `e8526ac`:** at startup the TUI sets `RLIMIT_CORE=0` and clears `PR_SET_DUMPABLE` (best-effort; shown in `:evidence` as `process: core_limit=… · dumpable=…`). Passphrase buffers are fixed-capacity (no reallocation copies), and per-message passphrase copies are zeroized.
  - **M-3 — `948b26f`:** the onion listener serves each inbound connection on its own small thread, capped at 16 concurrent; extra connections are closed and counted (`:evidence` shows `refused_conns`). Deadlines are total-time, not per-read: a frame header must arrive within 30 s of idle, a frame body within 20 s, and a connection closes after 120 s.
  - **M-9 (rest) — `cf9cf6b`:** after unlock the TUI keeps a derived store key (`envelope::StoreKey`: salt + key, zeroized on drop, best-effort `mlock`, no Debug/Clone) and zeroizes the passphrase. All saves and outgoing commits use the key; lock, wipe, emergency scrub and exit drop it. Envelope format unchanged; a salt mismatch is refused. The gate requires `unlock_session(` in the TUI.
  - **L-1 + L-2 (FFI) — `b2f936b`:** ratchet export/import and passphrase blob FFI reuse the shared envelope module (OS CSPRNG salts/nonces, zeroized keys and plaintext, null checks). Format unchanged; duplicate Argon2id helper removed.
  - **L-3, L-5, L-6 — `eb02545`:** `rust_apply_basic_seccomp` reports `false` (no filter is installed; Haskell callers ignore the result). The unused `ratchet_recv_advanced` helper is removed (Android copy untouched). Ratchet step counters saturate instead of wrapping, and speculative receive refuses once the counter is exhausted.
  - **L-10 — `415181e`:** SOCKS proxy and ControlPort hosts are parsed as IP literals (`localhost` maps to 127.0.0.1) and must be loopback before any connect; names are never resolved. Short forms such as `127.1` are now refused.
  - **L-12 — `1803035`:** contact bootstrap (library and TUI) and speculative ratchet receive reject non-contributory (low-order) X25519 results. Honest keys are unaffected.
  - **L-7 — `90ee629`:** local pack/blob parsers cap `Vec` preallocation by the remaining input and use checked offsets. Formats unchanged.
  - **L-2 (remaining copies) — `53d1c5a`:** `DoubleRatchet::to_bytes` returns `Zeroizing<Vec<u8>>` so speculative-receive snapshots scrub on drop; `decrypt_with_key` zeroizes the in-place open buffer after copying plaintext; TUI wraps ratchet-byte and onion-key clones in `Zeroizing`, scrubs the draft via `clear_input_secure`, and uses `take_zeroizing_vec` at store call sites. No wire/blob format change. Android duplicate tree untouched.
  - **L-11 (shared BufReader) — `98baebc`:** ControlPort I/O keeps one `BufReader` for the connection lifetime (`ControlConn`); authenticate + `ADD_ONION` no longer create a fresh reader via `TcpStream::try_clone` per command (which could drop buffered reply bytes). Line/count bounds and `ED25519-V3:` key validation from H-2 remain. Regression: two sequential commands succeed when the follow-up reply was coalesced into the same TCP read.
  - **Still open from the review:** M-1 (bootstrap handshake), M-2 (skipped-key handling), M-5 (FFI global ratchet store) — deliberately left for a protocol/API-level change. Lows not done: L-4 (Haskell depends on the current behaviour), L-8 (broad FFI signature changes), L-9 (hint-length strictness is wire-parsing; needs a sender audit first). L-11 is closed (shared BufReader). Remaining L-2 copies from the review are closed. All Info items remain open.
  - **Flatpak `--filesystem=/run/tor:ro` — deferred, not committed:** with the line added, `flatpak-builder --show-manifest` parses and `flatpak-builder-lint manifest` reports no new findings. But the unchanged manifest already fails lint (`finish-args-arbitrary-dbus-access`, `finish-args-contains-both-x11-and-wayland`, `finish-args-home-filesystem-access`, `finish-args-x11-without-ipc`), and a real build needs the Nix-built prebuilts, so the "checks still pass" condition could not be met. Do not add `/var/lib/tor`.
- **State file hygiene — `779e468`:** new `private_fs` module for `hashchat_data/`. The data dir must be a non-symlink directory owned by the current user; group/other bits are cleared to 0700 (existing 0755 dirs upgrade in place). `state.enc` / `machine.key` are opened `O_NOFOLLOW` and **refused** if they are symlinks, non-regular, foreign-owned, group/other-accessible, or over a 256 MiB cap. Writes are temp file (0600) + `fsync` + `rename`, so a crash cannot leave a truncated blob and a loose-mode file is replaced rather than rewritten in place. TUI runs `check_state_storage` before the KDF; a refusal shows a fixed, path-free reason and does not count toward unlock backoff. A malformed `machine.key` (insecure-dev only) is refused instead of regenerated. Residual: only the final dir component is checked (parent symlinks such as `/home -> /var/home` stay allowed); a symlinked `hashchat_data` is refused. **No blob or wire format change.**
- **Max plaintext send size — `a1ef213`:** TUI refuses UTF-8 plaintext > **`MAX_PLAINTEXT_SEND_BYTES` (8 KiB)** via `check_plaintext_send_size` **before** ratchet encrypt; clear status, no body echo. Sized so AES-GCM + wire-v2 framing stays under `MAX_HS_INBOUND_FRAME` (16 KiB) (`MAX_FRAMED_SEND_BYTES` compile-time assert). Unit tests in `wire.rs`; `:help` one-liner. **Local UX / memory gate — not a wire-protocol version bump.**
- **Contact SOCKS isolation polish — `4bdc085`:** TUI send/retry pass optional `SocksIsolationCreds` into `socks5_send`. Prefer `socks_isolation_for_contact(contact_id, &seed)` when unlocked; fall back to `socks_isolation_for_onion` for pending retries. Creds use redacted `Debug`; never logged. Default-on NetConfig `socks_isolation` with optional `:isolate on|off|status` (Extreme forces on / refuses off); older prefs blobs default on. `:evidence` prints `socks_isol=on|off` only. Fail-closed loopback + onion policy unchanged.
- **SOCKS IsolateSOCKSAuth (initial) — `b4c7d9d`:** first cut used per-destination onion tags (`socks_isolation_credentials`) for Tor `IsolateSOCKSAuth`. Superseded for contact paths by the polish tip above; onion fallback remains for unmatched pending retries.
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

Recorded validation at tip `98baebc`: `cargo test --lib` passed 185 tests (186 with `--features tui`), `cargo build --bin hashchat-tui --features tui` succeeded, and `./scripts/ci-security-gate.sh` passed offline.

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
