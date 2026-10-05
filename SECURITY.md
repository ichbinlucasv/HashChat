# Security Policy for HashChat

HashChat is an anonymous messenger. Security is the top priority.

**Primary repository**: https://codeberg.org/ichbinlucasv/HashChat  
**Mirror**: https://github.com/ichbinlucasv/HashChat

## Supported Versions

Only the latest `main` branch is supported for security issues.

## Reporting a Vulnerability

**Please do NOT open public issues for security problems.**

Instead, report privately by:
- Opening a private security advisory on Codeberg (primary) or GitHub mirror (if available), or
- Contacting the maintainer directly (preferred for serious issues).

We take reports seriously and will respond within 48 hours.

## Maintainer validation & OPSEC reporting

When validating Tor / two-peer behavior, or reviewing bug and security reports:

- Checklist: [`docs/TWO_PEER_VALIDATION.md`](docs/TWO_PEER_VALIDATION.md)
- What `:evidence` / `:audit-status` prints (safe metadata): [`docs/VALIDATION_EVIDENCE.md`](docs/VALIDATION_EVIDENCE.md)
- What reports should include vs forbid: [`docs/OPSEC_REPORTING.md`](docs/OPSEC_REPORTING.md)
- Fill-in template: `scripts/validation-evidence-template.txt`

In the Rust TUI, `:evidence` (alias `:audit-status`) dumps **posture metadata only** — not a proof of E2EE. Prefer those lines in tickets over free-form dumps.

### Never record / never ask reporters to paste

Do **not** copy into logs, screenshots, tickets, advisories, chat, or git commits (and do **not** instruct reporters to paste):

- Tor control **cookies** / cookie file bytes / secret-bearing cookie paths
- Identity or onion **private keys** (`ED25519-V3:` blobs, etc.)
- Full **onion addresses** or raw `hashchat://` contact links
- Passphrases or passphrase hints
- **SAS** values (short or long)
- Message **bodies**, frame bytes, decrypt dumps, unredacted scrollback
- Contact names/ids that might encode secrets — use **counts** from `:evidence`

Ask for tip SHA, OS/Tor versions, reproduce steps without secrets, and `:evidence` output instead. See `docs/OPSEC_REPORTING.md`.

## Critical Rules for Contributors & Users

1. **Never commit**:
   - Anything inside `tor/hidden_service/`
   - Compiled Rust libraries (`rust-lib/`)
   - Any `.onion` private keys
   - Database files (`*.db`)

2. **Tor Hidden Services**:
   - Real `.onion` private keys must never leave your machine.
   - The `tor/torrc` in this repo is safe to share (it contains no secrets).

3. **Cryptography**:
   - All changes to `src/rust/ratchet.rs` or encryption code must be reviewed.
   - We use `ring` + `x25519-dalek` for primitives.

4. **Build Artifacts**:
   - Never commit `target/`, `dist-newstyle/`, or generated launchers.

5. **Android**:
   - Never commit native libraries built for release without stripping symbols.


## At-rest crypto (desktop)

**Default (secure path):** long-term identity seed, onion material, **contacts**,
**per-contact Double Ratchet state**, and **pending outbound frames** are wrapped with
**Argon2id(passphrase) → AES-256-GCM** into `hashchat_data/state.enc` (blob v4: identity + contacts/ratchets/pending + net prefs + disappear TTL; v1–v3 still load with defaults). Empty passphrase is refused. No raw `machine.key`
is written on this path.

**Insecure-dev only:** set `HASHCHAT_INSECURE_DEV_PERSIST=1` to use a raw
`hashchat_data/machine.key` (mode 0600) wrap — for local CI/dev, never production.
Onion / identity private material must not appear as sibling plaintext files under
`hashchat_data/` (Tor may still keep HS keys under `tor/hidden_service/` when Tor
itself persists them; prefer `DiscardPK` / passphrase-wrapped copies in app state).

**CI posture:** Forgejo `build` on push/PR runs `scripts/ci-security-gate.sh` (offline,
fail-closed) before Rust tests/TUI build — asserts Clearnet/I2P refusals + TUI
`require_messenger_transport`, insecure-dev persist opt-in only, cookie-only Tor
ControlPort AUTHENTICATE (no bare AUTHENTICATE), cargo-audit config presence (I-1),
and release-notes honesty that the `quantum` feature is not production PQ (I-8).
Forgejo then runs `cargo audit --deny warnings` with known ratatui 0.29 transitive
informational advisories ignored in `.cargo/audit.toml`. The offline gate soft-skips
audit when the tool or advisory DB is missing so local/offline runs stay deterministic.
No Tor daemon required for the gate itself.

A duress passphrase (`:duress set`) triggers the same wipe when typed at the unlock prompt; see THREATMODEL.md for what that does and does not cover.

The dead-man switch (`:deadman set N`) runs the same wipe at startup if the store has not been unlocked for N days. It only fires when HashChat is started; if the program is never run again, nothing happens.

Nuclear wipe (`wipe_local_sensitive` / TUI `:wipe` → `:wipe-confirm`) deletes
`state.enc` (and thus contacts/ratchets/pending) along with other local data under
`hashchat_data/` and Tor HS material under `tor/hidden_service/`. The TUI confirm
path also zeroizes in-RAM passphrase, `onion_key`, ratchet maps, and pending frame
bodies via `SessionState::wipe_memory_secure`.

Before unlinking, the wipe overwrites each file under `hashchat_data/` and
`tor/hidden_service/` once with random bytes and syncs it. That matters mostly for
the Tor hidden service key, which Tor keeps unencrypted. On SSDs, copy-on-write
filesystems and snapshots the overwrite may not reach the old blocks.

**Honest limits:** wipe is a best-effort local erase. It does not defeat kernel
implants, prior memory exfiltration, swap/core-dump residues, or forensic copies
already taken. See THREATMODEL.md.

**Durable send (H3):** prefer encrypt → durable queue commit → Tor send. A crash
after commit but before Tor ACK may resend on restart. The receiver refuses a
frame for a step it has already consumed, so a resent duplicate is dropped. Lost
or reordered frames are tolerated: keys passed over are stored (at most
`MAX_SKIP` = 200 per frame, 1000 per contact, oldest dropped first) and a late
frame opens with its stored key, which is then erased. Losing every frame of a
whole DH epoch still breaks the session; fixing that needs the previous chain
length in the header, which is planned with the bootstrap handshake change.
The queue holds at most 64 frames. When it is full a send is refused before the
ratchet advances, instead of being dropped after the fact; `:retry` frees space.
Call sites that advance without commit risk losing forward-secrecy continuity
across restart.

Message logs may still use separate Argon2id envelopes under profile dirs; the
authoritative restart path for contacts/ratchets/pending is `state.enc`.

**Disappearing messages (Rust TUI):** `:disappear` / `:ttl` sets a local TTL (persisted in `state.enc` blob v4). Expiry erases UI plaintext and attempts `wipe_skipped_key` on the contact ratchet when `msg_number` is known. **TTL is not on the wire** — peers are not forced to erase. Bodies are not durably logged beyond the in-memory transcript. Extreme defaults to 1h when TTL was off.

## Unsafe inventory (I-5)

`hashchat-tui` contains **no** `unsafe`. All `unsafe` lives in the Rust library and
is intentional FFI / Linux hardening, not peer-facing parsers:

| Location | Role | Notes |
|---|---|---|
| `src/rust/lib.rs` | FFI slice/pointer views, `static mut` ratchet store, `mlock`/`mlockall`/`madvise`, `setrlimit`/`prctl` | Covered by open review items M-4/M-5/L-8 for API contract; TUI path does not use the raw FFI store |
| `src/rust/emergency_scrub.rs` | `libc::signal` for SIGINT/SIGTERM flag | Handler only stores an atomic; no secret access |
| `src/rust/private_fs.rs` | `geteuid` ownership checks; test-only `mkfifo` | Production path is read-only uid check |

Reducing further `unsafe` means finishing M-5 (mutex + generation IDs for the FFI
store) and L-8 (`unsafe extern "C"` + null checks) — deliberately deferred as
API-level work. Do not add new `unsafe` in the TUI.

## Quantum feature (I-8)

The optional Cargo feature `quantum` compiles `src/rust/quantum.rs`, which is a
**stub**: every hybrid API returns an error. Enabling the feature does **not**
provide post-quantum security. Release notes and `docs/RELEASE_PROCESS.md` must
keep an explicit “not production PQ” disclaimer; the CI security gate checks this.

## Responsible Disclosure

We appreciate responsible disclosure and will credit researchers (unless they prefer anonymity).

Thank you for helping keep HashChat users safe.
