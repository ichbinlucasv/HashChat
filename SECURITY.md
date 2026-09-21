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
**Argon2id(passphrase) → AES-256-GCM** into `hashchat_data/state.enc` (blob v2; v1
identity-only blobs still load). Empty passphrase is refused. No raw `machine.key`
is written on this path.

**Insecure-dev only:** set `HASHCHAT_INSECURE_DEV_PERSIST=1` to use a raw
`hashchat_data/machine.key` (mode 0600) wrap — for local CI/dev, never production.
Onion / identity private material must not appear as sibling plaintext files under
`hashchat_data/` (Tor may still keep HS keys under `tor/hidden_service/` when Tor
itself persists them; prefer `DiscardPK` / passphrase-wrapped copies in app state).

Nuclear wipe (`wipe_local_sensitive` / TUI `:wipe` → `:wipe-confirm`) deletes
`state.enc` (and thus contacts/ratchets/pending) along with other local data under
`hashchat_data/` and Tor HS material under `tor/hidden_service/`. The TUI confirm
path also zeroizes in-RAM passphrase, `onion_key`, ratchet maps, and pending frame
bodies via `SessionState::wipe_memory_secure`.

**Honest limits:** wipe is a best-effort local erase. It does not defeat kernel
implants, prior memory exfiltration, swap/core-dump residues, or forensic copies
already taken. See THREATMODEL.md.

**Durable send (H3):** prefer encrypt → durable queue commit → Tor send. A crash
after commit but before Tor ACK may resend on restart; peers should tolerate
duplicates via skipped keys. Call sites that advance without commit risk losing
forward-secrecy continuity across restart.

Message logs may still use separate Argon2id envelopes under profile dirs; the
authoritative restart path for contacts/ratchets/pending is `state.enc`.

## Responsible Disclosure

We appreciate responsible disclosure and will credit researchers (unless they prefer anonymity).

Thank you for helping keep HashChat users safe.
