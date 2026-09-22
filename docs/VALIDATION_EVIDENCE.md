# Validation evidence (`:evidence` / `:audit-status`)

**Audience:** Anyone filing tickets, overnight notes, or the two-peer fill-in  
**Checklist:** `docs/TWO_PEER_VALIDATION.md`  
**Fill-in:** `scripts/validation-evidence-template.txt`  
**Client:** Rust `hashchat-tui` (Haskell desktop is transitional / not recommended)

Tor is the default transport and is **fail-closed**. Do not document or suggest silent clearnet fallbacks.

---

## Commands

| Command | Alias | Purpose |
|---------|-------|---------|
| `:evidence` | `:audit-status` | Print **posture metadata** for OPSEC-safe validation notes |

Both names invoke the same dump. Prefer `:evidence` in tickets; `:audit-status` is an accepted alias.

---

## What `:evidence` prints (safe to share)

The dump is **metadata about posture**, not a transcript and not a crypto proof. Typical fields (token / label style; exact wording may evolve):

- Unlock / session state (locked vs unlocked labels)
- Net mode / DNS / posture **tokens** (e.g. Tor / Extreme labels — not proxy URLs with secrets)
- TTL and lock-timeout **labels**
- Contact / blocked / muted / unverified **counts** (integers only)
- Tor probe: `socks=ok|fail`, `control=ok|fail`
- Hidden-service listening yes/no and related **drop counts**

Safe companions in the same ticket or fill-in:

- Tip SHA, build method (`make tui` / `cargo` / `./run-tui`)
- Host / OS / Tor **versions** (not cookie paths with secrets)
- UTC-offset timestamps, commands run, pass/fail rows
- Redacted screenshots (onions / SAS / bodies cropped or blurred)

---

## What must NEVER appear in tickets

Do **not** paste, screenshot unredacted, commit, or attach:

| Category | Examples |
|----------|----------|
| Tor auth | Control cookies, cookie file bytes, `AUTHENTICATE` material |
| Keys | Onion private keys, `ED25519-V3:` blobs, identity key material |
| Identifiers | Full onion addresses, raw `hashchat://` contact links |
| Secrets | Passphrases, passphrase hints, SAS short/long values |
| Content | Message bodies, frame bytes, decrypt dumps, unredacted scrollback |
| Risky labels | Contact names/ids that might encode secrets — use **counts** instead |

If something sensitive appears by accident: redact before sharing, rotate disposable identities, and treat the leak as an OPSEC incident for that exercise (do not “fix” by pasting more context).

---

## Honesty limits

`:evidence` / `:audit-status` does **not** prove:

- End-to-end encryption correctness
- Forward secrecy
- Peer authenticity beyond what SAS OOB compare + signed-contact `:verify` already provide

Treat Tor-down or probe `fail` results as **blocking** for preview claims until re-validated with Tor restored. Pair every two-peer claim with the checklist in `docs/TWO_PEER_VALIDATION.md`.
