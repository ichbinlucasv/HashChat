# Two-Peer Tor Validation Checklist

**Audience:** Maintainers validating HashChat on two real hosts  
**Purpose:** OPSEC-safe path for the overnight “When Lucas wakes” two-peer exercise  
**Client:** Rust `hashchat-tui` only (Haskell Brick is transitional / not recommended)  
**Companion fill-in:** `scripts/validation-evidence-template.txt`  
**What `:evidence` prints:** `docs/VALIDATION_EVIDENCE.md`  
**In-TUI posture dump:** `:evidence` (alias `:audit-status`) — metadata only, **not** a proof of E2EE

This checklist is for **disposable identities** on **two separate physical hosts** with **real local Tor** (loopback SOCKS + cookie-authenticated ControlPort). Tor is the **default** transport and is **fail-closed**: there is **no silent clearnet fallback**. Record only non-sensitive evidence.

---

## Never record (explicit)

Do **not** copy into logs, screenshots, tickets, chat, git commits, or the fill-in template:

| Forbidden | Why |
|-----------|-----|
| Tor control **cookies** / cookie file bytes | Authenticators for ControlPort |
| Cookie **paths that embed secrets** | Can leak layout + auth material |
| Identity / onion **private keys**, `ED25519-V3:` blobs | Permanent deanonymization risk |
| Full **onion addresses** or `hashchat://` contact links | Long-lived identifiers |
| Passphrases or passphrase hints | Account takeover |
| **SAS** values (short or long) | Out-of-band secrets; logging defeats compare |
| Message **bodies**, frame bytes, decrypt dumps | Content compromise |
| Contact **names/ids** that might encode secrets | Prefer **counts only** via `:evidence` |
| Core dumps, heap dumps, unredacted scrollback | May contain any of the above |

**Safe to record:** tip SHA; host / OS / Tor **versions**; UTC-offset timestamps; commands run; pass/fail rows; redacted UI (no onions / SAS / bodies); and `:evidence` / `:audit-status` output as documented in `docs/VALIDATION_EVIDENCE.md`.

---

## Prerequisites

1. Checkout the tip named in `docs/OVERNIGHT_PROGRESS.md` on branch `codeberg-primary`.
2. Local Tor: loopback **SOCKS** (typically `9050`) and **ControlPort** with **cookie** auth only (no bare `AUTHENTICATE` password).
3. Build/run the **Rust** TUI (`make tui` / `./run-tui`, or `cargo build --release --locked --bin hashchat-tui --features tui`). Do not use the Haskell desktop for this exercise.
4. Use **disposable** identities; wipe or discard after the exercise (`./scripts/clean-security.sh --strict` when appropriate).

Quick start pointers: [INSTALL.md](../INSTALL.md) (Tor setup) · [README.md](../README.md) · this checklist · fill-in template.

---

## Peer A / Peer B steps

Complete on **both** hosts unless noted. Mark pass/fail in `scripts/validation-evidence-template.txt`.

### 1. Checkout tip

- [ ] `git fetch` (HTTPS Codeberg) + checkout the documented tip SHA on `codeberg-primary`
- [ ] Record tip SHA (short + full if desired) — no other secrets

### 2. Tor SOCKS + cookie ControlPort

- [ ] SOCKS reachable on loopback
- [ ] ControlPort reachable; cookie auth works for `:listen` (fail-closed if cookie missing / unreadable)
- [ ] Optional: run `:evidence` — expect `socks=ok` / `control=ok` tokens only (never dump cookie bytes)

### 3. Create disposable identities

- [ ] Peer A: create/unlock a fresh session
- [ ] Peer B: create/unlock a fresh session
- [ ] Do **not** reuse production identities

### 4. Exchange signed contacts

- [ ] Each peer `:listen` (publishes v3 onion via ControlPort)
- [ ] Exchange signed `hashchat://` contacts **out of band** (secure channel of your choosing)
- [ ] Each peer `:add-contact <link>`
- [ ] Never paste full links or onions into the evidence log or tickets

### 5. SAS OOB compare

- [ ] Compare short SAS **out of band** (voice / in-person preferred)
- [ ] Do **not** write SAS values into evidence, tickets, or commits

### 6. `:verify`

- [ ] After SAS match: `:verify` on the selected / named contact
- [ ] Confirm send is allowed only after verify (or document Standard `:send-unverified` if intentionally testing bypass — Extreme must refuse)

### 7. Bidirectional send / receive

- [ ] A → B plaintext send succeeds; B receives
- [ ] B → A plaintext send succeeds; A receives
- [ ] Status/UI shows sizes / peer labels as designed — **no body echo in status**

### 8. Restart / retry

- [ ] Quit and relaunch; unlock; Tor still required (no clearnet path)
- [ ] With a queued offline frame (if induced): `:retry` after SOCKS returns
- [ ] Extreme: expect contacts/queue/deny/verify **not** durable — re-add as needed

### 9. TTL (local disappear)

- [ ] `:disappear` / `:ttl` set a short TTL; confirm local erase behavior
- [ ] Honesty: TTL is **local** — peer erasure is not enforced on the wire

### 10. Lock / unlock

- [ ] `:lock` clears RAM secrets and returns to unlock; disk `state.enc` intact
- [ ] Idle `:lock-timeout` behavior acceptable for the posture under test
- [ ] Unlock with correct passphrase restores session (Standard durable state)

### 11. Block / mute / delete

- [ ] `:block` — send refused; inbound dropped without decrypt/display
- [ ] `:mute` — inbound suppressed in UI; ratchet can still sync
- [ ] `:delete-contact` (confirm) — local wipe of ratchet/pending/related UI; **not** remote wipe
- [ ] Record **counts** via `:evidence`, not ids/onions

### 12. Tor-down fail-closed

- [ ] Stop or block local Tor SOCKS/ControlPort
- [ ] Send / `:listen` / `:retry` refuse or queue **without** clearnet fallback
- [ ] `:evidence` shows `socks=fail` and/or `control=fail` as appropriate
- [ ] Restore Tor; confirm recovery path

### 13. Evidence capture (OPSEC-safe)

- [ ] Run `:evidence` / `:audit-status` on each peer; paste **only** those lines into the template
- [ ] Fill `scripts/validation-evidence-template.txt` (host/OS/Tor versions, tip SHA, UTC-offset timestamps, pass/fail rows)
- [ ] Before sharing: re-read `docs/VALIDATION_EVIDENCE.md` “never put in tickets”; redact any accidental onion/SAS/body leakage

---

## `:evidence` honesty

`:evidence` / `:audit-status` prints **posture metadata** (unlock state, net tokens, TTL labels, contact/deny **counts**, Tor probe ok/fail, HS listening yes/no, drop count). Details: `docs/VALIDATION_EVIDENCE.md`.

It is **not** cryptographic proof of end-to-end encryption, forward secrecy, or peer authenticity. Pair it with SAS OOB compare and signed-contact `:verify`, and treat failures as blocking for preview claims.
