# Two-Peer Tor Validation Checklist

**Audience:** Lucas / maintainers validating HashChat on two real hosts  
**Purpose:** OPSEC-safe path for the OVERNIGHT “When Lucas wakes” two-peer exercise  
**Companion fill-in:** `scripts/validation-evidence-template.txt`  
**In-TUI posture dump:** `:evidence` (alias `:audit-status`) — metadata only, not a proof of E2EE

This checklist is for **disposable identities** on **two separate physical hosts** with **real local Tor** (SOCKS + cookie-authenticated ControlPort). Record only non-sensitive evidence.

---

## Never record (explicit)

Do **not** copy into logs, screenshots, tickets, chat, or the fill-in template:

- Tor control **cookies** or cookie file contents / paths that embed secrets
- Identity / onion **private keys**, `ED25519-V3:` blobs, or wrapped key material
- Full **onion addresses** or `hashchat://` contact links
- Passphrases or passphrase hints
- **SAS** values (short or long)
- Message **bodies**, frame bytes, or decrypt dumps
- Contact **names/ids** if they might encode secrets — prefer **counts only**
- Core dumps, heap dumps, or unredacted terminal scrollback that may contain any of the above

Safe to record: tip SHA, host/OS/Tor **versions**, UTC-offset timestamps, commands run, pass/fail, redacted UI (no onions/SAS/bodies), and `:evidence` output.

---

## Prerequisites

1. Checkout the tip named in `docs/OVERNIGHT_PROGRESS.md` on `codeberg-primary`.
2. Local Tor: loopback **SOCKS** (typically 9050) and **ControlPort** with **cookie** auth only (no bare `AUTHENTICATE`).
3. Build/run Rust TUI (`make tui` / `./run-tui` or `cargo build --release --locked --bin hashchat-tui --features tui`).
4. Use **disposable** identities; wipe or discard after the exercise.

---

## Peer A / Peer B steps

Complete on **both** hosts unless noted. Mark pass/fail in the template.

### 1. Checkout tip

- [ ] `git fetch` + checkout the documented tip SHA
- [ ] Record tip SHA (short + full if desired) — no other secrets

### 2. Tor SOCKS + cookie ControlPort

- [ ] SOCKS reachable on loopback
- [ ] ControlPort reachable; cookie auth works for `:listen` (fail-closed if cookie missing)
- [ ] Optional: run `:evidence` — expect `socks=ok` / `control=ok` tokens only

### 3. Create disposable identities

- [ ] Peer A: create/unlock a fresh session
- [ ] Peer B: create/unlock a fresh session
- [ ] Do **not** reuse production identities

### 4. Exchange signed contacts

- [ ] Each peer `:listen` (publishes v3 onion via ControlPort)
- [ ] Exchange signed `hashchat://` contacts **out of band** (secure channel of your choosing)
- [ ] Each peer `:add-contact <link>`
- [ ] Never paste full links or onions into the evidence log

### 5. SAS OOB compare

- [ ] Compare short SAS **out of band** (voice/in-person preferred)
- [ ] Do **not** write SAS values into evidence

### 6. `:verify`

- [ ] After SAS match: `:verify` on the selected / named contact
- [ ] Confirm send is allowed only after verify (or document Standard `:send-unverified` if intentionally testing bypass — Extreme must refuse)

### 7. Bidirectional send / receive

- [ ] A → B plaintext send succeeds; B receives
- [ ] B → A plaintext send succeeds; A receives
- [ ] Status/UI shows sizes / peer labels as designed — **no body echo in status**

### 8. Restart / retry

- [ ] Quit and relaunch; unlock; Tor still required
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
- [ ] Send / `:listen` / `:retry` refuse or queue without clearnet fallback
- [ ] `:evidence` shows `socks=fail` and/or `control=fail` as appropriate
- [ ] Restore Tor; confirm recovery path

### 13. Evidence capture (OPSEC-safe)

- [ ] Run `:evidence` / `:audit-status` on each peer; paste **only** those lines into the template
- [ ] Fill `scripts/validation-evidence-template.txt` (host/OS/Tor versions, tip SHA, UTC timestamps, pass/fail rows)
- [ ] Redact any accidental onion/SAS/body leakage before sharing

---

## `:evidence` honesty

`:evidence` prints **posture metadata** (unlock state, net tokens, TTL labels, contact/deny **counts**, Tor probe ok/fail, HS listening yes/no, drop count). It is **not** cryptographic proof of end-to-end encryption, forward secrecy, or peer authenticity — pair it with SAS OOB compare and signed-contact verify, and treat failures as blocking for preview claims.
