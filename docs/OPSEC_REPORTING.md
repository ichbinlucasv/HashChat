# OPSEC-safe bug and security reporting

**Audience:** Anyone filing bugs, overnight notes, or private security reports  
**Maintainer validation:** `docs/TWO_PEER_VALIDATION.md`  
**What `:evidence` prints:** `docs/VALIDATION_EVIDENCE.md`  
**Fill-in (two-peer):** `scripts/validation-evidence-template.txt`  
**Client:** Rust `hashchat-tui` (Haskell desktop is transitional / not recommended)

Tor is the **default** transport and is **fail-closed**. Do not suggest silent clearnet fallbacks in reports.

This note tells reporters **what to include** and **what never to paste**. Maintainers: point contributors here from `SECURITY.md` / `CONTRIBUTING.md`.

---

## Prefer private channels for security

- Security vulnerabilities: **private** Codeberg advisory (primary) or GitHub mirror advisory, or contact the maintainer directly.
- Do **not** open a public issue for a security problem.
- Ordinary non-security bugs may use public issues — still follow the never-paste rules below.

---

## Include (safe)

| Include | Notes |
|---------|--------|
| Tip SHA | Branch `codeberg-primary` short/full SHA |
| Host / OS / Tor **versions** | Not cookie paths that embed secrets |
| Build / run method | e.g. `make tui`, `./run-tui`, `cargo … --features tui` |
| UTC-offset timestamps | When the failure happened |
| Steps to reproduce | Commands and UI actions — **no** secrets in the steps |
| Expected vs actual | Pass/fail language is fine |
| `:evidence` / `:audit-status` output | Metadata only; see `docs/VALIDATION_EVIDENCE.md` |
| Redacted screenshots | Crop/blur onions, SAS, bodies, contact links |
| Failure mode labels | e.g. SOCKS fail, ControlPort cookie missing, listen refused |

For two-peer Tor validation claims, follow `docs/TWO_PEER_VALIDATION.md` and fill `scripts/validation-evidence-template.txt` instead of inventing a new evidence format.

---

## Never paste (forbidden)

Do **not** put any of the following into issues, advisories, chat, screenshots, git commits, or attachments:

| Forbidden | Why |
|-----------|-----|
| Tor control **cookies** / cookie file bytes | ControlPort authenticators |
| Cookie **paths that embed secrets** | Layout + auth leakage |
| Identity / onion **private keys**, `ED25519-V3:` blobs | Permanent deanonymization |
| Full **onion addresses** or raw `hashchat://` contact links | Long-lived identifiers |
| Passphrases or passphrase hints | Account takeover |
| **SAS** values (short or long) | Logging defeats out-of-band compare |
| Message **bodies**, frame bytes, decrypt dumps | Content compromise |
| Contact **names/ids** that might encode secrets | Prefer **counts** from `:evidence` |
| Core dumps, heap dumps, unredacted scrollback | May contain any of the above |

**Never instruct anyone to paste secrets “for debugging.”** Ask for posture metadata (`:evidence`), versions, tip SHA, and redacted steps instead.

If something sensitive appears by accident: redact before sharing, rotate disposable identities when appropriate, and treat it as an OPSEC incident for that exercise — do not “fix” by pasting more context.

---

## Honesty about `:evidence`

`:evidence` (alias `:audit-status`) prints **posture metadata** (unlock state, net tokens, TTL labels, contact/deny **counts**, Tor probe ok/fail, HS listening yes/no). It does **not** prove E2EE, forward secrecy, or peer authenticity.

Details: `docs/VALIDATION_EVIDENCE.md`.
