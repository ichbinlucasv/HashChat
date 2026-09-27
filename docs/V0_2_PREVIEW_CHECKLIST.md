# v0.2 Linux Preview — Release-Readiness Checklist

**Scope:** Linux preview of the Rust desktop TUI (`hashchat-tui --features tui`). Preview only — no production-readiness claim.  
**Transport:** Tor is the default network and is **fail-closed**; there is **no silent clearnet fallback**.  
**Related:** [`RELEASE_PROCESS.md`](RELEASE_PROCESS.md) (formal process), [`RELEASE_NOTES_v0.2.md`](RELEASE_NOTES_v0.2.md) (notes), [`TESTING_STRATEGY.md`](TESTING_STRATEGY.md), [`BUILD_REPRODUCIBILITY.md`](BUILD_REPRODUCIBILITY.md).

This checklist collects the steps a maintainer should complete before calling a tip "v0.2 Linux preview ready". It does not replace `RELEASE_PROCESS.md`; it is a practical run sheet that points at the existing scripts and docs.

---

## 1. Tip and tree

- [ ] Working on `codeberg-primary`, fetched and not behind the Codeberg tip.
- [ ] Record the full tip SHA being validated (safe to share).
- [ ] `git status` is clean for the release build (no unrelated local edits in the build tree).

## 2. Build

Rust-only release path (Cabal/GHC are not required; Haskell desktop is transitional / not recommended — see [INSTALL.md § Haskell desktop removal criteria](../INSTALL.md#haskell-desktop-removal-criteria)).

- [ ] Library: `cargo build --release --locked` (produces `target/release/libhashchat_rust.so`).
- [ ] **Preferred desktop build:** `cargo build --release --locked --bin hashchat-tui --features tui`
- [ ] `test -x target/release/hashchat-tui`
- [ ] Convenience wrappers behave the same where used: `make tui` / `./run-tui` (see [`INSTALL.md`](../INSTALL.md)).

## 3. Tests and gates

These mirror the required `build` job in [`.forgejo/workflows/build.yml`](../.forgejo/workflows/build.yml) and the existing scripts under `scripts/`.

- [ ] **CI security gate (offline, fail-closed):** `./scripts/ci-security-gate.sh` (requires `rg`). Checks NetMode Clearnet/I2P refusal anchors and the TUI transport gate, insecure-dev persistence remains opt-in, and cookie-only ControlPort `AUTHENTICATE`.
- [ ] Unit tests: `cargo test --lib` (also `make test`).
- [ ] Release-profile tests: `cargo test --release`.
- [ ] Supply chain (CI, blocking): `cargo audit --deny warnings` passes.
- [ ] Forgejo `build` job is green on the tip being validated. (The `haskell-parity` job is manual/opt-in and is **not** a release gate.)
- [ ] **Before any signed tag:** `./scripts/pre-tag-check.sh --strict` (runs `scripts/clean-security.sh --strict`, `cargo test --release`, `cargo audit --deny high`, sensitive-file checks, SBOM generation, and testing-strategy checks).
- [ ] SBOM: `./scripts/generate-sbom.sh <outdir>` output reviewed / diffed against the previous preview.

## 4. Two-peer Tor validation

Follow [`TWO_PEER_VALIDATION.md`](TWO_PEER_VALIDATION.md) end to end on **two separate physical hosts** with **disposable identities** and **real local Tor**.

- [ ] Host Tor configured per [`TOR_HOST_SETUP.md`](TOR_HOST_SETUP.md): loopback SOCKS + cookie-authenticated ControlPort; cookie file readable by the user running the TUI.
- [ ] All steps in `TWO_PEER_VALIDATION.md` pass on both peers (identities, signed contact exchange, SAS out-of-band compare, `:verify`, bidirectional send/receive, restart/retry, TTL, lock/unlock, block/mute/delete).
- [ ] **Tor-down fail-closed:** with Tor stopped, send/listen refuse and nothing falls back to clearnet.
- [ ] Posture captured with `:evidence` (alias `:audit-status`) on each peer — metadata only; see [`VALIDATION_EVIDENCE.md`](VALIDATION_EVIDENCE.md) for what it prints and what it does **not** prove (it is not a proof of E2EE, forward secrecy, or peer authenticity).
- [ ] `scripts/validation-evidence-template.txt` filled in (tip SHA, host / OS / Tor versions, UTC-offset timestamps, pass/fail rows).
- [ ] Optional hardware evidence log via `./scripts/real-device-test.sh` (guided; writes under `docs/evidence/`).

## 5. Network posture

- [ ] Tor is the default messenger transport.
- [ ] Non-Tor modes (`I2P`, `Clearnet`) are explicit refusals and do not open messenger sockets (enforced by `scripts/ci-security-gate.sh` anchors).
- [ ] No code path or doc for the preview suggests a silent clearnet fallback.
- [ ] Release notes and install docs state that host Tor is required.

## 6. Known limitations (must appear in release notes)

- [ ] **No I2P path yet.** I2P mode is selectable but refuses send/listen; there is no working I2P transport in this preview.
- [ ] **Disappearing-message TTL is local-only.** `:disappear` / `:ttl` erase messages locally; erasure on the peer is **not** enforced on the wire.
- [ ] **Haskell desktop retirement is incomplete.** Per [INSTALL.md § Haskell desktop removal criteria](../INSTALL.md#haskell-desktop-removal-criteria), criteria 1–3 are met and criteria 4 and 5 are open:
  - Criterion 4 (open): a dedicated PR on `codeberg-primary` that documents deletion, updates SBOM/scripts that still mention Haskell, and confirms `cargo test --lib` + release TUI build stay green has not been filed.
  - Criterion 5 (open): the maintainer has not explicitly approved tree removal.
  - The Haskell tree stays in-tree (opt-in only via `HASHCHAT_ALLOW_HASKELL=1`) and is not a supported preview path.
- [ ] Other limitations already listed in [`RELEASE_NOTES_v0.2.md`](RELEASE_NOTES_v0.2.md) and [`THREATMODEL.md`](../THREATMODEL.md) are still accurate for this tip.

## 7. Reporting

All bug reports, validation notes, and security reports follow [`OPSEC_REPORTING.md`](OPSEC_REPORTING.md). Security issues go through private channels (see [`SECURITY.md`](../SECURITY.md)).

- [ ] Reports include only safe data: tip SHA, OS / Tor versions, redacted steps, pass/fail, and `:evidence` / `:audit-status` output.
- [ ] **Never paste:** Tor control cookies or cookie bytes, identity/onion private keys, full onion addresses or raw `hashchat://` links, passphrases or hints, SAS values, message bodies / frame bytes / decrypt dumps, or core dumps and unredacted scrollback.
- [ ] Evidence, tickets, screenshots, and commits reviewed for the above before publishing.

## 8. Sign-off

- [ ] Sections 1–7 complete for the recorded tip SHA.
- [ ] Remaining release steps continue in [`RELEASE_PROCESS.md`](RELEASE_PROCESS.md).
