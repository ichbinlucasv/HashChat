# HashChat v0.2 Release Process (Formal Skeleton)

**Owner:** Core maintainers  
**Date:** 2026  
**Status:** Draft / Expert Recommendation  
**Desktop product surface:** Rust TUI (`hashchat-tui --features tui`)  
**Transport:** Tor-only by default; **fail-closed** (no silent clearnet fallback). Host Tor required for Flatpak.

## 1. Pre-Release Checklist (Cybersecurity Expert Requirements)

- [ ] All critical + high-value items from the 14-item expert list are either complete or have clear "known limitation" entries in the release notes.
- [ ] `./scripts/clean-security.sh` has been run on a clean tree.
- [ ] Git history has been cleaned (see rec-10) and force-with-lease push performed (when intentionally rewriting; otherwise normal fast-forward to Codeberg primary).
- [ ] `cargo test --release` (and Android unit tests where applicable) pass locally and in CI with no regressions on paranoid paths (wipe, posture, disappearing, export roundtrips, mlock safety).
- [ ] Desktop release path builds: `cargo build --release --locked --bin hashchat-tui --features tui` (Haskell / Cabal is transitional / not recommended).
- [ ] No hardcoded "demo-pass" or equivalent secrets remain in production code paths (only in clearly marked tests/examples).
- [ ] Android Rust crate has real DoubleRatchet serialization for export/import (high-4), or the gap is called out loudly in RELEASE_NOTES.
- [ ] THREATMODEL.md has been updated with all new features (cross-device export, groups with sender keys, voice chunking, net-mode refuse paths, etc.).
- [ ] RELEASE_NOTES_v0.2.md is complete, honest, OPSEC-safe, and includes:
  - What is strong
  - Known limitations and audit findings
  - Recommended hardened usage (preview — no production-readiness overclaim)
  - Security contact
  - Pointer to `docs/TWO_PEER_VALIDATION.md` for hardware / two-peer Tor evidence

## 2. Build & Reproducibility

- [ ] `nix build .#hashchat-flatpak` produces a clean, reproducible `.flatpak` whose `command` / desktop `Exec` is **`hashchat-tui`**.
- [ ] Flatpak docs state **host Tor required** (SOCKS + ControlPort cookie auth; cookie not bundled) and **fail-closed** non-Tor behavior.
- [ ] Android `.so` files are built from a documented, reproducible process (long-11) where claimed.
- [ ] All builds use pinned toolchains where possible.

## 3. Signing & Distribution (Final v0.2 Polish + Signed Tag Prep)

**Pre-Tag Checklist (Run this sequence):**
```bash
# NEVER relax this ritual (protect clean-security + force-with-lease discipline)
./scripts/clean-security.sh
git status --short

# Desktop product surface (Rust TUI) — required
cargo test --release
cargo build --release --locked --bin hashchat-tui --features tui
(cd android/src/main/rust && cargo test --release)

# Transitional Haskell parity only (optional; not a release path)
# cabal build hashchat-cli -f-tui

# Supply chain (arch-3): Run audit + basic SBOM
cargo install cargo-audit --locked 2>/dev/null || true
cargo audit --deny high || echo "High/critical issues found - review before tagging"

# Generate basic SBOM (see scripts/generate-sbom.sh)
./scripts/generate-sbom.sh sbom-pre-tag || echo "SBOM generation completed with warnings"

# Flatpak (recommended for release packaging)
# nix build .#hashchat-flatpak
# result/hashchat-tui.flatpak should exist and install cleanly
# Confirm Exec/command is hashchat-tui; host Tor still required after install

# Critical before v0.2 signed tag:
# - Real icons generated (or confirm improved placeholder + docs sufficient for preview)
# - Real screenshots captured per docs/SCREENSHOTS.md (or confirm placeholders + instructions)
# - Hardware / two-peer Tor evidence recorded per docs/TWO_PEER_VALIDATION.md
#   (fill scripts/validation-evidence-template.txt; never record cookies, keys, onions,
#   passphrases, SAS, or message bodies). Also see docs/TESTING_STRATEGY.md / REAL_DEVICE_TESTING.md.
#   This is a HARD REQUIREMENT before any signed tag. The signed tag message must explicitly
#   reference that recent real-device + Tails/Qubes (or equivalent) testing was performed and
#   documented. No signed tag is considered complete without this evidence.
# - Honest limitations refreshed in RELEASE_NOTES_v0.2.md (preview; no production overclaim)
```

**Creating the Signed Tag:**
```bash
git tag -s v0.2 -m "HashChat v0.2 - Maximum Paranoid Messenger (preview)

Key packaging / desktop notes:
- Desktop product surface: Rust TUI (hashchat-tui); Flatpak command/Exec = hashchat-tui
- Host Tor required (SOCKS + ControlPort cookie); fail-closed, no silent clearnet fallback
- Flatpak: install-only manifest, Nix-driven prebuilts
- Hardware evidence: see docs/TWO_PEER_VALIDATION.md (do not embed secrets in the tag message)

See RELEASE_NOTES_v0.2.md and THREATMODEL.md for honest status and known limitations.

This is a preview release. Recommended environments for testing: Tails or Qubes OS."
```

**After tagging (exact safe sequence):**
```bash
git tag -v v0.2
git show v0.2 --quiet

# Push only when intentionally publishing (Codeberg primary first)
# Prefer fast-forward when history was not rewritten; use force-with-lease only after a deliberate rewrite
git push --force-with-lease origin main   # or: git push origin codeberg-primary
git push --force-with-lease origin --tags
```

- [ ] Update known limitations in RELEASE_NOTES_v0.2.md before creating the tag.
- [ ] Confirm Flatpak / INSTALL Flatpak section still document host Tor + fail-closed.
- [ ] Announce only after the signed tag exists on Codeberg (primary) and GitHub mirror.

## 4. Post-Release

- [ ] Announce with link to THREATMODEL.md, RELEASE_NOTES, and `docs/TWO_PEER_VALIDATION.md` (for how hardware evidence was / should be captured).
- [ ] Provide clear security contact (e.g., security@hashchat.example or a dedicated .onion).
- [ ] Monitor for issues related to the known limitations listed in the release notes.

## Known Audit Findings & Current Status (refresh vs tip)

- Desktop release path is **Rust `hashchat-tui`**; Haskell Brick desktop remains transitional / not recommended.
- Android Rust DoubleRatchet parity (high-4) advanced for core serialization; remaining envelope / Keystore gaps must stay loud in release notes where still present.
- Nix Flatpak path: install-only manifest; prebuilt binary name **`hashchat-tui`**; host Tor not bundled.
- Quantum (long-13) remains a gated skeleton (`#[cfg(feature = "quantum")]`) — not production PQ.
- "demo-pass" strings (where still present in Kotlin persistence) are intentional auditor visibility until removed — never for real deployments.
- Android mlock remains a documented best-effort gap.
- Decentralized discovery is still design-level; no production implementation claim.
- THREATMODEL.md and RELEASE_NOTES_v0.2.md must be the canonical honest sources.
- Two-peer / hardware evidence process: **`docs/TWO_PEER_VALIDATION.md`** (do not edit that file from packaging-only passes).

## Reproducible Verification Commands (for anyone reproducing the signed tag)

```bash
# 1. Clean + verify no secrets in tree
./scripts/clean-security.sh
git status --short   # must show only source changes, never tor/ or *.db or voice temps

# 2. Reproduce desktop Rust TUI (release surface)
cargo test --release
cargo build --release --locked --bin hashchat-tui --features tui
# Optional transitional Cabal parity only:
# cabal build hashchat-cli -f-tui

# 3. Reproduce Android Rust (where claiming high-4 artifacts)
cd android/src/main/rust && cargo check --release
# Real .so: cd android && ./build-android.sh

# 4. Reproduce Flatpak
nix build .#hashchat-flatpak
# Install/run still needs host Tor; Exec/command must be hashchat-tui

# 5. With quantum feature (skeleton only)
cargo check --release --features quantum
```

## Signing & Tag (executable)

```bash
# After all checks + (if needed) clean history rewrite (rec-10)
git tag -s v0.2 -m "HashChat v0.2 - Maximum Paranoid Messenger (preview)

See RELEASE_NOTES_v0.2.md, THREATMODEL.md, and docs/TWO_PEER_VALIDATION.md
for honest status, known limitations, and hardware-evidence process."
git tag -v v0.2   # verify signature
```

This document is the authoritative process skeleton. Update it before every future tag.

**Expert note:** Treat v0.2 as a **preview**. Call out remaining envelope / Android mlock / discovery gaps loudly. Do not claim production readiness.
