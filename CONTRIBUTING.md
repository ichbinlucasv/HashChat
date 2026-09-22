# Contributing to HashChat

Thank you for your interest in HashChat — a maximum-anonymity messenger.
**Rust is the only recommended desktop path** (`hashchat-tui --features tui`).
Haskell desktop is **transitional / not recommended** (kept compiling if present; see INSTALL.md removal criteria).

**Primary development happens on Codeberg**: https://codeberg.org/ichbinlucasv/HashChat  
Active tip branch: `codeberg-primary`. GitHub is a read-only mirror.

## Code of Conduct

- Security first. Always.
- Be respectful and constructive.
- Never submit code that weakens privacy or anonymity.

## How to Contribute

### 1. Reporting Bugs & Security Issues

**Security vulnerabilities must be reported privately.**

- Use Codeberg Security Advisories (primary) or GitHub mirror, or
- Contact the maintainer directly.

Public issues for security problems will be closed without comment.

**OPSEC for all reports** (bugs and security): follow [`docs/OPSEC_REPORTING.md`](docs/OPSEC_REPORTING.md).

- Include: tip SHA (`codeberg-primary`), OS/Tor versions, build/run method, UTC-offset time, reproduce steps **without secrets**, expected vs actual, and `:evidence` / `:audit-status` posture lines when relevant.
- Never paste: Tor cookies, onion/identity private keys, full onions or `hashchat://` links, passphrases, SAS values, message bodies, or unredacted dumps.
- Two-peer Tor validation: [`docs/TWO_PEER_VALIDATION.md`](docs/TWO_PEER_VALIDATION.md) · evidence dump: [`docs/VALIDATION_EVIDENCE.md`](docs/VALIDATION_EVIDENCE.md) · fill-in: `scripts/validation-evidence-template.txt`.
- Maintainers: do **not** ask reporters to paste secrets “for debugging.”

### 2. Development Setup (Rust recommended)

```bash
# 1. Install Rust + build deps (Fedora example)
sudo dnf install rust cargo gcc make pkg-config openssl-devel tor
# or: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Checkout tip
git checkout codeberg-primary

# 3. Build / test
cargo test --lib
cargo build --release --locked --bin hashchat-tui --features tui
# or: make tui && make test

# 4. Run the recommended desktop TUI
./run-tui
```

Do **not** install Cabal for normal contribution work. Haskell is opt-in only
(`HASHCHAT_ALLOW_HASKELL=1` / `./build.sh --haskell`) and is not recommended.

See [README.md](README.md) and [INSTALL.md](INSTALL.md).

### 3. Project Structure

- `src/rust/` — Cryptography, Tor, persistence, net modes (primary)
- `src/bin/hashchat_tui.rs` — Native Rust desktop TUI (`--features tui`)
- `android/` — Kotlin UI over the same Rust crate
- `src/haskell/`, `app-desktop/` — Transitional Haskell (not recommended; do not expand)

### 4. Security Guidelines (Very Important)

- Never commit anything from `tor/hidden_service/`
- Never commit compiled artifacts (`rust-lib/`, `target/`, `dist-newstyle/`)
- Never commit ControlPort cookies, onion keys, or local `hashchat_data/`
- Never commit or paste into tickets: cookies, private keys, onions, passphrases, SAS, or message bodies (see [`docs/OPSEC_REPORTING.md`](docs/OPSEC_REPORTING.md))
- All changes to the ratchet (`ratchet.rs`) must be discussed first
- Prefer constant-time operations; use `zeroize` for sensitive data
- Maintainer two-peer checks: [`docs/TWO_PEER_VALIDATION.md`](docs/TWO_PEER_VALIDATION.md); use `:evidence` / `:audit-status` for safe posture metadata ([`docs/VALIDATION_EVIDENCE.md`](docs/VALIDATION_EVIDENCE.md))

Run `./scripts/clean-security.sh` before commits that touched local sensitive state.

### 5. Commit Style

- Use conventional commits when possible
- Keep commits small and focused
- Reference issues when applicable

Example:
```
feat(rust): add explicit network modes (Tor default, fail-closed)

- Document Tor / I2P / Clearnet refusal paths
- Keep extreme posture Tor-only
```

### 6. Testing

- `cargo test --lib` (required)
- Build recommended TUI: `cargo build --release --locked --bin hashchat-tui --features tui`
- Manual: `./run-tui` with host Tor (SOCKS + ControlPort cookie auth)
- For Android changes, test on device or emulator

### 7. Feature Areas (Current Focus)

1. Harden Rust desktop TUI (Tor ControlPort, two-peer path, wipe)
2. Keep network modes fail-closed (no silent clearnet)
3. Android thin UI over the shared Rust crate
4. Reproducible Flatpak / Nix distribution
5. Retire Haskell desktop once removal criteria in INSTALL.md are met

If you want to work on any of these, please open an issue first on Codeberg.

## License

By contributing, you agree that your contributions will be licensed under the AGPLv3.

---

Thank you for helping make private communication stronger.
