# Contributing to HashChat

Thank you for your interest in HashChat — a maximum-anonymity messenger built with Haskell + Rust.

## Code of Conduct

- Security first. Always.
- Be respectful and constructive.
- Never submit code that weakens privacy or anonymity.

## How to Contribute

### 1. Reporting Bugs & Security Issues

**Security vulnerabilities must be reported privately.**

- Use GitHub Security Advisories, or
- Contact the maintainer directly.

Public issues for security problems will be closed without comment.

### 2. Development Setup

```bash
# 1. Install dependencies (Fedora example)
sudo dnf install ghc cabal-install rust cargo ncurses-devel

# 2. Build everything
./build.py

# 3. Run the TUI
./run-desktop
```

See [README.md](README.md) for full build instructions.

### 3. Project Structure

- `src/rust/` — Cryptography, ratchet, secure memory (ring + x25519-dalek)
- `src/haskell/HashChat/` — Core logic, Tor integration, ratchet state
- `app-desktop/TUI.hs` — Beautiful Brick TUI (black + yellow + white)
- `app/Main.hs` — CLI
- `android/` — Kotlin + Rust JNI

### 4. Security Guidelines (Very Important)

- Never commit anything from `tor/hidden_service/`
- Never commit compiled artifacts (`rust-lib/`, `target/`, `dist-newstyle/`)
- All changes to the ratchet (`ratchet.rs`) must be discussed first
- Prefer constant-time operations from `ring`
- Use `zeroize` for all sensitive data

Run `./scripts/clean-security.sh` before every commit.

### 5. Commit Style

- Use conventional commits when possible
- Keep commits small and focused
- Reference issues when applicable

Example:
```
feat(ratchet): add proper DH ratchet step on send

- Implement key rotation in DoubleRatchet
- Expose via FFI
- Update TUI to display ratchet steps
```

### 6. Testing

- Run `./build.py` successfully
- Test the TUI (`./run-desktop`)
- Test the CLI (`./run-cli cli`)
- For Android changes, test on device or emulator

### 7. Feature Areas (Current Focus)

We are actively working on:
1. Production-ready Double Ratchet
2. Real Tor hidden service integration
3. Disappearing messages
4. Voice + file transfer with forward secrecy
5. Burner profiles
6. Full Android experience
7. Metadata-resistant groups

If you want to work on any of these, please open an issue first.

## License

By contributing, you agree that your contributions will be licensed under the AGPLv3.

---

Thank you for helping make private communication stronger.
