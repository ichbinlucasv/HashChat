# Security Policy for HashChat

HashChat is a **maximum-anonymity** messenger. Security is the #1 priority.

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

## Responsible Disclosure

We appreciate responsible disclosure and will credit researchers (unless they prefer anonymity).

Thank you for helping keep HashChat users safe.
