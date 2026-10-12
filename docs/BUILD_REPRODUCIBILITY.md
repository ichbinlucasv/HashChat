# Reproducible Builds for HashChat

This document describes how to build HashChat in a highly reproducible and auditable way — suitable for high-security or high-trust environments.

## Current State (2026)

- `build.sh` enforces `--locked` for Cargo.
- The project is 100% Rust (Haskell/Cabal removed 2026-10-12); `Cargo.lock` is the only lockfile.
- The project is moving toward stronger reproducibility.

## Recommended Setup for Maximum Reproducibility

### 1. Use Pinned Toolchains

**Rust**
```bash
rustup install 1.82.0          # Pin exact version
rustup default 1.82.0
cargo +1.82.0 build --locked
```

### 2. Use Nix (Long-term Ideal)

`flake.nix` provides the Rust TUI package:

```bash
nix build .#hashchat-tui
```

Nix gives the strongest reproducibility guarantees currently possible.

### 3. Build Environment Recommendations

- **Best**: Tails OS (amnesic + reproducible)
- **Excellent**: Qubes OS disposable VM based on Fedora or Debian
- **Good**: Clean Fedora/Ubuntu VM with pinned toolchains

Never build security-critical software on a daily driver machine.

## Verification

After building, you should be able to reproduce the exact same binary hashes when using the same pinned toolchains and lockfiles.

---

This document will be expanded as we move toward full Nix-based reproducible builds.