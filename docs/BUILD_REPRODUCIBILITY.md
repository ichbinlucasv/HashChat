# Reproducible Builds for HashChat

This document describes how to build HashChat in a highly reproducible and auditable way — suitable for high-security or high-trust environments.

## Current State (2026)

- `build.sh` enforces `--locked` for Cargo.
- Cabal builds respect `cabal.project` and lockfiles when present.
- The project is moving toward stronger reproducibility.

## Recommended Setup for Maximum Reproducibility

### 1. Use Pinned Toolchains

**Rust**
```bash
rustup install 1.82.0          # Pin exact version
rustup default 1.82.0
cargo +1.82.0 build --locked
```

**Haskell (GHC)**
Use `ghcup` and pin a specific GHC version:

```bash
ghcup install ghc 9.6.7
ghcup set ghc 9.6.7
```

Then build with:
```bash
cabal build --ghc-options="-fhide-source-paths"
```

### 2. Use `cabal freeze` (when stable)

```bash
cabal freeze
```

Commit the resulting `cabal.project.freeze` file.

### 3. Use Nix (Long-term Ideal)

A `flake.nix` is planned. When available:

```bash
nix build .#hashchat-tui
```

Nix gives the strongest reproducibility guarantees currently possible.

### 4. Build Environment Recommendations

- **Best**: Tails OS (amnesic + reproducible)
- **Excellent**: Qubes OS disposable VM based on Fedora or Debian
- **Good**: Clean Fedora/Ubuntu VM with pinned toolchains

Never build security-critical software on a daily driver machine.

## Verification

After building, you should be able to reproduce the exact same binary hashes (for Rust) and similar Haskell artifacts when using the same pinned toolchains and lockfiles.

---

This document will be expanded as we move toward full Nix-based reproducible builds.