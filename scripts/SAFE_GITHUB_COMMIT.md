# Safe GitHub Commit Process for HashChat

**Goal**: Contribute to open source without ever leaking security-sensitive material.

## Golden Rules

1. **Never commit**:
   - `tor/hidden_service/` (contains your real .onion private key)
   - `rust-lib/` (compiled libraries)
   - Any `.db` file
   - `run-cli` or `run-desktop` (generated)
   - Any file containing real ratchet state or keys

2. Always run the cleaners before committing.

## Recommended Safe Workflow

```bash
# 1. Run the security cleaner
./scripts/clean-security.sh

# 2. (Optional but recommended) Run full history cleaner if you added bad files
# bash scripts/clean-git-history.sh

# 3. Review what will be committed
git status --short

# 4. Stage changes
git add -A

# 5. Commit with a good message
git commit -m "feat: improve ratchet stability + Tor persistence + disappearing messages foundation

Security notes:
- All sensitive directories remain untracked
- No private keys, ratchet state, or onion keys committed
"

# 6. Push normally (no force needed for normal commits)
git push
```

## After Force-Pushing History (only when removing old bloat)

If you ran the history cleaner:

```bash
git push --force-with-lease origin main
```

**Warning**: All collaborators must delete and re-clone the repository.

## What is Safe to Commit

- Source code (`.hs`, `.rs`, `.cabal`, `Cargo.toml`, etc.)
- Documentation
- Configuration templates (`tor/torrc` is safe)
- Build scripts
- Tests

## Tools We Provide

- `scripts/clean-security.sh` — Daily use
- `scripts/safe-commit.sh` — Guided commit process
- `scripts/clean-git-history.sh` — Nuclear option for removing large files from history

Use them.
