#!/bin/bash
# HashChat - Local Security & Cleanliness Script
# Run this before committing or pushing

echo "=== HashChat Security Cleanup ==="

# Remove build artifacts
echo "[1/6] Removing build artifacts..."
rm -rf target/ dist-newstyle/ rust-lib/ run-cli run-desktop 2>/dev/null || true

# Remove any accidentally created tor keys
echo "[2/6] Checking for Tor hidden service keys..."
if [ -d "tor/hidden_service" ]; then
    echo "WARNING: tor/hidden_service exists locally. Make sure it is in .gitignore"
fi

# Remove databases
echo "[3/6] Removing local databases..."
rm -f *.db *.db-shm *.db-wal 2>/dev/null || true

# Clean Android build
echo "[4/6] Cleaning Android build..."
rm -rf android/build/ android/.gradle/ android/.cxx/ 2>/dev/null || true

echo "[5/6] Running cargo + cabal clean (optional)..."
cargo clean 2>/dev/null || true
cabal clean 2>/dev/null || true

echo "[6/6] Done."
echo ""
echo "Your working directory is now clean."
echo "Remember: Never commit anything from tor/hidden_service/"
echo "Run 'git status' to see what will be committed."
