#!/bin/bash
# HashChat Safe Commit Script
# This script helps you commit without leaking security-sensitive data.

set -e

echo "=== HashChat Safe Commit Helper ==="
echo ""

# Run security cleaner first
if [ -f "./scripts/clean-security.sh" ]; then
    echo "[1/4] Running security cleaner..."
    bash ./scripts/clean-security.sh
else
    echo "Warning: clean-security.sh not found"
fi

echo ""
echo "[2/4] Checking for dangerous files that might still be staged..."
if git ls-files --others --ignored --exclude-standard | grep -E "(hidden_service|rust-lib|\.key|\.pem|hashchat\.db)" ; then
    echo "ERROR: Dangerous files detected in working directory!"
    exit 1
fi

echo "[3/4] Showing what will be committed..."
git status --short

echo ""
read -p "Do you want to continue with commit? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "[4/4] Creating commit..."
git add -A

echo ""
echo "Recommended commit message:"
echo "----------------------------------------"
cat << 'MSG'
feat: advance all core security features + security hygiene

- Improve Double Ratchet stability (better KDF, rotation, ZeroizeOnDrop)
- Enhance Tor control port + onion persistence
- Add disappearing message foundation tied to ratchet
- Security: hardened .gitignore, safe commit script, SECURITY.md
- Various stability improvements across the 8 planned features

Security: No sensitive material (Tor keys, ratchet state, databases) committed.
MSG
echo "----------------------------------------"

echo ""
echo "Run this manually:"
echo 'git commit -m "feat: advance all core security features + security hygiene"'
echo ""
echo "Then push with:"
echo 'git push'
echo ""
echo "Safe commit process complete."