#!/bin/bash
#
# HashChat - Aggressive Git History Cleanup Script
# WARNING: This REWRITES HISTORY. Only run if you understand the risks.
#
# This script removes large media files and old dead code from Git history.
# After running, you will need to force push.
#
# Usage:
#   1. Make sure you have a clean working tree
#   2. Run: bash scripts/clean-git-history.sh
#   3. Then: git push --force-with-lease origin main
#

set -e

echo "=== HashChat History Cleanup ==="
echo ""

# Install git-filter-repo if not present
if ! command -v git-filter-repo &> /dev/null; then
    echo "git-filter-repo not found. Installing via pip..."
    pip install git-filter-repo || pip3 install git-filter-repo
fi

echo "Removing large media files and old GTK code from history..."

git filter-repo --path grok-video-1c9a9b13-f4d0-4beb-9cd6-3229e7362144.mp4 --invert-paths --force || true
git filter-repo --path grok-image-c881f444-cc70-4aff-8b35-55e8f616ba02.jpg --invert-paths --force || true
git filter-repo --path 1c9a9b13-f4d0-4beb-9cd6-3229e7362144.jpg --invert-paths --force || true
git filter-repo --path src/haskell/Desktop.hs --invert-paths --force || true

echo ""
echo "History rewrite complete."
echo ""
echo "Next steps:"
echo "1. git push --force-with-lease origin main"
echo "2. Tell your collaborators to re-clone the repo (do not pull)."
echo ""
echo "Done."