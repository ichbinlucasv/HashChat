#!/bin/bash
#
# HashChat Pre-Tag Verification Script
# Run this before creating any signed release tag (especially v0.2).
#
# This script automates the most critical OPSEC and quality rituals.
# It is designed to be loud and fail-hard on important checks.
#
# Usage:
#   ./scripts/pre-tag-check.sh
#   ./scripts/pre-tag-check.sh --strict
#

set -euo pipefail

STRICT=false
if [[ "${1:-}" == "--strict" ]]; then
    STRICT=true
fi

echo "================================================================"
echo "   HashChat PRE-TAG VERIFICATION SCRIPT (OPSEC Edition)"
echo "================================================================"
echo "Strict mode: $STRICT"
echo ""

fail() {
    echo ""
    echo "!!! PRE-TAG CHECK FAILED: $1"
    if [ "$STRICT" = true ]; then
        echo "Exiting in strict mode."
        exit 1
    else
        echo "Warning (non-strict). Fix this before any real signed tag."
    fi
}

# 1. Clean security ritual
echo "[1/8] Running maximum paranoid clean..."
if ! ./scripts/clean-security.sh --strict; then
    fail "clean-security.sh --strict did not complete cleanly"
fi

# 2. Git status must be clean
echo "[2/8] Checking git status..."
if [ -n "$(git status --porcelain)" ]; then
    fail "Working tree is not clean. Commit or stash changes first."
else
    echo "  -> Working tree is clean."
fi

# 3. Run paranoid Rust tests
echo "[3/8] Running cargo test --release (paranoid paths)..."
if ! cargo test --release; then
    fail "cargo test --release failed"
fi

# 4. Run cargo audit with high severity
echo "[4/8] Running cargo audit --deny high..."
if ! cargo audit --deny high; then
    fail "cargo audit found HIGH or CRITICAL advisories"
fi

# 5. Check for obvious "demo-pass" in non-test Kotlin code (basic heuristic)
echo "[5/8] Scanning for hardcoded demo-pass in Android source..."
if grep -r "demo-pass" android/src/main/java --include="*.kt" | grep -v "DEMO_INSECURE\|EXPERT OPSEC WARNING" | grep -q .; then
    fail "Hardcoded 'demo-pass' found in Android main source without proper isolation comments"
else
    echo "  -> No obvious unprotected demo-pass strings found in main source."
fi

# 6. Basic check that key docs have been touched recently
echo "[6/8] Checking recent updates to critical docs..."
RECENT_FILES=$(git log --since="30 days ago" --name-only --pretty=format: | sort | uniq)
if ! echo "$RECENT_FILES" | grep -q "RELEASE_NOTES_v0.2.md"; then
    echo "  WARNING: RELEASE_NOTES_v0.2.md has not been updated in the last 30 days."
fi
if ! echo "$RECENT_FILES" | grep -q "THREATMODEL.md"; then
    echo "  WARNING: THREATMODEL.md has not been updated in the last 30 days."
fi

# 7. Verify no obvious sensitive files are tracked
echo "[7/8] Verifying no sensitive files are accidentally tracked..."
if git ls-files | grep -E "(tor/hidden_service|groups\.enc|.*export.*\.bin)" | grep -q .; then
    fail "Sensitive files appear to be tracked in git!"
else
    echo "  -> No obvious sensitive files tracked."
fi

# 8. Generate basic SBOM (supply chain visibility)
echo "[8/9] Generating basic SBOM..."
./scripts/generate-sbom.sh "$OUTPUT_DIR/sbom" || echo "  -> SBOM generation had issues (non-fatal for now)"

# 9. Testing strategy evidence (Tier 3 requirement - now treated as mandatory)
echo "[9/10] Checking testing strategy requirements..."
echo ""
echo "  MANDATORY before any signed tag:"
echo "  - At least one full real-device + Tails/Qubes test pass performed in the last 90 days"
echo "  - Results must be documented (date, environment, key observations) per docs/TESTING_STRATEGY.md"
echo "  - This is now a required artifact. The tag message should reference that this check was satisfied."
echo ""
echo "  (This check is currently manual. Future versions may add stronger enforcement.)"

# 10. Final summary
echo "[10/10] All automated checks completed."
echo ""
echo "================================================================"
echo "   PRE-TAG CHECK SUMMARY"
echo "================================================================"
echo "Please manually confirm before creating a signed tag:"
echo "  - At least one full real-hardware test pass (Tails/Qubes + physical Android)"
echo "  - Icons and screenshots status acceptable for the release type"
echo "  - RELEASE_NOTES_v0.2.md and THREATMODEL.md are up to date and brutally honest"
echo "  - All 'demo-pass' usages have been reviewed and accepted for this release"
echo ""
echo "When creating the signed tag, include a reference that this script was run:"
echo "  ./scripts/pre-tag-check.sh --strict"
echo ""
echo "Script finished."
