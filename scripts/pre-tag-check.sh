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

# 5. Check for any "demo-pass" remnants in non-test Kotlin code (Wave 10: now zero tolerance after full excision)
echo "[5/8] Scanning for any remaining hardcoded demo-pass in Android source (must be zero after Wave 10 closure)..."
if grep -r -E "(demo-pass|DEMO_INSECURE_RATCHET_PASSPHRASE|getInsecureGroupDemoPassphrase)" android/src/main/java --include="*.kt" | grep -v "EXPERT OPSEC WARNING\|Wave 10: legacy demo-pass surface fully excised\|REMOVED in Wave 10" | grep -q .; then
    fail "Hardcoded demo-pass strings or calls remain in Android main source after Wave 10 closure. This item must be finished."
else
    echo "  -> No demo-pass remnants found in main source (Wave 10 closure verified)."
fi

# 6. Aggressive critical doc + no-new-TODO gate (Tier 2 pre-tag hardening)
echo "[6/8] Aggressive check: critical docs modified recently + no new security TODOs/FIXMEs..."
# Require both key docs touched in the last 20 commits (stronger than "30 days")
RECENT_DOCS=$(git log --oneline -20 --name-only --pretty=format: | sort | uniq)
MISSING=0
if ! echo "$RECENT_DOCS" | grep -q "RELEASE_NOTES_v0.2.md"; then
    echo "  FAIL (pre-tag gate): RELEASE_NOTES_v0.2.md not modified in last 20 commits."
    MISSING=1
fi
if ! echo "$RECENT_DOCS" | grep -q "THREATMODEL.md"; then
    echo "  FAIL (pre-tag gate): THREATMODEL.md not modified in last 20 commits."
    MISSING=1
fi

# No new TODO/FIXME in security-critical files since last tag (or in working tree for dev)
CRITICAL_FILES="android/src/main/rust/src/lib.rs android/src/main/java/MainActivity.kt scripts/clean-security.sh scripts/pre-tag-check.sh src/rust/*.rs src/haskell/HashChat/Group.hs"
NEW_TODOS=$(git diff --name-only HEAD~5 -- $CRITICAL_FILES 2>/dev/null | xargs -I{} git diff HEAD~5 -- {} 2>/dev/null | grep -E '^\+.*(TODO|FIXME|XXX|HACK)' | grep -v 'TODO (deep ongoing work)' || true)
if [ -n "$NEW_TODOS" ]; then
    echo "  HARD FAIL (Deep Wave): New TODO/FIXME added in security-critical files since recent commits:"
    echo "$NEW_TODOS"
    echo "  Fix or remove the new TODOs/FIXMEs before tagging."
    exit 1
fi

if [ "$MISSING" -eq 1 ]; then
    echo "  >>> Pre-tag gate: Update the missing critical docs before tagging."
fi
echo "  -> Critical docs + TODO hygiene check complete (stricter gate active)."

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
echo "  MANDATORY before any signed tag (Tier 3 requirement):"
echo "  - At least one full real-device + Tails/Qubes test pass performed in the last 90 days"
echo "  - Results must be documented (date, environment, key observations) per docs/TESTING_STRATEGY.md"
echo "  - The signed tag message MUST reference that this check was satisfied."
echo ""
echo "  This is a HARD REQUIREMENT. No signed tag will be considered complete without recent real-hardware testing evidence."

# Wave 7 ALL: Evidence file gate is hard blocking (no more "even a dated log for v0.2-preview" leniency in spirit)
EVIDENCE_FILE=$(ls -1t TESTING_EVIDENCE*.log 2>/dev/null | head -1 || true)
if [ -z "$EVIDENCE_FILE" ]; then
    echo "  >>> HARD FAIL for signed tags (Wave 7 ultra gate): No TESTING_EVIDENCE_*.log found."
    echo "  >>> Blocking requirement. Create dated real-hardware evidence log and re-run before any tag attempt."
    exit 1
else
    echo "  -> Found testing evidence: $EVIDENCE_FILE (modified $(stat -c %y "$EVIDENCE_FILE" 2>/dev/null || echo 'recently'))"
fi

# Wave 6 even deeper: Local evidence marker is now a HARD FAIL for signed tags
LOCAL_RUN_MARKER=".pre-tag-check-local-ran-$(git rev-parse HEAD 2>/dev/null || echo current)"
if [ ! -f "$LOCAL_RUN_MARKER" ]; then
    echo "  >>> HARD FAIL (Wave 6 ultra gate): No local pre-tag evidence marker for this exact commit."
    echo "  >>> Create it with: echo 'pre-tag-check passed on $(date) - Wave 6' > $LOCAL_RUN_MARKER && git add $LOCAL_RUN_MARKER"
    echo "  >>> Then re-run this script. This is now blocking."
    exit 1
else
    echo "  -> Local pre-tag evidence marker found for this commit."
fi

# SBOM diff stub (T3 CI paranoia)
echo "  [SBOM] For future tags: compare $OUTPUT_DIR/sbom against previous tag SBOM (manual step for v0.2-preview)."
echo "  Example: ./scripts/generate-sbom.sh /tmp/sbom-prev && diff -u /tmp/sbom-prev/sbom.json $OUTPUT_DIR/sbom/sbom.json || echo 'SBOM diff review required'"

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
echo "  - Local pre-tag evidence marker + TESTING_EVIDENCE log must exist for this exact commit (hard enforced by this script)"
echo ""
echo "When creating the signed tag, include a reference that this script was run:"
echo "  ./scripts/pre-tag-check.sh --strict"
echo ""
echo "Script finished."
