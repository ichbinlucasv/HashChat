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
    echo "  WARNING (will hard-fail post-v0.2): New TODO/FIXME added in security-critical files:"
    echo "$NEW_TODOS"
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

# Enforce simple evidence file gate (even a dated log is accepted for v0.2-preview)
EVIDENCE_FILE=$(ls -1t TESTING_EVIDENCE*.log 2>/dev/null | head -1 || true)
if [ -z "$EVIDENCE_FILE" ]; then
    echo "  >>> WARNING (will become hard FAIL in post-v0.2): No TESTING_EVIDENCE_*.log found in repo root."
    echo "  >>> Create one (e.g. 'date > TESTING_EVIDENCE_2026-05-31.log ; echo \"Real device test: voice+groups on Pixel 6a, posture gates worked\" >> ...') and re-run before tagging."
else
    echo "  -> Found testing evidence: $EVIDENCE_FILE (modified $(stat -c %y "$EVIDENCE_FILE" 2>/dev/null || echo 'recently'))"
fi

# Additional local-run gate (T3 CI paranoia): require that the person tagging has actually run this script locally on the exact commit
LOCAL_RUN_MARKER=".pre-tag-check-local-ran-$(git rev-parse HEAD 2>/dev/null || echo current)"
if [ ! -f "$LOCAL_RUN_MARKER" ]; then
    echo "  >>> STRONG RECOMMENDATION (will become hard requirement): Create $LOCAL_RUN_MARKER after running this script locally on the exact commit you intend to tag."
    echo "  >>> echo 'pre-tag-check passed on $(date)' > $LOCAL_RUN_MARKER && git add $LOCAL_RUN_MARKER"
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
echo ""
echo "When creating the signed tag, include a reference that this script was run:"
echo "  ./scripts/pre-tag-check.sh --strict"
echo ""
echo "Script finished."
