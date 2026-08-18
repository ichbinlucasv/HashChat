#!/bin/bash
#
# HashChat - Maximum Paranoid Security Cleanup Script
# Run this BEFORE every commit and push.
#
# This is a core OPSEC ritual. Bypassing it is considered a serious process violation.
#
# Philosophy (naximalist paranoid):
# - Minimize lifetime of any sensitive material (ratchet state, voice, exports, groups.enc, etc.)
# - Be loud and fail-hard when we cannot clean something
# - Cover more than just build artifacts
# - Support "strict" mode for high-risk sessions

set -euo pipefail

STRICT_MODE=false
SHRED_PASSES=3

while [[ $# -gt 0 ]]; do
    case $1 in
        --strict)
            STRICT_MODE=true
            shift
            ;;
        --passes)
            SHRED_PASSES="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "=== HashChat MAXIMUM PARANOID Security Cleanup ==="
echo "Strict mode: $STRICT_MODE | Shred passes: $SHRED_PASSES"
echo ""

fail_hard() {
    echo "!!! CRITICAL OPSEC FAILURE: $1"
    if [ "$STRICT_MODE" = true ]; then
        echo "Exiting with failure because --strict mode is active."
        exit 1
    fi
    echo "Continuing (non-strict mode). This is a process violation."
}

# 1. Standard build artifacts
echo "[1/9] Removing standard build artifacts..."
rm -rf target/ dist-newstyle/ rust-lib/ run-cli run-desktop 2>/dev/null || true

# 2. Tor hidden service keys (never commit these)
echo "[2/9] Checking and cleaning Tor hidden service material..."
if [ -d "tor/hidden_service" ]; then
    echo "  -> Found tor/hidden_service directory. Shredding contents..."
    find tor/hidden_service -type f -exec shred -v -n $SHRED_PASSES -z {} \; 2>/dev/null || true
    rm -rf tor/hidden_service 2>/dev/null || true
fi

# 3. Local databases and persistence
echo "[3/9] Shredding local databases and persistence files..."
find . -maxdepth 2 \( \
    -name "*.db" -o \
    -name "*.db-shm" -o \
    -name "*.db-wal" -o \
    -name "groups.enc" -o \
    -name "*export*.bin" -o \
    -name "*ratchet*.bin" \
\) -exec shred -v -n $SHRED_PASSES -z {} \; 2>/dev/null || true

# 4. Voice recording artifacts (high sensitivity - plaintext audio)
echo "[4/9] Shredding voice recording artifacts (very high sensitivity)..."
find . -type f \( \
    -name "*hashchat_voice*" -o \
    -name "*voice_rec*" -o \
    -name "*voice_play*" \
\) -exec shred -v -n $SHRED_PASSES -z {} \; 2>/dev/null || true

# 5. Android build artifacts (including Rust side)
echo "[5/9] Deep cleaning Android build artifacts..."
rm -rf android/build/ android/.gradle/ android/.cxx/ 2>/dev/null || true
find android -name "*.so" -o -name "*.o" -o -name "*.a" 2>/dev/null | while read -r f; do
    shred -v -n $SHRED_PASSES -z "$f" 2>/dev/null || true
    rm -f "$f" 2>/dev/null || true
done

# 6. Rust clean
echo "[6/9] Running cargo clean..."
cargo clean 2>/dev/null || true

if [ "$STRICT_MODE" = true ]; then
    echo "  [STRICT] Also cleaning user cargo caches (this can be slow)..."
    rm -rf ~/.cargo/registry ~/.cargo/git 2>/dev/null || true
fi

# 7. Temporary sensitive files (exports, ratchet blobs, etc.)
echo "[7/9] Shredding temporary sensitive files..."
find . -maxdepth 3 -type f \( \
    -name "*_export*" -o \
    -name "*ratchet_blob*" -o \
    -name "*cross_device*" \
\) -exec shred -v -n $SHRED_PASSES -z {} \; 2>/dev/null || true

# 8. Android JNI is the same crate (feature android); cargo clean above covers it.
echo "[8/9] Android uses src/rust/ with --features android (no second crate)."

# 9. Final status check
echo "[9/9] Final verification..."
REMAINING=$(find . -maxdepth 3 \( \
    -name "*hashchat_voice*" -o \
    -name "groups.enc" -o \
    -name "*export*" -o \
    -path "*/tor/hidden_service/*" \
\) 2>/dev/null | wc -l)

if [ "$REMAINING" -gt 0 ]; then
    fail_hard "Some high-sensitivity files may still be present after cleaning."
else
    echo "  -> No obvious high-sensitivity artifacts detected in common locations."
fi

echo ""
echo "=== HashChat Paranoid Cleanup Complete ==="
echo "Working directory should now be clean."
echo "Run 'git status' and review carefully before committing."
echo ""

if [ "$STRICT_MODE" = true ]; then
    echo "Strict mode completed successfully."
fi

exit 0
