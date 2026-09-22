#!/bin/bash
#
# HashChat Basic SBOM Generation Script
#
# Generates a minimal Software Bill of Materials focused on the most security-critical parts
# (primarily the Rust Double Ratchet + crypto surface).
#
# This is a pragmatic first step toward item 8 in the expert recommendations.
# For a real v0.2 or later release, consider more complete tooling (e.g. Syft, CycloneDX, etc.).

set -euo pipefail

OUTPUT_DIR="${1:-sbom}"
mkdir -p "$OUTPUT_DIR"

echo "=== HashChat Basic SBOM Generation ==="
echo "Output directory: $OUTPUT_DIR"
echo ""

# 1. Rust SBOM (most critical component)
echo "[1/3] Generating Rust SBOM (cargo-sbom)..."
if command -v cargo-sbom >/dev/null 2>&1; then
    cargo sbom --output-format json > "$OUTPUT_DIR/rust-sbom.json" 2>/dev/null || \
    cargo sbom > "$OUTPUT_DIR/rust-sbom.json" || echo "cargo-sbom failed or not fully configured"
    echo "  -> Rust SBOM written to $OUTPUT_DIR/rust-sbom.json (if successful)"
else
    echo "  -> cargo-sbom not installed. Installing temporarily..."
    cargo install cargo-sbom --quiet 2>/dev/null || true
    cargo sbom > "$OUTPUT_DIR/rust-sbom.json" 2>/dev/null || echo "  -> cargo-sbom generation failed"
fi

# 2. Transitional Haskell note (opt-in only; NOT a release path — criterion 2)
echo "[2/3] Creating transitional Haskell dependency note (non-release)..."
cat > "$OUTPUT_DIR/haskell-deps.txt" << 'EOF'
HashChat Haskell Dependencies — TRANSITIONAL / NOT A RELEASE PATH

The recommended desktop client is the Rust binary hashchat-tui (--features tui).
GHC/Cabal remain in-tree only for opt-in parity checks:
  HASHCHAT_ALLOW_HASKELL=1 ./run-tui
  ./build.sh --haskell
  nix develop .#haskellDev

Direct Cabal deps (if you intentionally maintain the Brick TUI) live in hashchat.cabal.
Do not treat this file as a release SBOM surface. Rust owns crypto + recommended TUI.

EOF
echo "  -> Transitional Haskell note written to $OUTPUT_DIR/haskell-deps.txt"

# 3. Overall project summary
echo "[3/3] Creating project SBOM summary..."
cat > "$OUTPUT_DIR/project-sbom-summary.txt" << EOF
HashChat Project - Basic SBOM Summary
Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

Primary Security Boundary: Rust (Double Ratchet, Argon2id, AES-GCM, Zeroize, framing, recommended TUI)
Recommended Desktop: Rust hashchat-tui (--features tui) — Cabal is NOT a release path
Android UI/Glue: Kotlin (thin layer + Android Keystore + BiometricPrompt)
Transitional Haskell: Brick TUI over Rust FFI (opt-in only; see haskell-deps.txt)

Rust Direct Dependencies (security-critical):
- See rust-sbom.json for full list (generated via cargo-sbom when available)
- Key crates: ring, zeroize, argon2, ed25519-dalek, x25519-dalek, hkdf, sha2, subtle

Haskell (transitional / opt-in only):
- See haskell-deps.txt and hashchat.cabal — not required for release

Known Weak Areas (documented):
- Android mlock is best-effort only
- Some "demo-pass" strings remain in Android persistence (explicitly isolated + warned)

This summary should be reviewed before any signed release tag.
EOF

echo ""
echo "=== SBOM Generation Complete ==="
echo "Files created in $OUTPUT_DIR/:"
ls -1 "$OUTPUT_DIR" 2>/dev/null || echo "(directory may be empty if generation partially failed)"
echo ""
echo "Recommendation: Review these files before creating any signed tag."
echo "For production releases, integrate a proper tool like Syft or Trivy SBOM generation."
