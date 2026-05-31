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

# 2. Simple dependency summary for Haskell side (very basic)
echo "[2/3] Creating basic Haskell dependency note..."
cat > "$OUTPUT_DIR/haskell-deps.txt" << 'EOF'
HashChat Haskell Dependencies (High-Level Summary)

This project uses GHC + Cabal for the high-level protocol, TUI, and Tor framing logic.
Direct dependencies are declared in hashchat.cabal.

Key security-relevant notes:
- Uses cryptonite for some legacy crypto paths (being phased toward Rust).
- Uses sqlite-simple for local encrypted persistence.
- Network/Tor handling is custom (no heavy external HTTP libraries in critical paths).

For a full SBOM of the Haskell side, use tools such as:
- cabal-plan
- haskell-sbom (community tools)
- or manual review of hashchat.cabal + cabal.project.freeze (if present)

This file is intentionally lightweight because the Rust core owns the cryptographic boundary.
EOF
echo "  -> Haskell dependency note written to $OUTPUT_DIR/haskell-deps.txt"

# 3. Overall project summary
echo "[3/3] Creating project SBOM summary..."
cat > "$OUTPUT_DIR/project-sbom-summary.txt" << EOF
HashChat Project - Basic SBOM Summary
Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

Primary Security Boundary: Rust (Double Ratchet, Argon2id, AES-GCM, Zeroize, framing)
High-Level Logic: Haskell (TUI, protocol state machines, group logic, Tor v3 hidden services)
Android UI/Glue: Kotlin (thin layer + Android Keystore + BiometricPrompt)

Rust Direct Dependencies (security-critical):
- See rust-sbom.json for full list (generated via cargo-sbom when available)
- Key crates: ring, zeroize, argon2, ed25519-dalek, x25519-dalek, hkdf, sha2, subtle

Haskell Direct Dependencies:
- See haskell-deps.txt and hashchat.cabal

Known Weak Areas (documented):
- Android mlock is best-effort only
- Some "demo-pass" strings remain in Android persistence (explicitly isolated + warned)
- No full SBOM for Haskell side yet

This summary should be reviewed before any signed release tag.
EOF

echo ""
echo "=== SBOM Generation Complete ==="
echo "Files created in $OUTPUT_DIR/:"
ls -1 "$OUTPUT_DIR" 2>/dev/null || echo "(directory may be empty if generation partially failed)"
echo ""
echo "Recommendation: Review these files before creating any signed tag."
echo "For production releases, integrate a proper tool like Syft or Trivy SBOM generation."
