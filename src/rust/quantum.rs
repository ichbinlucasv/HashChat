// =============================================================================
// HashChat Quantum-Resistant Hybrid Ratchet (long-13 gated module)
// =============================================================================
// This module is compiled ONLY when the "quantum" feature is enabled:
//
//   cargo build --features quantum
//
// It is intentionally a skeleton / stub for v0.2.
//
// All future production implementation MUST satisfy the requirements listed
// below. These are non-negotiable for a "maximum paranoid" messenger.
//
// SECURITY REQUIREMENTS (must be enforced in any real implementation):
// - Constant-time: all KEM operations, encoding, and comparisons must be
//   constant-time (no secret-dependent branches or memory accesses).
// - Zeroization: every secret (private keys, shared secrets, intermediate
//   values) must be zeroized on drop using the zeroize crate (or equivalent).
// - Side-channel resistance: the implementation must be audited against
//   timing, cache, power, and electromagnetic side channels. ML-KEM
//   implementations from audited crates (e.g. future pqcrypto or mls-kem)
//   are strongly preferred over custom code.
// - Hybrid design: we combine classical X25519 with ML-KEM-768 (or Kyber768)
//   so that security holds as long as at least one of the two remains unbroken.
// - KDF domain separation: all context strings must be distinct and include
//   a protocol version + "quantum" marker.
// - No new dependencies that cannot be audited or that pull in large attack
//   surface (prefer pure-Rust, no_std friendly PQ crates when possible).
//
// Current status (v0.2):
// - This module only provides the public interface + clear "not yet implemented"
// - Long-term: expand to full hybrid (we have the skeleton; future waves for real ML-KEM).
// - See ROADMAP for quantum-resistant options.
//   errors. Enabling the feature does not give you quantum resistance yet.
// - The classical DoubleRatchet in ratchet.rs remains the only production path.
//
// Roadmap note: When a suitable ML-KEM crate stabilizes and is added under
// this feature, QuantumHybridRatchet will become the default for new sessions
// (with a migration path for existing contacts).
// =============================================================================

use zeroize::Zeroize;

pub const KEM_PUBLIC_KEY_LEN: usize = 1184; // ML-KEM-768 example size (placeholder)
pub const KEM_CIPHERTEXT_LEN: usize = 1088;
pub const KEM_SHARED_SECRET_LEN: usize = 32;

/// Placeholder for a hybrid (classical + post-quantum) ratchet state.
/// In a real implementation this would contain both an X25519 ratchet
/// and an ML-KEM KEM state, plus the combined root/chain keys.
pub struct QuantumHybridRatchet {
    // TODO: add real fields once a PQ KEM crate is selected and audited.
    _placeholder: [u8; 32],
}

impl Zeroize for QuantumHybridRatchet {
    fn zeroize(&mut self) {
        self._placeholder.zeroize();
    }
}

impl Drop for QuantumHybridRatchet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl QuantumHybridRatchet {
    /// Create a fresh hybrid ratchet (stub).
    pub fn new() -> Self {
        Self { _placeholder: [0u8; 32] }
    }

    /// Perform the hybrid key encapsulation (stub).
    /// In production: run ML-KEM-768 encapsulate + X25519, then HKDF the two
    /// shared secrets together with strong domain separation.
    pub fn encapsulate(&self) -> Result<([u8; KEM_CIPHERTEXT_LEN], [u8; KEM_SHARED_SECRET_LEN]), &'static str> {
        Err("Quantum resistance is not yet implemented (long-13). Enable only for testing the interface.")
    }

    /// Decapsulate (stub).
    pub fn decapsulate(&self, _ct: &[u8; KEM_CIPHERTEXT_LEN]) -> Result<[u8; KEM_SHARED_SECRET_LEN], &'static str> {
        Err("Quantum resistance is not yet implemented (long-13).")
    }

    /// Export the hybrid state for encrypted persistence (must be zeroized after use).
    pub fn to_bytes(&self) -> Vec<u8> {
        // In a real impl this would serialize both classical and PQ parts.
        vec![]
    }

    pub fn from_bytes(_data: &[u8]) -> Result<Self, &'static str> {
        Err("Quantum resistance is not yet implemented (long-13).")
    }
}

/// Feature-gated entry point that the rest of the crate can call when the
/// "quantum" feature is active. Currently always returns the "not yet"
/// error so that no code path accidentally believes it has PQ security.
pub fn hybrid_ratchet_new() -> Result<QuantumHybridRatchet, &'static str> {
    Err("QuantumHybridRatchet is a stub (long-13). Compile with --features quantum to see the interface; it does not yet provide post-quantum security.")
}
