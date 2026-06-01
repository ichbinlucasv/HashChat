# Long-Term Identity Keypair for ContactAddress

**Status**: Design Phase (Option A)  
**Priority**: Critical (Biggest remaining metadata/QR gap)  
**Related**: THREATMODEL.md, Contact.hs, TUI.hs, Profile.hs, Core.hs

---

## Problem Statement

Currently, when a user generates a shareable contact link (`:my-contact` or equivalent on Android), the `ContactAddress` contains:

- Their Tor v3 onion address (public)
- A **randomly generated 32-byte public key** created fresh every time the QR is shown

This is a **placeholder**. It is better than the old dummy value (0xAB...), but it is not a real, persisted, long-term identity keypair.

**Consequences**:
- Every time you share your contact, the "identity key" changes.
- No stable long-term identity that others can use for X3DH-style key agreement.
- Future secure contact introduction / profile proofs become much harder.
- This was explicitly called out in Wave 8/9 reviews and the THREATMODEL as the largest remaining gap for proper SimplexChat-level profile sharing.

---

## Goals

1. Every burner profile should have **one stable long-term identity keypair**.
2. The **private key never leaves the device** and is stored encrypted at rest.
3. Only the **public key** is ever placed into the `ContactAddress` QR/link.
4. The keypair should be suitable for both:
   - Signing (ed25519)
   - Key agreement / X3DH (x25519)
5. Respect Extreme mode and Dynamic Security Posture (long-term identity surface is sensitive).
6. Enable future X3DH handshake when someone scans your contact QR.

---

## Design Questions & Recommendations

### 1. Key Type Choice

**Recommendation**: Use a combined **XEd25519** style keypair (or separate ed25519 + x25519 derived from the same seed).

- `ed25519_dalek` for signing
- `x25519_dalek` for key agreement
- Generate from a 32-byte seed (like the ratchet does)

This matches what the Rust crypto layer already uses (`ed25519_dalek` + `x25519_dalek`).

Alternative: Use `curve25519-dalek` + proper XEd25519 construction for a single key that serves both purposes. Slightly cleaner but more implementation work.

**Proposed**: Start with separate but co-generated ed25519 + x25519 keys derived from one seed. Easy to evolve later.

### 2. Storage Location & Model

**Strong Recommendation**: Implement the crypto + encrypted storage in **Rust**, exposed via JNI/Foreign function interface to Haskell.

Reasons:
- All sensitive crypto (ratchet, zeroize, mlock attempts) already lives in Rust.
- Easier to apply constant-time, zeroize, and secure storage patterns.
- Android can use the same Rust code + Android Keystore for the wrapping key.

Storage shape idea (per profile):

```rust
struct LongTermIdentity {
    seed: [u8; 32],           // master seed (encrypted at rest)
    ed25519_pub: [u8; 32],
    x25519_pub:  [u8; 32],
}
```

Encrypted with the same mechanism as ratchets (Argon2id + AES-GCM envelope derived from profile passphrase).

### 3. Lifecycle

- **Creation**: On first creation of a burner profile (or lazily on first `:my-contact` if we want to support old profiles).
- **Persistence**: Stored alongside the profile's ratchet state (encrypted blob).
- **Migration**: Existing profiles without a long-term key should generate one on next use (with a clear "your contact address changed" UX note).
- **Extreme mode**: Generation or export of the long-term public key should be refused or heavily warned when `EXTREME_MODE` or strict posture is active.

### 4. Haskell <-> Rust Boundary

We will need new FFI functions, for example:

```rust
// Generate + persist for a profile
fn profile_create_longterm_identity(profile_key: &[u8]) -> Result<Vec<u8>, Error>;

// Get public keys only (for QR generation)
fn profile_get_longterm_pub(profile_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error>;

// Future: sign, x3dh_prekey, etc.
```

Haskell side will call these via the existing Rust FFI layer (or extend it).

### 5. TUI / Android Impact

- TUI (`TUI.hs`): Replace the current `unsafePerformIO` random generation with a call that fetches the real persisted public key for the current profile.
- Add posture/Extreme checks before showing the "Share my contact" action.
- Android: Similar change in the contact sharing flow. Use the same Rust call via JNI.

### 6. Security Considerations

- Long-term identity keys are high-value targets. Compromise = ability to link sessions over time and perform active attacks on future introductions.
- Must be wiped on Nuclear Panic Wipe.
- Should be covered by the same zeroization and encrypted-at-rest guarantees as ratchets.
- In Extreme mode, we may want to disable ContactAddress generation entirely (or use one-time single-use keys).

---

## Proposed Implementation Phases

### Phase A – Design (Current)
- [x] Write this document
- [ ] User reviews and confirms design direction
- [ ] Decide on exact key construction (XEd25519 vs separate keys)
- [ ] Decide storage format and encryption envelope

### Phase B – Core Rust Implementation
- [x] Add `LongTermIdentity` struct + generation in Rust
- [x] Implement encrypted storage (reuse ratchet envelope logic)
- [x] Add FFI functions: new, get_public (ed+x), export/import encrypted, wipe
- [x] Compiles and basic tests in module
- Wired into Haskell Core.hs with wrappers + session cached ID for stability

### Phase C – Integration
- [x] Wire into Haskell `Core` layer (newLongTermIdentity, getLongTermIdentityPublic, export/import, wipe + session cached)
- [x] Modify TUI generation path (`:my-contact`) — now uses real ed25519 pub from LongTermIdentity instead of random
- [ ] Full per-profile storage (currently session-cached; real would use ProfileKey + blob per profile)
- [ ] Android JNI + Kotlin integration (pending, similar FFI)
- [ ] Update tests and documentation
- Extreme / posture gating already present in TUI for contact QR

### Phase D – Polish & Migration
- Migration path for existing profiles
- Update THREATMODEL.md + RELEASE_NOTES
- Real hardware testing of contact QR flow with the new keys
- Consider adding a "rotate long-term identity" action (advanced / dangerous)

---

## Open Questions (to resolve in Phase A)

1. Should we use a single XEd25519 key or separate ed25519 + x25519?
2. Should the long-term identity be tied 1:1 to the Tor hidden service key, or completely independent?
3. Do we want to support multiple long-term identities per profile in the future (e.g. "work" vs "personal" contact addresses)?
4. How aggressive should Extreme mode be about blocking long-term identity exposure?

---

## Next Action

Once the user confirms this design direction, we move to **Option B**: Start the Rust implementation of key generation + encrypted storage.

---

**Document owner**: Update this file as decisions are made.