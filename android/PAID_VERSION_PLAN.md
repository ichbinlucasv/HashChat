# Android Paid Version Plan

## Goals
- Keep full source code open on Codeberg (primary) and GitHub mirror for auditability and trust.
- Offer the Android app as a paid download (initially ~20 CHF, later cheaper) to help fund infrastructure.
- Maintain the strongest possible security and OPSEC on Android.

## Proposed Structure
- **Free / Open Source**: All source code lives in this repo under `android/`.
- **Paid Distribution**: APK or F-Droid (with donation) or direct paid download.
- **Billing**: Use Google Play Billing or a self-hosted license server (preferred for privacy).
- **Hardened Storage**:
  - Use Android Keystore for passphrase-derived keys.
  - Store encrypted ratchet state and message logs using the same Argon2id + AES pattern as desktop.
  - Avoid storing sensitive data in cleartext SharedPreferences or external storage.

## Security Requirements (Non-Negotiable)
- All sensitive operations go through the existing Rust FFI (same as desktop).
- Panic wipe must work reliably on Android (clear app data + zeroize in-memory).
- No unnecessary permissions.
- Strong protection against backup extraction (exclude from backups where possible).

## Next Steps (when development starts)
1. Set up proper Android NDK + Rust + cargo-ndk build.
2. Implement JNI bindings for the new Rust blob encryption functions (`src/rust/android_jni.rs`).
3. Add billing + license validation (keep it minimal and auditable).
4. Port the TUI concepts to a proper Android UI (Jetpack Compose or XML + RecyclerView for messages).
5. Implement per-profile isolated encrypted storage using the same Argon2id + AES pattern.

JNI lives in the single crate: `src/rust/android_jni.rs` (`cargo build --features android`).

## Monetization Philosophy (Updated Recommendation - aligns Comprehensive Roadmap Sec7)

- **Linux / Desktop (TUI)**: Always free and fully open source (AGPL). Core Tor/I2P/mesh/chat/basic email/file always free. No paywall on anonymity.
- **Android**: Source remains 100% public on Codeberg (primary) + thin GitHub mirror. Distribution:
  - Self-hosted F-Droid repo (recommended for privacy, donation unlock preferred)
  - Direct APK (donation-based unlock or one-time)
  - Optional paid unlock for convenience

**Open-core freemium (Pro tier, mirrors ProtonMail success while preserving decentralization):**
- Free tier = all core (Tor primary + I2P + mesh + chat + basic email/file + Extreme + E2EE + queues + XFTP).
- Pro (one-time $49-99 or $5-12/mo): unlimited DHT storage (email/groups/channels), priority relay hosting credits, enterprise team key mgmt, accelerated PQ modules, professional support, certified hardware bundles, ad-free premium themes/icons.
- Additional: Optional paid self-hostable relay-hosting service (run your own relay for community, get credits/badges), custom integrations, donations with visible badges.
- No Google/Play dependency; F-Droid self-hosted + donation unlock preferred.

**Why this is better for privacy + sustainability:**
- No Google Play dependency or surveillance.
- Users audit the exact same code (open-core).
- Aligns with roadmap: free core anonymity, paid extras for power users/teams/hosts without compromising defaults or decentralization.
- Desktop TUI remains the ultra-secure free default forever.

This approach (per user directive + approved plan) keeps the project sustainable while maintaining the highest possible integrity and "no stop until all" implementations. See ROADMAP.md Sec7 + PAID for details.
