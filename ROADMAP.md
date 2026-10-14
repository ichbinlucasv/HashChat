# HashChat Roadmap

Goal: Build a usable anonymous messenger with a **Rust-first** stack (crypto, Tor, desktop TUI), with focus on security, forward secrecy, and metadata resistance. The legacy Haskell desktop was removed on 2026-10-12; the project is 100% Rust.

**We have moved from "build the foundations" to "polish to production".**

## What Is Actually Done (as of this build)

### Core security (implemented)
- Real Double Ratchet in Rust (KDF chains, DH ratcheting, skipped keys, zeroize on drop)
- Bidirectional Tor v3 hidden services with proper sender-header framing
- Encrypted persistence (Argon2id + AES-GCM) for ratchets, messages, and groups
- Panic wipe (multi-pass + Rust zeroize + kernel anti-forensics + mlock)
- Dynamic Security Posture with real environment inspection + action refusals
- Burner profiles + plausible deniability decoy profiles with automatic wipe on switch
- Disappearing messages tied to ratchet key erasure
- Wave 8: ContactAddress + ConnectionRequest (public-only QR links hashchat://contact/v1/...), full TUI wiring (:my-contact / :add-contact in Brick TUI + CLI; the Haskell/Brick client was later removed on 2026-10-12), safer parser, export of helpers
- Wave 8: Generalized SOCKS5/ProxyConfig transport (sendOverProxy) with I2P + bridge/pluggable notes + call-site updates; hardened CI audit (no || true) + pre-tag demo-pass scan
- Wave 8: THREATMODEL update on remaining gaps (placeholder pubkey in QR, last gated demo-pass surface, no per-profile proxy yet, evidence logs required for tags)

### Desktop / Android UX (both platforms)
- Full contact actions: Block, Mute, Delete, Report, View security info, Disappearing timer
- Multi-member groups with sender-key forward secrecy + member management + QR join
- Voice messages: per-chunk ratchet streaming + playback with seek bars (Android RecyclerView + TUI)
- Burner switching (p/n), decoy mode (D), prominent panic wipe (w)
- Black + #FFD700 gold theme on both TUI and Android

### Android (Production Direction)
- RecyclerView chat + dedicated group member management screen
- Hardware-backed Android Keystore + optional BiometricPrompt for ratchet unlock
- QR scanning + group join flow
- Background Tor receiver thread

### Distribution & Reproducibility
- Pure-Nix reproducible Flatpak (`nix build .#hashchat-flatpak`)
- Nix cross-compile path for Android Rust libraries
- Qubes/Tails disposable VM build scripts that enforce `clean-security.sh` + anti-forensics

## Current phase: polish toward a complete preview (high priority)

Significant progress has been made on most items below. This document is kept honest and up to date.

### Immediate Polish Items (Critical Remaining)
0. **Haskell desktop retirement** — **Done (2026-10-12).** All five removal criteria in INSTALL.md are met: criterion 4 by the removal commits on `codeberg-primary` (tree, Cabal/GHC tooling, `haskell-parity` CI job, `HASHCHAT_ALLOW_HASKELL` hatch and Haskell-only C FFI deleted; `cargo test --lib`, release TUI build, clippy and CI security gate green), criterion 5 by explicit approval from the maintainer, Lucas, on 2026-10-12.
1. **Remove legacy dead code** — Massive stubFunction block in Main.hs removed (done in this pass).
2. **Android "demo-pass" hardening** — Hardcoded passphrase in group persistence flagged with expert warnings + scoped constant. Must be replaced with user-derived + Keystore in production.
3. **Honest docs** — ROADMAP + README refresh in progress (this update).

### High-value OPSEC / hardening (active)
- Android Rust: Port real DoubleRatchet logic (in progress - major gap for cross-device).
- Add mlock + seccomp to Android Rust side.
- Make CI fail on missing security-path test coverage (in progress).
- Side-channel / constant-time review of export, groups, voice (in progress).
- Full multi-screen navigation hardening on Android (significant improvements made).
- Expand decentralized discovery into concrete protocol with message formats (skeleton expanded).

### Credibility & Hardening (Mostly Complete)
- Basic + expanded tests for ratchet, wipe, disappearing, posture, export (strong progress).
- More disappearing-message key wipe integration (improved across stack).
- Posture refusal pass (centralized helper + dynamic re-eval added).

### Medium / Longer Term
- Reproducible Android .so in Nix.
- Update THREATMODEL.md with all new features.
- Quantum skeleton moved to gated module.
- Formal v0.2 release process with signed tag and limitations document.

## Medium Term (Next 1-2 Months)

- Make Flatpak the primary distribution method (signed, one-command via Nix).
- One final git history clean + v0.2 / "preview" tag.
- Android: Proper multi-screen navigation (dedicated Group list screen, improved voice recording UI).
- Next technical feature: streaming file transfer or secure cross-device ratchet export.

## Longer Term / Stretch Goals

- Real test suite + CI that exercises wipe, posture, and crypto paths.
- Quantum-resistant options (post-quantum KEMs as noted in earlier roadmap).
- Decentralized discovery without leaking metadata.

Approach: small trusted computing base; Rust for crypto, Tor, persistence, and the recommended desktop TUI; Tor-only default transport (fail-closed). Haskell desktop removed 2026-10-12.

Contributions are very welcome — especially in the remaining polish areas above.

---

## First release scope

The first release is small on purpose: reliable one-to-one chat, the wipe family (`:wipe`, duress passphrase, dead-man switch, panic key), Tor with bridges and a clear kill switch when Tor is down, self-hosted relays, and reproducible signed builds. Everything else below comes after that and is ordered, not promised.

## Planned features, in order

Standing rules for every item: no phone number, email, real name or identity check, in the app or in any website or licence step; no telemetry; Tor is the default transport and there is no silent fallback; the project holds no user data, so GDPR and LGPD are met by collecting nothing (see PRIVACY.md); security work comes before interface polish, and within that, higher security value before lower effort.

**Done so far.** `:wipe` with a random overwrite before unlink; a duress passphrase that wipes at the unlock prompt and can open an empty decoy profile afterwards (`:duress set decoy`); a dead-man switch that wipes at startup after N days without an unlock; a wipe after N failed unlocks that survives restarts; a panic key (Ctrl+\) and `hashchat-tui --wipe` to wipe without a prompt; contact links bound to the onion service key, so a link cannot claim an onion its author does not control (I-6); frames padded to fixed size classes (512 B to 8 KiB) inside the encrypted payload; wire format v3, which carries the start of the sender's DH epoch so a lost run of messages, even a whole epoch, no longer breaks the session; separate chains for each direction at bootstrap, bound to both static keys, which closes the reflection and shared-key part of M-1; optional send-time jitter (`:jitter`, up to two minutes) that holds each committed frame for a random delay before it goes to Tor; a warning at unlock when the system clock reads more than an hour earlier than the last save (`:clock`, `:clock-reset`); a warning at unlock when the running binary is not the one recorded in the profile (`:binary`, `:binary-accept`); a warning at unlock when the dead-man, failed-unlock or duress setting changed while the profile was locked (`:wipe-settings`, `:wipe-settings-accept`); a warning at unlock when `state.enc` is not the copy last saved in that directory, which catches an older backup or image put back in place. When Tor drops while a profile is open, the transcript says so, the header counts frames waiting in the encrypted queue, and those frames go out over Tor on their own once SOCKS answers again. `:bridges torrc LINE` checks an obfs4, snowflake or webtunnel bridge line and prints the torrc lines to add, `:bridges` asks Tor (read-only) whether bridges are on and whether every built circuit starts at one of them, and `:bridges require on` keeps every outgoing frame in the encrypted queue until that check passes and withdraws a published onion service if the check later fails.

### Before the first release

1. **Finish the handshake and wire format (M-1).** Partial: `init_directional_with_salt` / `fresh_bootstrap_salt` so a shared per-session salt stops static re-add from recreating old roots; `frame_v3_sealed` / `is_sealed_hint` for empty-hint frames; one-time invite links (`invite` module: `hashchat://invite/v1/...` signed over a fresh salt, random invite id and expiry, optional onion binding; the inviter's `PendingInvites` hands each salt out once, and both sides derive the same salted root). **TUI wired (2026-10-14):** `:invite [ttl]` issues an onion-bound one-time link (default 24 h, max 7 days; `:invite count`, `:invite revoke-all`), open invites persist in the encrypted profile (blob v13, dropped on disk under Extreme), `:add-contact <invite>` starts the salted session and prints an invite reply, and `:add-contact <reply>` on the inviter side spends the invite once after checking a salt-keyed HMAC tag that binds the reply to the redeemer's signed contact link. Still open: carry the reply inside the redeemer's first frame instead of out of band, wire sealed frames through the TUI send path, cover traffic, and per-contact onion addresses (a separate queue for each contact, as SimpleX does) so two contacts cannot tell they talk to the same person.
2. **Finish the wipe family.** A panic gesture beyond the key (for example on Android); a decoy profile that holds plausible content rather than an empty one. Later: travel mode (hide chats and keys, restore with the passphrase) and remote wipe by a trusted contact with a secret word. Keep the honest limits in the docs: overwriting is unreliable on SSDs and copy-on-write filesystems, and a wipe after an investigation has started can be read as destroying evidence.
3. **Tor bridges and the kill switch.** Pluggable-transport bridge configuration (obfs4, Snowflake). The Tor-down state, the held queue, bridge line checks, the check that bridges took effect (`:bridges`) and the opt-in send hold (`:bridges require on`) are done. With it on, `:listen` also waits for the check before publishing the onion service, and while the service is published the TUI re-runs the check (every 30 s while it passes) and withdraws the onion service when bridges stop being active; publishing again is a manual `:listen`. What remains: I2P as its own transport. I2P comes later as its own transport. Until then non-Tor modes keep refusing.
4. **Self-hosted relay.** A small Rust store-and-forward relay people run themselves, reachable only over Tor, holding padded ciphertext for offline peers, no accounts, no logs. One command to set it up as an onion service. Then several relays per contact with failover. Operators see ciphertext only and carry the usual hosting duties; a data-processing statement ships with the relay.
5. **Reproducible, signed builds and updates.** Bit-for-bit Linux binary and Android libraries, built by more than one independent builder, signed with an offline key, with a verify script. Updates are signed, checkable offline and never applied silently. Releases are published over Tor and on Codeberg, with torrent or IPFS later and the signature check built in.
6. **Trust documents.** PRIVACY.md is in place. Still to write: an honest limits page in the app and the docs, a plain-language safe-use guide, an open threat model, a signed warrant canary file, a short calm statement from the founder about what the project is for and what it will not do, and a bug bounty paid in Monero once funds allow.

### After the first release

**SimpleX-class parity.** Checked against the current feature list: no user identifiers (done, there is only an onion address and public keys), groups (done), voice messages (listed as done above), disappearing messages (local timer done; the peer cannot be forced to delete), one-time invitation links (done in the TUI via `:invite`; QR display still open), separate queue per contact (missing, see item 1), self-hostable relays (item 4), an incognito profile per chat (burner profiles exist per session, not per chat), file transfer (missing, streamed over the ratchet), and an encrypted local backup (missing; the library has an encrypted ratchet export (`DoubleRatchet` + `envelope`), the app does not). Order: one-time invitations, per-chat incognito profile, encrypted backup and import/export migration, file transfer.

**Beyond parity, ordered by security value.**
- Cryptography: a hybrid X25519 plus ML-KEM exchange, claimed only once a vetted implementation is used and tested; deniable authentication; fuzzing and formal checks of the parsers and the ratchet in CI; `unsafe` confined to one small audited module; Shamir-split encrypted identity backup.
- Resilience: encrypted offline and scheduled send queue; bridges first, then I2P; mesh, Bluetooth and Wi-Fi Direct messaging; offline and air-gapped transfer by QR and removable media; serverless QR device linking.
- Safety: lock on an unknown USB device or a new network; a sealed last-resort message to a trusted contact if the dead-man switch fires; hidden second profile, only after a written design that has been reviewed, with its limits stated and no claim of being undetectable; a self-audit screen listing fingerprints, relays and the local data inventory; plain-text export of your own data.
- Usability: encrypted searchable history with per-chat expiry; chat folders; quiet mode with no message content in notifications; large text, a high-contrast black and gold theme and keyboard-only use; safe link handling (open in Frihart without scripts over Tor, strip tracking parameters); contact import by link only, never an address-book upload; a self-run contact directory that is never central.
- Groups and community: private groups for small teams, families and house churches with simple admin keys, moderation by the group's own admins, expiring invites, optional public rooms on top of the relay.
- Packaging: AppArmor and SELinux profiles, Flatpak sandbox, Qubes and Tails modes, safe defaults for GrapheneOS, Jolla and Volla.
- Documentation: translations to Portuguese, French, German and Spanish.

**Payments for paid builds.** The 100 EUR lifetime licence for non-Linux platforms is paid in Monero or Bitcoin, which are the defaults; Lightning is welcome. No account, no licence server and no wallet in the app. The planned check works like this: the buyer pays to a fresh per-order address, the seller confirms the payment on chain, and the buyer receives a one-time licence token that is a signature over a random order number, verified offline by the build. The token is tied to nothing about the buyer. The flow collects only what the chain shows; no name, email, country or ID is requested. A donation page accepts XMR, BTC and Lightning. Linux and Linux phones stay free.

**Licence for paid builds.** The source stays under the AGPL, and the AGPL does not allow restricting who may use the source. The paid non-Linux builds are sold under a separate purchase licence, and that licence does not permit sale to governments or government bodies. The purchase terms bind the buyer through the act of payment and cannot be backed by collecting identity data, because we do not collect it. The limit is stated plainly: the terms can refuse a sale and bind the buyer, but they cannot stop a government from building the AGPL source itself or from buying through a third party who is not honest about who they are. Companies that need an invoice may supply details voluntarily; individuals never have to.

**Shared with Frihart.** The wipe family (panic key, duress passphrase, overwrite wipe), the signed-build and update scheme, the payment and licence check, the honest limits page and PRIVACY.md are meant to be the same in both products, so they should live in code or documents that both can reuse.

## Transport Expansion (Wave 7+)

Major ongoing work to give users strong anonymity flexibility:

- SOCKS5 proxy support (foundation) — allows routing through user Tor, I2P, Proton, Mullvad, IVPN, etc.
- I2P as first-class transport (high strategic value).
- Better Tor bridge / pluggable transport support.

These features are being built in a way that preserves the core metadata-resistant model and integrates with the Extreme profile.

## Post-v0.2 Philosophy Decision Required (Tier 3)

Before the next major phase we must explicitly decide the Android vs Desktop TUI strategy:

**Option A (Recommended by current direction):** "Make Android as strong as the desktop TUI."
- Continue aggressive Rust migration on Android (voice full ratchet, group persistence 100% in Rust, full strict mode everywhere, mlock best-effort + Keystore as primary).
- Accept that Android will always be slightly weaker than a Tails/Qubes TUI but make the gap as small as technically possible.
- Result: one product with two high-quality surfaces.

**Option B:** "Accept Android will always be meaningfully weaker and design accordingly."
- Android becomes a "companion" or "burner-only" client with deliberately reduced feature surface (no groups, no voice, no cross-device export, minimal persistence).
- Desktop TUI remains the primary hardened client.
- Extreme users get Option C (see below).

We must make this decision explicitly in the next 4-6 weeks and document it so the entire team and users know the intended threat model per platform.

## Second Ultra-Stripped "Extreme" Profile (Tier 3)

Some users (journalists in the most hostile environments, high-value targets) may want an even smaller attack surface than the current burner + decoy model.

Proposed "Extreme" profile (disabled by default, user must explicitly enable):

- Groups completely disabled
- Voice recording/playback disabled
- Cross-device ratchet export disabled
- Decoy profile disabled (only one burner)
- No persistent contacts or history beyond current session
- Strict mode forced on at all times with no bypass
- Even more aggressive memory wiping + shorter key lifetimes
- Smaller APK / binary surface (if we ever split builds)

This would be a separate launch mode or compile-time flag. It trades almost all usability for the smallest possible trusted computing base and metadata surface.

Implementation sketch: a top-level `ExtremeMode` flag that gates entire feature paths in both TUI and Android, plus a dedicated THREATMODEL section.

**Decision needed:** Do we want this as a real supported mode post-v0.2, or is the current burner + decoy + strict mode sufficient?

Document owner: keep this section updated after the philosophy decision.

## Android: maximum Rust (approved by Lucas, 2026-10-12)
Goal: move as much of the Android app as possible into Rust, keeping only the minimal Kotlin/Java shell Android requires (Activity entry, permissions, lifecycle).
1. Inventory Kotlin code in `android/` and classify: must-stay shell vs. movable logic. **Done:** [docs/ANDROID_RUST_INVENTORY.md](docs/ANDROID_RUST_INVENTORY.md). Device posture policy is `device_posture` in the shared crate; **JNI binding done** (`evaluatePostureFromSignals` / `isActionAllowedForSignals`); Android crate path-depends on `hashchat-rust`.
2. Move all crypto, Tor, messaging, storage and state logic into the Rust crate (shared with desktop where possible). **In progress:** the group list is owned by Rust (`group_store::GroupBook` via JNI `groupBook*`; Kotlin renders and Keystore-wraps only). The native ratchet, group sender-key and voice stores are Mutex-guarded (no `static mut`), slot ids are bounded, and exported key bytes are zeroized (2026-10-14). Still open: persisting group sender keys (needs a user-derived key), message-list and decoy state, export flow.
3. Evaluate a Rust UI (Slint or egui via android-activity) on a prototype screen; adopt only if stable and accessible.
4. Migrate screens incrementally; never break the working app; tests green at every step.
5. End state: Kotlin limited to a thin generated shell.

## Front end: elegant Rust UI (approved by Lucas, 2026-10-12)

Implement [docs/DESIGN.md](docs/DESIGN.md) in the real UI, step by step, in Rust. Concepts: `docs/screenshots/concept/`.

1. **TUI theme module** (ratatui): one `theme.rs` with the palette tokens, truecolor with 16-color fallback.
2. **TUI status bar**: Tor / fail-closed / posture / lock as colored pills; red when Tor is down.
3. **TUI contacts and chat**: verified / unverified markers, gold outgoing messages, mono meta line.
4. **TUI SAS and contact-link panels** matching the concepts (`:sas`, `:verify`, `:my-contact`, `:add-contact`).
5. **Android**: once the Rust core is bound (see "Android: maximum Rust"), pilot one screen in Slint (or egui) with the same tokens, then migrate screen by screen.
6. Replace concept images with real screenshots as each piece lands.

## Sustainability: free + paid model (approved by Lucas, 2026-10-12)

Principle: **privacy and anonymity are always free; paying never unlocks
privacy, only comfort features.** Free mode is the default.

- Free: tor-only end-to-end messaging, small groups, sas contact verification, fail-closed transport, local encrypted storage.
- Supporter (paid): large groups, multi-device sync, bigger files, themes, encrypted backup, priority support.
- Draft prices: €4.99/month, €49/year, €149 lifetime. Bundle with
  Frihart: €7.99/month or €229 lifetime. Launch offer: €99 lifetime for the
  first 500 supporters. Pay-what-you-want, any amount.
- Payments: crypto only. Monero preferred, plus Bitcoin and Lightning, via
  self-hosted BTCPay Server (Monero plugin) or MoneroPay. Fresh address per
  invoice, no account, no license server. Prepaid 3/6/12-month packs with a
  local expiry reminder.
- Done: offline Ed25519 license module (`src/rust/entitlement.rs`), `:support` screen in the TUI,
  [docs/SUPPORT.md](docs/SUPPORT.md), [docs/HOW_TO_PAY.md](docs/HOW_TO_PAY.md),
  [docs/PAYMENTS_SETUP.md](docs/PAYMENTS_SETUP.md).
- Next: Lucas provides receiving addresses (or an xpub / view-only wallet)
  and a server for BTCPay; generate the offline signing key and set
  `MAINTAINER_PUBKEY`; wire each comfort feature to `Entitlement::allows`
  as it ships.
