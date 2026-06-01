# HashChat Screenshot Guidelines for v0.2 / Flathub

**Critical**: Real screenshots are a v0.2 blocking item. The metainfo.xml currently uses example.com placeholders. Replace before any public release or Flathub submission.

## Theme & Style (Mandatory for Consistency)
- Black background (#000000)
- Gold accents (#FFD700) for titles, highlights, bubbles, borders
- White text for body
- Explicit "via Tor v3 · Double Ratchet" metadata lines where possible
- Live Security Posture visible in title bar (TUI) or top bar (Android)

## Desktop TUI Screenshots (Recommended 4-5 shots)

### 1. Main view (default screenshot)
- Terminal: 120x40 or wider, clean black
- Show active contact with 3-4 messages (mix sent/received)
- Visible in title or status block: "Security Posture: MAX PARANOID (Tails/Qubes + Tor recommended)"
- Gold "HC" or project branding
- Input bar at bottom with hint text
- No sensitive real data (use burner profile "Demo")

### 2. Posture refusal
- Trigger with 'v' (voice) or 'g' (group) while in a simulated low-posture env (or edit code temporarily to force "LOW")
- Clear red/gold warning line: "[SECURITY] DYNAMIC POSTURE REFUSAL: Voice disabled..."
- Shows the paranoid gating in action (key for credibility)

### 3. Voice playback
- After 'v' record (demo chunk) or simulated receive
- During/after ffplay: show the "[VOICE] Playback complete. Chunk file + associated ratchet material wiped." + wipeRatchetMessageKey log
- Emphasizes forward secrecy + explicit wipe

### 4. Groups / QR
- 'g' menu or active group view
- Show "hashchat://group/..." QR-style link text
- Member list with sender-key ratchets

### 5. 'a' actions menu (Simplex parity)
- Long-press equivalent: full list (Block, Report, Delete, Mute, Disappearing timer, Security Info / ratchet step / E2EE posture)

**Capture tip (Fedora desktop for marketplace)**: 
- Install: `sudo dnf install grim slurp gnome-screenshot optipng`
- Prep (recommended): `HASHCHAT_DEMO=main ./scripts/screenshot-prep-fedora.sh` (handles Tor, build hint, demo states for exact shots).
- Specific shots (resize term ~120x40+):
  - Main: `HASHCHAT_DEMO=main ./run-tui` → grim ...
  - Refusal: `HASHCHAT_DEMO=refusal ./run-tui` (or temp force LOW in getSecurityPosture for 'v'/'g' trigger).
  - Voice: `HASHCHAT_DEMO=voice ./run-tui` → 'v' then playback.
  - Groups/QR + actions: `HASHCHAT_DEMO=groups ./run-tui` then 'g'/'a'.
- Capture: `grim -g "$(slurp -o)" hashchat-tui-xxx.png` or `gnome-screenshot -a`.
- Optimize: `optipng *.png`.
- Fedora/Flathub: Upload to Codeberg releases (or host); replace example.com in flatpak/org.hashchat.HashChat.metainfo.xml with real https://... . Use exact black+gold theme. See prep script for icon raster (rsvg-convert) and Flatpak submit steps.

## Android Screenshots (Recommended 4 shots)

Use Android emulator (API 34+, dark theme) or real device. Disable system bars if possible for clean look. Use the exact gold/black colors from res/values.

### 1. Main chat (RecyclerView)
- Gold bubbles for your messages, dark for peer
- Top bar: profile name + live posture indicator (e.g. "MAX PARANOID · Tor")
- Bottom input + gold voice mic button
- "via Tor v3 · Double Ratchet" meta under messages

### 2. Long-press actions (exact Simplex parity)
- Long-press a message → dialog with: Block / Report / Delete / Disappear (timer menu) / Security Info (shows ratchet step + E2EE + wipe status)
- Matches TUI 'a' menu 1:1

### 3. Voice recording + playback
- Dedicated voice recording screen or active recording state
- Playback with real SeekBar dragging + live progress
- Post-playback toast or banner: "Voice complete (ratchet key advanced + wiped after playback)"

### 4. Posture refusal + group QR
- Attempt voice/group in low posture → clear refusal Toast + top bar update
- Groups list / detail screen with QR hashchat:// link and member list

**Capture tip**: Use Android Studio screenshot tool or `adb exec-out screencap -p > shot.png`. Clean status bar if possible. Use consistent demo profile "Demo User".

## OPSEC for Screenshots
- Never use real Tor onion addresses, real ratchet exports, or identifiable data.
- Always run `./scripts/clean-security.sh` before and after capture sessions.
- Use burner profiles + decoy where possible.
- Delete all screenshot source files from host after uploading to release assets or repo (or store only in encrypted volume).

## Process Before v0.2 Signed Tag
1. Capture the 6-8 shots on clean environment (Tails/Qubes preferred for authenticity).
2. Optimize + name consistently (hashchat-tui-main.png, hashchat-android-voice-wipe.png, etc.).
3. Replace the 4 `<screenshot>` blocks in `flatpak/org.hashchat.HashChat.metainfo.xml` with real https://raw.githubusercontent.com/... URLs or local relative if packaging allows.
4. Update this file with "Captured on [date] using [device/env]".
5. Re-run full clean + tests + `./scripts/safe-commit.sh` style flow.
6. Proceed to signed tag per RELEASE_PROCESS.md.

This directly satisfies the "Real screenshots" critical item from the expert v0.2 blocking list.

See also: flatpak/ICONS.md, docs/RELEASE_NOTES_v0.2.md (Known Limitations), THREATMODEL.md.