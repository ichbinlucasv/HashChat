# HashChat design system

Dark-first, black and gold, calm. Security state is always visible, never hidden in a menu.
Concept images: [`docs/screenshots/concept/`](screenshots/concept/) (HTML/CSS sources in `src/`).

## Palette
| Token | Hex | Use |
|---|---|---|
| bg | `#000000` / `#0B0B0D` | window / panels |
| surface | `#121214` | inputs, incoming bubbles |
| hairline | `#1D1B15` | borders |
| gold | `#FFD24A` (brand `#FFD700`) | brand, outgoing bubbles, verified |
| gold-deep | `#E8B400` | gradient end |
| text | `#EDEDED` · muted `#8A8778` | body · metadata |
| tor | `#C4A8FF` | Tor transport pill |
| i2p | `#7EE0C6` | I2P (only shown as refused today) |
| danger | `#FF8A8A` | unverified, wipe, refusal |

TUI mapping (ratatui): gold → `Color::Rgb(255,210,74)`, muted → `Rgb(138,135,120)`, danger → `Rgb(255,138,138)`; fall back to 16-color `Yellow` / `DarkGray` / `Red`.

## Typography
- UI: Inter (fallback DejaVu Sans), 15 px body, 600 for names, 800 for the wordmark.
- Mono: JetBrains Mono / DejaVu Sans Mono for onion addresses, SAS, fingerprints, commands, metadata.

## Spacing and shape
4 px grid (4/8/12/16/24). Radius: 12 px cards, 16 px bubbles (tail corner 4 px), pills fully round.

## Components
- **Status bar pills** (always on): `Tor · onion listening`, `Fail-closed · no clearnet`, posture, lock.
- **Contact row**: avatar initial, name, one status line (verified / unverified / disappearing / muted).
- **Bubbles**: incoming = surface, outgoing = gold gradient; meta line in mono (`via Tor v3 · Double Ratchet`).
- **Verification badge**: gold `✓ Verified (SAS)`; red banner for unverified with `:send-unverified` as the explicit escape.
- **SAS grid**: 8 mono blocks, numbers only, compare out of band, then `:verify` or `:block`.
- **Contact link card**: `hashchat://` signed link (Contact Link v1), checks list (signature, onion, Tor-only).
- **Fail-closed indicator**: if Tor is down the pill turns red and sending is refused; never a silent fallback.
- **Destructive actions** (`:wipe`, `:duress`, `:delete-contact`) are red and always need the confirm command.

## Rules
Show only features that exist. Never show real onion addresses or keys in screenshots.
