# HashChat Flatpak Icons

Canonical brand: **logo 2** — gold chat bubble with hash (#) + typing dots on black `#0A0A0A` / gold `#FFD700`.
Source assets: `branding/hashchat-icon.svg` and matching PNGs (synced into hicolor).

## Required files (present)

Under `flatpak/icons/hicolor/`:

| Path | Status |
|------|--------|
| `scalable/apps/org.hashchat.HashChat.svg` | Present (logo 2) |
| `64x64/apps/org.hashchat.HashChat.png` | Present |
| `128x128/apps/org.hashchat.HashChat.png` | Present |
| `256x256/apps/org.hashchat.HashChat.png` | Present |
| `512x512/apps/org.hashchat.HashChat.png` | Present |

Desktop/metainfo `Icon=` / icon name: **`org.hashchat.HashChat`**.
The Flatpak manifest installs scalable + all four raster sizes (fail-hard if missing).

## Design guidelines

- Black `#0A0A0A` plate + gold `#FFD700` mark (see `branding/COLORS.md`)
- Recognizable at 64px; no blue brand colour
- Older shield explorations stay under `branding/alts/` (reference only)

## Regenerating rasters from SVG

From project root (keep filenames exact):

```bash
# rsvg-convert (librsvg)
for s in 64 128 256 512; do
  rsvg-convert -w $s -h $s flatpak/icons/hicolor/scalable/apps/org.hashchat.HashChat.svg \
    -o flatpak/icons/hicolor/${s}x${s}/apps/org.hashchat.HashChat.png
done
```

Or copy from branding after updating the SVG:

```bash
cp branding/hashchat-icon.svg flatpak/icons/hicolor/scalable/apps/org.hashchat.HashChat.svg
# then regenerate PNGs, or copy branding/hashchat-icon-512.png → 512x512/…
```

## Before Flathub

- [x] Logo 2 SVG + 64/128/256/512 in hicolor
- [x] Manifest installs icons
- [ ] Real screenshots in metainfo (see `docs/SCREENSHOTS.md`)
- [ ] Visual check on GNOME/KDE after `flatpak install`
