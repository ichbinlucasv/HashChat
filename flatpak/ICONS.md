# HashChat Flatpak Icons

For a proper, Flathub-ready release, the following icons are required:

## Required Files

Place icons in `flatpak/icons/hicolor/`:

### Scalable (Recommended)
- `scalable/apps/org.hashchat.HashChat.svg` (vector, preferred)

### Raster (Required by Flathub)
You must provide properly sized PNGs:

- `64x64/apps/org.hashchat.HashChat.png`
- `128x128/apps/org.hashchat.HashChat.png`
- `256x256/apps/org.hashchat.HashChat.png`
- `512x512/apps/org.hashchat.HashChat.png` (highly recommended)

## Design Guidelines

- Use the project colors: Black (#000000) background + Gold (#FFD700) accents
- Keep it simple and recognizable at small sizes
- Test on both light and dark themes
- Avoid text in icons if possible (the current placeholder uses "HC")

## Current Status

- Improved security-themed placeholder SVG exists (black #000000 + gold #FFD700 lock + HC monogram; rounded with double border for paranoid aesthetic).
- No production-quality raster icons yet (critical blocking item for v0.2 / Flathub).
- Full hicolor directory tree prepared for 64/128/256/512 + scalable.

## Generating Raster Icons from the SVG (Exact Commands for Maintainers)

Use the scalable SVG as source of truth. Run from project root:

### Preferred (rsvg-convert from librsvg2-bin, small + sharp):
```bash
mkdir -p flatpak/icons/hicolor/{64x64,128x128,256x256,512x512}/apps
for s in 64 128 256 512; do
  rsvg-convert -w $s -h $s flatpak/icons/hicolor/scalable/apps/org.hashchat.HashChat.svg \
    -o flatpak/icons/hicolor/${s}x${s}/apps/org.hashchat.HashChat.png
done
```

### Alternative (ImageMagick convert, common on Fedora):
```bash
for s in 64 128 256 512; do
  convert -background none -resize ${s}x${s} \
    flatpak/icons/hicolor/scalable/apps/org.hashchat.HashChat.svg \
    flatpak/icons/hicolor/${s}x${s}/apps/org.hashchat.HashChat.png
done
```

### Inkscape (highest quality for complex paths):
```bash
for s in 64 128 256 512; do
  inkscape --export-type=png --export-width=$s --export-height=$s \
    --export-filename=flatpak/icons/hicolor/${s}x${s}/apps/org.hashchat.HashChat.png \
    flatpak/icons/hicolor/scalable/apps/org.hashchat.HashChat.svg
done
```

After generation, verify with `file` and visually at small sizes. Update this file with credits.

## Before Public Release / Flathub (Critical)

1. Commission or draw final professional icon (same black+gold, lock or abstract "H" shield, no text if possible at small sizes).
2. Run one of the pipelines above to produce the 4 PNGs.
3. Commit the PNGs + updated SVG.
4. Test Flatpak install icon appearance on GNOME/KDE.

The current improved placeholder (with lock symbol) is used until real assets replace it.
Real icons are a v0.2 blocking item per expert review.
