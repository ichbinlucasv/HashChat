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

- Placeholder SVG exists (functional but not final)
- No production-quality raster icons yet

## Before Public Release / Flathub

1. Replace the placeholder SVG with a high-quality vector icon
2. Export proper PNGs at all required sizes
3. Update this file with the final icon designer credit if applicable

Until real icons are added, the current placeholder will be used.
