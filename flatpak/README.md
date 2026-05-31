# HashChat Flatpak

This directory contains everything needed to build and distribute HashChat as a Flatpak.

## Current Status (as of June 2026)

- The manifest is now **pure install-only** (no application code is built inside the Flatpak sandbox).
- The **only supported and reproducible way** to build a working `.flatpak` is:
  ```bash
  nix build .#hashchat-flatpak
  ```
- Both the Rust library and the TUI binary are pre-built by the flake for maximum reliability.

## Building

### Recommended (Reproducible)
```bash
nix build .#hashchat-flatpak
flatpak install --user result/hashchat-tui.flatpak
flatpak run org.hashchat.HashChat
```

### Manual (Not Recommended)
You can try building with `flatpak-builder` directly, but you must provide the two prebuilt artifacts in a `prebuilt/` directory before running it.

## Icons

See [ICONS.md](./ICONS.md) for the exact requirements.

Current status: Placeholder SVG only. Real icons are still needed for a finished release.

## Flathub Readiness

The metainfo.xml has been improved with releases, categories, and keywords.

Still missing before Flathub submission:
- Real screenshots
- High-quality icons at all required sizes
- Proper release notes with dates

## "Proper and Finished" Checklist (June 2026)

- [x] Manifest is minimal and install-only (no in-sandbox app builds)
- [x] Nix flake reliably produces prebuilt artifacts
- [x] Strong, well-documented finish-args
- [x] Basic icon support + clear documentation (ICONS.md)
- [ ] Real high-quality icons (SVG + properly sized PNGs)
- [ ] Real screenshots in metainfo.xml
- [ ] Final Flathub submission polish
- [ ] Signed v0.2 release

Current state: The packaging foundation is solid and "proper". The remaining items above are mostly asset-related (icons + screenshots) rather than structural.

## Contact

For questions about the Flatpak packaging, open an issue on the main repository.
