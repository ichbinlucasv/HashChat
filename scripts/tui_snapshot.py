#!/usr/bin/env python3
"""Render ratatui TestBackend cell dumps (*.cells) to PNG.

Usage: HASHCHAT_SNAPSHOT_DIR=/tmp/cells cargo test --features tui --bin hashchat-tui design_
       python3 scripts/tui_snapshot.py /tmp/cells docs/screenshots/real
"""
import sys, pathlib
from PIL import Image, ImageDraw, ImageFont

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
FS, CW, CH, PAD = 16, 10, 21, 18

def hexc(h, default):
    return default if h == "-" else tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))

def render(src, dst):
    lines = src.read_text(encoding="utf-8").split("\n")
    w, h = map(int, lines[0].split())
    f, fb = ImageFont.truetype(MONO, FS), ImageFont.truetype(MONO_B, FS)
    img = Image.new("RGB", (w * CW + 2 * PAD, h * CH + 2 * PAD), (0, 0, 0))
    d = ImageDraw.Draw(img)
    cells = [(row.split("\t", 3) + ["", "", "", " "])[:4] for row in lines[1:1 + w * h]]
    for i, (fg, bg, bold, sym) in enumerate(cells):
        x, y = PAD + (i % w) * CW, PAD + (i // w) * CH
        d.rectangle([x, y, x + CW, y + CH], fill=hexc(bg, (0, 0, 0)))
    for i, (fg, bg, bold, sym) in enumerate(cells):
        x, y = PAD + (i % w) * CW, PAD + (i // w) * CH
        if sym.strip():
            d.text((x, y + 1), sym, font=fb if bold == "1" else f, fill=hexc(fg, (237, 237, 237)))
    img.save(dst)
    print(dst)

if __name__ == "__main__":
    s, o = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    o.mkdir(parents=True, exist_ok=True)
    for c in sorted(s.glob("*.cells")):
        render(c, o / (c.stem + ".png"))
