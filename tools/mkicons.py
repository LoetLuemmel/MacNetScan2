#!/usr/bin/env python3
"""mkicons.py ICON.png OUT.r [preview.png] - MacNetScan 2's Finder icon family from a PNG: ICN#, icl8, icl4 (32 px) and
ics#, ics8, ics4 (16 px), id 128, plus the bundle (BNDL, FREF, owner resource 'IPSc') and 'vers'. The PNG has no alpha:
the 16 px icon is the middle Mac alone; the mask is everything a flood fill of near-white from the border does not reach. Colours go to the nearest entry of
the Mac's standard 8-bit and 4-bit tables. Needs ImageMagick (`magick`) for the scaling; stdlib otherwise.
  Rez -a OUT.r -o "Project Resources.rsrc", build, then: SetFile -a B MacNetScan  (the Finder reads the BNDL) """
import subprocess, sys, struct, zlib

src, out = sys.argv[1], sys.argv[2]
preview = sys.argv[3] if len(sys.argv) > 3 else None


def clut8():
    t = []
    for r in range(6):
        for g in range(6):
            for b in range(6):
                t.append((0xFF - 0x33 * r, 0xFF - 0x33 * g, 0xFF - 0x33 * b))
    t = t[:215]                                              # the cube without black
    ramp = [0xEE, 0xDD, 0xBB, 0xAA, 0x88, 0x77, 0x55, 0x44, 0x22, 0x11]
    t += [(v, 0, 0) for v in ramp] + [(0, v, 0) for v in ramp] + [(0, 0, v) for v in ramp] + [(v, v, v) for v in ramp]
    t.append((0, 0, 0))
    assert len(t) == 256
    return t


CLUT4 = [(0xFF, 0xFF, 0xFF), (0xFC, 0xF3, 0x05), (0xFF, 0x64, 0x02), (0xDD, 0x08, 0x06), (0xF2, 0x08, 0x84),
         (0x46, 0x00, 0xA5), (0x00, 0x00, 0xD4), (0x02, 0xAB, 0xEA), (0x1F, 0xB7, 0x14), (0x00, 0x64, 0x11),
         (0x56, 0x2C, 0x05), (0x90, 0x71, 0x3A), (0xC0, 0xC0, 0xC0), (0x80, 0x80, 0x80), (0x40, 0x40, 0x40),
         (0x00, 0x00, 0x00)]
CLUT8 = clut8()


def nearest(table, c):
    return min(range(len(table)), key=lambda i: sum((table[i][k] - c[k]) ** 2 for k in range(3)))


def pixels(n, crop=None):
    pre = ["-crop", crop, "+repage"] if crop else []
    raw = subprocess.run(["magick", src] + pre + ["-filter", "Lanczos", "-resize", f"{n}x{n}!", "-depth", "8", "rgb:-"],
                         capture_output=True, check=True).stdout
    return [[tuple(raw[(y * n + x) * 3:(y * n + x) * 3 + 3]) for x in range(n)] for y in range(n)]


def mask_of(px):
    n = len(px)
    white = lambda c: min(c) > 232
    outside = [[False] * n for _ in range(n)]
    stack = [(x, y) for x in range(n) for y in (0, n - 1)] + [(x, y) for y in range(n) for x in (0, n - 1)]
    while stack:
        x, y = stack.pop()
        if 0 <= x < n and 0 <= y < n and not outside[y][x] and white(px[y][x]):
            outside[y][x] = True
            stack += [(x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)]
    return [[not outside[y][x] for x in range(n)] for y in range(n)]


def planes(px, m):
    n = len(px)
    icon, mask = bytearray(), bytearray()
    for y in range(n):
        for x0 in range(0, n, 8):
            bi = bm = 0
            for x in range(x0, x0 + 8):
                r, g, b = px[y][x]
                dark = m[y][x] and (r * 30 + g * 59 + b * 11) / 100 < 150
                bi = bi << 1 | (1 if dark else 0)
                bm = bm << 1 | (1 if m[y][x] else 0)
            icon.append(bi)
            mask.append(bm)
    return bytes(icon + mask)


def deep(px, m, table, per):
    o = bytearray()
    for y, row in enumerate(px):
        v = [nearest(table, c) if m[y][x] else 0 for x, c in enumerate(row)]
        o += bytes(v) if per == 8 else bytes(v[i] << 4 | v[i + 1] for i in range(0, len(v), 2))
    return bytes(o)


def hexdata(b, width=32):
    return "\n".join('\t$"' + b[i:i + width].hex().upper() + '"' for i in range(0, len(b), width))


big, small = pixels(32), pixels(16, "260x260+126+118")	# 16 px: the middle Mac alone
mb, ms = mask_of(big), mask_of(small)
parts = [("ICN#", planes(big, mb)), ("icl8", deep(big, mb, CLUT8, 8)), ("icl4", deep(big, mb, CLUT4, 4)),
         ("ics#", planes(small, ms)), ("ics8", deep(small, ms, CLUT8, 8)), ("ics4", deep(small, ms, CLUT4, 4))]
r = ["/* Icons.r - MacNetScan 2's Finder bundle, icons and version; written by tools/mkicons.py from",
     "   assets/LAN-Scan-Icon-512.png, do not edit by hand. Rez -a Icons.r -o \"Project Resources.rsrc\";",
     "   after Build Application: SetFile -a B MacNetScan (the Finder reads the BNDL then). */", "",
     '#include "Types.r"', "",
     "data 'IPSc' (0, \"Owner resource\") {", '\t$"0E" "MacNetScan 2.0"', "};", "",
     "resource 'BNDL' (128) {", "\t'IPSc', 0,", "\t{", "\t\t'ICN#', { 0, 128 },", "\t\t'FREF', { 0, 128 }", "\t}", "};", "",
     "resource 'FREF' (128) { 'APPL', 0, \"\" };", "",
     "resource 'vers' (1) {", "\t0x02, 0x00, release, 0x00, verUS, \"2.0\",",
     "\t\"2.0, \\0xA9 2026 Pit F\\0x9Arster - MIT License\"", "};", "",
     "resource 'vers' (2) {", "\t0x02, 0x00, release, 0x00, verUS, \"2.0\", \"MacNetScan 2\"", "};", ""]
for typ, data in parts:
    r.append(f"data '{typ}' (128, \"MacNetScan\") {{\n{hexdata(data)}\n}};\n")
open(out, "w").write("\n".join(r))
print(out, "written")

if preview:
    S, PAD = 6, 8
    tiles = [(big, mb, 32), (small, ms, 16)]
    w = PAD + sum(n * S + PAD for _, _, n in tiles)
    h = 32 * S + 2 * PAD
    img = [[(150, 150, 150)] * w for _ in range(h)]
    x0 = PAD
    for px, m, n in tiles:
        for y in range(n):
            for x in range(n):
                if not m[y][x]:
                    continue
                c = CLUT8[nearest(CLUT8, px[y][x])]
                for dy in range(S):
                    for dx in range(S):
                        img[PAD + y * S + dy][x0 + x * S + dx] = c
        x0 += n * S + PAD
    raw = b"".join(b"\0" + bytes(sum(row, ())) for row in img)
    ch = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    open(preview, "wb").write(b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                              + ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b""))
