#!/usr/bin/env python3
"""pixicons.py OUT.r [preview.png] - MacNetScan 2's Finder icon family drawn pixel by pixel, the way icons were made in
1995 (ResEdit's fat bits), not scaled down from a picture: a platinum compact Mac with a black outline whose screen
shows the radar of the tool bar's logo (green rings, the beam, two blips), on a network cable with two more machines.
Writes ICN#, icl8, icl4 (32 px), ics#, ics8, ics4 (16 px), id 128, the bundle (BNDL, FREF, owner resource 'IPSc') and
'vers' - the same resources tools/mkicons.py wrote from the PNG, which this replaces. Every colour is an entry of the
Mac's standard 8-bit table (cube or grey ramp); the 4-bit and 1-bit icons take the nearest entry / dark-or-light.
  Rez -a OUT.r -o "Project Resources.rsrc", build, then: SetFile -a B MacNetScan  (the Finder reads the BNDL) """
import sys, struct, zlib

out = sys.argv[1]
preview = sys.argv[2] if len(sys.argv) > 2 else None

K = (0x00, 0x00, 0x00)      # outline, screen
W = (0xFF, 0xFF, 0xFF)      # light edge
P = (0xDD, 0xDD, 0xDD)      # platinum
S = (0xAA, 0xAA, 0xAA)      # shade
D = (0x77, 0x77, 0x77)      # dark shade
RING = (0x00, 0x66, 0x00)
BEAM = (0x33, 0xFF, 0x33)
TRAIL = (0x00, 0x99, 0x00)
BLIP = (0xCC, 0xFF, 0xCC)
LED = (0x33, 0xCC, 0x33)


class Canvas:
    def __init__(self, n):
        self.n = n
        self.px = [[None] * n for _ in range(n)]

    def set(self, x, y, c):
        if 0 <= x < self.n and 0 <= y < self.n:
            self.px[y][x] = c

    def rect(self, l, t, r, b, c):                       # inclusive
        for y in range(t, b + 1):
            for x in range(l, r + 1):
                self.set(x, y, c)

    def frame(self, l, t, r, b, c):
        for x in range(l, r + 1):
            self.set(x, t, c); self.set(x, b, c)
        for y in range(t, b + 1):
            self.set(l, y, c); self.set(r, y, c)

    def line(self, x0, y0, x1, y1, c):                   # Bresenham
        dx, dy = abs(x1 - x0), -abs(y1 - y0)
        sx, sy = (1 if x0 < x1 else -1), (1 if y0 < y1 else -1)
        e = dx + dy
        while True:
            self.set(x0, y0, c)
            if x0 == x1 and y0 == y1:
                return
            e2 = 2 * e
            if e2 >= dy:
                e += dy; x0 += sx
            if e2 <= dx:
                e += dx; y0 += sy

    def bevel_box(self, l, t, r, b, face=P):             # a platinum box: black outline, light top left, shade
        self.rect(l, t, r, b, face)
        self.frame(l, t, r, b, K)
        for x in range(l + 1, r):
            self.set(x, t + 1, W); self.set(x, b - 1, S)
        for y in range(t + 1, b):
            self.set(l + 1, y, W); self.set(r - 1, y, S)


def compact_mac(c, l, t, w, h, scr, scope):
    """A compact Mac: body l..l+w-1, t..t+h-1 (the foot included); scr = (l, t, r, b) of the screen, relative."""
    r, b = l + w - 1, t + h - 1
    c.bevel_box(l, t, r, b - 2)
    c.rect(l + 1, b - 1, r - 1, b, P)                    # the foot, a little narrower
    c.frame(l + 1, b - 2, r - 1, b, K)
    for x in range(l + 2, r - 1):
        c.set(x, b - 1, S)
    sl, st, sr, sb = l + scr[0], t + scr[1], l + scr[2], t + scr[3]
    c.frame(sl - 1, st - 1, sr + 1, sb + 1, D)           # the bezel, sunk
    for x in range(sl - 1, sr + 2):
        c.set(x, sb + 1, W)
    for y in range(st - 1, sb + 2):
        c.set(sr + 1, y, W)
    c.rect(sl, st, sr, sb, K)
    scope(c, sl, st, sr, sb)


def scope32(c, l, t, r, b):                              # 12 x 10: a ring, the beam to 1 o'clock, three blips
    cx, cy = (l + r) // 2, (t + b) // 2 + 1
    for x, y in [(-1, -4), (0, -4), (1, -4), (-3, -3), (-2, -3), (2, -3), (3, -3), (-3, -2), (3, -2), (-4, -1), (4, -1),
                 (-4, 0), (4, 0), (-4, 1), (4, 1), (-3, 2), (3, 2), (-3, 3), (-2, 3), (2, 3), (3, 3), (-1, 4), (0, 4),
                 (1, 4)]:
        c.set(cx + x, cy + y, RING)
    c.set(cx, cy, RING)
    c.line(cx, cy, cx + 3, cy - 1, TRAIL)                # the afterglow, then the beam
    c.line(cx, cy, cx + 2, cy - 3, BEAM)
    c.set(cx + 1, cy - 1, BLIP)                          # a blip the beam just passed, two still dim
    c.set(cx - 2, cy + 1, TRAIL)
    c.set(cx + 1, cy + 2, TRAIL)


def scope16(c, l, t, r, b):                              # 6 x 5: one ring, the beam
    cx, cy = (l + r) // 2, (t + b) // 2
    for x, y in [(-1, -2), (0, -2), (1, -2), (-2, -1), (2, -1), (-2, 0), (2, 0), (-2, 1), (2, 1), (-1, 2), (0, 2),
                 (1, 2)]:
        c.set(cx + x, cy + y, RING)
    c.set(cx, cy, BEAM); c.set(cx + 1, cy - 1, BEAM)
    c.set(cx - 1, cy + 1, BLIP)


def tiny_box(c, l, t):                                   # a 7 x 7 machine on the cable: a monitor with a lit screen
    c.bevel_box(l, t, l + 6, t + 5)
    c.rect(l + 2, t + 2, l + 4, t + 3, K)
    c.set(l + 3, t + 2, LED)
    c.rect(l + 2, t + 6, l + 4, t + 6, K)                # its foot


big = Canvas(32)
compact_mac(big, 1, 1, 20, 26, (4, 3, 15, 12), scope32)
big.rect(5, 18, 11, 18, K)                               # the floppy slot
big.set(5, 22, LED)                                      # the power light
big.rect(10, 27, 12, 29, K)                              # the cable leaves the Mac below...
big.line(11, 30, 30, 30, K)                              # ...and runs along the bottom: the network
big.line(11, 29, 11, 30, K)
for x0, y0 in [(23, 5), (23, 16)]:                       # two more machines, tapped onto the cable at x 26
    tiny_box(big, x0, y0)
big.line(26, 12, 26, 15, K)
big.line(26, 23, 26, 30, K)
big.line(22, 30, 22, 30, K)

small = Canvas(16)
compact_mac(small, 2, 0, 12, 16, (2, 2, 7, 6), scope16)
small.rect(5, 10, 8, 10, K)                              # the floppy slot


def mask(cv):                                            # every pixel set, and the holes a flood fill cannot reach
    n = cv.n
    outside = [[False] * n for _ in range(n)]
    stack = [(x, y) for x in range(n) for y in (0, n - 1)] + [(x, y) for y in range(n) for x in (0, n - 1)]
    while stack:
        x, y = stack.pop()
        if 0 <= x < n and 0 <= y < n and not outside[y][x] and cv.px[y][x] is None:
            outside[y][x] = True
            stack += [(x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)]
    return [[not outside[y][x] for x in range(n)] for y in range(n)]


def clut8():
    t = []
    for r in range(6):
        for g in range(6):
            for b in range(6):
                t.append((0xFF - 0x33 * r, 0xFF - 0x33 * g, 0xFF - 0x33 * b))
    t = t[:215]
    ramp = [0xEE, 0xDD, 0xBB, 0xAA, 0x88, 0x77, 0x55, 0x44, 0x22, 0x11]
    t += [(v, 0, 0) for v in ramp] + [(0, v, 0) for v in ramp] + [(0, 0, v) for v in ramp] + [(v, v, v) for v in ramp]
    t.append((0, 0, 0))
    return t


CLUT8 = clut8()
CLUT4 = [(0xFF, 0xFF, 0xFF), (0xFC, 0xF3, 0x05), (0xFF, 0x64, 0x02), (0xDD, 0x08, 0x06), (0xF2, 0x08, 0x84),
         (0x46, 0x00, 0xA5), (0x00, 0x00, 0xD4), (0x02, 0xAB, 0xEA), (0x1F, 0xB7, 0x14), (0x00, 0x64, 0x11),
         (0x56, 0x2C, 0x05), (0x90, 0x71, 0x3A), (0xC0, 0xC0, 0xC0), (0x80, 0x80, 0x80), (0x40, 0x40, 0x40),
         (0x00, 0x00, 0x00)]


def nearest(table, c):
    return min(range(len(table)), key=lambda i: sum((table[i][k] - c[k]) ** 2 for k in range(3)))


def colour(cv, m, x, y):
    c = cv.px[y][x]
    return c if c is not None else (W if m[y][x] else None)   # a hole inside the outline is white


def planes(cv, m):
    icon, msk = bytearray(), bytearray()
    for y in range(cv.n):
        for x0 in range(0, cv.n, 8):
            bi = bm = 0
            for x in range(x0, x0 + 8):
                c = colour(cv, m, x, y)
                dark = c is not None and (c[0] * 30 + c[1] * 59 + c[2] * 11) / 100 < 128
                bi = bi << 1 | (1 if dark else 0)
                bm = bm << 1 | (1 if m[y][x] else 0)
            icon.append(bi)
            msk.append(bm)
    return bytes(icon + msk)


def deep(cv, m, table, per):
    o = bytearray()
    for y in range(cv.n):
        v = [nearest(table, colour(cv, m, x, y)) if m[y][x] else 0 for x in range(cv.n)]
        o += bytes(v) if per == 8 else bytes(v[i] << 4 | v[i + 1] for i in range(0, len(v), 2))
    return bytes(o)


def hexdata(b, width=32):
    return "\n".join('\t$"' + b[i:i + width].hex().upper() + '"' for i in range(0, len(b), width))


for cv in (big, small):                                  # every colour must be a CLUT entry, exactly
    for row in cv.px:
        for c in row:
            assert c is None or c in CLUT8, c

mb, ms = mask(big), mask(small)
parts = [("ICN#", planes(big, mb)), ("icl8", deep(big, mb, CLUT8, 8)), ("icl4", deep(big, mb, CLUT4, 4)),
         ("ics#", planes(small, ms)), ("ics8", deep(small, ms, CLUT8, 8)), ("ics4", deep(small, ms, CLUT4, 4))]
r = ["/* Icons.r - MacNetScan 2's Finder bundle, icons and version; written by tools/pixicons.py (icons drawn pixel",
     "   by pixel), do not edit by hand. Rez -a Icons.r -o \"Project Resources.rsrc\";",
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

if preview:                                              # fat bits: 8-bit, 1-bit and 16 px, on the desktop grey
    Z, PAD = 8, 8
    bg = (0x99, 0x99, 0x99)
    tiles = [(big, mb, False), (big, mb, True), (small, ms, False), (small, ms, True)]
    w = PAD + sum(cv.n * Z + PAD for cv, _, _ in tiles)
    h = 32 * Z + 2 * PAD
    img = [[bg] * w for _ in range(h)]
    x0 = PAD
    for cv, m, bw in tiles:
        for y in range(cv.n):
            for x in range(cv.n):
                if not m[y][x]:
                    continue
                c = colour(cv, m, x, y)
                if bw:
                    c = K if (c[0] * 30 + c[1] * 59 + c[2] * 11) / 100 < 128 else W
                for dy in range(Z):
                    for dx in range(Z):
                        img[PAD + y * Z + dy][x0 + x * Z + dx] = c
        x0 += cv.n * Z + PAD
    raw = b"".join(b"\0" + bytes(sum(row, ())) for row in img)
    ch = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    open(preview, "wb").write(b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                              + ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b""))
