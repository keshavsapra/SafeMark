#!/usr/bin/env python3
"""Generate Safemark's shield+bookmark icons at 16/32/48/128 px."""
from PIL import Image, ImageDraw, ImageFilter
import os

S = 8  # supersample scale (bezier math runs at base size 1.0 * base)
BASE = 128 * S

def quad(p0, p1, p2, t):
    x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t ** 2 * p2[0]
    y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t ** 2 * p2[1]
    return (x, y)

def shield_points():
    """Shield outline with rounded top corners, tapering to a bottom point."""
    pts = []
    r = 0.055
    pca, pcb = (0.10, 0.115), (0.90, 0.115)
    a, b = (0.855, 0.115 + r), (0.145, 0.115 + r)
    # bottom tip
    tip = (0.5, 0.94)

    # top edge: left corner -> right corner
    pts += [quad((0.145, 0.115), (0.10, 0.115), (0.145, 0.115 + r), t / 8) for t in range(9)]
    edge_top = [((0.145 + r) + (0.855 - r) * i / 16, 0.115) for i in range(17)]
    pts += edge_top
    pts += [quad((0.855, 0.115), (0.90, 0.115), (0.855, 0.115 + r), t / 8) for t in range(9)]
    # right side down, then curve to tip
    pts += [(0.855, y) for y in [0.115 + r + i * (0.52 - 0.115 - r) / 10 for i in range(11)]]
    pts += [quad((0.855, 0.52), (0.83, 0.78), tip, t / 14) for t in range(15)]
    # mirror on the left
    pts += [quad(tip, (0.17, 0.78), (0.145, 0.52), t / 14) for t in range(15)]
    pts += [(0.145, y) for y in sorted([0.115 + r + i * (0.52 - 0.115 - r) / 10 for i in range(11)], reverse=True)]
    pts += [quad((0.145, 0.52 + r), (0.145, 0.115), (0.145 + r, 0.115), t / 8) for t in range(9)]
    return [(x * BASE, y * BASE) for x, y in pts]

def ribbon_points():
    """Classic bookmark ribbon: rounded top, V notch cut into the bottom."""
    x0, x1 = 0.355, 0.645
    y0, yn, yt = 0.275, 0.735, 0.625
    r = 0.022
    return [
        ((x0 + r) * BASE, y0 * BASE),
        ((x1 - r) * BASE, y0 * BASE),
        (x1 * BASE, (y0 + r) * BASE),
        (x1 * BASE, yn * BASE),
        ((x0 + x1) / 2 * BASE, yt * BASE),
        (x0 * BASE, yn * BASE),
        (x0 * BASE, (y0 + r) * BASE),
    ]

BASESIZE = 128
canvas = Image.new("RGBA", (BASESIZE * S, BASESIZE * S), (0, 0, 0, 0))
mask = Image.new("L", (BASESIZE * S, BASESIZE * S), 0)
ImageDraw.Draw(mask).polygon(shield_points(), fill=255)

# vertical gradient fill: indigo-blue -> deep violet-blue
grad = Image.new("L", (1, BASESIZE * S))
for y in range(BASESIZE * S):
    t = y / (BASESIZE * S - 1)
    val = int(150 - 40 * t)  # row brightness driver unused; real color below
    grad.putpixel((0, y), 255)
grad = grad.resize((BASESIZE * S, BASESIZE * S))

top, bottom = (0x6D, 0x7C, 0xFF), (0x40, 0x38, 0xD8)
fill = Image.new("RGBA", canvas.size)
for y in range(canvas.height):
    t = y / (canvas.height - 1)
    c = tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3)) + (255,)
    ImageDraw.Draw(fill).line([(0, y), (canvas.width, y)], fill=c)
canvas.paste(fill, (0, 0), Image.composite(fill, Image.new("RGBA", canvas.size, (0,0,0,0)), mask).split()[3])

# subtle drop shadow + edge stroke for depth
shadow = Image.new("L", canvas.size, 0)
ImageDraw.Draw(shadow).polygon(shield_points(), fill=90)
shadow = shadow.filter(ImageFilter.GaussianBlur(4 * S / 8))
sh = Image.new("RGBA", canvas.size, (20, 20, 60, 0))
sh.putalpha(shadow)
canvas = Image.alpha_composite(sh, canvas)

draw = ImageDraw.Draw(canvas)
draw.polygon(shield_points(), outline=(255, 255, 255, 70), width=int(2.4 * S / 8))
# white bookmark ribbon, tiny drop edge
draw.polygon(ribbon_points(), fill=(255, 255, 255, 255), outline=(230, 232, 255, 255), width=int(1.5 * S / 8))

os.makedirs("icons", exist_ok=True)
for size in (16, 32, 48, 128):
    canvas.resize((size, size), Image.LANCZOS).save(f"icons/icon{size}.png")

print("icons written:", os.listdir("icons"))
