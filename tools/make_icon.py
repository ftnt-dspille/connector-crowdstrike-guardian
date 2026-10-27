#!/usr/bin/env python3
"""Generate the connector icons (small 150x150, large 500x500).

    python3 tools/make_icon.py

Draws a shield-and-circuit glyph on a dark gradient: Guardian guards AI
agents. Pure Pillow, no external assets, so the repo carries no trademarked
logo. Re-run any time; the output is committed.
"""

import os

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, "..", "crowdstrike_guardian", "images")

TOP = (26, 34, 56)  # deep navy
BOTTOM = (15, 76, 92)  # teal edge
ACCENT = (252, 61, 49)  # CrowdStrike red
BODY = (235, 240, 248)


def _background(size):
    image = Image.new("RGB", (size, size))
    draw = ImageDraw.Draw(image)
    for y in range(size):
        t = y / max(size - 1, 1)
        color = tuple(int(TOP[i] + (BOTTOM[i] - TOP[i]) * t) for i in range(3))
        draw.line([(0, y), (size, y)], fill=color)
    return image


def _shield(draw, size):
    """A shield outline centered in the canvas."""
    width, height = size, size
    cx = width / 2
    top = height * 0.16
    bottom = height * 0.86
    half = width * 0.27
    notch = height * 0.60
    points = [
        (cx - half, top),
        (cx + half, top),
        (cx + half, notch),
        (cx, bottom),
        (cx - half, notch),
    ]
    return points


def draw_icon(size):
    image = _background(size)
    draw = ImageDraw.Draw(image)

    # shield body
    points = _shield(draw, size)
    draw.polygon(points, fill=(20, 28, 48))

    # inner circuit nodes: an agent (top), tools (bottom row), edges
    cx = size / 2
    nodes = [
        (cx, size * 0.30, size * 0.055),  # the AI agent
        (cx - size * 0.16, size * 0.52, size * 0.042),  # tool
        (cx + size * 0.16, size * 0.52, size * 0.042),  # tool
        (cx, size * 0.64, size * 0.042),  # execution
    ]
    edges = [(0, 1), (0, 2), (1, 3), (2, 3)]
    line_width = max(int(size * 0.018), 2)
    for a, b in edges:
        x1, y1, _ = nodes[a]
        x2, y2, _ = nodes[b]
        draw.line([(x1, y1), (x2, y2)], fill=BODY, width=line_width)
    for i, (x, y, r) in enumerate(nodes):
        fill = ACCENT if i == 0 else BODY
        draw.ellipse([x - r, y - r, x + r, y + r], fill=fill)

    # a subtle scan arc over the top edge of the shield
    radius = size * 0.34
    box = [cx - radius, size * 0.30 - radius, cx + radius, size * 0.30 + radius]
    draw.arc(box, start=200, end=340, fill=(120, 200, 220), width=max(int(size * 0.012), 1))

    return image


def main():
    os.makedirs(TARGET, exist_ok=True)
    for name, size in (("small_icon.png", 150), ("large_icon.png", 500)):
        path = os.path.join(TARGET, name)
        draw_icon(size).save(path)
        print(f"wrote {path} ({size}x{size})")


if __name__ == "__main__":
    main()
