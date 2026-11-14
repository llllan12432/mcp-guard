"""Regenerate the demo assets in submission/ from a real run of the demo.

    python submission/make_assets.py        # needs Pillow (pip install pillow); not a project dependency

It runs `demo/run_demo.py` once, records every output line with its timestamp, and writes:

    demo-output.txt   the captured output, unedited
    demo-output.png   the same text drawn as an image (all four scenarios + summary)
    demo.gif          the same text replayed line by line
    demo.cast         asciinema v2 recording with the real timings (asciinema play demo.cast)

The images are drawn from the captured text with Pillow. They are not screen captures of
a terminal window; the wording and order are exactly what the script printed. Long lines
are wrapped, and the GIF shortens long waits.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
# The demo runs with the project's virtualenv; this script itself only needs Pillow.
DEMO_PYTHON = ROOT / ".venv" / "bin" / "python" if (ROOT / ".venv" / "bin" / "python").exists() else Path(sys.executable)
FONT_PATH = "/System/Library/Fonts/Menlo.ttc"  # macOS; change for other systems
FONT_SIZE, LINE_HEIGHT, PAD, COLUMNS = 15, 21, 18, 112
BACKGROUND, PLAIN = (18, 20, 26), (208, 212, 220)
COLOURS = [  # first match wins
    ("=== ", (255, 255, 255)),
    ("ATTACK SUCCEEDED", (255, 107, 107)),
    ("attack stopped", (105, 219, 124)),
    ("guard:", (255, 212, 59)),
    ("(!)", (255, 169, 77)),
    ("outbox:", (255, 107, 107)),
    ("$ ", (116, 192, 252)),
]


def capture() -> list[tuple[float, str]]:
    """Run the demo and return (seconds since start, line) for every output line."""
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    process = subprocess.Popen(
        [str(DEMO_PYTHON), str(ROOT / "demo" / "run_demo.py")],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=ROOT, env=env,
    )
    start, lines = time.monotonic(), []
    for line in process.stdout:
        lines.append((time.monotonic() - start, line.rstrip("\n")))
    if process.wait() != 0:
        raise SystemExit("demo failed:\n" + "\n".join(text for _, text in lines))
    return lines


def wrap(line: str) -> list[str]:
    return textwrap.wrap(line, COLUMNS, subsequent_indent="          ", break_long_words=True) or [""]


def colour_of(line: str) -> tuple[int, int, int]:
    return next((colour for marker, colour in COLOURS if marker in line), PLAIN)


def draw(rows: list[tuple[str, tuple[int, int, int]]], width: int, height: int, font) -> Image.Image:
    image = Image.new("RGB", (width, height), BACKGROUND)
    pen = ImageDraw.Draw(image)
    for index, (text, colour) in enumerate(rows):
        pen.text((PAD, PAD + index * LINE_HEIGHT), text, font=font, fill=colour)
    return image


def main() -> None:
    lines = capture()
    command = "$ python demo/run_demo.py"
    (HERE / "demo-output.txt").write_text(command + "\n" + "\n".join(text for _, text in lines) + "\n", encoding="utf-8")

    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    width = int(font.getlength("M") * COLUMNS) + 2 * PAD

    # Each output line becomes one or more rows (wrapped), all with the colour of the whole line.
    rows_per_line = [[(command, colour_of(command))]] + [[(row, colour_of(text)) for row in wrap(text)] for _, text in lines]
    all_rows = [row for rows in rows_per_line for row in rows]

    # 1. Still image with everything.
    draw(all_rows, width, 2 * PAD + len(all_rows) * LINE_HEIGHT, font).save(HERE / "demo-output.png", optimize=True)

    # 2. GIF: reveal line by line in a fixed-height window that scrolls.
    visible = 30
    height = 2 * PAD + visible * LINE_HEIGHT
    times = [0.0] + [t for t, _ in lines]
    frames, durations, shown = [], [], []
    for index, rows in enumerate(rows_per_line):
        shown += rows
        frames.append(draw(shown[-visible:], width, height, font).quantize(colors=32))
        gap = (times[index + 1] - times[index]) if index + 1 < len(times) else 0
        text = rows[0][0]
        pause = 2.2 if "result:" in text else 0.9 if text.startswith("===") else 0.35
        durations.append(int(1000 * min(max(gap, pause), 2.5)))
    durations[-1] = 6000
    frames[0].save(HERE / "demo.gif", save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True)

    # 3. asciinema v2 cast with the real timings.
    with (HERE / "demo.cast").open("w", encoding="utf-8") as cast:
        cast.write(json.dumps({"version": 2, "width": 200, "height": 50, "title": "MCP Guard demo"}) + "\n")
        cast.write(json.dumps([0.0, "o", command + "\r\n"]) + "\n")
        for seconds, text in lines:
            cast.write(json.dumps([round(seconds + 0.5, 3), "o", text + "\r\n"], ensure_ascii=False) + "\n")

    print(f"wrote demo-output.txt/.png, demo.gif ({len(frames)} frames), demo.cast to {HERE}")


if __name__ == "__main__":
    main()
