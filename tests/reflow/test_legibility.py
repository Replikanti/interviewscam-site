"""text_pixels and legibility_problem in tools/sitecheck.py, the measure of
reflow case (7)'s legibility step (Replikanti/interviewscam#34, ADR-0003
part 6 amendment).

Why it exists: the paint check of case (7) proves that the revealed skip
link draws something, not that its label can be read. The legibility step
captures the link's box as shown and again with only its glyph fill made
transparent; the pixels that differ are the text, and enough of them must
reach 4.5:1 (WCAG 2.2 SC 1.4.3) against the pixel under them.

Run by `bash tools/selftest.sh` (suite `reflow-isolation`, which discovers
tests/reflow) as python3 -I -B -m unittest, locally and in CI, without a
browser: every case builds synthetic PNGs and calls the module's pure
functions through importlib. The browser rows of reflow-search and the
reflow fixtures pin what Chrome really draws; these cases pin the bounds.
"""

import base64
import importlib.util
import re
import struct
import sys
import unittest
import zlib
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sitecheck = load("sitecheck", ROOT / "tools" / "sitecheck.py")

WHITE = (255, 255, 255)


def encode(rows, width, channels=3):
    """A base64 8-bit PNG of decoded rows, RGB (3 channels) or RGBA (4)."""
    raw = b"".join(b"\x00" + bytes(row) for row in rows)

    def chunk(kind, body):
        return (struct.pack(">I", len(body)) + kind + body
                + struct.pack(">I", zlib.crc32(kind + body)))

    data = (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, len(rows), 8,
                                         2 if channels == 3 else 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
    return base64.b64encode(data).decode()


def image(pixels, width, channels=3, alpha=255):
    """A base64 PNG of a row-major list of (r, g, b) pixels."""
    rows = []
    for y in range(len(pixels) // width):
        row = bytearray()
        for r, g, b in pixels[y * width:(y + 1) * width]:
            row += bytes((r, g, b) + ((alpha,) if channels == 4 else ()))
        rows.append(row)
    return encode(rows, width, channels)


def flat(colour, width=8, height=4, channels=3, marks=()):
    """A base64 PNG of one colour, with marks {index: colour} on it."""
    pixels = [colour] * (width * height)
    for index, mark in dict(marks).items():
        pixels[index] = mark
    return image(pixels, width, channels)


def ratio(a, b):
    """WCAG 2.2 contrast of two 8-bit greys, an own copy of the formula, so
    the bounds below do not come from the module under test."""
    def lum(v):
        c = v / 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    hi, lo = sorted((lum(a), lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


class Measure(unittest.TestCase):
    def test_grey_118_counts_119_does_not(self):
        # The bound is inclusive at 8-bit resolution: 118 on white is
        # 4.5422:1, 119 is 4.4781:1. No pair of 8-bit greys is exactly 4.5.
        self.assertGreaterEqual(ratio(118, 255), 4.5)
        self.assertLess(ratio(119, 255), 4.5)
        blank = flat(WHITE)
        self.assertEqual(sitecheck.text_pixels(flat(WHITE, marks={3: (118,) * 3}), blank),
                         (1, 1))
        self.assertEqual(sitecheck.text_pixels(flat(WHITE, marks={3: (119,) * 3}), blank),
                         (0, 1))

    def test_contrast_is_symmetric(self):
        # Light text on a dark ground counts as dark text on a light one.
        self.assertEqual(sitecheck.text_pixels(flat((0, 0, 0), marks={0: (255,) * 3}),
                                               flat((0, 0, 0))), (1, 1))
        self.assertEqual(sitecheck.text_pixels(flat(WHITE, marks={0: (0,) * 3}),
                                               flat(WHITE)), (1, 1))

    def test_counts_every_legible_pixel(self):
        marks = {i: (0x23, 0x50, 0xC8) for i in (0, 5, 9, 31)}
        marks[12] = (200, 200, 200)  # paints, 1.6:1: not legible
        self.assertEqual(sitecheck.text_pixels(flat(WHITE, marks=marks), flat(WHITE)), (4, 5))

    def test_noise_never_counts(self):
        # Raster noise: 1 level is at most 1.016:1 and 8 levels at most
        # 1.135:1 at the worst grey, far below 4.5:1, and neither paints.
        for delta in (1, 8):
            worst = max(ratio(v, v + delta) for v in range(256 - delta))
            self.assertLess(worst, 1.14)
            for v in range(256 - delta):
                with self.subTest(delta=delta, grey=v):
                    self.assertEqual(sitecheck.text_pixels(flat((v + delta,) * 3),
                                                           flat((v,) * 3)), (0, 0))
        self.assertEqual(sitecheck.text_pixels(flat((9,) * 3), flat((0,) * 3)), (0, 32))

    def test_identical_captures_have_no_text(self):
        shot = flat((0x23, 0x50, 0xC8), marks={2: WHITE})
        self.assertEqual(sitecheck.text_pixels(shot, shot), (0, 0))

    def test_size_mismatch_is_none(self):
        self.assertIsNone(sitecheck.text_pixels(flat(WHITE, width=8), flat(WHITE, width=9)))
        self.assertIsNone(sitecheck.text_pixels(flat(WHITE, height=4), flat(WHITE, height=5)))

    def test_transparent_pixel_is_none(self):
        opaque = flat(WHITE, channels=4)
        for alpha in (0, 254):
            with self.subTest(alpha=alpha):
                rows = [bytearray(bytes(WHITE + (255,)) * 8) for _ in range(4)]
                rows[1][7] = alpha
                seethrough = encode(rows, 8, channels=4)
                self.assertIsNone(sitecheck.text_pixels(seethrough, opaque))
                self.assertIsNone(sitecheck.text_pixels(opaque, seethrough))
        self.assertEqual(sitecheck.text_pixels(opaque, opaque), (0, 0))

    def test_rgb_and_rgba_agree(self):
        marks = {1: (0, 0, 0), 6: (118, 118, 118), 7: (119, 119, 119)}
        rgb = sitecheck.text_pixels(flat(WHITE, marks=marks), flat(WHITE))
        rgba = sitecheck.text_pixels(flat(WHITE, channels=4, marks=marks),
                                     flat(WHITE, channels=4))
        self.assertEqual(rgb, (2, 3))
        self.assertEqual(rgba, rgb)

    def test_every_channel_is_read(self):
        # Fix round 1 (QA): non-grey pixels, so a decode that reads one
        # channel from the wrong offset changes the result. Yellow on white
        # differs only in blue: it paints (255 levels) and stays far below
        # 4.5:1 (1.07:1); blue on white reaches 8.59:1.
        for channels in (3, 4):
            with self.subTest(channels=channels):
                shot = flat(WHITE, channels=channels, marks={2: (255, 255, 0), 5: (0, 0, 255)})
                self.assertEqual(sitecheck.text_pixels(shot, flat(WHITE, channels=channels)),
                                 (1, 2))
                width, _, got, rows = sitecheck.png_rows(base64.b64decode(
                    image([(10, 20, 30), (40, 50, 60)], 2, channels)))
                self.assertEqual(got, channels)
                self.assertEqual(sitecheck.rgb_pixels(rows, channels),
                                 [(10, 20, 30), (40, 50, 60)])

    def test_not_png_is_usage_error(self):
        junk = base64.b64encode(b"GIF89a not a png").decode()
        with self.assertRaises(sitecheck.UsageError):
            sitecheck.text_pixels(junk, flat(WHITE))

    def test_luminance_table_is_the_wcag_formula(self):
        self.assertEqual(len(sitecheck.SRGB_LINEAR), 256)
        for v in range(256):
            c = v / 255
            want = c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
            self.assertEqual(sitecheck.SRGB_LINEAR[v], want)
        self.assertEqual(sitecheck.srgb_luminance("#2350C8"),
                         sitecheck.rgb_luminance(0x23, 0x50, 0xC8))


class Verdict(unittest.TestCase):
    LABEL, BOX = "'a.visually-hidden'", "120.0 x 40.0 CSS px"

    def test_count_at_threshold_passes(self):
        with mock.patch.object(sitecheck, "REFLOW_TEXT_MIN_PIXELS", 7):
            self.assertIsNone(sitecheck.legibility_problem(self.LABEL, self.BOX, (7, 9)))

    def test_count_below_threshold_fails(self):
        with mock.patch.object(sitecheck, "REFLOW_TEXT_MIN_PIXELS", 7):
            problem = sitecheck.legibility_problem(self.LABEL, self.BOX, (6, 9))
        self.assertIn("6 of its 9 text pixel(s) reach 4.5:1", problem)
        self.assertIn("7 needed (WCAG 2.2 SC 1.4.3)", problem)

    def test_no_ink_fails(self):
        problem = sitecheck.legibility_problem(self.LABEL, self.BOX, (0, 0))
        self.assertIn("0 of its 0 text pixel(s)", problem)

    def test_unmeasurable_captures_fail(self):
        problem = sitecheck.legibility_problem(self.LABEL, self.BOX, None)
        self.assertIn("differ in size or hold a transparent pixel", problem)


class Summary(unittest.TestCase):
    def test_range_is_smallest_to_largest(self):
        # Fix round 1 (QA): every real page counts the same, so only this
        # case tells the two ends of the range apart.
        with mock.patch.object(sitecheck, "REFLOW_TEXT_MIN_PIXELS", 343):
            self.assertEqual(sitecheck.legibility_summary(3, 2, [700, 400, 512]),
                             "skip-link reveals: 3, legible 2 (text pixels at 4.5:1 or more: "
                             "400 to 700, at least 343)")

    def test_no_count_ends_after_legible(self):
        self.assertEqual(sitecheck.legibility_summary(0, 0, []),
                         "skip-link reveals: 0, legible 0")


class Constants(unittest.TestCase):
    def test_constants_match_adr(self):
        adr = (ROOT / "docs" / "adr" / "0003-browser-checks.md").read_text(encoding="utf-8")
        cells = [line.split("|")[1] for line in adr.splitlines() if line.startswith("| ")]
        for name, text in (("REFLOW_TEXT_MIN_PIXELS", str(sitecheck.REFLOW_TEXT_MIN_PIXELS)),
                           ("REFLOW_TEXT_CONTRAST", f"{sitecheck.REFLOW_TEXT_CONTRAST:g}")):
            with self.subTest(name=name):
                rows = [cell for cell in cells if f"`{name}`" in cell]
                self.assertEqual(len(rows), 1, f"{name}: {len(rows)} Numbers rows name it")
                self.assertRegex(rows[0], rf"(?<![\d.,]){re.escape(text)}(?![\d,]|\.\d)")
        self.assertEqual(sitecheck.REFLOW_TEXT_CONTRAST, 4.5)


if __name__ == "__main__":
    unittest.main()
