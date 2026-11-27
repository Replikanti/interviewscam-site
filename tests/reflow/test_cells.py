"""The cells of reflow case (7) in tools/sitecheck.py (Replikanti/interviewscam#61,
ADR-0003 part 6 amendment): reveal_widths, cell_state_problem,
reveal_cells_summary and the cell constants.

Why it exists: case (7) runs the skip-link case at one width per band of
the built stylesheet's breakpoints (SITE_MEDIA_PRELUDES, the closed list of
site rule (a)) with the script running and with scripting off. The widths
are derived from the preludes, never hand-written, and a cell is measured
only after the browser proves its media state. These cases pin the
derivation's arithmetic, its refusals, the proof and the summary text.

Run by `bash tools/selftest.sh` (suite `reflow-isolation`, which discovers
tests/reflow) as python3 -I -B -m unittest, locally and in CI, without a
browser: every case calls the module's pure functions through importlib.
The reflow-cells rows pin what Chrome really does in each cell.
"""

import importlib.util
import re
import sys
import unittest
from decimal import Decimal
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
PRELUDES = ("@media(max-width:24rem)", "@media(max-width:21.25rem)")


class Derivation(unittest.TestCase):
    def test_breakpoints_from_preludes(self):
        breakpoints, _ = sitecheck.reveal_widths(PRELUDES, 320, 16)
        self.assertEqual(breakpoints, (Decimal(384), Decimal(340)))
        self.assertEqual(sitecheck.SITE_MEDIA_PRELUDES, PRELUDES)
        self.assertEqual(sitecheck.REFLOW_REVEAL_BREAKPOINTS, (384, 340))

    def test_cell_widths_one_per_band(self):
        _, widths = sitecheck.reveal_widths(PRELUDES, 320, 16)
        self.assertEqual(widths, (320, 341, 385))
        self.assertEqual(sitecheck.REFLOW_REVEAL_WIDTHS, (320, 341, 385))
        # max-width is inclusive: 340 is still in the band at or below
        # 21.25rem, 341 the first whole width above it, 384 still at or
        # below 24rem, 385 above both.
        for width, band in ((320, (True, True)), (340, (True, True)), (341, (True, False)),
                            (384, (True, False)), (385, (False, False))):
            with self.subTest(width=width):
                self.assertEqual(tuple(width <= bp for bp in (384, 340)), band)

    def test_fractional_breakpoint_rounds_up(self):
        breakpoints, widths = sitecheck.reveal_widths(("@media(max-width:21.3rem)",), 320, 16)
        self.assertEqual(breakpoints, (Decimal("340.8"),))
        self.assertEqual(widths, (320, 341))
        _, widths = sitecheck.reveal_widths(("@media(max-width:21.25rem)",), 320, 16)
        self.assertEqual(widths, (320, 341))

    def test_prelude_outside_grammar_refused(self):
        for prelude in ("@media(min-width:24rem)", "@media(prefers-color-scheme:dark)",
                        "@media (max-width:24rem)", "@media(max-width:384px)",
                        "@media(max-width:24rem)\n"):
            with self.subTest(prelude=prelude), self.assertRaises(ValueError):
                sitecheck.reveal_widths((prelude,), 320, 16)

    def test_breakpoint_below_reflow_width_refused(self):
        with self.assertRaises(ValueError):
            sitecheck.reveal_widths(("@media(max-width:19rem)",), 320, 16)
        # At the base width itself the band below holds the base cell.
        self.assertEqual(sitecheck.reveal_widths(("@media(max-width:20rem)",), 320, 16)[1],
                         (320, 321))

    def test_duplicate_breakpoints_one_width(self):
        _, widths = sitecheck.reveal_widths(
            ("@media(max-width:24rem)", "@media(max-width:24.0rem)"), 320, 16)
        self.assertEqual(widths, (320, 385))

    def test_cells_order_and_count(self):
        self.assertEqual(sitecheck.REFLOW_REVEAL_STATES, (0, 2))
        self.assertEqual(sitecheck.REFLOW_REVEAL_CELLS,
                         ((320, 0), (320, 2), (341, 0), (341, 2), (385, 0), (385, 2)))
        self.assertEqual(sitecheck.REFLOW_REVEAL_CELLS[0],
                         (sitecheck.REFLOW_WIDTH, 0))
        self.assertEqual([sitecheck.REFLOW_STATES[s] for s in sitecheck.REFLOW_REVEAL_STATES],
                         ["with the script running", "with scripting off"])

    def test_cell_script_queries_the_preludes(self):
        self.assertIn('["(max-width:24rem)", "(max-width:21.25rem)"]',
                      sitecheck.REFLOW_CELL_SCRIPT)


class Proof(unittest.TestCase):
    def test_cell_state_matches(self):
        for width, media in ((320, [True, True]), (341, [True, False]), (385, [False, False])):
            with self.subTest(width=width):
                self.assertIsNone(sitecheck.cell_state_problem(
                    width, 640, {"w": width, "h": 640, "media": media}))

    def test_cell_state_mismatch_reported(self):
        problem = sitecheck.cell_state_problem(341, 640, {"w": 341, "h": 640,
                                                          "media": [True, True]})
        self.assertEqual(problem, "@media(max-width:21.25rem) matches at 341 CSS px "
                                  "(340 CSS px at 16 px per rem)")
        problem = sitecheck.cell_state_problem(385, 640, {"w": 385, "h": 640,
                                                          "media": [True, False]})
        self.assertIn("@media(max-width:24rem) matches at 385 CSS px", problem)
        problem = sitecheck.cell_state_problem(320, 640, {"w": 320, "h": 640,
                                                          "media": [False, True]})
        self.assertIn("@media(max-width:24rem) does not match at 320 CSS px", problem)
        self.assertIn("the viewport is 980 x 640 CSS px, not 385 x 640",
                      sitecheck.cell_state_problem(385, 640, {"w": 980, "h": 640,
                                                              "media": [False, False]}))
        self.assertIn("the viewport is 385 x 600 CSS px, not 385 x 640",
                      sitecheck.cell_state_problem(385, 640, {"w": 385, "h": 600,
                                                              "media": [False, False]}))
        for media in (None, [False], [False, False, False], {}):
            with self.subTest(media=media):
                self.assertIn("not one answer per prelude", sitecheck.cell_state_problem(
                    385, 640, {"w": 385, "h": 640, "media": media}))

    def test_cell_state_needs_booleans(self):
        # A truthy non-boolean is no proof.
        self.assertIsNotNone(sitecheck.cell_state_problem(
            320, 640, {"w": 320, "h": 640, "media": [1, 1]}))


class Summary(unittest.TestCase):
    WHAT = ("(320, 341 and 385 CSS px wide, with the script running and with "
            "scripting off)")

    def test_cells_summary(self):
        self.assertEqual(sitecheck.reveal_cells_summary(12, 8),
                         f"reveal cells: 8 of 12 legible {self.WHAT}")
        self.assertEqual(sitecheck.reveal_cells_summary(0, 0),
                         f"reveal cells: 0 of 0 legible {self.WHAT}")
        self.assertEqual(sitecheck.REFLOW_CELLS_NOT_RUN,
                         "reveal cells: not run (--no-reveal-cells)")

    def test_summary_follows_the_constants(self):
        with mock.patch.object(sitecheck, "REFLOW_REVEAL_WIDTHS", (320, 400)):
            self.assertEqual(sitecheck.reveal_cells_summary(4, 4),
                             "reveal cells: 4 of 4 legible (320 and 400 CSS px wide, with "
                             "the script running and with scripting off)")


class Constants(unittest.TestCase):
    def test_constants_match_adr(self):
        adr = (ROOT / "docs" / "adr" / "0003-browser-checks.md").read_text(encoding="utf-8")
        cells = [line.split("|")[1] for line in adr.splitlines() if line.startswith("| ")]
        for name, text in (("REFLOW_REVEAL_CELLS", "320, 341 and 385"),
                           ("REFLOW_ROOT_FONT_PX", str(sitecheck.REFLOW_ROOT_FONT_PX))):
            with self.subTest(name=name):
                rows = [cell for cell in cells if f"`{name}`" in cell]
                self.assertEqual(len(rows), 1, f"{name}: {len(rows)} Numbers rows name it")
                self.assertRegex(rows[0], rf"(?<![\d.,]){re.escape(text)}(?![\d,]|\.\d)")
        self.assertEqual(sitecheck.REFLOW_ROOT_FONT_PX, 16)


if __name__ == "__main__":
    unittest.main()
