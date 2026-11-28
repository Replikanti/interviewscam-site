"""The pinned computed style of reflow case (7) in tools/sitecheck.py
(Replikanti/interviewscam#63, ADR-0003 part 6 amendment): the table parser,
renderer and loader of tools/skip-link-style.tsv, style_problems with its
allowlist rules, the style reference proof, the summary and the parser
default.

Why it exists: case (7) once proved the revealed skip link legible by a
pixel count plus a hand-listed set of properties, and each review round of
Replikanti/interviewscam#34 found one more property that kept the count
while the label became unreadable. The closed rule compares the complete
computed style of the link, its ::first-line and ::first-letter, body and
html with a pinned baseline. These cases pin the table's form, every rule
of the comparison at its thresholds, and the refusals that keep a re-pin
from passing silently.

Run by `bash tools/selftest.sh` (suite `reflow-isolation`, which discovers
tests/reflow) as python3 -I -B -m unittest, locally and in CI, without a
browser: every case calls the module's pure functions through importlib,
and a fake DevTools client answers the style reference load. The
reflow-style and reflow-style-cells rows pin what Chrome really does.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sitecheck = load("sitecheck_style", ROOT / "tools" / "sitecheck.py")
SCOPES = sitecheck.SKIP_LINK_STYLE_SCOPES
EL, FIRST_LINE, FIRST_LETTER, BODY, HTML = SCOPES
PRODUCT = "HeadlessChrome/157.0.0.0"


def table_text(rows, product=PRODUCT):
    return f"# chrome: {product}\n" + "".join("\t".join(row) + "\n" for row in rows)


# One row per scope, sorted: the smallest table the parser accepts.
MINIMAL = [(EL, "color", "rgb(0, 0, 0)"), (FIRST_LINE, "color", "rgb(0, 0, 0)"),
           (FIRST_LETTER, "color", "rgb(0, 0, 0)"), (BODY, "color", "rgb(0, 0, 0)"),
           (HTML, "color", "rgb(0, 0, 0)")]


def live_style(extra=None, drop=()):
    """{scope: {property: value}} of a link that meets every allowlist rule
    at 320 CSS px and pins color and font-family, with extra merged in and
    the (scope, property) pairs of drop removed."""
    style = {}
    for scope in SCOPES:
        props = {"color": "rgb(0, 0, 0)", "font-family": "\"DejaVu Sans\""}
        style[scope] = props
    style[EL].update({"width": "123px", "height": "42px", "inline-size": "123px",
                      "block-size": "42px", "right": "181px", "bottom": "582px",
                      "inset-inline-end": "181px", "inset-block-end": "582px",
                      "transform-origin": "61.5px 21px", "perspective-origin": "61.5px 21px"})
    for scope, w, h in ((BODY, "320px", "900px"), (HTML, "320px", "900px")):
        style[scope].update({"width": w, "inline-size": w, "height": h, "block-size": h,
                             "transform-origin": "160px 450px",
                             "perspective-origin": "160px 450px"})
    for scope, props in (extra or {}).items():
        style[scope].update(props)
    for scope, prop in drop:
        del style[scope][prop]
    return style


def pinned_table(style=None):
    """The table of a live style: its non-allowlisted, non-custom rows."""
    _, table = sitecheck.parse_skip_link_style(
        sitecheck.render_skip_link_style(PRODUCT, style or live_style()))
    return table


def script_value(style, chain=sitecheck.SKIP_LINK_STYLE_CHAIN):
    """The REFLOW_STYLE_SCRIPT result of a {scope: {property: value}}."""
    return {"chain": list(chain), "scopes": [[scope, [[p, v] for p, v in props.items()]]
                                              for scope, props in style.items()]}


def problems(style, table=None, reference=None, width=320, chrome=PRODUCT):
    return sitecheck.style_problems(script_value(style), reference,
                                    table if table is not None else pinned_table(),
                                    PRODUCT, chrome, width)


class Parse(unittest.TestCase):
    def refuses(self, text, needle):
        with self.assertRaises(sitecheck.UsageError) as ctx:
            sitecheck.parse_skip_link_style(text)
        self.assertIn(needle, str(ctx.exception))
        return str(ctx.exception)

    def test_parse_accepts_minimal(self):
        product, table = sitecheck.parse_skip_link_style(table_text(MINIMAL))
        self.assertEqual(product, PRODUCT)
        self.assertEqual(list(table), list(SCOPES))
        self.assertEqual(table[HTML], {"color": "rgb(0, 0, 0)"})

    def test_parse_refuses_bom(self):
        self.refuses("\ufeff" + table_text(MINIMAL), "skip-link-style.tsv:1: starts with a byte "
                     "order mark")

    def test_parse_refuses_cr(self):
        text = table_text(MINIMAL).replace("\n", "\r\n", 3)
        self.refuses(text, ":1: holds a carriage return")

    def test_parse_refuses_nul(self):
        text = table_text(MINIMAL).replace("rgb(0, 0, 0)", "rgb(0,\0 0, 0)", 2)
        self.refuses(text, ":2: holds a NUL")

    def test_parse_refuses_missing_final_lf(self):
        self.refuses(table_text(MINIMAL)[:-1], ":6: the last line does not end in LF")

    def test_parse_refuses_blank_line(self):
        text = table_text(MINIMAL).replace("\n", "\n\n", 2)
        self.refuses(text, ":2: a blank line")

    def test_parse_refuses_two_fields(self):
        rows = [MINIMAL[0][:2]] + MINIMAL[1:]
        self.refuses(table_text(rows), ":2: 2 tab-separated fields, not 3")

    def test_parse_refuses_four_fields(self):
        rows = MINIMAL[:2] + [MINIMAL[2] + ("x",)] + MINIMAL[3:]
        self.refuses(table_text(rows), ":4: 4 tab-separated fields, not 3")

    def test_parse_refuses_unknown_scope(self):
        rows = MINIMAL[:3] + [("main", "color", "red")] + MINIMAL[3:]
        self.refuses(table_text(rows), ":5: the scope 'main' is not one of")

    def test_parse_refuses_unsorted(self):
        # The first and the last row swapped.
        rows = [MINIMAL[-1]] + MINIMAL[1:-1] + [MINIMAL[0]]
        self.refuses(table_text(rows), "out of order")
        # By property within a scope, in code-point order: Z (U+005A)
        # sorts before a.
        self.refuses(table_text([(EL, "b", "1"), (EL, "a", "1")] + MINIMAL[1:]), ":3: "
                     "a.visually-hidden a is out of order")
        sitecheck.parse_skip_link_style(table_text([(EL, "Z", "1"), (EL, "a", "1")]
                                                   + MINIMAL[1:]))

    def test_parse_refuses_missing_header(self):
        self.refuses("".join("\t".join(r) + "\n" for r in MINIMAL), ":1: the first line is not")
        self.refuses(table_text(MINIMAL, product=""), ":1: the first line is not")
        self.refuses(table_text(MINIMAL).replace("# chrome: ", "# Chrome: ", 1),
                     ":1: the first line is not")

    def test_parse_refuses_second_header(self):
        text = table_text(MINIMAL).replace("\n", f"\n# chrome: {PRODUCT}\n", 1)
        self.refuses(text, ":2: a second header")

    def test_parse_refuses_bad_escape(self):
        rows = [(EL, "color", "a\\xb")] + MINIMAL[1:]
        self.refuses(table_text(rows), ":2: the escape '\\\\x'")
        rows = [(EL, "color", "ab\\")] + MINIMAL[1:]
        self.refuses(table_text(rows), ":2: the escape")

    def test_parse_refuses_scope_without_rows(self):
        self.refuses(table_text(MINIMAL[:2] + MINIMAL[3:]), "the scope "
                     "a.visually-hidden::first-letter has no row")
        self.refuses(table_text(MINIMAL[:-1]), "the scope html has no row")

    def test_parse_refuses_duplicate_row(self):
        rows = [MINIMAL[0], (EL, "color", "red")] + MINIMAL[1:]
        self.refuses(table_text(rows), ":3: a.visually-hidden color is listed twice")

    def test_parse_refuses_allowlisted_row(self):
        rows = [(EL, "color", "x"), (EL, "width", "10px")] + MINIMAL[1:]
        self.refuses(table_text(rows), ":3: a.visually-hidden width is in "
                     "SKIP_LINK_STYLE_ALLOWED")

    def test_parse_refuses_custom_property(self):
        rows = [(EL, "--x", "1")] + MINIMAL
        self.refuses(table_text(rows), ":2: '--x' is empty or a custom property")


class RoundTrip(unittest.TestCase):
    def test_round_trip_escapes(self):
        rows = [(EL, "color", "a\\\\b"), (EL, "content", "x\\ty"), (EL, "quotes", "\\n\u201c")]
        text = table_text(rows + MINIMAL[1:])
        product, table = sitecheck.parse_skip_link_style(text)
        self.assertEqual(table[EL], {"color": "a\\b", "content": "x\ty", "quotes": "\n\u201c"})
        self.assertEqual(sitecheck.render_skip_link_style(product, table), text)

    def test_round_trip_real_table(self):
        text = sitecheck.SKIP_LINK_STYLE_PATH.read_text(encoding="utf-8")
        product, table = sitecheck.parse_skip_link_style(text)
        self.assertEqual(sitecheck.render_skip_link_style(product, table), text)

    def test_repin_dump_parses_back(self):
        style = live_style({EL: {"--color-primary": "#000"}})
        dump = sitecheck.render_skip_link_style(PRODUCT, style)
        product, table = sitecheck.parse_skip_link_style(dump)
        self.assertEqual(product, PRODUCT)
        want = {scope: {p: v for p, v in props.items() if not p.startswith("--")
                        and f"{scope}/{p}" not in sitecheck.SKIP_LINK_STYLE_ALLOWED}
                for scope, props in style.items()}
        self.assertEqual(table, want)
        self.assertEqual(problems(style, table=table), [])


class Loader(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.text = table_text(MINIMAL)
        self.path = self.dir / "skip-link-style.tsv"
        self.path.write_text(self.text, encoding="utf-8")
        self.sha = hashlib.sha256(self.text.encode()).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def test_loader_accepts_pinned(self):
        self.assertEqual(sitecheck.load_skip_link_style(self.path, self.sha)[0], PRODUCT)

    def test_loader_refuses_other_digest(self):
        with self.assertRaises(sitecheck.UsageError) as ctx:
            sitecheck.load_skip_link_style(self.path, "0" * 64)
        self.assertIn("not the pinned " + "0" * 64, str(ctx.exception))

    def test_loader_refuses_symlink(self):
        link = self.dir / "link.tsv"
        os.symlink(self.path, link)
        with self.assertRaises(sitecheck.UsageError) as ctx:
            sitecheck.load_skip_link_style(link, self.sha)
        self.assertIn("a symlink", str(ctx.exception))

    def test_loader_refuses_missing(self):
        with self.assertRaises(sitecheck.UsageError):
            sitecheck.load_skip_link_style(self.dir / "none.tsv", self.sha)
        with self.assertRaises(sitecheck.UsageError):
            sitecheck.load_skip_link_style(self.dir, self.sha)

    def test_real_table_matches_its_pin(self):
        product, table = sitecheck.load_skip_link_style(sitecheck.SKIP_LINK_STYLE_PATH,
                                                        sitecheck.SKIP_LINK_STYLE_SHA256)
        self.assertTrue(product)
        self.assertEqual(list(table), list(SCOPES))


class Rules(unittest.TestCase):
    def rule(self, rule, value, width=320, box=("123px", "42px")):
        return sitecheck.style_rule_problem(rule, value, {"width": box[0], "height": box[1]},
                                            width)

    def test_origin_rule_tolerance(self):
        self.assertIsNone(self.rule("origin", "61.5px 21px"))
        self.assertIsNone(self.rule("origin", "61.515625px 21px"))
        self.assertIsNone(self.rule("origin", "61.484375px 21.015625px"))
        self.assertIsNotNone(self.rule("origin", "61.53125px 21px"))
        self.assertIsNotNone(self.rule("origin", "61.5px 20.96875px"))
        self.assertEqual(sitecheck.SKIP_LINK_STYLE_TOLERANCE, 1 / 64)

    def test_origin_rule_tall_box(self):
        # Chrome writes a length with 6 significant digits (Chrome 158, run
        # 46118966945): a body 13045.2px tall has its centre at 6522.58px,
        # 0.02 px from half the written height; one unit of the size's last
        # digit (0.1 px here) is the tolerance, 1/64 px below 10000 px.
        box = ("320px", "13045.2px")
        self.assertIsNone(self.rule("origin", "160px 6522.58px", box=box))
        self.assertIsNone(self.rule("origin", "160px 6522.69px", box=box))
        self.assertIsNotNone(self.rule("origin", "160px 6522.75px", box=box))
        self.assertEqual(sitecheck.style_origin_tolerance(13045.2), 0.1)
        self.assertEqual(sitecheck.style_origin_tolerance(9999.98), 1 / 64)
        self.assertEqual(sitecheck.style_origin_tolerance(172.297), 1 / 64)
        self.assertEqual(sitecheck.style_origin_tolerance(0), 1 / 64)
        self.assertEqual(sitecheck.SKIP_LINK_STYLE_DIGITS, 6)

    def test_origin_rule_forms(self):
        self.assertIsNone(self.rule("origin", "61.5px 21px 0px"))
        for value in ("61.5px 21px 1px", "auto", "0px 0px", "61.5px", "61.5px  21px",
                      "61.5px 21px 0px 0px", "50% 50%", "61.5px 21px 0"):
            with self.subTest(value=value):
                self.assertIsNotNone(self.rule("origin", value))
        # The box must be a resolved px size.
        self.assertIsNotNone(self.rule("origin", "61.5px 21px", box=("auto", "42px")))

    def test_viewport_rule_uses_cell_width(self):
        self.assertIsNone(self.rule("viewport", "341px", width=341))
        self.assertIsNone(self.rule("viewport", "340.984375px", width=341))
        self.assertIsNotNone(self.rule("viewport", "340.96875px", width=341))
        self.assertIsNotNone(self.rule("viewport", "320px", width=341))
        self.assertIsNone(self.rule("viewport", "320px", width=320))
        self.assertEqual(self.rule("viewport", "300px"), "not the 320 CSS px of the cell")

    def test_length_rule_forms(self):
        for value in ("0px", "172.5px", "12px", "0.5px"):
            with self.subTest(value=value):
                self.assertIsNone(self.rule("length", value))
        for value in ("-1px", "auto", "1e3px", " 12px", "12px ", "012px", "12", "12.px",
                      "12PX"):
            with self.subTest(value=value):
                self.assertIsNotNone(self.rule("length", value))


class Problems(unittest.TestCase):
    def test_pinned_style_passes(self):
        self.assertEqual(problems(live_style()), [])

    def test_b1_changed_value(self):
        style = live_style({EL: {"font-family": "serif"}})
        found = problems(style)
        self.assertEqual(found, ["a.visually-hidden font-family is 'serif', pinned "
                                 "'\"DejaVu Sans\"'"])

    def test_b1_reference_classifies(self):
        style = live_style({BODY: {"color": "rgb(1, 1, 1)"}})
        reference = live_style({BODY: {"color": "rgb(1, 1, 1)"}})
        found = problems(style, reference=reference, chrome="HeadlessChrome/158.0.0.0")
        self.assertEqual(len(found), 1)
        self.assertIn("which is Chrome's own value for this markup with the author styles "
                      "blocked", found[0])
        self.assertIn("the table was pinned on 'HeadlessChrome/157[.]0[.]0[.]0', this is "
                      "'HeadlessChrome/158[.]0[.]0[.]0'", found[0])
        self.assertNotIn("Chrome's own value", problems(style, reference=live_style())[0])

    def test_every_scope_compared(self):
        for scope in SCOPES:
            with self.subTest(scope=scope):
                found = problems(live_style({scope: {"color": "red"}}))
                self.assertEqual(found, [f"{scope} color is 'red', pinned 'rgb(0, 0, 0)'"])

    def test_allowlist_rules_applied(self):
        found = problems(live_style({HTML: {"width": "300px"}}))
        # The origin rules read the same width, so both origins fail too.
        self.assertEqual(found, ["html perspective-origin is '160px 450px', not the centre of "
                                 "its '300px' x '900px' box (rule origin)",
                                 "html transform-origin is '160px 450px', not the centre of its "
                                 "'300px' x '900px' box (rule origin)",
                                 "html width is '300px', not the 320 CSS px of the cell "
                                 "(rule viewport)"])
        found = problems(live_style({BODY: {"inline-size": "300px"}}))
        self.assertEqual(found, ["body inline-size is '300px', not the 320 CSS px of the cell "
                                 "(rule viewport)"])
        found = problems(live_style({EL: {"transform-origin": "0px 0px"}}))
        self.assertEqual(len(found), 1)
        self.assertIn("a.visually-hidden transform-origin is '0px 0px', not the centre", found[0])
        found = problems(live_style({BODY: {"block-size": "auto"}}))
        self.assertEqual(found, ["body block-size is 'auto', not a non-negative length in px "
                                 "(rule length)"])
        # At 341 the same style fails on four viewport pairs.
        self.assertEqual(len(problems(live_style(), width=341)), 4)

    def test_new_property_equal_to_reference(self):
        style = live_style({scope: {"-webkit-text-stroke-width": "0px"} for scope in SCOPES})
        self.assertEqual(problems(style, reference=style), [])

    def test_new_property_different_from_reference(self):
        style = live_style({scope: {"-webkit-text-stroke-width": "0px"} for scope in SCOPES})
        reference = live_style({scope: {"-webkit-text-stroke-width": "0px"} for scope in SCOPES})
        style[EL]["-webkit-text-stroke-width"] = "1px"
        style[FIRST_LINE]["-webkit-text-stroke-width"] = "1px"
        style[FIRST_LETTER]["-webkit-text-stroke-width"] = "1px"
        found = problems(style, reference=reference)
        self.assertEqual(len(found), 1)
        self.assertIn("a.visually-hidden -webkit-text-stroke-width is '1px', a property the "
                      "pinned style does not name, and not Chrome's own value '0px'", found[0])

    def test_new_property_pseudo_compared_with_element(self):
        style = live_style({scope: {"-webkit-text-stroke-width": "0px"} for scope in SCOPES})
        # The reference's pseudo-elements are not comparable (an inline link
        # without author CSS): a different value there does not matter.
        reference = live_style({scope: {"-webkit-text-stroke-width": "0px"} for scope in SCOPES})
        reference[FIRST_LINE]["-webkit-text-stroke-width"] = "9px"
        self.assertEqual(problems(style, reference=reference), [])
        style[FIRST_LINE]["-webkit-text-stroke-width"] = "1px"
        found = problems(style, reference=reference)
        self.assertEqual(len(found), 1)
        self.assertIn(f"{FIRST_LINE} -webkit-text-stroke-width is '1px', a property the pinned "
                      "style does not name, and not the element's own value '0px'", found[0])

    def test_new_property_without_reference_fails_closed(self):
        style = live_style({BODY: {"-webkit-text-stroke-width": "0px"}})
        found = problems(style, reference=None)
        self.assertEqual(found, ["body -webkit-text-stroke-width is '0px', a property the "
                                 "pinned style does not name, and the tree has no style "
                                 "reference load to compare it with"])

    def test_missing_property(self):
        table = pinned_table()
        table[EL]["-x-no-such-property"] = "none"
        found = problems(live_style(), table=table)
        self.assertEqual(found, ["the pinned style names a.visually-hidden -x-no-such-property, "
                                 "which this Chrome does not report"])
        found = problems(live_style(drop=[(HTML, "perspective-origin")]))
        self.assertEqual(found, ["the pinned style names html perspective-origin, which this "
                                 "Chrome does not report"])

    def test_lookalike_property_name_is_missing(self):
        table = pinned_table()
        table[EL]["f\u043ent-family"] = table[EL].pop("font-family")
        found = problems(live_style(), table=table, reference=live_style())
        # font-family itself is now a property the table does not name,
        # equal to the reference here, so only the look-alike row fails.
        self.assertEqual(found, ["the pinned style names a.visually-hidden f\u043ent-family, "
                                 "which this Chrome does not report"])

    def test_custom_properties_skipped_only_with_two_hyphens(self):
        reference = live_style()
        self.assertEqual(problems(live_style({EL: {"--x": "1"}}), reference=reference), [])
        for prop in ("-webkit-x", "\u2014x", "-x"):
            with self.subTest(prop=prop):
                found = problems(live_style({EL: {prop: "1"}}), reference=reference)
                self.assertEqual(len(found), 1)
                self.assertIn("a property the pinned style does not name", found[0])

    def test_value_compared_exactly(self):
        table = pinned_table(live_style({EL: {"padding-top": "0px"}}))
        for value in ("0px ", "0 px", "0PX"):
            with self.subTest(value=value):
                self.assertEqual(len(problems(live_style({EL: {"padding-top": value}}),
                                              table=table)), 1)
        for family in ("\"DejaVu\u200b Sans\"", "\"DejaVu S\u0430ns\""):
            with self.subTest(family=family):
                self.assertEqual(len(problems(live_style({EL: {"font-family": family}}))), 1)

    def test_allowlist_keys_exact(self):
        self.assertNotIn("a.visually-hidden/Width", sitecheck.SKIP_LINK_STYLE_ALLOWED)
        found = problems(live_style({EL: {"Width": "1px"}}), reference=live_style())
        self.assertEqual(len(found), 1)
        self.assertIn("a.visually-hidden Width is '1px', a property the pinned style does not "
                      "name", found[0])

    def test_unreadable_style_fails_closed(self):
        for value in ({}, None, {"chain": list(sitecheck.SKIP_LINK_STYLE_CHAIN), "scopes": []},
                      {"chain": list(sitecheck.SKIP_LINK_STYLE_CHAIN),
                       "scopes": script_value(live_style())["scopes"][:4]},
                      {"chain": list(sitecheck.SKIP_LINK_STYLE_CHAIN),
                       "scopes": [[EL, [["color", 1]]]]},
                      {"chain": list(sitecheck.SKIP_LINK_STYLE_CHAIN),
                       "scopes": [[EL, [["color", "a"], ["color", "b"]]]]}):
            with self.subTest(value=value):
                found = sitecheck.style_problems(value, None, pinned_table(), PRODUCT, PRODUCT,
                                                 320)
                self.assertEqual(len(found), 1)
                self.assertTrue(found[0].startswith("could not read the computed style"))

    def test_chain_finding_has_no_property_list(self):
        value = script_value(live_style({EL: {"color": "red"}}),
                             chain=("a.visually-hidden", "div", "body", "html"))
        found = sitecheck.style_problems(value, None, pinned_table(), PRODUCT, PRODUCT, 320)
        self.assertEqual(found, ["the focused element and its ancestors are "
                                 "'a[.]visually-hidden > div > body > html', not "
                                 "a.visually-hidden > body > html, so its computed style cannot "
                                 "be compared with the pinned scopes"])

    def test_at_most_named_differences(self):
        extra = {EL: {f"p{n:02}": "1" for n in range(14)}}
        found = problems(live_style(extra), reference=live_style())
        self.assertEqual(len(found), sitecheck.REFLOW_NAMED + 1)
        self.assertEqual(found[-1], "4 more")


class Summary(unittest.TestCase):
    def test_style_summary(self):
        self.assertEqual(sitecheck.style_summary(72, 70, 1850, False),
                         "skip-link style: 70 of 72 cells as pinned (1850 rows in 5 scopes, "
                         f"{len(sitecheck.SKIP_LINK_STYLE_ALLOWED)} allowed)")
        self.assertEqual(sitecheck.style_summary(0, 0, 0, True),
                         "skip-link style: not run (--no-style-baseline)")

    def test_parser_default_runs_baseline(self):
        args = sitecheck.build_parser().parse_args(["reflow", "--chrome", "x", "public"])
        self.assertIs(args.no_style_baseline, False)
        args = sitecheck.build_parser().parse_args(
            ["reflow", "--chrome", "x", "--no-style-baseline", "public"])
        self.assertIs(args.no_style_baseline, True)


class FakeTools:
    """The DevTools calls of the style reference load: the proof answer and
    the style script's answer, and every call recorded."""

    def __init__(self, proof):
        self.proof = proof
        self.calls = []

    def send(self, method, params=None, session=None, budget=None):
        self.calls.append((method, params))
        if method == "Runtime.evaluate":
            if "styleSheets" in params["expression"]:
                return {"result": {"value": self.proof}}
            return {"result": {"value": script_value(live_style())}}
        return {}


class Reference(unittest.TestCase):
    def run_reference(self, proof):
        tools = FakeTools(proof)
        value = sitecheck.reflow_style_reference(tools, "s", lambda url: None, "http://x/a-z/",
                                                 "public/a-z/index.html")
        return tools, value

    def test_reference_blocks_and_resets(self):
        tools, value = self.run_reference({"sheets": 1, "rules": 0, "adopted": 0,
                                           "hidden": True, "position": "static"})
        self.assertEqual(value, script_value(live_style()))
        methods = [m for m, _ in tools.calls]
        self.assertEqual(methods[:2], ["Network.enable", "Network.setBlockedURLs"])
        self.assertEqual(tools.calls[1][1], {"urls": ["*.css", "*.js", "*.mjs"]})
        self.assertEqual(methods[-2:], ["Network.setBlockedURLs", "Network.disable"])
        self.assertEqual(tools.calls[-2][1], {"urls": []})
        self.assertEqual(methods.count("Input.dispatchKeyEvent"), 2)

    def test_reference_proof_refuses_applied_sheet(self):
        for proof, needle in (({"sheets": 1, "rules": 3, "adopted": 0, "hidden": True,
                                "position": "static"},
                               "still applied a stylesheet: document.styleSheets holds '3' "
                               "rule(s) in '1' sheet(s) and '0' adopted sheet(s), not 0"),
                              ({"sheets": 0, "rules": 0, "adopted": 1, "hidden": True,
                                "position": "static"},
                               "still applied a stylesheet: document.styleSheets holds '0' "
                               "rule(s) in '0' sheet(s) and '1' adopted sheet(s), not 0"),
                              ({"sheets": 1, "rules": 0, "adopted": 0, "hidden": True,
                                "position": "absolute"},
                               "still applied a stylesheet: the focused skip link's computed position is "
                               "'absolute', not static")):
            with self.subTest(proof=proof):
                with self.assertRaises(sitecheck.UsageError) as ctx:
                    self.run_reference(proof)
                self.assertIn("reflow: the style reference load of public/a-z/index.html "
                              + needle, str(ctx.exception))

    def test_reference_proof_refuses_other_focus(self):
        with self.assertRaises(sitecheck.UsageError) as ctx:
            self.run_reference({"sheets": 1, "rules": 0, "adopted": 0, "hidden": False,
                                "position": "static"})
        self.assertIn("focused no element of class visually-hidden", str(ctx.exception))

    def test_reference_blocked_list(self):
        self.assertEqual(sitecheck.REFLOW_STYLE_REFERENCE_BLOCKED, ("*.css", "*.js", "*.mjs"))


class Constants(unittest.TestCase):
    def test_constants_match_adr(self):
        adr = (ROOT / "docs" / "adr" / "0003-browser-checks.md").read_text(encoding="utf-8")
        cells = [line.split("|")[1] for line in adr.splitlines() if line.startswith("| ")]
        rules = sorted(set(sitecheck.SKIP_LINK_STYLE_ALLOWED.values()))
        for name, text in (("SKIP_LINK_STYLE_SCOPES", str(len(SCOPES))),
                           ("SKIP_LINK_STYLE_ALLOWED", str(len(sitecheck.SKIP_LINK_STYLE_ALLOWED))),
                           ("SKIP_LINK_STYLE_TOLERANCE", "1/64")):
            with self.subTest(name=name):
                rows = [cell for cell in cells if f"`{name}`" in cell]
                self.assertEqual(len(rows), 1, f"{name}: {len(rows)} Numbers rows name it")
                self.assertRegex(rows[0], rf"(?<![\d.,/]){re.escape(text)}(?![\d,/]|\.\d)")
        self.assertEqual(len(SCOPES), 5)
        self.assertEqual(rules, ["length", "origin", "viewport"])
        self.assertEqual(sitecheck.SKIP_LINK_STYLE_TOLERANCE, 1 / 64)
        self.assertEqual(sitecheck.SKIP_LINK_STYLE_CHAIN, ("a.visually-hidden", "body", "html"))


if __name__ == "__main__":
    unittest.main()
