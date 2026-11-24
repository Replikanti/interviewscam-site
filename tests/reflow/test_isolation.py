"""isolation_problems in tools/sitecheck.py, the proof of the hidden capture
of the pinned regions' pixel occlusion check (Replikanti/interviewscam#39,
ADR-0005 part 6 amendment).

Run by `bash tools/selftest.sh` (suite `reflow-isolation`) as python3 -I -B
-m unittest, locally and in CI, without a browser: every case builds a
synthetic DOMSnapshot.captureSnapshot reply (strings, documents, their
nodes and layout tables) and calls the module's pure functions through
importlib. The browser rows of reflow-search pin the shape Chrome really
returns; these cases pin every branch and every member of the sets.
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

ELEMENT, TEXT, DOCUMENT = 1, 3, 9
# The computed style of a layout object outside a region once hidden, and
# of an ancestor that paints nothing above its descendants.
HIDDEN = {"visibility": "hidden"}
PLAIN = {"visibility": "visible"}
# Chrome's style row of a document's layout object (the LayoutView): empty,
# since a document has no computed style.
EMPTY = "empty"
DEFAULTS = {"visibility": "visible", "outline-style": "none", "text-decoration-line": "none",
            "overflow-x": "visible", "overflow-y": "visible", "resize": "none"}


class Snapshot:
    """A DOMSnapshot reply built entry by entry, in tree order."""

    def __init__(self):
        self.strings = []
        self.documents = []

    def string(self, text):
        if text not in self.strings:
            self.strings.append(text)
        return self.strings.index(text)

    def document(self):
        doc = {"nodes": {"parentIndex": [], "nodeType": [], "nodeName": [], "nodeValue": [],
                         "backendNodeId": [], "attributes": [],
                         "pseudoType": {"index": [], "value": []}},
               "layout": {"nodeIndex": [], "styles": []}}
        self.documents.append(doc)
        return doc

    def add(self, doc, parent, kind, name, backend, style=None, pseudo=None, attrs=(),
            value=None):
        """One entry; style (a dict over DEFAULTS) gives it a layout object.
        Returns its index."""
        nodes = doc["nodes"]
        index = len(nodes["parentIndex"])
        nodes["parentIndex"].append(parent)
        nodes["nodeType"].append(kind)
        nodes["nodeName"].append(self.string(name))
        nodes["nodeValue"].append(-1 if value is None else self.string(value))
        nodes["backendNodeId"].append(backend)
        nodes["attributes"].append([-1 if x == "" else self.string(x)
                                    for pair in attrs for x in pair])
        if pseudo is not None:
            nodes["pseudoType"]["index"].append(index)
            nodes["pseudoType"]["value"].append(self.string(pseudo))
        if style == EMPTY:
            doc["layout"]["nodeIndex"].append(index)
            doc["layout"]["styles"].append([])
        elif style is not None:
            full = dict(DEFAULTS, **style)
            doc["layout"]["nodeIndex"].append(index)
            doc["layout"]["styles"].append(
                [-1 if full[p] is None else self.string(full[p])
                 for p in sitecheck.REFLOW_SNAPSHOT_STYLES])
        return index

    def reply(self):
        return {"documents": self.documents, "strings": self.strings}


REGION = 50


def page(main_style=None, root_style=None, sibling=HIDDEN):
    """A page as Home holds a pinned region: the document, html, head,
    body with a header, main and in main a heading and the region (a p
    with its text). Returns (snapshot, doc, indexes)."""
    snap = Snapshot()
    doc = snap.document()
    at = {}
    at["document"] = snap.add(doc, -1, DOCUMENT, "#document", 1, style=EMPTY)
    at["html"] = snap.add(doc, at["document"], ELEMENT, "HTML", 2, style=root_style or PLAIN,
                          attrs=[("lang", "en")])
    at["head"] = snap.add(doc, at["html"], ELEMENT, "HEAD", 3)
    at["body"] = snap.add(doc, at["html"], ELEMENT, "BODY", 4, style=PLAIN)
    at["header"] = snap.add(doc, at["body"], ELEMENT, "HEADER", 5, style=HIDDEN,
                            attrs=[("class", "site-header")])
    at["header-text"] = snap.add(doc, at["header"], TEXT, "#text", 6, style=HIDDEN, value="x")
    at["main"] = snap.add(doc, at["body"], ELEMENT, "MAIN", 7, style=main_style or PLAIN,
                          attrs=[("id", "main"), ("class", "container")])
    at["h1"] = snap.add(doc, at["main"], ELEMENT, "H1", 8, style=sibling,
                        attrs=[("class", "home-title")])
    at["h1-text"] = snap.add(doc, at["h1"], TEXT, "#text", 9, style=sibling, value="Title")
    at["region"] = snap.add(doc, at["main"], ELEMENT, "P", REGION, style=PLAIN,
                            attrs=[("class", "lead")])
    at["region-text"] = snap.add(doc, at["region"], TEXT, "#text", 51, style=PLAIN,
                                 value="Lead")
    return snap, doc, at


def problems(snap, region=REGION):
    return sitecheck.isolation_problems(snap.reply(), region)


class Outside(unittest.TestCase):
    def test_pass_everything_hidden(self):
        snap, _, _ = page()
        self.assertEqual(problems(snap), [])

    def test_visible_element(self):
        snap, _, _ = page(sibling=PLAIN)
        self.assertEqual(problems(snap), [("outside", ["h1.home-title",
                                                       "h1.home-title (its text)"])])

    def test_hidden_values_accepted(self):
        for value in ("hidden", "collapse"):
            with self.subTest(value=value):
                snap, _, _ = page(sibling={"visibility": value})
                self.assertEqual(problems(snap), [])

    def test_collapse_is_hidden(self):
        self.assertIn("collapse", sitecheck.REFLOW_HIDDEN_VISIBILITY)
        snap, doc, at = page()
        snap.add(doc, at["header"], ELEMENT, "::after", 60, style={"visibility": "collapse"},
                 pseudo="after")
        self.assertEqual(problems(snap), [])

    def test_visible_refused(self):
        self.assertNotIn("visible", sitecheck.REFLOW_HIDDEN_VISIBILITY)
        self.assertEqual(sitecheck.REFLOW_HIDDEN_VISIBILITY, frozenset({"hidden", "collapse"}))

    def test_pseudo_element_stays_visible(self):
        snap, doc, at = page()
        snap.add(doc, at["header"], ELEMENT, "::after", 60, style=PLAIN, pseudo="after")
        self.assertEqual(problems(snap), [("outside", ["header.site-header::after"])])

    def test_shadow_content_outside(self):
        snap, doc, at = page()
        root = snap.add(doc, at["header"], 11, "#document-fragment", 61)
        snap.add(doc, root, ELEMENT, "DIV", 62, style=PLAIN, attrs=[("id", "placeholder")])
        self.assertEqual(problems(snap), [("outside", ["div#placeholder"])])

    def test_head_shown(self):
        snap, doc, at = page()
        snap.add(doc, at["head"], ELEMENT, "TITLE", 63, style=PLAIN)
        self.assertEqual(problems(snap), [("outside", ["title"])])

    def test_nested_document(self):
        snap, doc, at = page()
        snap.add(doc, at["header"], ELEMENT, "IFRAME", 64, style=HIDDEN)
        inner = snap.document()
        top = snap.add(inner, -1, DOCUMENT, "#document", 65, style=PLAIN)
        snap.add(inner, top, ELEMENT, "svg", 66, style=PLAIN)
        self.assertEqual(problems(snap), [("outside", ["#document in a nested document",
                                                       "svg in a nested document"]),
                                          ("frame", ["iframe"])])

    def test_frame_owners(self):
        self.assertEqual(sitecheck.REFLOW_FRAME_OWNERS,
                         frozenset({"iframe", "frame", "object", "embed"}))
        for name in ("IFRAME", "FRAME", "OBJECT", "EMBED"):
            for style in (HIDDEN, PLAIN):
                with self.subTest(name=name, style=style):
                    snap, doc, at = page()
                    snap.add(doc, at["header"], ELEMENT, name, 64, style=style)
                    self.assertEqual(problems(snap), [("frame", [name.lower()])])

    def test_frame_owner_by_content_document(self):
        snap, doc, at = page()
        owner = snap.add(doc, at["header"], ELEMENT, "DIV", 64, style=HIDDEN)
        doc["nodes"]["contentDocumentIndex"] = {"index": [owner], "value": [1]}
        self.assertEqual(problems(snap), [("frame", ["div"])])

    def test_frame_owner_without_box_or_inside(self):
        snap, doc, at = page()
        snap.add(doc, at["header"], ELEMENT, "IFRAME", 64)
        snap.add(doc, at["region"], ELEMENT, "IFRAME", 65, style=PLAIN)
        self.assertEqual(problems(snap), [])

    def test_nested_document_without_style(self):
        snap, _, _ = page()
        inner = snap.document()
        snap.add(inner, -1, DOCUMENT, "#document", 65, style=EMPTY)
        self.assertEqual(problems(snap), [("outside", ["#document in a nested document"])])

    def test_nested_document_text_label(self):
        snap, doc, at = page()
        inner = snap.document()
        top = snap.add(inner, -1, DOCUMENT, "#document", 65)
        body = snap.add(inner, top, ELEMENT, "BODY", 66, style=HIDDEN)
        snap.add(inner, body, TEXT, "#text", 67, style=PLAIN, value="x")
        self.assertEqual(problems(snap), [("outside", ["body (its text) in a nested document"])])

    def test_region_subtree_ignored(self):
        snap, doc, at = page()
        snap.add(doc, at["region"], ELEMENT, "::before", 70, style=PLAIN, pseudo="before")
        span = snap.add(doc, at["region"], ELEMENT, "SPAN", 71, style=PLAIN)
        root = snap.add(doc, span, 11, "#document-fragment", 72)
        snap.add(doc, root, ELEMENT, "DIV", 73, style=PLAIN)
        self.assertEqual(problems(snap), [])

    def test_empty_attribute_value(self):
        # Chrome writes -1 for an empty string, an attribute without a value.
        snap, doc, at = page()
        snap.add(doc, at["main"], ELEMENT, "DIV", 75, style=PLAIN,
                 attrs=[("hidden", ""), ("class", "")])
        self.assertEqual(problems(snap), [("outside", ["div"])])

    def test_element_sibling_of_region_is_outside(self):
        snap, doc, at = page()
        snap.add(doc, at["main"], ELEMENT, "DIV", 74, style=PLAIN, attrs=[("class", "a b")])
        self.assertEqual(problems(snap), [("outside", ["div.a.b"])])

    def test_one_entry_per_layout_owner(self):
        snap, doc, at = page()
        after = snap.add(doc, at["header"], ELEMENT, "::after", 60, style=PLAIN, pseudo="after")
        doc["layout"]["nodeIndex"].append(after)
        doc["layout"]["styles"].append(doc["layout"]["styles"][-1])
        self.assertEqual(problems(snap), [("outside", ["header.site-header::after"])])


class Ancestors(unittest.TestCase):
    def test_ancestor_text_any_character(self):
        for char in (" ", " ", "​", "　", "﻿", "stray"):
            with self.subTest(char=ascii(char)):
                snap, doc, at = page()
                snap.add(doc, at["main"], TEXT, "#text", 80, style=PLAIN, value=char)
                self.assertEqual(problems(snap),
                                 [("ancestor", ["main#main.container (its text)"])])

    def test_unrendered_text_ignored(self):
        snap, doc, at = page()
        snap.add(doc, at["main"], TEXT, "#text", 80, value=" ")
        snap.add(doc, at["body"], TEXT, "#text", 81, value="\n")
        self.assertEqual(problems(snap), [])

    def test_ancestor_pseudo_elements(self):
        for kind in ("before", "after", "marker", "first-letter", "check",
                     "backdrop"):
            with self.subTest(kind=kind):
                snap, doc, at = page()
                snap.add(doc, at["main"], ELEMENT, "::" + kind, 82, style=PLAIN, pseudo=kind)
                self.assertEqual(problems(snap),
                                 [("ancestor", [f"main#main.container::{kind}"])])

    def test_ancestor_pseudo_hidden_still_counts(self):
        snap, doc, at = page()
        snap.add(doc, at["body"], ELEMENT, "::before", 83, style=HIDDEN, pseudo="before")
        self.assertEqual(problems(snap), [("ancestor", ["body::before"])])

    def test_document_children(self):
        snap, doc, at = page()
        snap.add(doc, at["html"], TEXT, "#text", 84, style=PLAIN, value="x")
        self.assertEqual(problems(snap), [("ancestor", ["html (its text)"])])

    def test_document_node_not_a_finding(self):
        # The LayoutView (the document's layout object) is in every chain,
        # with Chrome's empty style row, or with a style that is visible
        # and a scroll container: neither an outside box nor ancestor paint.
        snap, _, _ = page()
        self.assertEqual(problems(snap), [])
        snap, doc, _ = page()
        doc["layout"]["styles"][0] = [snap.string(v) for v in (
            "visible", "none", "none", "auto", "auto", "none")]
        self.assertEqual(problems(snap), [])

    def test_unreadable_property_fails_closed(self):
        # Chrome writes -1 for a property it cannot read; no rule accepts it.
        snap, _, _ = page(sibling={"visibility": None})
        self.assertEqual(problems(snap), [("outside", ["h1.home-title",
                                                       "h1.home-title (its text)"])])
        snap, _, _ = page(main_style={"resize": None})
        self.assertEqual(problems(snap), [("paint", ["main#main.container resize "])])


class AncestorPaint(unittest.TestCase):
    def paint(self, style, **where):
        snap, _, _ = page(**{where.get("on", "main_style"): dict(PLAIN, **style)})
        return problems(snap)

    def test_each_member(self):
        for prop, value in (("outline-style", "solid"), ("outline-style", "auto"),
                            ("text-decoration-line", "underline"),
                            ("text-decoration-line", "line-through"),
                            ("overflow-x", "scroll"), ("overflow-x", "auto"),
                            ("overflow-y", "scroll"), ("overflow-y", "auto"),
                            ("resize", "both"), ("resize", "vertical")):
            with self.subTest(prop=prop, value=value):
                self.assertEqual(self.paint({prop: value}),
                                 [("paint", [f"main#main.container {prop} {value}"])])

    def test_overflow_without_scroll_bar_passes(self):
        for axis in ("overflow-x", "overflow-y"):
            for value in ("hidden", "clip", "visible"):
                with self.subTest(axis=axis, value=value):
                    self.assertEqual(self.paint({axis: value}), [])

    def test_scrollbar_set(self):
        self.assertEqual(sitecheck.REFLOW_SCROLLBAR_OVERFLOW, frozenset({"scroll", "auto"}))

    def test_styles_read(self):
        self.assertEqual(sitecheck.REFLOW_SNAPSHOT_STYLES,
                         ("visibility", "outline-style", "text-decoration-line",
                          "overflow-x", "overflow-y", "resize"))

    def test_outline_on_root(self):
        self.assertEqual(self.paint({"outline-style": "dashed"}, on="root_style"),
                         [("paint", ["html outline-style dashed"])])

    def test_two_properties_two_items(self):
        self.assertEqual(self.paint({"outline-style": "solid", "resize": "both"}),
                         [("paint", ["main#main.container outline-style solid",
                                     "main#main.container resize both"])])

    def test_outside_element_paint_not_read(self):
        snap, doc, at = page(sibling=dict(HIDDEN, **{"outline-style": "solid"}))
        self.assertEqual(problems(snap), [])

    def test_region_paint_not_read(self):
        snap, doc, at = page()
        snap.add(doc, at["region"], ELEMENT, "SPAN", 90,
                 style=dict(PLAIN, **{"outline-style": "solid"}))
        self.assertEqual(problems(snap), [])

    def test_all_kinds_together(self):
        snap, doc, at = page(main_style=dict(PLAIN, **{"outline-style": "solid"}),
                             sibling=PLAIN)
        snap.add(doc, at["main"], TEXT, "#text", 80, style=PLAIN, value="x")
        snap.add(doc, at["header"], ELEMENT, "EMBED", 91, style=HIDDEN)
        self.assertEqual([kind for kind, _ in problems(snap)],
                         ["outside", "frame", "ancestor", "paint"])


class Broken(unittest.TestCase):
    def assertBroken(self, reply, region=REGION, why=""):
        got = sitecheck.isolation_problems(reply, region)
        self.assertEqual(len(got), 1, got)
        self.assertEqual(got[0][0], "broken")
        self.assertIn(why, got[0][1][0])

    def test_region_missing(self):
        snap, _, _ = page()
        self.assertBroken(snap.reply(), region=999, why="the region is not in it")
        self.assertBroken(snap.reply(), region=None, why="the region is not in it")
        self.assertBroken(snap.reply(), region=True, why="the region is not in it")

    def test_malformed_snapshot(self):
        def edited(change):
            snap, doc, _ = page()
            reply = snap.reply()
            change(reply, doc)
            return reply

        cases = {
            "not an object": lambda r, d: r.clear() or r.update(x=1),
            "strings missing": lambda r, d: r.pop("strings"),
            "strings not text": lambda r, d: r["strings"].append(1),
            "documents empty": lambda r, d: r.update(documents=[]),
            "documents not a list": lambda r, d: r.update(documents={}),
            "a document not an object": lambda r, d: r["documents"].append(1),
            "nodes missing": lambda r, d: d.pop("nodes"),
            "layout missing": lambda r, d: d.pop("layout"),
            "parentIndex missing": lambda r, d: d["nodes"].pop("parentIndex"),
            "nodeType short": lambda r, d: d["nodes"]["nodeType"].pop(),
            "nodeName long": lambda r, d: d["nodes"]["nodeName"].append(0),
            "backendNodeId missing": lambda r, d: d["nodes"].pop("backendNodeId"),
            "a bool for an int": lambda r, d: d["nodes"]["nodeType"].__setitem__(0, True),
            "a float for an int": lambda r, d: d["nodes"]["parentIndex"].__setitem__(1, 0.0),
            "a bool for a layout entry": lambda r, d: d["layout"]["nodeIndex"].__setitem__(1, True),
            "a negative layout entry": lambda r, d: d["layout"]["nodeIndex"].__setitem__(1, -1),
            "parent after child": lambda r, d: d["nodes"]["parentIndex"].__setitem__(1, 5),
            "parent is self": lambda r, d: d["nodes"]["parentIndex"].__setitem__(1, 1),
            "parent below -1": lambda r, d: d["nodes"]["parentIndex"].__setitem__(1, -2),
            "name out of range": lambda r, d: d["nodes"]["nodeName"].__setitem__(1, 999),
            "name negative": lambda r, d: d["nodes"]["nodeName"].__setitem__(1, -1),
            "layout entry out of range": lambda r, d: d["layout"]["nodeIndex"].__setitem__(0, 999),
            "styles short": lambda r, d: d["layout"]["styles"].pop(),
            "a style row short": lambda r, d: d["layout"]["styles"][1].pop(),
            "a style out of range": lambda r, d: d["layout"]["styles"][1].__setitem__(0, 999),
            "styles not a list": lambda r, d: d["layout"].update(styles={}),
            "an element without a style": lambda r, d: d["layout"]["styles"].__setitem__(3, []),
            "an ancestor without a style": lambda r, d: d["layout"]["styles"].__setitem__(1, []),
            "a style below -1": lambda r, d: d["layout"]["styles"][1].__setitem__(0, -2),
            "a pseudoType of -1": lambda r, d: d["nodes"].update(
                pseudoType={"index": [4], "value": [-1]}),
            "an attribute below -1": lambda r, d: d["nodes"]["attributes"][1].__setitem__(1, -2),
            "pseudoType not an object": lambda r, d: d["nodes"].update(pseudoType=[]),
            "pseudoType lengths": lambda r, d: d["nodes"]["pseudoType"]["index"].append(1),
            "pseudoType out of range": lambda r, d: d["nodes"].update(
                pseudoType={"index": [999], "value": [0]}),
            "attributes odd": lambda r, d: d["nodes"]["attributes"][1].append(0),
            "attributes short": lambda r, d: d["nodes"]["attributes"].pop(),
            "attributes not a list": lambda r, d: d["nodes"].update(attributes={}),
            "contentDocumentIndex out of range": lambda r, d: d["nodes"].update(
                contentDocumentIndex={"index": [999], "value": [1]}),
            "contentDocumentIndex not an object": lambda r, d: d["nodes"].update(
                contentDocumentIndex=[]),
        }
        for name, change in cases.items():
            with self.subTest(name=name):
                self.assertBroken(edited(change), why="the DOM snapshot cannot be read")
        for reply in (None, [], "x", 1):
            with self.subTest(reply=reply):
                self.assertBroken(reply, why="the DOM snapshot cannot be read")

    def test_unexpected_error_fails_closed(self):
        # The snapshot is checked before it is read, so no reply reaches
        # these; any that a later edit lets through still fails closed.
        snap, _, _ = page()
        for error in (TypeError, ValueError, KeyError, IndexError, AttributeError):
            with self.subTest(error=error.__name__):
                with mock.patch.object(sitecheck, "snapshot_rare", side_effect=error("x")):
                    self.assertBroken(snap.reply(), why=f"cannot be read: {error.__name__}")

    def test_optional_tables_absent(self):
        snap, doc, _ = page(sibling=PLAIN)
        doc["nodes"].pop("pseudoType")
        doc["nodes"].pop("attributes")
        self.assertEqual(problems(snap), [("outside", ["h1", "h1 (its text)"])])


class Messages(unittest.TestCase):
    def test_named_cap(self):
        items = [f"div{i}" for i in range(12)]
        text = sitecheck.isolation_message("outside", items, "a region")
        self.assertIn("'div9' and 2 more (12 in all)", text)
        self.assertNotIn("'div10'", text)
        self.assertEqual(sitecheck.REFLOW_NAMED, 10)

    def test_named_at_cap(self):
        text = sitecheck.reflow_named([f"div{i}" for i in range(10)])
        self.assertTrue(text.endswith("'div9' (10 in all)"), text)

    def test_prefixes(self):
        for kind, prefix in (("broken", "(isolation) "), ("outside", "(isolation) "),
                             ("frame", "(isolation) "),
                             ("ancestor", "(isolation) "), ("paint", "(ancestor paint) ")):
            with self.subTest(kind=kind):
                self.assertTrue(sitecheck.isolation_message(kind, ["x"], "r").startswith(prefix))
        self.assertTrue(sitecheck.reflow_animation_message("after the hiding", "r", ["a"])
                        .startswith("(animation) after the hiding of r"))

    def test_names_defanged(self):
        text = sitecheck.isolation_message("outside", ["p.lead"], "r")
        self.assertIn("'p[.]lead' (1 in all)", text)



VALUES = {"outline-style": "none", "text-decoration-line": "none", "overflow-x": "visible",
          "overflow-y": "visible", "resize": "none"}


def read(label, **values):
    """One read of the isolate step: [label, the closed-list values]."""
    full = dict(VALUES, **{k.replace("_", "-"): v for k, v in values.items()})
    return [label, [full[p] for p in sitecheck.REFLOW_SNAPSHOT_STYLES[1:]]]


class PseudoPaint(unittest.TestCase):
    def test_each_member_on_each_pseudo_element(self):
        for pseudo in ("::first-line", "::first-letter"):
            for prop, value in (("outline-style", "solid"), ("text-decoration-line", "underline"),
                                ("overflow-x", "scroll"), ("overflow-x", "auto"),
                                ("overflow-y", "scroll"), ("overflow-y", "auto"),
                                ("resize", "both")):
                with self.subTest(pseudo=pseudo, prop=prop, value=value):
                    label = "main#main.container" + pseudo
                    self.assertEqual(sitecheck.pseudo_paint_items([read(label, **{prop: value})]),
                                     [f"{label} {prop} {value}"])

    def test_nothing_painted(self):
        self.assertEqual(sitecheck.pseudo_paint_items([read("main::first-line"),
                                                       read("body::first-letter",
                                                            overflow_x="hidden")]), [])
        self.assertEqual(sitecheck.pseudo_paint_items([]), [])

    def test_read_of_another_shape_fails_closed(self):
        bad = "an ancestor pseudo-element read of another shape"
        for entry in (["main::first-line"], ["main", ["none"] * 4], [1, ["none"] * 5],
                      ["main", ["none"] * 4 + [None]], "main", None):
            with self.subTest(entry=entry):
                self.assertEqual(sitecheck.pseudo_paint_items([entry]), [bad])
        self.assertEqual(sitecheck.pseudo_paint_items({"x": 1}), [bad])


GROUND = (0xF3, 0xF6, 0xFC)


def png(width=40, height=20, pixel=GROUND, marks=()):
    """A base64 RGB PNG of one colour with (x, y, colour) marks."""
    raw = b""
    for y in range(height):
        row = bytearray(bytes(pixel) * width)
        for mx, my, colour in marks:
            if my == y:
                row[mx * 3:mx * 3 + 3] = bytes(colour)
        raw += b"\x00" + bytes(row)

    def chunk(kind, body):
        return (struct.pack(">I", len(body)) + kind + body
                + struct.pack(">I", zlib.crc32(kind + body)))

    data = (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
    return base64.b64encode(data).decode()


BLACK, WHITE = (0, 0, 0), (255, 255, 255)


class Canvas(unittest.TestCase):
    def test_forced_colours(self):
        self.assertEqual(sitecheck.REFLOW_BLANK_CANVAS, ("#000000", "#ffffff"))

    def test_canvas_alone(self):
        self.assertIsNone(sitecheck.pixel_canvas(png(pixel=BLACK), "#000000"))
        self.assertIsNone(sitecheck.pixel_canvas(png(pixel=WHITE), "#ffffff"))

    def test_tolerance_bounds(self):
        self.assertIsNone(sitecheck.pixel_canvas(png(pixel=BLACK, marks=[(3, 4, (8, 0, 0))]),
                                                 "#000000"))
        self.assertEqual(sitecheck.pixel_canvas(png(pixel=BLACK, marks=[(3, 4, (9, 0, 0))]),
                                                "#000000"),
                         "1 pixel(s) off the forced canvas colour #000000, x 3 to 3, y 4 to 4 "
                         "of the slice, by up to 9 of 255")

    def test_ground_eraser_shows_on_a_forced_canvas(self):
        # Paint in the page's canvas colour is uniform against itself and
        # off both forced colours (review run 2, finding 1).
        band = [(x, y, GROUND) for y in range(5, 9) for x in range(40)]
        self.assertIsNone(sitecheck.pixel_canvas(png(marks=band), "#f3f6fc"))
        for pixel, colour in ((BLACK, "#000000"), (WHITE, "#ffffff")):
            with self.subTest(colour=colour):
                got = sitecheck.pixel_canvas(png(pixel=pixel, marks=band), colour)
                self.assertTrue(got.startswith(f"160 pixel(s) off the forced canvas colour "
                                               f"{colour}, x 0 to 39, y 5 to 8"), got)

    def test_few_rows_mostly_overprint(self):
        # Two rows almost wholly overprint beside 18 canvas rows: the
        # reference is the forced colour, never a majority of any kind.
        marks = [(x, y, (0xDD, 0, 0)) for y in (6, 7) for x in range(38)]
        got = sitecheck.pixel_canvas(png(pixel=BLACK, marks=marks), "#000000")
        self.assertEqual(got, "76 pixel(s) off the forced canvas colour #000000, x 0 to 37, "
                              "y 6 to 7 of the slice, by up to 221 of 255")

    def test_whole_slice_another_colour(self):
        got = sitecheck.pixel_canvas(png(pixel=GROUND), "#000000")
        self.assertTrue(got.startswith("800 pixel(s) off"), got)


REGION_ROW = {"kind": "a pinned line", "label": "p.lead", "index": 0, "controls": 0,
              "misses": [], "over": [], "pseudo": [], "top": 0, "height": 10, "left": 0,
              "width": 40, "content": True}
SHOWN = png(marks=[(x, 3, (0x0F, 0x17, 0x2A)) for x in range(5, 30)])


class FakeTools:
    """The DevTools calls reflow_hits makes, answered from a scenario: the
    extras of each step mode, the snapshot, and the six screenshots of a
    slice (as rendered, hidden outside, every element hidden, then the
    paint check's three)."""

    def __init__(self, extras=None, snapshot=None, shots=None):
        # An override replaces keys of the default extra, not the whole dict,
        # so a scenario names only what it changes (the :hover read is []).
        defaults = {"freeze": {"running": [], "hover": []},
                    "isolate": {"moved": False, "running": [], "rules": 1, "lines": [],
                                "hover": []},
                    "blank": {"rules": 2},
                    "unisolate": {"moved": False, "running": [], "sheets": True,
                                  "focus": True, "hover": []}}
        self.extras = {mode: dict(extra, **(extras or {}).get(mode, {}))
                       for mode, extra in defaults.items()}
        self.snapshot = snapshot if snapshot is not None else page()[0].reply()
        self.shots = list(shots or [SHOWN, SHOWN, png(pixel=BLACK), png(pixel=WHITE), SHOWN,
                                    png(), SHOWN])
        self.calls = []

    def send(self, method, params=None, session=None, budget=None):
        params = params or {}
        self.calls.append(method)
        if method == "Runtime.evaluate" and not params.get("returnByValue"):
            return {"result": {"objectId": "o1"}}
        if method == "DOM.describeNode":
            return {"described": {"backendNodeId": REGION}}
        if method == "DOMSnapshot.captureSnapshot":
            return self.snapshot
        if method == "Page.captureScreenshot":
            return {"data": self.shots.pop(0)}
        if method != "Runtime.evaluate":
            return {}
        expression = params["expression"]
        if "window.__iscRegions = regions" in expression:
            return {"result": {"value": [dict(REGION_ROW)]}}
        if "return {vh: innerHeight}" in expression:
            return {"result": {"value": {"vh": 640}}}
        found = re.search(r'var mode = "(\w+)"', expression)
        mode = found.group(1) if found else None
        value = {"x": 0, "y": 0, "vh": 640, "saved": None, "extra": {}}
        if mode in self.extras:
            value["extra"] = self.extras[mode]
        elif mode == "hide":
            value["saved"] = [["", ""], ["", ""], False]
        return {"result": {"value": value}}


def run(tools):
    findings = sitecheck.Findings()
    sitecheck.reflow_hits(tools, "s", findings, "w")
    return findings.items


PIXELS = "(occlusion) the pixels of"


class Plumbing(unittest.TestCase):
    """reflow_hits against FakeTools: each guard reports and blocks the
    comparison of the slice; a paint-only finding does not block it."""

    def test_clean_slice(self):
        self.assertEqual(run(FakeTools()), [])

    def test_restore_checked(self):
        for extra, lost in (({"sheets": False}, "its stylesheets did not come back"),
                            ({"focus": False}, "the focus did not come back"),
                            ({"sheets": None}, "its stylesheets did not come back"),
                            ({"focus": None}, "the focus did not come back")):
            with self.subTest(extra=extra):
                back = {"moved": False, "running": [], "sheets": True, "focus": True,
                        "hover": []}
                back.update(extra)
                for key in [k for k, v in back.items() if v is None]:
                    del back[key]
                # Replaced whole, so a key left out stays out (an override
                # of FakeTools merges per key and would put it back).
                tools = FakeTools()
                tools.extras["unisolate"] = back
                items = run(tools)
                self.assertEqual(len(items), 1, items)
                self.assertIn("was not restored after the captures", items[0])
                self.assertIn(lost, items[0])

    def differing(self, extras=None, snapshot=None):
        # The hidden capture differs from the rendered one, so a slice that
        # is compared gives the pixel finding.
        return run(FakeTools(extras, snapshot, [SHOWN, png(), png(pixel=BLACK),
                                                png(pixel=WHITE), SHOWN, png(), SHOWN]))

    def test_compared_when_clean(self):
        items = self.differing()
        self.assertEqual(len(items), 1, items)
        self.assertIn(PIXELS, items[0])

    def test_each_guard_reports_and_blocks(self):
        moved = "moved when everything outside it was hidden"
        cases = (
            ({"freeze": {"running": ["CSSAnimation of h1"]}}, "(animation) before the first capture"),
            ({"isolate": {"moved": False, "running": ["CSSTransition of h1"], "rules": 1}},
             "(animation) after the hiding"),
            ({"unisolate": {"moved": False, "running": ["CSSTransition of h1"], "sheets": True,
                            "focus": True}}, "(animation) at the second capture"),
            ({"isolate": {"moved": True, "running": [], "rules": 1}}, moved),
            ({"unisolate": {"moved": True, "running": [], "sheets": True, "focus": True}}, moved),
            ({"isolate": {"broken": "the region is not in the document's element tree"}},
             "(isolation)"),
            ({"isolate": {"moved": False, "running": [], "rules": 0}}, "rules, not 1, so everything outside"),
            ({"blank": {"rules": 1}}, "that hides every element"),
        )
        for extras, text in cases:
            with self.subTest(text=text):
                items = self.differing(extras)
                self.assertTrue(any(text in item for item in items), items)
                self.assertFalse(any(PIXELS in item for item in items), items)

    def test_moved_reported_once(self):
        items = self.differing({"isolate": {"moved": True, "running": [], "rules": 1},
                                "unisolate": {"moved": True, "running": [], "sheets": True,
                                              "focus": True}})
        self.assertEqual(sum("moved when everything" in item for item in items), 1, items)

    def test_snapshot_problems_block_but_paint_does_not(self):
        snap, _, _ = page(sibling=PLAIN)
        items = self.differing(snapshot=snap.reply())
        self.assertTrue(any("still show" in item for item in items), items)
        self.assertFalse(any(PIXELS in item for item in items), items)
        snap, _, _ = page(main_style=dict(PLAIN, **{"outline-style": "solid"}))
        items = self.differing(snapshot=snap.reply())
        self.assertTrue(any("(ancestor paint)" in item for item in items), items)
        self.assertTrue(any(PIXELS in item for item in items), items)

    def test_first_line_paint_reported_not_blocking(self):
        lines = [read("main#main.container::first-line", text_decoration_line="line-through")]
        items = self.differing({"isolate": {"moved": False, "running": [], "rules": 1,
                                            "lines": lines}})
        self.assertTrue(any("'main#main[.]container::first-line text-decoration-line "
                            "line-through'" in item for item in items), items)
        self.assertTrue(any(PIXELS in item for item in items), items)

    def test_blank_captures_must_be_the_forced_canvas(self):
        band = [(x, 5, GROUND) for x in range(40)]
        for shots, colour in (
                ([png(pixel=BLACK, marks=band), png(pixel=WHITE)], "#000000"),
                ([png(pixel=BLACK), png(pixel=WHITE, marks=band)], "#ffffff")):
            with self.subTest(colour=colour):
                items = run(FakeTools(shots=[SHOWN, png()] + shots + [SHOWN, png(), SHOWN]))
                self.assertTrue(any("with every element hidden, the slice of" in item
                                    and f"forced canvas colour {colour}" in item
                                    for item in items), items)
                self.assertFalse(any(PIXELS in item for item in items), items)

    def test_blank_finding_once_per_slice(self):
        band = [(x, 5, GROUND) for x in range(40)]
        items = run(FakeTools(shots=[SHOWN, png(), png(pixel=BLACK, marks=band),
                                     png(pixel=WHITE, marks=band), SHOWN, png(), SHOWN]))
        self.assertEqual(sum("with every element hidden" in item for item in items), 1, items)

    def test_blank_capture_asks_for_each_colour(self):
        tools = FakeTools()
        asked = []
        send = tools.send

        def spy(method, params=None, session=None, budget=None):
            found = re.search(r'var mode = "blank", saved = ("[^"]*")', (params or {}).get(
                "expression", ""))
            if found:
                asked.append(found.group(1))
            return send(method, params, session, budget)

        tools.send = spy
        self.assertEqual(run(tools), [])
        self.assertEqual(asked, ['"#000000"', '"#ffffff"'])

    HOVER_PHASES = (("freeze", "before the first capture"),
                    ("isolate", "after the hiding"),
                    ("unisolate", "after the second capture"))

    def test_hover_each_read_reports_and_blocks(self):
        # The pointer rests on the page at one read: one (isolation) finding
        # with that phase's wording, and the pixels are not compared
        # (Replikanti/interviewscam#55).
        for mode, phase in self.HOVER_PHASES:
            with self.subTest(mode=mode):
                items = self.differing({mode: {"hover": ["button"]}})
                self.assertEqual(len(items), 1, items)
                self.assertIn("w: (isolation) ", items[0])
                self.assertIn(f"{phase} of ", items[0])
                self.assertIn("'button' (1 in all)", items[0])
                self.assertIn(":hover", items[0])
                self.assertNotIn(PIXELS, items[0])

    def test_hover_one_finding_per_read(self):
        items = self.differing({mode: {"hover": ["button"]} for mode, _ in self.HOVER_PHASES})
        self.assertEqual(len(items), 3, items)
        for (_, phase), item in zip(self.HOVER_PHASES, items):
            self.assertIn(phase, item)

    def test_hover_html_alone_is_a_finding(self):
        # Inside the viewport html stays hovered even over a bare spot, so
        # only an empty set passes.
        for mode, _ in self.HOVER_PHASES:
            with self.subTest(mode=mode):
                items = self.differing({mode: {"hover": ["html"]}})
                self.assertEqual(len(items), 1, items)
                self.assertIn("'html' (1 in all)", items[0])

    def test_hover_unreadable_fails_closed(self):
        for mode, phase in self.HOVER_PHASES:
            for how, value in (("missing", None), ("null", None), ("string", "button"),
                               ("number", 1), ("dict", {"0": "button"})):
                with self.subTest(mode=mode, how=how):
                    tools = FakeTools(shots=[SHOWN, png(), png(pixel=BLACK), png(pixel=WHITE),
                                             SHOWN, png(), SHOWN])
                    if how == "missing":
                        del tools.extras[mode]["hover"]
                    else:
                        tools.extras[mode]["hover"] = value
                    items = run(tools)
                    self.assertEqual(len(items), 1, items)
                    self.assertIn("w: (isolation) ", items[0])
                    self.assertIn(f"was not read {phase}", items[0])
                    self.assertNotIn(PIXELS, items[0])

    def test_hover_names_capped(self):
        names = [f"div{i}" for i in range(12)]
        text = sitecheck.reflow_hover_message("after the hiding", "a region", names)
        self.assertTrue(text.startswith("(isolation) after the hiding of a region, "), text)
        self.assertIn("'div9' and 2 more (12 in all)", text)
        self.assertNotIn("'div10'", text)
        self.assertIn("Replikanti/interviewscam#55", text)

    def test_hover_not_read_after_broken_isolate(self):
        # The broken branch returns no :hover; the one broken finding stands.
        tools = FakeTools()
        tools.extras["isolate"] = {"broken": "the region is not in the document's element tree"}
        items = run(tools)
        self.assertEqual(len(items), 1, items)
        self.assertIn("so everything outside it cannot be hidden", items[0])

    def test_kept_focus_not_restored(self):
        items = run(FakeTools({"unisolate": {"moved": False, "running": [], "sheets": True,
                                             "focus": False,
                                             "focusWas": "h2#search-answer-heading",
                                             "focusNow": "body"}}))
        self.assertEqual(len(items), 1, items)
        self.assertIn("the focus did not come back (focus on 'h2#search-answer-heading' "
                      "before, on 'body' after)", items[0])


if __name__ == "__main__":
    unittest.main()
