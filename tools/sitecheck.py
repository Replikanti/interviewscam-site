#!/usr/bin/env python3
"""Safety-net checks for interviewscam.com (ADR-0002 parts 3, 4 and 6).

Standard library only, Python 3.11 or newer, always run as `python3 -I`.
Isolated mode drops the script directory from sys.path, so this is one file.

Subcommands. Each exits 0 when clean, 1 on findings and 2 on a usage or
internal error, so a crash never reads as a finding or as a pass.

  records [--root DIR] [--schemas DIR]
      Every record (content/reports/*.md, content/campaigns/*.md, except
      _index.md) has TOML front matter that passes its schema. Every value
      the schema marks with x-defang is defanged (D8). The live form of an
      artifact appears in no other string and no body of any record (R2).
      No record body carries a bare URL, a Markdown link or a <...> autolink
      (SPEC section 5); the rule fails closed.
  site --records DIR [--schemas DIR] PUBLIC
      The built site in PUBLIC makes no third-party request (D9). Every page
      carries exactly one CSP meta, right after <meta charset>, equal to
      params.csp in DIR/hugo.toml. The live form of a record artifact appears
      nowhere in PUBLIC (R3), decoded or not. Forms stay on the origin, no
      web manifest, no inline style, script or event handler, one canonical
      link to the page itself, no mailto: link, only token colours, no SMIL
      animation, and .visually-hidden and !important only where ADR-0003
      part 6 allows them (counted across all built CSS).
  tokens [--root DIR]
      data/tokens.toml is well formed and every listed colour pair meets its
      WCAG 2.2 contrast minimum with the ratio it states. No colour literal
      appears in assets/, layouts/, static/ or hugo.toml.
  reflow --chrome BIN PUBLIC
      Every HTML page in PUBLIC, loaded in headless Chrome at a 320 CSS px
      viewport, has no page-level horizontal overflow, and every word and
      replaced element lies within the viewport and within every clipping
      ancestor (geometry, ADR-0003 part 6). CI only.
  guard [--root DIR] [--hugo BIN]
      Repo-level rules: no JavaScript package-manager tooling in the build
      chain (D3); the Hugo hardening keys of ADR-0001 in hugo.toml AND in the
      effective config that `hugo config` reports; no config/ directory and
      no second root config file; every action owned by actions/ and pinned
      to a 40-hex commit SHA (ADR-0002 part 6); Pages off until M6. Only
      tools/lighthouse.sh may name the registry tools, only
      .github/workflows/lighthouse.yml may run it, and the job that does has
      no token permissions and no checkout (ADR-0003 part 2).
  lighthouse --reports DIR --version V
      The score gate of ADR-0003 part 3 on the JSON reports in DIR: exactly
      3 runs per page, the pinned version, the mobile profile, a median of at
      least LIGHTHOUSE_MIN_SCORE in each category, same-origin requests only.
  tree-digest LOCKFILE --expect SHA256
      The digest of a resolved dependency tree (ADR-0003 part 1): every entry
      from the public registry with a sha512 integrity, then SHA-256 over the
      sorted `name@version integrity` lines, compared with the pin.

A finding never prints an artifact in live form: values are shown defanged.
"""

import sys

if sys.version_info < (3, 11):
    print("sitecheck: Python 3.11 or newer is required (tomllib)", file=sys.stderr)
    sys.exit(2)

import argparse
import datetime
import decimal
import fcntl
import functools
import hashlib
import html
import html.parser
import http.server
import json
import math
import os
import re
import select
import shutil
import subprocess
import tempfile
import threading
import time
import tomllib
import unicodedata
import urllib.parse
from pathlib import Path

SITE_ORIGIN = "https://interviewscam.com"


class UsageError(Exception):
    """A usage or internal error: exit 2, never a finding."""


class Findings:
    def __init__(self):
        self.items = []

    def add(self, where, message):
        self.items.append(f"FAIL: {where}: {message}")

    def extend(self, other):
        self.items.extend(other.items)

    def report(self, summary):
        for item in self.items:
            print(item)
        print(summary)
        if self.items:
            print(f"{len(self.items)} finding(s)")
            return 1
        return 0


# ---------------------------------------------------------------------------
# Text helpers

# Dot look-alikes that browsers map to "." in a hostname (IDNA).
DOT_CHARS = "\u3002\uff0e\uff61"
DOT = r"[.\u3002\uff0e\uff61]"
# Invisible characters that a copy-paste carries along without a trace.
INVISIBLE = dict.fromkeys(map(ord, "\u00ad\u200b\u200c\u200d\u2060\ufeff"))
TO_DOT = str.maketrans(dict.fromkeys(DOT_CHARS, "."))


def norm(text):
    """Fold a string for live-form comparison: NFKC, dots, invisibles, case."""
    text = unicodedata.normalize("NFKC", text)
    return text.translate(INVISIBLE).translate(TO_DOT).lower()


def refang(value):
    """The live form of a defanged artifact (R2, R3)."""
    live = value.replace("[.]", ".").replace("[:]", ":").replace("[@]", "@")
    return re.sub(r"(?i)hxxp", "http", live)


def show(value, limit=120):
    """A value as findings print it: defanged, so a log never holds it live."""
    text = unicodedata.normalize("NFKC", str(value)).translate(TO_DOT)
    text = re.sub(r"(?i)http", "hxxp", text)
    text = re.sub(r"(?<!\[)\.(?!\])", "[.]", text)
    text = text.replace("\n", "\\n")
    if len(text) > limit:
        text = text[:limit] + "..."
    return repr(text)


MD_ESCAPE = re.compile(r"\\([!-/:-@\[-`{-~])")


def text_variants(text):
    """The text as written, entity-decoded and Markdown-unescaped, folded."""
    variants = {text, html.unescape(text)}
    variants |= {MD_ESCAPE.sub(r"\1", v) for v in list(variants)}
    return {norm(v) for v in variants}


# ---------------------------------------------------------------------------
# Defang predicates (x-defang modes)

LIVE_SCHEME = re.compile(r"(?i)\b(?:https?|ftps?|wss?)://")
WWW_PREFIX = re.compile(rf"(?i)(?<![\w-])www{DOT}")
LABEL = r"[^\W_](?:[\w-]{0,61}[^\W_])?"
TLD = r"(?:[^\W\d_]{2,63}|xn--[a-z0-9-]{1,59})"
LIVE_HOST = re.compile(rf"(?i)(?<![\w-])(?:{LABEL}{DOT})+{TLD}(?![\w-])")
LIVE_IPV4 = re.compile(rf"(?<!\d)(?:\d{{1,3}}{DOT}){{3}}\d{{1,3}}(?!\d)")

DEFANG_MODES = ("host", "url-only")
# A scheme anywhere in a token (irm('hxxps://...'), url=hxxps://...), with any
# run of slashes after it, or a leading run of slashes (protocol-relative):
# both are replaced by a space so the host that follows is split out.
SCHEME_IN_TOKEN = re.compile(
    r"(?i)[a-z][a-z0-9+.\-]*:(?=[/\\])[/\\]*|^[/\\]+")
URL_HOST_END = re.compile(r"[/?#\\]")


def defang_problems(value, mode):
    """Why a string is not defanged under mode, or [] when it is."""
    text = unicodedata.normalize("NFKC", value).translate(INVISIBLE)
    problems = []
    if LIVE_SCHEME.search(text):
        problems.append("live URL scheme (write hxxp:// or hxxps://)")
    if mode == "url-only":
        return problems
    # Only the host part of each token counts: a dot in a URL path or query
    # (/download/GoogleMeet.exe, ?id=abc.def) is not a hostname.
    # The host part is cut at the raw / ? # \ and decoded afterwards: %2E in
    # a host is a dot, and an encoded %2F (hxxps://x%2F@host) cannot hide one.
    hosts = [urllib.parse.unquote(URL_HOST_END.split(part, maxsplit=1)[0])
             for token in text.split()
             for part in SCHEME_IN_TOKEN.sub(" ", token).split()]
    if any(WWW_PREFIX.search(h) for h in hosts):
        problems.append("live www. prefix (write www[.])")
    if any(LIVE_HOST.search(h) for h in hosts):
        problems.append("live hostname (write every dot as [.])")
    if any(LIVE_IPV4.search(h) for h in hosts):
        problems.append("live IPv4 address (write every dot as [.])")
    return problems


# ---------------------------------------------------------------------------
# JSON-Schema subset validator (ADR-0002 part 4). It fails closed on every
# keyword it does not implement, so a schema never looks stricter than it is.

VALIDATION_KEYWORDS = {
    "type", "required", "properties", "additionalProperties", "items",
    "enum", "const", "pattern", "minLength", "minItems", "format", "x-defang",
}
ANNOTATION_KEYWORDS = {
    "$schema", "$id", "$comment", "title", "description", "examples",
}
TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}
FORMATS = {"date"}


def schema_problems(schema, where):
    """Every keyword or value in schema that this validator cannot honour."""
    problems = []
    if not isinstance(schema, dict):
        return [f"{where}: a schema must be a JSON object"]
    for key, value in schema.items():
        here = f"{where}/{key}"
        if key in ANNOTATION_KEYWORDS:
            continue
        if key not in VALIDATION_KEYWORDS:
            problems.append(f"{here}: unsupported schema keyword {key!r} "
                            "(the subset validator fails closed)")
            continue
        if key == "type":
            names = value if isinstance(value, list) else [value]
            if not names or any(n not in TYPES for n in names):
                problems.append(f"{here}: unsupported type {value!r}")
        elif key == "required":
            if not (isinstance(value, list)
                    and all(isinstance(v, str) for v in value)):
                problems.append(f"{here}: must be a list of property names")
        elif key == "properties":
            if not isinstance(value, dict):
                problems.append(f"{here}: must be an object")
            else:
                for name, sub in value.items():
                    problems += schema_problems(sub, f"{here}/{name}")
        elif key == "additionalProperties":
            if not isinstance(value, bool):
                problems += schema_problems(value, here)
        elif key == "items":
            problems += schema_problems(value, here)
        elif key == "enum":
            if not isinstance(value, list) or not value:
                problems.append(f"{here}: must be a non-empty list")
        elif key == "pattern":
            try:
                re.compile(value)
            except (re.error, TypeError) as exc:
                problems.append(f"{here}: invalid pattern: {exc}")
        elif key in ("minLength", "minItems"):
            if type(value) is not int or value < 0:
                problems.append(f"{here}: must be a non-negative integer")
        elif key == "format":
            if value not in FORMATS:
                problems.append(f"{here}: unsupported format {value!r} "
                                "(the subset validator fails closed)")
        elif key == "x-defang":
            if value not in DEFANG_MODES:
                problems.append(f"{here}: x-defang must be one of "
                                f"{', '.join(DEFANG_MODES)}, not {value!r}")
    return problems


def type_ok(value, name):
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return type(value) is int
    if name == "number":
        return type(value) in (int, float)
    return value is None


def same(a, b):
    """JSON equality: true is not 1."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    return a == b


def iter_strings(value, path):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, sub in value.items():
            yield from iter_strings(sub, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        for i, sub in enumerate(value):
            yield from iter_strings(sub, f"{path}[{i}]")


def validate(value, schema, path, errors, artifacts):
    """Validate value against schema; collect x-defang values in artifacts."""
    where = path or "(front matter)"
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(type_ok(value, n) for n in names):
            errors.append(f"{where}: expected type {'/'.join(names)}")
            return
    if "const" in schema and not same(value, schema["const"]):
        errors.append(f"{where}: must equal {schema['const']!r}")
    if "enum" in schema and not any(same(value, e) for e in schema["enum"]):
        errors.append(f"{where}: must be one of {schema['enum']!r}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{where}: shorter than {schema['minLength']} characters")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{where}: does not match pattern {schema['pattern']!r}")
        if schema.get("format") == "date":
            try:
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                    raise ValueError
                datetime.date.fromisoformat(value)
            except ValueError:
                errors.append(f"{where}: not a date (YYYY-MM-DD)")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{where}: fewer than {schema['minItems']} items")
        if "items" in schema:
            for i, item in enumerate(value):
                validate(item, schema["items"], f"{path}[{i}]", errors, artifacts)
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{where}: required property {name!r} is missing")
        extra = schema.get("additionalProperties", True)
        for name, sub in value.items():
            sub_path = f"{path}.{name}" if path else name
            if name in props:
                validate(sub, props[name], sub_path, errors, artifacts)
            elif extra is False:
                errors.append(f"{sub_path}: property not allowed by the schema")
            elif isinstance(extra, dict):
                validate(sub, extra, sub_path, errors, artifacts)
    if "x-defang" in schema:
        mode = schema["x-defang"]
        for sub_path, text in iter_strings(value, path):
            artifacts.append((sub_path, text))
            for problem in defang_problems(text, mode):
                errors.append(f"{sub_path}: not defanged ({mode}): {problem}: "
                              f"{show(text)}")


# ---------------------------------------------------------------------------
# Records

# content/<section>/ -> schema file. A record section that is not listed
# here fails closed: it has no schema, so nothing would check it.
RECORD_SCHEMAS = {
    "reports": "report.schema.json",
    "campaigns": "campaign.schema.json",
}
FRONT_MATTER = re.compile(r"\+\+\+[ \t]*\r?\n(.*?)\r?\n\+\+\+[ \t]*(?:\r?\n|\Z)", re.S)


def plain(value):
    """TOML values as JSON values: dates and times become ISO strings."""
    if isinstance(value, (datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    return value


class Record:
    def __init__(self, rel, data, body, body_line):
        self.rel = rel
        self.data = data
        self.body = body
        self.body_line = body_line
        self.artifacts = []  # (path, defanged value)


def load_schemas(schema_dir, findings):
    schemas = {}
    for section, name in RECORD_SCHEMAS.items():
        path = schema_dir / name
        where = f"schema/{name}"
        try:
            schema = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            findings.add(where, f"missing schema for content/{section}/")
            continue
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            findings.add(where, f"cannot read the schema: {exc}")
            continue
        problems = schema_problems(schema, "#")
        for problem in problems:
            findings.add(where, problem)
        if not problems:
            schemas[section] = schema
    return schemas


def load_records(root, schema_dir, findings):
    """Parse and validate every record. Returns the records that parsed."""
    schemas = load_schemas(schema_dir, findings)
    content = root / "content"
    records = []
    if not content.is_dir():
        return records
    for path in sorted(p for p in content.rglob("*") if not p.is_dir()):
        rel = path.relative_to(root).as_posix()
        parts = path.relative_to(content).parts
        if len(parts) == 1:
            continue  # a page at the top of content/, not a record
        section = parts[0]
        if section not in RECORD_SCHEMAS:
            findings.add(rel, f"no schema is mapped to the record directory "
                              f"content/{section}/ (fails closed; mapped: "
                              f"{', '.join(sorted(RECORD_SCHEMAS))})")
            continue
        if len(parts) != 2 or path.suffix != ".md":
            findings.add(rel, f"unexpected file in content/{section}/: a record "
                              f"is content/{section}/<slug>.md")
            continue
        if path.name == "_index.md":
            continue  # the section page, not a record
        try:
            text = path.read_text(encoding="utf-8").removeprefix("\ufeff")
        except (OSError, UnicodeDecodeError) as exc:
            findings.add(rel, f"cannot read the record: {exc}")
            continue
        match = FRONT_MATTER.match(text)
        if not match:
            findings.add(rel, "front matter must be TOML between +++ lines "
                              "at the top of the file")
            continue
        try:
            data = plain(tomllib.loads(match.group(1)))
        except tomllib.TOMLDecodeError as exc:
            findings.add(rel, f"front matter is not valid TOML: {exc}")
            continue
        body_line = text.count("\n", 0, match.end()) + 1
        record = Record(rel, data, text[match.end():], body_line)
        if section in schemas:
            errors = []
            validate(data, schemas[section], "", errors, record.artifacts)
            for error in errors:
                findings.add(rel, error)
        records.append(record)
    return records


def live_forms(records):
    """(folded live form, record, path, defanged value) for every artifact
    whose live form differs from what is stored."""
    forms = []
    for record in records:
        for path, value in record.artifacts:
            live = refang(value)
            if norm(live) != norm(value):
                forms.append((norm(live), record, path, value))
    return forms


# SPEC section 5: record bodies carry no live URLs. Fails closed: a link in a
# code span or an escaped bracket is flagged too. URL_RULES also bind every
# front-matter string outside params.sources (plan decision 6).
BARE_URL = re.compile(r"([a-z][a-z0-9+.\-]*)://")
URL_RULES = [
    (BARE_URL, "bare URL"),
    # //host: a protocol-relative URL (a scheme's // is excluded).
    (re.compile(r"(?<![\w:/])//[^\s/]"), "protocol-relative URL"),
]
BODY_LINE_RULES = URL_RULES + [
    (re.compile(rf"(?<![\w-])www{DOT}"), "bare www. address"),
    (re.compile(r"(?<![a-z0-9])(?:mailto|javascript):"), "bare mailto:/javascript: URL"),
    (LIVE_IPV4, "live IPv4 address"),
    (re.compile(r"\]\("), "Markdown link or image"),
    (re.compile(r"\]\["), "Markdown reference link"),
    (re.compile(r"<[^<>\s]*[:@][^<>\s]*>"), "<...> autolink"),
    # Shortcodes render template output into the body ({{% param %}},
    # {{< figure link= >}}), which this check cannot see.
    (re.compile(r"\{\{[<%]"), "Hugo shortcode"),
]
# Run on the whole body: a definition label may span lines and hold \].
BODY_WHOLE_RULES = [
    (re.compile(r"\[(?!\^)(?:\\.|[^\]\\])*\]:"), "Markdown link reference definition"),
]
# hxxp/hxxps as the whole scheme or after punctuation: (hxxps:// and -hxxps://
# are defanged, a letter before it (xhxxps://, 1https://) is not.
DEFANGED_SCHEME = re.compile(r"(?:^|[^a-z])hxxps?$")


def rule_labels(variant, rules):
    """(label, offset) for every rule that matches the folded text."""
    found = []
    for rule, label in rules:
        for match in rule.finditer(variant):
            if label == "bare URL" and DEFANGED_SCHEME.search(match.group(1)):
                # A defanged scheme still needs a defanged host after it.
                token = re.split(r"\s", variant[match.start():], maxsplit=1)[0]
                if not defang_problems(token, "host"):
                    continue
                label = "half-defanged URL (live host after hxxp)"
            found.append((label, match.start()))
    return found


def body_problems(record):
    found = {}
    for offset, line in enumerate(record.body.split("\n")):
        for variant in text_variants(line):
            for label, _ in rule_labels(variant, BODY_LINE_RULES):
                found.setdefault((record.body_line + offset, label), None)
    for variant in text_variants(record.body):
        for label, pos in rule_labels(variant, BODY_WHOLE_RULES):
            line = record.body_line + variant.count("\n", 0, pos)
            found.setdefault((line, label), None)
    return [f"line {line}: body contains a {label}; record bodies carry no bare "
            "URLs, Markdown links or autolinks, live links belong in sources "
            "(SPEC section 5)" for line, label in sorted(found)]


def front_matter_problems(record):
    """Live URLs in front matter belong only in params.sources (decision 6)."""
    problems = []
    for path, text in iter_strings(record.data, ""):
        if path == "params.sources" or path.startswith(("params.sources.",
                                                        "params.sources[")):
            continue
        if (path, text) in record.artifacts:
            continue  # checked by its x-defang mode
        labels = []
        for variant in text_variants(text):
            for label, _ in rule_labels(variant, URL_RULES):
                if label not in labels:
                    labels.append(label)
        for label in labels:
            problems.append(f"{path}: front matter string contains a {label}; "
                            "live links belong only in params.sources (D8)")
    return problems


def cmd_records(args):
    root = Path(args.root).resolve()
    schema_dir = Path(args.schemas).resolve() if args.schemas else root / "schema"
    if not root.is_dir():
        raise UsageError(f"--root {root} is not a directory")
    findings = Findings()
    records = load_records(root, schema_dir, findings)
    for record in records:
        for problem in body_problems(record) + front_matter_problems(record):
            findings.add(record.rel, problem)
    forms = live_forms(records)
    for live, origin, path, value in forms:
        for record in records:
            for spath, text in iter_strings(record.data, ""):
                if (spath, text) in record.artifacts:
                    continue  # artifact fields carry the defanged form
                if any(live in v for v in text_variants(text)):
                    findings.add(record.rel, f"{spath}: the live form of artifact "
                                 f"{show(value)} ({origin.rel}: {path}) appears "
                                 "here (R2)")
            if any(live in v for v in text_variants(record.body)):
                findings.add(record.rel, f"body: the live form of artifact "
                             f"{show(value)} ({origin.rel}: {path}) appears "
                             "here (R2)")
    n_reports = sum(r.rel.startswith("content/reports/") for r in records)
    n_artifacts = sum(len(r.artifacts) for r in records)
    return findings.report(
        f"records checked: {len(records)} (reports {n_reports}, campaigns "
        f"{len(records) - n_reports}), artifacts: {n_artifacts}")


# ---------------------------------------------------------------------------
# Site

# Element -> attributes whose URL the browser fetches without a click.
# <a href> is absent on purpose: a click is a navigation, not a request.
REQUEST_ATTRS = {
    "script": ("src",),
    "link": ("href", "imagesrcset"),
    "img": ("src", "srcset", "lowsrc"),
    "source": ("src", "srcset"),
    "video": ("src", "poster"),
    "audio": ("src",),
    "track": ("src",),
    "iframe": ("src",),
    "frame": ("src",),
    "embed": ("src",),
    "object": ("data", "codebase"),
    "portal": ("src",),
    "html": ("manifest",),
    # SVG inside HTML; html.parser lowercases tag names.
    "image": ("href", "xlink:href"),
    "use": ("href", "xlink:href"),
    "feimage": ("href", "xlink:href"),
}
# Space-separated URL lists.
URL_LIST_ATTRS = {("a", "ping"), ("area", "ping")}
SRCSET_ATTRS = {"srcset", "imagesrcset"}
SAME_ORIGIN = re.compile(r"(?i)^https://interviewscam\.com(?:[/?#]|$)")
HAS_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")
HTML_SUFFIXES = {".html", ".htm", ".xhtml"}
# XML outputs (sitemap, M3 feeds, XSL) get no CSP on Pages, so every
# attribute and every <?xml-stylesheet?> counts, as in an SVG file.
XML_SUFFIXES = {".svg", ".xml", ".xsl", ".xslt", ".rss", ".atom"}


C0_AND_SPACE = "".join(map(chr, range(0x21)))


def leaves_origin(url):
    """True when url names another origin or a scheme other than ours."""
    # The WHATWG URL parser drops tabs and newlines anywhere and strips
    # every C0 control and space at both ends.
    url = re.sub(r"[\t\n\r]", "", url).strip(C0_AND_SPACE)
    if re.match(r"^[/\\]{2}", url):
        return True  # protocol-relative
    if HAS_SCHEME.match(url):
        return not SAME_ORIGIN.match(url)
    return False


def srcset_urls(value):
    return [c.strip().split()[0] for c in value.split(",") if c.strip()]


# A comment opener inside a string is not a comment, so strings are matched
# first and kept; an unclosed comment runs to the end of the sheet.
CSS_COMMENT_OR_STRING = re.compile(r"""(["'])(?:\\.|(?!\1)[^\\])*\1|/\*.*?(?:\*/|\Z)""", re.S)
CSS_ESCAPE = re.compile(r"\\(?:([0-9a-fA-F]{1,6})[ \t\r\n\f]?|(.))", re.S)
CSS_URL = re.compile(r"(?i)url\(\s*(?:(['\"])(.*?)\1|([^)\s'\"]*))\s*\)", re.S)
CSS_STRING = re.compile(r"(['\"])(.*?)\1", re.S)


def css_unescape(css):
    """CSS escapes decoded: \\69 and \\i are both an "i"."""
    def unescape(match):
        if match.group(1):
            try:
                return chr(int(match.group(1), 16))
            except (ValueError, OverflowError):
                return "\ufffd"
        return match.group(2)
    return CSS_ESCAPE.sub(unescape, css)


def css_decode(css):
    css = CSS_COMMENT_OR_STRING.sub(lambda m: m.group(0) if m.group(1) else "", css)
    return css_unescape(css)


def css_urls(css):
    """Every url(...) target and quoted string (@import, image-set, src)."""
    css = css_decode(css)
    urls = [m.group(2) if m.group(1) else m.group(3) for m in CSS_URL.finditer(css)]
    urls += [m.group(2) for m in CSS_STRING.finditer(css)]
    return urls


JS_URL = re.compile(r"""(['"`])\s*((?:[a-zA-Z][a-zA-Z0-9+.\-]*:)?//[^'"`\s]*)""")


class Page(html.parser.HTMLParser):
    """Start tags (with their first-wins attributes), text and style blocks."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.elements = []  # (tag, {attr: value})
        self.text = []
        self.styles = []
        self.pis = []
        self.decls = []
        self._in_style = False

    def _element(self, tag, attrs):
        first = {}
        for name, value in attrs:
            first.setdefault(name, value if value is not None else "")
        self.elements.append((tag, first))

    def handle_starttag(self, tag, attrs):
        self._element(tag, attrs)
        self._in_style = tag == "style"

    def handle_startendtag(self, tag, attrs):
        self._element(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "style":
            self._in_style = False

    def handle_data(self, data):
        (self.styles if self._in_style else self.text).append(data)

    def handle_pi(self, data):
        self.pis.append(data)

    def handle_decl(self, decl):
        self.decls.append(decl)


def parse_page(text):
    page = Page()
    page.feed(text)
    page.close()
    return page


def html_request_problems(page):
    problems = []
    for tag, attrs in page.elements:
        if tag == "base":
            problems.append("<base> element (it re-targets every relative URL)")
        names = list(REQUEST_ATTRS.get(tag, ())) + ["background"]
        if tag == "input" and attrs.get("type", "").strip().lower() == "image":
            names.append("src")
        for name in names:
            if name not in attrs:
                continue
            urls = srcset_urls(attrs[name]) if name in SRCSET_ATTRS else [attrs[name]]
            for url in urls:
                if leaves_origin(url):
                    problems.append(f"<{tag} {name}> loads {show(url)}")
        for (ptag, pname) in URL_LIST_ATTRS:
            if tag == ptag and pname in attrs:
                for url in attrs[pname].split():
                    if leaves_origin(url):
                        problems.append(f"<{tag} {pname}> pings {show(url)}")
        if "srcdoc" in attrs:
            problems.append(f"<{tag} srcdoc> (an embedded document; fails closed)")
        if tag == "meta" and attrs.get("http-equiv", "").strip().lower() == "refresh":
            target = re.split(r"[;,]", attrs.get("content", ""), maxsplit=1)
            if len(target) == 2:
                url = re.sub(r"(?i)^\s*url\s*=\s*", "", target[1]).strip().strip("'\"")
                if leaves_origin(url):
                    problems.append(f"<meta http-equiv=refresh> to {show(url)}")
        if "style" in attrs:
            for url in css_urls(attrs["style"]):
                if leaves_origin(url):
                    problems.append(f"<{tag} style> loads {show(url)}")
    for block in page.styles:
        for url in css_urls(block):
            if leaves_origin(url):
                problems.append(f"<style> loads {show(url)}")
    return problems


def svg_request_problems(page):
    """In an SVG or XML file every attribute counts, except namespace
    declarations, and so do processing instructions and declarations."""
    problems = []
    for tag, attrs in page.elements:
        for name, value in attrs.items():
            if name == "xmlns" or name.startswith("xmlns:"):
                continue
            if name == "style":
                urls = css_urls(value)
            else:
                urls = [value]
            for url in urls:
                if leaves_origin(url):
                    problems.append(f"<{tag} {name}> loads {show(url)}")
    for block in page.styles:
        for url in css_urls(block):
            if leaves_origin(url):
                problems.append(f"<style> loads {show(url)}")
    for item in page.pis + page.decls:
        for match in re.finditer(r"""(['"])(.*?)\1""", item):
            if leaves_origin(match.group(2)):
                problems.append(f"<?...?>/<!...> declaration references "
                                f"{show(match.group(2))}")
    return problems


CSP_SOURCES = {"'self'", "'none'"}
CSP_REPORTING = {"report-uri", "report-to"}


def csp_problems(policy):
    """A policy may only use 'self' and 'none', and must set default-src."""
    problems = []
    seen = set()
    for directive in (d.strip() for d in policy.split(";")):
        if not directive:
            continue
        name, *sources = directive.split()
        name = name.lower()
        if name in seen:
            problems.append(f"duplicate CSP directive {name}")
        seen.add(name)
        if name in CSP_REPORTING:
            problems.append(f"CSP reporting directive {name} sends requests")
        for source in sources:
            if source.lower() not in CSP_SOURCES:
                problems.append(f"CSP source not allowed in {name}: {show(source)} "
                                "(only 'self' and 'none' are)")
    if "default-src" not in seen:
        problems.append("CSP has no default-src")
    return problems


def csp_position_problems(page, csp):
    problems = []
    metas = [attrs for tag, attrs in page.elements
             if tag == "meta"
             and attrs.get("http-equiv", "").strip().lower() == "content-security-policy"]
    if len(metas) != 1:
        problems.append(f"expected exactly one Content-Security-Policy meta, found "
                        f"{len(metas)}")
    head = [(tag, attrs) for tag, attrs in page.elements if tag not in ("html", "head")]
    if not head or head[0][0] != "meta" or "charset" not in head[0][1]:
        problems.append("the first element in <head> must be <meta charset>")
    elif len(head) < 2 or head[1][1].get("http-equiv", "").strip().lower() \
            != "content-security-policy":
        problems.append("the Content-Security-Policy meta is not the first element "
                        "after <meta charset>")
    for attrs in metas:
        if attrs.get("content", "") != csp:
            problems.append("the Content-Security-Policy meta does not equal "
                            "params.csp in hugo.toml")
    return problems


# ---------------------------------------------------------------------------
# CSS structure: just enough of a parser for the .visually-hidden rule and the
# named-colour scan. Strings, escapes and parentheses are kept intact, so a
# brace or semicolon inside them does not end a block.

class CssRule:
    def __init__(self, parents, prelude, declarations):
        self.parents = parents  # preludes of the enclosing blocks, outermost first
        self.prelude = prelude  # selector list or at-rule prelude, comments removed
        self.declarations = declarations  # raw declaration texts, in order


def css_rules(css):
    """Every block of a stylesheet as a CssRule, comments removed. A statement
    outside any block (@import ...;) comes back as a rule with that statement
    as prelude, no parents and no declarations. Unbalanced braces never raise:
    a stray } is ignored and an unclosed block ends with the sheet."""
    text = CSS_COMMENT_OR_STRING.sub(lambda m: m.group(0) if m.group(1) else " ", css)
    rules, stack, buf = [], [], []
    depth, i, n = 0, 0, len(text)

    def flush():
        item = "".join(buf).strip()
        buf.clear()
        if not item:
            return
        if stack:
            stack[-1][1].append(item)
        else:
            rules.append(CssRule((), item, []))

    while i < n:
        ch = text[i]
        if ch == "\\":
            buf.append(text[i:i + 2])
            i += 2
            continue
        if ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            buf.append(text[i:j + 1])
            i = j + 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if depth == 0 and ch == "{":
            prelude = "".join(buf).strip()
            buf.clear()
            stack.append((prelude, []))
        elif depth == 0 and ch == ";":
            flush()
        elif depth == 0 and ch == "}":
            flush()
            if stack:
                prelude, declarations = stack.pop()
                rules.append(CssRule(tuple(p for p, _ in stack), prelude, declarations))
        else:
            buf.append(ch)
        i += 1
    flush()
    while stack:
        prelude, declarations = stack.pop()
        rules.append(CssRule(tuple(p for p, _ in stack), prelude, declarations))
    return rules


def css_declaration(text):
    """(property, value) of a declaration text, property lowercased."""
    name, sep, value = text.partition(":")
    if not sep:
        return "", text
    return css_unescape(name).strip().lower(), value


# ADR-0003 part 6: the one sanctioned utility class. The reflow check exempts
# elements that carry it while their box is at most 1 x 1 px and their
# display is not contents. What this rule enforces: across ALL the site's
# CSS the class has exactly one top-level definition with the pinned
# hiding declarations and at most one :focus/:focus-visible reveal, both
# entirely !important; !important appears nowhere else; no attribute
# selector on `class` (it could match the class without naming it); inline
# style is banned by rule (c).
VISUALLY_HIDDEN = "visually-hidden"
VISUALLY_HIDDEN_WORD = re.compile(r"(?i)visually-hidden")
VH_DEFINITION = ".visually-hidden"
VH_REVEAL = {".visually-hidden:focus", ".visually-hidden:focus-visible"}
# The hiding pattern: a 1 x 1 px absolutely positioned box that clips its
# content and keeps it on one line. Each is required with exactly this value.
VH_REQUIRED = {
    # Pinned so `display: contents` (no box, text still painted) cannot
    # apply; an absolutely positioned box is blockified anyway.
    "display": "block",
    "position": "absolute",
    "width": "1px",
    "height": "1px",
    "overflow": "hidden",
    "clip-path": "inset(50%)",
    "white-space": "nowrap",
}
# Allowed in the definition with any value: they only shrink or reset the box,
# and the runtime 1 x 1 px check in reflow catches a value that grows it.
VH_OPTIONAL = {"margin", "padding", "border", "clip"}
IMPORTANT = re.compile(r"(?i)!\s*important")
CLASS_ATTRIBUTE_SELECTOR = re.compile(r"(?i)\[\s*(?:[\w*-]*\|)?class\s*(?:[~|^$*]?=|\])")


def css_selector_text(prelude):
    return re.sub(r"\s+", " ", css_unescape(prelude)).strip()


def css_value_text(value):
    """A declaration value as compared: unescaped, !important removed,
    lowercased, whitespace collapsed and trimmed inside parentheses."""
    value = IMPORTANT.sub("", css_unescape(value)).strip().lower()
    value = re.sub(r"\s+", " ", value)
    return re.sub(r"\(\s*", "(", re.sub(r"\s*\)", ")", value))


class CssRuleResult:
    def __init__(self):
        self.problems = []
        self.definitions = 0
        self.reveals = 0


def css_rule_problems(css):
    """The .visually-hidden and !important rule (ADR-0003 part 6) on one
    stylesheet. The caller adds up definitions and reveals across files."""
    result = CssRuleResult()
    problems = result.problems
    attributed = 0
    for rule in css_rules(css):
        selector = css_selector_text(rule.prelude)
        top_level = not rule.parents
        is_definition = top_level and selector == VH_DEFINITION
        is_reveal = top_level and all(p.strip() in VH_REVEAL for p in selector.split(","))
        if not selector.startswith("@") and CLASS_ATTRIBUTE_SELECTOR.search(selector):
            problems.append(f"{show(selector)}: attribute selector on class; select "
                            "by class name (it could match .visually-hidden without "
                            "naming it)")
        if is_definition or is_reveal:
            result.definitions += is_definition
            result.reveals += is_reveal
            seen = {}
            for declaration in rule.declarations:
                found = len(IMPORTANT.findall(css_unescape(declaration)))
                attributed += found
                if not found:
                    problems.append(f"{show(selector)}: declaration {show(declaration)} "
                                    "is not !important; every declaration of the "
                                    ".visually-hidden definition and its reveal is, so "
                                    "only they win the cascade")
                prop, value = css_declaration(declaration)
                if prop in seen:
                    problems.append(f"{show(selector)}: {prop} is declared twice")
                seen[prop] = css_value_text(value)
            if is_definition:
                for prop, value in seen.items():
                    if prop not in VH_REQUIRED and prop not in VH_OPTIONAL:
                        problems.append(f"{show(selector)}: {prop} is not part of the "
                                        "hiding pattern")
                for prop, want in VH_REQUIRED.items():
                    if seen.get(prop) != want:
                        problems.append(f"{show(selector)}: the definition needs "
                                        f"{prop}: {want} !important (found "
                                        f"{show(seen.get(prop, 'nothing'))}); it must "
                                        "provably hide")
            continue
        if VISUALLY_HIDDEN_WORD.search(selector) or any(
                VISUALLY_HIDDEN_WORD.search(css_unescape(p)) for p in rule.parents):
            inside = "".join(f" inside {show(css_selector_text(p))}" for p in rule.parents)
            problems.append(f"{show(selector)}{inside}: .visually-hidden may appear only "
                            "in its one top-level definition and its :focus/"
                            ":focus-visible reveal (not nested in @media, @container "
                            "or @supports, not in a compound or descendant selector)")
        for declaration in rule.declarations:
            decoded = css_unescape(declaration)
            if VISUALLY_HIDDEN_WORD.search(decoded):
                problems.append(f"{show(selector)}: declaration {show(declaration)} "
                                "names visually-hidden outside its definition")
            found = len(IMPORTANT.findall(decoded))
            attributed += found
            if found:
                problems.append(f"{show(selector)}: !important outside the "
                                ".visually-hidden definition and its reveal "
                                f"({show(declaration)})")
    # Fail closed: an !important the block walk did not attribute to a
    # declaration (in a selector, an at-rule prelude, a stray statement).
    stripped = CSS_COMMENT_OR_STRING.sub(lambda m: m.group(0) if m.group(1) else " ", css)
    total = len(IMPORTANT.findall(css_unescape(stripped)))
    if total > attributed:
        problems.append(f"!important outside any declaration ({total - attributed} "
                        "occurrence(s)); it is allowed only in the .visually-hidden "
                        "definition and its reveal")
    return result


# ---------------------------------------------------------------------------
# Markup rules of the built site (PR 3 of milestone 2, ADR-0003 parts 3 and 6)

FORM_ATTRS = {("form", "action"), ("button", "formaction"), ("input", "formaction")}
URL_ATTRS = ("href", "src", "action", "formaction", "xlink:href", "data")
JSON_LD = "application/ld+json"


def url_scheme(url):
    """The scheme of url as a browser reads it (tabs, newlines and edge C0
    controls dropped, lowercased), or ""."""
    url = re.sub(r"[\t\n\r]", "", url).strip(C0_AND_SPACE)
    match = HAS_SCHEME.match(url)
    return match.group(0)[:-1].lower() if match else ""


def own_path(rel):
    """The site path of a file under public/ (posix, relative)."""
    if rel == "index.html":
        return "/"
    if rel.endswith("/index.html"):
        return "/" + rel[:-len("index.html")]
    return "/" + rel


def markup_problems(page, rel):
    """Rules (a) to (e) on one HTML page; rel is its path under public/."""
    problems = []
    canonicals = []
    for tag, attrs in page.elements:
        # (a) A form never submits to another origin or scheme.
        for (ftag, fattr) in FORM_ATTRS:
            if tag == ftag and fattr in attrs and leaves_origin(attrs[fattr]):
                problems.append(f"(a) <{tag} {fattr}> submits to "
                                f"{show(attrs[fattr])}, another origin")
        # (b) No web manifest until its icons[].src are request-scanned.
        rels = attrs.get("rel", "").lower().split()
        if tag == "link" and "manifest" in rels:
            problems.append("(b) <link rel=manifest>: a web manifest fails closed "
                            "until its icons are request-scanned")
        # (c) The CSP (style-src 'self', script-src 'self') blocks inline
        # styles and scripts silently: dead styling, dead behaviour.
        if "style" in attrs:
            problems.append(f"(c) <{tag} style> attribute: inline styles are "
                            "blocked by the CSP; use a class in the stylesheet")
        if tag == "style":
            problems.append("(c) <style> element: inline styles are blocked by the "
                            "CSP; use the stylesheet")
        if tag == "script" and not attrs.get("src", "").strip() \
                and attrs.get("type", "").strip().lower() != JSON_LD:
            problems.append("(c) inline <script> without src: blocked by the CSP; "
                            "use one first-party file")
        for name in attrs:
            if name.startswith("on"):
                problems.append(f"(c) <{tag} {name}> event-handler attribute: "
                                "blocked by the CSP")
        for name in URL_ATTRS:
            if name not in attrs:
                continue
            scheme = url_scheme(attrs[name])
            if scheme == "javascript":
                problems.append(f"(c) <{tag} {name}> is a javascript: URL")
            # (e) No mailto: link anywhere: the address is plain text (SPEC
            # section 7, issue #3 STOP 1 decision 6).
            if scheme == "mailto" and name not in ("src", "data"):
                problems.append(f"(e) <{tag} {name}> is a mailto: URL; show the "
                                "address as plain text")
        if tag == "link" and "canonical" in rels:
            canonicals.append(attrs.get("href", ""))
        # (h) wrap=off keeps a textarea's lines from wrapping; its text has
        # no DOM range, so reflow could only see it through (5).
        if tag == "textarea" and attrs.get("wrap", "").strip().lower() == "off":
            problems.append("(h) <textarea wrap=off>: the text cannot wrap at 320 px")
        # (g) SVG animation can set an href (mailto:, javascript:) or a colour
        # at run time, which no static check here reads.
        if tag in SMIL_ELEMENTS:
            problems.append(f"(g) SMIL animation element <{tag}>: it can set any "
                            "attribute at run time")
    # (d) Canonical tags (ADR-0003 part 3).
    if rel == "404.html":
        if canonicals:
            problems.append("(d) 404.html has a canonical link; it answers for every "
                            "missing URL, so it has none")
        return problems
    want = SITE_ORIGIN + own_path(rel)
    if len(canonicals) != 1:
        problems.append(f"(d) {len(canonicals)} <link rel=canonical>, exactly one is "
                        f"needed: {show(want)}")
    for href in canonicals:
        if href == want:
            continue
        if not HAS_SCHEME.match(href.strip()):
            problems.append(f"(d) canonical {show(href)} is relative; it must be "
                            f"the absolute {show(want)}")
        else:
            problems.append(f"(d) canonical {show(href)} is not this page's own "
                            f"URL {show(want)}")
    return problems


def json_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, sub in value.items():
            yield key
            yield from json_strings(sub)
    elif isinstance(value, list):
        for sub in value:
            yield from json_strings(sub)


def cmd_site(args):
    root = Path(args.records).resolve()
    public = Path(args.public).resolve()
    schema_dir = Path(args.schemas).resolve() if args.schemas else root / "schema"
    if not public.is_dir():
        raise UsageError(f"{public} is not a directory (build the site first)")
    findings = Findings()

    try:
        config = tomllib.loads((root / "hugo.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise UsageError(f"cannot read {root / 'hugo.toml'}: {exc}") from exc
    csp = config.get("params", {}).get("csp")
    if not isinstance(csp, str) or not csp.strip():
        findings.add("hugo.toml", "params.csp is missing")
        csp = None
    else:
        for problem in csp_problems(csp):
            findings.add("hugo.toml: params.csp", problem)

    record_findings = Findings()
    records = load_records(root, schema_dir, record_findings)
    for item in record_findings.items:
        findings.items.append(item + " (records loaded for the built-defang scan)")
    forms = live_forms(records)

    allowed = token_colors(root)
    vh_definitions = vh_reveals = 0
    vh_used = []
    n_html = 0
    files = sorted(p for p in public.rglob("*") if p.is_file())
    for path in files:
        rel = "public/" + path.relative_to(public).as_posix()
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        suffix = path.suffix.lower()
        scans = []
        if suffix == ".webmanifest":
            findings.add(rel, "(b) a web manifest fails closed until its icons are "
                         "request-scanned")
        if text is None:
            lowered = data.lower()
            for live, origin, apath, value in forms:
                if live.encode("utf-8") in lowered:
                    findings.add(rel, f"the live form of artifact {show(value)} "
                                 f"({origin.rel}: {apath}) appears in the built "
                                 "site (R3)")
            continue
        unescaped = html.unescape(text)
        scans += [text, unescaped, urllib.parse.unquote(unescaped)]
        if suffix in HTML_SUFFIXES or suffix in XML_SUFFIXES:
            page = parse_page(text)
            joined = "".join(page.text)
            scans += [joined, urllib.parse.unquote(joined)]
            for _, attrs in page.elements:
                for value in attrs.values():
                    scans += [value, urllib.parse.unquote(value)]
            if suffix in HTML_SUFFIXES:
                n_html += 1
                for problem in html_request_problems(page):
                    findings.add(rel, f"third-party request: {problem} (D9)")
                if csp is not None:
                    for problem in csp_position_problems(page, csp):
                        findings.add(rel, f"CSP: {problem}")
                for tag, attrs in page.elements:
                    if tag == "meta" and attrs.get("http-equiv", "").strip().lower() \
                            == "content-security-policy":
                        for problem in csp_problems(attrs.get("content", "")):
                            findings.add(rel, problem)
                for problem in markup_problems(page, path.relative_to(public).as_posix()):
                    findings.add(rel, problem)
                if any(VISUALLY_HIDDEN in attrs.get("class", "").split()
                       for _, attrs in page.elements):
                    vh_used.append(rel)
            else:
                for problem in svg_request_problems(page):
                    findings.add(rel, f"third-party request: {problem} (D9)")
                for tag, _ in page.elements:
                    if tag in SMIL_ELEMENTS:
                        findings.add(rel, f"(g) SMIL animation element <{tag}>: it can "
                                     "set any attribute at run time")
            for problem in markup_color_problems(page, allowed, smil=False):
                findings.add(rel, f"(f) {problem}; colours come only from "
                             "data/tokens.toml")
        elif suffix == ".css":
            for url in css_urls(text):
                if leaves_origin(url):
                    findings.add(rel, f"third-party request: CSS loads {show(url)} (D9)")
            result = css_rule_problems(text)
            vh_definitions += result.definitions
            vh_reveals += result.reveals
            for problem in result.problems:
                findings.add(rel, f"CSS: {problem} (ADR-0003 part 6)")
            for problem in css_color_problems(text, allowed):
                findings.add(rel, f"(f) {problem}; colours come only from "
                             "data/tokens.toml")
        elif suffix in (".js", ".mjs"):
            for match in JS_URL.finditer(text):
                if leaves_origin(match.group(2)):
                    findings.add(rel, f"third-party request: script URL literal "
                                 f"{show(match.group(2))} (D9)")
        if suffix == ".json":
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                findings.add(rel, f"not valid JSON: {exc}")
            else:
                for string in json_strings(parsed):
                    scans += [string, urllib.parse.unquote(string)]
        folded = [norm(s) for s in scans]
        for live, origin, apath, value in forms:
            if any(live in s for s in folded):
                findings.add(rel, f"the live form of artifact {show(value)} "
                             f"({origin.rel}: {apath}) appears in the built site (R3)")
    # Counted across ALL built CSS: a second file could otherwise redefine
    # the class with its own, equally !important, rule.
    if vh_definitions > 1:
        findings.add("public", f"CSS: {vh_definitions} top-level .visually-hidden "
                     "definitions across the built CSS; exactly one is allowed "
                     "(ADR-0003 part 6)")
    if vh_reveals > 1:
        findings.add("public", f"CSS: {vh_reveals} .visually-hidden reveal rules across "
                     "the built CSS; at most one is allowed (ADR-0003 part 6)")
    if vh_used and vh_definitions == 0:
        findings.add(vh_used[0], "CSS: the page uses class visually-hidden, but no "
                     "built CSS defines it (ADR-0003 part 6)")
    if n_html == 0:
        findings.add("public", "no HTML pages found; nothing was checked")
    return findings.report(
        f"site checked: {len(files)} files, {n_html} HTML pages, "
        f"{len(forms)} artifact live forms scanned")


# ---------------------------------------------------------------------------
# Design tokens (SPEC section 7): data/tokens.toml is the only place a colour
# value may appear, and every listed pair is contrast-checked.

TOKENS_FILE = "data/tokens.toml"
TOKEN_KEY = re.compile(r"[a-z][a-z0-9_]*")
TOKEN_COLOR = re.compile(r"#[0-9A-Fa-f]{6}(?:[0-9A-Fa-f]{2})?")
# WCAG 2.2: SC 1.4.3 (text 4.5:1, large text 3:1) and SC 1.4.11 (non-text 3:1).
CONTRAST_MIN = {"text": decimal.Decimal("4.5"), "large_text": decimal.Decimal("3"),
                "non_text": decimal.Decimal("3")}
PAIR_KEYS = {"fg", "bg", "kind", "ratio", "use"}
# Tables of positive numbers (CSS px, weights, line-height factors) and of
# font stacks; any other top-level key fails closed.
TOKEN_NUMBER_TABLES = {"weight", "type", "line_height", "space", "layout", "radius",
                       "target", "focus", "border", "shadow", "underline"}
TOKEN_STRING_TABLES = {"font"}

# Colour literals outside the tokens file: hex (not an &#123; entity, not
# followed by a word character) and colour functions, in every scanned file.
HEX_COLOR = re.compile(r"(?<!&)#(?:[0-9A-Fa-f]{8}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{3,4})(?!\w)")
COLOR_FUNCTION = re.compile(
    r"(?i)(?<![\w-])(rgba?|hsla?|hwb|lab|lch|oklab|oklch|color|color-mix|light-dark|"
    r"contrast-color|device-cmyk)\s*\(")
# CSS named colours (CSS Color 4) and system colours. currentcolor,
# transparent and the CSS-wide keywords are allowed. The deprecated system
# colour `background` is left out: it is also the property name that a
# `transition` list carries.
NAMED_COLORS = frozenset("""
aliceblue antiquewhite aqua aquamarine azure beige bisque black blanchedalmond
blue blueviolet brown burlywood cadetblue chartreuse chocolate coral
cornflowerblue cornsilk crimson cyan darkblue darkcyan darkgoldenrod darkgray
darkgreen darkgrey darkkhaki darkmagenta darkolivegreen darkorange darkorchid
darkred darksalmon darkseagreen darkslateblue darkslategray darkslategrey
darkturquoise darkviolet deeppink deepskyblue dimgray dimgrey dodgerblue
firebrick floralwhite forestgreen fuchsia gainsboro ghostwhite gold goldenrod
gray green greenyellow grey honeydew hotpink indianred indigo ivory khaki
lavender lavenderblush lawngreen lemonchiffon lightblue lightcoral lightcyan
lightgoldenrodyellow lightgray lightgreen lightgrey lightpink lightsalmon
lightseagreen lightskyblue lightslategray lightslategrey lightsteelblue
lightyellow lime limegreen linen magenta maroon mediumaquamarine mediumblue
mediumorchid mediumpurple mediumseagreen mediumslateblue mediumspringgreen
mediumturquoise mediumvioletred midnightblue mintcream mistyrose moccasin
navajowhite navy oldlace olive olivedrab orange orangered orchid palegoldenrod
palegreen paleturquoise palevioletred papayawhip peachpuff peru pink plum
powderblue purple rebeccapurple red rosybrown royalblue saddlebrown salmon
sandybrown seagreen seashell sienna silver skyblue slateblue slategray
slategrey snow springgreen steelblue tan teal thistle tomato turquoise violet
wheat white whitesmoke yellow yellowgreen
accentcolor accentcolortext activetext buttonborder buttonface buttontext
canvas canvastext field fieldtext graytext highlight highlighttext linktext
mark marktext selecteditem selecteditemtext visitedtext
activeborder activecaption appworkspace buttonhighlight buttonshadow
captiontext inactiveborder inactivecaption inactivecaptiontext infobackground
infotext menu menutext scrollbar threeddarkshadow threedface threedhighlight
threedlightshadow threedshadow window windowframe windowtext
""".split())
CSS_WORD = re.compile(r"(?<![\w-])[A-Za-z][\w-]*")
COLOR_ATTRS = {"fill", "stroke", "color", "stop-color", "flood-color", "lighting-color"}
# HTML's obsolete presentational colour attributes: banned outright.
PRESENTATIONAL_COLOR_ATTRS = {"bgcolor", "text", "link", "alink", "vlink"}
# SVG animation elements can set any attribute (a colour, an href) at run
# time, which no static value check reads: banned in the built site, rule (g).
SMIL_ELEMENTS = {"set", "animate", "animatetransform", "animatemotion", "animatecolor"}
VENDOR_VALUE = re.compile(r"(?i)(?<![\w-])-(?:webkit|moz|ms|o)-[\w-]+")
CSS_STRING_LITERAL = re.compile(r"""(["'])(?:\\.|(?!\1)[^\\])*\1""", re.S)
TEMPLATE_ACTION = re.compile(r"\{\{.*?\}\}", re.S)
MARKUP_SUFFIXES = {".html", ".htm", ".svg", ".xml"}
# Raster images cannot carry a CSS colour; any other file that is not UTF-8
# fails closed.
RASTER_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico"}


def srgb_luminance(hex_color):
    """WCAG 2.2 relative luminance of an opaque #RRGGBB colour."""
    channels = []
    for i in (1, 3, 5):
        c = int(hex_color[i:i + 2], 16) / 255
        channels.append(c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4)
    r, g, b = channels
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(a, b):
    hi, lo = sorted((srgb_luminance(a), srgb_luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def floor2(value):
    """value floored to 2 decimals, as a Decimal (WCAG ratios are not rounded)."""
    return decimal.Decimal(math.floor(value * 100)) / 100


def is_number(value):
    return isinstance(value, (int, decimal.Decimal)) and not isinstance(value, bool)


def named_colors_in(value):
    """CSS named colours in a declaration value (strings removed)."""
    value = CSS_STRING.sub(" ", css_unescape(value))
    return [w for w in CSS_WORD.findall(value) if w.lower() in NAMED_COLORS]


def tokens_file_problems(path, findings):
    """Validate data/tokens.toml; returns (n colours, pair report lines)."""
    rel = TOKENS_FILE
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"),
                             parse_float=decimal.Decimal)
    except FileNotFoundError:
        findings.add(rel, "missing; it is the single source of the colour tokens "
                     "(SPEC section 7)")
        return 0, []
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        findings.add(rel, f"cannot read: {exc}")
        return 0, []
    known = {"color", "pair"} | TOKEN_NUMBER_TABLES | TOKEN_STRING_TABLES
    for key in data:
        if key not in known:
            findings.add(rel, f"unknown top-level key {key!r} (fails closed)")
    colors = data.get("color")
    if not isinstance(colors, dict) or not colors:
        findings.add(rel, "[color] is missing or empty")
        colors = {}
    for key, value in colors.items():
        if not TOKEN_KEY.fullmatch(key):
            findings.add(rel, f"color.{key}: keys are snake_case (a-z, 0-9, _)")
        if not isinstance(value, str) or not TOKEN_COLOR.fullmatch(value):
            findings.add(rel, f"color.{key}: {show(value)} is not #RRGGBB or #RRGGBBAA")
    for table in sorted(TOKEN_NUMBER_TABLES | TOKEN_STRING_TABLES):
        if table not in data:
            continue
        values = data[table]
        if not isinstance(values, dict):
            findings.add(rel, f"[{table}] is not a table")
            continue
        for key, value in values.items():
            if not TOKEN_KEY.fullmatch(key):
                findings.add(rel, f"{table}.{key}: keys are snake_case (a-z, 0-9, _)")
            if table in TOKEN_STRING_TABLES:
                if not isinstance(value, str) or not value.strip():
                    findings.add(rel, f"{table}.{key}: must be a non-empty string")
            elif not is_number(value) or value <= 0:
                findings.add(rel, f"{table}.{key}: {show(value)} is not a positive "
                             "number")
    pairs = data.get("pair")
    if not isinstance(pairs, list) or not pairs:
        findings.add(rel, "no [[pair]] entries; every colour pair the layout uses is "
                     "listed and checked")
        pairs = []
    lines, seen = [], set()
    for n, pair in enumerate(pairs, 1):
        where = f"{rel}: pair {n}"
        if not isinstance(pair, dict):
            findings.add(where, "not a table")
            continue
        for key in sorted(set(pair) - PAIR_KEYS):
            findings.add(where, f"unknown key {key!r} (fails closed)")
        for key in sorted(PAIR_KEYS - set(pair)):
            findings.add(where, f"missing key {key!r}")
        fg, bg, kind = pair.get("fg"), pair.get("bg"), pair.get("kind")
        ratio, use = pair.get("ratio"), pair.get("use")
        where = f"{rel}: pair {n} ({fg}/{bg}, {kind})"
        if kind not in CONTRAST_MIN:
            findings.add(where, f"kind {show(kind)} is not one of "
                         f"{', '.join(sorted(CONTRAST_MIN))}")
        if not isinstance(use, str) or not use.strip():
            findings.add(where, "use is empty; say where the pair appears")
        if (fg, bg, kind) in seen:
            findings.add(where, "duplicate (fg, bg, kind)")
        seen.add((fg, bg, kind))
        hexes = []
        for role, key in (("fg", fg), ("bg", bg)):
            value = colors.get(key) if isinstance(key, str) else None
            if not isinstance(value, str) or not TOKEN_COLOR.fullmatch(value):
                findings.add(where, f"{role} {show(key)} is not a colour token")
            elif len(value) != 7:
                findings.add(where, f"{role} {key} = {value} has an alpha channel; a "
                             "contrast ratio needs opaque colours")
            else:
                hexes.append(value)
        if len(hexes) != 2:
            continue
        actual = contrast_ratio(*hexes)
        floored = floor2(actual)
        if not is_number(ratio):
            findings.add(where, f"ratio {show(ratio)} is not a number; it is "
                         f"{floored:.2f}")
        elif decimal.Decimal(ratio) != floored:
            findings.add(where, f"stated ratio {ratio} is wrong; the WCAG ratio floored "
                         f"to 2 decimals is {floored:.2f}")
        minimum = CONTRAST_MIN.get(kind)
        if minimum is not None and decimal.Decimal(actual) < minimum:
            findings.add(where, f"contrast {floored:.2f}:1 is below the {kind} minimum "
                         f"{minimum}:1 (WCAG 2.2)")
        lines.append(f"  {fg}/{bg} {kind}: {floored:.2f}:1 (minimum "
                     f"{minimum if minimum is not None else '?'}:1)")
    return len(colors), lines


def expand_hex(value):
    """#rgb/#rgba as #rrggbb/#rrggbbaa, lowercased (minifiers shorten them)."""
    value = value.lower()
    if len(value) in (4, 5):
        return "#" + "".join(c * 2 for c in value[1:])
    return value


def token_colors(root):
    """The colour values of <root>/data/tokens.toml, expanded and lowercased;
    empty when the file is missing or broken (the tokens check reports it),
    so every hex colour in the build then fails closed."""
    try:
        data = tomllib.loads((root / TOKENS_FILE).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return set()
    colors = data.get("color")
    if not isinstance(colors, dict):
        return set()
    return {expand_hex(v) for v in colors.values()
            if isinstance(v, str) and TOKEN_COLOR.fullmatch(v)}


def color_value_problems(value, allowed):
    """Colours in one CSS value or colour attribute. allowed: the token
    colours a hex value may equal (the built site), or None to skip hex
    (the source scan reports every hex line by line)."""
    text = CSS_STRING.sub(" ", css_unescape(value))
    problems = []
    if allowed is not None:
        for match in HEX_COLOR.finditer(text):
            if expand_hex(match.group(0)) not in allowed:
                problems.append(f"hex colour {match.group(0)!r} is not a token colour")
    for match in COLOR_FUNCTION.finditer(text):
        problems.append(f"colour function {match.group(1)}()")
    for word in CSS_WORD.findall(text):
        if word.lower() in NAMED_COLORS:
            problems.append(f"named colour {word!r}")
    # Vendor-prefixed values include colours no list names (-webkit-link,
    # -webkit-focus-ring-color, ...): banned as values; prefixed property
    # names stay allowed.
    for match in VENDOR_VALUE.finditer(text):
        problems.append(f"vendor-prefixed value {match.group(0)!r}")
    return problems


def css_color_problems(css, allowed):
    """Colours of one stylesheet: no backslash escape outside a string (an
    escape can spell a colour the patterns do not read), then every declaration
    value through color_value_problems."""
    problems = []
    stripped = CSS_COMMENT_OR_STRING.sub(lambda m: m.group(0) if m.group(1) else " ", css)
    if "\\" in CSS_STRING_LITERAL.sub('""', stripped):
        problems.append("backslash escape outside a string; write the character "
                        "itself")
    for rule in css_rules(css):
        for declaration in rule.declarations:
            prop, value = css_declaration(declaration)
            for problem in color_value_problems(value, allowed):
                problems.append(f"{problem} in {show(prop)}")
    return problems


def markup_color_problems(page, allowed, smil):
    """Colours in an HTML, SVG or XML page: colour attributes, the
    theme-color meta, style attributes and <style> blocks. Presentational
    colour attributes fail outright, and with smil=True so do SMIL animation
    elements (rule (g) reports them on the built site)."""
    problems = []
    for tag, attrs in page.elements:
        if smil and tag in SMIL_ELEMENTS:
            problems.append(f"SMIL animation element <{tag}> (it can animate a colour "
                            "that no value check reads)")
        for name in sorted(PRESENTATIONAL_COLOR_ATTRS & set(attrs)):
            problems.append(f"presentational colour attribute <{tag} {name}>")
        values = [(name, attrs[name]) for name in sorted(COLOR_ATTRS) if name in attrs]
        if tag == "meta" and attrs.get("name", "").strip().lower() == "theme-color":
            values.append(("content", attrs.get("content", "")))
        for name, value in values:
            for problem in color_value_problems(value, allowed):
                problems.append(f"{problem} in <{tag} {name}>")
        if "style" in attrs:
            for problem in css_color_problems("x{" + attrs["style"] + "}", allowed):
                problems.append(f"{problem} in <{tag} style>")
    for block in page.styles:
        for problem in css_color_problems(block, allowed):
            problems.append(f"{problem} in <style>")
    return problems


def color_literal_problems(rel, text):
    """Colour literals in one scanned source file (raw text, templates
    included). The built site gets the same value checks in `site` rule (f),
    which also sees what templates inject from data/ and hugo.toml."""
    problems = []
    for n, line in enumerate(text.splitlines(), 1):
        for match in HEX_COLOR.finditer(line):
            problems.append((f"{rel}:{n}", f"hex colour {match.group(0)!r}; colours "
                             "live only in data/tokens.toml (a fragment id that looks "
                             "like hex fails closed: rename it)"))
        for match in COLOR_FUNCTION.finditer(line):
            problems.append((f"{rel}:{n}", f"colour function {match.group(1)}(); "
                             "colours live only in data/tokens.toml"))
    suffix = Path(rel).suffix.lower()
    bare = TEMPLATE_ACTION.sub(" ", text)
    if suffix == ".css":
        found = css_color_problems(bare, None)
    elif suffix in MARKUP_SUFFIXES:
        found = markup_color_problems(parse_page(bare), None, smil=True)
    else:
        found = []
    for problem in found:
        problems.append((rel, f"{problem}; colours live only in data/tokens.toml"))
    return problems


def cmd_tokens(args):
    root = Path(args.root).resolve()
    if not root.is_dir():
        raise UsageError(f"--root {root} is not a directory")
    findings = Findings()
    n_colors, lines = tokens_file_problems(root / TOKENS_FILE, findings)
    scanned = [root / "hugo.toml"] if (root / "hugo.toml").is_file() else []
    for top in ("assets", "layouts", "static"):
        if (root / top).is_dir():
            scanned += sorted(p for p in (root / top).rglob("*") if p.is_file())
    for path in scanned:
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            if path.suffix.lower() not in RASTER_SUFFIXES:
                findings.add(rel, "not UTF-8 text and not a raster image; the colour "
                             "scan cannot read it (fails closed)")
            continue
        except OSError as exc:
            findings.add(rel, f"cannot read: {exc}")
            continue
        for where, problem in color_literal_problems(rel, text):
            findings.add(where, problem)
    if lines:
        print("contrast of the listed pairs (WCAG 2.2, floored):")
        for line in lines:
            print(line)
    return findings.report(f"tokens checked: {n_colors} colours, {len(lines)} pairs, "
                           f"{len(scanned)} files scanned for colour literals")


# ---------------------------------------------------------------------------
# Reflow at 320 CSS px (ADR-0003 part 6), CI only. The runner's Google Chrome
# runs headless and is driven over --remote-debugging-pipe: the DevTools
# protocol as NUL-separated JSON on file descriptors 3 (commands in) and 4
# (responses out), so no websocket and no registry code.

# WCAG 2.2 SC 1.4.10: 320 CSS px wide content scrolls only vertically. The
# height is not load-bearing: the check reads widths only, and 640 is a
# typical phone height at that width.
REFLOW_WIDTH = 320
REFLOW_HEIGHT = 640
# A cold headless start and a local static page each take about a second on
# the runner; 30 s caps a hang at a small part of the job timeout.
REFLOW_TIMEOUT = 30
# At most this many elements are named per page and case, so one broken
# template cannot flood the log; the count is always printed.
REFLOW_NAMED = 10
# Sub-pixel tolerance: layout positions are fractional, and a box that ends
# at 320.3 px because of rounding hides nothing.
REFLOW_EPSILON = 0.5
CHROME_FLAGS = (
    "--headless=new", "--remote-debugging-pipe", "--no-first-run",
    "--no-default-browser-check", "--disable-extensions", "--disable-sync",
    "--disable-background-networking", "--disable-component-update",
    "--disable-default-apps", "--hide-scrollbars", "--mute-audio",
)

# Runs in the page; geometry, not CSS properties (ADR-0003 part 6). Every
# word of every DOM text item (one Range per run of non-space characters, so
# collapsible spaces never count) and every replaced element (img, outermost
# svg, video, iframe, form controls, ...) must lie horizontally within the
# viewport [0, width], and within the box of every clipping ancestor:
# overflow-x not visible, contain with paint (paint, content, strict),
# content-visibility not visible, a clip-path or a clip (the padding box
# for the first three, the border box for clip-path and clip). That covers
# clipping, scrolling, paint containment, fixed positioning, negative
# margins and right-to-left overflow alike. (1) Page-level overflow stays a
# separate check. (4) An element with the visually-hidden class is exempt,
# with its subtree, only while its own box is at most 1 x 1 px.
REFLOW_SCRIPT = r"""
(async () => {
  await document.fonts.ready;
  const vw = %(width)d, exempt = %(exempt)s, limit = %(limit)d, eps = %(eps)s;
  const root = document.documentElement;
  const label = (el) => {
    let s = el.tagName.toLowerCase();
    if (el.id) s += "#" + el.id;
    for (const c of el.classList) s += "." + c;
    return s;
  };
  const snippet = (t) => t.replace(/\s+/g, " ").trim().slice(0, 40);
  const notHidden = [], hiddenOk = new Set();
  for (const el of root.querySelectorAll("." + exempt)) {
    const r = el.getBoundingClientRect();
    const display = getComputedStyle(el).display;
    if (display === "contents") notHidden.push(label(el) + " has display: contents");
    else if (r.width <= 1 && r.height <= 1) hiddenOk.add(el);
    else notHidden.push(label(el) + " is " + Math.round(r.width) + " x " +
                        Math.round(r.height) + " CSS px");
  }
  const isExempt = (el) => {
    for (let e = el; e; e = e.parentElement) if (hiddenOk.has(e)) return true;
    return false;
  };
  const clipCache = new Map();
  const clips = (el) => {
    if (!el) return [];
    if (clipCache.has(el)) return clipCache.get(el);
    const out = clips(el.parentElement).slice();
    const cs = getComputedStyle(el);
    const byPaint = cs.overflowX !== "visible" || /\b(paint|content|strict)\b/.test(cs.contain) ||
                    (cs.contentVisibility || "visible") !== "visible";
    const byShape = (cs.clipPath && cs.clipPath !== "none") || (cs.clip && cs.clip !== "auto");
    if (el !== root && (byPaint || byShape)) {
      const r = el.getBoundingClientRect();
      let left = r.left, right = r.right;
      if (byPaint && !byShape && (el.clientWidth || el.clientHeight)) {
        left = r.left + el.clientLeft;
        right = left + el.clientWidth;
      }
      out.push({el, left, right});
    }
    clipCache.set(el, out);
    return out;
  };
  const outside = [], cut = [];
  let nOutside = 0, nCut = 0, nItems = 0;
  const place = (rect, owner, what) => {
    if (rect.width === 0 && rect.height === 0) return;
    nItems++;
    if (rect.left < -eps || rect.right > vw + eps) {
      nOutside++;
      if (outside.length < limit) outside.push(what + " in " + label(owner) + " at x " +
        Math.round(rect.left) + " to " + Math.round(rect.right));
      return;
    }
    for (const c of clips(owner)) {
      if (c.el === owner && what.startsWith("<")) continue;
      if (rect.left < c.left - eps || rect.right > c.right + eps) {
        nCut++;
        if (cut.length < limit) cut.push(what + " in " + label(owner) + " at x " +
          Math.round(rect.left) + " to " + Math.round(rect.right) + ", clipped by " +
          label(c.el) + " at x " + Math.round(c.left) + " to " + Math.round(c.right));
        return;
      }
    }
  };
  const walker = document.createTreeWalker(document.body || root, 4 /* text only */);
  for (let t = walker.nextNode(); t; t = walker.nextNode()) {
    const owner = t.parentElement;
    if (!owner || isExempt(owner)) continue;
    const words = /\S+/g;
    let m;
    while ((m = words.exec(t.data)) !== null) {
      const range = document.createRange();
      range.setStart(t, m.index);
      range.setEnd(t, m.index + m[0].length);
      for (const rect of range.getClientRects()) place(rect, owner, "\"" + snippet(m[0]) + "\"");
    }
  }
  const replaced = "img, svg, video, audio, iframe, canvas, object, embed, input, select, textarea, meter, progress";
  for (const el of (document.body || root).querySelectorAll(replaced)) {
    if (el.tagName.toLowerCase() === "svg" && el.ownerSVGElement) continue;
    if (isExempt(el)) continue;
    place(el.getBoundingClientRect(), el, "<" + el.tagName.toLowerCase() + ">");
  }
  // (5) Text inside form controls has no DOM range: a control whose content
  // is wider than its box fails.
  const controls = [];
  for (const el of (document.body || root).querySelectorAll("input, textarea, select")) {
    if (isExempt(el)) continue;
    if (el.scrollWidth > el.clientWidth) controls.push(label(el) + " scrollWidth " +
      el.scrollWidth + " > clientWidth " + el.clientWidth);
  }
  const page = root.scrollWidth, wide = [];
  if (page > vw) {
    const all = [...root.querySelectorAll("*")], out = [];
    for (const el of all) {
      if (isExempt(el)) continue;
      const r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) continue;
      const sticks = r.right > vw + eps || r.left < -eps;
      const spills = el.clientWidth > 0 && el.scrollWidth > el.clientWidth &&
                     r.left + el.scrollWidth > vw + eps;
      if (sticks || spills) out.push(el);
    }
    for (const el of out) {
      if (!out.some((o) => o !== el && el.contains(o))) wide.push(label(el));
    }
  }
  return {screen: screen.width, page, items: nItems,
          wide: wide.slice(0, limit), nWide: wide.length,
          outside, nOutside, cut, nCut, notHidden, controls};
})()
"""


class DevTools:
    """A minimal DevTools-protocol client over the two pipe ends."""

    def __init__(self, write_fd, read_fd):
        self.write_fd, self.read_fd = write_fd, read_fd
        self.next_id = 0
        self.buffer = b""
        self.events = []

    def _read(self, deadline):
        while b"\0" not in self.buffer:
            left = deadline - time.monotonic()
            if left <= 0:
                raise UsageError("reflow: no answer from Chrome within "
                                 f"{REFLOW_TIMEOUT} s")
            ready, _, _ = select.select([self.read_fd], [], [], left)
            if not ready:
                continue
            chunk = os.read(self.read_fd, 1 << 16)
            if not chunk:
                raise UsageError("reflow: Chrome closed the DevTools pipe")
            self.buffer += chunk
        message, self.buffer = self.buffer.split(b"\0", 1)
        return json.loads(message)

    def send(self, method, params=None, session=None):
        self.next_id += 1
        message = {"id": self.next_id, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        data = json.dumps(message).encode("utf-8") + b"\0"
        while data:
            data = data[os.write(self.write_fd, data):]
        deadline = time.monotonic() + REFLOW_TIMEOUT
        while True:
            reply = self._read(deadline)
            if reply.get("id") == self.next_id:
                if "error" in reply:
                    raise UsageError(f"reflow: {method} failed: {reply['error']}")
                return reply.get("result", {})
            if "method" in reply:
                self.events.append(reply)

    def wait_event(self, method, session):
        deadline = time.monotonic() + REFLOW_TIMEOUT
        while True:
            for event in self.events:
                if event.get("method") == method and event.get("sessionId") == session:
                    self.events.remove(event)
                    return event
            reply = self._read(deadline)
            if "method" in reply:
                self.events.append(reply)


def start_chrome(chrome, profile, log):
    """Chrome headless with its DevTools pipe on fds 3 and 4 of the child.
    Returns (process, DevTools)."""
    to_chrome_r, to_chrome_w = os.pipe()
    from_chrome_r, from_chrome_w = os.pipe()
    # Move all four ends above 10, so none of them is fd 3 or 4.
    ends = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10)
            for fd in (to_chrome_r, to_chrome_w, from_chrome_r, from_chrome_w)]
    for fd in (to_chrome_r, to_chrome_w, from_chrome_r, from_chrome_w):
        os.close(fd)
    to_chrome_r, to_chrome_w, from_chrome_r, from_chrome_w = ends
    # The parent may hold fds 3 and 4 already (the CI runner passes some
    # down): park them above 10, put the pipe ends there for the child, and
    # restore them after the start.
    parked = {}
    for fd in (3, 4):
        try:
            parked[fd] = (fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10), os.get_inheritable(fd))
        except OSError:
            parked[fd] = None
    os.dup2(to_chrome_r, 3)
    os.dup2(from_chrome_w, 4)
    try:
        process = subprocess.Popen(
            [chrome, *CHROME_FLAGS, f"--user-data-dir={profile}", "about:blank"],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, pass_fds=(3, 4))
    except OSError as exc:
        raise UsageError(f"reflow: cannot start {chrome}: {exc}") from exc
    finally:
        for fd, saved in parked.items():
            if saved is None:
                os.close(fd)
            else:
                os.dup2(saved[0], fd, inheritable=saved[1])
                os.close(saved[0])
        os.close(to_chrome_r)
        os.close(from_chrome_w)
    return process, DevTools(to_chrome_w, from_chrome_r)


class SiteHandler(http.server.SimpleHTTPRequestHandler):
    """Serves PUBLIC quietly and records every error response."""
    errors = []

    def log_message(self, fmt, *args):
        pass

    def log_request(self, code="-", size="-"):
        try:
            status = int(code)
        except (TypeError, ValueError):
            status = 0
        # Chrome asks for /favicon.ico on its own; the site links its icon.
        if status >= 400 and self.path != "/favicon.ico":
            SiteHandler.errors.append(f"{status} {self.path}")


def reflow_pages(public):
    pages = []
    for path in sorted(public.rglob("*.html")):
        rel = path.relative_to(public).as_posix()
        url = own_path(rel)
        pages.append((rel, urllib.parse.quote(url)))
    return pages


def cmd_reflow(args):
    public = Path(args.public).resolve()
    chrome = args.chrome
    if not public.is_dir():
        raise UsageError(f"{public} is not a directory (build the site first)")
    if not (os.path.isfile(chrome) and os.access(chrome, os.X_OK)):
        raise UsageError(f"--chrome {chrome} is not an executable file")
    findings = Findings()
    pages = reflow_pages(public)
    if not pages:
        findings.add("public", "no HTML pages found; nothing was checked")
        return findings.report("reflow checked: 0 pages")

    work = Path(tempfile.mkdtemp(prefix="reflow-"))
    log_path = work / "chrome.log"
    server = process = None
    n_items = 0
    try:
        with open(log_path, "wb") as log:
            process, tools = start_chrome(chrome, work / "profile", log)
        SiteHandler.errors = []
        handler = functools.partial(SiteHandler, directory=str(public))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        origin = f"http://127.0.0.1:{server.server_address[1]}"

        version = tools.send("Browser.getVersion")
        print(f"reflow: {version.get('product', '?')}, viewport {REFLOW_WIDTH}x"
              f"{REFLOW_HEIGHT} CSS px, mobile")
        target = tools.send("Target.createTarget", {"url": "about:blank"})["targetId"]
        session = tools.send("Target.attachToTarget",
                             {"targetId": target, "flatten": True})["sessionId"]
        tools.send("Page.enable", session=session)
        tools.send("Emulation.setDeviceMetricsOverride",
                   {"width": REFLOW_WIDTH, "height": REFLOW_HEIGHT,
                    "screenWidth": REFLOW_WIDTH, "screenHeight": REFLOW_HEIGHT,
                    "deviceScaleFactor": 1, "mobile": True}, session=session)
        script = REFLOW_SCRIPT % {"width": REFLOW_WIDTH, "limit": REFLOW_NAMED,
                                  "exempt": json.dumps(VISUALLY_HIDDEN),
                                  "eps": json.dumps(REFLOW_EPSILON)}
        for rel, path in pages:
            where = f"public/{rel}"
            tools.events.clear()
            nav = tools.send("Page.navigate", {"url": origin + path}, session=session)
            if nav.get("errorText"):
                findings.add(where, f"did not load: {nav['errorText']}")
                continue
            tools.wait_event("Page.loadEventFired", session)
            reply = tools.send("Runtime.evaluate",
                               {"expression": script, "awaitPromise": True,
                                "returnByValue": True}, session=session)
            if "exceptionDetails" in reply:
                raise UsageError(f"reflow: the measuring script failed on {where}: "
                                 f"{reply['exceptionDetails'].get('text')}")
            result = reply.get("result", {}).get("value") or {}
            if result.get("screen") != REFLOW_WIDTH:
                raise UsageError(f"reflow: the viewport emulation did not apply on "
                                 f"{where} (screen width {result.get('screen')})")
            n_items += result.get("items", 0)
            page_width = result.get("page", 0)
            if page_width > REFLOW_WIDTH:
                named = ", ".join(show(e, 80) for e in result.get("wide", [])) \
                    or "none found"
                findings.add(where, f"(1) the page is {page_width} CSS px wide at a "
                             f"{REFLOW_WIDTH} px viewport (WCAG 2.2 SC 1.4.10); "
                             f"{result.get('nWide', 0)} element(s) stick out: {named}")
            for key, count, text in (
                    ("outside", "nOutside", f"lies outside the {REFLOW_WIDTH} px viewport"),
                    ("cut", "nCut", "is cut off by a clipping ancestor (overflow, "
                     "contain, content-visibility, clip-path or clip)")):
                items = result.get(key, [])
                for item in items:
                    findings.add(where, f"({'2' if key == 'outside' else '3'}) {text}: "
                                 f"{show(item, 200)}; long text must wrap at "
                                 f"{REFLOW_WIDTH} px")
                extra = result.get(count, 0) - len(items)
                if extra > 0:
                    findings.add(where, f"({'2' if key == 'outside' else '3'}) {extra} "
                                 f"more item(s) {text}")
            for item in result.get("controls", []):
                findings.add(where, f"(5) form control content wider than its box: "
                             f"{show(item, 160)}; its text is cut at {REFLOW_WIDTH} px")
            for item in result.get("notHidden", []):
                findings.add(where, f"(4) .visually-hidden element {show(item, 120)}; "
                             "the class is exempt only while its box is at most 1 x 1 "
                             "CSS px and its display is not contents")
        for error in sorted(set(SiteHandler.errors)):
            findings.add("public", f"the local server answered {error}; a page was "
                         "measured without one of its files")
        tools.send("Browser.close")
    except BaseException:
        if log_path.exists():
            text = log_path.read_text(encoding="utf-8", errors="replace").strip()
            if text:
                print("reflow: Chrome log:", file=sys.stderr)
                print(text[-4000:], file=sys.stderr)
        raise
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if process is not None:
            try:
                process.wait(timeout=REFLOW_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        shutil.rmtree(work, ignore_errors=True)
    return findings.report(f"reflow checked: {len(pages)} pages at {REFLOW_WIDTH} "
                           f"CSS px, {n_items} words and replaced elements")


# ---------------------------------------------------------------------------
# Lighthouse score gate (ADR-0003 part 3). It runs in the same job as the
# tool, so it is a quality gate; the security boundary is the pin and the
# isolation (ADR-0003 parts 1 and 2).

# SPEC section 8. A constant, not a flag, so a workflow cannot lower it.
LIGHTHOUSE_MIN_SCORE = 95
LIGHTHOUSE_CATEGORIES = ("performance", "accessibility", "best-practices", "seo")
# The smallest odd count that absorbs one outlier (ADR-0003 numbers table).
LIGHTHOUSE_RUNS = 3
LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}


def url_origin(url):
    """(scheme, host, port) of an absolute URL, or None."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    if not parts.scheme or not parts.hostname:
        return None
    default = {"http": 80, "https": 443}.get(parts.scheme.lower())
    return (parts.scheme.lower(), parts.hostname.lower(), port or default)


def display_score(score):
    """A category score as Lighthouse shows it: 0 to 100, rounded half up."""
    return int(score * 100 + 0.5)


def failing_audits(report, category):
    """`id (score)` for every weighted audit of category that scored below 1."""
    refs = dig(report, "categories", category, "auditRefs")
    audits = report.get("audits")
    out = []
    if not isinstance(refs, list) or not isinstance(audits, dict):
        return out
    for ref in refs:
        if not isinstance(ref, dict) or not ref.get("weight"):
            continue
        score = dig(audits, ref.get("id"), "score")
        if isinstance(score, (int, float)) and not isinstance(score, bool) \
                and score < 1:
            out.append(f"{ref.get('id')} ({score})")
    return out


def cmd_lighthouse(args):
    reports_dir = Path(args.reports).resolve()
    if not reports_dir.is_dir():
        raise UsageError(f"--reports {reports_dir} is not a directory")
    findings = Findings()
    paths = sorted(reports_dir.glob("*.json"))
    if not paths:
        findings.add(f"--reports {args.reports}", "no Lighthouse reports found; nothing "
                     "was measured")
    pages = {}  # page path -> [(report name, report, {category: score})]
    for path in paths:
        name = path.name
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            findings.add(name, f"cannot read the report: {exc}")
            continue
        if not isinstance(report, dict):
            findings.add(name, "the report is not a JSON object")
            continue
        error = report.get("runtimeError")
        if error:
            code = dig(error, "code") if isinstance(error, dict) else error
            findings.add(name, f"runtimeError {show(code)}: the run did not "
                         "complete")
        version = report.get("lighthouseVersion")
        if version != args.version:
            findings.add(name, f"lighthouseVersion {json.dumps(version)} is not "
                         f"the pinned {json.dumps(args.version)}")
        form = dig(report, "configSettings", "formFactor")
        if form != "mobile":
            findings.add(name, f"formFactor {json.dumps(form)}, the gate needs the "
                         "mobile profile (SPEC section 8)")
        url = report.get("requestedUrl") or report.get("finalDisplayedUrl")
        origin = url_origin(url) if isinstance(url, str) else None
        if origin is None:
            findings.add(name, "no absolute requestedUrl; cannot tell which "
                         "page was audited")
            continue
        if origin[0] != "http" or origin[1] not in LOOPBACK_HOSTS:
            findings.add(name, f"audited {show(url)}, not the built site on "
                         "loopback http")
        items = dig(report, "audits", "network-requests", "details", "items")
        if not isinstance(items, list):
            findings.add(name, "no network-requests audit items; cannot prove "
                         "same-origin requests (fails closed)")
            items = []
        for item in items:
            target = item.get("url") if isinstance(item, dict) else None
            if not isinstance(target, str) or url_origin(target) != origin:
                findings.add(name, f"request to {show(target)} leaves the "
                             "audited origin (D9)")
        scores = {}
        for category in LIGHTHOUSE_CATEGORIES:
            if not isinstance(dig(report, "categories", category), dict):
                findings.add(name, f"category {category} is missing")
                continue
            score = dig(report, "categories", category, "score")
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                findings.add(name, f"category {category}: score is "
                             f"{json.dumps(score)}, not a number")
                continue
            scores[category] = display_score(score)
        page = urllib.parse.urlsplit(url).path or "/"
        pages.setdefault(page, []).append((name, report, scores))

    rows = []
    for page, runs in sorted(pages.items()):
        row = [page]
        if len(runs) != LIGHTHOUSE_RUNS:
            findings.add(page, f"{len(runs)} report(s), the gate needs exactly "
                         f"{LIGHTHOUSE_RUNS} per page")
        for category in LIGHTHOUSE_CATEGORIES:
            values = [(s[category], r) for _, r, s in runs if category in s]
            if len(runs) != LIGHTHOUSE_RUNS or len(values) != len(runs):
                row.append("-")
                continue
            values.sort(key=lambda v: v[0])
            median, median_report = values[len(values) // 2]
            row.append(str(median))
            audits = ", ".join(failing_audits(median_report, category)) or "none listed"
            if median < LIGHTHOUSE_MIN_SCORE:
                findings.add(page, f"median {category} score {median} is below "
                             f"{LIGHTHOUSE_MIN_SCORE}; failing audits of the "
                             f"median run: {audits}")
            elif median < 100:
                print(f"note: {page}: median {category} score {median}; audits "
                      f"below 1 in the median run: {audits}")
        rows.append(row)
    header = ["page"] + list(LIGHTHOUSE_CATEGORIES)
    widths = [max(len(r[i]) for r in rows + [header]) for i in range(len(header))]
    print(f"median of {LIGHTHOUSE_RUNS} runs per page, threshold "
          f"{LIGHTHOUSE_MIN_SCORE}:")
    for row in [header] + rows:
        print("  " + "  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip())
    # The canonical audit per run, shown and not gated (it weighs into seo):
    # ADR-0003 part 3 needs a run log that shows it passing on real tags.
    for page, runs in sorted(pages.items()):
        results = []
        for _, report, _ in runs:
            audit = dig(report, "audits", "canonical")
            if not isinstance(audit, dict):
                results.append("absent")
            elif audit.get("scoreDisplayMode") == "notApplicable":
                results.append("not applicable")
            else:
                results.append(json.dumps(audit.get("score")))
        print(f"canonical audit on {page}: {', '.join(results)}")
    return findings.report(
        f"lighthouse checked: {len(pages)} pages, {len(paths)} reports, "
        f"version {args.version}")


# ---------------------------------------------------------------------------
# Tree digest (ADR-0003 part 1). The lockfile is generated in CI, in a
# temporary directory of the job that runs the tool; the repo never holds
# one (D3), so the fixtures name it lock.json.

PUBLIC_REGISTRY = "https://registry.npmjs.org/"
SHA512_INTEGRITY = re.compile(r"sha512-[A-Za-z0-9+/]{86}==")


def package_name(key):
    """The package name of a lockfile `packages` key: its last path segment,
    or the last two when the second-to-last is a scope. The segment before
    the name must equal the key's first segment (the install directory), so
    any other layout fails closed."""
    parts = key.split("/")
    if len(parts) >= 3 and parts[-2].startswith("@"):
        name, before = f"{parts[-2]}/{parts[-1]}", parts[-3]
    elif len(parts) >= 2:
        name, before = parts[-1], parts[-2]
    else:
        return None
    if before != parts[0] or not name.strip("@/"):
        return None
    return name


def cmd_tree_digest(args):
    if not re.fullmatch(r"[0-9a-f]{64}", args.expect):
        raise UsageError("--expect must be a 64-hex SHA-256 "
                         "(LIGHTHOUSE_TREE_SHA256 in tools/pins.env)")
    path = Path(args.lockfile)
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UsageError(f"cannot read {path}: {exc}") from exc
    findings = Findings()
    where = path.name
    if not isinstance(lock, dict) or lock.get("lockfileVersion") not in (2, 3):
        version = lock.get("lockfileVersion") if isinstance(lock, dict) else None
        findings.add(where, f"lockfileVersion {json.dumps(version)}; only 2 and 3 "
                     "carry the packages map this digest reads")
        return findings.report("tree digest: not computed")
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not packages:
        findings.add(where, "no packages map")
        return findings.report("tree digest: not computed")
    first = None
    lines = set()
    for key, entry in packages.items():
        if key == "":
            continue  # the root manifest the job generated
        here = f"{where}: packages[{key!r}]"
        if not isinstance(entry, dict):
            findings.add(here, "not an object")
            continue
        if entry.get("link"):
            findings.add(here, "link entry; every package must come from the "
                         "public registry (fails closed)")
            continue
        name = package_name(key)
        top = key.split("/", 1)[0]
        first = first or top
        if name is None or top != first:
            findings.add(here, "unexpected key layout; cannot derive the package "
                         "name (fails closed)")
            continue
        version = entry.get("version")
        integrity = entry.get("integrity")
        resolved = entry.get("resolved")
        if not isinstance(version, str) or not version:
            findings.add(here, "no version")
            continue
        if not isinstance(integrity, str) or not SHA512_INTEGRITY.fullmatch(integrity):
            findings.add(here, f"integrity {show(integrity, 24)} is not a single "
                         "sha512- hash")
            continue
        if not isinstance(resolved, str) or not resolved.startswith(PUBLIC_REGISTRY):
            findings.add(here, f"resolved {show(resolved)} is not on the public "
                         f"registry {show(PUBLIC_REGISTRY)}")
            continue
        lines.add(f"{name}@{version} {integrity}")
    ordered = sorted(lines)
    digest = hashlib.sha256("".join(f"{line}\n" for line in ordered)
                            .encode("utf-8")).hexdigest()
    print(f"tree digest: {digest} ({len(ordered)} packages)")
    if not findings.items and digest != args.expect:
        print("resolved tree (name@version), for review against the expected "
              "set of packages:")
        for line in ordered:
            print("  " + line.split(" ", 1)[0])
        findings.add(where, f"tree digest {digest} does not match the pin "
                     f"{args.expect}; review the list above, then pin the "
                     "digest as LIGHTHOUSE_TREE_SHA256 in tools/pins.env")
    return findings.report(f"tree digest checked: {len(ordered)} packages")


# ---------------------------------------------------------------------------
# Guard

# The pattern tables. The tool scan skips exactly these lines of this file
# (compared character for character), and nothing else.
JS_TOOLS = ('npm', 'npx', 'node', 'yarn', 'pnpm', 'bun', 'corepack')
JS_FILES = ('package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', '.yarnrc', '.yarnrc.yml', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', '.npmrc', 'bun.lock', 'bun.lockb', 'node_modules')
TABLE_LINES = {f"JS_TOOLS = {JS_TOOLS!r}", f"JS_FILES = {JS_FILES!r}"}
TOOL_WORD = re.compile(r"(?i)(?<![a-z0-9_])(?:" + "|".join(JS_TOOLS) + r")(?![a-z0-9])")

ACTION_REF = re.compile(r"""(?<![\w-])['"]?uses['"]?\s*:\s*(['"]?)([^\s'"#,}\]]*)\1""")
ACTION_OWNER = re.compile(r"actions/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@.*")
ACTION_PINNED = re.compile(r"[^@]+@[0-9a-f]{40}")
PAGES_RULES = [
    (re.compile(r"(?i)deploy-pages"), "actions/deploy-pages"),
    (re.compile(r"(?i)configure-pages"), "actions/configure-pages"),
    (re.compile(r"""(?i)(?<![\w-])['"]?pages['"]?\s*:\s*['"]?write"""), "pages: write"),
    (re.compile(r"""(?i)(?<![\w-])['"]?id-token['"]?\s*:\s*['"]?write"""), "id-token: write"),
    (re.compile(r"(?i)(?<![\w-])write-all(?![\w-])"), "permissions: write-all"),
]
HUGO_PRIVACY = ("disqus", "googleAnalytics", "instagram", "vimeo", "x", "youtube")
ROOT_CONFIG = re.compile(r"(?i)(?:hugo|config)\.(?:toml|ya?ml|json)")


def dig(mapping, *keys):
    for key in keys:
        if not isinstance(mapping, dict) or key not in mapping:
            return None
        mapping = mapping[key]
    return mapping


def git_files(root):
    """Tracked plus untracked, not ignored files, relative to root."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
             "--exclude-standard"],
            check=True, capture_output=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise UsageError(f"guard needs a git work tree at {root}: {exc}") from exc
    return sorted({p for p in out.decode("utf-8", "replace").split("\0") if p})


def in_guard_fail_fixture(rel):
    """The guard's own fail fixtures hold forbidden files on purpose; the
    self-test runs each one and proves it fails for that reason."""
    parts = rel.split("/")
    return (len(parts) > 4 and parts[:3] == ["tests", "fixtures", "guard"]
            and parts[3].startswith("fail-"))


def guard_package_files(files, findings):
    for rel in files:
        if in_guard_fail_fixture(rel):
            continue
        parts = rel.split("/")
        if parts[-1] in JS_FILES or any(p in JS_FILES for p in parts[:-1]):
            findings.add(rel, "JavaScript package-manager file in the repo; the "
                              "build chain stays free of it (D3)")


# Site sources and fixtures are not executed by the build; everything else
# that looks like a script is (a workflow may only start tools/*.sh, but a
# tools/ script can call a script elsewhere).
NOT_EXECUTED = ("assets/", "layouts/", "static/", "content/", "data/", "i18n/",
                "archetypes/", "docs/", "tests/fixtures/")
SCRIPT_SUFFIXES = {".sh", ".bash", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb",
                   ".pl", ".ps1", ".mk"}
SCRIPT_NAMES = {"Makefile", "makefile", "GNUmakefile", "justfile", "Justfile",
                "Taskfile.yml", "Rakefile"}


def scanned_for_tools(root, rel):
    if rel.startswith(("tools/", ".github/workflows/", ".github/actions/")):
        return True
    if rel.startswith(NOT_EXECUTED):
        return False
    name = rel.rsplit("/", 1)[-1]
    if name in SCRIPT_NAMES or Path(name).suffix.lower() in SCRIPT_SUFFIXES:
        return True
    try:
        with open(root / rel, "rb") as handle:
            return handle.read(2) == b"#!"
    except OSError:
        return True


# ADR-0003 part 2: the one script that may name the registry tools, and the
# one workflow that may run it. The guard itself (this file) names both.
LIGHTHOUSE_SCRIPT = "tools/lighthouse.sh"
LIGHTHOUSE_WORKFLOW = ".github/workflows/lighthouse.yml"
LIGHTHOUSE_REFERENCE = re.compile(r"(?i)lighthouse\.sh")
REFERENCE_ALLOWED = {LIGHTHOUSE_SCRIPT, LIGHTHOUSE_WORKFLOW, "tools/sitecheck.py"}


def guard_tool_invocations(root, files, findings):
    for rel in files:
        if not scanned_for_tools(root, rel):
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            findings.add(rel, f"cannot read: {exc}")
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if rel not in REFERENCE_ALLOWED and LIGHTHOUSE_REFERENCE.search(line):
                findings.add(f"{rel}:{n}", f"references {LIGHTHOUSE_SCRIPT}; only "
                             f"{LIGHTHOUSE_WORKFLOW} may run it, so no other "
                             "script or workflow can reach the registry code "
                             "(ADR-0003 part 2)")
            if rel == LIGHTHOUSE_SCRIPT:
                continue  # the carve-out: it runs the registry tools
            if rel == "tools/sitecheck.py" and line in TABLE_LINES:
                continue
            match = TOOL_WORD.search(line)
            if match:
                findings.add(f"{rel}:{n}", f"invokes or names the JavaScript "
                             f"tool {match.group(0)!r} in the build chain (D3)")


def guard_hugo_config(root, hugo_bin, findings):
    names = sorted(os.listdir(root))
    for name in names:
        if ROOT_CONFIG.fullmatch(name) and name != "hugo.toml":
            findings.add(name, "a second root config file; hugo.toml is the only "
                               "Hugo config (PR #10 review)")
    if (root / "config").exists():
        findings.add("config/", "a config/ directory overrides hugo.toml per "
                                "environment; it is not allowed (PR #10 review)")
    try:
        source = tomllib.loads((root / "hugo.toml").read_text(encoding="utf-8"))
    except FileNotFoundError:
        findings.add("hugo.toml", "missing")
        return
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        findings.add("hugo.toml", f"cannot read: {exc}")
        return

    def expect(where, actual, wanted, why):
        if not same_json(actual, wanted):
            findings.add(where, f"must be {json.dumps(wanted)}, is "
                                f"{json.dumps(actual)} ({why})")

    expect("hugo.toml: security.exec.allow", dig(source, "security", "exec", "allow"),
           ["none"], "ADR-0001, D3")
    expect("hugo.toml: security.http.urls", dig(source, "security", "http", "urls"),
           ["none"], "ADR-0001, D3, D9")
    expect("hugo.toml: markup.goldmark.extensions.linkify",
           dig(source, "markup", "goldmark", "extensions", "linkify"), False,
           "ADR-0001, D8")
    expect("hugo.toml: markup.goldmark.renderer.unsafe",
           dig(source, "markup", "goldmark", "renderer", "unsafe"), False,
           "ADR-0001, D8, D7")
    for key in HUGO_PRIVACY:
        expect(f"hugo.toml: privacy.{key}.disable", dig(source, "privacy", key, "disable"),
               True, "ADR-0001, D9")

    # The effective config: what the build really uses, after config/
    # directories, HUGO_* environment variables and case-variant keys.
    where = "effective Hugo config (hugo config)"
    if not hugo_bin or not os.access(hugo_bin, os.X_OK):
        raise UsageError(f"hugo binary not found at {hugo_bin!r}; pass --hugo or "
                         "set HUGO_BIN (tools/fetch-tools.sh)")
    try:
        result = subprocess.run(
            [hugo_bin, "config", "--format", "json", "--source", str(root)],
            capture_output=True, timeout=120, cwd=root)
    except (OSError, subprocess.SubprocessError) as exc:
        findings.add(where, f"could not run: {exc}")
        return
    if result.returncode != 0:
        findings.add(where, "hugo config failed: "
                     + result.stderr.decode("utf-8", "replace").strip()[:300])
        return
    try:
        effective = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        findings.add(where, f"not JSON: {exc}")
        return

    def none_list(value):
        return value == "none" or value == ["none"]

    allow = dig(effective, "security", "exec", "allow")
    if not none_list(allow):
        findings.add(where, f"security.exec.allow is {json.dumps(allow)}, must be "
                            "none (ADR-0001, D3)")
    urls = dig(effective, "security", "http", "urls")
    if not none_list(urls):
        findings.add(where, f"security.http.urls is {json.dumps(urls)}, must be "
                            "none (ADR-0001, D3, D9)")
    # Hugo omits a false boolean from this output; true is always printed.
    linkify = dig(effective, "markup", "goldmark", "extensions", "linkify")
    if linkify not in (None, False):
        findings.add(where, f"markup.goldmark.extensions.linkify is "
                            f"{json.dumps(linkify)}, must be false (ADR-0001, D8)")
    unsafe = dig(effective, "markup", "goldmark", "renderer", "unsafe")
    if unsafe not in (None, False):
        findings.add(where, f"markup.goldmark.renderer.unsafe is "
                            f"{json.dumps(unsafe)}, must be false (ADR-0001, D8)")
    for key in HUGO_PRIVACY:
        disable = dig(effective, "privacy", key.lower(), "disable")
        if disable is not True:
            findings.add(where, f"privacy.{key}.disable is {json.dumps(disable)}, "
                                "must be true (ADR-0001, D9)")
    # The records check reads content/; Hugo must build exactly that tree.
    contentdir = effective.get("contentdir")
    if contentdir != "content":
        findings.add(where, f"contentdir is {json.dumps(contentdir)}, must be "
                            "\"content\" (the records check reads only content/)")
    if effective.get("theme") not in (None, "", []):
        findings.add(where, f"theme is {json.dumps(effective.get('theme'))}; a theme "
                            "can mount content the records check never reads")
    if dig(effective, "module", "imports") not in (None, []):
        findings.add(where, "module.imports is set; an imported module can mount "
                            "content the records check never reads")
    mounts = dig(effective, "module", "mounts")
    if not isinstance(mounts, list):
        findings.add(where, "module.mounts is missing; cannot prove which content "
                            "Hugo builds")
        mounts = []
    for mount in mounts:
        target = str(dig(mount, "target") or "").strip("/")
        if target == "content" or target.startswith("content/"):
            if dig(mount, "source") != "content" or target != "content":
                findings.add(where, f"content mount {json.dumps(mount)}: every "
                                    "content mount must be source \"content\" to "
                                    "target \"content\" (the records check reads "
                                    "only content/)")
    csp = dig(source, "params", "csp")
    if dig(effective, "params", "csp") != csp:
        findings.add(where, "params.csp differs from params.csp in hugo.toml "
                            "(the single source of the CSP, D9)")


def same_json(a, b):
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# A workflow may only execute the entry points in tools/ (which the tool
# scan covers), with plain flags: no inline scripts, no other shells.
RUN_KEY = re.compile(r"""(?<![\w-])['"]?run['"]?\s*:(.*)$""")
RUN_ALLOWED = re.compile(r" bash tools/[a-z0-9_-]+\.sh(?: --[a-z0-9-]+)*")
SHELL_KEY = re.compile(r"""(?<![\w-])['"]?shell['"]?\s*:(.*)$""")
# working-directory moves a run: step into an unscanned tree, env can set
# BASH_ENV (a script bash sources first), and defaults sets both for a job.
EXEC_KEYS = re.compile(r"""(?<![\w-])['"]?(container|services|entrypoint|working-directory|env|defaults)['"]?\s*:""")
# YAML forms the per-line rules cannot read are refused, fail closed: a
# permission whose value is on the next line or behind an anchor, alias,
# tag or block scalar, a quoted key with an escape, a complex key.
PERMISSION_INDIRECT = re.compile(
    r"""(?i)(?<![\w-])['"]?(pages|id-token)['"]?\s*:\s*(?:#.*)?$"""
    r"""|(?i:(?<![\w-])['"]?(?:pages|id-token)['"]?\s*:\s*[|>&*!])""")
# Any backslash inside a double-quoted string, anywhere on the line (block
# or flow style), because an escape can spell a key the guard looks for.
ESCAPED_KEY = re.compile(r'"(?:[^"\\]|\\.)*\\')
COMPLEX_KEY = re.compile(r"^\s*(?:-\s+)?\?(?:\s|$)")


def action_pins(root, findings):
    """The allowlisted actions/<name>@<sha> pairs, from tools/pins.env."""
    pins = set()
    path = root / "tools" / "pins.env"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return pins
    for n, line in enumerate(lines, 1):
        match = re.fullmatch(r"(ACTION_[A-Z0-9_]+)=(\S+)", line)
        if not match:
            continue
        if not re.fullmatch(r"actions/[A-Za-z0-9_.-]+@[0-9a-f]{40}", match.group(2)):
            findings.add(f"tools/pins.env:{n}", f"{match.group(1)} must be "
                         "actions/<name>@<40-hex commit SHA>")
            continue
        pins.add(match.group(2))
    return pins


def guard_workflows(root, files, findings):
    pins = action_pins(root, findings)
    for rel in files:
        if not rel.startswith(".github/workflows/"):
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            findings.add(rel, f"cannot read: {exc}")
            continue
        if not re.search(r"(?m)^permissions\s*:", text):
            findings.add(rel, "no top-level permissions block; the token would get "
                              "the repo default, which can include pages: write")
        for n, line in enumerate(text.splitlines(), 1):
            for match in ACTION_REF.finditer(line):
                ref = match.group(2)
                if not ACTION_OWNER.fullmatch(ref):
                    findings.add(f"{rel}:{n}", f"action {ref!r} is not owned by "
                                 "actions/ (ADR-0002 part 6)")
                elif not ACTION_PINNED.fullmatch(ref):
                    findings.add(f"{rel}:{n}", f"action {ref!r} is not pinned to "
                                 "a 40-hex commit SHA (ADR-0002 part 6)")
                elif ref not in pins:
                    findings.add(f"{rel}:{n}", f"action {ref!r} is not an "
                                 "allowlisted ACTION_* pin in tools/pins.env (a "
                                 "SHA from a fork network resolves under actions/ "
                                 "too)")
            match = RUN_KEY.search(line)
            if match and not RUN_ALLOWED.fullmatch(match.group(1)):
                findings.add(f"{rel}:{n}", f"run step {match.group(1).strip()!r}: a "
                             "workflow may only run `bash tools/<name>.sh [--flag]` "
                             "(D3; the tool scan covers tools/)")
            match = SHELL_KEY.search(line)
            if match and match.group(1).strip() != "bash":
                findings.add(f"{rel}:{n}", f"shell {match.group(1).strip()!r}: "
                             "only bash is allowed")
            match = EXEC_KEYS.search(line)
            if match:
                findings.add(f"{rel}:{n}", f"{match.group(1)}: not allowed in a "
                             "workflow (a container, service, working directory "
                             "or environment can run code the tool scan never "
                             "sees; fails closed)")
            if PERMISSION_INDIRECT.search(line):
                findings.add(f"{rel}:{n}", "pages/id-token permission with an "
                             "indirect value (next line, anchor, alias, tag or "
                             "block scalar); write it inline (fails closed)")
            if ESCAPED_KEY.search(line) or COMPLEX_KEY.search(line):
                findings.add(f"{rel}:{n}", "YAML quoted string with a backslash "
                             "escape or a complex key indicator; the guard reads "
                             "keys literally (fails closed)")
            for rule, label in PAGES_RULES:
                if rule.search(line):
                    findings.add(f"{rel}:{n}", f"{label}: Pages stays off until "
                                 "M6 (#7)")
            # ADR-0003 part 2: nothing with a token or on the deploy path
            # reads what the job running the registry code could write.
            if WORKFLOW_RUN.search(line):
                findings.add(f"{rel}:{n}", "workflow_run trigger: a run started "
                             "by another workflow can download that run's "
                             "artifacts, which the lighthouse job could have "
                             "replaced (ADR-0003 part 2)")
            if rel != LIGHTHOUSE_WORKFLOW and DOWNLOAD_ARTIFACT.search(line):
                findings.add(f"{rel}:{n}", "actions/download-artifact outside the "
                             f"lighthouse job of {LIGHTHOUSE_WORKFLOW}; an artifact "
                             "of a run with that job can hold what registry code "
                             "wrote (ADR-0003 part 2)")


# lighthouse.yml is read by indentation, so every YAML form that can move a
# key out of its line, or merge one mapping into another, is refused there.
YAML_QUOTED = re.compile(r""""[^"]*"|'[^']*'""")
YAML_EXPRESSION = re.compile(r"\$\{\{.*?\}\}")
YAML_COMMENT = re.compile(r"(?:^|\s)#.*$")
YAML_ANCHOR_OR_ALIAS = re.compile(r"(?:^|[\s\[,])[&*][^\s,\]]")
EMPTY_PERMISSIONS = re.compile(r"\s*permissions\s*:\s*\{\}\s*")
JOB_KEY = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*")
FORBIDDEN_IN_LIGHTHOUSE_JOB = re.compile(
    r"actions/(checkout|upload-artifact|upload-pages-artifact)(?![\w-])")
WORKFLOW_RUN = re.compile(r"(?i)(?<![\w-])workflow_run(?![\w-])")
DOWNLOAD_ARTIFACT = re.compile(r"(?i)actions/download-artifact(?![\w-])")
# Credentials that could reach the job running the registry code, besides
# GITHUB_TOKEN (which permissions: {} empties). Matched on the raw line,
# comments included, so no quoting or comment trick hides one.
LIGHTHOUSE_CREDENTIALS = [
    (re.compile(r"(?i)(?<![\w-])secrets(?![\w-])"), "a secrets reference"),
    (re.compile(r"""(?i)(?<![\w-])github\s*(?:\.\s*|\[\s*['"]?)token(?![\w-])"""),
     "a github.token reference"),
    (re.compile(r"""(?i)(?<![\w-])['"]?(github-token|run-id|repository)['"]?\s*:"""),
     "a download input that reads another run or repository"),
]
NEEDS_KEY = re.compile(r"\s*needs\s*:(.*)$")
JOB_NAME_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")


def yaml_bare(line):
    """The line without quoted strings, ${{ }} expressions and its comment."""
    line = YAML_EXPRESSION.sub("", YAML_QUOTED.sub('""', line))
    return YAML_COMMENT.sub("", line).rstrip()


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def workflow_jobs(lines):
    """{job id: [(line number, line)]} for the block under top-level jobs:,
    split by indentation, or None when the layout cannot be read."""
    start = next((i for i, line in enumerate(lines)
                  if re.fullmatch(r"jobs\s*:", yaml_bare(line))), None)
    if start is None:
        return None
    jobs, current, job_indent = {}, None, None
    for i in range(start + 1, len(lines)):
        bare = yaml_bare(lines[i])
        if not bare.strip():
            continue
        indent = indent_of(bare)
        if indent == 0:
            break
        if job_indent is None:
            job_indent = indent
        if indent < job_indent:
            return None
        if indent == job_indent:
            match = JOB_KEY.fullmatch(bare.strip())
            if not match:
                return None
            current = match.group(1)
            if current in jobs:
                return None
            jobs[current] = []
            continue
        jobs[current].append((i + 1, lines[i]))
    return jobs


def guard_lighthouse_workflow(root, files, findings):
    """The job that runs tools/lighthouse.sh holds no token permission and
    no other credential, has no checkout, uploads nothing and is a leaf; only
    it downloads an artifact; the workflow never builds the Pages artifact
    (ADR-0003 part 2)."""
    if LIGHTHOUSE_WORKFLOW not in files:
        return
    rel = LIGHTHOUSE_WORKFLOW
    try:
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        findings.add(rel, f"cannot read: {exc}")
        return
    lines = text.splitlines()
    for n, line in enumerate(lines, 1):
        for rule, label in LIGHTHOUSE_CREDENTIALS:
            if rule.search(line):
                findings.add(f"{rel}:{n}", f"{label} in {LIGHTHOUSE_WORKFLOW}; no "
                             "credential may reach the job that runs registry "
                             "code (D3, ADR-0003 part 2)")
        lowered = line.lower()
        if "upload-pages-artifact" in lowered or "github-pages" in lowered:
            findings.add(f"{rel}:{n}", "the Lighthouse workflow must never build "
                         "or name the Pages artifact (ADR-0003 part 2)")
        bare = yaml_bare(line)
        if YAML_ANCHOR_OR_ALIAS.search(bare):
            findings.add(f"{rel}:{n}", "YAML anchor or alias; the guard reads "
                         "this file by indentation (fails closed)")
        if not EMPTY_PERMISSIONS.fullmatch(bare) and ("{" in bare or "}" in bare):
            findings.add(f"{rel}:{n}", "YAML flow mapping; the guard reads this "
                         "file by indentation, only `permissions: {}` is "
                         "allowed (fails closed)")
    jobs = workflow_jobs(lines)
    if jobs is None:
        findings.add(rel, "cannot read the jobs block by indentation (fails "
                     "closed)")
        return
    registry_jobs = {job for job, body in jobs.items()
                     if any((m := RUN_KEY.search(line))
                            and LIGHTHOUSE_REFERENCE.search(m.group(1))
                            for _, line in body)}
    allowed_downloads = {n for job in registry_jobs if job == "lighthouse"
                         for n, _ in jobs[job]}
    for n, line in enumerate(lines, 1):
        if DOWNLOAD_ARTIFACT.search(line) and n not in allowed_downloads:
            findings.add(f"{rel}:{n}", "actions/download-artifact outside the job "
                         f"`lighthouse` that runs {LIGHTHOUSE_SCRIPT} (ADR-0003 "
                         "part 2)")
    for job, body in jobs.items():
        # The registry job stays a leaf: no job may run after it and read
        # what it left behind.
        content = [(n, YAML_COMMENT.sub("", line).rstrip()) for n, line in body]
        content = [(n, line) for n, line in content if line.strip()]
        child = min(indent_of(line) for _, line in content) if content else None
        for i, (n, line) in enumerate(content):
            match = NEEDS_KEY.match(line) if indent_of(line) == child else None
            if not match:
                continue
            values = [match.group(1)]
            for _, more in content[i + 1:]:
                if indent_of(more) <= child:
                    break
                values.append(more)
            named = set(JOB_NAME_TOKEN.findall(" ".join(values)))
            for target in sorted(named & registry_jobs):
                findings.add(f"{rel}:{n}", f"job {job} needs {target}, the job "
                             f"that runs {LIGHTHOUSE_SCRIPT}; it stays a leaf, so "
                             "nothing reads what it could write (ADR-0003 part 2)")
    for job, body in jobs.items():
        if job not in registry_jobs:
            continue
        content = [(n, yaml_bare(line)) for n, line in body if yaml_bare(line).strip()]
        child = min(indent_of(bare) for _, bare in content) if content else None
        perms = [(n, bare) for n, bare in content if indent_of(bare) == child
                 and re.match(r"\s*permissions\s*:", bare)]
        if len(perms) != 1 or not EMPTY_PERMISSIONS.fullmatch(perms[0][1]):
            findings.add(f"{rel}: job {job}", f"runs {LIGHTHOUSE_SCRIPT} without "
                         "exactly one job-level `permissions: {}`; the registry "
                         "code must hold no token permission (D3, ADR-0003 "
                         "part 2)")
        for n, line in body:
            match = FORBIDDEN_IN_LIGHTHOUSE_JOB.search(line)
            if match:
                findings.add(f"{rel}:{n}", f"job {job} runs {LIGHTHOUSE_SCRIPT} "
                             f"and uses actions/{match.group(1)}; that job has "
                             "no checkout and uploads nothing (ADR-0003 part 2)")


def cmd_guard(args):
    root = Path(args.root).resolve()
    if not root.is_dir():
        raise UsageError(f"--root {root} is not a directory")
    hugo_bin = args.hugo or os.environ.get("HUGO_BIN", "")
    findings = Findings()
    files = git_files(root)
    guard_package_files(files, findings)
    guard_tool_invocations(root, files, findings)
    guard_hugo_config(root, hugo_bin, findings)
    guard_workflows(root, files, findings)
    guard_lighthouse_workflow(root, files, findings)
    n_workflows = sum(f.startswith(".github/workflows/") for f in files)
    return findings.report(f"guard checked: {len(files)} files, "
                           f"{n_workflows} workflows")


# ---------------------------------------------------------------------------

def main(argv):
    parser = argparse.ArgumentParser(prog="sitecheck", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("records")
    p.add_argument("--root", default=".")
    p.add_argument("--schemas")
    p.set_defaults(func=cmd_records)
    p = sub.add_parser("site")
    p.add_argument("--records", required=True)
    p.add_argument("--schemas")
    p.add_argument("public")
    p.set_defaults(func=cmd_site)
    p = sub.add_parser("tokens")
    p.add_argument("--root", default=".")
    p.set_defaults(func=cmd_tokens)
    p = sub.add_parser("reflow")
    p.add_argument("--chrome", required=True)
    p.add_argument("public")
    p.set_defaults(func=cmd_reflow)
    p = sub.add_parser("guard")
    p.add_argument("--root", default=".")
    p.add_argument("--hugo")
    p.set_defaults(func=cmd_guard)
    p = sub.add_parser("lighthouse")
    p.add_argument("--reports", required=True)
    p.add_argument("--version", required=True)
    p.set_defaults(func=cmd_lighthouse)
    p = sub.add_parser("tree-digest")
    p.add_argument("lockfile")
    p.add_argument("--expect", required=True)
    p.set_defaults(func=cmd_tree_digest)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    try:
        return args.func(args)
    except UsageError as exc:
        print(f"sitecheck: ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception:  # an internal error is exit 2, never a finding
        import traceback
        traceback.print_exc()
        sys.exit(2)
