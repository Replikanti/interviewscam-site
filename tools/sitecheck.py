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
      nowhere in PUBLIC (R3), decoded or not.
  guard [--root DIR] [--hugo BIN]
      Repo-level rules: no JavaScript package-manager tooling in the build
      chain (D3); the Hugo hardening keys of ADR-0001 in hugo.toml AND in the
      effective config that `hugo config` reports; no config/ directory and
      no second root config file; every action owned by actions/ and pinned
      to a 40-hex commit SHA (ADR-0002 part 6); Pages off until M6.

A finding never prints an artifact in live form: values are shown defanged.
"""

import sys

if sys.version_info < (3, 11):
    print("sitecheck: Python 3.11 or newer is required (tomllib)", file=sys.stderr)
    sys.exit(2)

import argparse
import datetime
import html
import html.parser
import json
import os
import re
import subprocess
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


def css_decode(css):
    def unescape(match):
        if match.group(1):
            try:
                return chr(int(match.group(1), 16))
            except (ValueError, OverflowError):
                return "\ufffd"
        return match.group(2)
    css = CSS_COMMENT_OR_STRING.sub(lambda m: m.group(0) if m.group(1) else "", css)
    return CSS_ESCAPE.sub(unescape, css)


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
            else:
                for problem in svg_request_problems(page):
                    findings.add(rel, f"third-party request: {problem} (D9)")
        elif suffix == ".css":
            for url in css_urls(text):
                if leaves_origin(url):
                    findings.add(rel, f"third-party request: CSS loads {show(url)} (D9)")
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
    if n_html == 0:
        findings.add("public", "no HTML pages found; nothing was checked")
    return findings.report(
        f"site checked: {len(files)} files, {n_html} HTML pages, "
        f"{len(forms)} artifact live forms scanned")


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
    p = sub.add_parser("guard")
    p.add_argument("--root", default=".")
    p.add_argument("--hugo")
    p.set_defaults(func=cmd_guard)
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
