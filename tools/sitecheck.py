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
      (SPEC section 5); the rule fails closed. Then the record rules R4 to
      R15 of ADR-0004 (slugs, persona names, references, dates, evidence,
      hostnames and IP forms in record text, _index.md, verdict phrases,
      source hosts), with the retired slugs of DIR/record-policy.json.
  site --records DIR [--schemas DIR] PUBLIC
      The built site in PUBLIC makes no third-party request (D9). Every page
      carries exactly one CSP meta, right after <meta charset>, equal to
      params.csp in DIR/hugo.toml. The live form of a record artifact appears
      nowhere in PUBLIC (R3), decoded or not. Forms stay on the origin, no
      web manifest, no inline style, script or event handler, one canonical
      link to the page itself, no mailto: link, only token colours, no SMIL
      animation, and .visually-hidden and !important only where ADR-0003
      part 6 allows them (counted across all built CSS).
  render --records DIR [--schemas DIR] PUBLIC
      The built record pages in PUBLIC follow the markup contract of
      ADR-0004 (milestone 3): one page per record and none without one, the
      fixed titles, the D6 chip, state sentence and What was checked list,
      the D10 label after every visible persona name, the exact D7 label, the
      campaign line and attribution with their source links, every artifact
      in an artifact element and only source and lookup links out, JSON-LD
      of the allowed types only and no ClaimReview, no hidden persona name in
      any file, and the index lists on /reports/, /campaigns/ and Home.
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
import encodings.idna
import fcntl
import functools
import hashlib
import html
import html.parser
import http.server
import ipaddress
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
# Invisible characters that a copy-paste carries along without a trace: the
# whole Default_Ignorable_Code_Point set, which browsers drop from a host
# (UTS #46), so attacker\ufe0f.example opens attacker.example. The standard
# library has no such property, so the ranges are copied from Unicode's
# DerivedCoreProperties.txt (Unicode 16.0, Default_Ignorable_Code_Point).
# They are stripped before every check, not rejected, so emoji in prose
# (U+FE0F, the ZWJ of a family emoji) keep passing.
DEFAULT_IGNORABLE = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
INVISIBLE = dict.fromkeys(c for lo, hi in DEFAULT_IGNORABLE for c in range(lo, hi + 1))
TO_DOT = str.maketrans(dict.fromkeys(DOT_CHARS, "."))


def norm(text):
    """Fold a string for live-form comparison: NFKC, dots, invisibles, case."""
    text = unicodedata.normalize("NFKC", text)
    return text.translate(INVISIBLE).translate(TO_DOT).lower()


# Defanged spellings and the character each stands for. The one table that
# refang() and host-mode parsing (restructure) share, so they cannot drift.
DEFANGS = (("[.]", "."), ("[://]", "://"), ("[:]", ":"), ("[@]", "@"))
# Every entry but the dot: a defanged scheme separator or userinfo still
# splits a URL the way the live form would, while [.] keeps a host defanged.
STRUCTURE_DEFANGS = tuple((d, live) for d, live in DEFANGS if live != ".")


def refang(value):
    """The live form of a defanged artifact (R2, R3)."""
    for defanged, live in DEFANGS:
        value = value.replace(defanged, live)
    return re.sub(r"(?i)hxxp", "http", value)


def restructure(text):
    """text with every defanged separator except [.] read as the character it
    stands for, so hxxps[:]//host splits at its scheme like hxxps://host."""
    for defanged, live in STRUCTURE_DEFANGS:
        text = text.replace(defanged, live)
    return text


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

# The one x-defang mode (ADR-0004 part 3). The former mode url-only is gone,
# so a schema that still uses it fails closed.
DEFANG_MODES = ("host",)
# A scheme anywhere in a token (irm('hxxps://...'), url=hxxps://...), with any
# run of slashes after it, or a leading run of slashes (protocol-relative):
# the token is split there, so the host that follows is split out.
SCHEME_IN_TOKEN = re.compile(
    r"(?i)[a-z][a-z0-9+.\-]*:(?=[/\\])[/\\]*|^[/\\]+")
URL_HOST_END = re.compile(r"[/?#\\]")
# The site's own host, the only live host record text may carry (R11).
OWN_HOST = urllib.parse.urlsplit(SITE_ORIGIN).hostname


def token_pieces(text):
    """(piece, after a scheme or leading slashes) for every whitespace token,
    split at every scheme in it."""
    pieces = []
    for token in text.split():
        for i, piece in enumerate(SCHEME_IN_TOKEN.split(token)):
            if piece:
                pieces.append((piece, i > 0))
    return pieces


def raw_authority(piece):
    """The authority of a URL piece as a browser cuts it: up to the first raw
    / ? # or \\ (for http and https a browser reads \\ as /)."""
    return URL_HOST_END.split(piece, maxsplit=1)[0]


def percent_decode(text):
    """Percent-decoded until it no longer changes (at most three rounds), so
    %2E, %66 and a double-encoded %252E all come out as what they spell."""
    for _ in range(3):
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            break
        text = decoded
    return text


# A word that can only be a scheme in front of a host: letters first, no dot.
SCHEME_WORD = re.compile(r"(?i)[a-z][a-z0-9+\-]*:?")


def find_host(piece):
    """(host part, read past a scheme-like prefix) of a token piece without
    a recognised scheme. When the text before the first / ? # or \\ is empty
    or a scheme-like word without a dot (hxxps, hxxps:), the host is the next
    part that is neither, so hxxps//host and hxxps:/host read like
    hxxps://host whatever the scheme's spelling (ADR-0004 part 3,
    amendment). Otherwise the first part is the host."""
    parts = URL_HOST_END.split(piece)
    if len(parts) > 1 and (parts[0] == "" or SCHEME_WORD.fullmatch(parts[0])):
        for part in parts[1:]:
            if part and not SCHEME_WORD.fullmatch(part):
                return part, True
    return parts[0], False


def value_hosts(text):
    """(host, URL-shaped, whole value) for every token piece of text, read
    twice: as written (cut at the raw / ? # \\ first, then decoded, so an
    encoded %2F cannot hide a host) and percent-decoded first (so hxxps%3A//
    is a scheme). [:], [://] and [@] read as what they stand for."""
    found = []
    for reading in (restructure(text), restructure(percent_decode(text))):
        whole = reading.strip()
        for piece, url in token_pieces(reading):
            if url:
                host, shaped = raw_authority(piece), True
            else:
                host, shaped = find_host(piece)
            found.append((percent_decode(host), shaped, piece == whole))
    return list(dict.fromkeys(found))


def host_part(piece):
    """The host part of a token piece: cut at the raw / ? # \\ and decoded
    afterwards, so %2E in a host is a dot, and an encoded %2F
    (hxxps://x%2F@host) cannot hide one."""
    return percent_decode(raw_authority(piece))


def idna_label(label):
    """One label in its ASCII (xn--) form, lowercase."""
    if label.isascii():
        return label.lower()
    try:
        return encodings.idna.ToASCII(label).decode("ascii").lower()
    except UnicodeError:
        try:
            return "xn--" + label.lower().encode("punycode").decode("ascii")
        except UnicodeError:
            return label


# A run of text that can be a host: no space, URL delimiter or markup.
HOST_RUN = re.compile(r"""[^\s/\\?#@:\[\]<>"'()`*]+""")


def idna_fold(text):
    """Every non-ASCII run of text that can be a host in its xn-- form, so a
    Unicode host and its punycode spelling compare equal (R2, R11, R15)."""
    def fold(match):
        run = match.group()
        return run if run.isascii() else ".".join(idna_label(l) for l in run.split("."))
    return HOST_RUN.sub(fold, text)


# IDNA deviation characters: UTS #46 nontransitional processing, which
# browsers use, keeps them, while IDNA2003 (encodings.idna) maps ß to ss and
# ς to σ and drops the joiners. Characters UTS #46 ignores are dropped.
DEVIATIONS = "\u00df\u03c2\u200c\u200d"
ZWJ = "\u200d"
# Every default-ignorable except the joiners, which nontransitional
# processing keeps (CheckJoiners decides whether they are valid).
IGNORED = {c: None for c in INVISIBLE if c not in (0x200C, 0x200D)}


def nontransitional_label(label):
    """One label in its UTS #46 nontransitional xn-- form (deviation
    characters kept, encoded with the punycode codec: faß is xn--fa-hia), or
    None when the browser rejects it. CheckJoiners: a ZWJ is valid only after
    a virama (combining class 9). A ZWNJ is kept in every position, because
    its second valid context (Arabic joining types) is not in the standard
    library, and an extra form only adds a match (fails closed)."""
    out = []
    for i, char in enumerate(label):
        if char in DEVIATIONS:
            if char == ZWJ and (i == 0 or unicodedata.combining(label[i - 1]) != 9):
                return None
            out.append(char)
        else:
            out.append(unicodedata.normalize("NFKC", char).lower())
    label = unicodedata.normalize("NFC", "".join(out))
    if label.isascii():
        return label
    try:
        return "xn--" + label.encode("punycode").decode("ascii")
    except UnicodeError:
        return None


def nontransitional_fold(text):
    """text with every non-ASCII run that can be a host in its UTS #46
    nontransitional form; a run the browser rejects stays as it is."""
    def fold(match):
        run = match.group()
        if run.isascii():
            return run
        labels = [nontransitional_label(l) for l in run.split(".")]
        return run if None in labels else ".".join(labels)
    text = unicodedata.normalize("NFC", text).translate(IGNORED).translate(TO_DOT)
    return HOST_RUN.sub(fold, text).lower()


def authority_host(authority):
    """The host of an authority, userinfo and port cut at the raw @ and :,
    percent-decoded, not folded yet."""
    return percent_decode(re.sub(r":[0-9]*$", "", authority.rsplit("@", 1)[-1]))


def canonical_host(authority):
    """A host as a browser resolves it: userinfo and port cut at the raw @
    and :, percent-decoded, NFKC with dot look-alikes and invisibles folded,
    lowercase, IDNA-folded to the xn-- form, trailing dot stripped. The
    form R12 reads; R15 and R2 also compare the nontransitional form
    (host_forms; ADR-0004 part 3, amendment)."""
    return idna_fold(norm(authority_host(authority))).removesuffix(".")


def host_forms(authority):
    """Every form a browser may resolve the host to: the canonical
    (transitional) form and the UTS #46 nontransitional one. A match on
    either counts (R2, R15)."""
    forms = {canonical_host(authority)}
    nontransitional = nontransitional_fold(authority_host(authority)).removesuffix(".")
    if nontransitional.isascii():
        forms.add(nontransitional)
    return forms


URL_SCHEME = re.compile(r"(?i)[a-z][a-z0-9+.\-]*:(?=[/\\])")
C0_AND_SPACE = "".join(map(chr, range(0x21)))


def url_authority(url):
    """The raw authority of a URL or a bare host (WHATWG: tab and newline
    removed, C0 controls and spaces trimmed, the scheme and any run of / or
    \\ after it skipped)."""
    text = re.sub(r"[\t\n\r]", "", url).strip(C0_AND_SPACE)
    match = URL_SCHEME.match(text)
    rest = text[match.end():] if match else text
    return raw_authority(rest.lstrip("/\\"))


def url_host(url):
    """The canonical host of a URL or a bare host."""
    return canonical_host(url_authority(url))


# One label of an IPv4 address as the WHATWG URL parser reads it: hex, octal
# or decimal (R12).
IP_NUMBER = re.compile(r"0x[0-9a-f]*|0[0-7]*|[1-9][0-9]*")
CANONICAL_IPV4_LABEL = re.compile(r"0|[1-9][0-9]{0,2}")
# The one field where a bare number is a handle, not a host (R12, amendment).
NUMERIC_HANDLE = re.compile(r"params\.artifacts\.handles\[\d+\]\.value")


def ip_literal_form(host, exempt_bare_number):
    """True when host is an IPv4 address in integer, hex, octal or short form
    (3232235777, 0xc0a80001, 127.1), which a browser resolves like the dotted
    form (R12). The canonical dotted form is LIVE_IPV4's. exempt_bare_number
    lets a single decimal or octal number pass (a numeric handle)."""
    h = norm(host).rsplit("@", 1)[-1]
    h = re.sub(r":[0-9]*$", "", h).removesuffix(".")
    labels = h.split(".")
    if not 1 <= len(labels) <= 4:
        return False
    values = []
    for label in labels:
        if not IP_NUMBER.fullmatch(label):
            return False
        if label.startswith("0x"):
            values.append(int(label[2:] or "0", 16))
        elif len(label) > 1 and label.startswith("0"):
            values.append(int(label, 8))
        else:
            values.append(int(label))
    if any(v > 255 for v in values[:-1]) or values[-1] >= 256 ** (5 - len(labels)):
        return False  # not an IPv4 address at all (the URL parser rejects it)
    if len(labels) == 4 and all(CANONICAL_IPV4_LABEL.fullmatch(l) for l in labels):
        return False
    if exempt_bare_number and len(labels) == 1 and not labels[0].startswith("0x"):
        return False
    return True


IP_FORM_PROBLEM = ("IPv4 address in integer, hex, octal or short form (R12: "
                   "write the dotted IPv4, defanged)")


# The one form a urls artifact may take (ADR-0004 part 3, amendment): hxxp or
# hxxps, then :// in one of its DEFANGS spellings (read by restructure), then
# a non-empty authority, then an optional path, query or fragment.
URL_ARTIFACT = re.compile(r"params\.artifacts\.urls\[\d+\]")
URL_FORM = re.compile(r"(?i)hxxps?://(?P<authority>[^/?#\\\s]+)(?:[/?#][^\s\\]*)?")
URL_FORM_PROBLEM = ("not a URL in the form hxxps://host[.]tld/path (the scheme hxxp "
                    "or hxxps, then ://, [://] or [:]//, then a host name or a "
                    "dotted IPv4, never a bracketed IPv6; R12 and R2 read the "
                    "host only from this form)")
LIVE_NAME_PROBLEM = ("live hostname (write every dot as [.], also in a path, a "
                     "file name or a repository: attacker/interview[.]task)")


# IPv6 candidates: the inside of brackets, and a standalone run of hex
# digits, colons and dots that holds a colon (not part of a word, so Foo::Bar
# is no candidate). Only a candidate that parses as IPv6 counts.
IPV6_BRACKETED = re.compile(r"\[([^\[\]\s]*)\]")
IPV6_BARE = re.compile(r"(?<![\w:.])[0-9a-fA-F.]*:[0-9a-fA-F:.]*(?![\w:.])")
IPV6_PROBLEM = ("IPv6 address (an IPv6 artifact cannot be declared, ADR-0004 "
                "part 3)")


def is_ipv6(candidate):
    try:
        ipaddress.IPv6Address(candidate.split("%", 1)[0])
    except ValueError:
        return False
    return True


def has_ipv6_literal(readings):
    """True when any reading holds an IPv6 literal, bracketed or bare. The
    bare unspecified address :: alone is no host a link can reach."""
    for reading in readings:
        if any(is_ipv6(m.group(1)) for m in IPV6_BRACKETED.finditer(reading)):
            return True
        if any(m.group() != "::" and is_ipv6(m.group())
               for m in IPV6_BARE.finditer(reading)):
            return True
    return False


def defang_problems(value, mode, numeric_handle=False, url_field=False):
    """Why a string is not defanged under mode, or [] when it is. The whole
    value is scanned in every reading (as written, with the DEFANGS
    separators read, percent-decoded): every dotted name anywhere in it is
    defanged, a path or file name included, as in record text (R11), so no
    spelling of a scheme can hide a host. A urls value (url_field) must also
    take URL_FORM, and R12 reads its host only from that authority. In other
    fields R12 reads every token's host (value_hosts); a bare single number
    there is an integer IPv4 only as the whole value, and never in
    handles[].value (numeric_handle)."""
    text = unicodedata.normalize("NFKC", value).translate(INVISIBLE)
    problems = []
    if LIVE_SCHEME.search(text):
        problems.append("live URL scheme (write hxxp:// or hxxps://)")
    readings = {text, restructure(text), restructure(percent_decode(text))}
    if any(WWW_PREFIX.search(r) for r in readings):
        problems.append("live www. prefix (write www[.])")
    if any(LIVE_HOST.search(r) for r in readings):
        problems.append(LIVE_NAME_PROBLEM)
    if any(LIVE_IPV4.search(r) for r in readings):
        problems.append("live IPv4 address (write every dot as [.])")
    # An IPv6 artifact cannot be declared (part 3): [::ffff:7f00:1] opens
    # 127.0.0.1. One rule for every host-mode field, urls included.
    ipv6 = has_ipv6_literal(readings)
    if ipv6:
        problems.append(IPV6_PROBLEM)
    if url_field:
        form = URL_FORM.fullmatch(restructure(text))
        host = form.group("authority").rsplit("@", 1)[-1] if form else ""
        if not form or ipv6 or (host.startswith("[") and not host.startswith("[.]")):
            problems.append(URL_FORM_PROBLEM)
        elif ip_literal_form(authority_host(form.group("authority")), False):
            problems.append(IP_FORM_PROBLEM)
    elif any(ip_literal_form(h, not url and (numeric_handle or not whole))
             for h, url, whole in value_hosts(text)):
        problems.append(IP_FORM_PROBLEM)
    return problems


# Inline markup that a reader never sees: HTML comments and tags, link and
# image syntax around their text, code and emphasis markers (R5, R11, R14).
MARKUP_COMMENT = re.compile(r"<!--.*?(?:-->|\Z)", re.S)
MARKUP_AUTOLINK = re.compile(r"<([a-z][a-z0-9+.\-]*:[^<>\s]*|[^<>\s@]+@[^<>\s]+)>", re.I)
MARKUP_TAG = re.compile(r"</?[a-z][^<>]*>", re.I)
MARKUP_LINK = re.compile(r"!?\[([^\]]*)\](?:\([^)]*\)|\[[^\]]*\])")
MARKUP_MARKERS = re.compile(r"[`*_~]+")


def strip_markup(text):
    """The text a reader sees once inline Markdown and HTML render."""
    text = MARKUP_COMMENT.sub("", text)
    text = MARKUP_AUTOLINK.sub(r"\1", text)
    text = MARKUP_TAG.sub("", text)
    text = MARKUP_LINK.sub(r"\1", text)
    text = MARKUP_MARKERS.sub("", text)
    return MD_ESCAPE.sub(r"\1", html.unescape(text))


def rendered_variants(text):
    """text_variants plus each with its markup stripped, folded."""
    variants = text_variants(text)
    return variants | {norm(strip_markup(v)) for v in variants}


def record_text_problems(text):
    """R11 and R12 on one string of record text. Every variant (as written,
    decoded, markup stripped, percent-decoded) is read whole, a URL's path,
    query and fragment included: every dotted name in record text is
    defanged (ADR-0004 part 3). The only live host allowed is the site's
    own; there is no other exemption."""
    problems = []
    for variant in rendered_variants(text):
        scanned = restructure(percent_decode(variant))
        if LIVE_IPV4.search(scanned):
            problems.append("a live IPv4 address (R11: write every dot as [.])")
        if WWW_PREFIX.search(scanned):
            problems.append("a live www. prefix (R11: write www[.])")
        for match in LIVE_HOST.finditer(scanned):
            host = idna_fold(norm(match.group())).removesuffix(".")
            if host == OWN_HOST:
                continue
            if scanned[:match.start()].endswith("@"):
                problems.append(f"an email address on the live host {show(host)} "
                                "(R11: write every dot as [.])")
            else:
                problems.append(f"the live dotted name {show(host)} (R11: write "
                                "every dot as [.], or an undotted form such as "
                                "Doctor Web)")
        for host, url, _ in value_hosts(scanned):
            if url and ip_literal_form(host, False):
                problems.append(f"an {IP_FORM_PROBLEM}")
    return list(dict.fromkeys(problems))


# ---------------------------------------------------------------------------
# JSON-Schema subset validator (ADR-0002 part 4). It fails closed on every
# keyword it does not implement, so a schema never looks stricter than it is.

VALIDATION_KEYWORDS = {
    "type", "required", "properties", "additionalProperties", "items",
    "enum", "const", "pattern", "minLength", "minItems", "minimum", "format",
    "x-defang",
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
        elif key == "minimum":
            if type(value) not in (int, float):
                problems.append(f"{here}: must be a number")
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
    if type(value) in (int, float) and "minimum" in schema:
        if value < schema["minimum"]:
            errors.append(f"{where}: less than the minimum {schema['minimum']!r}")
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
            numeric = NUMERIC_HANDLE.fullmatch(sub_path) is not None
            url_field = URL_ARTIFACT.fullmatch(sub_path) is not None
            for problem in defang_problems(text, mode, numeric, url_field):
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
        self.artifacts = []  # (path, defanged value) of every x-defang string
        path = Path(rel)  # content/<section>/<slug>.md, or content/_index.md
        self.section = path.parts[1] if len(path.parts) > 2 else ""
        self.slug = path.stem

    @property
    def params(self):
        params = self.data.get("params")
        return params if isinstance(params, dict) else {}


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


def read_front_matter(path, rel, findings, what):
    """(data, body, body line) of a content file, or None after a finding."""
    try:
        text = path.read_text(encoding="utf-8").removeprefix("﻿")
    except (OSError, UnicodeDecodeError) as exc:
        findings.add(rel, f"cannot read the {what}: {exc}")
        return None
    match = FRONT_MATTER.match(text)
    if not match:
        findings.add(rel, "front matter must be TOML between +++ lines "
                          "at the top of the file")
        return None
    try:
        data = plain(tomllib.loads(match.group(1)))
    except tomllib.TOMLDecodeError as exc:
        findings.add(rel, f"front matter is not valid TOML: {exc}")
        return None
    return data, text[match.end():], text.count("\n", 0, match.end()) + 1


def load_records(root, schema_dir, findings, index_pages=None):
    """Parse and validate every record. Returns the records that parsed.
    With a list in index_pages, every content/<section>/_index.md that
    parsed is appended to it (R13); without one, they are skipped."""
    schemas = load_schemas(schema_dir, findings)
    content = root / "content"
    records = []
    if not content.is_dir():
        return records
    for path in sorted(p for p in content.rglob("*") if not p.is_dir()):
        rel = path.relative_to(root).as_posix()
        parts = path.relative_to(content).parts
        if len(parts) == 1:
            # A page at the top of content/, not a record. The home page
            # content/_index.md is a section page too (R13).
            if path.name == "_index.md" and index_pages is not None:
                parsed = read_front_matter(path, rel, findings, "section page")
                if parsed:
                    index_pages.append(Record(rel, *parsed))
            continue
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
            # The section page, not a record; R13 checks it.
            if index_pages is not None:
                parsed = read_front_matter(path, rel, findings, "section page")
                if parsed:
                    index_pages.append(Record(rel, *parsed))
            continue
        parsed = read_front_matter(path, rel, findings, "record")
        if not parsed:
            continue
        record = Record(rel, *parsed)
        if section in schemas:
            errors = []
            validate(record.data, schemas[section], "", errors, record.artifacts)
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
# front-matter string except params.sources[].url (ADR-0004 part 3).
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
    """Live URLs in front matter belong only in params.sources[].url (D8)."""
    problems = []
    for path, text in iter_strings(record.data, ""):
        if is_source_url(path):
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
                            "live links belong only in params.sources[].url (D8)")
    return problems


# ---------------------------------------------------------------------------
# Record rules R4 to R15 (ADR-0004, table "Record rules R4 to R15"). Each rule
# reads only values of the right type, so a missing or mistyped field is the
# schema's finding alone and every fixture fails for its own reason.

RECORD_POLICY = "record-policy.json"
SOURCE_URL = re.compile(r"params\.sources\[\d+\]\.url")
DOMAIN_ARTIFACT = re.compile(r"params\.artifacts\.domains\[\d+\]")
SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
PERSONA_SLUG = re.compile(r"persona-[1-9][0-9]*")
SLUG_SUFFIX = re.compile(r"-(?:[2-9]|[1-9][0-9]+)")
ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
INDEX_KEYS = ("title", "description")
# R14: a heuristic net for the D7 label rule, not a proof; review stays
# binding. A word may not run into a phrase from the left (this is a scam).
VERDICT_PHRASE = re.compile(r"(?<!\w)(?:verified scam|confirmed scam|is a scam|"
                            r"scam company|fraudulent company)")


def comparison_variants(text):
    """text_variants plus each percent-decoded, with \\ read as / and
    IDNA-folded, the form canonical_host gives a host (R2)."""
    variants = text_variants(text)
    variants |= {idna_fold(percent_decode(v).replace("\\", "/")) for v in variants}
    return variants | {nontransitional_fold(percent_decode(text).replace("\\", "/"))}


def is_source_url(path):
    return SOURCE_URL.fullmatch(path) is not None


def slugify(name):
    """R4: NFKD ASCII folding, lowercase, [.] and every non-alphanumeric run
    as -, trimmed."""
    folded = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", folded.lower()).strip("-")


def word_variants(text):
    """The text as written, entity-decoded, Markdown-unescaped and with its
    markup stripped: NFKC, case-folded, invisibles dropped, whitespace
    collapsed (R5, R14)."""
    variants = {text, html.unescape(text)}
    variants |= {MD_ESCAPE.sub(r"\1", v) for v in list(variants)}
    variants |= {strip_markup(v) for v in list(variants)}
    return {" ".join(unicodedata.normalize("NFKC", v).translate(INVISIBLE)
                     .casefold().split()) for v in variants}


def record_text(record):
    """(path, string) of every front-matter string that is record text (R11):
    neither an x-defang field nor params.sources[].url."""
    return [(path, text) for path, text in iter_strings(record.data, "")
            if (path, text) not in record.artifacts and not is_source_url(path)]


def free_text(record):
    """(path, string) of every front-matter string except the declared
    artifacts and the source URLs, so names and aliases count (R5, R14)."""
    return [(path, text) for path, text in iter_strings(record.data, "")
            if not path.startswith("params.artifacts.") and not is_source_url(path)]


def declared_artifacts(record):
    """(path, value) of every artifact value under params.artifacts."""
    return [(path, value) for path, value in record.artifacts
            if path.startswith("params.artifacts.")]


def sources_of(record):
    sources = record.params.get("sources")
    return [s for s in sources if isinstance(s, dict)] if isinstance(sources, list) else []


def source_hosts(url):
    """Every form of the host of a source URL (host_forms)."""
    return {h for h in host_forms(url_authority(url)) if h}


def domain_hosts(value):
    """Every form of the live host a domain artifact declares: refanged, then
    read like a source host, so both sides of R15 share the same forms."""
    return {h.removeprefix("*.").strip(".")
            for h in host_forms(url_authority(refang(value)))} - {""}


def load_policy(schema_dir, findings):
    """The retired slugs of schema/record-policy.json (R4). The file holds
    nothing else: an exemption list cannot be added (ADR-0004 part 3)."""
    where = f"schema/{RECORD_POLICY}"
    try:
        policy = json.loads((schema_dir / RECORD_POLICY).read_text(encoding="utf-8"))
    except FileNotFoundError:
        findings.add(where, "missing record policy (it holds retired_slugs, R4)")
        return set()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        findings.add(where, f"cannot read the record policy: {exc}")
        return set()
    if not isinstance(policy, dict):
        findings.add(where, "the record policy must be a JSON object")
        return set()
    extra = sorted(set(policy) - {"retired_slugs"})
    if extra:
        findings.add(where, f"keys not allowed: {', '.join(map(show, extra))}; the "
                     "record policy holds only retired_slugs and no allowlist "
                     "(ADR-0004 part 3)")
    retired = policy.get("retired_slugs")
    if not isinstance(retired, list):
        findings.add(where, "retired_slugs must be a list of slugs")
        return set()
    good = set()
    for i, slug in enumerate(retired):
        if not isinstance(slug, str) or not SLUG.fullmatch(slug):
            findings.add(where, f"retired_slugs[{i}]: {show(slug)} is not a slug")
        elif slug in good:
            findings.add(where, f"retired_slugs[{i}]: {show(slug)} is listed twice")
        else:
            good.add(slug)
    return good


def slug_problems(record, retired):
    """R4: slugs follow the name, persona slugs carry no name, retired slugs
    stay retired."""
    problems = []
    params = record.params
    name = params.get("name")
    if record.section == "reports" and params.get("name_type") == "persona":
        if not PERSONA_SLUG.fullmatch(record.slug):
            problems.append(f"slug {show(record.slug)}: a persona report's slug is "
                            "persona-N with N >= 1, so its URL never carries a "
                            "name (R4)")
    elif isinstance(name, str):
        base = slugify(name)
        if not base:
            problems.append("params.name slugifies to nothing, so it gives no slug (R4)")
        elif record.slug != base and not (record.slug.startswith(base)
                                          and SLUG_SUFFIX.fullmatch(record.slug[len(base):])):
            problems.append(f"slug {show(record.slug)} is neither {show(base)} nor "
                            f"{show(base + '-N')} with N >= 2, the slug of params.name (R4)")
    if record.slug in retired:
        problems.append(f"slug {show(record.slug)} is retired in schema/{RECORD_POLICY} "
                        "and is never reused (R4)")
    return problems


def reference_problems(record, campaign_slugs, report_slugs):
    """R7: campaign, source and related references resolve."""
    problems = []
    params = record.params
    ids = [s["id"] for s in sources_of(record) if isinstance(s.get("id"), str)]
    for dup in sorted({i for i in ids if ids.count(i) > 1}):
        problems.append(f"params.sources: the source id {show(dup)} appears more than "
                        "once; source ids are unique per record (R7)")
    if record.section == "campaigns":
        attribution = params.get("attribution")
        for i, entry in enumerate(attribution if isinstance(attribution, list) else []):
            source = entry.get("source") if isinstance(entry, dict) else None
            if isinstance(source, str) and source not in ids:
                problems.append(f"params.attribution[{i}].source {show(source)} is no "
                                "source id of this record; attribution is stated "
                                "only as a cited source states it (R7)")
        return problems
    campaign = params.get("campaign")
    if isinstance(campaign, dict):
        slug = campaign.get("slug")
        if isinstance(slug, str) and slug not in campaign_slugs:
            problems.append(f"params.campaign.slug {show(slug)} names no campaign "
                            "record content/campaigns/<slug>.md (R7)")
        source = campaign.get("source")
        if isinstance(source, str) and source not in ids:
            problems.append(f"params.campaign.source {show(source)} is no source id of "
                            "this record (R7)")
        basis = campaign.get("basis")
        if basis == "artifact":
            if "artifact" not in campaign:
                problems.append("params.campaign: basis \"artifact\" needs "
                                "params.campaign.artifact, the declared artifact "
                                "the cited source lists (R7)")
            elif not isinstance(campaign["artifact"], str):
                pass  # the schema reports the type
            elif campaign["artifact"] not in {v for _, v in declared_artifacts(record)}:
                problems.append(f"params.campaign.artifact {show(campaign['artifact'])} "
                                "is none of this record's declared artifact values (R7)")
        elif basis == "named" and "artifact" in campaign:
            problems.append("params.campaign.artifact: basis \"named\" takes no "
                            "artifact; use basis \"artifact\" when the source lists "
                            "one (R7)")
    related = params.get("related")
    for i, slug in enumerate(related if isinstance(related, list) else []):
        if not isinstance(slug, str):
            continue
        if slug == record.slug:
            problems.append(f"params.related[{i}]: a report is not related to "
                            "itself (R7)")
        elif slug not in report_slugs:
            problems.append(f"params.related[{i}] {show(slug)} names no report "
                            "record content/reports/<slug>.md (R7)")
    return problems


def date_problems(record):
    """R8: first seen <= last seen (<= last reviewed for reports)."""
    params = record.params
    dates = {key: params.get(key) for key in ("first_seen", "last_seen", "last_reviewed")}
    dates = {k: v for k, v in dates.items() if isinstance(v, str) and ISO_DATE.fullmatch(v)}
    order = [("first_seen", "last_seen")]
    if record.section == "reports":
        order.append(("last_seen", "last_reviewed"))
    return [f"params.{later} {dates[later]} is before params.{earlier} "
            f"{dates[earlier]} (R8)"
            for earlier, later in order
            if earlier in dates and later in dates and dates[later] < dates[earlier]]


def report_problems(record):
    """R6, R9 and R10: rules on one report's own fields."""
    problems = []
    params = record.params
    if "hide_name" in params and params.get("name_type") != "persona":
        problems.append("params.hide_name: only a persona record can hide its "
                        "name (R6)")
    count = params.get("independent_reports")
    if type(count) is int and count < 1 and not sources_of(record):
        problems.append("params.independent_reports is 0 and the record cites no "
                        "source; a report needs an independent report or a cited "
                        "source (R9)")
    if isinstance(params.get("artifacts"), dict) and not declared_artifacts(record):
        problems.append("params.artifacts declares no artifact; a report declares "
                        "at least one (R10)")
    return problems


def text_problems(record):
    """R11 and R12 on the record text of a record or section page."""
    problems = []
    for path, text in record_text(record):
        for problem in record_text_problems(text):
            problems.append(f"{path}: record text contains {problem}")
    for offset, line in enumerate(record.body.split("\n")):
        for problem in record_text_problems(line):
            problems.append(f"line {record.body_line + offset}: body contains {problem}")
    return problems


def verdict_problems(record):
    """R14: no verdict phrase in a free-text string or the body."""
    problems = []
    for path, text in free_text(record) + [("body", record.body)]:
        found = {m.group() for v in word_variants(text) for m in VERDICT_PHRASE.finditer(v)}
        for phrase in sorted(found):
            problems.append(f"{path}: contains the verdict phrase {phrase!r}; labels "
                            "state facts, never a verdict (R14, D7)")
    return problems


def persona_problems(records):
    """R5: (record, problem) for every persona name or alias in the free text
    or body of any record, so hide_name can remove it in one line."""
    found = []
    personas = []
    for persona in records:
        params = persona.params
        if persona.section != "reports" or params.get("name_type") != "persona":
            continue
        names = [("params.name", params.get("name"))]
        aliases = params.get("aliases")
        names += [(f"params.aliases[{i}]", a)
                  for i, a in enumerate(aliases if isinstance(aliases, list) else [])]
        for field, name in names:
            folded = word_variants(name) if isinstance(name, str) else set()
            for text in sorted(t for t in folded if t):
                personas.append((persona, field, re.compile(
                    rf"(?<!\w){re.escape(text)}(?!\w)")))
    for record in records:
        texts = free_text(record) + [("body", record.body)]
        for persona, field, pattern in personas:
            for path, text in texts:
                if record is persona and (path == "params.name"
                                          or path.startswith("params.aliases[")):
                    continue
                if any(pattern.search(v) for v in word_variants(text)):
                    found.append((record, f"{path}: contains the {field} of the persona "
                                  f"record {persona.rel}; a persona name renders only "
                                  "from that record, so hide_name can remove it (R5)"))
    return list(dict.fromkeys(found))


def host_relation(host, domain):
    """How a source host relates to a declared domain (R15), or None."""
    if host == domain:
        return "equals"
    if host.endswith("." + domain):
        return "is a subdomain of"
    if domain.endswith("." + host):
        return "is a parent of"
    return None


def source_problems(records):
    """(record, problem) for R12 and R15 on every params.sources[].url."""
    found = []
    domains = [(r, path, value, domain_hosts(value))
               for r in records if r.section == "reports"
               for path, value in r.artifacts if DOMAIN_ARTIFACT.fullmatch(path)]
    for record in records:
        for i, source in enumerate(sources_of(record)):
            url = source.get("url")
            if not isinstance(url, str):
                continue
            where = f"params.sources[{i}].url"
            # A browser reads the IDNA deviation characters (ss, final sigma,
            # the joiners) nontransitionally, so only an ASCII host has one
            # reading (ADR-0004 part 3, amendment).
            if not authority_host(url_authority(url)).isascii():
                found.append((record, f"{where}: its host is not ASCII; write the "
                              "xn-- form of the host, which a browser reads only "
                              "one way (R15)"))
            hosts = source_hosts(url)
            if not hosts:
                continue
            if any(ip_literal_form(h, False) for h in hosts):
                found.append((record, f"{where}: its host is an {IP_FORM_PROBLEM}"))
            for other, path, value, forms in domains:
                for host, domain in sorted((h, d) for h in hosts for d in forms):
                    relation = host_relation(host, domain)
                    if relation:
                        found.append((record, f"{where}: its host {show(host)} "
                                      f"{relation} the declared artifact domain "
                                      f"{show(value)} ({other.rel}: {path}); a source "
                                      "never points at a declared domain (R15)"))
                        break
    return found


def index_problems(page):
    """R13: a section page carries only title and description strings, plus
    the body rule and R11."""
    problems = []
    extra = sorted(set(page.data) - set(INDEX_KEYS))
    if extra:
        problems.append(f"front matter keys not allowed: {', '.join(map(show, extra))}; "
                        "an _index.md carries only title and description (R13)")
    for key in INDEX_KEYS:
        if key in page.data and not isinstance(page.data[key], str):
            problems.append(f"{key}: must be a string (R13)")
    return problems + body_problems(page) + front_matter_problems(page) + text_problems(page)


def cmd_records(args):
    root = Path(args.root).resolve()
    schema_dir = Path(args.schemas).resolve() if args.schemas else root / "schema"
    if not root.is_dir():
        raise UsageError(f"--root {root} is not a directory")
    findings = Findings()
    index_pages = []
    records = load_records(root, schema_dir, findings, index_pages)
    retired = load_policy(schema_dir, findings)
    for record in records:
        for problem in body_problems(record) + front_matter_problems(record):
            findings.add(record.rel, problem)
    forms = live_forms(records)
    for live, origin, path, value in forms:
        targets = {live, idna_fold(live), nontransitional_fold(refang(value))}
        for record in records:
            for spath, text in iter_strings(record.data, ""):
                if (spath, text) in record.artifacts:
                    continue  # artifact fields carry the defanged form
                if any(t in v for t in targets for v in comparison_variants(text)):
                    findings.add(record.rel, f"{spath}: the live form of artifact "
                                 f"{show(value)} ({origin.rel}: {path}) appears "
                                 "here (R2)")
            if any(t in v for t in targets for v in comparison_variants(record.body)):
                findings.add(record.rel, f"body: the live form of artifact "
                             f"{show(value)} ({origin.rel}: {path}) appears "
                             "here (R2)")
    campaign_slugs = {r.slug for r in records if r.section == "campaigns"}
    report_slugs = {r.slug for r in records if r.section == "reports"}
    for record in records:
        problems = slug_problems(record, retired)
        problems += reference_problems(record, campaign_slugs, report_slugs)
        problems += date_problems(record)
        if record.section == "reports":
            problems += report_problems(record)
        problems += text_problems(record) + verdict_problems(record)
        for problem in problems:
            findings.add(record.rel, problem)
    for record, problem in persona_problems(records) + source_problems(records):
        findings.add(record.rel, problem)
    for page in index_pages:
        for problem in index_problems(page):
            findings.add(page.rel, problem)
    n_reports = sum(r.section == "reports" for r in records)
    n_artifacts = sum(len(declared_artifacts(r)) for r in records)
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
# Render rules on the built site (ADR-0004; milestone 3, PR 3). They pin the
# markup contract the record templates implement: the class hooks below, the
# fixed D6, D7 and D10 wording, the titles, the links a record page may carry
# and the structured data. The wording lives here on purpose a second time,
# independently of data/labels.toml, so a copy change shows up in a
# safety-net diff (ADR-0004 Consequences).

STATE_CHIP = {"name_abused": "Name abused", "front": "Front"}
STATE_SENTENCE = {
    "name_abused": "This name belongs to someone else. The campaign used it "
                   "without their involvement.",
    "front": "No real company, person or product was found behind this name.",
}
PERSONA_LABEL = "(name used by the campaign, possibly a stolen identity)"
TITLE_SUFFIX = " · interviewscam.com"
REPORT_TITLE = "{name}, a name used in fake job interviews"
HIDDEN_TITLE = "A person's name used in fake job interviews, hidden on request"
CAMPAIGN_TITLE = "{name}, a campaign family that uses fake job interviews"
SECTION_TITLES = {"reports": "Names used in fake job interviews",
                  "campaigns": "Campaign families"}
LABEL_REPORTED = "Reported {n} times, evidence reviewed on {date}"
LABEL_REPORTED_ONCE = "Reported once, evidence reviewed on {date}"
LABEL_ONE_SOURCE = "Named in 1 cited source, reviewed on {date}"
LABEL_SOURCES = "Named in {k} cited sources, reviewed on {date}"
CAMPAIGN_LINE = "Campaign family that used this name: {campaign}. Source: {source}"
CAMPAIGN_LINE_ARTIFACT = ", which lists {artifact}"
UNATTRIBUTED = "Campaign family: unattributed"
SOURCE_REF = "{title} ({publisher}, {date})"
ATTRIBUTION_LINE = "{statement}, as stated by {source}"
NO_ATTRIBUTION = "No attribution is stated by the cited sources."
# The two lookup URL forms of a SHA-256 (ADR-0004 part 9).
LOOKUPS = {
    "malwarebazaar": "https://bazaar.abuse.ch/sample/{}/",
    "virustotal": "https://www.virustotal.com/gui/file/{}",
}
HOME_LATEST = 5  # ADR-0004 Numbers: the Home list of 5 reports
# Structured data (ADR-0004 part 8): JSON-LD only, from these types only.
JSONLD_TYPES = {"WebPage", "WebSite", "Organization", "BreadcrumbList", "ListItem"}
JSONLD_ORGANIZATION = "interviewscam.com"
# The only context: an inline context could alias @type to another key. The
# schema.org context itself maps "type" to "@type", so both keys are read.
JSONLD_CONTEXT = "https://schema.org"
JSONLD_TYPE_KEYS = ("@type", "type")
# The keys each type may carry (ADR-0004 part 8 and the JSON-LD contract of
# the record pages): an allowlist, so an IRI key (rdf:type), a prefixed key
# (schema:additionalType), additionalType, about, mentions or a keyword such
# as @reverse cannot add an object about a record's subject. Every object is
# typed; the block root may instead be a bare @graph container.
# No dateModified: no record states when it was last changed, so the key
# would claim a modification the record does not state (ADR-0004 part 8).
JSONLD_KEYS = {
    "WebPage": {"url", "name", "description", "datePublished", "lastReviewed",
                "isPartOf", "publisher"},
    "WebSite": {"name", "url"},
    "Organization": {"name", "url"},
    "BreadcrumbList": {"itemListElement"},
    "ListItem": {"position", "name", "item"},
}
JSONLD_OBJECT_KEYS = {"@context", "@id", *JSONLD_TYPE_KEYS}
# lastReviewed is a report's D7 evidence review (params.last_reviewed); only
# a report page may carry it (ADR-0004 part 8).
REPORT_PAGE_URL = re.compile(re.escape(SITE_ORIGIN) + r"/reports/[^/]+/")
JSONLD_GRAPH_KEYS = {"@context", "@graph"}
MICRODATA_ATTRS = ("itemscope", "itemtype", "itemprop", "vocab", "typeof")
# RDFa: a second structured-data syntax, banned outright (ADR-0004 part 8).
# The base layout uses none of them (no Open Graph <meta property>), so no
# exception exists. A rel token with a colon is an RDFa CURIE.
RDFA_ATTRS = ("property", "resource", "prefix", "about", "datatype", "inlist")
VOID_ELEMENTS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
                 "meta", "param", "source", "track", "wbr"}
NO_TEXT_ELEMENTS = {"script", "style", "template"}
HIDING_TAGS = {"template", "noscript", "select", "datalist"}
# Elements whose end tag HTML lets a page omit. The render tree infers no
# end tags, so an omitted one is a finding of its own (close every <li>).
OPTIONAL_END = ("li", "p", "dt", "dd", "tr", "td", "th", "option")
# Text a reader may never see: content in these never meets a requirement
# (a chip, a state sentence, a persona label), and a persona name in it is a
# finding (rules 3 to 6).
HIDDEN_CONTENT = ("hidden, aria-hidden, visually-hidden, <template>, <noscript>, "
                  "<select>, an SVG <title>, a closed <dialog> or <details>")
# Rule 7 on every page: URL schemes that carry or open a file in place.
FILE_SCHEMES = ("data", "blob", "javascript", "vbscript", "file")
# Rule 7 on every page: a link to a lookup service is one of the two lookup
# page forms, never a sample download or an API path.
LOOKUP_SERVICE_HOSTS = ("abuse.ch", "virustotal.com")
LOOKUP_PAGE = re.compile(r"https://bazaar\.abuse\.ch/sample/[0-9a-f]{64}/"
                         r"|https://www\.virustotal\.com/gui/file/[0-9a-f]{64}")
# Rule 7 on every page: an internal link (relative or to the site's own
# host) points to a page path, which ends in "/", or to one of these
# non-page files. The production build and the fixtures link none today
# (404.html is served, never linked); PR 5 adds /feed.json.
INTERNAL_FILES = frozenset()
# The one written form of an absolute link to the site's own host.
OWN_URL = re.compile(r"https://interviewscam\.com(?:[/?#]|$)")
# Rule 3: a link to a report page, and the list-item contract around it.
REPORT_LINK = re.compile(r"/reports/([^/]+)(?:/|$)")
RECORD_DATE = "record-date"
# Rule 9 and rule 4: the alphanumeric tokens of a name, matched with at
# least one other character between them (Morgan+Placeholder,
# morgan-placeholder, morgan_placeholder.png). Joined with no separator
# (MorganPlaceholder) only when every token has at least JOIN_MIN_LETTERS
# letters, so short tokens such as "A. Bout", "Li Ke" or "T. Rust" never
# match ordinary words (about, like, trust).
JOIN_MIN_LETTERS = 4
NAME_TOKEN = re.compile(r"[^\W_]+")


class Element:
    """One element of a built page: tag, attributes, children (Element or str)."""

    def __init__(self, tag, attrs, parent):
        self.tag = tag
        self.attrs = attrs
        self.parent = parent
        self.children = []

    @property
    def classes(self):
        return self.attrs.get("class", "").split()

    def walk(self):
        yield self
        for child in self.children:
            if isinstance(child, Element):
                yield from child.walk()

    def hides(self):
        """The element itself hides its content (HIDDEN_CONTENT): any
        hidden attribute whatever its value, aria-hidden="true", the class
        visually-hidden, <template>, <noscript>, a <select> or <datalist>
        (option text is no inline copy), an SVG <title> or <desc> (a
        tooltip), a <dialog> without open, and every child of a <details>
        without open except its <summary>."""
        parent = self.parent
        return (self.tag in HIDING_TAGS or "hidden" in self.attrs
                or self.attrs.get("aria-hidden", "").strip().lower() == "true"
                or VISUALLY_HIDDEN in self.classes
                or (self.tag == "dialog" and "open" not in self.attrs)
                or (self.tag in ("title", "desc") and self.inside_tag("svg"))
                or (parent is not None and parent.tag == "details"
                    and "open" not in parent.attrs and self.tag != "summary"))

    def concealed(self):
        """The element or one of its ancestors hides it."""
        el = self
        while el is not None:
            if el.hides():
                return True
            el = el.parent
        return False

    def strings(self, shown=True):
        """Text pieces; shown=True skips hidden content, shown=False keeps
        it, <template> content included (never script or style)."""
        closed = shown and self.tag == "details" and "open" not in self.attrs
        for child in self.children:
            if isinstance(child, str):
                if not closed:  # loose text of a closed <details> is hidden
                    yield child
            elif shown and (child.tag in NO_TEXT_ELEMENTS or child.hides()):
                continue
            elif child.tag not in ("script", "style"):
                yield from child.strings(shown)

    def text(self, sep="", shown=True):
        """The text inside the element, whitespace collapsed, hidden content
        left out (shown=False keeps it). sep="" joins the text pieces as a
        browser lays out inline text; sep=" " also separates block
        neighbours that a tight join would run together."""
        return squash(sep.join(self.strings(shown)))

    def nearest(self, tag):
        el = self.parent
        while el is not None and el.tag != tag:
            el = el.parent
        return el

    def inside_tag(self, tag):
        el = self.parent
        while el is not None:
            if el.tag == tag:
                return True
            el = el.parent
        return False

    def inside(self, cls):
        el = self.parent
        while el is not None:
            if cls in el.classes:
                return True
            el = el.parent
        return False


class RenderPage(Page):
    """Page, plus an element tree that keeps each element's text and class
    list, so the render rules can be scoped to the class hooks."""

    def __init__(self):
        super().__init__()
        self.root = Element("#document", {}, None)
        self._open = [self.root]
        self.jsonld = []  # raw text of every application/ld+json block
        self._script = None
        # Elements of OPTIONAL_END closed without their own end tag: the
        # tree infers no end tags, so such a page is reported, not read.
        self.unclosed = []

    def _tree_element(self, tag, attrs):
        first = {}
        for name, value in attrs:
            first.setdefault(name, value if value is not None else "")
        el = Element(tag, first, self._open[-1])
        self._open[-1].children.append(el)
        return el

    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        el = self._tree_element(tag, attrs)
        if tag == "script":
            ld = el.attrs.get("type", "").strip().lower() == JSON_LD
            self._script = [] if ld else None
        if tag not in VOID_ELEMENTS:
            self._open.append(el)

    def handle_startendtag(self, tag, attrs):
        super().handle_startendtag(tag, attrs)
        self._tree_element(tag, attrs)

    def handle_endtag(self, tag):
        super().handle_endtag(tag)
        if tag == "script" and self._script is not None:
            self.jsonld.append("".join(self._script))
            self._script = None
        # An end tag closes the nearest open element of its name; a stray
        # one is ignored, as a browser ignores it.
        for i in range(len(self._open) - 1, 0, -1):
            if self._open[i].tag == tag:
                self.unclosed += [el.tag for el in self._open[i + 1:]
                                  if el.tag in OPTIONAL_END]
                del self._open[i:]
                break

    def close(self):
        super().close()
        self.unclosed += [el.tag for el in self._open[1:] if el.tag in OPTIONAL_END]
        del self._open[1:]

    def handle_data(self, data):
        super().handle_data(data)
        if self._script is not None:
            self._script.append(data)
        self._open[-1].children.append(data)


def squash(text):
    return " ".join(text.split())


def fold_words(text):
    """NFKC, invisibles dropped, case-folded, whitespace collapsed (R5)."""
    return " ".join(unicodedata.normalize("NFKC", text).translate(INVISIBLE)
                    .casefold().split())


def parse_render_page(text):
    page = RenderPage()
    page.feed(text)
    page.close()
    return page


def jsonld_values(page):
    """(index, parsed value or None, error) of every JSON-LD block."""
    blocks = []
    for i, raw in enumerate(page.jsonld):
        try:
            blocks.append((i, json.loads(raw), None))
        except json.JSONDecodeError as exc:
            blocks.append((i, None, str(exc)))
    return blocks


def by_class(page, cls):
    return [n for n in page.root.walk() if cls in n.classes]


def by_tag(page, tag):
    return [n for n in page.root.walk() if n.tag == tag]


def links_in(el, shown=False):
    """(href, link text) of every <a> or <area> link inside el, the SVG
    xlink:href form included; shown=True leaves out links in hidden
    content, which never meet a requirement."""
    return [(a.attrs[name], a.text()) for a in el.walk() if a.tag in ("a", "area")
            and not (shown and a.concealed())
            for name in ("href", "xlink:href") if name in a.attrs]


def browser_url(url):
    """url as the WHATWG parser reads it: tabs and newlines dropped, C0
    controls and spaces stripped at both ends."""
    return re.sub(r"[\t\n\r]", "", url).strip(C0_AND_SPACE)


def site_path(href, page_path):
    """The percent-decoded path on the site's own host that an href points
    to, read as a browser reads it (backslashes as slashes; any case,
    trailing dot, http or https, port or userinfo), the bare origin as "/";
    None for another host or scheme. Whether the href is written in the
    canonical form is internal_link_problems' finding."""
    url = browser_url(href).replace("\\", "/")
    try:
        parts = urllib.parse.urlsplit(urllib.parse.urljoin(SITE_ORIGIN + page_path, url))
        host = (parts.hostname or "").rstrip(".")
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or host != OWN_HOST:
        return None
    return urllib.parse.unquote(parts.path) or "/"


def nav_targets(page):
    """(element, URL) of every navigation a click or a submit makes: <a> and
    <area> href (and SVG xlink:href), <form action>, <button formaction>
    and <input formaction>."""
    targets = []
    for el in page.root.walk():
        if el.tag in ("a", "area"):
            names = ("href", "xlink:href")
        elif el.tag == "form":
            names = ("action",)
        elif el.tag in ("button", "input"):
            names = ("formaction",)
        else:
            continue
        targets += [(el, el.attrs[name]) for name in names if name in el.attrs]
    return targets


def text_param(record, key):
    value = record.params.get(key)
    return value if isinstance(value, str) else None


def is_persona(record):
    return record.section == "reports" and record.params.get("name_type") == "persona"


def is_hidden(record):
    return is_persona(record) and record.params.get("hide_name") is True


def record_names(record):
    """(field, name) of params.name and every alias that is a string."""
    names = [("params.name", record.params.get("name"))]
    aliases = record.params.get("aliases")
    names += [(f"params.aliases[{i}]", a)
              for i, a in enumerate(aliases if isinstance(aliases, list) else [])]
    return [(field, name) for field, name in names if isinstance(name, str) and name.strip()]


def display_name(record):
    """The name as it renders: with the D10 label for a visible persona."""
    name = text_param(record, "name") or ""
    return f"{name} {PERSONA_LABEL}" if is_persona(record) else name


def record_title(record):
    """The fixed title of a record page, without the site suffix (rule 2)."""
    if record.section == "campaigns":
        return CAMPAIGN_TITLE.format(name=text_param(record, "name") or "")
    if is_hidden(record):
        return HIDDEN_TITLE
    return REPORT_TITLE.format(name=display_name(record))


def record_label(record):
    """The D7 label of a report (rule 5), or None when none can be derived."""
    count = record.params.get("independent_reports")
    date = text_param(record, "last_reviewed")
    if type(count) is not int or date is None:
        return None
    if count >= 2:
        return LABEL_REPORTED.format(n=count, date=date)
    if count == 1:
        return LABEL_REPORTED_ONCE.format(date=date)
    k = len(sources_of(record))
    if k == 0:
        return None  # R9 is the records check's finding
    return LABEL_ONE_SOURCE.format(date=date) if k == 1 else \
        LABEL_SOURCES.format(k=k, date=date)


def source_ref(source):
    return SOURCE_REF.format(title=source.get("title"), publisher=source.get("publisher"),
                             date=source.get("date"))


def source_by_id(record, source_id):
    for source in sources_of(record):
        if source.get("id") == source_id:
            return source
    return None


def lookup_urls(record):
    """(declared lookup URLs per listed_on, every lookup URL of a declared
    hash) of a report (rule 7)."""
    listed, possible = set(), set()
    artifacts = record.params.get("artifacts")
    hashes = artifacts.get("sha256") if isinstance(artifacts, dict) else None
    for entry in hashes if isinstance(hashes, list) else []:
        if not isinstance(entry, dict) or not isinstance(entry.get("value"), str):
            continue
        value = entry["value"]
        possible |= {form.format(value) for form in LOOKUPS.values()}
        on = entry.get("listed_on")
        for service in on if isinstance(on, list) else []:
            if service in LOOKUPS:
                listed.add(LOOKUPS[service].format(value))
    return listed, possible


def name_pattern(name):
    """A name as whole words (NFKC, case-folded): its alphanumeric tokens in
    order, with a run of other characters between them (or none, when
    every token has JOIN_MIN_LETTERS letters), and no letter or digit right
    before or after (rules 4 and 9). An initial (a single-letter token)
    matches only with a period right after it ("A. Page", "a.page"), so it
    never meets ordinary copy such as "a page"."""
    folded = fold_words(name)
    tokens = NAME_TOKEN.findall(folded)
    if not tokens:
        return re.compile(rf"(?<![^\W_]){re.escape(folded)}(?![^\W_])")
    joinable = all(sum(c.isalpha() for c in tok) >= JOIN_MIN_LETTERS for tok in tokens)

    def initial(tok):
        return len(tok) == 1 and tok.isalpha()
    parts = []
    for i, tok in enumerate(tokens):
        if i:
            parts.append(r"[\W_]*" if joinable or initial(tokens[i - 1]) else r"[\W_]+")
        parts.append(re.escape(tok) + (r"\." if initial(tok) else ""))
    return re.compile(rf"(?<![^\W_]){''.join(parts)}(?![^\W_])")


def title_problems(page, want):
    """Rule 2: one <title> with the fixed title plus suffix, one <h1> with
    the fixed title."""
    problems = []
    # An SVG <title> is a tooltip, not the document title.
    titles = [n for n in by_tag(page, "title") if not n.inside_tag("svg")]
    if len(titles) != 1:
        problems.append(f"rule 2: {len(titles)} <title> elements, exactly one is needed")
    for el in titles:
        if el.text() != want + TITLE_SUFFIX:
            problems.append(f"rule 2: <title> reads {show(el.text())}, the fixed title "
                            f"is {show(want + TITLE_SUFFIX)} (SPEC section 5)")
    h1s = by_tag(page, "h1")
    if len(h1s) != 1:
        problems.append(f"rule 2: {len(h1s)} <h1> elements, exactly one is needed")
    for el in h1s:
        if el.text() != want:
            problems.append(f"rule 2: <h1> reads {show(el.text())}, the fixed title "
                            f"is {show(want)} (SPEC section 5)")
    return problems


def shown_one(els, cls, rule):
    """(the one visible element or None, problems) for a hook that must
    occur exactly once; a hidden one never counts (HIDDEN_CONTENT)."""
    shown = [n for n in els if not n.concealed()]
    hidden = len(els) - len(shown)
    note = f" (and {hidden} in hidden content: {HIDDEN_CONTENT}, which never " \
        "counts)" if hidden else ""
    if len(shown) != 1:
        return (shown[0] if shown else None,
                [f"{rule}: {len(shown)} elements of class {cls}{note}, exactly one "
                 "visible one is needed"])
    if hidden:
        return shown[0], [f"{rule}: {hidden} element(s) of class {cls} in hidden "
                          f"content ({HIDDEN_CONTENT}); a hook is never hidden"]
    return shown[0], []


def one_of_class(page, cls, rule):
    """(el or None, problems) for a hook that must occur exactly once."""
    return shown_one(by_class(page, cls), cls, rule)


def report_links(page, page_path):
    """(element, slug) of every link to a report page (rule 3), a link to
    the page itself (the skip link, an in-page anchor) aside."""
    links, seen = [], set()
    for el, url in nav_targets(page):
        path = site_path(url, page_path)
        match = REPORT_LINK.match(path) if path and path != page_path else None
        if match and id(el) not in seen:
            seen.add(id(el))
            links.append((el, match.group(1)))
    return links


def report_items(page, page_path, reports):
    """Rule 3 (D6) on every page: each link to a report page is a list
    item with the name, exactly one state chip reading the report's state
    and the date (the list-item contract of ADR-0004). Returns (the list
    items that hold a report link, problems)."""
    problems, items = [], {}
    for a, slug in report_links(page, page_path):
        where = f"/reports/{slug}/"
        record = reports.get(slug)
        li = a.nearest("li")
        if record is None:
            problems.append(f"rule 3: a link points to {where}, which is no report record")
        elif li is None:
            problems.append(f"rule 3: the link to {where} sits in no list item; every "
                            "link to a report is a list item with the name, one state "
                            "chip and the date (D6)")
        else:
            items.setdefault(id(li), (li, []))[1].append((slug, record))
    for li, entries in items.values():
        slug, record = entries[0]
        where = f"/reports/{slug}/"
        if len(entries) > 1:
            problems.append(f"rule 3: one list item holds {len(entries)} report links "
                            f"({', '.join(f'/reports/{s}/' for s, _ in entries)}); each "
                            "report is its own item with its own chip (D6)")
            continue
        state = record.params.get("state")
        chips = [n for n in li.walk() if "state-chip" in n.classes]
        chip, found = shown_one(chips, "state-chip",
                                f"rule 3: the list item linking {where}")
        problems += [f"{p} (D6)" for p in found]
        if chip is not None and not found and state in STATE_CHIP \
                and chip.text() != STATE_CHIP[state]:
            problems.append(f"rule 3: the state chip next to {where} reads "
                            f"{show(chip.text())}, the state {state} reads "
                            f"{show(STATE_CHIP[state])} (D6)")
        dates = [n for n in li.walk() if RECORD_DATE in n.classes]
        date_el, found = shown_one(dates, RECORD_DATE,
                                   f"rule 3: the list item linking {where}")
        problems += found
        want = record.data.get("date")
        if date_el is not None and not found and isinstance(want, str) \
                and date_el.text() != want:
            problems.append(f"rule 3: the list item linking {where} shows the date "
                            f"{show(date_el.text())}, the record's date is {want}")
    return [li for li, _ in items.values()], problems


def own_chips(page, items):
    """The state chips that sit in no list item holding a report link."""
    inside = {id(n) for li in items for n in li.walk()}
    return [n for n in by_class(page, "state-chip") if id(n) not in inside]


def state_problems(page, record, chips):
    """Rule 3 (D6) on a report page: exactly one chip of its own (chips is
    the page's chips outside report list items) with the state's text, the
    state sentence, and the What was checked list equal to state_basis, in
    order."""
    problems = []
    state = record.params.get("state")
    if state not in STATE_CHIP:
        return problems  # the schema's finding
    chip, found = shown_one(chips, "state-chip", "rule 3")
    problems += found
    if chip is not None and chip.text() != STATE_CHIP[state]:
        problems.append(f"rule 3: the state chip reads {show(chip.text())}, the state "
                        f"{state} reads {show(STATE_CHIP[state])} (D6)")
    sentence, found = one_of_class(page, "state-sentence", "rule 3")
    problems += found
    if sentence is not None and sentence.text() != STATE_SENTENCE[state]:
        problems.append(f"rule 3: the state sentence reads {show(sentence.text())}, the "
                        f"state {state} reads {show(STATE_SENTENCE[state])} (D6)")
    basis = record.params.get("state_basis")
    want = [squash(b) for b in basis if isinstance(b, str)] if isinstance(basis, list) else []
    el, found = one_of_class(page, "state-basis", "rule 3")
    problems += found
    if el is not None:
        got = [li.text() for li in el.walk() if li.tag == "li" and not li.concealed()]
        if got != want:
            problems.append(f"rule 3: What was checked lists {got!r}, params.state_basis "
                            f"is {want!r} in this order (D6)")
    return problems


def chip_problems(page, chips, report_page):
    """Rule 3 on every page: a chip carries only its own class (never a
    warning or call-to-action colour) and one of the two state texts, and
    outside report list items a chip appears only on a report page (chips
    is the page's chips outside report list items)."""
    problems = []
    for chip in by_class(page, "state-chip"):
        if chip.classes != ["state-chip"]:
            problems.append(f"rule 3: a state chip has the classes {chip.classes!r}; it "
                            "carries the class state-chip alone, so no warning colour "
                            "reaches it (D6, pick constraint 1)")
        if chip.text() not in STATE_CHIP.values():
            problems.append(f"rule 3: a state chip reads {show(chip.text())}, not one of "
                            f"{sorted(STATE_CHIP.values())!r} (D6)")
    if not report_page and chips:
        problems.append(f"rule 3: {len(chips)} state chip(s) belong to no report link; "
                        "a chip sits in the list item of a report link or once on its "
                        "report page (D6)")
    return problems


def page_texts(page):
    """Every text of a page a reader or a search engine sees: the joined
    visible text (tight and spaced), each JSON-LD string and every attribute
    value, as written and percent-decoded (an alt, an aria-description, a
    search link)."""
    texts = [page.root.text(), page.root.text(" ")]
    for _, value, _ in jsonld_values(page):
        if value is not None:
            texts += list(json_strings(value))
    for el in page.root.walk():
        for value in el.attrs.values():
            texts += [value, urllib.parse.unquote(value)]
    return texts


def hidden_texts(page):
    """The text of every outermost element that hides its content
    (HIDDEN_CONTENT), <template> content included."""
    texts = [el.text(sep, shown=False) for el in page.root.walk()
             if el.hides() and not (el.parent is not None and el.parent.concealed())
             for sep in ("", " ")]
    # The loose text of a closed <details> (outside its <summary>) is hidden
    # too; its element children are collected above, since they hide.
    texts += [squash(sep.join(c for c in el.children if isinstance(c, str)))
              for el in page.root.walk()
              if el.tag == "details" and "open" not in el.attrs and not el.concealed()
              for sep in ("", " ")]
    return texts


def persona_label_problems(page, personas):
    """Rule 4 (D10): every whole-word occurrence of a visible persona's name
    or alias is followed by the persona label, and none sits in hidden
    content, where a label does not count."""
    problems = []
    label = " " + fold_words(PERSONA_LABEL)
    for el in by_class(page, "persona-label"):
        if el.text() != PERSONA_LABEL:
            problems.append(f"rule 4: a persona-label element reads {show(el.text())}, "
                            f"the label is {show(PERSONA_LABEL)} (D10)")
    texts = [fold_words(t) for t in page_texts(page)]
    hidden = [fold_words(t) for t in hidden_texts(page)]
    for persona in personas:
        names = record_names(persona)
        for field, name in names:
            pattern = name_pattern(name)
            if any(pattern.search(text) for text in hidden):
                problems.append(f"rule 4: the {field} of the persona record "
                                f"{persona.rel} appears in hidden content "
                                f"({HIDDEN_CONTENT}), where no label counts (D10)")
            for text in texts:
                # A shorter name inside a labelled longer one (an alias that
                # is part of the name) is covered by that label.
                covered = [(m.start(), m.end()) for _, other in names
                           for m in name_pattern(other).finditer(text)
                           if text.startswith(label, m.end())]
                bare = [m for m in pattern.finditer(text)
                        if not text.startswith(label, m.end())
                        and not any(s <= m.start() and m.end() <= e and (s, e) != m.span()
                                    for s, e in covered)]
                if bare:
                    problems.append(f"rule 4: the {field} of the persona record "
                                    f"{persona.rel} renders without the label "
                                    f"{show(PERSONA_LABEL)} right after it (D10)")
                    break
    return problems


def verdict_page_problems(page):
    """Rule 5: no R14 verdict phrase on a record or section page."""
    found = {m.group() for text in page_texts(page) + hidden_texts(page)
             for m in VERDICT_PHRASE.finditer(fold_words(text))}
    return [f"rule 5: the page contains the verdict phrase {phrase!r}; labels state "
            "facts, never a verdict (D7, R14)" for phrase in sorted(found)]


def label_problems(page, record):
    """Rule 5 (D7): the exact label."""
    want = record_label(record)
    if want is None:
        return []
    el, problems = one_of_class(page, "record-label", "rule 5")
    if el is not None and el.text() != want:
        problems.append(f"rule 5: the label reads {show(el.text())}, the fixed label "
                        f"is {show(want)} (D7)")
    return problems


def source_link_problems(el, source, what):
    """The element links the source's URL with the source's title."""
    url, title = source.get("url"), source.get("title")
    if not any(href == url and text == squash(str(title))
               for href, text in links_in(el, shown=True)):
        return [f"rule 6: {what} does not link its source {show(source.get('id'))} "
                f"({show(title)}) to the source URL {show(url)}"]
    return []


def campaign_line_problems(page, record, campaigns, page_path):
    """Rule 6: the campaign line on a report page, with the campaign link and
    the source as a link to its URL."""
    el, problems = one_of_class(page, "campaign-line", "rule 6")
    if el is None:
        return problems
    campaign = record.params.get("campaign")
    if not isinstance(campaign, dict):
        if el.text() != UNATTRIBUTED:
            problems.append(f"rule 6: the campaign line reads {show(el.text())}, an "
                            f"unattributed report reads {show(UNATTRIBUTED)}")
        return problems
    slug = campaign.get("slug")
    target = campaigns.get(slug)
    name = text_param(target, "name") if target else None
    source = source_by_id(record, campaign.get("source"))
    if name is None or source is None:
        return problems  # R7 is the records check's finding
    want = CAMPAIGN_LINE.format(campaign=squash(name), source=source_ref(source))
    if campaign.get("basis") == "artifact" and isinstance(campaign.get("artifact"), str):
        want += CAMPAIGN_LINE_ARTIFACT.format(artifact=campaign["artifact"])
    want = squash(want)
    if el.text() != want:
        problems.append(f"rule 6: the campaign line reads {show(el.text())}, the fixed "
                        f"wording is {show(want)} (ADR-0004 part 6)")
    path = f"/campaigns/{slug}/"
    if not any(site_path(href, page_path) == path and text == squash(name)
               for href, text in links_in(el, shown=True)):
        problems.append(f"rule 6: the campaign line does not link {show(name)} to {path}")
    problems += source_link_problems(el, source, "the campaign line")
    return problems


def attribution_problems(page, record):
    """Rule 6: one attribution element per entry, in order, each linking its
    source; without entries, the one fixed sentence."""
    problems = []
    els = by_class(page, "attribution")
    hidden = [n for n in els if n.concealed()]
    if hidden:
        problems.append(f"rule 6: {len(hidden)} attribution element(s) in hidden content "
                        f"({HIDDEN_CONTENT}); hidden content never counts")
        els = [n for n in els if not n.concealed()]
    entries = record.params.get("attribution")
    entries = [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []
    if not entries:
        if [n.text() for n in els] != [NO_ATTRIBUTION]:
            problems.append(f"rule 6: without attribution entries the page carries one "
                            f"attribution element reading {show(NO_ATTRIBUTION)}, found "
                            f"{[n.text() for n in els]!r}")
        return problems
    if len(els) != len(entries):
        problems.append(f"rule 6: {len(els)} attribution elements for "
                        f"{len(entries)} params.attribution entries")
    for i, (entry, el) in enumerate(zip(entries, els)):
        source = source_by_id(record, entry.get("source"))
        if source is None or not isinstance(entry.get("statement"), str):
            continue  # R7 and the schema report it
        want = squash(ATTRIBUTION_LINE.format(statement=entry["statement"],
                                              source=source_ref(source)))
        if el.text() != want:
            problems.append(f"rule 6: params.attribution[{i}] reads {show(el.text())}, "
                            f"the fixed wording is {show(want)} (ADR-0004 part 6)")
        problems += source_link_problems(el, source, f"params.attribution[{i}]")
    return problems


def sources_list_problems(page, record):
    """Rule 6: every source of the record is listed as a link to its URL,
    outside the campaign line and the attribution."""
    problems = []
    listed = [(a.attrs["href"], a.text()) for a in page.root.walk()
              if a.tag in ("a", "area") and "href" in a.attrs and not a.concealed()
              and not a.inside("campaign-line") and not a.inside("attribution")]
    for i, source in enumerate(sources_of(record)):
        url, title = source.get("url"), source.get("title")
        if not any(href == url and text == squash(str(title)) for href, text in listed):
            problems.append(f"rule 6: params.sources[{i}] ({show(title)}) is not listed "
                            f"as a link to {show(url)}")
    return problems


def artifact_problems(page, record):
    """Rule 7: every declared artifact inside an artifact element, and the
    lookups of each hash equal to its listed_on."""
    problems = []
    boxes = {n.text() for n in by_class(page, "artifact") if not n.concealed()}
    for path, value in declared_artifacts(record):
        if squash(value) not in boxes:
            problems.append(f"rule 7: {path} {show(value)} appears in no element of "
                            "class artifact as stored")
    listed, possible = lookup_urls(record)
    hrefs = {browser_url(href) for href, _ in links_in(page.root, shown=True)}
    every_href = {browser_url(href) for href, _ in links_in(page.root)}
    for url in sorted(listed - hrefs):
        problems.append(f"rule 7: the lookup {show(url)} of a hash listed there is "
                        "not linked")
    for url in sorted((every_href & possible) - listed):
        problems.append(f"rule 7: the lookup {show(url)} is linked, but the hash does "
                        "not list that service in listed_on (ADR-0004 part 9)")
    return problems


def external_link_problems(page, record):
    """Rule 7: on a record page every external link is a source URL of the
    record or a lookup URL of one of its hashes."""
    allowed = {s.get("url") for s in sources_of(record)} | lookup_urls(record)[1]
    return [f"rule 7: external link {show(href)} is neither a source URL of this "
            "record nor a lookup of one of its hashes (D8)"
            for href, _ in links_in(page.root)
            if leaves_origin(href) and browser_url(href) not in allowed]


def jsonld_duplicate_keys(raw):
    """The keys that occur twice in one object of a JSON-LD block: json
    keeps the last, so "@type": "Person", "@type": "WebPage" would read as
    a WebPage."""
    duplicates = []

    def pairs(items):
        seen = set()
        for key, _ in items:
            if key in seen:
                duplicates.append(key)
            seen.add(key)
        return dict(items)
    try:
        json.loads(raw, object_pairs_hook=pairs)
    except json.JSONDecodeError:
        pass  # reported as invalid JSON
    return duplicates


def jsonld_value_problems(value, types, where, page_url):
    """Rule 8: the values of a typed object's keys. The site-identity values
    are pinned (publisher, isPartOf, a WebSite, every url, item and @id a
    site URL, a WebPage's url its own page); free text is only type-checked,
    because titles carry the subject's name."""
    problems = []
    kind = "/".join(types)
    for key in ("name", "description", "datePublished", "lastReviewed"):
        if key in value and not isinstance(value[key], str):
            problems.append(f"rule 8: {where} has a {kind} whose {key} is not a string")
    if "lastReviewed" in value and not REPORT_PAGE_URL.match(page_url):
        problems.append(f"rule 8: {where} has a {kind} with lastReviewed on a page that "
                        "is not a report page; only a report states a review date, so "
                        "no other page may claim one (ADR-0004 part 8)")
    for key in ("url", "item", "@id"):
        if key in value and not (isinstance(value[key], str)
                                 and value[key].startswith(SITE_ORIGIN + "/")):
            problems.append(f"rule 8: {where} has a {kind} whose {key} "
                            f"{show(json.dumps(value[key]))} is not a URL of this site "
                            f"({SITE_ORIGIN}/...)")
    if "position" in value and type(value["position"]) is not int:
        problems.append(f"rule 8: {where} has a {kind} whose position is not an integer")
    if "itemListElement" in value and not isinstance(value["itemListElement"], list):
        problems.append(f"rule 8: {where} has a {kind} whose itemListElement is not a list")
    for key in ("url", "@id"):
        if "WebPage" in types and value.get(key, page_url) != page_url:
            problems.append(f"rule 8: {where} has a WebPage whose {key} "
                            f"{show(json.dumps(value.get(key)))} is not this page's own "
                            f"URL {show(page_url)}")
    if "Organization" in types and value.get("url", SITE_ORIGIN + "/") != SITE_ORIGIN + "/":
        problems.append(f"rule 8: {where} has an Organization at "
                        f"{show(json.dumps(value.get('url')))}; the only Organization is "
                        f"{JSONLD_ORGANIZATION!r} at {SITE_ORIGIN}/ (ADR-0004 part 8)")
    if "WebSite" in types and (value.get("name") != JSONLD_ORGANIZATION
                               or value.get("url") != SITE_ORIGIN + "/"):
        problems.append(f"rule 8: {where} has a WebSite named {show(value.get('name'))} "
                        f"at {show(json.dumps(value.get('url')))}; the only WebSite is "
                        f"{JSONLD_ORGANIZATION!r} at {SITE_ORIGIN}/ (ADR-0004 part 8)")
    for key, want in (("publisher", "Organization"), ("isPartOf", "WebSite")):
        sub = value.get(key)
        if key in value and not (isinstance(sub, dict) and sub.get("@type") == want):
            problems.append(f"rule 8: {where} has a {kind} whose {key} is "
                            f"{show(json.dumps(sub))}, not the site's {want} object "
                            f"named {JSONLD_ORGANIZATION!r} (ADR-0004 part 8)")
    return problems


def jsonld_type_problems(value, where, page_url, root=True):
    """Rule 8 on one JSON-LD value: the only context, every object typed with
    an allowed type, an interviewscam.com Organization only, and on each
    object only the keys of JSONLD_KEYS. A block root may be a bare @graph
    container instead of an object."""
    problems = []
    if isinstance(value, list):
        for sub in value:
            problems += jsonld_type_problems(sub, where, page_url, root)
        return problems
    if not isinstance(value, dict):
        return problems
    if "@context" in value and value["@context"] != JSONLD_CONTEXT:
        problems.append(f"rule 8: {where} has the @context "
                        f"{show(json.dumps(value['@context']))}; the only context is "
                        f"{JSONLD_CONTEXT!r}, so no key can stand in for @type")
    types = []
    for key in JSONLD_TYPE_KEYS:
        if key in value:
            types += value[key] if isinstance(value[key], list) else [value[key]]
    for t in types:
        if not isinstance(t, str) or t not in JSONLD_TYPES:
            problems.append(f"rule 8: {where} has the @type {show(t)}; only "
                            f"{', '.join(sorted(JSONLD_TYPES))} are used "
                            "(ADR-0004 part 8)")
    if "Organization" in types and value.get("name") != JSONLD_ORGANIZATION:
        problems.append(f"rule 8: {where} is an Organization named "
                        f"{show(value.get('name'))}; the only Organization is "
                        f"{JSONLD_ORGANIZATION!r}, never a record's subject (D6)")
    if not types:
        if root and "@graph" in value:
            allowed = JSONLD_GRAPH_KEYS
        else:
            allowed = None
            problems.append(f"rule 8: {where} has an object without @type (keys "
                            f"{sorted(value)!r}); every object has one of the allowed "
                            "types, so none can describe a record's subject "
                            "(ADR-0004 part 8)")
    elif all(isinstance(t, str) and t in JSONLD_TYPES for t in types):
        allowed = JSONLD_OBJECT_KEYS.union(*(JSONLD_KEYS[t] for t in types))
        problems += jsonld_value_problems(value, types, where, page_url)
    else:
        allowed = None  # the type finding is enough
    for key in sorted(value) if allowed is not None else ():
        if key not in allowed:
            kind = " (an IRI, prefixed or keyword key)" if ":" in key or \
                key.startswith("@") else ""
            kind_of = "/".join(types) if types else "@graph container"
            problems.append(f"rule 8: {where} has the key {show(key)}{kind} on a "
                            f"{kind_of}; a {kind_of} carries only "
                            f"{', '.join(sorted(allowed))} (ADR-0004 part 8)")
    # The value of a key that is not allowed is that key's finding alone.
    for key, sub in value.items():
        if key != "@context" and (allowed is None or key in allowed):
            problems += jsonld_type_problems(sub, where, page_url, False)
    return problems


def structured_data_problems(page, page_url):
    """Rule 8 on one page: JSON-LD parses without duplicate keys and uses
    only the allowed types and keys; no microdata or RDFa attribute."""
    problems = []
    for i, value, error in jsonld_values(page):
        if error is not None:
            problems.append(f"rule 8: JSON-LD block {i + 1} is not valid JSON: {error}")
            continue
        for key in dict.fromkeys(jsonld_duplicate_keys(page.jsonld[i])):
            problems.append(f"rule 8: JSON-LD block {i + 1} repeats the key {show(key)} "
                            "in one object; a parser keeps only one of them")
        problems += jsonld_type_problems(value, f"JSON-LD block {i + 1}", page_url)
    names = sorted({a for n in page.root.walk() for a in n.attrs
                    if a in MICRODATA_ATTRS or a in RDFA_ATTRS})
    for name in names:
        problems.append(f"rule 8: the attribute {name} is microdata or RDFa; structured "
                        "data is JSON-LD only (ADR-0004 part 8)")
    if any(":" in token for n in page.root.walk()
           for token in n.attrs.get("rel", "").split()):
        problems.append("rule 8: a rel attribute holds a CURIE (a token with a colon), "
                        "which is RDFa; structured data is JSON-LD only (ADR-0004 "
                        "part 8)")
    return list(dict.fromkeys(problems))


def percent_decodings(text):
    """text and its percent-decodings until they stop changing (at most
    three rounds, so %252B reads as +)."""
    out = [text]
    for _ in range(3):
        decoded = urllib.parse.unquote(out[-1])
        if decoded == out[-1]:
            break
        out.append(decoded)
    return out


def file_scans(rel, data, page):
    """The R3 scan set of one built file, folded for word matching: the
    file's path (every directory and file name), raw, entity-decoded and
    percent-decoded text, joined text (hidden and <template> content
    included), attribute values, JSON-LD strings, and every string of a
    file that parses as JSON whatever its name. A file that is not UTF-8 is
    read with replacement characters, so its text is scanned too."""
    text = data.decode("utf-8", "replace")
    unescaped = html.unescape(text)
    scans = percent_decodings(rel) + [text] + percent_decodings(unescaped)
    if page is not None:
        scans += [page.root.text(shown=False), page.root.text(" ", shown=False)]
        for el in page.root.walk():
            for value in el.attrs.values():
                scans += percent_decodings(value)
        for _, value, _ in jsonld_values(page):
            if value is not None:
                scans += list(json_strings(value))
    else:
        try:
            scans += list(json_strings(json.loads(text)))
        except (json.JSONDecodeError, RecursionError):
            pass  # not JSON; a broken .json file is sitecheck site's finding
    return [fold_words(s) for s in scans]


def hidden_name_problems(scans, hidden):
    """Rule 9: no name or alias of a hidden persona in the file, its path
    included. The finding names the field, never the name."""
    problems = []
    for persona in hidden:
        for field, name in record_names(persona):
            pattern = name_pattern(name)
            if any(pattern.search(s) for s in scans):
                problems.append(f"rule 9: the {field} of {persona.rel} is hidden "
                                "(hide_name) and appears in this file or its path "
                                "(ADR-0004 part 5)")
    return problems


def url_problems(page):
    """Rule 7 on every page: no URL that carries or opens a file in place,
    and a link to a lookup service only to one of its lookup pages."""
    problems = []
    for el in page.root.walk():
        for name in URL_ATTRS:
            if name not in el.attrs:
                continue
            url = browser_url(el.attrs[name])
            scheme = url_scheme(url)
            if scheme in FILE_SCHEMES:
                problems.append(f"rule 7: <{el.tag} {name}> is a {scheme}: URL; the "
                                "site never carries or opens a file (D8)")
                continue
            try:
                host = urllib.parse.urlsplit(url.replace("\\", "/")).hostname or ""
            except ValueError:
                continue  # not a URL a browser follows to another host
            host = host.rstrip(".")
            if any(host == h or host.endswith("." + h) for h in LOOKUP_SERVICE_HOSTS) \
                    and not LOOKUP_PAGE.fullmatch(url):
                problems.append(f"rule 7: <{el.tag} {name}> {show(url)} is on a lookup "
                                "service but is not a lookup page of a hash (a sample "
                                "download or an API path); a hash links only to its "
                                "MalwareBazaar sample page or VirusTotal file page (D8, "
                                "ADR-0004 part 9)")
    return problems


def internal_link_problems(page, page_path):
    """Rule 7 on every page, for every navigation to the site's own host
    (nav_targets): an absolute one is written exactly
    https://interviewscam.com plus a path; no backslash in its path; and
    it points to a page (a path ending in "/") or to a file in
    INTERNAL_FILES, never to another file such as /files/setup.exe. A link
    to the page itself (the skip link of 404.html) is no file link."""
    problems = []
    for el, href in nav_targets(page):
        path = site_path(href, page_path)
        if path is None:
            continue
        raw = browser_url(href)
        if (HAS_SCHEME.match(raw) or re.match(r"[/\\]{2}", raw)) and not OWN_URL.match(raw):
            problems.append(f"rule 7: the link {show(href)} names the site's own host in "
                            f"another form; an absolute link to it is written exactly "
                            f"{SITE_ORIGIN} plus a path (no other scheme, case, port, "
                            "userinfo or trailing dot)")
        if "\\" in re.split(r"[?#]", raw, maxsplit=1)[0]:
            problems.append(f"rule 7: the internal link {show(href)} has a backslash in "
                            "its path; a browser reads it as a slash, so write the slash")
        if path != page_path and not path.endswith("/") and path not in INTERNAL_FILES:
            problems.append(f"rule 7: the internal link {show(href)} points to the file "
                            f"{show(path)}, not to a page; a link on this site opens a "
                            "page, never a file (D8)")
    return problems


def record_set_problems(public, records):
    """Rule 1: every record has its page, every entry under a record section
    belongs to a record, and a record directory holds only its index.html,
    at any depth, so no fixture, alternative page or data file of a record
    and no future-dated record can slip in or out unnoticed."""
    problems = []
    for record in records:
        page = public / record.section / record.slug / "index.html"
        if not page.is_file():
            problems.append((f"public/{record.section}/{record.slug}/index.html",
                             f"rule 1: {record.rel} has no built page (a future date "
                             "or a build error skips it)"))
    for section in RECORD_SCHEMAS:
        slugs = {r.slug for r in records if r.section == section}
        folder = public / section
        if not folder.is_dir():
            continue
        for entry in sorted(folder.iterdir()):
            if entry.name == "index.html" and entry.is_file():
                continue
            if entry.is_dir() and entry.name in slugs:
                for sub in sorted(p for p in entry.rglob("*") if not p.is_dir()):
                    inner = sub.relative_to(entry).as_posix()
                    if inner != "index.html":
                        problems.append((f"public/{section}/{entry.name}/{inner}",
                                         "rule 1: a record directory holds only its "
                                         "index.html; this is a second output of "
                                         f"content/{section}/{entry.name}.md"))
                continue
            problems.append((f"public/{section}/{entry.name}",
                             f"rule 1: belongs to no record in content/{section}/ "
                             "(a fixture record or a stale page in the build)"))
    return problems


def fixture_leak_problems(fixtures, records):
    """Rule 1, production only (--fixtures): no record under content/ shares
    its slug or its name with a fixture record under <fixtures>/**/content/.
    A leaked fixture builds its own page, so the record set alone cannot
    tell it from a real record. persona-N slugs are numbered, not named,
    so only a persona's name counts."""
    slugs, names = {}, {}
    scratch = Findings()
    for content in sorted(p for p in fixtures.rglob("content") if p.is_dir()):
        for section in RECORD_SCHEMAS:
            for path in sorted((content / section).glob("*.md")):
                if path.name == "_index.md":
                    continue
                rel = f"{fixtures.name}/{path.relative_to(fixtures).as_posix()}"
                if not PERSONA_SLUG.fullmatch(path.stem):
                    slugs.setdefault((section, path.stem), rel)
                parsed = read_front_matter(path, rel, scratch, "fixture record")
                params = parsed[0].get("params") if parsed else None
                name = params.get("name") if isinstance(params, dict) else None
                if isinstance(name, str) and name.strip():
                    names.setdefault((section, fold_words(name)), rel)
    problems = []
    for record in records:
        by_slug = None if PERSONA_SLUG.fullmatch(record.slug) else \
            slugs.get((record.section, record.slug))
        name = text_param(record, "name")
        by_name = names.get((record.section, fold_words(name))) if name else None
        matches = [(what, rel) for what, rel in (("slug", by_slug), ("name", by_name))
                   if rel]
        if matches:
            what = " and ".join(w for w, _ in matches)
            problems.append((record.rel, f"rule 1: shares its {what} with the fixture "
                             f"record {matches[0][1]}; fixture records never enter "
                             "content/ (a fixture leak, ADR-0004 part 10)"))
    return problems


def linked_paths(page, page_path):
    return {site_path(href, page_path) for href, _ in links_in(page.root, shown=True)} \
        - {None}


def index_link_problems(pages, records):
    """Rule 10: /reports/ links every report, /campaigns/ every campaign, and
    Home the five latest reports and every campaign."""
    problems = []
    for section in RECORD_SCHEMAS:
        members = [r for r in records if r.section == section]
        if not members:
            continue
        rel = f"public/{section}/index.html"
        page = pages.get(rel)
        if page is None:
            problems.append((rel, f"rule 10: content/{section}/ has records, but the "
                                  f"section page /{section}/ was not built"))
            continue
        linked = linked_paths(page, f"/{section}/")
        for record in members:
            if f"/{section}/{record.slug}/" not in linked:
                problems.append((rel, f"rule 10: /{section}/ does not link {record.rel}"))
    if not records:
        return problems
    home = pages.get("public/index.html")
    if home is None:
        problems.append(("public/index.html", "rule 10: records exist, but no Home page "
                                              "was built"))
        return problems
    linked = linked_paths(home, "/")
    for record in records:
        if record.section == "campaigns" and f"/campaigns/{record.slug}/" not in linked:
            problems.append(("public/index.html",
                             f"rule 10: Home does not link the campaign {record.rel}"))
    reports = [r for r in records if r.section == "reports"]
    shown = [r for r in reports if f"/reports/{r.slug}/" in linked]
    want = min(HOME_LATEST, len(reports))
    if len(shown) != want:
        problems.append(("public/index.html",
                         f"rule 10: Home links {len(shown)} reports; it links the "
                         f"{want} latest by date"))

    def date_of(record):
        value = record.data.get("date")
        return value if isinstance(value, str) else ""
    # Any tie-break among equal dates is a valid choice of the latest.
    unshown = [r for r in reports if r not in shown]
    if shown and unshown:
        oldest = min(shown, key=date_of)
        newest = max(unshown, key=date_of)
        if date_of(newest) > date_of(oldest):
            problems.append(("public/index.html",
                             f"rule 10: Home links {oldest.rel} ({date_of(oldest)}) but "
                             f"not the newer {newest.rel} ({date_of(newest)}); it links "
                             f"the {HOME_LATEST} latest by date"))
    return problems


def cmd_render(args):
    root = Path(args.records).resolve()
    public = Path(args.public).resolve()
    schema_dir = Path(args.schemas).resolve() if args.schemas else root / "schema"
    if not public.is_dir():
        raise UsageError(f"{public} is not a directory (build the site first)")
    fixtures = Path(args.fixtures).resolve() if args.fixtures else None
    if fixtures is not None and not fixtures.is_dir():
        raise UsageError(f"{fixtures} is not a directory (--fixtures)")
    findings = Findings()

    record_findings = Findings()
    records = load_records(root, schema_dir, record_findings)
    for item in record_findings.items:
        findings.items.append(item + " (records loaded for the render check)")
    by_page = {f"public/{r.section}/{r.slug}/index.html": r for r in records}
    by_dir = {(r.section, r.slug): r for r in records}
    reports = {r.slug: r for r in records if r.section == "reports"}
    campaigns = {r.slug: r for r in records if r.section == "campaigns"}
    personas = [r for r in records if is_persona(r) and not is_hidden(r)]
    hidden = [r for r in records if is_hidden(r)]

    for rel, problem in record_set_problems(public, records):
        findings.add(rel, problem)
    if fixtures is not None:
        for rel, problem in fixture_leak_problems(fixtures, records):
            findings.add(rel, problem)

    pages = {}
    files = sorted(p for p in public.rglob("*") if p.is_file())
    for path in files:
        rel = "public/" + path.relative_to(public).as_posix()
        data = path.read_bytes()
        suffix = path.suffix.lower()
        page = None
        if suffix in HTML_SUFFIXES or suffix in XML_SUFFIXES:
            try:
                page = parse_render_page(data.decode("utf-8"))
            except UnicodeDecodeError:
                page = None
        scans = file_scans(rel, data, page)
        problems = []
        # Rule 8: the retired fact-check type appears nowhere, in any form.
        if any("claimreview" in s for s in scans):
            problems.append("rule 8: contains ClaimReview; it is never used (ADR-0004 "
                            "part 8, SPEC section 5)")
        problems += hidden_name_problems(scans, hidden)
        page_path = own_path(rel.removeprefix("public/"))
        if page is not None:
            if any("download" in n.attrs for n in page.root.walk()):
                problems.append("rule 7: an element carries the download attribute; "
                                "the site never offers a file download (D8)")
            problems += url_problems(page)
            problems += internal_link_problems(page, page_path)
            problems += persona_label_problems(page, personas)
            problems += structured_data_problems(page, SITE_ORIGIN + page_path)
            # The tree infers no end tags (OPTIONAL_END): a page that omits
            # one gets that finding instead of the class-scoped rules, which
            # would read a nesting no browser builds.
            for tag in dict.fromkeys(page.unclosed):
                n = page.unclosed.count(tag)
                problems.append(f"markup: {n} <{tag}> element(s) closed without their own "
                                f"</{tag}>; close every <{tag}> explicitly, because the "
                                "render check infers no end tags")
        if page is not None and suffix in HTML_SUFFIXES:
            pages[rel] = page
        if page is not None and suffix in HTML_SUFFIXES and not page.unclosed:
            parts = rel.split("/")
            # Every HTML page under a record directory is that record's page,
            # so an alternative page meets the record rules too (rule 1
            # reports it as well).
            record = by_dir.get((parts[1], parts[2])) if len(parts) > 3 else None
            section = next((s for s in SECTION_TITLES if rel == f"public/{s}/index.html"),
                           None)
            items, found = report_items(page, page_path, reports)
            problems += found
            chips = own_chips(page, items)
            problems += chip_problems(page, chips, record is not None
                                      and record.section == "reports")
            if record is not None:
                problems += title_problems(page, record_title(record))
                problems += verdict_page_problems(page)
                if record.section == "reports":
                    problems += state_problems(page, record, chips)
                    problems += label_problems(page, record)
                    problems += campaign_line_problems(page, record, campaigns, page_path)
                    problems += artifact_problems(page, record)
                else:
                    problems += attribution_problems(page, record)
                problems += sources_list_problems(page, record)
                problems += external_link_problems(page, record)
            elif section is not None:
                problems += title_problems(page, SECTION_TITLES[section])
                problems += verdict_page_problems(page)
        for problem in dict.fromkeys(problems):
            findings.add(rel, problem)
    for rel, problem in index_link_problems(pages, records):
        findings.add(rel, problem)
    if not pages:
        findings.add("public", "no HTML pages found; nothing was checked")
    n_reports = sum(r.section == "reports" for r in records)
    n_record_pages = sum(rel in by_page for rel in pages)
    return findings.report(
        f"render checked: {len(records)} records (reports {n_reports}, campaigns "
        f"{len(records) - n_reports}), {n_record_pages} record pages, {len(pages)} "
        f"HTML pages, {len(files)} files")


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
    p = sub.add_parser("render")
    p.add_argument("--records", required=True)
    p.add_argument("--schemas")
    p.add_argument("--fixtures")
    p.add_argument("public")
    p.set_defaults(func=cmd_render)
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
