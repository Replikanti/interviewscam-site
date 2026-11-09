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
  literals [--root DIR]
      Fixed public copy lives only in data/labels.toml (ADR-0004 part 13):
      no letter or digit in template text (L1) or in a visible attribute
      (L2, every attribute off a closed list), no string literal in a
      template action that is copy, no action that prints a bare literal,
      and a literal in a value position only with a never-copy shape or from
      a fixed list (L3), only listed functions and members, copy read only
      through label.html and label-list.html (L4), no generated text in CSS
      (L5), and a template that cannot be read fails closed (L6). Reads
      layouts/, assets/ and the markup and CSS files of static/.
  reflow --chrome BIN [--launch-timeout SECONDS] PUBLIC
      Every HTML page in PUBLIC, loaded in headless Chrome at a 320 CSS px
      viewport, has no page-level horizontal overflow, and every word and
      replaced element lies within the viewport and within every clipping
      ancestor (geometry, ADR-0003 part 6). CI only. A Chrome that gives no
      first answer within REFLOW_LAUNCH_TIMEOUT, or closes the pipe before
      it, is started once more; every later answer has REFLOW_TIMEOUT.
      Stall probes and Chrome's own log (kept on the tmpfs REFLOW_LOG_DIR)
      go to stderr. --launch-timeout (default REFLOW_LAUNCH_TIMEOUT) is for
      the self-test only.
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
import base64
import copy
import datetime
import decimal
import encodings.idna
import fcntl
import functools
import hashlib
import html
import html.entities
import html.parser
import http.server
import ipaddress
import json
import math
import os
import re
import select
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import tomllib
import unicodedata
import urllib.parse
import zlib
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
# review5 A3 audit: ASCII case only. Python folded U+0131 into `i`, so
# `https://` U+0131 `nterviewscam.com` passed as this origin; a browser maps
# that host to its own punycode name, another origin.
SAME_ORIGIN = re.compile(r"^https://interviewscam\.com(?:[/?#]|$)", re.I | re.A)
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
# The directive names of Content Security Policy Level 3 (W3C, section 6:
# fetch, document, navigation and reporting directives) plus
# upgrade-insecure-requests. A browser ignores any other name, so an unknown
# "directive" is free text in hugo.toml; it fails (review3 6). With the
# sources limited to CSP_SOURCES, params.csp is a closed vocabulary.
CSP_DIRECTIVES = frozenset("""
base-uri child-src connect-src default-src font-src form-action frame-ancestors
frame-src img-src manifest-src media-src object-src report-to report-uri sandbox
script-src script-src-attr script-src-elem style-src style-src-attr style-src-elem
upgrade-insecure-requests worker-src
""".split())


CSP_WHITESPACE = "\t\n\f\r "


def csp_problems(policy):
    """A policy may only use 'self' and 'none', directive names from
    CSP_DIRECTIVES, and must set default-src."""
    problems = []
    seen = set()
    # review4 A1: CSP splits on ASCII whitespace only, so a no-break space
    # stays inside a token (an unknown directive or source) and fails.
    for directive in (d.strip(CSP_WHITESPACE) for d in policy.split(";")):
        if not directive:
            continue
        name, *sources = re.split(f"[{CSP_WHITESPACE}]+", directive)
        name = name.lower()
        if name in seen:
            problems.append(f"duplicate CSP directive {name}")
        seen.add(name)
        if name not in CSP_DIRECTIVES:
            problems.append(f"CSP directive {show(name)} is not a CSP Level 3 directive "
                            "(CSP_DIRECTIVES); a browser ignores it, so it would be free "
                            "text (review3 6)")
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
# CSS the class has exactly one top-level definition and at most one
# :focus/:focus-visible reveal, each with exactly the pinned declarations
# below, each declaration once !important; !important appears nowhere else;
# no attribute selector on `class` (it could match the class without naming
# it); inline style is banned by rule (c).
VISUALLY_HIDDEN = "visually-hidden"
VISUALLY_HIDDEN_WORD = re.compile(r"(?i)visually-hidden")
VH_DEFINITION = ".visually-hidden"
VH_REVEAL = {".visually-hidden:focus", ".visually-hidden:focus-visible"}
# M3 PR 10 fix round 1 (PR #33 review, finding 1): the definition and the
# reveal are pinned to today's declarations as the pinned Hugo's minifier
# writes them (property, value; the value compared unescaped, without
# !important, whitespace collapsed and trimmed inside parentheses, case kept),
# with no optional extras. A box measure cannot see clip, clip-path or
# opacity, so a one-line edit (`clip: rect(0 0 0 0)` in the definition,
# `clip-path: none` dropped from the reveal, `opacity: 0` added to it) hid
# the revealed skip link while every check passed. Pinned, any change to
# these two rules is a tools/ change and gets the safety-net review; reflow
# case (7) proves the outcome (the focused link paints). Both are pinned by
# content in tests/fixtures/literals/allowlists.tsv.
# The hiding pattern: a 1 x 1 px absolutely positioned box without margin,
# padding or border that clips its content and keeps it on one line.
# `display: block` so `display: contents` (no box, text still painted)
# cannot apply; an absolutely positioned box is blockified anyway.
VH_DEFINITION_DECLARATIONS = {
    "display": "block",
    "position": "absolute",
    "width": "1px",
    "height": "1px",
    "margin": "0",
    "padding": "0",
    "border": "0",
    "overflow": "hidden",
    "clip-path": "inset(50%)",
    "white-space": "nowrap",
}
# The reveal: the box grows to its content, unclipped and wrapping, placed
# at the top left on a card with the focus colours (tokens from
# data/tokens.toml). No opacity, visibility, transform, filter or clip.
VH_REVEAL_DECLARATIONS = {
    "top": "var(--space-x2)",
    "left": "var(--space-x2)",
    "z-index": "1",
    "width": "auto",
    "height": "auto",
    "padding": "var(--space-x3)var(--space-x4)",
    "overflow": "visible",
    "clip-path": "none",
    "white-space": "normal",
    "background": "var(--color-card)",
    "border": "var(--border-width)solid var(--color-card-border)",
    "border-radius": "var(--radius-control)",
    "color": "var(--color-primary)",
    "font-weight": "var(--weight-label)",
}
# review5 A3: re.ASCII and CSS whitespace, because a browser matches the
# keyword in ASCII case only (`!` U+0131 `mportant` is no `!important`; the
# browser drops that declaration).
IMPORTANT = re.compile(r"![\t\n\f\r ]*important", re.I | re.A)
# ADR-0004 part 11 (M3 PR 9 fix round 1, review 6, #31 Known limit 2): an
# author display value beats the browser's [hidden] rule, and a selector
# need not name .copy to match the button (`dd > *`), so no check of the
# selectors that set display can close it. Instead the Copy button is hidden
# by exactly one top-level rule, `.copy[hidden] { display: none !important }`,
# the second place !important is allowed: no rule without !important can
# override it, and the only other !important declarations are those of
# .visually-hidden, whose definition loses on specificity (0,1,0 against
# 0,2,0) and whose :focus reveal cannot match an element display: none
# keeps from focus. Inline style is banned by rule (c). The rule is required
# exactly once on a site with a Copy button.
# M4 PR 3 (ADR-0005 parts 4 and 6): the same holds for the result sections of
# the Home search, which carry the class search-out and the hidden attribute
# until search.js reveals one, so the rule is a table of the classes hidden
# until their script runs, each with its own `.<class>[hidden]` rule.
HIDDEN_UNTIL_SCRIPT = {
    "copy": ("a Copy button (class copy)",
             "copy.js reveals it (ADR-0004 part 11)"),
    "search-out": ("search results (class search-out)",
                   "search.js reveals one of them (ADR-0005 part 4)"),
}
HIDDEN_RULES = {f".{cls}[hidden]": cls for cls in HIDDEN_UNTIL_SCRIPT}
HIDDEN_DECLARATION = ("display", "none")
HIDDEN_RULE_NAMES = " and ".join(f"the {sel} rule" for sel in HIDDEN_RULES)
CLASS_ATTRIBUTE_SELECTOR = re.compile(r"(?i)\[\s*(?:[\w*-]*\|)?class\s*(?:[~|^$*]?=|\])")


def css_selector_text(prelude):
    return re.sub(r"\s+", " ", css_unescape(prelude)).strip()


def css_value_text(value, lower=True):
    """A declaration value as compared: unescaped, !important removed,
    lowercased (unless lower is False: the pinned .visually-hidden
    declarations keep case, because a custom property name is
    case-sensitive), whitespace collapsed and trimmed inside parentheses."""
    value = IMPORTANT.sub("", css_unescape(value)).strip()
    value = re.sub(r"\s+", " ", value.lower() if lower else value)
    return re.sub(r"\(\s*", "(", re.sub(r"\s*\)", ")", value))


class CssRuleResult:
    def __init__(self):
        self.problems = []
        self.definitions = 0
        self.reveals = 0
        self.hidden_rules = dict.fromkeys(HIDDEN_UNTIL_SCRIPT, 0)  # class -> count


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
        if top_level and selector in HIDDEN_RULES:
            cls = HIDDEN_RULES[selector]
            result.hidden_rules[cls] += 1
            found = [(len(IMPORTANT.findall(css_unescape(d))), css_declaration(d))
                     for d in rule.declarations]
            attributed += sum(n for n, _ in found)
            got = [(prop, css_value_text(value)) for _, (prop, value) in found]
            if got != [HIDDEN_DECLARATION] or [n for n, _ in found] != [1]:
                problems.append(f"{show(selector)}: the rule must be exactly `display: "
                                f"none !important` (found {show('; '.join(rule.declarations))}"
                                f"); it hides {HIDDEN_UNTIL_SCRIPT[cls][0]} until "
                                f"{HIDDEN_UNTIL_SCRIPT[cls][1]}, and no other rule may "
                                "override it")
            continue
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
                elif found > 1:
                    problems.append(f"{show(selector)}: declaration {show(declaration)} "
                                    "has !important more than once; a browser drops it")
                prop, value = css_declaration(declaration)
                if prop in seen:
                    problems.append(f"{show(selector)}: {prop} is declared twice")
                seen[prop] = css_value_text(value, lower=False)
            if is_reveal and sorted(p.strip() for p in selector.split(",")) \
                    != sorted(VH_REVEAL):
                problems.append(f"{show(selector)}: the reveal's selector must be exactly "
                                f"{', '.join(sorted(VH_REVEAL))} (pinned, M3 PR 10)")
            pinned = VH_DEFINITION_DECLARATIONS if is_definition else VH_REVEAL_DECLARATIONS
            what = "the definition" if is_definition else "the reveal"
            for prop in seen:
                if prop not in pinned:
                    problems.append(f"{show(selector)}: {prop} is not part of "
                                    f"{'the hiding pattern' if is_definition else 'the reveal'}"
                                    f"; {what} holds exactly its pinned declarations "
                                    "(M3 PR 10)")
            for prop, want in pinned.items():
                if seen.get(prop) != want:
                    problems.append(f"{show(selector)}: {what} needs "
                                    f"{prop}: {want} !important (found "
                                    f"{show(seen.get(prop, 'nothing'))}); "
                                    + ("it must provably hide" if is_definition else
                                       "it must provably show the skip link on keyboard "
                                       "focus"))
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
                                f"and {HIDDEN_RULE_NAMES} ({show(declaration)})")
    # Fail closed: an !important the block walk did not attribute to a
    # declaration (in a selector, an at-rule prelude, a stray statement).
    stripped = CSS_COMMENT_OR_STRING.sub(lambda m: m.group(0) if m.group(1) else " ", css)
    total = len(IMPORTANT.findall(css_unescape(stripped)))
    if total > attributed:
        problems.append(f"!important outside any declaration ({total - attributed} "
                        "occurrence(s)); it is allowed only in the .visually-hidden "
                        f"definition and its reveal and {HIDDEN_RULE_NAMES}")
    return result


# ---------------------------------------------------------------------------
# Markup rules of the built site (PR 3 of milestone 2, ADR-0003 parts 3 and 6)

FORM_ATTRS = {("form", "action"), ("button", "formaction"), ("input", "formaction")}
URL_ATTRS = ("href", "src", "action", "formaction", "xlink:href", "data")
JSON_LD = "application/ld+json"


# Rule (j) (ADR-0005 part 5; exact from M4 PR 3 fix round 2): the path of a
# built script is exactly the name resources.Minify and
# resources.Fingerprint "sha384" give it, /js/<stem>.min.<the SHA-384 hex of
# the file's own bytes>.js, compared as a whole string, not read with a
# pattern, so no other length, alphabet or separator can pass.
BUILT_SCRIPT_DIR = "/js/"
BUILT_SCRIPT_INFIX = ".min."
BUILT_SCRIPT_SUFFIX = ".js"


def built_script_path(stem, data):
    """The path Hugo writes for the pinned script stem whose built bytes
    are data."""
    return (BUILT_SCRIPT_DIR + stem + BUILT_SCRIPT_INFIX + hashlib.sha384(data).hexdigest()
            + BUILT_SCRIPT_SUFFIX)


def script_stems():
    """The stems of the scripts SCRIPT_SHA256 pins under assets/js/: the
    key assets/js/<stem>.js gives <stem>."""
    stems = set()
    for key in SCRIPT_SHA256:
        match = re.fullmatch(r"assets/js/([a-z0-9]+)\.js", key)
        if match:
            stems.add(match.group(1))
    return stems


def url_scheme(url):
    """The scheme of url as a browser reads it (tabs, newlines and edge C0
    controls dropped, lowercased), or ""."""
    url = re.sub(r"[\t\n\r]", "", url).strip(C0_AND_SPACE)
    match = HAS_SCHEME.match(url)
    return match.group(0)[:-1].lower() if match else ""


# Rule (k), stylesheet links in one closed form (M3 PR 10, ADR-0003 part 6
# and ADR-0004 part 11; #31 fix round 2 delta re-review, comment
# 6713575984, finding 2, and fix round 3, comment 6714476035, finding 2).
# A computed style is the result of every route at once (a `type`, an
# `integrity`, a `<template>`, a `title` set, `<noscript>`, an `<svg>`
# around the link, CSS error recovery), so instead of modelling which
# links a browser applies, a stylesheet link counts only in the one form
# the base layout writes: exactly these attributes, `rel` exactly
# `stylesheet`, an href naming a built .css file in the closed path form
# below, and only start tags of HEAD_PREFIX_TAGS before it. Every other
# stylesheet link is a finding.
STYLESHEET_LINK_ATTRS = frozenset({"rel", "href"})
HEAD_PREFIX_TAGS = frozenset({"html", "head", "meta", "title", "link"})
ASCII_WHITESPACE = "\t\n\f\r "
# M3 PR 10 fix round 1 (PR #33 review, findings 2 and 3): an href of rule
# (k) and a src of rule (j) is a root-relative path in a closed alphabet,
# read as it stands, with no URL resolution. The pinned Hugo writes exactly
# `/css/site.min.<64 hex>.css` and `/js/copy.min.<96 hex>.js` on every page
# of both trees (.RelPermalink with the root baseURL), so lowercase ASCII
# letters, digits and `.` between single slashes are all it writes. Why
# closed instead of resolved: a relative href resolves against the
# requested URL, and Pages serves 404.html at every missing path, so on
# 404.html it names another file per request (finding 2); and urljoin
# itself differs between Pythons (3.12.3, CI's, drops an empty trailing
# `;` parameter, 3.14 keeps it; finding 3). In the closed form there is no
# `//`, `.` or `..` segment, `%`, `;`, `?`, `#`, a backslash, whitespace, scheme
# or host, so the path a browser requests is the text itself, on every
# page URL and every Python.
RESOURCE_PATH_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789./")


def resource_path(value):
    """Rule (k)'s href and rule (j)'s src in the closed form (M3 PR 10 fix
    round 1): (the path, None) when value is a root-relative path of
    RESOURCE_PATH_CHARS whose every segment is non-empty and starts with a
    letter or digit, else (None, the reason)."""
    if not value.startswith("/"):
        return None, ("is not root-relative (it must start with a single /; a "
                      "relative one resolves against the requested URL, and Pages "
                      "serves 404.html at every missing path)")
    bad = next((c for c in value if c not in RESOURCE_PATH_CHARS), None)
    if bad is not None:
        return None, (f"holds {show(bad)} (U+{ord(bad):04X}), outside the closed "
                      "alphabet of lowercase ASCII letters, digits, . and / that the "
                      "pinned Hugo writes")
    for segment in value[1:].split("/"):
        if not segment:
            return None, "holds an empty path segment (//, or a trailing /)"
        if segment.startswith("."):
            return None, (f"holds the segment {show(segment)}; a segment starts with a "
                          "letter or digit (no . or .. segment)")
    return value, None


def stylesheet_links(page, css_files):
    """Rule (k) on one HTML page: (the site paths of the stylesheets it
    applies, the problems). A <link> whose rel (ASCII-lowercased, split on
    ASCII whitespace) holds `stylesheet` counts only in the closed form;
    any other is a finding and does not count. The href is read as it
    stands (resource_path), the same on every page URL."""
    applied, problems = set(), []
    prefix = True  # only start tags of HEAD_PREFIX_TAGS so far
    for tag, attrs in page.elements:
        if tag == "link" and "stylesheet" in \
                re.split(r"[\t\n\f\r ]+", ascii_lower(attrs.get("rel", ""))):
            href = attrs.get("href")
            where = f"(k) <link rel={show(attrs.get('rel', ''))} href={show(href or '')}>"
            ok = True
            if set(attrs) != STYLESHEET_LINK_ATTRS:
                extra = sorted(set(attrs) - STYLESHEET_LINK_ATTRS)
                missing = sorted(STYLESHEET_LINK_ATTRS - set(attrs))
                problems.append(f"{where} has the attributes {', '.join(sorted(attrs))}"
                                f"{'; not allowed: ' + ', '.join(extra) if extra else ''}"
                                f"{'; missing: ' + ', '.join(missing) if missing else ''}; "
                                "a stylesheet link has exactly rel and href")
                ok = False
            if ascii_lower(attrs.get("rel", "")).strip(ASCII_WHITESPACE) != "stylesheet":
                problems.append(f"{where}: rel is not exactly `stylesheet`")
                ok = False
            if not prefix:
                problems.append(f"{where} comes after an element other than "
                                f"{', '.join(sorted(HEAD_PREFIX_TAGS))} (inside or after "
                                "a template, noscript, svg, math, script, style or the body)")
                ok = False
            if href is not None:
                path, problem = resource_path(href)
                if problem:
                    problems.append(f"{where}: the href {problem}")
                    ok = False
                elif path not in css_files:
                    problems.append(f"{where}: the href ({show(path)}) names no built "
                                    ".css file")
                    ok = False
            if ok:
                applied.add(path)
        if tag not in HEAD_PREFIX_TAGS:
            prefix = False
    return applied, problems


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


# The suffixes whose content cmd_site parses and checks beyond the byte scan
# for live artifacts; a file of one of them that is not UTF-8 is a finding.
SITE_TEXT_SUFFIXES = frozenset(HTML_SUFFIXES | XML_SUFFIXES
                               | {".css", ".js", ".mjs", ".json"})


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
    scripts = []  # (rel, page path, src) of every <script src>, for rule (j)
    page_scripts = {}  # page rel -> the attributes of each of its <script> elements
    vh_definitions = vh_reveals = 0
    vh_used = []
    # Per class of HIDDEN_UNTIL_SCRIPT: the number of its rules across the
    # built CSS, the pages with an element of the class, and the site paths
    # of the built CSS files holding its rule.
    hidden_counts = dict.fromkeys(HIDDEN_UNTIL_SCRIPT, 0)
    hidden_used = {cls: [] for cls in HIDDEN_UNTIL_SCRIPT}
    hidden_files = {cls: set() for cls in HIDDEN_UNTIL_SCRIPT}
    vh_files, reveal_files = set(), set()  # the same for the definition and the reveal
    stylesheets = {}  # page rel -> the site paths of the stylesheets it applies
    n_html = 0
    files = sorted(p for p in public.rglob("*") if p.is_file())
    css_files = {"/" + p.relative_to(public).as_posix() for p in files
                 if p.suffix.lower() == ".css"}
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
            # M3 PR 10 fix round 1 (PR #33 review, finding 4): fail closed on a
            # file whose rules this check reads (markup, CSS, script, JSON)
            # but cannot decode, so no rule counts a file it never read (a
            # linked .css file still counted in rule (k)'s css_files).
            if suffix in SITE_TEXT_SUFFIXES:
                findings.add(rel, f"not UTF-8, so its {suffix} rules were never read; "
                             "every built markup, CSS, script and JSON file is UTF-8 "
                             "(fail closed)")
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
                for problem in rawtext_built_problems(text):
                    findings.add(rel, problem)
                scripts += [(rel, attrs["src"]) for tag, attrs in page.elements
                            if tag == "script" and "src" in attrs]
                page_scripts[rel] = [attrs for tag, attrs in page.elements
                                     if tag == "script"]
                # (m) the head by position (M4 PR 3 fix round 7).
                for problem in head_problems(text, rel, not args.no_built_pins):
                    findings.add(rel, problem)
                # (k) per page (M3 PR 10): the stylesheets every page applies.
                stylesheets[rel], problems = stylesheet_links(page, css_files)
                for problem in problems:
                    findings.add(rel, f"{problem} (ADR-0003 part 6)")
                # (k) No <template> element: its content is inert and it can
                # hold a declarative shadow root (none today).
                if any(tag == "template" for tag, _ in page.elements):
                    findings.add(rel, "(k) <template> element: its content is inert and "
                                 "can hold a shadow root, so the page's links and "
                                 "elements are not those a browser applies (ADR-0003 "
                                 "part 6)")
                if any(VISUALLY_HIDDEN in attrs.get("class", "").split()
                       for _, attrs in page.elements):
                    vh_used.append(rel)
                for cls in HIDDEN_UNTIL_SCRIPT:
                    if any(cls in attrs.get("class", "").split()
                           for _, attrs in page.elements):
                        hidden_used[cls].append(rel)
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
            for cls, count in result.hidden_rules.items():
                hidden_counts[cls] += count
                if count:
                    hidden_files[cls].add("/" + path.relative_to(public).as_posix())
            if result.definitions:
                vh_files.add("/" + path.relative_to(public).as_posix())
            if result.reveals:
                reveal_files.add("/" + path.relative_to(public).as_posix())
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
    # (j) The pinned scripts (ADR-0005 part 5, amending ADR-0004 part 11 and
    # M3 PR 9's one-script rule): every built .js or .mjs file is the
    # minified, fingerprinted build of a script pinned in SCRIPT_SHA256,
    # /js/<stem>.min.<96 hex>.js for the stem of a key assets/js/<stem>.js,
    # at most one file per stem, and every <script src> names one of them,
    # so a script can reach a page only as a reviewed change of the pin.
    # Every other <script> is a JSON-LD data block (rule (c)).
    js_files = ["/" + p.relative_to(public).as_posix() for p in files
                if p.suffix.lower() in JS_SUFFIXES]
    built = {}  # stem -> the built files named for it
    for path in js_files:
        data = (public / path[1:]).read_bytes()
        stem = next((s for s in sorted(script_stems())
                     if path == built_script_path(s, data)), None)
        if stem is None:
            findings.add("public", f"(j) {show(path, 240)} is not the build of a pinned script: "
                         "every .js or .mjs file is exactly /js/<stem>.min.<SHA-384 hex of its "
                         "bytes>.js for a script assets/js/<stem>.js of SCRIPT_SHA256 ("
                         f"{', '.join(sorted(script_stems()))}), as resources.Minify and "
                         "resources.Fingerprint \"sha384\" name it (ADR-0005 part 5)")
        else:
            built.setdefault(stem, []).append(path)
            digest = hashlib.sha384(data).hexdigest()
            if not args.no_built_pins and digest != BUILT_SCRIPT_SHA384.get(stem):
                findings.add("public", f"(j) the bytes of {show(path, 240)} (SHA-384 {digest}) "
                             f"are not the pinned build of the script {stem} "
                             "(BUILT_SCRIPT_SHA384 in tools/sitecheck.py): a built script "
                             "changes only with its pin, whatever input changed it, so the "
                             "change gets the safety-net review")
    for stem, paths in sorted(built.items()):
        if len(paths) > 1:
            findings.add("public", f"(j) {len(paths)} built files for the script {stem} "
                         f"({', '.join(paths)}); at most one file per pinned script "
                         "(ADR-0005 part 5)")
    allowed_scripts = {p for paths in built.values() for p in paths}
    for rel, src in scripts:
        # M3 PR 10 fix round 1: read as rule (k) reads an href, in the
        # closed path form (resource_path), so no query, fragment or
        # relative path.
        path, problem = resource_path(src)
        if path is None or path not in allowed_scripts:
            findings.add(rel, f"(j) <script src={show(src)}> does not name the built file "
                         "of a pinned script ("
                         f"{', '.join(sorted(allowed_scripts)) or 'none'}); every <script "
                         "src> names one (ADR-0005 part 5)"
                         + (f"; the src {problem}" if problem else ""))
    # (j) The script tags (M4 PR 3 fix round 6, delta review 5 finding 1),
    # in one closed form, as rule (k) holds <link>: a <script src> has
    # exactly the attributes src, integrity and defer, defer empty (no
    # async, nomodule, type, crossorigin or any later attribute, so no tag
    # can turn a script off, defer it otherwise or run it as a module), and
    # every other <script> exactly type="application/ld+json" (rule (c)'s
    # data block); no page names a script twice. With the built pins on
    # (every build, never a hand-made fixture), the integrity is the
    # SHA-384 of the file the src names, and each page kind loads exactly
    # the scripts baseof.html emits, in order: copy.js on every page,
    # search.js after it on Home and on no other page.
    by_stem = {stem: paths[0] for stem, paths in built.items() if len(paths) == 1}
    for rel, tags in sorted(page_scripts.items()):
        srcs = []
        for attrs in tags:
            if "src" in attrs:
                srcs.append(attrs["src"])
                if sorted(attrs) != sorted(SCRIPT_SRC_ATTRS) or attrs.get("defer") != "":
                    findings.add(rel, f"(j) <script> has the attributes {show(attrs, 240)}; a "
                                 "script tag has exactly src, integrity and defer (empty), as "
                                 "baseof.html emits it, so no attribute can turn the script "
                                 "off, run it as a module or change when it runs (ADR-0005 "
                                 "part 5)")
            elif attrs != {"type": JSON_LD}:
                findings.add(rel, f"(j) <script> has the attributes {show(attrs, 240)}; a "
                             "script without src is exactly <script "
                             f"type=\"{JSON_LD}\">, a JSON-LD data block (rule (c))")
        twice = sorted({src for src in srcs if srcs.count(src) > 1})
        if twice:
            findings.add(rel, f"(j) the page names {', '.join(show(t) for t in twice)} more "
                         "than once; each script is loaded once (ADR-0005 part 5)")
        if args.no_built_pins:
            continue
        for attrs in tags:
            path = resource_path(attrs.get("src", ""))[0] if "src" in attrs else None
            if path in allowed_scripts:
                data = (public / path[1:]).read_bytes()
                want = "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode()
                if attrs.get("integrity") != want:
                    findings.add(rel, f"(j) <script src={show(attrs['src'])}> has the integrity "
                                 f"{show(attrs.get('integrity', 'none'))}; it is {want}, the "
                                 "SHA-384 of the file it names (ADR-0005 part 5)")
        kind = SCRIPTS_BY_PAGE_KIND["home" if rel == "public/index.html" else "other"]
        want = [by_stem.get(stem) for stem in kind]
        got = [resource_path(src)[0] for src in srcs]
        if got != want:
            findings.add(rel, f"(j) the page loads {got}; "
                         f"{'Home' if rel == 'public/index.html' else 'every page but Home'} "
                         f"loads exactly {want} ({', '.join(kind)}), as baseof.html emits "
                         "them: search.js on Home only, copy.js on every page (ADR-0005 "
                         "part 5)")
    # (l) The pinned stylesheet (M4 PR 3 fix round 4): every built .css
    # file is exactly /css/<stem>.min.<SHA-256 hex of its bytes>.css for a
    # stem of BUILT_STYLESHEETS, compared as a whole string, at most one
    # file per stem; with the source pin of `guard`, no stylesheet reaches
    # a page that the safety-net review has not read.
    built_styles = {}
    for path in sorted(css_files):
        data = (public / path[1:]).read_bytes()
        stem = next((s for s in sorted(BUILT_STYLESHEETS)
                     if path == built_style_path(s, data)), None)
        if stem is None:
            findings.add("public", f"(l) {show(path, 240)} is not the build of the pinned "
                         "stylesheet: every .css file is exactly /css/<stem>.min.<SHA-256 hex "
                         f"of its bytes>.css for a stem of BUILT_STYLESHEETS ("
                         f"{', '.join(sorted(BUILT_STYLESHEETS))}), as resources.Minify and "
                         "resources.Fingerprint name it, and its sources are pinned in "
                         "STYLESHEET_SHA256 (CSS is a reviewed surface)")
        else:
            built_styles.setdefault(stem, []).append(path)
            digest = hashlib.sha256(data).hexdigest()
            if not args.no_built_pins and digest != BUILT_STYLESHEET_SHA256.get(stem):
                findings.add("public", f"(l) the bytes of {show(path, 240)} (SHA-256 {digest}) "
                             f"are not the pinned build of the stylesheet {stem} "
                             "(BUILT_STYLESHEET_SHA256 in tools/sitecheck.py): a built "
                             "stylesheet changes only with its pin, whatever input changed it "
                             "(a source, a second data file Hugo merges into the tokens, a "
                             "config), so the change gets the safety-net review")
    for stem, paths in sorted(built_styles.items()):
        if len(paths) > 1:
            findings.add("public", f"(l) {len(paths)} built files for the stylesheet {stem} "
                         f"({', '.join(paths)}); at most one file per pinned stylesheet")
    # Counted across ALL built CSS: a second file could otherwise redefine
    # the class with its own, equally !important, rule.
    if vh_definitions > 1:
        findings.add("public", f"CSS: {vh_definitions} top-level .visually-hidden "
                     "definitions across the built CSS; exactly one is allowed "
                     "(ADR-0003 part 6)")
    if vh_reveals > 1:
        findings.add("public", f"CSS: {vh_reveals} .visually-hidden reveal rules across "
                     "the built CSS; at most one is allowed (ADR-0003 part 6)")
    # Per class of the table (M4 PR 3): one rule across all built CSS, and
    # (fix round 2 of M3 PR 9, delta review 3) per page: the rule counts
    # only in a stylesheet the page itself applies, so a built CSS file no
    # page links (`static/css/print.css`) does not satisfy it.
    for cls, (what, until) in HIDDEN_UNTIL_SCRIPT.items():
        selector = f".{cls}[hidden]"
        if hidden_counts[cls] > 1:
            findings.add("public", f"CSS: {hidden_counts[cls]} top-level {selector} rules "
                         f"across the built CSS; exactly one is allowed, for {what}")
        for rel in hidden_used[cls]:
            if not stylesheets[rel] & hidden_files[cls]:
                findings.add(rel, f"CSS: the page has {what}, but no built CSS holds the "
                             f"rule `{selector} {{ display: none !important }}` in a "
                             "stylesheet the page applies (a <link rel=stylesheet> in the "
                             "closed form of rule (k)), so an author display value could "
                             f"show it without the script; it stays hidden until {until}")
    # Per page (M3 PR 10, #31 Known limit 5): the definition and its reveal
    # count only in a stylesheet the page applies, so a file no page links
    # (`static/css/print.css`) does not satisfy them, and the reveal, capped
    # at one above, is required wherever the class is used.
    for rel in vh_used:
        if not stylesheets[rel] & vh_files:
            findings.add(rel, "CSS: the page uses class visually-hidden, but no built "
                         "CSS holds its definition in a stylesheet the page applies (a "
                         "<link rel=stylesheet> in the closed form of rule (k)), so the "
                         "hidden text shows (ADR-0003 part 6)")
        if not stylesheets[rel] & reveal_files:
            findings.add(rel, "CSS: the page uses class visually-hidden, but no built "
                         "CSS holds its :focus/:focus-visible reveal in a stylesheet the "
                         "page applies (a <link rel=stylesheet> in the closed form of "
                         "rule (k)), so the skip link stays a 1 x 1 px box on keyboard "
                         "focus (WCAG 2.2 SC 2.4.7; ADR-0003 part 6)")
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
# The display name of a persona with params.hide_name (ADR-0004 part 5): the
# text of its record link in every list (rule 3) and of its /a-z/ entry.
HIDDEN_NAME = "Name hidden on request"
TITLE_SUFFIX = " · interviewscam.com"
REPORT_TITLE = "{name}, a name used in fake job interviews"
# The <title> of a visible persona's own report page puts the D10 label
# first, word for word and capitalised as the start of a sentence, so a
# search result cut at about 60 characters still shows the whole label
# (SPEC section 5, ADR-0004 part 4, amended in M3 PR 6). Only that <title>
# takes this form: the h1, the lists and JSON-LD keep the label after the
# name, and the meta description is the summary, with neither (rule 2).
PERSONA_LABEL_FIRST = "Name used by the campaign, possibly a stolen identity: {name}"
PERSONA_HEAD_TITLE = "{name}"
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
# non-page files: the data feed, which /data-feed/ links (M3 PR 8).
# 404.html is served, never linked.
INTERNAL_FILES = frozenset({"/feed.json"})
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
# Rule 4's exempt spans (the label-first <title>, the own-artifact boxes):
# the joined text keeps their text between these two private-use
# characters, and a name match is exempt only when it lies wholly between
# one pair. Both are non-word characters, so a name that runs across a
# marker still matches; the same characters in page text are replaced
# first, so a page cannot forge a span.
SPAN_OPEN, SPAN_CLOSE = "\ue000", "\ue001"
SPAN_FORGERY = str.maketrans({SPAN_OPEN: "\ufffd", SPAN_CLOSE: "\ufffd"})


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

    def strings(self, shown=True, spans=frozenset()):
        """Text pieces; shown=True skips hidden content, shown=False keeps
        it, <template> content included (never script or style). The text
        of an element in spans (rule 4's exemptions) is kept between
        SPAN_OPEN and SPAN_CLOSE; with spans, those characters in the page
        text itself are replaced, so a page cannot forge a span."""
        closed = shown and self.tag == "details" and "open" not in self.attrs
        for child in self.children:
            if isinstance(child, str):
                if not closed:  # loose text of a closed <details> is hidden
                    yield child.translate(SPAN_FORGERY) if spans else child
            elif shown and (child.tag in NO_TEXT_ELEMENTS or child.hides()):
                continue
            elif child in spans:
                yield SPAN_OPEN
                yield from child.strings(shown, spans)
                yield SPAN_CLOSE
            elif child.tag not in ("script", "style"):
                yield from child.strings(shown, spans)

    def text(self, sep="", shown=True, spans=frozenset()):
        """The text inside the element, whitespace collapsed, hidden content
        left out (shown=False keeps it). sep="" joins the text pieces as a
        browser lays out inline text; sep=" " also separates block
        neighbours that a tight join would run together."""
        return squash(sep.join(self.strings(shown, spans)))

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


def rendered_name(record):
    """The name as a record link shows it (record-name.html in html form):
    the placeholder for a hidden persona, the name plus the D10 label for a
    visible one, else the name; whitespace collapsed."""
    if is_hidden(record):
        return HIDDEN_NAME
    return squash(display_name(record))


def rendered_aliases(record):
    """The aliases as a list shows them: none for a hidden persona, each
    with the D10 label for a visible one; whitespace collapsed."""
    aliases = record.params.get("aliases")
    if is_hidden(record) or not isinstance(aliases, list):
        return []
    return [squash(f"{a} {PERSONA_LABEL}" if is_persona(record) else a)
            for a in aliases if isinstance(a, str)]


def record_title(record):
    """The fixed title of a record page, without the site suffix (rule 2)."""
    if record.section == "campaigns":
        return CAMPAIGN_TITLE.format(name=text_param(record, "name") or "")
    if is_hidden(record):
        return HIDDEN_TITLE
    return REPORT_TITLE.format(name=display_name(record))


def head_title(record):
    """The <title> of a record page, without the site suffix (rule 2): the
    label-first form for a visible persona, else the fixed title."""
    if is_persona(record) and not is_hidden(record):
        return PERSONA_HEAD_TITLE.format(
            name=PERSONA_LABEL_FIRST.format(name=text_param(record, "name") or ""))
    return record_title(record)


def own_record(by_page, rel, page):
    """The record whose own page this is: public/<section>/<slug>/index.html
    itself, never a page nested under its directory (rule 1 fails that),
    and only when the page has no markup: finding, whose nesting the
    class-scoped reads below cannot trust. None otherwise."""
    return None if page.unclosed else by_page.get(rel)


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


def document_titles(page):
    """The document <title> elements; an SVG <title> is a tooltip."""
    return [n for n in by_tag(page, "title") if not n.inside_tag("svg")]


def title_problems(page, want, head=None):
    """Rule 2: one <title> with the fixed title plus suffix, one <h1> with
    the fixed title. head is the <title> form when it differs from the h1
    (a visible persona's own page: the label first)."""
    problems = []
    head = want if head is None else head
    titles = document_titles(page)
    if len(titles) != 1:
        problems.append(f"rule 2: {len(titles)} <title> elements, exactly one is needed")
    for el in titles:
        if el.text() != head + TITLE_SUFFIX:
            problems.append(f"rule 2: <title> reads {show(el.text())}, the fixed title "
                            f"is {show(head + TITLE_SUFFIX)} (SPEC section 5)")
    h1s = by_tag(page, "h1")
    if len(h1s) != 1:
        problems.append(f"rule 2: {len(h1s)} <h1> elements, exactly one is needed")
    for el in h1s:
        if el.text() != want:
            problems.append(f"rule 2: <h1> reads {show(el.text())}, the fixed title "
                            f"is {show(want)} (SPEC section 5)")
    return problems


def description_problems(page, record):
    """Rule 2 on a visible persona's own page: the one meta description
    reads exactly the record's summary, so it carries neither the name nor
    the label (SPEC section 5). R5 keeps the name out of the summary in the
    source; rule 4 alone would pass a description with the labelled name."""
    want = text_param(record, "summary")
    if want is None:
        return []  # the schema's finding
    metas = [n for n in by_tag(page, "meta")
             if n.attrs.get("name", "").strip().lower() == "description"]
    problems = []
    if len(metas) != 1:
        problems.append(f"rule 2: {len(metas)} <meta name=\"description\"> elements, "
                        "exactly one is needed")
    for el in metas:
        got = squash(el.attrs.get("content", ""))
        if got != squash(want):
            problems.append(f"rule 2: the meta description reads {show(got)}; on a "
                            "persona page it is exactly params.summary, without the name "
                            "or the label (SPEC section 5)")
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


# The markup of the regions whose whole text is pinned (M4 PR 2 fix rounds 3
# and 5): a list item of record-item.html (rule 3), an /a-z/ entry of
# index-item.html and the no-report block of no-report.html (rule 15). Each
# holds exactly the element tree its template emits for the record, in
# count, order and nesting, every attribute value byte for byte as the
# builds write it (an href exactly /reports/<slug>/, /campaigns/<slug>/,
# /before-your-call/ or /report-a-scam/, read raw, not through site_path),
# and nothing else. Why: the text readers skip hidden content that a page
# can still show (hidden on an element site.css lays out, aria-hidden,
# <select>, <noscript>), text can live in an attribute (aria-label, title,
# value, a query string in an href, which the status bar and the address
# bar show), and an empty extra link is announced by its URL. The exact
# tree closes the class; a list of forbidden constructs would close only
# the probes.


def tree(tag, attrs=None, *children):
    """One element of an expected region tree: (tag, attributes, children)."""
    return (tag, dict(attrs or {}), list(children))


def name_labels(record):
    """The persona-label span of a visible persona's name or alias."""
    return [tree("span", {"class": "persona-label"})] if is_persona(record) \
        and not is_hidden(record) else []


def record_href(record):
    return f"/{record.section}/{record.slug}/"


def item_tree(record):
    """The tree record-item.html emits for a report, or None when the
    record has no date string (the records check's finding)."""
    date = record.data.get("date")
    if not isinstance(date, str):
        return None
    return tree("li", None, tree("a", {"href": record_href(record)}, *name_labels(record)),
                tree("span", {"class": "state-chip"}),
                tree("time", {"class": RECORD_DATE, "datetime": date}))


def entry_tree(record):
    """The tree index-item.html emits for a record, or None without a date."""
    date = record.data.get("date")
    if not isinstance(date, str):
        return None
    first = [tree("a", {"href": record_href(record)}, *name_labels(record))]
    if record.section == "reports":
        first.append(tree("span", {"class": "state-chip"}))
    first.append(tree("time", {"class": RECORD_DATE, "datetime": date}))
    meta = [tree("span", {"class": INDEX_TYPE})]
    aliases = rendered_aliases(record)
    if aliases:
        meta.append(tree("span", {"class": INDEX_ALIASES},
                         *(name_labels(record) * len(aliases))))
    if record.section == "reports":
        campaign = record.params.get("campaign")
        link = [tree("a", {"href": f"/campaigns/{campaign.get('slug')}/"})] \
            if isinstance(campaign, dict) else []
        meta.append(tree("span", {"class": INDEX_CAMPAIGN}, *link))
    return tree("li", None, *first, tree("span", {"class": "index-meta"}, *meta))


def block_tree():
    """The tree no-report.html emits."""
    return tree("div", {"class": NO_REPORT}, tree("p"),
                tree("ul", {"class": "link-list"},
                     *(tree("li", None, tree("a", {"href": path}))
                       for path, _ in NO_REPORT_LINKS)))


def shape_problems(root, what, template, want):
    """root against the tree want, element by element in order: the same
    tag and exactly the same attributes and values at every position, and
    no element more or less. The first difference is the finding."""
    def shown(tag, attrs):
        return "<" + tag + "".join(f" {k}={show(v, 40)}" for k, v in attrs.items()) + ">"

    def compare(el, expected):
        tag, attrs, children = expected
        if el.tag != tag or el.attrs != attrs:
            return [f"{what} holds {shown(el.tag, el.attrs)}, which {template} does not "
                    f"emit there (it emits {shown(tag, attrs)}); it holds exactly its "
                    "template's elements and attributes, so no text can hide from this "
                    "check and still show"]
        actual = [c for c in el.children if isinstance(c, Element)]
        for i in range(max(len(actual), len(children))):
            if i >= len(children):
                return [f"{what} holds {shown(actual[i].tag, actual[i].attrs)}, which "
                        f"{template} does not emit there (it emits nothing more inside "
                        f"{shown(tag, attrs)}); it holds exactly its template's elements "
                        "and attributes, so no text can hide from this check and still show"]
            if i >= len(actual):
                return [f"{what} lacks {shown(children[i][0], children[i][1])}, which "
                        f"{template} emits there"]
            found = compare(actual[i], children[i])
            if found:
                return found
        return []
    return compare(root, want) if want is not None else []


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
            items.setdefault(id(li), (li, []))[1].append((slug, record, a))
    for li, entries in items.values():
        slug, record, a = entries[0]
        where = f"/reports/{slug}/"
        if len(entries) > 1:
            problems.append(f"rule 3: one list item holds {len(entries)} report links "
                            f"({', '.join(f'/reports/{s}/' for s, _, _ in entries)}); each "
                            "report is its own item with its own chip (D6)")
            continue
        # The link shows its own record's name, so the chip and the date
        # beside it are that name's (M4 PR 2 fix round 1: the text of a
        # link was tied to nothing, so two items could swap their names).
        name = rendered_name(record)
        if a.text() != name:
            problems.append(f"rule 3: the link to {where} reads {show(a.text())}; it "
                            f"shows its record's name as it renders, {show(name)} (D6)")
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
        # The whole item (fix round 3): its markup is record-item.html's and
        # its text is name, chip, date. An /a-z/ entry is rule 15's.
        if page_path == A_Z_PATH and li.parent is not None \
                and INDEX_LIST in li.parent.classes:
            continue
        what = f"rule 3: the list item linking {where}"
        problems += shape_problems(li, what, "record-item.html", item_tree(record))
        if state in STATE_CHIP and isinstance(want, str):
            text = squash(f"{name} {STATE_CHIP[state]} {want}")
            if li.text() != text:
                problems.append(f"{what} reads {show(li.text(), 300)}; it reads exactly "
                                f"{show(text, 300)} (name, chip, date; D6)")
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


def page_texts(page, spans=frozenset()):
    """Every text of a page a reader or a search engine sees: the joined
    visible text (tight and spaced), each JSON-LD string and every attribute
    value, as written and percent-decoded (an alt, an aria-description, a
    search link). The joined text keeps the text of the elements in spans
    (rule 4's exemptions) between SPAN_OPEN and SPAN_CLOSE; their
    attributes are scanned as usual."""
    texts = [page.root.text(spans=spans), page.root.text(" ", spans=spans)]
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


def head_exemption(page, record):
    """Rule 4 on a visible persona's own page: the document <title>, when it
    is the only one and reads exactly the label-first head form (ADR-0004
    part 4). Any other <title> stays in the scan."""
    titles = document_titles(page)
    if len(titles) == 1 and titles[0].text() == head_title(record) + TITLE_SUFFIX:
        return set(titles)
    return set()


# Rule 4: the only characters an own-artifact box may hold, the printable
# ASCII range U+0021 to U+007E (94 characters, no space). Every member
# draws a visible glyph and the set can be read by eye; each wider set
# tried in PR 6 had a member that draws blank or folds to a space
# (ADR-0004 part 5, operator decision at #27 STOP 2).
BOX_CHARS = frozenset(map(chr, range(0x21, 0x7F)))


def plain_box(el):
    """Rule 4 (ADR-0004 part 5): the box holds nothing but text, with no
    child element (a <br> or an empty tag would break the name for the eye
    but not for the scan), and that text, entity-decoded (the parser does
    that) with nothing dropped or folded, consists only of BOX_CHARS. Any
    other character, whitespace, a blank, an invisible, a combining mark or
    a non-ASCII letter, makes the box non-exempt, so it fails closed."""
    if any(not isinstance(child, str) for child in el.children):
        return False
    text = "".join(el.children)
    return bool(text) and all(c in BOX_CHARS for c in text)


def labelled_box(el):
    """Rule 4, the labelled variant (ADR-0004 part 5, M3 PR 8; #27 Known
    limit 4): the box holds nothing but text, and the first child of its
    parent after it, past whitespace-only text, is a visible persona-label
    element, which the rule reads as exactly PERSONA_LABEL. An own
    artifact that is not pure printable ASCII is shown this way, so its
    name never renders without the label right next to it."""
    if any(not isinstance(child, str) for child in el.children) or el.parent is None:
        return False
    siblings = el.parent.children
    after = siblings[next(i for i, c in enumerate(siblings) if c is el) + 1:]
    for child in after:
        if isinstance(child, str):
            if child.strip(" \t\n\r\f"):
                return False
            continue
        return "persona-label" in child.classes and not child.concealed()
    return False


def own_artifact_boxes(page, record):
    """Rule 4 on a visible persona's own page (ADR-0004 part 5): the code
    boxes that may hold the persona's own name, as its own artifacts do.
    Only when the page's single h1 reads exactly the labelled title; then
    every <code> outside hidden content whose whole text equals a declared
    artifact value of the record as stored, that is a plain box (plain_box:
    a handle or a mailbox built from the name, never the name as a name)
    or a labelled one (labelled_box: the D10 label right after it), and
    that carries the class artifact or is the <code> child of the page's
    single campaign-line element. Their attributes stay in the scan."""
    h1s = by_tag(page, "h1")
    if len(h1s) != 1 or h1s[0].text() != record_title(record):
        return set()
    values = {squash(value) for _, value in declared_artifacts(record)}
    lines = by_class(page, "campaign-line")
    line = lines[0] if len(lines) == 1 else None
    return {el for el in by_tag(page, "code")
            if not el.concealed() and el.text() in values
            and (plain_box(el) or labelled_box(el))
            and ("artifact" in el.classes or (line is not None and el.parent is line))}


def in_one_span(text, match):
    """The match lies wholly between one SPAN_OPEN and its SPAN_CLOSE."""
    inner = match.group()
    if SPAN_OPEN in inner or SPAN_CLOSE in inner:
        return False
    return text.rfind(SPAN_OPEN, 0, match.start()) > text.rfind(SPAN_CLOSE, 0, match.start())


def persona_label_problems(page, personas, own=None):
    """Rule 4 (D10): every whole-word occurrence of a visible persona's name
    or alias is followed by the persona label, and none sits in hidden
    content, where a label does not count. own is the record whose own page
    this is (own_record): for that persona's names alone a match that lies
    wholly inside the label-first <title> or one own-artifact box is
    exempt; a match that runs across a box's edge is not."""
    problems = []
    label = " " + fold_words(PERSONA_LABEL)
    for el in by_class(page, "persona-label"):
        if el.text() != PERSONA_LABEL:
            problems.append(f"rule 4: a persona-label element reads {show(el.text())}, "
                            f"the label is {show(PERSONA_LABEL)} (D10)")
    texts = [fold_words(t) for t in page_texts(page)]
    own_texts = texts
    if own is not None and any(own is p for p in personas):
        spans = frozenset(head_exemption(page, own) | own_artifact_boxes(page, own))
        if spans:
            own_texts = [fold_words(t) for t in page_texts(page, spans)]
    hidden = [fold_words(t) for t in hidden_texts(page)]
    for persona in personas:
        names = record_names(persona)
        for field, name in names:
            pattern = name_pattern(name)
            if any(pattern.search(text) for text in hidden):
                problems.append(f"rule 4: the {field} of the persona record "
                                f"{persona.rel} appears in hidden content "
                                f"({HIDDEN_CONTENT}), where no label counts (D10)")
            # The span exemption applies to the two joined texts (indexes 0
            # and 1) only: attribute values and JSON-LD strings get none, so
            # a marker forged there exempts nothing.
            for i, text in enumerate(own_texts if persona is own else texts):
                # A shorter name inside a labelled longer one (an alias that
                # is part of the name) is covered by that label.
                covered = [(m.start(), m.end()) for _, other in names
                           for m in name_pattern(other).finditer(text)
                           if text.startswith(label, m.end())]
                bare = [m for m in pattern.finditer(text)
                        if not text.startswith(label, m.end())
                        and not any(s <= m.start() and m.end() <= e and (s, e) != m.span()
                                    for s, e in covered)
                        and not (persona is own and i < 2 and in_one_span(text, m))]
                if bare:
                    problems.append(f"rule 4: the {field} of the persona record "
                                    f"{persona.rel} renders without the label "
                                    f"{show(PERSONA_LABEL)} right after it (D10; the "
                                    "only exemptions are the label-first <title> of its "
                                    "own page and its own artifact boxes there, "
                                    "ADR-0004 parts 4 and 5)")
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
        # The labelled variant (rule 4): on a visible persona's page an
        # artifact that is not pure printable ASCII carries the label.
        if is_persona(record) and not is_hidden(record) and \
                any(c not in BOX_CHARS for c in campaign["artifact"]):
            want += " " + PERSONA_LABEL
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


def jsonld_date_problems(value, kind, where, record):
    """Rule 8: the dates of a WebPage are the record's own (ADR-0004 part 8,
    amended in M3 PR 6). record is the record whose own page this is, or
    None. On a record page datePublished equals the record's date, and on a
    report page lastReviewed equals params.last_reviewed, as strings
    (YYYY-MM-DD). On any other page no record states a publication date, so
    a datePublished there is a finding."""
    problems = []
    published = value.get("datePublished")
    if "datePublished" in value and record is None:
        problems.append(f"rule 8: {where} has a {kind} with datePublished on a page that "
                        "is not a record's own page; no record states that date, so the "
                        "page may not claim one (ADR-0004 part 8)")
    elif isinstance(published, str) and record is not None:
        want = record.data.get("date")
        if isinstance(want, str) and published != want:
            problems.append(f"rule 8: {where} has a {kind} whose datePublished "
                            f"{show(published)} is not the record's date {show(want)} "
                            "(ADR-0004 part 8)")
    reviewed = value.get("lastReviewed")
    if isinstance(reviewed, str) and record is not None and record.section == "reports":
        want = text_param(record, "last_reviewed")
        if want is not None and reviewed != want:
            problems.append(f"rule 8: {where} has a {kind} whose lastReviewed "
                            f"{show(reviewed)} is not the record's last_reviewed "
                            f"{show(want)} (ADR-0004 part 8)")
    return problems


def jsonld_value_problems(value, types, where, page_url, record=None):
    """Rule 8: the values of a typed object's keys. The site-identity values
    are pinned (publisher, isPartOf, a WebSite, every url, item and @id a
    site URL, a WebPage's url its own page), and so are a WebPage's dates
    (jsonld_date_problems); free text is only type-checked, because titles
    carry the subject's name."""
    problems = []
    kind = "/".join(types)
    for key in ("name", "description", "datePublished", "lastReviewed"):
        if key in value and not isinstance(value[key], str):
            problems.append(f"rule 8: {where} has a {kind} whose {key} is not a string")
    if "lastReviewed" in value and not REPORT_PAGE_URL.match(page_url):
        problems.append(f"rule 8: {where} has a {kind} with lastReviewed on a page that "
                        "is not a report page; only a report states a review date, so "
                        "no other page may claim one (ADR-0004 part 8)")
    if "WebPage" in types:
        problems += jsonld_date_problems(value, kind, where, record)
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


def jsonld_type_problems(value, where, page_url, root=True, record=None):
    """Rule 8 on one JSON-LD value: the only context, every object typed with
    an allowed type, an interviewscam.com Organization only, and on each
    object only the keys of JSONLD_KEYS. A block root may be a bare @graph
    container instead of an object."""
    problems = []
    if isinstance(value, list):
        for sub in value:
            problems += jsonld_type_problems(sub, where, page_url, root, record)
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
        problems += jsonld_value_problems(value, types, where, page_url, record)
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
            problems += jsonld_type_problems(sub, where, page_url, False, record)
    return problems


def structured_data_problems(page, page_url, record=None):
    """Rule 8 on one page: JSON-LD parses without duplicate keys and uses
    only the allowed types and keys, and a WebPage's dates are those of
    record, the record whose own page this is (None on any other page); no
    microdata or RDFa attribute."""
    problems = []
    for i, value, error in jsonld_values(page):
        if error is not None:
            problems.append(f"rule 8: JSON-LD block {i + 1} is not valid JSON: {error}")
            continue
        for key in dict.fromkeys(jsonld_duplicate_keys(page.jsonld[i])):
            problems.append(f"rule 8: JSON-LD block {i + 1} repeats the key {show(key)} "
                            "in one object; a parser keeps only one of them")
        problems += jsonld_type_problems(value, f"JSON-LD block {i + 1}", page_url,
                                         record=record)
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


# Rules 11 to 13: the data feed /feed.json (SPEC section 5, ADR-0004 part
# 7), its schema and its documentation page. The fixed values live here on
# purpose, independently of layouts/home.feed.json, like the page wording.
FEED_REL = "public/feed.json"
FEED_SCHEMA = "feed.schema.json"
FEED_PAGE_REL = "public/data-feed/index.html"
FEED_VERSION = 1  # ADR-0004 Numbers: the first published form
FEED_HOME_URL = SITE_ORIGIN + "/"
FEED_DOC_URL = SITE_ORIGIN + "/data-feed/"


def feed_report_entry(record):
    """Rule 12: the feed entry a report record must have, field by field
    (schema/feed.schema.json, ADR-0004 part 7). A hidden persona has name
    null, aliases [] and name_label null; a visible persona's name_label
    is the D10 label; every other name_label is null."""
    p = record.params
    persona, hidden = is_persona(record), is_hidden(record)
    campaign = p.get("campaign")
    line = None
    if isinstance(campaign, dict):
        line = {"slug": campaign.get("slug"),
                "url": f"{SITE_ORIGIN}/campaigns/{campaign.get('slug')}/",
                "basis": campaign.get("basis"), "artifact": campaign.get("artifact"),
                "source_id": campaign.get("source")}
    artifacts = copy.deepcopy(p.get("artifacts")) if isinstance(p.get("artifacts"), dict) else {}
    hashes = artifacts.get("sha256")
    for entry in hashes if isinstance(hashes, list) else []:
        if isinstance(entry, dict):
            on = entry.get("listed_on") if isinstance(entry.get("listed_on"), list) else []
            entry["lookup_urls"] = [LOOKUPS[s].format(entry.get("value")) for s in on
                                    if s in LOOKUPS]
    return {
        "slug": record.slug, "url": f"{SITE_ORIGIN}/reports/{record.slug}/",
        "name": None if hidden else p.get("name"), "name_hidden": hidden,
        "name_label": PERSONA_LABEL if persona and not hidden else None,
        "aliases": [] if hidden else p.get("aliases", []),
        "name_type": p.get("name_type"), "state": p.get("state"),
        "state_basis": p.get("state_basis"), "campaign": line,
        "related": p.get("related", []), "summary": p.get("summary"),
        "evidence": p.get("evidence"), "first_seen": p.get("first_seen"),
        "last_seen": p.get("last_seen"), "last_reviewed": p.get("last_reviewed"),
        "published": record.data.get("date"),
        "independent_reports": p.get("independent_reports"),
        "label": record_label(record), "artifacts": artifacts,
        "sources": p.get("sources", []),
    }


def feed_campaign_entry(record, reports):
    """Rule 12: the feed entry a campaign record must have."""
    p = record.params
    attribution = p.get("attribution", [])
    return {
        "slug": record.slug, "url": f"{SITE_ORIGIN}/campaigns/{record.slug}/",
        "name": p.get("name"), "aliases": p.get("aliases", []),
        "summary": p.get("summary"), "first_seen": p.get("first_seen"),
        "last_seen": p.get("last_seen"), "delivery": p.get("delivery"),
        "targeted_os": p.get("targeted_os"), "steals": p.get("steals"),
        "attribution": [{"statement": a.get("statement"), "source_id": a.get("source")}
                        for a in attribution if isinstance(a, dict)]
        if isinstance(attribution, list) else attribution,
        "report_slugs": sorted(r.slug for r in reports
                               if isinstance(r.params.get("campaign"), dict)
                               and r.params["campaign"].get("slug") == record.slug),
        "sources": p.get("sources", []),
    }


def feed_field_paths(schema, prefix=""):
    """Rule 13: every field path the feed schema defines, for example
    reports[].artifacts.sha256[].value: each property, then the properties
    of an object value (path.) and of the objects of a list (path[].)."""
    paths = []
    for name, sub in (schema.get("properties") or {}).items():
        path = prefix + name
        paths.append(path)
        if isinstance(sub, dict):
            paths += feed_field_paths(sub, path + ".")
            items = sub.get("items")
            if isinstance(items, dict):
                paths += feed_field_paths(items, path + "[].")
    return paths


def feed_entry_problems(kind, got, want):
    """Rule 12: the entry has exactly the fields sitecheck computes, and
    every one equals the record's value. The field set is pinned here
    too, so a field renamed in the template, the schema and /data-feed/
    together still fails until this check learns it (a breaking change)."""
    problems = []
    for key in sorted(set(want) - set(got)):
        problems.append(f"rule 12: {kind}[{show(want['slug'])}] has no field {key}, "
                        "which sitecheck render computes from the record (ADR-0004 part 7)")
    for key in sorted(set(got) - set(want)):
        problems.append(f"rule 12: {kind}[{show(want['slug'])}] has the field {show(key)}, "
                        "which sitecheck render does not know (ADR-0004 part 7)")
    for key in want:
        if key in got and not same_json(got[key], want[key]):
            problems.append(f"rule 12: {kind}[{show(want['slug'])}].{key} is "
                            f"{show(json.dumps(got[key], ensure_ascii=False))}, the record "
                            f"gives {show(json.dumps(want[key], ensure_ascii=False))} "
                            "(ADR-0004 part 7)")
    return problems


def feed_list_problems(kind, entries, records):
    """Rule 12: one entry per record, sorted by slug, and none without one."""
    problems = []
    slugs = [e.get("slug") for e in entries]
    want = sorted(r.slug for r in records)
    for slug in want:
        if slug not in slugs:
            problems.append(f"rule 12: the record {kind}/{slug} has no entry in "
                            f"{kind} (SPEC section 5: every published record)")
    for slug in slugs:
        if slug not in want:
            problems.append(f"rule 12: the {kind} entry {show(slug)} has no record; the "
                            "feed lists exactly the published records")
    if len(set(slugs)) != len(slugs):
        problems.append(f"rule 12: {kind} lists a slug twice")
    if slugs != sorted(slugs, key=str):
        problems.append(f"rule 12: {kind} is not sorted by slug")
    return problems


def feed_name_exempt(path, entries, persona):
    """Rule 12 (the boundary of #23 STOP 2 decision 1): a visible persona's
    name may appear only in its own entry, whose name_label is the D10
    label, as that entry's name, an alias, or a value under its artifacts
    or its campaign.artifact (an own artifact, as on its page)."""
    match = re.match(r"reports\[(\d+)\]\.(.*)", path)
    if not match:
        return False
    entry = entries[int(match.group(1))]
    if entry.get("slug") != persona.slug or entry.get("name_label") != PERSONA_LABEL:
        return False
    field = match.group(2)
    return (field == "name" or re.fullmatch(r"aliases\[\d+\]", field) is not None
            or field.startswith("artifacts.") or field == "campaign.artifact")


def next_element(el):
    """The next element sibling of el, past whitespace-only text, or None
    (also when text with other characters comes first)."""
    if el.parent is None:
        return None
    siblings = el.parent.children
    for child in siblings[next(i for i, c in enumerate(siblings) if c is el) + 1:]:
        if isinstance(child, str):
            if child.strip(" \t\n\r\f"):
                return None
            continue
        return child
    return None


def feed_problems(public, schema_dir, records, personas, pages):
    """Rules 11 to 13 on public/feed.json and public/data-feed/index.html:
    (rel, problem) pairs, and the feed part of the summary line."""
    out = []
    summary = "; feed: not read"
    path = public / "feed.json"
    try:
        schema = json.loads((schema_dir / FEED_SCHEMA).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [(f"schema/{FEED_SCHEMA}", f"rule 11: cannot read the feed schema: "
                 f"{exc}")], summary
    bad = schema_problems(schema, "#")
    if bad:
        return [(f"schema/{FEED_SCHEMA}", f"rule 11: {b}") for b in bad], summary
    # Rule 13: the field list on /data-feed/ is exactly the schema's paths.
    want_paths = feed_field_paths(schema)
    page = pages.get(FEED_PAGE_REL)
    if page is None:
        out.append((FEED_PAGE_REL, "rule 13: the documentation page /data-feed/ is "
                    "missing or has a markup: finding (SPEC section 6, ADR-0004 part 7)"))
    else:
        documented = []
        for dt in by_tag(page, "dt"):
            if dt.concealed():
                continue
            codes = [c for c in dt.children if not isinstance(c, str)]
            if len(codes) != 1 or codes[0].tag != "code" or dt.text() != codes[0].text():
                out.append((FEED_PAGE_REL, f"rule 13: the field-list term {show(dt.text())} "
                            "is not one <code> holding a field path"))
                continue
            # A hidden term documents nothing (above), and neither does a
            # visible term whose description is hidden, empty or missing.
            dd = next_element(dt)
            if dd is None or dd.tag != "dd" or dd.concealed() or not dd.text():
                out.append((FEED_PAGE_REL, f"rule 13: the field-list term {show(dt.text())} "
                            "has no visible <dd> description right after it"))
                continue
            documented.append(dt.text())
        for field in want_paths:
            if field not in documented:
                out.append((FEED_PAGE_REL, f"rule 13: the feed field {field} of "
                            f"schema/{FEED_SCHEMA} is not documented on /data-feed/"))
        for field in dict.fromkeys(documented):
            if field not in want_paths:
                out.append((FEED_PAGE_REL, f"rule 13: /data-feed/ documents the field "
                            f"{show(field)}, which schema/{FEED_SCHEMA} does not define"))
            if documented.count(field) > 1:
                out.append((FEED_PAGE_REL, f"rule 13: /data-feed/ documents the field "
                            f"{show(field)} twice"))
    # Rule 11: the feed exists, parses and validates against the schema.
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return out + [(FEED_REL, "rule 11: /feed.json is missing; the home page builds it "
                       "(hugo.toml outputs, layouts/home.feed.json; SPEC section 5)")], summary
    except (OSError, UnicodeDecodeError) as exc:
        return out + [(FEED_REL, f"rule 11: cannot read /feed.json: {exc}")], summary
    try:
        feed = json.loads(raw)
    except (json.JSONDecodeError, RecursionError) as exc:
        return out + [(FEED_REL, f"rule 11: /feed.json is not JSON: {exc}")], summary
    for key in dict.fromkeys(jsonld_duplicate_keys(raw)):
        out.append((FEED_REL, f"rule 11: the key {show(key)} occurs twice in one object"))
    errors = []
    validate(feed, schema, "", errors, [])
    if not isinstance(feed, dict) or "version" not in feed:
        errors.insert(0, "the version field is missing")
    for error in errors:
        out.append((FEED_REL, f"rule 11: does not match schema/{FEED_SCHEMA}: {error}"))
    if errors:
        return out, summary
    summary = (f"; feed: {len(feed['reports'])} reports, {len(feed['campaigns'])} "
               f"campaigns, {len(want_paths)} fields")
    # Rule 12: the entries equal the record set and the records.
    reports = [r for r in records if r.section == "reports"]
    campaigns = [r for r in records if r.section == "campaigns"]
    for kind, entries, recs in (("reports", feed["reports"], reports),
                                ("campaigns", feed["campaigns"], campaigns)):
        out += [(FEED_REL, p) for p in feed_list_problems(kind, entries, recs)]
        by_slug = {r.slug: r for r in recs}
        for entry in entries:
            record = by_slug.get(entry.get("slug"))
            if record is None:
                continue
            want = feed_report_entry(record) if kind == "reports" else \
                feed_campaign_entry(record, reports)
            out += [(FEED_REL, p) for p in feed_entry_problems(kind, entry, want)]
    dates = [r.data.get("date") for r in records] + \
        [r.params.get("last_reviewed") for r in reports]
    dates = [d for d in dates if isinstance(d, str)]
    updated = max(dates) if dates else None
    if feed["updated"] != updated:
        out.append((FEED_REL, f"rule 12: updated is {show(feed['updated'])}, the latest "
                    f"record date or review date is {show(updated)}"))
    # Rule 12, D10 (#23 STOP 2 decision 1): a visible persona's name, matched
    # as rule 4 matches it, appears only inside its own labelled entry.
    strings = list(iter_strings(feed, ""))
    for persona in personas:
        for field, name in record_names(persona):
            pattern = name_pattern(name)
            for where, text in strings:
                if pattern.search(fold_words(text)) and \
                        not feed_name_exempt(where, feed["reports"], persona):
                    out.append((FEED_REL, f"rule 12: the {field} of the persona record "
                                f"{persona.rel} appears in {where}; in the feed it may "
                                "appear only as its own entry's name and aliases, with "
                                "name_label set, and in that entry's artifacts (D10)"))
    return out, summary


COPY_CLASS = "copy"
COPY_TARGET = "data-copy-target"


def copy_button_problems(page, record, contact):
    """Rule 14 (ADR-0004 part 11, M3 PR 9): every Copy button (a <button>
    with the class copy) has type="button", so it never submits a form, and
    the hidden attribute, so a page without the script shows none; its
    data-copy-target names exactly one element of the page, whose text
    (text only, no child element, entity-decoded, nothing dropped) is one of
    the declared artifact values of the page's own record as stored, or
    params.contact. copy.js copies that text unchanged, so the clipboard
    gets a defanged value or the address, never a live one."""
    problems = []
    ids = {}
    for el in page.root.walk():
        if "id" in el.attrs:
            ids.setdefault(el.attrs["id"], []).append(el)
    allowed = {value for _, value in declared_artifacts(record)} if record else set()
    if contact:
        allowed.add(contact)
    for el in page.root.walk():
        if el.tag != "button" or COPY_CLASS not in el.classes:
            continue
        target = el.attrs.get(COPY_TARGET, "")
        what = f"the Copy button for {show(target) if target else 'no target'}"
        if el.attrs.get("type", "").strip().lower() != "button":
            problems.append(f"rule 14: {what} has no type=\"button\"; a button in a form "
                            "would submit it (ADR-0004 part 11)")
        # Only the hidden state hides it: `hidden="until-found"` lays the box
        # out, find-in-page reveals it (M3 PR 9 fix round 1, review 5).
        hidden = el.attrs.get("hidden")
        if hidden is None or ascii_lower(hidden) not in ("", "hidden"):
            problems.append(f"rule 14: {what} is not hidden (hidden="
                            f"{show(hidden) if hidden is not None else 'missing'}); it is "
                            "in the markup with the hidden attribute, empty or `hidden`, "
                            "and only copy.js reveals it, so a page without the script "
                            "shows no dead button (ADR-0004 part 11)")
        found = ids.get(target, []) if target else []
        if len(found) != 1:
            problems.append(f"rule 14: {what} names {len(found)} elements with that id on "
                            "the page; it needs exactly one target (ADR-0004 part 11)")
            continue
        box = found[0]
        text = "".join(c for c in box.children if isinstance(c, str))
        if any(not isinstance(c, str) for c in box.children) or text not in allowed:
            problems.append(f"rule 14: {what} copies {show(text)}, which is not a declared "
                            "artifact value of this page's record as stored, nor "
                            "params.contact, held as text only; the clipboard must get the "
                            "defanged value or the address (ADR-0004 part 11)")
    return problems


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


# Rule 15: the A to Z page /a-z/ and the no-JavaScript path of the Home
# search (ADR-0005 parts 2 and 6, M4 PR 2). The wording lives here on
# purpose, independently of data/labels.toml, as the D6 and D7 strings do:
# the index campaign line is the D7 wording of an attribution, an entry's
# whole text is pinned (its name, chip, type and aliases stand together),
# and the no-report block says that no report is no sign of safety.
A_Z_REL = "public/a-z/index.html"
A_Z_PATH = "/a-z/"
HOME_REL = "public/index.html"
INDEX_LIST = "index-list"
INDEX_TYPE = "index-type"
INDEX_ALIASES = "index-aliases"
INDEX_CAMPAIGN = "index-campaign"
INDEX_CAMPAIGN_LINE = "Campaign family that used this name: {campaign}"
INDEX_ALIASES_LINE = "Also seen as: {aliases}"
INDEX_ALIAS_SEPARATOR = ", "
INDEX_SEPARATOR = " · "
INDEX_CAMPAIGN_TYPE = "Campaign family"
# The type of a report entry (params.name_type), as on a report page.
NAME_TYPES = {"company": "Company", "persona": "Recruiter persona",
              "meeting_app": "Meeting app", "domain": "Domain",
              "repository": "Repository", "package": "Package"}
NO_REPORT = "no-report"
# The no-report block on /a-z/, the browse page: conditional, because the
# page lists every reported name (M4 PR 2 fix round 1), and it states only
# what the list holds, because artifacts (ADR-0005 decision 3) and hidden
# names are not on it (fix round 3). It says that no entry is no sign
# of safety. Wording approved by the operator at STOP 2 of #36 (D7).
NO_REPORT_BROWSE_TEXT = ("Not finding a name here does not mean it is safe. This list shows "
                         "each report by its name and its other names. Apart from those "
                         "names, it does not show the addresses, handles and files listed "
                         "inside a report, or names hidden on request. New fake interviews "
                         "also use names nobody has reported yet.")
# Every navigation of the block, in order, with its text: no other link.
NO_REPORT_LINKS = [("/before-your-call/", "Before your call"),
                   ("/report-a-scam/", "Report a scam")]


def is_within(el, ancestor):
    """el is ancestor or sits inside it."""
    while el is not None:
        if el is ancestor:
            return True
        el = el.parent
    return False


def index_campaign_text(record, campaigns):
    """The campaign family of a report entry, or None when its campaign
    record has no name (R7 is the records check's finding)."""
    campaign = record.params.get("campaign")
    if not isinstance(campaign, dict):
        return UNATTRIBUTED
    target = campaigns.get(campaign.get("slug"))
    name = text_param(target, "name") if target else None
    return INDEX_CAMPAIGN_LINE.format(campaign=squash(name)) if name is not None else None


def index_entry_text(record, campaigns):
    """The visible text of an /a-z/ entry as index-item.html composes it:
    name, chip (a report), date, then type, aliases and campaign family (a
    report) joined by INDEX_SEPARATOR. None when a record field it needs is
    not readable (the records check's finding)."""
    date = record.data.get("date")
    if not isinstance(date, str):
        return None
    first = [rendered_name(record)]
    if record.section == "reports":
        chip = STATE_CHIP.get(record.params.get("state"))
        kind = NAME_TYPES.get(record.params.get("name_type"))
        line = index_campaign_text(record, campaigns)
        if chip is None or kind is None or line is None:
            return None
        first.append(chip)
    else:
        kind, line = INDEX_CAMPAIGN_TYPE, None
    first.append(date)
    second = [kind]
    aliases = rendered_aliases(record)
    if aliases:
        second.append(INDEX_ALIASES_LINE.format(aliases=INDEX_ALIAS_SEPARATOR.join(aliases)))
    if line is not None:
        second.append(line)
    return squash(" ".join(first) + " " + INDEX_SEPARATOR.join(second))


def index_text_problems(li, link, record, campaigns):
    """Rule 15 (b) on the text of one visible entry (M4 PR 2 fix round 1):
    its record link shows the record's name as it renders, one visible
    index-type holds its type, one visible index-aliases its visible
    aliases (none without), and the whole visible text of the entry is
    exactly what index-item.html composes, so no name, alias, type or
    attribution can stand in it but the record's own."""
    where = f"/{record.section}/{record.slug}/"
    problems = []
    name = rendered_name(record)
    if link.text() != name:
        problems.append(f"rule 15 (b): the record link of the entry of {where} reads "
                        f"{show(link.text())}; it shows the record's name as it renders, "
                        f"{show(name)}")
    kind = INDEX_CAMPAIGN_TYPE if record.section == "campaigns" else \
        NAME_TYPES.get(record.params.get("name_type"))
    el, found = shown_one([n for n in li.walk() if INDEX_TYPE in n.classes], INDEX_TYPE,
                          f"rule 15 (b): the entry of {where}")
    problems += found
    if el is not None and not found and kind is not None and el.text() != kind:
        problems.append(f"rule 15 (b): the type of the entry of {where} reads "
                        f"{show(el.text())}, the record's type is {show(kind)}")
    aliases = rendered_aliases(record)
    lines = [n for n in li.walk() if INDEX_ALIASES in n.classes]
    if not aliases:
        if lines:
            problems.append(f"rule 15 (b): the entry of {where} holds {len(lines)} "
                            f"element(s) of class {INDEX_ALIASES}; the record shows no "
                            "aliases")
    else:
        el, found = shown_one(lines, INDEX_ALIASES, f"rule 15 (b): the entry of {where}")
        problems += found
        want = INDEX_ALIASES_LINE.format(aliases=INDEX_ALIAS_SEPARATOR.join(aliases))
        if el is not None and not found and el.text() != want:
            problems.append(f"rule 15 (b): the aliases of the entry of {where} read "
                            f"{show(el.text())}; the record's visible aliases read "
                            f"{show(want)}")
    want = index_entry_text(record, campaigns)
    if want is not None and li.text() != want:
        problems.append(f"rule 15 (b): the entry of {where} reads {show(li.text(), 300)}; "
                        f"its fixed composition is {show(want, 300)} (name, chip, date, "
                        "type, aliases, campaign family, and no other text)")
    return problems


def index_entry_problems(page, li, record, campaigns):
    """Rule 15 (c) on one visible entry of the A to Z list: a report entry
    holds one visible index-campaign naming its campaign family in the
    fixed wording with the campaign linked, or the unattributed wording
    without a link; a campaign entry holds none."""
    where = f"/{record.section}/{record.slug}/"
    lines = [n for n in li.walk() if INDEX_CAMPAIGN in n.classes]
    if record.section == "campaigns":
        if lines:
            return [f"rule 15 (c): the entry of {where} holds {len(lines)} element(s) of "
                    f"class {INDEX_CAMPAIGN}; only a report entry names a campaign family"]
        return []
    el, problems = shown_one(lines, INDEX_CAMPAIGN, f"rule 15 (c): the entry of {where}")
    if el is None or problems:
        return problems
    links = [(site_path(href, A_Z_PATH), text) for href, text in links_in(el, shown=True)]
    campaign = record.params.get("campaign")
    if not isinstance(campaign, dict):
        if el.text() != UNATTRIBUTED:
            problems.append(f"rule 15 (c): the campaign family of {where} reads "
                            f"{show(el.text())}, an unattributed report reads "
                            f"{show(UNATTRIBUTED)} (ADR-0004 part 6)")
        if links:
            problems.append(f"rule 15 (c): the campaign family of the unattributed "
                            f"{where} holds {len(links)} link(s); it links nothing")
        return problems
    slug = campaign.get("slug")
    target = campaigns.get(slug)
    name = text_param(target, "name") if target else None
    if name is None:
        return problems  # R7 is the records check's finding
    want = INDEX_CAMPAIGN_LINE.format(campaign=squash(name))
    if el.text() != want:
        problems.append(f"rule 15 (c): the campaign family of {where} reads "
                        f"{show(el.text())}, the fixed wording is {show(want)} "
                        "(ADR-0005 part 2)")
    path = f"/campaigns/{slug}/"
    if links != [(path, squash(name))]:
        problems.append(f"rule 15 (c): the campaign family of {where} does not link "
                        f"exactly {show(name)} to {path} (it holds {len(links)} visible "
                        "link(s))")
    return problems


def a_z_problems(page, records, campaigns):
    """Rule 15 (b) to (d) on /a-z/. Returns (problems, entries)."""
    problems = []
    lists = by_class(page, INDEX_LIST)
    el, found = shown_one(lists, INDEX_LIST, "rule 15 (b): /a-z/")
    problems += found
    if el is not None and el.tag != "ul":
        problems.append(f"rule 15 (b): the element of class {INDEX_LIST} on /a-z/ is a "
                        f"<{el.tag}>; the A to Z list is one <ul>")
    if el is not None:
        problems += chain_problems(el, A_Z_CHAIN, "rule 15 (b): the A to Z list on /a-z/")
    entries = 0
    if el is not None:
        want = {f"/{r.section}/{r.slug}/": r for r in records}
        seen = {path: [] for path in want}
        targets = nav_targets(page)
        for li in el.walk():
            if li.tag != "li":
                continue
            if li.parent is not el:
                problems.append("rule 15 (b): an <li> inside the A to Z list is not one of "
                                "its entries (a direct <li> child of the list); the list "
                                "holds one <li> per record and no other")
                continue
            entries += 1
            if li.concealed():
                problems.append(f"rule 15 (b): an entry of the A to Z list is in hidden "
                                f"content ({HIDDEN_CONTENT}); an entry is never hidden")
                continue
            links = [(a, url) for a, url in targets if is_within(a, li)
                     and not a.concealed() and not a.inside(INDEX_CAMPAIGN)
                     and INDEX_CAMPAIGN not in a.classes]
            if len(links) != 1:
                problems.append(f"rule 15 (b): an entry of the A to Z list holds "
                                f"{len(links)} visible links outside {INDEX_CAMPAIGN}; "
                                "each holds exactly one, its record link")
                continue
            path = site_path(links[0][1], A_Z_PATH)
            if path not in want:
                problems.append(f"rule 15 (b): an entry of the A to Z list links "
                                f"{show(path or links[0][1])}, which is no record page; the "
                                "list holds one entry per record and no other")
                continue
            seen[path].append((li, links[0][0]))
        for path, record in want.items():
            if not seen[path]:
                problems.append(f"rule 15 (b): the A to Z list has no entry for {record.rel} "
                                f"({path})")
            elif len(seen[path]) > 1:
                problems.append(f"rule 15 (b): the A to Z list has {len(seen[path])} entries "
                                f"for {record.rel} ({path}); one per record")
            for li, link in seen[path]:
                problems += shape_problems(li, f"rule 15 (b): the entry of {path}",
                                           "index-item.html", entry_tree(record))
                problems += index_text_problems(li, link, record, campaigns)
                problems += index_entry_problems(page, li, record, campaigns)
    block, found = one_of_class(page, NO_REPORT, "rule 15 (d): /a-z/")
    problems += found
    if block is not None:
        problems += chain_problems(block, A_Z_CHAIN, "rule 15 (d): the no-report block on /a-z/")
        problems += shape_problems(block, "rule 15 (d): the no-report block on /a-z/",
                                   "no-report.html", block_tree())
        # The whole text, the sentence and then the two link texts, joined
        # with spaces: the template puts each in its own block element.
        want = squash(" ".join([NO_REPORT_BROWSE_TEXT] + [t for _, t in NO_REPORT_LINKS]))
        if block.text(" ") != want:
            problems.append(f"rule 15 (d): the no-report block on /a-z/ reads "
                            f"{show(block.text(' '), 300)}; its fixed text is "
                            f"{show(want, 300)} (the sentence, then the two link texts, "
                            "and no other text; ADR-0005 part 4)")
        # Every visible navigation of the block with its text, in order
        # (fix round 1: the link texts were free text).
        links = [(site_path(url, A_Z_PATH), el.text()) for el, url in nav_targets(page)
                 if is_within(el, block) and not el.concealed()]
        if links != NO_REPORT_LINKS:
            got = ", ".join(f"{show(path)} {show(text)}" for path, text in links) or "nothing"
            problems.append(f"rule 15 (d): the no-report block on /a-z/ links {got}; it "
                            "links exactly /before-your-call/ 'Before your call' and "
                            "/report-a-scam/ 'Report a scam', in that order, and nothing "
                            "else")
    return problems, entries


# The search form as layouts/home.html emits it (M4 PR 3 fix round 1,
# review finding 4): every control, attribute and text, so no control can
# shadow a property of the form (a button named submit or action) and no
# submitter can change where or how it submits. The texts are
# home.search_label, home.search_button and a_z.browse_link.
SEARCH_LABEL = "Company, app, domain or recruiter"
SEARCH_BUTTON = "Check"
# The search icon of layouts/_partials/icon.html as the minifier writes it.
SEARCH_ICON_ATTRS = {"class": "icon", "viewbox": "0 0 24 24", "fill": "none",
                     "stroke": "currentColor", "stroke-width": "2",
                     "stroke-linecap": "round", "stroke-linejoin": "round",
                     "aria-hidden": "true"}


def search_form_tree():
    """The tree of the search form of layouts/home.html."""
    icon = pinned("span", {"class": "search-icon"}, "",
                  pinned("svg", SEARCH_ICON_ATTRS, "",
                         pinned("circle", {"cx": "11", "cy": "11", "r": "6.5"}, ""),
                         pinned("path", {"d": "m16 16 4.5 4.5"}, "")))
    query = pinned("input", {"id": "q", "type": "search", "name": "q", "autocomplete": "off",
                             "spellcheck": "false"}, "")
    return pinned(
        "form", {"class": "card search", "role": "search", "method": "get",
                 "action": A_Z_PATH}, None,
        pinned("label", {"for": "q"}, SEARCH_LABEL),
        pinned("div", {"class": "search-row"}, None,
               pinned("div", {"class": "search-field"}, "", icon, query),
               pinned("button", {"class": "button-primary", "type": "submit"},
                      SEARCH_BUTTON)),
        link_list_spec([(A_Z_PATH, A_Z_LINK_TEXT)]))


def home_search_problems(home):
    """Rule 15 (e): Home has a visible link to /a-z/, and its one search form
    (role search), visible, submits get to /a-z/, every submitter of it
    included (formaction and formmethod override the form's own)."""
    problems = []
    if A_Z_PATH not in linked_paths(home, "/"):
        problems.append("rule 15 (e): Home has no visible link to /a-z/, the A to Z list "
                        "that serves the search without JavaScript (ADR-0005 part 2)")
    forms = [n for n in home.root.walk() if n.tag == "form"
             and "search" in ascii_lower(n.attrs.get("role", "")).split()]
    if len(forms) != 1:
        problems.append(f"rule 15 (e): Home has {len(forms)} search forms (form with role "
                        "search); it has exactly one")
        return problems
    form = forms[0]
    if form.concealed():
        problems.append(f"rule 15 (e): the search form on Home is in hidden content "
                        f"({HIDDEN_CONTENT})")
    what = "rule 15 (e): the search form on Home"
    problems += chain_problems(form, HOME_CHAIN, what)
    found = region_problems(form, search_form_tree(), what, "layouts/home.html")
    problems += found[1] if found else []
    form_id = form.attrs.get("id")
    submits = [("the form", form.attrs.get("action"), form.attrs.get("method"))]
    for el in home.root.walk():
        if el.tag not in ("button", "input"):
            continue
        owner = el.attrs.get("form")
        if (owner is None and is_within(el, form)) or \
                (owner is not None and form_id is not None and owner == form_id):
            if "formaction" in el.attrs or "formmethod" in el.attrs:
                submits.append((f"a <{el.tag}> of the form",
                                el.attrs.get("formaction", form.attrs.get("action")),
                                el.attrs.get("formmethod", form.attrs.get("method"))))
    for what, action, method in submits:
        if method is None or ascii_lower(method) != "get":
            problems.append(f"rule 15 (e): {what} on Home submits with method "
                            f"{show(method) if method is not None else 'missing'}; the "
                            "search submits get")
        if action is None or site_path(action, "/") != A_Z_PATH:
            problems.append(f"rule 15 (e): {what} on Home submits to "
                            f"{show(action) if action is not None else 'the page itself'}; "
                            "the search submits to /a-z/")
    return problems


# Rule 16 (ADR-0005 parts 4 and 6, M4 PR 3): the hidden result markup of the
# Home search, exactly as search.js reveals it. The search sentence of the
# no-report block in the result sections: the search matches names, other
# names and artifacts, but not names hidden on request, so the sentence
# states what the search looks at and never that the registry holds
# nothing (the absence claim of #36's review finding 7). Draft wording for
# the operator's D7 approval at STOP 2 of M4 PR 3.
NO_REPORT_TEXT = ("Not finding a report here does not mean it is safe. The search looks at "
                  "the names, other names, addresses, handles and files listed in each "
                  "report, but not at names hidden on request. New fake interviews also "
                  "use names nobody has reported yet.")
SEARCH_RESULTS = "search-results"
SEARCH_OUT = "search-out"
# The three sections in order, each with its heading (search.*_heading).
SEARCH_SECTIONS = [("search-answer", "Found in the registry"),
                   ("search-partial", "No exact match, but these come close"),
                   ("search-none", "No report matches your search")]
# The ids search.js reads by name: the input and the four result elements.
SEARCH_IDS = ["q", SEARCH_RESULTS] + [sid for sid, _ in SEARCH_SECTIONS]
# The What to do now panel of layouts/_partials/what-to-do.html
# (report.warning_*), pinned on Home inside the answer, and the A to Z link
# of the partial section (a_z.browse_link).
WHAT_TO_DO_HEADING = "What to do now"
WHAT_TO_DO_TEXT = ("If you were sent code, a repository or an app to run as part of an "
                   "interview like this, do not install or run it.")
WHAT_TO_DO_LINKS = [("/before-your-call/", "What to do before your call"),
                    ("/before-your-call/#already-ran", "Already ran it? What to do now")]
A_Z_LINK_TEXT = "Browse every report A to Z"
# The warning icon of layouts/_partials/icon.html as the pinned Hugo's
# minifier writes it (attribute names lowercased by the parser).
WARNING_ICON_ATTRS = {"class": "icon", "viewbox": "0 0 24 24", "fill": "none",
                      "stroke": "currentColor", "stroke-width": "2",
                      "stroke-linecap": "round", "stroke-linejoin": "round",
                      "aria-hidden": "true"}
WARNING_ICON_PATHS = ["M12 3.5 2.5 20h19L12 3.5z", "M12 10v4.5", "M12 17.5h.01"]


def pinned(tag, attrs=None, text=None, *children):
    """One element of a region tree with its whole text (hidden content
    included), or None where only its children's texts are pinned."""
    return (tag, dict(attrs or {}), list(children), text)


def bare_tree(spec):
    """The (tag, attrs, children) tree of shape_problems."""
    tag, attrs, children, _ = spec
    return (tag, attrs, [bare_tree(c) for c in children])


def link_list_spec(links):
    return pinned("ul", {"class": "link-list"}, None,
                     *(pinned("li", None, None, pinned("a", {"href": path}, label))
                       for path, label in links))


def no_report_tree():
    return pinned("div", {"class": NO_REPORT}, None,
                     pinned("p", None, NO_REPORT_TEXT), link_list_spec(NO_REPORT_LINKS))


def search_region_tree():
    """The tree layouts/home.html emits for #search-results: every element,
    attribute and text, in order."""
    def section(sid, heading, *body):
        return pinned("section", {"id": sid, "class": f"card {SEARCH_OUT}",
                                     "aria-labelledby": f"{sid}-heading", "hidden": ""},
                         None,
                         pinned("h2", {"id": f"{sid}-heading", "tabindex": "-1"}, heading),
                         *body)
    empty_list = pinned("ul", {"class": INDEX_LIST}, "")
    icon = pinned("span", {"class": "panel-icon"}, "",
                     pinned("svg", WARNING_ICON_ATTRS, "",
                               *(pinned("path", {"d": d}, "")
                                 for d in WARNING_ICON_PATHS)))
    panel = pinned("section", {"class": "panel-warn", "aria-labelledby": "what-to-do"},
                      None, pinned("h3", {"id": "what-to-do"}, WHAT_TO_DO_HEADING, icon),
                      pinned("p", None, WHAT_TO_DO_TEXT), link_list_spec(WHAT_TO_DO_LINKS))
    (answer, answer_head), (partial, partial_head), (none, none_head) = SEARCH_SECTIONS
    return pinned(
        "div", {"id": SEARCH_RESULTS, "class": SEARCH_OUT, "hidden": ""}, None,
        section(answer, answer_head, empty_list, panel),
        section(partial, partial_head, empty_list, link_list_spec([(A_Z_PATH, A_Z_LINK_TEXT)]),
                no_report_tree()),
        section(none, none_head, no_report_tree()))


def tree_texts(spec):
    """Every text the region shows once revealed, in document order."""
    tag, attrs, children, text = spec
    if text is not None:
        return [text] if text else []
    return [t for child in children for t in tree_texts(child)]


def search_results_problems(home):
    """Rule 16 (ADR-0005 parts 4 and 6): Home holds the hidden result
    sections of the search exactly as layouts/home.html emits them, the tree
    of search_region_tree compared raw in count, order and nesting, every
    attribute byte for byte, and the text of every pinned element, hidden
    content included (it is what search.js reveals); the empty lists hold
    no report link, chip or name. The ids search.js reads occur once on the
    page, q is an input of the search form, and no ancestor of the region
    hides it, so revealing it shows it."""
    problems = []
    ids = {}
    for el in home.root.walk():
        if "id" in el.attrs:
            ids.setdefault(el.attrs["id"], []).append(el)
    for name in SEARCH_IDS:
        found = ids.get(name, [])
        if len(found) != 1:
            problems.append(f"rule 16: Home holds {len(found)} elements with the id "
                            f"{name}; search.js reads it by name, so it occurs exactly once "
                            "(ADR-0005 part 4)")
    if problems:
        return problems
    query = (ids.get("q") or [None])[0]
    form = query.nearest("form") if query is not None else None
    if query is None or query.tag != "input" or "form" in query.attrs or form is None \
            or "search" not in ascii_lower(form.attrs.get("role", "")).split():
        problems.append("rule 16: the element with the id q on Home is not an <input> of "
                        "the search form (role search, no form attribute); search.js reads "
                        "the query and the form through it (ADR-0005 part 4)")
    region = (ids.get(SEARCH_RESULTS) or [None])[0]
    if region is None:
        return problems
    problems += chain_problems(region, HOME_CHAIN, f"rule 16: #{SEARCH_RESULTS} on Home")
    what = f"rule 16: #{SEARCH_RESULTS} on Home"
    found = region_problems(region, search_region_tree(), what, "layouts/home.html")
    if found and found[0] == "shape":
        return problems + found[1]
    for cls_el in home.root.walk():
        if SEARCH_OUT in cls_el.classes and not is_within(cls_el, region):
            problems.append(f"rule 16: an element of class {SEARCH_OUT} on Home sits outside "
                            f"#{SEARCH_RESULTS}; the class marks only the result box and its "
                            "three sections (ADR-0005 part 4)")
            break
    return problems + (found[1] if found else [])


def region_problems(root, want, what, template):
    """A pinned region against its tree (`pinned` specs): ("shape",
    problems) when an element or attribute differs (shape_problems), else
    ("text", problems) for every pinned element whose text, hidden content
    included, differs, and then for the region's whole text, so no loose
    text sits between its elements; None when it matches."""
    shape = shape_problems(root, what, template, bare_tree(want))
    if shape:
        return ("shape", shape)

    def texts(el, spec):
        tag, attrs, children, text = spec
        found = []
        if text is not None and el.text(" ", shown=False) != text:
            label = f"<{tag}{' id=' + attrs['id'] if 'id' in attrs else ''}" \
                f"{' class=' + attrs['class'] if 'class' in attrs else ''}>"
            found.append(f"{what}: {label} reads {show(el.text(' ', shown=False), 300)}; it "
                         f"reads exactly {show(text, 300)} (labels.toml through "
                         f"{template}, pinned here)")
        elements = [c for c in el.children if isinstance(c, Element)]
        for child, child_spec in zip(elements, children):
            found += texts(child, child_spec)
        return found
    problems = texts(root, want)
    whole = squash(" ".join(tree_texts(want)))
    if not problems and root.text(" ", shown=False) != whole:
        problems.append(f"{what} reads {show(root.text(' ', shown=False), 300)}; its whole "
                        f"text is exactly {show(whole, 300)}, so no loose text sits between "
                        "its elements")
    return ("text", problems) if problems else None


# The ancestors of the pinned regions (M4 PR 3 fix round 1, review finding
# 3): each region sits exactly where its templates put it, every ancestor's
# tag and whole attribute map as baseof.html, page.html and a-z.html emit
# them, so no wrapper (popover, inert, dialog, details, hidden, a style
# hook) and no added attribute can conceal or disable it. An exact chain,
# not a list of concealing constructs: a list closes only the probes.
HTML_CHAIN = [("main", {"id": "main", "class": "container", "tabindex": "-1"}),
              ("body", {}), ("html", {"lang": "en"})]
HOME_CHAIN = HTML_CHAIN  # #search-results and the search form, in layouts/home.html
A_Z_CHAIN = [("div", {"class": "card"})] + HTML_CHAIN  # the list and the block, a-z.html


def chain_problems(el, want, what):
    """el's ancestors (the #document root aside), innermost first, against
    want: the same tags and exactly the same attributes, none more."""
    got, parent = [], el.parent
    while parent is not None and parent.tag != "#document":
        got.append((parent.tag, parent.attrs))
        parent = parent.parent
    if got == want:
        return []

    def shown(chain):
        return " in ".join("<" + tag + "".join(f" {k}={show(v, 40)}" for k, v in attrs.items())
                           + ">" for tag, attrs in chain)
    return [f"{what} sits in {shown(got) or 'no element'}; its ancestors are exactly "
            f"{shown(want)}, as the templates emit them, so no wrapper or attribute can hide, "
            "cover or disable it"]


def search_problems(pages, records, campaigns):
    """Rule 15 on a site build: (a) /a-z/ exists; (b) to (d) its list and its
    no-report block; (e) the Home search. A page with a markup: finding is
    not read (that finding fails the check). Returns (problems, summary)."""
    problems, entries = [], 0
    page = pages.get(A_Z_REL)
    if page is None:
        problems.append((A_Z_REL, "rule 15 (a): /a-z/ was not built; it is the A to Z list "
                                  "of every report and campaign family (ADR-0005 part 2)"))
    elif not page.unclosed:
        found, entries = a_z_problems(page, records, campaigns)
        problems += [(A_Z_REL, p) for p in found]
    home = pages.get(HOME_REL)
    if home is None:
        problems.append((HOME_REL, "rule 15 (e): no Home page was built"))
    elif not home.unclosed:
        problems += [(HOME_REL, p) for p in home_search_problems(home)]
        problems += [(HOME_REL, p) for p in search_results_problems(home)]
    return problems, f"; search: {entries} entries on /a-z/, 3 result sections on Home"


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
    # Rule 14 compares a Copy target with params.contact (D1), read from the
    # hugo.toml of the records root when it has one (the self-test's render
    # fixtures bring one only where a button copies the address).
    contact = None
    try:
        config = tomllib.loads((root / "hugo.toml").read_text(encoding="utf-8"))
        contact = config.get("params", {}).get("contact")
    except FileNotFoundError:
        pass
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        findings.add("hugo.toml", f"cannot read params.contact for rule 14: {exc}")
    if not isinstance(contact, str):
        contact = None
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
            problems += copy_button_problems(page, by_page.get(rel), contact)
            problems += persona_label_problems(page, personas,
                                               own_record(by_page, rel, page))
            # JSON-LD does not depend on element nesting, so rule 8 reads the
            # page's own record even when the page has a markup: finding.
            problems += structured_data_problems(page, SITE_ORIGIN + page_path,
                                                 by_page.get(rel))
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
            own = own_record(by_page, rel, page)
            if record is not None:
                problems += title_problems(page, record_title(record),
                                           head_title(record) if own is record else None)
                if own is record and is_persona(record) and not is_hidden(record):
                    problems += description_problems(page, record)
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
    # Rules 11 to 13 run on every site build; --no-feed is for the
    # self-test's render fixtures, which pin the page contract without a
    # feed (selftest.sh passes it unless the case has a feed.txt).
    feed_summary = ""
    if not args.no_feed:
        problems, feed_summary = feed_problems(public, schema_dir, records, personas, pages)
        for rel, problem in problems:
            findings.add(rel, problem)
    # Rule 15 runs on every site build; --no-search is for the self-test's
    # render fixtures, which have a Home page but no /a-z/ (selftest.sh
    # passes it unless the case has a search.txt).
    search_summary = ""
    if not args.no_search:
        problems, search_summary = search_problems(pages, records, campaigns)
        for rel, problem in problems:
            findings.add(rel, problem)
    if not pages:
        findings.add("public", "no HTML pages found; nothing was checked")
    n_reports = sum(r.section == "reports" for r in records)
    n_record_pages = sum(rel in by_page for rel in pages)
    return findings.report(
        f"render checked: {len(records)} records (reports {n_reports}, campaigns "
        f"{len(records) - n_reports}), {n_record_pages} record pages, {len(pages)} "
        f"HTML pages, {len(files)} files{feed_summary}{search_summary}")


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
# Fixed copy only from data/labels.toml (ADR-0004 part 13, M3 PR 7). Every
# fixed public string of the templates lives in data/labels.toml, so a copy
# change is a labels diff, which the operator reviews as content. This check
# reads the template sources and fails on copy written anywhere else.

LITERALS_LABELS_READERS = {"layouts/_partials/label.html",
                           "layouts/_partials/label-list.html"}
# L2: the attributes a browser shows or reads out as text (a screen reader
# or a braille display reads every aria- one of them; srcdoc is a whole
# document), plus the content of <meta name="description"> and of any
# element with property or itemprop (Open Graph and microdata text that
# search results and link previews show).
LITERALS_TEXT_ATTRS = {"alt", "title", "aria-label", "aria-description",
                       "aria-roledescription", "aria-valuetext", "aria-placeholder",
                       "aria-braillelabel", "aria-brailleroledescription",
                       "placeholder", "label", "value", "abbr", "summary",
                       "xlink:title", "srcdoc"}
LITERALS_TEXT_CONTENT_KEYS = {"property", "itemprop"}
# The content of a <meta> is shown or read out (a link preview, a search
# result, an app name) unless the meta is on this closed list (M3 PR 9 fix
# round 1, review 1): exactly the names today's baseof.html uses for browser
# settings, and the CSP http-equiv. Any other meta content (twitter:title,
# og:title given as name=, application-name, refresh) is a visible
# attribute for L2 and the print sinks, and so is a meta with property or
# itemprop, or with both a name and an http-equiv.
LITERALS_META_PLAIN_NAMES = frozenset({"viewport", "color-scheme", "theme-color"})
LITERALS_META_PLAIN_HTTP_EQUIV = frozenset({"content-security-policy"})
# Attributes whose value assets/js/copy.js writes into the page as text
# (the two statuses of a Copy button): a visible attribute for L2 and for
# the print sinks (M3 PR 9), not a data-* token.
LITERALS_SCRIPT_TEXT_ATTRS = frozenset({"data-copy-done", "data-copy-failed"})
# L2, closed world (fix round 2, review2 3): the attributes whose value is
# never shown or read out as text (names, references, enumerated tokens,
# geometry), exactly those today's templates use plus src. Any other
# attribute whose value holds a letter or digit is a finding, so an ARIA or
# MathML text attribute nobody listed (aria-rowindextext, alttext, ...)
# fails instead of passing. data-*, the content of a meta and style keep
# their own rules. M3 PR 9 adds aria-live (the Copy button's status region,
# an enumerated token) and integrity (the script's SHA-384, a hash).
LITERALS_PLAIN_ATTRS = frozenset("""
action aria-current aria-hidden aria-labelledby aria-live autocomplete charset class
cx cy d datetime fill for height href http-equiv id integrity lang method name r rel
role rx spellcheck src stroke stroke-linecap stroke-linejoin stroke-width tabindex
type viewbox width xmlns
""".split())
# The attribute values a path piped into relURL or absURL may fill (A1).
LITERALS_URL_ATTRS = frozenset({"href", "src", "action"})
# A3: the only non-ASCII symbols (characters that are not a letter or digit)
# a template, asset or static file may hold in text, an attribute, a literal
# or a CSS string: what today's tree uses. Every other one (an emoji such as
# U+1F193 SQUARED FREE, an arrow, a dash, a no-break or zero-width space)
# fails.
LITERALS_SYMBOLS = frozenset({"·"})
# L3: what a literal may be when it is not copy. One lowercase token (keys,
# paths, class names, date layouts, URLs) ...
LITERALS_TOKEN = re.compile(r"[a-z0-9_.:/#?=&%@+-]+")
# ... a word of render rule 8's JSON-LD vocabulary (the only allowlist; it
# grows only with the JSON-LD contract) ...
LITERALS_VOCABULARY = frozenset(JSONLD_TYPES).union(*JSONLD_KEYS.values())
# ... or, by position, the field argument of where/sort: a page field such as
# Section or Params.campaign.slug, never printed.
LITERALS_FIELD_FUNCS = {"where", "sort"}
LITERALS_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
LITERALS_MESSAGE_FUNCS = {"errorf", "warnf"}
# Actions that do not print their pipeline. `return` does: a partial returns
# it to the caller, which prints it. (Hugo's `try` is a function, not a
# keyword, and is banned: it turns an errorf or warnf message into a value
# the page can print, L4.)
LITERALS_CONTROL = {"if", "else", "end", "range", "with", "define", "block",
                    "template", "break", "continue"}
LITERALS_URL_FUNCS = {"relURL", "absURL"}
# L3, value positions (Known limit 1 of M3 PR 7, closed as far as the
# sources prove it). Every literal is one lowercase token at most, so these
# functions, which turn tokens into words, capitals or sentences, are
# banned outright (no template uses them)...
LITERALS_TEXT_SHAPERS = {"humanize", "inflect.Humanize", "title", "strings.Title",
                         "upper", "strings.ToUpper", "strings.FirstUpper",
                         "delimit", "collections.Delimit", "println", "fmt.Println",
                         "apply", "collections.Apply", "replacePairs",
                         "strings.ReplacePairs"}
# ... replace and replaceRE only with a replacement literal that holds no
# whitespace and no markup (tokens.css turns "_" into "-") ...
LITERALS_REPLACE = {"replace": 3, "strings.Replace": 3, "replaceRE": 2,
                    "strings.ReplaceRE": 2}
# ... and replaceRE only below a comparison (an operand of eq, ne, ..., at
# any depth): a pattern with no letter passes the rule above and can still
# cut a label (`replaceRE ", [^ ]+" ""` turns the D10 label into "(name used
# by the campaign a stolen identity)"), so its result may only decide a
# bool, as in box-label.html (M3 PR 8 review 7) ...
LITERALS_COMPARE_ONLY = {"replaceRE", "strings.ReplaceRE"}
# ... the value operands of cond, default, or and and are copy unless they
# have a shape that is never text: a path or URL, a vocabulary word or a
# heading element name (checklist.html picks h2 or h3) ...
LITERALS_CHOOSERS = {"cond", "compare.Conditional", "default", "compare.Default",
                     "or", "and"}
LITERALS_HEADING = re.compile(r"h[1-6]")
# ... the commands that build a collection from their operands: every
# literal they hold is a key or a value of the collection, which can print
# wherever the collection goes (the closed-world rule below) ...
LITERALS_BUILDERS = {"slice", "collections.Slice", "dict", "collections.Dictionary",
                     "append", "collections.Append", "split", "strings.Split"}
# ... and nothing below a comparison is ever printed: its result is a bool.
LITERALS_COMPARE = {"eq", "ne", "lt", "le", "gt", "ge", "in", "not",
                    "compare.Eq", "compare.Ne", "compare.Lt", "compare.Le",
                    "compare.Gt", "compare.Ge", "collections.In", "hasPrefix",
                    "hasSuffix", "strings.HasPrefix", "strings.HasSuffix",
                    "strings.Contains", "strings.ContainsAny"}
# The print functions whose operands print as values.
LITERALS_PRINT_FUNCS = {"print", "printf", "println", "fmt.Print", "fmt.Printf",
                        "fmt.Println"}
LITERALS_LABEL_PARTIALS = {"label.html", "label-list.html"}
LITERALS_PARTIAL_FUNCS = {"partial", "partialCached", "partials.Include",
                          "partials.IncludeCached"}
# A function word that reads data rather than literals (the first segment):
# a call of it is never a constant.
LITERALS_DATA_ROOTS = {"partial", "partialCached", "partials", "site", "hugo", "now",
                       "page", "resources", "templates", "time.Now", "math.Rand"}
LITERALS_NUMBER = re.compile(r"[-+]?(?:0[xXoObB])?[0-9][0-9a-fA-F_]*(?:\.[0-9_]*)?"
                             r"(?:[eEpP][-+]?[0-9]+)?|'.'")
LITERALS_FUNC_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?")
# A printf verb: flags, argument index, width, precision, verb.
PRINTF_VERB = re.compile(r"%[-+# 0]*(?:\[\d+\])?(?:\d+|\*)?(?:\.(?:\d+|\*)?)?"
                         r"(?:\[\d+\])?[A-Za-z%]")
# Markup inside a literal: a tag named by a known element or by a printf
# verb, with its attributes. Any other <...> stays and is read as text.
LITERALS_ATTR = re.compile(r"""([^\s<>"'/=]+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s<>"'=`]+))?""")
LITERALS_TAG = re.compile(
    r"<(/?)(%[-+# 0]*(?:\[\d+\])?(?:\d+|\*)?(?:\.(?:\d+|\*)?)?(?:\[\d+\])?[A-Za-z]"
    r"|[A-Za-z][A-Za-z0-9-]*)"
    r"((?:\s+[^\s<>\"'/=]+(?:\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s<>\"'=`]+))?)*)\s*/?>")
HTML_ELEMENTS = frozenset("""
a abbr address area article aside audio b base bdi bdo blockquote body br button
canvas caption cite code col colgroup data datalist dd del details dfn dialog div
dl dt em embed fieldset figcaption figure footer form h1 h2 h3 h4 h5 h6 head header
hgroup hr html i iframe img input ins kbd label legend li link main map mark menu
meta meter nav noscript object ol optgroup option output p picture pre progress q
rp rt ruby s samp script search section select slot small source span strong style
sub summary sup table tbody td template textarea tfoot th thead time title tr track
u ul var video wbr
""".split())
SVG_ELEMENTS = frozenset(e.lower() for e in """
svg g defs symbol use image switch foreignObject desc metadata title circle ellipse
line path polygon polyline rect text textPath tspan marker mask pattern clipPath
linearGradient radialGradient stop filter feBlend feColorMatrix feComponentTransfer
feComposite feConvolveMatrix feDiffuseLighting feDisplacementMap feDistantLight
feDropShadow feFlood feFuncA feFuncB feFuncG feFuncR feGaussianBlur feImage feMerge
feMergeNode feMorphology feOffset fePointLight feSpecularLighting feSpotLight feTile
feTurbulence view a script style
""".split())
LITERALS_ELEMENTS = HTML_ELEMENTS | SVG_ELEMENTS
# L4: the members of `site` a template may read. Params and Data have their
# own rules; anything else (Menus, Copyright, Language, ...) is a copy source
# in hugo.toml and fails closed. BaseURL is off since fix round 3: no template
# reads it, and baseURL reaches a page only inside the permalinks.
LITERALS_SITE_MEMBERS = {"Title", "Home", "RegularPages", "Pages", "GetPage",
                         "Sections", "Params", "Data"}
LITERALS_SITE_PARAMS = {"operator", "contact", "csp"}
LITERALS_HUGO_DATA = {"labels", "tokens"}
# hugo: only Data (hugo.Sites, hugo.Environment, ... read config).
LITERALS_HUGO_MEMBERS = {"Data"}
# Every occurrence, overlapping: site.Home.Site.Params.x has two.
SITE_CHAIN = re.compile(r"(?=(?:^site|\.Site)(?![\w])(?:\.(\w+))?(?:\.(\w+))?)")
HUGO_CHAIN = re.compile(r"^hugo(?![\w])(?:\.(\w+))?(?:\.(\w+))?")
# Page methods that read config or the repository, or carry a value past
# the literal rules, each with its reason: .Language (its Label,
# LanguageName, ... come from hugo.toml), .Languages, .GitInfo and
# .CodeOwners (commit subjects, CODEOWNERS), .Param (falls back to site
# params), .Sitemap (changeFreq and priority come from hugo.toml), .Store
# and .Scratch (a value set in one action prints in another, review2 1e).
LITERALS_BANNED_METHODS = {
    "Language": "reads hugo.toml or the repository",
    "Languages": "reads hugo.toml or the repository",
    "Sites": "reads hugo.toml or the repository",
    "GitInfo": "reads hugo.toml or the repository",
    "CodeOwners": "reads hugo.toml or the repository",
    "Param": "falls back to site params, a copy source in hugo.toml",
    "Sitemap": "reads hugo.toml (its changeFreq and priority)",
    "Store": "keeps a value one action sets for another to print, past the literal rules",
    "Scratch": "keeps a value one action sets for another to print, past the literal rules",
}
# L4: functions that read copy from somewhere this check cannot see:
# translations, files, the environment and remote data.
LITERALS_BANNED_WORDS = {"T", "i18n", "readFile", "readDir", "unmarshal", "getenv",
                         "getJSON", "getCSV", "try"}
LITERALS_BANNED_PREFIXES = ("lang.Translate", "os.", "transform.Unmarshal",
                            "data.GetJSON", "data.GetCSV", "resources.GetRemote")
# L4: a scratch store carries a value past the literal rules like .Store,
# and emojify turns a token (:free:) into a symbol (review2 1e).
LITERALS_BANNED_STATE = {"newScratch", "collections.NewScratch", "emojify",
                         "transform.Emojify"}
# L3 and L4, closed world (fix round 2, review2 1). Deny lists kept
# leaking, so what a template may call and read is an allowlist of what
# today's templates use, and everything else fails. A new function or
# member comes with its own review of what it can print.
#   LITERALS_FUNCTIONS      the functions a template outside a CSS template
#                           may call (site.* and hugo.* chains have L4's
#                           own rules). No function on it cuts a string or
#                           changes its case upwards, except the three
#                           scoped below.
#   LITERALS_CSS_FUNCTIONS  the same for CSS templates (L5 reads what they
#                           print).
#   LITERALS_FILE_FUNCTIONS functions only some files may call: split cuts a
#                           string (the label key) and first cuts one too
#                           (`first 2 "warning"` prints "wa"); replaceRE
#                           can cut or rewrite one, so only box-label.html
#                           calls it, and only below a comparison
#                           (LITERALS_COMPARE_ONLY: its result decides
#                           whether the D10 label follows a box; M3 PR 8);
#                           the resources.*
#                           functions run only in baseof.html, because a
#                           resource prints its raw file through .Content
#                           and its name through .Title (review3 3).
#   LITERALS_MEMBERS        the capitalised members (Hugo's page and site
#                           methods) a chain may read; lowercase segments
#                           are params and dict keys, which are data.
LITERALS_FUNCTIONS = frozenset("""
absURL add and append cond default dict eq errorf first ge htmlEscape in index int
jsonify len lower merge ne not partial printf reflect.IsMap reflect.IsSlice relURL
replaceRE resources.Concat resources.ExecuteAsTemplate resources.Fingerprint resources.Get
resources.Minify safeHTML safeJS slice sort split time.Format where
""".split())
LITERALS_CSS_FUNCTIONS = frozenset("div float index replace safeCSS slice".split())
LITERALS_FILE_FUNCTIONS = {"split": frozenset(LITERALS_LABELS_READERS),
                           "first": frozenset({"layouts/home.html"}),
                           "replaceRE": frozenset({"layouts/_partials/box-label.html"}),
                           **{f: frozenset({"layouts/baseof.html"}) for f in (
                               "resources.Concat", "resources.ExecuteAsTemplate",
                               "resources.Fingerprint", "resources.Get",
                               "resources.Minify")}}
# The literal operands a resources.* call may take (review3 3): a resource
# prints its name (`{{ . }}`, .Title, .RelPermalink, and the target name of
# ExecuteAsTemplate or Concat is any string), so the names are a closed
# list, exactly what today's baseof.html uses: three names and, from M3 PR 9,
# the script js/copy.js and the algorithm of its fingerprint, sha384 (#29
# Known limit 3), and from M4 PR 3 the search script js/search.js (ADR-0005
# part 5). ExecuteAsTemplate's context is the bare dot, nothing else.
LITERALS_RESOURCE_KEYS = frozenset({"favicon.svg", "css/tokens.css", "css/site.css",
                                    "js/copy.js", "js/search.js", "sha384"})
# The resources.* functions whose first operand names the resource they
# build (M3 PR 9 fix round 2, delta review 4): that name sets the served
# file's path and suffix. Named as a script (a suffix of JS_SUFFIXES, ASCII
# case) the result would be a script built from another asset, a template or
# a string, past the pin of SCRIPT_SHA256, which holds only the source files
# under assets/; so the served script comes only from `resources.Get` of a
# pinned script. FromString and Copy are not on LITERALS_FUNCTIONS and fail
# there too; they are listed so a later widening of that list keeps this rule.
LITERALS_RESOURCE_TARGETS = frozenset({"resources.Concat", "resources.Copy",
                                       "resources.ExecuteAsTemplate",
                                       "resources.FromString"})
# Every action of label.html and label-list.html that assigns a variable, in
# its token form (review3 4): one of today's forms, so $v holds only a value
# of data/labels.toml (or "") when `return $v` returns it.
LITERALS_LABEL_ASSIGNS = frozenset({
    "$key := .", "$v := hugo.Data.labels", "$v = index $v .", '$v = ""',
    "$key := .key", "$fields := .fields", "$s := index $entry .",
    "range $i , $entry := $v"})
# Elements whose content a browser reads as text, not markup (review3 5):
# RCDATA (title, textarea), raw text (xmp, noembed, noframes, iframe, and
# noscript with scripting on) and plaintext, which never ends. html.parser
# reads title and textarea as markup up to CPython 3.12.3 and as text in
# later releases, so this check reads them itself.
LITERALS_RAWTEXT_ELEMENTS = ("title", "textarea", "xmp", "plaintext", "noembed",
                             "noframes", "iframe", "noscript")
LITERALS_MEMBERS = frozenset("""
ByDate Content ContentBaseName Data Date Description File Format GetPage
Home Integrity Kind Pages Params Path Permalink RegularPages RelPermalink Reverse
Section Sections Title
""".split())
# The positions of the closed-world rule (L3). A literal in a value
# position (one whose text can reach the page) passes only with a shape
# that is never copy (value_shape: no letter or digit, a JSON-LD vocabulary
# word or keyword, h1 to h6) or from these fixed lists; a path or URL is
# not such a shape, because it holds words.
#   LITERALS_DICT_KEYS          dict keys (a key prints through range $k or
#                               %v).
#   LITERALS_COLLECTION_VALUES  (file, literal) for the dict values, slice
#                               and append elements and split inputs today's
#                               templates build; numbers included (a number
#                               prints as digits).
#   LITERALS_DATE_LAYOUTS       the layout of time.Format and .Format (a
#                               layout prints every character that is not a
#                               layout element, ":date_full" included).
#   LITERALS_CONTEXT_PARTIALS   the partials that may take a bare literal as
#                               their context, each with the literals it may
#                               take (icon.html: its three icon names, an
#                               index key there, and any other name fails
#                               its build; fix round 3: the name was any
#                               literal before); the label partials take
#                               their key.
#   LITERALS_FILE_DICT_KEYS     file -> the dict keys only that file may use:
#                               the field names of /feed.json, plain English
#                               words, only in layouts/home.feed.json, which
#                               prints them as JSON keys (M3 PR 8 review 1).
LITERALS_DICT_KEYS = frozenset("""
check details fields first head html icon id items jsonld key label
malwarebazaar page part search tile title value virustotal warning
""".split())
LITERALS_FILE_DICT_KEYS = {"layouts/home.feed.json": frozenset("""
aliases artifact artifacts attribution basis campaign campaigns delivery
documentation_url evidence first_seen home_page_url independent_reports
last_reviewed last_seen lookup_urls name_hidden name_label name_type published
related report_slugs reports slug source_id sources state state_basis statement
steals summary targeted_os updated version
""".split())}
LITERALS_COLLECTION_VALUES = frozenset({
    ("layouts/_partials/lookups.html", "https://bazaar.abuse.ch/sample/%s/"),
    ("layouts/_partials/lookups.html", "https://www.virustotal.com/gui/file/%s"),
    ("layouts/_partials/breadcrumb.html", "1"),
    ("layouts/_partials/breadcrumb.html", "2"),
    ("layouts/_partials/breadcrumb.html", "3"),
    ("layouts/_partials/checklist.html", "title"),
    ("layouts/_partials/checklist.html", "warning-signs"),
    ("layouts/_partials/checklist.html", "tile-warn"),
    ("layouts/_partials/checklist.html", "warning"),
    ("layouts/_partials/checklist.html", "do-this-instead"),
    ("layouts/_partials/checklist.html", "tile-ok"),
    ("layouts/_partials/checklist.html", "check"),
    ("layouts/_partials/footer.html", "contact"),  # the address's id (Copy, M3 PR 9)
    ("layouts/_partials/header.html", "/before-your-call/"),
    ("layouts/_partials/header.html", "/methodology/"),
    ("layouts/_partials/header.html", "/about/"),
    ("layouts/_partials/how-to-send.html", "contact-send"),  # the address's id (Copy)
    ("layouts/_partials/jsonld.html", "https://schema.org"),
    ("layouts/_partials/record-item.html", "chip"),
    # The state chip of an A to Z entry, as in record-item.html (M4 PR 2).
    ("layouts/_partials/index-item.html", "chip"),
    ("layouts/home.feed.json", "1"),  # the feed's version (ADR-0004 part 7)
    ("layouts/reports/page.html", "summary"),
    ("layouts/reports/page.html", "basis"),
})
LITERALS_DATE_LAYOUTS = frozenset({"2006-01-02"})
LITERALS_CONTEXT_PARTIALS = {"icon.html": frozenset({"check", "search", "warning"})}
# printf verbs, exactly (review2 1c): no %c, %q, %U or %x (they turn
# numbers into letters), and no flag, width, precision or argument index
# (%.2s cuts a string).
LITERALS_PRINTF_VERBS = frozenset({"%s", "%d", "%v", "%T", "%%"})
# A data: URL can embed an image or document that draws text no check
# reads (A5); none is used, so it fails closed in markup, CSS and literals.
DATA_URL = re.compile(r"(?i)(?<![\w.-])data\s*:")
# The sets of this section that exempt, allow or name things instead of
# flagging them. Every other LITERALS_* and CSS_* set is a flagging set, and
# the self-test needs a fail row for each of its members (review2 5).
LITERALS_PASSING_SETS = (
    "LITERALS_LABELS_READERS", "LITERALS_PLAIN_ATTRS", "LITERALS_URL_ATTRS",
    "LITERALS_SYMBOLS", "LITERALS_VOCABULARY", "LITERALS_FIELD_FUNCS",
    "LITERALS_MESSAGE_FUNCS", "LITERALS_CONTROL", "LITERALS_URL_FUNCS",
    "LITERALS_COMPARE", "LITERALS_LABEL_PARTIALS", "LITERALS_DATA_ROOTS",
    "LITERALS_ELEMENTS", "LITERALS_SITE_MEMBERS", "LITERALS_SITE_PARAMS",
    "LITERALS_HUGO_DATA", "LITERALS_HUGO_MEMBERS", "LITERALS_FUNCTIONS",
    "LITERALS_CSS_FUNCTIONS", "LITERALS_FILE_FUNCTIONS", "LITERALS_MEMBERS",
    "LITERALS_DICT_KEYS", "LITERALS_FILE_DICT_KEYS", "LITERALS_COLLECTION_VALUES",
    "LITERALS_DATE_LAYOUTS", "LITERALS_CONTEXT_PARTIALS", "LITERALS_PRINTF_VERBS", "LITERALS_KEY_OPERANDS",
    "LITERALS_RESOURCE_KEYS", "LITERALS_LABEL_ASSIGNS", "LITERALS_PASSING_SETS",
    "LITERALS_PRINT_SOURCES", "LITERALS_META_PLAIN_NAMES", "LITERALS_META_PLAIN_HTTP_EQUIV",
    "LITERALS_SCRIPT_PATTERNS",
)
# The allowlists whose contents the self-test pins entry by entry in
# tests/fixtures/literals/allowlists.tsv (review3 A3): every passing set of
# this section plus the CSP and guard lists, defined further down.
PINNED_ALLOWLISTS = LITERALS_PASSING_SETS + (
    "CSP_DIRECTIVES", "CSP_SOURCES", "HUGO_ENV_ALLOWED", "HUGO_CONFIG_STRINGS",
    "HUGO_CONFIG_PINNED",
    # site rule (k) (M3 PR 10): its two passing sets, and the URL trim set
    # of url_scheme and leaves_origin.
    "STYLESHEET_LINK_ATTRS", "HEAD_PREFIX_TAGS", "C0_AND_SPACE",
    # M3 PR 10 fix round 1: the closed path alphabet of rules (k) and (j),
    # and the pinned declarations of the .visually-hidden definition and
    # its reveal.
    "RESOURCE_PATH_CHARS", "VH_DEFINITION_DECLARATIONS", "VH_REVEAL_DECLARATIONS",
    # and the T2 name regex (QA on PR #33: no net saw its text).
    "LITERALS_TEMPLATE_NAME")
# L5: the CSS properties and @counter-style descriptors whose strings the
# browser draws as text.
CSS_TEXT_PROPERTIES = {"content", "list-style", "list-style-type", "quotes",
                       "symbols", "additive-symbols", "prefix", "suffix", "pad",
                       "negative", "text-overflow", "hyphenate-character",
                       "text-emphasis", "text-emphasis-style"}
# The @counter-style descriptors draw their identifiers too (`symbols: F r
# e e` draws "Free"), not only their strings.
CSS_COUNTER_DESCRIPTORS = {"symbols", "additive-symbols", "prefix", "suffix", "pad",
                           "negative"}
CSS_PROPERTY = re.compile(r"(?:^|(?<=[{;]))\s*([A-Za-z-]+)\s*:", re.M)
LITERALS_FIX = ("fixed copy lives only in data/labels.toml; read it through "
                "layouts/_partials/label.html or label-list.html")
GO_ESCAPE = re.compile(r"\\(?:([abfnrtv\\'\"])|x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})"
                       r"|U([0-9A-Fa-f]{8})|([0-7]{3}))")
GO_ESCAPES = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t",
              "v": "\v", "\\": "\\", "'": "'", '"': '"'}


def go_unquote(raw):
    """The value of a Go interpreted string or char literal (quotes removed).
    A \\x or octal escape is one byte; a run of them is decoded as UTF-8."""
    out, pending = [], bytearray()

    def flush():
        if pending:
            out.append(pending.decode("utf-8", "replace"))
            pending.clear()

    pos = 0
    for match in GO_ESCAPE.finditer(raw):
        if match.start() > pos:
            flush()
            out.append(raw[pos:match.start()])
        simple, hexbyte, u4, u8, octal = match.groups()
        if hexbyte or octal:
            pending.append(int(hexbyte, 16) if hexbyte else int(octal, 8) & 0xFF)
        else:
            flush()
            if simple:
                out.append(GO_ESCAPES[simple])
            else:
                try:
                    out.append(chr(int(u4 or u8, 16)))
                except (ValueError, OverflowError):
                    out.append("�")
        pos = match.end()
    flush()
    out.append(raw[pos:])
    return "".join(out)


# A symbol that draws a letter or digit: circled, parenthesised, squared and
# regional-indicator letters (category So) and braille cells, which a reader
# reads as text (U+24D5 CIRCLED LATIN SMALL LETTER F, U+1F175, U+280B).
LETTER_NAME = re.compile(r"\b(?:LETTER|DIGIT) \w|^BRAILLE PATTERN ")


def copy_char(c, kinds="LN"):
    """c is, or draws, a letter (kinds "L") or a letter or digit ("LN"):
    by its category, by its NFKC form (U+2122 is "TM") or by its name."""
    if unicodedata.category(c)[0] in kinds:
        return True
    if c.isascii():
        return False
    if any(unicodedata.category(d)[0] in kinds for d in unicodedata.normalize("NFKC", c)):
        return True
    name = unicodedata.name(c, "")
    return bool(LETTER_NAME.search(name)) and ("N" in kinds or "DIGIT" not in name)


def has_letter(text):
    return any(copy_char(c, "L") for c in text)


def has_copy(text):
    """A letter or digit, or a symbol that draws one (copy_char): the test of
    every rule. Whitespace, punctuation and other symbols pass."""
    return any(copy_char(c) for c in text)


class Token:
    def __init__(self, kind, text, offset, space_before):
        self.kind = kind  # word, str, lparen, rparen, pipe, assign, comma
        self.text = text  # the word, or the value of a string literal
        self.offset = offset  # in the file
        self.space_before = space_before


class Group:
    """A parenthesised pipeline, one operand of its command. chained: a
    field chain follows it (`(x).Y`), so its value is not the pipeline's;
    chain is that field chain (`.Y`), which the print sinks follow."""

    def __init__(self, pipeline, chained=False, chain=""):
        self.pipeline = pipeline
        self.chained = chained
        self.chain = chain


class Pipeline:
    def __init__(self, commands, declared, assign=None):
        self.commands = commands  # each a list of Token and Group operands
        self.declared = declared  # $x := ... or $x = ... at this level
        self.assign = assign  # the := or = token of that assignment


class TemplateError(Exception):
    def __init__(self, what, offset):
        super().__init__(what)
        self.what = what
        self.offset = offset


WORD_STOP = set(" \t\r\n()|,\"'`}=")


def lex_action(text, start):
    """The tokens of the action whose {{ ends at start. Returns (end offset
    after }}, tokens, whether the action is only a comment). Raises
    TemplateError for an action, comment or string that is not terminated."""
    tokens, n, j, space = [], len(text), start, True
    only_comment, seen_comment = True, False
    if text.startswith("-", j) and j + 1 < n and text[j + 1] in " \t\r\n":
        j += 1
    while j < n:
        c = text[j]
        if text.startswith("}}", j):
            return j + 2, tokens, seen_comment and only_comment
        if c in " \t\r\n":
            space = True
            j += 1
            continue
        if text.startswith("/*", j):
            end = text.find("*/", j + 2)
            if end < 0:
                raise TemplateError("comment", j)
            seen_comment, space, j = True, True, end + 2
            continue
        if c == "-" and space and text.startswith("}}", j + 1):
            j += 1
            continue
        only_comment = False
        if c in "\"'":
            k = j + 1
            while k < n and text[k] != c and text[k] != "\n":
                k += 2 if text[k] == "\\" else 1
            if k >= n or text[k] != c:
                raise TemplateError("string", j)
            tokens.append(Token("str", go_unquote(text[j + 1:k]), j, space))
            j = k + 1
        elif c == "`":
            k = text.find("`", j + 1)
            if k < 0:
                raise TemplateError("string", j)
            tokens.append(Token("str", text[j + 1:k], j, space))
            j = k + 1
        elif c in "()|,":
            kind = {"(": "lparen", ")": "rparen", "|": "pipe", ",": "comma"}[c]
            tokens.append(Token(kind, c, j, space))
            j += 1
        elif c == "=" or text.startswith(":=", j):
            width = 1 if c == "=" else 2
            tokens.append(Token("assign", text[j:j + width], j, space))
            j += width
        elif c == "}":
            # A single brace is not part of any word of the template language.
            tokens.append(Token("word", c, j, space))
            j += 1
        else:
            k = j
            while k < n and text[k] not in WORD_STOP and not text.startswith(":=", k):
                k += 1
            tokens.append(Token("word", text[j:k], j, space))
            j = k
        space = False
    raise TemplateError("action", start - 2)


def parse_pipeline(tokens, i=0, depth=0):
    """(Pipeline, next index). Parentheses become Group operands; a field
    chain right after a group (`(x).Y`) stays with it."""
    commands, cur, declared, assign = [], [], False, None
    while i < len(tokens):
        t = tokens[i]
        if t.kind == "rparen":
            if depth:
                i += 1
                break
            i += 1
            continue
        if t.kind == "lparen":
            sub, i = parse_pipeline(tokens, i + 1, depth + 1)
            chained = (i < len(tokens) and tokens[i].kind == "word"
                       and tokens[i].text.startswith(".") and not tokens[i].space_before)
            chain = tokens[i].text if chained else ""
            if chained:
                i += 1
            cur.append(Group(sub, chained, chain))
            continue
        if t.kind == "pipe":
            commands.append(cur)
            cur = []
        elif t.kind == "assign":
            declared, assign, cur = True, t, []
        elif t.kind == "comma":
            cur = []
        else:
            cur.append(t)
        i += 1
    commands.append(cur)
    return Pipeline(commands, declared, assign), i


def pipeline_literals(pipeline, exempt=False):
    """(token, exempt, field) for every string literal of a pipeline: exempt
    inside an errorf/warnf command (the message never renders), field when it
    is the argument right after the first operand of where/sort."""
    for command in pipeline.commands:
        fn = command[0].text if command and isinstance(command[0], Token) \
            and command[0].kind == "word" else None
        inner = exempt or fn in LITERALS_MESSAGE_FUNCS
        for index, operand in enumerate(command):
            if isinstance(operand, Group):
                yield from pipeline_literals(operand.pipeline, inner)
            elif operand.kind == "str":
                yield operand, inner, fn in LITERALS_FIELD_FUNCS and index == 2


def first_operand(pipeline):
    command = pipeline.commands[0] if pipeline.commands else []
    if not command:
        return None
    head = command[0]
    return first_operand(head.pipeline) if isinstance(head, Group) else head


def action_pipeline(tokens):
    """(pipeline, prints, binds): the pipeline of an action without its
    keywords (`else if`, `range`, `define`, `return`, ...), whether the
    action prints it (no control keyword, or `return`), and whether it binds
    its value for a later print (a declaration, `with` or `range`)."""
    prints, binds = True, False
    while tokens and tokens[0].kind == "word" and (
            tokens[0].text in LITERALS_CONTROL or tokens[0].text == "return"):
        prints = prints and tokens[0].text == "return"
        binds = binds or tokens[0].text in ("with", "range")
        tokens = tokens[1:]
    pipeline = parse_pipeline(tokens)[0]
    return pipeline, prints, binds or pipeline.declared


def bound_literal(pipeline, binds):
    """A literal with a letter that the action binds to a variable or to the
    dot (`$x := "label"`, `with "label"`), which a later action prints, or None.
    Its shape no longer matters there: L3 sees only the variable."""
    if not binds or len(pipeline.commands) != 1 or len(pipeline.commands[0]) != 1:
        return None
    head = pipeline.commands[0][0]
    if isinstance(head, Token) and head.kind == "str" and has_letter(head.text):
        return head
    return None


def printed_arguments(pipeline):
    """The literals with a letter that print, print or println print as
    values: every literal operand except the format of printf."""
    for command in pipeline.commands:
        fn = command[0].text if command and isinstance(command[0], Token) \
            and command[0].kind == "word" else None
        if fn in LITERALS_PRINT_FUNCS:
            operands = command[2:] if fn in ("printf", "fmt.Printf") else command[1:]
            for operand in operands:
                if isinstance(operand, Token) and operand.kind == "str" \
                        and has_letter(operand.text):
                    yield operand
        for operand in command:
            if isinstance(operand, Group):
                yield from printed_arguments(operand.pipeline)


def url_path_print(pipeline):
    """`{{ "/about/" | relURL }}`: a path piped into relURL or absURL alone,
    the one printed literal that is not copy."""
    commands = pipeline.commands
    return (len(commands) == 2 and len(commands[0]) == 1
            and isinstance(commands[0][0], Token) and commands[0][0].kind == "str"
            and commands[0][0].text.startswith("/") and len(commands[1]) == 1
            and isinstance(commands[1][0], Token)
            and commands[1][0].text in LITERALS_URL_FUNCS)


def printed_literal(pipeline, prints):
    """The literal an action prints bare, or None (url_path_print aside)."""
    if not prints:
        return None
    if pipeline.declared:
        return None
    head = first_operand(pipeline)
    if not isinstance(head, Token) or head.kind != "str":
        return None
    if url_path_print(pipeline):
        return None
    return head


def command_head(command):
    """The function word a command calls, or None."""
    if command and isinstance(command[0], Token) and command[0].kind == "word":
        return command[0].text
    return None


def banned_function(word):
    """A function L3 or L4 bans outright, whose operands then add nothing."""
    return (word in LITERALS_BANNED_WORDS or word in LITERALS_BANNED_STATE
            or word in LITERALS_TEXT_SHAPERS
            or any(m in LITERALS_BANNED_METHODS for m in re.findall(r"\.(\w+)", word))
            or any(word.startswith(p) if p.endswith(".") else word == p
                   or word.startswith(p + ".") for p in LITERALS_BANNED_PREFIXES))


def data_function(word):
    """A function word that reads data, not its operands (site, partial, now,
    and the file, environment and translation readers L4 bans)."""
    return (word in LITERALS_DATA_ROOTS or word.split(".")[0] in LITERALS_DATA_ROOTS
            or word in LITERALS_BANNED_WORDS
            or any(word.startswith(p) if p.endswith(".") else word == p
                   or word.startswith(p + ".") for p in LITERALS_BANNED_PREFIXES))


def literal_only(pipeline):
    """The pipeline reads nothing but literals: every operand a string,
    number or bool literal, every function a pure one with operands
    (`upper "free"`, `cond true "a" "b"`); no field, variable, dot, niladic
    function (`now`, `site`) or data function (`partial`, `site.GetPage`)."""
    for index, command in enumerate(pipeline.commands):
        if not command:
            return False
        for position, operand in enumerate(command):
            if isinstance(operand, Group):
                if operand.chained or not literal_only(operand.pipeline):
                    return False
                continue
            if operand.kind == "str":
                continue
            if operand.kind != "word":
                return False
            word = operand.text
            if word in ("true", "false", "nil") or LITERALS_NUMBER.fullmatch(word):
                continue
            if (position == 0 and LITERALS_FUNC_WORD.fullmatch(word)
                    and not data_function(word) and (len(command) > 1 or index > 0)):
                continue
            return False
    return True


def literal_remainder(value):
    """A literal as L3 reads its text: markup tags (known elements and printf
    verbs) replaced by a space, so `free<br>money` stays two words, then
    printf verbs removed and entities decoded."""
    rest = LITERALS_TAG.sub(
        lambda m: " " if m.group(2).startswith("%")
        or m.group(2).lower() in LITERALS_ELEMENTS else m.group(0), value)
    return html.unescape(PRINTF_VERB.sub("", rest))


def never_text(value):
    """A value-position literal whose shape is never copy: no letter or digit
    once markup, verbs and entities are gone, a path or https URL, a word of
    the JSON-LD vocabulary or keyword, or a heading element name."""
    rest = literal_remainder(value).strip()
    if not has_copy(rest):
        return True
    if value.startswith(("/", "https://")) and LITERALS_TOKEN.fullmatch(value):
        return True
    return (rest in LITERALS_VOCABULARY or rest in JSONLD_OBJECT_KEYS
            or rest in JSONLD_GRAPH_KEYS or bool(LITERALS_HEADING.fullmatch(rest)))


def label_partial_call(command):
    fn = command_head(command)
    return (fn in LITERALS_PARTIAL_FUNCS and len(command) > 1
            and isinstance(command[1], Token) and command[1].kind == "str"
            and command[1].text in LITERALS_LABEL_PARTIALS)


def pipeline_commands(pipeline):
    """Every command of a pipeline, its groups' commands included."""
    for command in pipeline.commands:
        yield command
        for operand in command:
            if isinstance(operand, Group):
                yield from pipeline_commands(operand.pipeline)


def token_form(tokens):
    """An action's tokens as one line (strings quoted), for pinned forms."""
    return " ".join(('""' if x.text == "" else repr(x.text)) if x.kind == "str"
                    else x.text for x in tokens)


def resource_operand_problems(command):
    """(token, message) for a resources.* command: every operand a literal on
    LITERALS_RESOURCE_KEYS, except the context of ExecuteAsTemplate, which is
    the bare dot (review3 2 and 3)."""
    fn = command[0].text
    for i, operand in enumerate(command[1:], 1):
        if fn == "resources.ExecuteAsTemplate" and i == 2:
            if not (isinstance(operand, Token) and operand.kind == "word"
                    and operand.text == "."):
                yield command[0], ("resources.ExecuteAsTemplate takes the bare `.` (the "
                                   "page) as its context, nothing else: the asset template "
                                   "prints what it gets (L3, review3 2)")
        elif not (isinstance(operand, Token) and operand.kind == "str"
                  and operand.text in LITERALS_RESOURCE_KEYS):
            what = show(operand.text) if isinstance(operand, Token) else "a group"
            yield (operand if isinstance(operand, Token) else command[0]), (
                f"{fn} takes {what}, which is not a literal on LITERALS_RESOURCE_KEYS; a "
                "resource prints its name (`.Title`, `.RelPermalink`), so the names are "
                "a closed list (L3, review3 3)")


def value_problems(pipeline, quiet=False, first=True):
    """(token, message) for L3's value positions: the text-shaping functions,
    replace with a replacement that is not a plain literal, and a copy
    literal among the values of cond, default, or and and. Nothing below a
    comparison, an errorf/warnf or a label partial call counts (quiet)."""
    for index, command in enumerate(pipeline.commands):
        fn = command_head(command)
        if fn in LITERALS_TEXT_SHAPERS:
            yield command[0], (f"{fn} turns tokens into words, capitals or sentences, "
                               "which only data/labels.toml may hold (L3)")
        inner = quiet or fn in LITERALS_COMPARE or fn in LITERALS_MESSAGE_FUNCS \
            or label_partial_call(command)
        if not inner and fn in LITERALS_REPLACE:
            at = LITERALS_REPLACE[fn]
            new = command[at] if at < len(command) else None
            if new is None:
                yield command[0], (f"{fn} takes its replacement from the pipe; write "
                                   "it as a literal (L3)")
            elif not (isinstance(new, Token) and new.kind == "str"):
                yield command[0], (f"{fn} takes its replacement from a value, not a "
                                   "literal (L3)")
            elif re.search(r"[\s<]", html.unescape(new.text)):
                yield new, (f"{fn} replaces with {show(new.text)}, which holds "
                            "whitespace or markup and so joins tokens into words (L3)")
        if not inner and fn in LITERALS_CHOOSERS:
            for operand in command[1:]:
                if isinstance(operand, Token) and operand.kind == "str" \
                        and not never_text(operand.text):
                    yield operand, (f"{fn} picks the literal {show(operand.text)} as a "
                                    "value, which can print (L3)")
        for operand in command:
            if isinstance(operand, Group):
                yield from value_problems(operand.pipeline, inner, False)


def compare_only_problems(pipeline, below=False):
    """(token, message) for a LITERALS_COMPARE_ONLY call whose result is not
    an operand of a comparison: in a group under eq, ne, lt, le, gt, ge, in
    or not, at any depth. A pipe into a comparison, a variable or a with
    fails closed."""
    for command in pipeline.commands:
        fn = command_head(command)
        if fn in LITERALS_COMPARE_ONLY and not below:
            yield command[0], (f"{fn} only below a comparison (`ne ({fn} ...) \"\"`): its "
                               "result can cut or rewrite a label, so it may only "
                               "decide a bool (L3, M3 PR 8)")
        for operand in command:
            if isinstance(operand, Group):
                yield from compare_only_problems(operand.pipeline,
                                                 below or fn in LITERALS_COMPARE)


def group_assign_problems(pipeline):
    """(token, message) for an assignment inside parentheses at any depth,
    `eq ($x = "free") ""` or `ne ($x := replaceRE ...) ""`: the value leaves
    the comparison through the variable, so the quiet position and
    LITERALS_COMPARE_ONLY would pass what a later action prints. No layout
    needs one, so it fails closed (M3 PR 8 review2 1 and 2)."""
    for command in pipeline.commands:
        for operand in command:
            if isinstance(operand, Group):
                if operand.pipeline.declared:
                    yield operand.pipeline.assign, (
                        f"an assignment inside parentheses ({show(operand.pipeline.assign.text)}"
                        "): its value leaves the group through the variable, so a "
                        "comparison does not keep it quiet; assign in an action of its "
                        "own (L3, M3 PR 8)")
                yield from group_assign_problems(operand.pipeline)


def value_shape(value):
    """A literal in a value position whose shape is never copy: no letter or
    digit once markup, verbs and entities are gone, a word of the JSON-LD
    vocabulary or keyword, or a heading element name. Unlike never_text, a
    path or URL is not such a shape: it holds words (A1)."""
    rest = literal_remainder(value).strip()
    if not has_copy(rest):
        return True
    return (rest in LITERALS_VOCABULARY or rest in JSONLD_OBJECT_KEYS
            or rest in JSONLD_GRAPH_KEYS or bool(LITERALS_HEADING.fullmatch(rest)))


def number_literal(token):
    return (isinstance(token, Token) and token.kind == "word"
            and bool(LITERALS_NUMBER.fullmatch(token.text)))


# The operands of a command that are keys, never values: a name, a field, a
# lookup key, a count, a resource or page path. (function, first operand
# index; None: from that index on.)
LITERALS_KEY_OPERANDS = {
    "where": 2, "collections.Where": 2, "sort": 2, "collections.Sort": 2,
    "index": 2, "collections.Index": 2, "isset": 2, "collections.IsSet": 2,
    "resources.Get": 1, "resources.GetMatch": 1, "resources.ExecuteAsTemplate": 1,
    "resources.Concat": 1, "resources.Fingerprint": 1, "site.GetPage": 1,
}


def literal_positions(pipeline, quiet=False, key=False):
    """(token, kind, command) for every string, number and char literal of a
    pipeline, by the position it sits in (L3, closed world, review2 1):
      exempt      under errorf/warnf (the message never renders)
      quiet       below a comparison or in a label partial call (a bool, a
                  label key)
      key         a name, field, lookup key, count or path (the operands of
                  LITERALS_KEY_OPERANDS, a partial name, the count of first,
                  a split separator)
      dict-key    a key of dict
      collection  a dict value, a slice or append element, a split input
      layout      the layout of time.Format or .Format
      context     a partial's bare context
      format      the format of printf
      value       anywhere else: its text can reach the page."""
    for command in pipeline.commands:
        fn = command_head(command) or ""
        exempt = fn in LITERALS_MESSAGE_FUNCS
        inner = quiet or fn in LITERALS_COMPARE or label_partial_call(command)
        for i, operand in enumerate(command):
            if exempt:
                kind = "exempt"
            elif inner:
                kind = "quiet"
            elif key:
                kind = "key"
            elif i == 0:
                kind = "value"
            elif fn in LITERALS_PARTIAL_FUNCS:
                kind = "key" if i != 2 else "context"
            elif fn in ("dict", "collections.Dictionary"):
                kind = "dict-key" if i % 2 else "collection"
            elif fn in ("split", "strings.Split"):
                kind = "collection" if i == 1 else "key"
            elif fn in LITERALS_BUILDERS:
                kind = "collection"
            elif fn in ("first", "collections.First", "last", "collections.Last",
                        "after", "collections.After"):
                kind = "key" if i == 1 else "value"
            elif fn == "time.Format" or fn == "dateFormat" or fn.endswith(".Format"):
                kind = "layout" if i == 1 else "value"
            elif fn in ("printf", "fmt.Printf"):
                kind = "format" if i == 1 else "value"
            elif fn == "resources.ExecuteAsTemplate" and i == 2:
                kind = "value"  # the context the asset template prints (review3 2)
            elif fn in LITERALS_KEY_OPERANDS or fn.endswith(".GetPage"):
                kind = "key" if i >= LITERALS_KEY_OPERANDS.get(fn, 1) else "value"
            else:
                kind = "value"
            if isinstance(operand, Group):
                yield from literal_positions(
                    operand.pipeline, quiet or inner or exempt,
                    key or kind == "key")
                continue
            if operand.kind == "str" or number_literal(operand):
                yield operand, kind, command


def position_problems(rel, pipeline, binds, keywords):
    """(token, message) for the closed-world rule of L3 on one action (not
    for CSS templates: L5 reads what they print). binds: the action binds
    its value (a declaration, with or range)."""
    name_key = any(k in ("define", "block", "template") for k in keywords)
    whole_literal = literal_only(pipeline)
    dict_keys = {}  # id of a dict command -> its literal keys so far
    first = first_operand(pipeline)
    for token, kind, command in literal_positions(pipeline):
        if name_key and token is first:
            continue  # the name of define, block or template
        if url_path_print(pipeline) and token is first:
            continue  # the path piped into relURL or absURL: rule A1
        string = token.kind == "str"
        text = token.text
        fn = command_head(command) or "the action"
        if kind == "dict-key":
            seen = dict_keys.setdefault(id(command), set())
            if string and text in seen:
                yield command, token, (f"the dict key {show(text)} is repeated in one dict; "
                              "Hugo keeps the last value, and the print sinks would read "
                              "the dict in an order that changes from run to run (L3, #31 "
                              "delta review 2)")
            seen.add(text)
            if not (string and (value_shape(text) or text in LITERALS_DICT_KEYS
                                or text in LITERALS_FILE_DICT_KEYS.get(rel, ()))):
                yield command, token, (f"the dict key {show(text)} is not on LITERALS_DICT_KEYS "
                              "or on LITERALS_FILE_DICT_KEYS for this file; a "
                              "key prints wherever the dict goes (L3)")
        elif kind == "collection":
            if not ((string and value_shape(text))
                    or (rel, text) in LITERALS_COLLECTION_VALUES):
                yield command, token, (f"the {fn} value {show(text)} is not on "
                              "LITERALS_COLLECTION_VALUES for this file; a collection "
                              "value prints wherever the collection goes (L3)")
        elif kind == "layout":
            if not (string and text in LITERALS_DATE_LAYOUTS):
                yield command, token, (f"the date layout {show(text)} is not on "
                              "LITERALS_DATE_LAYOUTS; a layout prints its text (L3)")
        elif kind == "context":
            partial = command[1].text if isinstance(command[1], Token) else ""
            if partial not in LITERALS_CONTEXT_PARTIALS:
                yield command, token, (f"the partial {show(partial)} takes the bare literal "
                              f"{show(text)} as its context, which it can print; only "
                              "icon.html takes a bare literal (L3)")
            elif not (string and text in LITERALS_CONTEXT_PARTIALS[partial]):
                yield command, token, (f"the partial {show(partial)} takes the bare literal "
                              f"{show(text)}, which is not one of its names on "
                              "LITERALS_CONTEXT_PARTIALS; an edit of the partial could "
                              "print it (L3, fix round 3)")
        elif kind in ("value", "format"):
            if string and value_shape(text):
                continue
            if binds and whole_literal:
                yield command, token, (f"the action binds a value computed from literals alone "
                              f"({show(text)}), which a later print shows (L3)")
            elif kind == "format":
                yield command, token, (f"the printf format {show(text)} holds copy, which it "
                              "prints (L3)")
            else:
                yield command, token, (f"the literal {show(text)} sits in a value position of "
                              f"{fn}, where its text can reach the page (L3)")


def verb_problems(token):
    """printf verbs other than exactly %s, %d, %v, %T and %% (review2 1c)."""
    for match in PRINTF_VERB.finditer(token.text):
        if match.group(0) not in LITERALS_PRINTF_VERBS:
            yield token, (f"printf verb {match.group(0)!r} in {show(token.text)}: only "
                          "%s, %d, %v, %T and %% (no flag, width or precision), because "
                          "%c, %q, %x and %U turn numbers into letters and %.Ns cuts a "
                          "string (L3)")


ENTITY_START = re.compile(r"&(?:#[0-9]+;|#[xX][0-9A-Fa-f]+;|([A-Za-z][A-Za-z0-9]*;))")


def amp_problems(token):
    """An & that does not start a complete entity (review2 1d): `&#` plus a
    number printed after it is a letter no check reads."""
    for at in (m.start() for m in re.finditer("&", token.text)):
        match = ENTITY_START.match(token.text, at)
        if not match or (match.group(1) and match.group(1) not in html.entities.html5):
            yield token, (f"the literal {show(token.text)} holds an & that does not start "
                          "a complete entity; an entity completed by a printed value "
                          "draws a letter no check reads (L3)")
            return


def symbol_problems(text):
    """The non-ASCII symbols of text (characters that are not a letter or
    digit, which L1 to L3 already flag) that are not on LITERALS_SYMBOLS
    (A3), as one message part, or None."""
    bad = sorted({c for c in text if not c.isascii() and not copy_char(c)
                  and c not in LITERALS_SYMBOLS})
    if not bad:
        return None
    return ", ".join(f"U+{ord(c):04X} {unicodedata.name(c, 'unnamed')}" for c in bad)


def literal_problems(value, field):
    """Why a string literal of a template action is copy, or []: markup with
    its visible attributes, then the remainder without tags, printf verbs and
    entities."""
    problems = []
    if field and LITERALS_FIELD.fullmatch(value):
        return problems
    for tag in LITERALS_TAG.finditer(value):
        name = tag.group(2)
        if not name.startswith("%") and name.lower() not in LITERALS_ELEMENTS:
            continue
        attrs = []
        for attr in LITERALS_ATTR.finditer(tag.group(3)):
            raw = attr.group(2) or ""
            if raw[:1] in "\"'":
                raw = raw[1:-1]
            attrs.append((attr.group(1).lower(), html.unescape(PRINTF_VERB.sub("", raw))))
        problems.extend(attribute_problems(name.lower(), attrs, " in a markup literal",
                                           "L3"))
    rest = literal_remainder(value).strip()
    if (has_copy(rest) and not LITERALS_TOKEN.fullmatch(rest)
            and rest not in LITERALS_VOCABULARY):
        problems.append(f"string literal {show(value)} is copy (L3)")
    return problems


def copy_source_problems(rel, tokens, literals, css=False):
    """L4: where a template may read copy from. css: a CSS template, the one
    place data/tokens.toml may be read whole (L5 reads what it prints)."""
    problems = []
    for t in tokens:
        if t.kind != "word":
            continue
        w = t.text
        for match in SITE_CHAIN.finditer(w):
            member, sub = match.group(1), match.group(2)
            if member is None:
                problems.append((t, f"{w} without a member; read site.Title, "
                                 "site.Params.operator, site.Params.contact or "
                                 "site.Params.csp directly (L4)"))
            elif member == "Data":
                problems.append((t, f"{w}: never site.Data or .Site.Data; "
                                 "labels through label.html (L4)"))
            elif member == "Params" and sub not in LITERALS_SITE_PARAMS:
                problems.append((t, f"{w}: site.Params only as operator, contact or "
                                 "csp (L4)"))
            elif member not in LITERALS_SITE_MEMBERS:
                problems.append((t, f"{w}: site.{member} is not a member a template "
                                 "may read (L4)"))
        match = HUGO_CHAIN.match(w)
        if match:
            member, sub = match.group(1), match.group(2)
            if member is None:
                problems.append((t, f"{w} without a member (L4)"))
            elif member == "Data" and sub not in LITERALS_HUGO_DATA:
                problems.append((t, f"{w}: hugo.Data only as hugo.Data.labels or "
                                 "hugo.Data.tokens (L4)"))
            elif member == "Data" and sub == "labels" and rel not in LITERALS_LABELS_READERS:
                problems.append((t, f"{w}: data/labels.toml is read only inside "
                                 "label.html and label-list.html (L4)"))
            elif member not in LITERALS_HUGO_MEMBERS:
                problems.append((t, f"{w}: hugo.{member} is not a member a template may "
                                 "read; it reads the config or other sites (L4)"))
            elif sub == "tokens" and not css and not w.startswith("hugo.Data.tokens.color"):
                problems.append((t, f"{w}: outside a CSS template, data/tokens.toml only "
                                 "as hugo.Data.tokens.color; its fonts and pair use "
                                 "strings are text (L4)"))
            elif sub == "tokens" and not css and not TOKENS_COLOR_KEY.fullmatch(w):
                problems.append((t, f"{w}: outside a CSS template, a colour only by its "
                                 "key, hugo.Data.tokens.color.<key>; the whole table "
                                 "prints its keys (`range $k, $_`), which are words "
                                 "(L4, review3 A1)"))
        flagged = any(token is t for token, _ in problems)
        for match in re.finditer(r"\.(\w+)(?![\w])", w):
            method = match.group(1)
            if method in LITERALS_BANNED_METHODS:
                flagged = True
                problems.append((t, f"{w}: .{method} {LITERALS_BANNED_METHODS[method]}, "
                                 "not data/labels.toml (L4)"))
        if not flagged and (w.startswith(("$", ".")) or SITE_CHAIN.match(w)
                            or HUGO_CHAIN.match(w)):
            for match in re.finditer(r"\.([A-Z]\w*)(?![\w])", w):
                if match.group(1) not in LITERALS_MEMBERS:
                    problems.append((t, f"{w}: .{match.group(1)} is not on "
                                     "LITERALS_MEMBERS, the page and site members a "
                                     "template may read (L4)"))
                    break
        if w in LITERALS_BANNED_STATE:
            problems.append((t, f"{w}: a scratch store or emoji shortcode carries copy "
                             "past the literal rules (L4)"))
        elif w == "try":
            problems.append((t, "try: it turns an errorf or warnf message into a "
                             "value the page can print, so the message would be copy "
                             "(L4)"))
        elif w in LITERALS_BANNED_WORDS or any(
                w.startswith(p) if p.endswith(".") else w == p or w.startswith(p + ".")
                for p in LITERALS_BANNED_PREFIXES):
            problems.append((t, f"{w}: translations, file reads, the environment and "
                             "remote data are not a copy source (L4)"))
        elif not (w.startswith(("$", ".")) or w in ("true", "false", "nil", "}")
                  or w in LITERALS_CONTROL or w == "return"
                  or LITERALS_NUMBER.fullmatch(w) or SITE_CHAIN.match(w)
                  or HUGO_CHAIN.match(w) or w in LITERALS_TEXT_SHAPERS):
            allowed = LITERALS_CSS_FUNCTIONS if css else LITERALS_FUNCTIONS
            files = LITERALS_FILE_FUNCTIONS.get(w)
            if w not in allowed:
                problems.append((t, f"{w}: not on the list of functions a "
                                 f"{'CSS ' if css else ''}template may call "
                                 f"({'LITERALS_CSS_FUNCTIONS' if css else 'LITERALS_FUNCTIONS'}"
                                 "); a new one comes with its own review of what it "
                                 "can print (L3)"))
            elif files is not None and rel not in files:
                why = ("it cuts a string (L3)" if not w.startswith("resources.") else
                       "a resource prints its raw file and its name (L4, review3 3)")
                problems.append((t, f"{w}: only {', '.join(sorted(files))} may call it, "
                                 f"because {why}"))
    for t, _, _ in literals:
        if t.text.startswith("_internal/"):
            problems.append((t, f"internal template {show(t.text)}: its copy is not "
                             "in data/labels.toml (L4)"))
    return problems


def meta_content_plain(tag, first):
    """The content attribute of this start tag (first: name -> its first
    value) is a meta's browser setting, never shown: the meta has no
    property or itemprop, and either a name on LITERALS_META_PLAIN_NAMES and
    no http-equiv, or an http-equiv on LITERALS_META_PLAIN_HTTP_EQUIV and no
    name (ASCII case-insensitive, as browsers match them)."""
    if tag != "meta" or any(key in first for key in LITERALS_TEXT_CONTENT_KEYS):
        return False
    name, equiv = first.get("name"), first.get("http-equiv")
    if name is not None and equiv is None:
        return ascii_lower(name.strip()) in LITERALS_META_PLAIN_NAMES
    if equiv is not None and name is None:
        return ascii_lower(equiv.strip()) in LITERALS_META_PLAIN_HTTP_EQUIV
    return False


def ascii_lower(text):
    return text.translate(ASCII_LOWER)


def attribute_problems(tag, attrs, where="", rule="L2"):
    """L2 on one start tag (attrs: (name, value) pairs, names lowercase): the
    visible attributes, the token-only ones, and L5 on a style attribute."""
    first = {}
    for name, value in attrs:
        first.setdefault(name, value)
    meta_name = (first.get("name") or "").lower() if tag == "meta" else None
    plain_content = meta_content_plain(tag, first)
    text_content = tag == "meta" and not plain_content
    problems = []
    for name, value in first.items():
        if value is None:
            continue
        if name == "style":
            # An inline custom property or text property (L5); site rule (c)
            # bans the attribute in the built pages too.
            problems.extend(f"style attribute{where}: {problem}"
                            for _, problem in css_text_problems(value))
            continue
        visible = name in LITERALS_TEXT_ATTRS or name in LITERALS_SCRIPT_TEXT_ATTRS \
            or (name == "content" and text_content)
        token_only = name.startswith("data-") or (
            name == "content" and plain_content and meta_name != "viewport")
        if visible and has_copy(value):
            problems.append(f"visible attribute {name}={show(value)}{where} ({rule})")
        # A data-* value is read by script or CSS, and the content of
        # another named meta by the reader's tools: they may hold a
        # token (an id, a keyword), never words.
        elif token_only:
            if has_copy(value) and not LITERALS_TOKEN.fullmatch(value.strip()):
                problems.append(f"attribute {name}={show(value)}{where} holds words, not "
                                f"a token ({rule})")
        # Closed world (review2 3): any other attribute off the list of
        # attributes that never show text may hold no letter or digit.
        elif (not visible and not (name == "content" and plain_content)
              and name not in LITERALS_PLAIN_ATTRS
              and name not in LITERALS_TEXT_CONTENT_KEYS and has_copy(value)):
            problems.append(f"attribute {name}={show(value)}{where} is not on "
                            "LITERALS_PLAIN_ATTRS, the attributes that never show "
                            f"text, and holds a letter or digit ({rule})")
        if DATA_URL.search(value):
            problems.append(f"attribute {name}={show(value)}{where} holds a data: URL, "
                            "which can embed an image or document that draws text no "
                            "check reads; fails closed (L6)")
        bad = symbol_problems(value)
        if bad:
            problems.append(f"attribute {name}={show(value)}{where} holds non-ASCII "
                            f"symbols that are not on LITERALS_SYMBOLS ({bad}) ({rule})")
    return problems


class LiteralsPage(html.parser.HTMLParser):
    """L1 and L2 on a template whose actions are blanked: text runs and the
    visible attributes, each with its line."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.problems = []  # (line, message)

    def _attrs(self, tag, attrs):
        line = self.getpos()[0]
        for problem in attribute_problems(tag, attrs):
            self.problems.append((line, problem))

    def handle_starttag(self, tag, attrs):
        self._attrs(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        self._attrs(tag, attrs)

    def handle_data(self, data):
        if not has_copy(data):
            bad = symbol_problems(data)
            if bad:
                self.problems.append((self.getpos()[0], "text outside template actions "
                                      "holds non-ASCII symbols that are not on "
                                      f"LITERALS_SYMBOLS ({bad}) (L1)"))
            return
        line = self.getpos()[0]
        first = next(i for i, c in enumerate(data) if copy_char(c))
        line += data.count("\n", 0, first)
        self.problems.append((line, f"text {show(data.strip())} outside template "
                              "actions (L1)"))


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def blank_actions(text, spans):
    """(text, holes): text with every action replaced by one space plus its
    newlines, so line numbers stay and no action text reaches the HTML
    reading, and the offset of each blank in it."""
    out, holes, pos, size = [], [], 0, 0
    for start, end in spans:
        out.append(text[pos:start])
        size += start - pos
        holes.append(size)
        blank = " " + "\n" * text.count("\n", start, end)
        out.append(blank)
        size += len(blank)
        pos = end
    out.append(text[pos:])
    return "".join(out), holes


def css_text_problems(css, holes=()):
    """L5: (offset, message) for every CSS string the browser draws as text,
    every attr() that draws an attribute (which L2 does not cover), every
    var() that draws a custom property (whose value no rule reads as text),
    and every template action (holes: offsets of the blanked actions) that
    prints into one of those values."""
    stripped = CSS_COMMENT_OR_STRING.sub(
        lambda m: m.group(0) if m.group(1) else re.sub(r"[^\n]", " ", m.group(0)), css)
    problems = []
    data_urls = [m.start() for m in DATA_URL.finditer(stripped)]
    if not data_urls and DATA_URL.search(css_unescape(stripped)):
        data_urls = [0]  # only an escaped one: no offset in the source
    for offset in data_urls:
        problems.append((offset, "a data: URL can embed an image that draws text no "
                         "check reads; fails closed (L6)"))
    for match in CSS_PROPERTY.finditer(stripped):
        prop = match.group(1).lower()
        custom = prop.startswith("--")
        if prop not in CSS_TEXT_PROPERTIES and not custom:
            continue
        k, n, depth = match.end(), len(stripped), 0
        while k < n:
            ch = stripped[k]
            if ch in "\"'":
                k += 1
                while k < n and stripped[k] != ch:
                    k += 2 if stripped[k] == "\\" else 1
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
            elif depth == 0 and ch in ";}":
                break
            k += 1
        value = stripped[match.end():k]
        for string in CSS_STRING_LITERAL.finditer(value):
            text = css_unescape(string.group(0)[1:-1])
            bad = symbol_problems(text)
            if bad and not has_copy(text):
                problems.append((match.start(1), f"{prop} holds non-ASCII symbols that "
                                 f"are not on LITERALS_SYMBOLS ({bad}) (L5)"))
            if has_copy(text) and custom:
                problems.append((match.start(1), f"custom property {prop} holds the "
                                 f"text {show(text)}, which a text property could "
                                 "draw (L5)"))
            elif has_copy(text):
                problems.append((match.start(1), f"{prop} draws the text "
                                 f"{show(text)} (L5)"))
        if custom:
            continue
        if prop in CSS_COUNTER_DESCRIPTORS:
            idents = re.sub(r"(?i)url\([^)]*\)", " ",
                            CSS_STRING_LITERAL.sub(" ", css_unescape(value)))
            idents = re.sub(r"(?<![\w-])[-+]?\d+(?:\.\d+)?(?:px|em|rem|%)?(?![\w-])",
                            " ", idents)
            if has_copy(idents):
                problems.append((match.start(1), f"{prop} draws the identifiers "
                                 f"{show(' '.join(idents.split()))} (L5)"))
        if re.search(r"(?i)(?<![\w-])attr\s*\(", css_unescape(value)):
            problems.append((match.start(1), f"{prop} draws an attribute with attr() "
                             "(L5)"))
        if re.search(r"(?i)(?<![\w-])var\s*\(", css_unescape(value)):
            problems.append((match.start(1), f"{prop} draws a custom property with "
                             "var(), whose value no rule reads as text (L5)"))
        if any(match.end() <= hole < k for hole in holes):
            problems.append((match.start(1), f"{prop} takes a value printed by a "
                             "template action, which L5 cannot read (L5)"))
    return problems


def template_actions(rel, text, findings):
    """(start, end, tokens, comment) for every action of a template, in
    order; an unterminated one is an L6 finding and ends the file."""
    actions, pos = [], 0
    while True:
        start = text.find("{{", pos)
        if start < 0:
            break
        try:
            end, tokens, comment = lex_action(text, start + 2)
        except TemplateError as exc:
            findings.add(f"{rel}:{line_of(text, exc.offset)}",
                         f"unterminated {exc.what} (L6); the template cannot be read")
            actions.append((start, len(text), None, True))
            break
        actions.append((start, end, tokens, comment))
        pos = end
    return actions


def template_names(command_or_tokens):
    """The name a `template` action calls, or None when it is not a literal."""
    tokens = command_or_tokens
    if len(tokens) > 1 and tokens[1].kind == "str":
        return tokens[1].text
    return None


def partial_problems(pipeline, root):
    """(token, message): every partial call names a file of
    layouts/_partials/ as a literal. Hugo serves its embedded templates
    (pagination.html, opengraph.html, ...) under any name that file does not
    take, and their copy is not in data/labels.toml."""
    base = (root / "layouts" / "_partials").resolve()
    for command in pipeline.commands:
        fn = command_head(command)
        if fn in LITERALS_PARTIAL_FUNCS:
            name = command[1] if len(command) > 1 else None
            if not (isinstance(name, Token) and name.kind == "str"):
                yield command[0], (f"{fn} without a literal name: a computed name "
                                   "can reach an embedded Hugo template (L4)")
            else:
                path = (base / name.text).resolve()
                if base not in path.parents or not path.is_file():
                    yield name, (f"partial {show(name.text)} is not a file under "
                                 "layouts/_partials/, so Hugo would use its embedded "
                                 "template, whose copy is not in data/labels.toml (L4)")
        for operand in command:
            if isinstance(operand, Group):
                yield from partial_problems(operand.pipeline, root)


def printf_formats(pipeline, exempt=False):
    """The literal formats of every printf command, outside errorf/warnf."""
    for command in pipeline.commands:
        fn = command_head(command)
        inner = exempt or fn in LITERALS_MESSAGE_FUNCS
        if (not inner and fn in ("printf", "fmt.Printf") and len(command) > 1
                and isinstance(command[1], Token) and command[1].kind == "str"):
            yield command[1]
        for operand in command:
            if isinstance(operand, Group):
                yield from printf_formats(operand.pipeline, inner)


# A1: the open value of an href, src or action attribute of a real start tag,
# right where the action starts.
# review3 6: the one place params.csp may print, and review3 5: a literal
# that opens a raw-text element.
TOKENS_COLOR_KEY = re.compile(r"hugo\.Data\.tokens\.color\.[a-z0-9_]+")
SHORTCODE_OPEN = re.compile(r"\{\{[<%]")
CONTENT_SHORTCODE = re.compile(r"\{\{< param (?:operator|contact) >\}\}")
CSP_META_OPEN = '<meta http-equiv="Content-Security-Policy" content="'
RAWTEXT_LITERAL = re.compile(r"(?i)<(?:%s)\b" % "|".join(LITERALS_RAWTEXT_ELEMENTS))
# review4 1: every start and end tag is read as a browser's tokenizer reads
# it (WHATWG HTML 13.2.5) and skipped whole, so a '<!--', '<' or quote in an
# attribute value never counts as text: the tag name runs to whitespace, '/'
# or '>', an attribute name to whitespace, '/', '>' or '=', and a value is
# quoted or runs to whitespace or '>'. The groups are atomic, so a tag
# without its '>' fails in linear time. review5 A3: re.ASCII and ASCII
# lowercase, because Python folds case over Unicode (`<` U+017F `tyle>` read
# as `<style>`, U+212A as `k`) and a browser lowercases A to Z only.
TAG_ATTRS = (r"""(?>[\t\n\f\r /]|[^\t\n\f\r />][^\t\n\f\r />=]*+"""
             r"""(?:[\t\n\f\r ]*+=[\t\n\f\r ]*+(?:"[^"]*+"|'[^']*+'|[^\t\n\f\r >"'][^\t\n\f\r >]*+)?)?)*+""")
TAG_END = r"(?=[\t\n\f\r />])"
# A browser reads `<!x`, `<?x` and `</ x` as a comment to the next '>'; Go's
# escaper reads them as text (and escapes the '<'), so only the reading of a
# built page skips them. A `<![CDATA[` is skipped as one too, and rule (i)
# fails it closed.
RAWTEXT_SCAN = re.compile(r"""<!--|<(/?)([A-Za-z][^\t\n\f\r />]*+)(%s)>"""
                          r"""|<!|<\?|</(?![A-Za-z])""" % TAG_ATTRS, re.ASCII)
ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
URL_ATTR_OPEN = re.compile(r"""<[A-Za-z][A-Za-z0-9-]*(?:\s[^<>]*)?\s([A-Za-z:-]+)\s*=\s*["']?$""")


def template_literal_problems(rel, text, findings, counts, markup, root, defines,
                              css=False, record=None):
    """L1 to L4 and L6 on one template file; returns the file with its actions
    blanked and the offsets of the blanks in it, for L5. markup: read the
    text as HTML (not for CSS). css: a CSS template, whose actions print
    into a stylesheet, where L5 reads the text (so the closed-world position
    rule of L3 does not apply). record: a dict that receives the file's
    actions and the indexes of those with a finding, for the print sinks
    (one defect, one finding)."""
    actions = template_actions(rel, text, findings)
    spans = [(start, end) for start, end, _, _ in actions]
    reported = set()
    scope = []
    flagged = set()  # token offsets with a finding: one defect, one finding
    bare, holes = blank_actions(text, spans)

    def in_url_attr(index):
        """The action starts the value of an href, src or action attribute
        of a real start tag (A1), not text or another attribute."""
        before = bare[:holes[index]]
        match = URL_ATTR_OPEN.search(before[before.rfind("<"):])
        return bool(match) and match.group(1).lower() in LITERALS_URL_ATTRS

    def report(token, message, fix=True):
        key = (token.offset, message)
        if key not in reported:
            reported.add(key)
            flagged.add(token.offset)
            findings.add(f"{rel}:{line_of(text, token.offset)}",
                         f"{message}; {LITERALS_FIX}" if fix else message)

    def report_new(token, message):
        if token.offset not in flagged:
            report(token, message)

    for index, (start, end, tokens, comment) in enumerate(actions):
        if comment or tokens is None:
            continue
        counts["actions"] += 1
        if tokens and tokens[0].kind == "word" and tokens[0].text == "template":
            name = template_names(tokens)
            if name is None or (name not in defines and not name.startswith("_internal/")):
                report(tokens[0], f"template {show(name) if name else 'without a literal name'} "
                       "is not defined by a layout, so Hugo would use an embedded "
                       "template, whose copy is not in data/labels.toml (L4)")
        pipeline, prints, binds = action_pipeline(tokens)
        literals = list(pipeline_literals(pipeline))
        counts["literals"] += len(literals)
        printed = False
        for t, exempt, field in literals:
            if exempt:
                continue
            for problem in literal_problems(t.text, field):
                printed = True  # one defect, one finding: no constant-print finding
                report(t, problem)
        head = printed_literal(pipeline, prints)
        if head is not None:
            printed = True
            report(head, f"the action prints a bare literal {show(head.text)} (L3)")
        bound = bound_literal(pipeline, binds)
        if bound is not None:
            report(bound, f"the action binds the bare literal {show(bound.text)} for a "
                   "later print (L3)")
        for arg in printed_arguments(pipeline):
            if not any(t is arg for t, exempt, _ in literals if exempt):
                printed = True
                report(arg, f"print, printf or println prints the literal "
                       f"{show(arg.text)} as a value (L3)")
        if prints and url_path_print(pipeline) and not in_url_attr(index):
            printed = True
            report(tokens[0], f"the action prints the path {show(tokens[0].text)} as "
                   "text; a path piped into relURL or absURL may only start the value "
                   "of an href, src or action attribute (L3)")
        first = pipeline.commands[0] if pipeline.commands else []
        if (prints and not pipeline.declared and not printed and first
                and command_head(first) not in LITERALS_MESSAGE_FUNCS
                and not url_path_print(pipeline) and literal_only(pipeline)):
            report(first[0], "the action prints a value computed from literals alone "
                   "(`upper \"free\"`, `cond true \"a\" \"b\"`), which is fixed copy (L3)")
        for t, problem in value_problems(pipeline):
            report(t, problem)
        for t, problem in compare_only_problems(pipeline):
            report(t, problem)
        for t, problem in group_assign_problems(pipeline):
            report(t, problem)
        for t, problem in partial_problems(pipeline, root):
            report(t, problem)
        for t, problem in copy_source_problems(rel, tokens, literals, css):
            report(t, problem, fix=False)
        keywords = []
        for t in tokens:
            if not (t.kind == "word" and (t.text in LITERALS_CONTROL or t.text == "return")):
                break
            keywords.append(t.text)
        # The closed-world rules (fix round 2, review2 1, A3, A5).
        if not css:
            for command, t, problem in position_problems(rel, pipeline, binds, keywords):
                head = command_head(command)
                if not (head and banned_function(head)):
                    report_new(t, problem)  # a banned function: one finding
        for t in printf_formats(pipeline):
            for _, problem in verb_problems(t):
                report_new(t, problem)
        for t, exempt, _ in literals:
            if exempt:
                continue
            for _, problem in amp_problems(t):
                report_new(t, problem)
            value = html.unescape(t.text)
            if RAWTEXT_LITERAL.search(value):
                report_new(t, f"the literal {show(t.text)} opens a raw-text element "
                           "(LITERALS_RAWTEXT_ELEMENTS), whose markup the browser shows "
                           "as text; fails closed (L6, review3 5)")
            if DATA_URL.search(value):
                report_new(t, f"the literal {show(t.text)} holds a data: URL, which can "
                           "embed an image or document that draws text no check reads; "
                           "fails closed (L6)")
            bad = symbol_problems(value)
            if bad:
                report_new(t, f"the literal {show(t.text)} holds non-ASCII symbols that "
                           f"are not on LITERALS_SYMBOLS ({bad}) (L3)")
        # Fix round 3 (review3 3, 4, 6).
        if rel in LITERALS_LABELS_READERS and any(x.kind == "assign" for x in tokens):
            form = token_form(tokens)
            if form not in LITERALS_LABEL_ASSIGNS:
                report_new(tokens[0], f"{rel} assigns `{form}`, which is not one of its "
                           "forms on LITERALS_LABEL_ASSIGNS; `return $v` must return a "
                           "value of data/labels.toml (L4, review3 4)")
        for x in tokens:
            if x.kind != "word":
                continue
            if re.search(r"\.Content(?![\w])", x.text):
                if x.text != ".Content" or not x.space_before:
                    report_new(x, f"{x.text}: .Content only as the bare `.Content` of "
                               "the page; on a resource it prints the raw file, comments "
                               "included (L4, review3 3)")
                elif rel == "layouts/baseof.html":
                    report_new(x, ".Content: none in baseof.html, where the dot of a "
                               "`with` can be a resource (L4, review3 3)")
            if any(m.group(1) == "Params" and m.group(2) == "csp"
                   for m in SITE_CHAIN.finditer(x.text)) and not (
                    rel == "layouts/baseof.html" and len(tokens) == 1
                    and x.text == "site.Params.csp"
                    and text[:start].endswith(CSP_META_OPEN)
                    and text[end:].startswith('">')):
                report_new(x, f"{x.text}: params.csp only as the whole action `{{{{ "
                           "site.Params.csp }}` that fills the content of baseof.html's "
                           f"{CSP_META_OPEN}\"> (L4, review3 6)")
        for command in pipeline_commands(pipeline):
            # A built resource never takes a script name (reported even when
            # the literal has another finding, so each listed function and
            # each suffix shows on its own).
            if command_head(command) in LITERALS_RESOURCE_TARGETS and len(command) > 1 \
                    and isinstance(command[1], Token) and command[1].kind == "str" \
                    and ascii_lower(command[1].text).endswith(tuple(JS_SUFFIXES)):
                report(command[1], f"{command_head(command)} names the resource it "
                           f"builds {show(command[1].text)}, a script: the served script "
                           "comes only from resources.Get of a script pinned in "
                           "SCRIPT_SHA256, so no resource built from another asset, a "
                           "template or a string takes a script name "
                           "(LITERALS_RESOURCE_TARGETS, L3, #31 delta review 4)", fix=False)
            # The listed resources.* functions; any other one fails as unlisted.
            if (command_head(command) or "").startswith("resources.") \
                    and command_head(command) in LITERALS_FUNCTIONS:
                for problem in resource_operand_problems(command):
                    report_new(*problem)
        if rel == "layouts/baseof.html":
            # Every block, template and partial (label partials aside) takes
            # the page, the bare dot, outside with and range: a resource
            # never becomes another template's dot (review3 3).
            kw = keywords[0] if keywords else None
            calls = []
            if kw in ("block", "template") and pipeline.commands and pipeline.commands[0]:
                command = pipeline.commands[0]
                calls.append((tokens[0], command[1] if len(command) > 1 else None))
            for command in pipeline_commands(pipeline):
                if command_head(command) in LITERALS_PARTIAL_FUNCS \
                        and not label_partial_call(command):
                    calls.append((command[0], command[2] if len(command) > 2 else None))
            for at, ctx in calls:
                if not (isinstance(ctx, Token) and ctx.kind == "word" and ctx.text == ".") \
                        or any(s in ("with", "range") for s in scope):
                    report_new(at, "in baseof.html every block, template and partial "
                               "takes the bare `.` (the page), outside with and range, "
                               "so a resource never becomes its dot (L4, review3 3)")
            if kw in ("with", "range", "if", "define", "block"):
                scope.append(kw)
            elif kw == "end" and scope:
                scope.pop()
        # label.html and label-list.html return labels and nothing else, so
        # the label key a call hands them (a quiet position) never prints.
        if (rel in LITERALS_LABELS_READERS and prints and not pipeline.declared
                and not (first and command_head(first) in LITERALS_MESSAGE_FUNCS)
                and not (keywords == ["return"] and len(tokens) == 2
                         and tokens[1].kind == "word" and tokens[1].text == "$v")):
            report_new(tokens[0], f"{rel} may print nothing but `return $v` (a value "
                       "of data/labels.toml), so the label key a call passes never "
                       "reaches the page (L4)")
    if markup:
        markup_page_problems(rel, bare, findings, holes)
    if record is not None:
        record["actions"] = actions
        record["flagged"] = {i for i, (start, end, _, _) in enumerate(actions)
                             if any(start <= offset < end for offset in flagged)}
    return bare, holes


def markup_page_problems(rel, bare, findings, holes=()):
    """L1, L2 and the markup forms of L6 on a file read as HTML."""
    forms, normalised = markup_form_problems(bare, Path(rel).suffix.lower() in HTML_SUFFIXES,
                                             holes, rel)
    for offset, problem in forms:
        findings.add(f"{rel}:{line_of(bare, offset)}", problem)
    page = LiteralsPage()
    page.feed(normalised)
    page.close()
    for line, problem in page.problems:
        findings.add(f"{rel}:{line}", f"{problem}; {LITERALS_FIX}")


# L6: comment and marked-section forms that browsers and Python versions
# read differently (html.parser changed its comment rules in 3.13 and 3.14,
# and CI's python3 is the runner's). They fail closed, and are rewritten to
# the form a browser reads before html.parser sees them: `<!-->` and
# `<!--->` are empty comments, `--!>` ends one.
ABRUPT_COMMENT = re.compile(r"<!---?>")


# review7 A1: the end tag of a script, a style or a raw-text element of
# LITERALS_RAWTEXT_ELEMENTS. A browser ends the element at `</name` before
# whitespace, `/` or `>` (`</style x>`, `</style/>`); html.parser before the
# 2025 HTML5 tag fix (vanilla CPython 3.12.3) ends script and style only at
# `</` + optional Unicode whitespace + name (Unicode case folding) + optional
# Unicode whitespace + `>`, and stays in script or style to the end of the
# file otherwise. Every such end tag but the name plus optional ASCII
# whitespace before `>` fails closed, and is rewritten to `</name>` before
# html.parser sees it. A Unicode-case spelling (`</ſtyle>`) is rewritten to
# itself: tag names count in ASCII case only, so it is no end tag of a
# style, and the file fails here on it. The pattern is
# wider than the browser (leading whitespace, Unicode case and whitespace),
# so it also takes the end tags only the old html.parser ends at.
RAWTEXT_END_TAG = re.compile(r"</\s*(%s)(?=[\s/>]|\Z)[^>]*+>?" % "|".join(
    ("script", "style") + LITERALS_RAWTEXT_ELEMENTS), re.I)
RAWTEXT_END_TAG_PLAIN = re.compile(r"</(%s)[\t\n\f\r ]*>" % "|".join(
    ("script", "style") + LITERALS_RAWTEXT_ELEMENTS), re.I | re.A)


def rawtext_end_tags(text):
    """(offset, name, token) for every end tag of RAWTEXT_END_TAG that is not
    the name plus optional ASCII whitespace before `>`."""
    for match in RAWTEXT_END_TAG.finditer(text):
        if not RAWTEXT_END_TAG_PLAIN.fullmatch(match.group(0)):
            yield match.start(), match.group(1).lower(), match.group(0)


def plain_end_tag(name, token):
    """`</name>` for an end tag of rawtext_end_tags, padded with its newlines
    and spaces to its length where it is long enough, so line numbers stay."""
    plain = f"</{name.lower()}>" + "\n" * token.count("\n")
    return plain + " " * max(0, len(token) - len(plain))


def rawtext_end_tag_message(name, token):
    return (f"end tag {show(token)}: a {name} end tag may hold only its name and "
            "ASCII whitespace before '>'; browsers and html.parser versions end the "
            "element in different places, so what follows is read two ways; fails "
            "closed")


DOCTYPE = re.compile(r"(?i)<!doctype\b[^>]*>?")


def rawtext_spans(text, built=False):
    """(name, tag offset, content start, content end) for every raw-text
    element of LITERALS_RAWTEXT_ELEMENTS and every script and style, read as
    a browser reads it in HTML: HTML comments skipped, every other tag
    skipped whole with its attributes, the content running to `</name`
    before whitespace, `/` or `>`, or to the end of the file; plaintext never
    ends; script and style content skipped. This does not track svg and
    math, where script and style are markup (review5 A1): the callers fail
    every script or style whose content holds '<' (rule (i)) or read its
    text (L1). A script or style start tag that ends in `/>` comes out as
    `/script` or `/style` with an empty content (review5 1: both checks fail
    it closed). built: a built page, where bogus comments are skipped too."""
    pos = 0
    while True:
        match = RAWTEXT_SCAN.search(text, pos)
        if not match:
            return
        token = match.group(0)
        if token == "<!--":
            close = text.find("-->", match.end())
            pos = len(text) if close < 0 else close + 3
            continue
        if match.group(2) is None:  # a bogus comment opener
            if not built:
                pos = match.start() + 1
            else:
                close = text.find(">", match.start() + 2)
                pos = len(text) if close < 0 else close + 1
            continue
        pos = match.end()
        if match.group(1):  # an end tag: skipped whole
            continue
        name = match.group(2).translate(ASCII_LOWER)
        if name in LITERALS_RAWTEXT_ELEMENTS:
            end = len(text)
            if name != "plaintext":
                close = re.compile(r"</%s%s" % (name, TAG_END), re.I | re.A).search(text, pos)
                if close:
                    end = close.start()
            yield name, match.start(), pos, end
            pos = max(pos, end)
            continue
        if name in ("script", "style"):
            if token.endswith("/>"):
                yield "/" + name, match.start(), pos, pos
                continue
            close = re.compile(r"</%s%s" % (name, TAG_END), re.I | re.A).search(text, pos)
            end = len(text) if close is None else close.start()
            yield name, match.start(), pos, end
            pos = end

def rawtext_built_problems(text):
    """Site rule (i) on a built HTML page (review3 5): no '<' in the text of a
    <title> or <textarea> once entities are decoded, because markup there
    shows as text, and none of the obsolete raw-text elements. Read with a
    pattern, not html.parser, whose reading changed after CPython 3.12.3.
    review4 1: any '<!--' fails closed, because browsers end a comment at
    `-->`, `--!>`, `<!-->` or `<!--->` and read one inside a script in its
    own way (the minifier leaves none); a <noscript> holding '<' fails
    closed, because a browser without scripting reads its content as
    markup. review5 1: a self-closed script or style fails closed. review5
    A1: so does a script or style whose content holds '<': inside svg or
    math a browser reads that content as markup, and this check does not
    track svg and math, so it fails wherever the element is; for the same
    reason any `<![CDATA[` fails (the minifier leaves none). review7 A1: an
    end tag of RAWTEXT_END_TAG that is more than its name and ASCII
    whitespace, and a script or style without an end tag, fail closed:
    html.parser before the 2025 HTML5 tag fix reads past them to the end of
    the page (the minifier writes neither)."""
    problems = []
    if "<!--" in text:
        problems.append("(i) '<!--': a comment opener in a built page; browsers "
                        "and this check could end it in different places, so it "
                        "fails closed")
    if "<![CDATA[" in text:
        problems.append("(i) '<![CDATA[': text to ']]>' inside svg or math and a "
                        "comment to '>' elsewhere, so this check and a browser could "
                        "read what follows differently; fails closed")
    for _, name, token in rawtext_end_tags(text):
        problems.append(f"(i) {rawtext_end_tag_message(name, token)} (review7 A1)")
    if any(name in ("script", "style") and end == len(text)
           for name, _, _, end in rawtext_spans(text, built=True)):
        problems.append("(i) an unterminated <script> or <style>: html.parser versions "
                        "read its content to the end of the file differently; fails "
                        "closed (review7 A1)")
    for name, tag, start, end in rawtext_spans(text, built=True):
        if name.startswith("/"):
            problems.append(f"(i) <{name[1:]}/>: a self-closed {name[1:]}, raw text in "
                            "HTML but markup inside <svg>; fails closed")
        elif name in ("script", "style"):
            if "<" in text[start:end]:
                problems.append(f"(i) <{name}> content holds '<': markup to a browser "
                                "inside svg or math, which this check does not track; "
                                "fails closed")
        elif name in ("title", "textarea", "noscript", "iframe"):
            if "<" in html.unescape(text[start:end]):
                problems.append(f"(i) <{name}> text holds '<': markup there shows as "
                                "text" + (" or, without scripting, is read as markup"
                                          if name == "noscript" else ""))
        elif name in ("xmp", "plaintext", "noembed", "noframes"):
            problems.append(f"(i) <{name}>: an obsolete raw-text element, whose "
                            "markup shows as text")
    return problems


def markup_form_problems(bare, html_page=True, holes=(), rel=""):
    """([(offset, message)], text normalised as a browser reads it).
    html_page: an HTML file, where `<!doctype html>` is the one DOCTYPE.
    holes: the offsets of the blanked actions; rel: the file."""
    problems = []
    # review7 A1: every end tag of a script, a style or a raw-text element
    # that is more than its name and ASCII whitespace fails closed and is
    # rewritten to `</name>` (its newlines kept after it) before anything
    # else reads the file, so the old and the patched html.parser end the
    # element at the same place.
    for offset, name, token in rawtext_end_tags(bare):
        problems.append((offset, rawtext_end_tag_message(name, token) + " (L6, review7 A1)"))
    bare = RAWTEXT_END_TAG.sub(lambda m: m.group(0) if RAWTEXT_END_TAG_PLAIN.fullmatch(
        m.group(0)) else plain_end_tag(m.group(1), m.group(0)), bare)
    # An internal DTD subset declares entities that an XML parser (an SVG or
    # XML file opened on its own) expands into text, while html.parser keeps
    # it inside the declaration: any DOCTYPE but the HTML one and any
    # <!ENTITY fail closed (review2 4).
    for match in DOCTYPE.finditer(bare):
        # review5 A3: HTML whitespace and ASCII case only, as the tokenizer
        # reads it (a no-break space makes another DOCTYPE name).
        if not (html_page and re.fullmatch(r"<!doctype[\t\n\f\r ]+html[\t\n\f\r ]*>",
                                           match.group(0), re.I | re.A)):
            problems.append((match.start(), f"DOCTYPE {show(match.group(0))}: only "
                             "`<!doctype html>` in an HTML file; any other, an internal "
                             "subset above all, can declare entities an XML parser "
                             "expands into text this check never reads; fails closed "
                             "(L6)"))
    # Raw-text elements (review3 5), read by this check, not by html.parser,
    # whose reading of title and textarea changed after CPython 3.12.3. A
    # flagged content is blanked before the parse, so the findings do not
    # depend on the runner's Python either.
    blank, closed = [], []
    for name, tag, start, end in rawtext_spans(bare):
        if name in ("script", "style"):
            continue  # L1 reads their text
        if name.startswith("/"):
            closed.append(start - 2)
            problems.append((tag, f"<{name[1:]}/>: a self-closed {name[1:]} is raw text "
                             "in HTML but markup inside <svg>, so what follows is read "
                             "two ways; fails closed (L6, review5 1)"))
        elif name == "plaintext":
            blank.append((start, end))
            problems.append((tag, "<plaintext>: everything after it is text to the "
                             "browser, to the end of the file; fails closed (L6, "
                             "review3 5)"))
        elif "<" in bare[start:end]:
            blank.append((start, end))
            problems.append((tag, f"<{name}> holds '<': its content is text to the "
                             "browser, so markup there shows as text, and html.parser "
                             "versions read it differently; fails closed (L6, review3 5)"))
        elif any(start <= h < end for h in holes) and not (
                rel == "layouts/baseof.html" and name == "title"):
            problems.append((tag, f"<{name}> holds a template action: whatever it "
                             "prints, markup included, shows as text; only the <title> "
                             "of baseof.html holds one (L6, review3 5)"))
    for match in re.finditer(r"(?i)<!entity", bare):
        problems.append((match.start(), "an <!ENTITY declaration: an XML parser expands "
                         "it into text this check never reads; fails closed (L6)"))
    for match in ABRUPT_COMMENT.finditer(bare):
        problems.append((match.start(), f"abrupt comment {match.group(0)!r}: browsers "
                         "end the comment there, older html.parser versions do not; "
                         "fails closed (L6)"))
    for match in re.finditer(r"--!>", bare):
        problems.append((match.start(), "'--!>' ends a comment in browsers but not in "
                         "every html.parser version; fails closed (L6)"))
    for match in re.finditer(r"<!\[", bare):
        problems.append((match.start(), "marked section '<![' (CDATA): browsers and "
                         "html.parser versions read its text differently, and Hugo's "
                         "minifier can print it; fails closed (L6)"))
    read = bare
    for start, end in blank:
        read = read[:start] + re.sub(r"[^\n]", " ", read[start:end]) + read[end:]
    # A self-closed script or style (failed above) gets a space before its
    # `/>`: html.parser before the 2025 fix reads `<style x=a/>` as
    # self-closed, later ones as `x="a/"` and a style. html.parser 3.14.8
    # reads `<style x=a />` as self-closed, but `<script x= />` as a script
    # start tag with x="/" and what follows as script text (review 9 A3);
    # vanilla 3.12.3 reads it differently, and the findings of such a file
    # can differ between the two. The file already fails above.
    for offset in sorted(closed, reverse=True):
        read = read[:offset] + " " + read[offset:]
    # A script or style with no end tag: html.parser before the 2025 fix
    # drops its content at the end of the file, later ones read it as text.
    # It fails closed, and the end tag is added, so L1 reads the content.
    for name, tag, start, end in rawtext_spans(read):
        if name in ("script", "style") and end == len(read):
            problems.append((tag, f"unterminated <{name}>: html.parser versions read "
                             "its content to the end of the file differently; fails "
                             "closed (L6, review7 A1)"))
            read += f"</{name}>"
            break
    text = ABRUPT_COMMENT.sub("<!---->", read).replace("--!>", "-->")
    pos = 0
    while True:
        start = text.find("<!--", pos)
        if start < 0:
            break
        end = text.find("-->", start + 4)
        if end < 0:
            problems.append((start, "unterminated HTML comment: what follows it is "
                             "read differently by browsers and html.parser; fails "
                             "closed (L6)"))
            # Blanked, so html.parser never reads it (vanilla CPython
            # 3.12.3 reads it as text).
            text = text[:start] + re.sub(r"[^\n]", " ", text[start:])
            break
        pos = end + 3
    return problems, text


# L3 print sinks (M3 PR 9, #29 Known limit 1, ADR-0004 part 13). The
# closed world above decides where a literal may sit; it does not follow a
# value to the place it prints, so a never-copy shape, a listed token
# (a collection value, a dict key, an icon or resource name), true or false
# and the words Hugo writes for a value (.Kind, %T, a date with its zone)
# could still reach the page text. Here every action is parsed with a marker,
# so the check knows the sink it prints into: the page text, a visible
# attribute (L2's list, the content of a description meta, the attributes
# copy.js shows), a non-text attribute, a comment, an element name or a
# JSON data block. Then the templates are run abstractly from the page
# templates down every partial call, with the dot, every variable and
# every partial result as a set of value kinds, and an action that prints
# into the page text or a visible attribute may print only from the listed
# sources (LITERALS_PRINT_SOURCES): a label partial, the output of a
# partial that prints (its own text is checked in its own file), a content
# field, site.Title, site.Params.operator or .contact, a date in the pinned
# layout, and printf, htmlEscape, safeHTML, default, cond, and and or over
# those. Everything else is a finding wherever it reaches text.
#
# The value kinds (a value is a frozenset of them):
#   label             a string of data/labels.toml (label.html)
#   content           a content field: front matter, title, body, a file name
#   config            site.Title, site.Params.operator, site.Params.contact
#   date              a date formatted with the pinned layout
#   output            what a partial without return prints
#   markup            a literal of markup without text, through safeHTML
#   formatted         printf of listed sources with a format without tags
#   formatted-markup  the same with tags, through safeHTML
#   empty             the empty string, nothing
#   and the kinds no text sink takes: ("lit", text) a template literal,
#   markup-raw and formatted-markup-raw (markup not through safeHTML, which
#   Hugo escapes into visible tags), escaped-markup, ("bool", b), number,
#   nil, runtime (a word Hugo writes: .Kind, .Section, %T, a time, a
#   resource name), url, json, csp, tokens, integrity, page, params, site,
#   file, time, resource, label-entry, ("dict", items), ("list", value)
#   and unknown (anything the analysis cannot follow, which fails closed).
#   flagged is a value an action with a finding of the rules above computed
#   (a bound literal, a range over a listed set): where it prints, the
#   finding is already there, so it is not reported twice (one defect, one
#   finding).
LITERALS_PRINT_SOURCES = {
    "text": frozenset({"label", "content", "config", "date", "output", "markup",
                       "formatted", "formatted-markup", "empty"}),
    "visible": frozenset({"label", "content", "config", "date", "formatted", "empty"}),
}
SINK_REPORTED = frozenset({"flagged"})  # already a finding where it was computed
# Every value kind of the analysis (the list above; a tuple shape by its
# first item). A printed value of any other kind fails closed, so a new kind
# is registered here, and the self-test then needs a row for it: one
# literals-members row per kind the page text rejects (M3 PR 9 fix round 1,
# QA), so a kind added to LITERALS_PRINT_SOURCES["text"] turns a row red.
SINK_KINDS = frozenset({
    "label", "content", "config", "date", "output", "markup", "formatted",
    "formatted-markup", "empty", "lit", "markup-raw", "formatted-markup-raw",
    "escaped-markup", "bool", "number", "nil", "runtime", "url", "json", "csp",
    "tokens", "integrity", "page", "params", "site", "hugo", "file", "time",
    "resource", "resource-data", "siteparams", "hugodata", "label-entry", "dict",
    "list", "unknown", "flagged"})
# The JSON-LD keys whose values search results show as text: in a
# `<script type="application/ld+json">` block they take only what a
# visible attribute takes, or null. render rule 8 pins every other value of
# a JSON-LD block (types, keys, URLs, dates, positions), and rule 12 pins
# every field of /feed.json against the records, so the `.json` layout
# needs no key rule.
LITERALS_DATA_TEXT_KEYS = frozenset({"name", "description"})
# T2 (M3 PR 10, ADR-0004 part 13): the only form of a define and block
# name. No `/` or `.`, so Hugo cannot resolve the name by path (an inline
# partial `define "_partials/x.html"` runs at `partial "x.html"`); ASCII
# only, so no case fold or look-alike can map it to another name.
LITERALS_TEMPLATE_NAME = re.compile(r"[a-z][a-z0-9_-]*", re.A)
SINK_MARK = 0xF0000  # supplementary private use area A: one character per action
SINK_MARKS = re.compile("[\U000F0000-\U000FFFFD]")
SINK_TAG_OPEN = re.compile("<(/?)(?=[\U000F0000-\U000FFFFD])")
SINK_TAG_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
# The parse state of plain page text (SinkPage), and the elements whose
# content a browser does not read as markup: inside one, a define's call
# site sees only the end tag of that element (script and style also have
# their own JavaScript and CSS states, which this reading does not follow).
SINK_PLAIN = ("data", None)
SINK_RAW_ELEMENTS = frozenset(("script", "style") + LITERALS_RAWTEXT_ELEMENTS)
GO_TRIM_SPACE = (" ", "\t", "\r", "\n")
SINK_WHERE = {"text": "the page text", "visible": "a visible attribute",
              "data": "a JSON data block", "tag": "an element name"}


def sink_kind(tag, name, attrs):
    """The sink of an attribute value: visible, plain (never shown) or text
    for an attribute name nobody listed (fails closed)."""
    first = {}
    for key, value in attrs:
        first.setdefault(key, value)
    if name in LITERALS_TEXT_ATTRS or name in LITERALS_SCRIPT_TEXT_ATTRS:
        return "visible"
    if name == "content" and tag == "meta":
        return "plain" if meta_content_plain(tag, first) else "visible"
    if name.startswith("data-") or name in LITERALS_PLAIN_ATTRS:
        return "plain"
    return "visible"


class SinkPage(html.parser.HTMLParser):
    """Where each marker (one per action) sits in a file read as HTML, and
    the parse state there (SINK_PLAIN, the open raw-text element or the one
    attribute value; None for a tag or attribute name, a comment or a
    declaration), so a define's end can be compared with its start."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.sinks = {}  # marker index -> (kind, where)
        self.states = {}  # marker index -> parse state
        self.raw = None  # the open script or style element: (tag, attrs)
        self.inside = None  # the open script, style or raw-text element: (tag, position)

    def _mark(self, text, kind, where, state=None):
        for match in SINK_MARKS.finditer(text or ""):
            self.sinks.setdefault(ord(match.group(0)) - SINK_MARK, (kind, where))
            self.states.setdefault(ord(match.group(0)) - SINK_MARK, state)

    def _tag(self, tag, attrs):
        self._mark(tag, "tag", "an element name")
        at = self.getpos()
        for i, (name, value) in enumerate(attrs):
            self._mark(name, "text", "an attribute name")
            if value is not None:
                self._mark(value, sink_kind(tag, name, attrs), f"the attribute {name}",
                           ("attr", at, i))

    def handle_starttag(self, tag, attrs):
        self._tag(tag, attrs)
        if tag in ("script", "style"):
            self.raw = (tag, dict((k, v or "") for k, v in attrs))
        if self.inside is None and tag in SINK_RAW_ELEMENTS:
            self.inside = (tag, self.getpos())

    def handle_startendtag(self, tag, attrs):
        self._tag(tag, attrs)

    def handle_endtag(self, tag):
        self._mark(tag, "tag", "an element name")
        if self.raw and tag == self.raw[0]:
            self.raw = None
        if self.inside and tag == self.inside[0]:
            self.inside = None

    def handle_data(self, data):
        state = ("data", self.inside)
        if self.raw and self.raw[0] == "script" \
                and self.raw[1].get("type", "").strip().lower() == JSON_LD:
            self._mark(data, "data", "a JSON-LD block", state)
        else:
            self._mark(data, "text", "the page text", state)

    def handle_comment(self, data):
        self._mark(data, "comment", "a comment")

    def handle_decl(self, decl):
        self._mark(decl, "text", "a declaration")

    def unknown_decl(self, data):
        self._mark(data, "text", "a declaration")

    def handle_pi(self, data):
        self._mark(data, "text", "a processing instruction")


def marked_sinks(text, count, states=None):
    """{index: (kind, where)} for count markers in text read as HTML; a
    marker right after `<` or `</` is read as an element name. A marker the
    parse never reaches is a text sink (fails closed), and its state, which
    states (a dict, if given) receives per marker, is None."""
    page = SinkPage()
    page.feed(SINK_TAG_OPEN.sub(lambda m: "<" + m.group(1) + "x", text))
    page.close()
    if states is not None:
        states.update({i: page.states.get(i) for i in range(count)})
    return {i: page.sinks.get(i, ("text", "the page text")) for i in range(count)}


def action_sinks(rel, text, actions, states=None):
    """{action index: (kind, where)} for the actions of one template; states
    (a dict, if given) receives the parse state at each action. A JSON or
    text layout has no markup context: its state is SINK_PLAIN throughout."""
    suffix = Path(rel).suffix.lower()
    if suffix == ".json" or (suffix not in MARKUP_SUFFIXES and suffix != ".htm"):
        if states is not None:
            states.update({i: SINK_PLAIN for i in range(len(actions))})
        if suffix == ".json":
            return {i: ("data", "a JSON layout") for i in range(len(actions))}
        return {i: ("text", "a text layout") for i in range(len(actions))}
    out, pos = [], 0
    for i, (start, end, _, _) in enumerate(actions):
        out.append(text[pos:start])
        out.append(chr(SINK_MARK + i))
        pos = end
    out.append(text[pos:])
    return marked_sinks("".join(out), len(actions), states)


def state_where(state, kind, where):
    """The place of a parse state for a message: the sink's own words, but a
    script, a style or a raw-text element by its name (their text is a page
    text sink, the strictest, which says nothing about the context)."""
    if kind == "text" and state is not None and state[0] == "data" and state[1]:
        return f"a {state[1][0]} element"
    return where


def body_text(text, actions, first, last):
    """The template text of a define or block body: what it writes between
    its own action (first) and its end (last) besides its actions, with the
    trim markers applied (`{{- ` and ` -}}` drop the ASCII whitespace next
    to them, as Go does)."""
    parts = []
    for i in range(first, last):
        segment = text[actions[i][1]:actions[i + 1][0]]
        if text[actions[i][1] - 3:actions[i][1]] == "-}}" \
                and text[actions[i][1] - 4:actions[i][1] - 3] in GO_TRIM_SPACE:
            segment = segment.lstrip("".join(GO_TRIM_SPACE))
        if text.startswith("{{-", actions[i + 1][0]) \
                and text[actions[i + 1][0] + 3:actions[i + 1][0] + 4] in GO_TRIM_SPACE:
            segment = segment.rstrip("".join(GO_TRIM_SPACE))
        parts.append(segment)
    return "".join(parts)


def printf_sinks(fmt):
    """The sink of each verb of a literal printf format (`%%` aside), read as
    an HTML fragment, and whether the format holds a tag."""
    verbs = [m for m in PRINTF_VERB.finditer(fmt) if m.group(0) != "%%"]
    out, pos = [], 0
    for i, match in enumerate(verbs):
        out.append(fmt[pos:match.start()])
        out.append(chr(SINK_MARK + i))
        pos = match.end()
    out.append(fmt[pos:])
    sinks = marked_sinks("".join(out), len(verbs))
    return [(verbs[i].group(0), sinks[i]) for i in range(len(verbs))], "<" in fmt


def kinds(*shapes):
    return frozenset(shapes)


UNKNOWN, NIL, EMPTY = kinds("unknown"), kinds("nil"), kinds("empty")
PAGE_LIST = ("list", kinds("page"))
# The page members a template may read (LITERALS_MEMBERS) and their value
# kinds; any other member is unknown. `.Summary` and `.Site` are not on
# LITERALS_MEMBERS (L4 fails them), so they have no entry (M3 PR 9 fix
# round 1: every entry has a self-test row that its cut turns red).
PAGE_MEMBERS = {"Title": "content", "Description": "content", "Content": "content",
                "Params": "params", "Permalink": "url",
                "RelPermalink": "url", "Path": "url", "Date": "time", "Kind": "runtime",
                "Section": "runtime", "File": "file", "RegularPages": PAGE_LIST,
                "Pages": PAGE_LIST, "Sections": PAGE_LIST, "Home": "page",
                "GetPage": "page"}
SITE_MEMBERS = {"Title": "config", "Params": "siteparams", "Home": "page",
                "RegularPages": PAGE_LIST, "Pages": PAGE_LIST, "Sections": PAGE_LIST,
                "GetPage": "page"}
MARKUP_KINDS = {"markup", "markup-raw", "output", "formatted-markup",
                "formatted-markup-raw"}
FALSY = {"nil", "empty", ("bool", False)}


def join(*values):
    """The union of value kinds, with every list shape merged into one and
    dicts of the same keys merged key by key."""
    shapes, lists, dicts = set(), [], {}
    for value in values:
        for s in value:
            if isinstance(s, tuple) and s[0] == "list":
                lists.append(s[1])
            elif isinstance(s, tuple) and s[0] == "dict":
                dicts.setdefault(frozenset(k for k, _ in s[1]), []).append(dict(s[1]))
            else:
                shapes.add(s)
    if lists:
        shapes.add(("list", join(*lists)))
    for keys, items in dicts.items():
        shapes.add(("dict", frozenset((k, join(*(d[k] for d in items))) for k in keys)))
    return frozenset(shapes)


def truth(value):
    """True, False or None (either) for a value used as a condition. A
    branch is pruned only on a literal bool, nil or the empty string (M3 PR 9
    fix round 1, review 2): a partial's output, a label, a page or a
    non-empty literal decide nothing here, because a partial that prints
    nothing returns "" at build time, which is false, and pruning on a guess
    drops the path Hugo then runs."""
    if not value:
        return None
    if all(s in FALSY for s in value):
        return False
    if all(s == ("bool", True) for s in value):
        return True
    return None


def truthy(value):
    return frozenset(s for s in value if s not in FALSY) or value


def field_of(shape, name):
    """The value of one field or niladic method of one value shape."""
    if isinstance(shape, tuple):
        if shape[0] == "dict":
            # A computed key ("*") can be any name at build time, the one
            # looked up included.
            items = dict(shape[1])
            if "*" in items:
                return join(items["*"], items.get(name, frozenset()))
            return items.get(name, NIL)
        if shape[0] == "list" and name in ("ByDate", "Reverse"):
            return kinds(shape)
        return UNKNOWN
    table = {"page": PAGE_MEMBERS, "site": SITE_MEMBERS}.get(shape)
    if table is not None:
        got = table.get(name, "unknown")
        return kinds(got)
    if shape in ("params", "content", "file"):
        return kinds("content")
    if shape == "siteparams":
        return kinds({"operator": "config", "contact": "config", "csp": "csp"}.get(
            name, "unknown"))
    if shape == "hugo":
        return kinds("hugodata" if name == "Data" else "unknown")
    if shape == "hugodata":
        return kinds({"tokens": "tokens"}.get(name, "unknown"))
    if shape == "tokens":
        return kinds("tokens")
    if shape == "label-entry":
        return kinds("label")
    if shape == "resource":
        return kinds({"RelPermalink": "url", "Permalink": "url",
                      "Data": "resource-data"}.get(name, "runtime"))
    if shape == "resource-data":
        return kinds("integrity" if name == "Integrity" else "runtime")
    if shape == "time":
        return kinds("runtime")
    if shape == "nil":
        return NIL
    if shape == "flagged":
        return kinds("flagged")
    return UNKNOWN


def field(value, name):
    return join(*(field_of(s, name) for s in value)) if value else value


def element(value):
    """The value of one element a range over value or index into it gives."""
    out = []
    for s in value:
        if isinstance(s, tuple) and s[0] == "list":
            out.append(s[1])
        elif isinstance(s, tuple) and s[0] == "dict":
            out.extend(v for _, v in s[1])
        elif s in ("params", "content"):
            out.append(kinds("content"))
        elif s in ("tokens", "flagged"):
            out.append(kinds(s))
        elif s in ("nil", "empty"):
            continue
        else:
            out.append(UNKNOWN)
    return join(*out)


def range_keys(value):
    out = []
    for s in value:
        if isinstance(s, tuple) and s[0] == "list":
            out.append(kinds("number"))
        elif isinstance(s, tuple) and s[0] == "dict":
            out.append(frozenset(("lit", k) if k != "*" else "unknown" for k, _ in s[1]))
        elif s in ("params", "content"):
            out.append(kinds("content"))
        elif s == "flagged":
            out.append(kinds("flagged"))
        elif s in ("nil", "empty"):
            continue
        else:
            out.append(UNKNOWN)
    return join(*out)


def literal_kind(text):
    """A string literal as a value: empty, markup without text, or itself."""
    if text == "":
        return EMPTY
    if LITERALS_TAG.search(text) and not literal_remainder(text).strip():
        return kinds("markup-raw")
    return kinds(("lit", text))


def map_kinds(value, table):
    return frozenset(table.get(s, s) if isinstance(s, str) else s for s in value)


ESCAPE = {k: "escaped-markup" for k in MARKUP_KINDS}
SAFE_HTML = {"markup-raw": "markup", "formatted-markup-raw": "formatted-markup"}


def describe(shape):
    """A value kind in a finding."""
    if isinstance(shape, tuple):
        if shape[0] == "lit":
            return f"the literal {show(shape[1])}"
        if shape[0] == "bool":
            return "a bool (true or false)"
        return f"a {shape[0]}"
    return {"markup-raw": "markup that Hugo escapes into visible tags",
            "formatted-markup-raw": "printf markup that Hugo escapes into visible tags",
            "escaped-markup": "markup escaped into visible tags",
            "runtime": "a word Hugo writes for a value (.Kind, .Section, %T, a time, a "
                       "resource)",
            "unknown": "a value this check cannot follow",
            "nil": "a missing value", "params": "the page's params (a map)",
            "url": "a URL", "integrity": "a resource's integrity hash",
            "json": "JSON", "csp": "the CSP", "tokens": "a design token",
            "label-entry": "a table of data/labels.toml",
            "output": "the output of a partial (markup)", "markup": "markup",
            "formatted-markup": "printf markup"}.get(shape, f"a {shape}")


class Piped:
    """The value a pipe hands to the next command as its last argument."""

    def __init__(self, value):
        self.value = value


class SinkState:
    def __init__(self, dot, env, top):
        self.dot, self.env, self.top = dot, env, top

    def copy(self, dot=None):
        return SinkState(self.dot if dot is None else dot, dict(self.env), self.top)


def join_env(*envs):
    keys = set().union(*envs)
    return {k: join(*(e[k] for e in envs if k in e)) for k in keys}


class SinkStep:
    def __init__(self, kind, index, tokens, pipeline=None, names=(), body=(),
                 branches=(), orelse=None, name=None, end=None):
        self.kind, self.index, self.tokens = kind, index, tokens
        self.pipeline, self.names = pipeline, names
        self.body, self.branches, self.orelse, self.name = body, branches, orelse, name
        self.end = end  # a define or block: the index of its end action


def bound_names(tokens):
    """The variables a with or range declares before its := (or =)."""
    names = []
    for t in tokens:
        if t.kind == "assign":
            return names
        if t.kind == "word" and t.text.startswith("$"):
            names.append(t.text)
    return []


def after_assign(tokens):
    for i, t in enumerate(tokens):
        if t.kind == "assign":
            return tokens[i + 1:]
    return tokens


def sink_tree(actions):
    """The actions of one template as a tree of if, with, range, define and
    block steps. Raises TemplateError on an unbalanced end or else."""
    items = [(i, tokens) for i, (_, _, tokens, comment) in enumerate(actions)
             if not comment and tokens]
    pos = 0

    def block(stop):
        nonlocal pos
        steps = []
        while pos < len(items):
            i, tokens = items[pos]
            head = tokens[0].text if tokens[0].kind == "word" else ""
            if head in stop:
                return steps
            pos += 1
            if head in ("if", "with", "range"):
                steps.append(conditional(head, i, tokens[1:]))
            elif head in ("define", "block"):
                name = tokens[1].text if len(tokens) > 1 and tokens[1].kind == "str" else None
                rest = parse_pipeline(tokens[2:])[0] if head == "block" else None
                body = block(("end",))
                end = items[pos][0] if pos < len(items) else None
                close()
                steps.append(SinkStep(head, i, tokens, rest, body=body, name=name,
                                      end=end))
            elif head == "template":
                name = tokens[1].text if len(tokens) > 1 and tokens[1].kind == "str" else None
                steps.append(SinkStep("template", i, tokens, parse_pipeline(tokens[2:])[0],
                                      name=name))
            elif head in ("end", "else"):
                raise TemplateError(head, 0)
            elif head in ("break", "continue"):
                continue
            elif head == "return":
                steps.append(SinkStep("return", i, tokens, parse_pipeline(tokens[1:])[0]))
            else:
                pipeline = parse_pipeline(tokens)[0]
                if pipeline.declared:
                    names = [t.text for t in tokens if t.kind == "word"
                             and t.text.startswith("$")][:1]
                    steps.append(SinkStep("assign", i, tokens,
                                          parse_pipeline(after_assign(tokens))[0], names))
                else:
                    steps.append(SinkStep("print", i, tokens, pipeline))
        if stop:
            raise TemplateError("end", 0)
        return steps

    def close():
        nonlocal pos
        if pos >= len(items) or items[pos][1][0].text != "end":
            raise TemplateError("end", 0)
        pos += 1

    def conditional(head, i, rest):
        nonlocal pos
        branches, at = [], i
        while True:
            names = bound_names(rest) if head in ("with", "range") else []
            pipeline = parse_pipeline(after_assign(rest) if names else rest)[0]
            body = block(("else", "end"))
            branches.append((head, pipeline, names, body, at))
            at, tokens = items[pos]
            pos += 1
            if tokens[0].text == "end":
                return SinkStep(branches[0][0], i, None, branches=branches, orelse=None)
            if len(tokens) > 1 and tokens[1].kind == "word" and tokens[1].text in ("if", "with") \
                    and branches[0][0] != "range":
                head, rest = tokens[1].text, tokens[2:]
                continue
            orelse = block(("end",))
            close()
            return SinkStep(branches[0][0], i, None, branches=branches, orelse=orelse)

    return block(())


class SinkAnalysis:
    """The abstract run of the templates (see the section comment)."""

    # The runs of a range body before it must settle (ADR-0004 Numbers): every
    # range of today's templates settles in at most 2.
    MAX_ROUNDS = 8

    def __init__(self, files):
        self.files = files  # rel -> {"text", "actions", "flagged", "tree", "sinks", "defines"}
        self.memo, self.running = {}, set()
        self.printed = {}  # (rel, index) -> value
        self.problems = []  # (rel, index, message) for analysis failures

    # -- values ---------------------------------------------------------
    def operand(self, op, st):
        if isinstance(op, Piped):
            return op.value
        if isinstance(op, Group):
            value = self.pipeline(op.pipeline, st)
            return self.chain(value, op.chain) if op.chain else value
        if op.kind == "str":
            return literal_kind(op.text)
        if op.kind != "word":
            return UNKNOWN
        word = op.text
        if word in ("true", "false"):
            return kinds(("bool", word == "true"))
        if word == "nil":
            return NIL
        if LITERALS_NUMBER.fullmatch(word):
            return kinds("number")
        if word.startswith((".", "$")) or word in ("site", "hugo") \
                or word.startswith(("site.", "hugo.")):
            return self.word(word, st)
        return self.call(word, [], st)

    def word(self, word, st):
        """A field chain: `.`, `.a.B`, `$`, `$x.y`, `site.Title`, `hugo.Data`."""
        if word == ".":
            return st.dot
        if word.startswith("."):
            return self.chain(st.dot, word)
        head, _, rest = word.partition(".")
        if head == "$":
            base = st.top
        elif head.startswith("$"):
            base = st.env.get(head, UNKNOWN)
        else:
            base = kinds(head)
        return self.chain(base, "." + rest) if rest else base

    def chain(self, value, text):
        for name in text.split(".")[1:]:
            value = field(value, name) if name else UNKNOWN
        return value

    def lit(self, op):
        return op.text if isinstance(op, Token) and op.kind == "str" else None

    def pipeline(self, pipeline, st):
        value = None
        for command in pipeline.commands:
            value = self.command(command, st, None if value is None else Piped(value))
        return UNKNOWN if value is None else value

    def command(self, command, st, piped):
        if not command:
            return UNKNOWN
        head, ops = command[0], list(command[1:]) + ([piped] if piped else [])
        if isinstance(head, Token) and head.kind == "word" and not (
                head.text.startswith((".", "$")) or head.text in ("site", "hugo", "true",
                                                                 "false", "nil")
                or head.text.startswith(("site.", "hugo."))
                or LITERALS_NUMBER.fullmatch(head.text)):
            return self.call(head.text, ops, st)
        if not ops:
            return self.operand(head, st)
        # A method with arguments on a chain (`.Date.Format "2006-01-02"`,
        # `site.GetPage "x"`): only Format and GetPage are read.
        if isinstance(head, Token) and head.kind == "word":
            base, _, method = head.text.rpartition(".")
            if method == "Format":
                layout = self.lit(ops[0])
                return kinds("date" if layout in LITERALS_DATE_LAYOUTS else "runtime")
            if method == "GetPage":
                return kinds("page")
        return UNKNOWN

    def call(self, fn, ops, st):
        ev = lambda op: self.operand(op, st)  # noqa: E731
        if fn in LITERALS_PARTIAL_FUNCS:
            name = self.lit(ops[0]) if ops else None
            if name == "label.html":
                return kinds("label")
            if name == "label-list.html":
                return kinds(("list", kinds("label-entry")))
            if name is None:
                return UNKNOWN
            return self.partial(name, ev(ops[1]) if len(ops) > 1 else NIL)
        if fn in ("printf", "fmt.Printf"):
            return self.printf(ops, st) if ops else UNKNOWN
        if fn == "htmlEscape":
            return map_kinds(ev(ops[-1]), ESCAPE) if ops else UNKNOWN
        if fn == "safeHTML":
            return map_kinds(ev(ops[-1]), SAFE_HTML) if ops else UNKNOWN
        if fn in ("safeJS", "safeCSS", "lower"):
            return ev(ops[-1]) if ops else UNKNOWN
        if fn == "jsonify":
            return kinds("json")
        if fn == "default":
            if len(ops) < 2:
                return UNKNOWN
            given = ev(ops[-1])
            return join(frozenset(s for s in given if s not in FALSY), ev(ops[0]))
        if fn == "cond":
            if len(ops) != 3:
                return UNKNOWN
            test = truth(ev(ops[0]))
            if test is True:
                return ev(ops[1])
            if test is False:
                return ev(ops[2])
            return join(ev(ops[1]), ev(ops[2]))
        if fn in ("and", "or"):
            values = [ev(op) for op in ops]
            for value in values:
                t = truth(value)
                if t is (fn == "or"):
                    return value
                if t is None:
                    return join(*values)
            return values[-1] if values else UNKNOWN
        if fn in LITERALS_COMPARE or fn in ("reflect.IsMap", "reflect.IsSlice"):
            return kinds(("bool", None))
        if fn == "time.Format":
            layout = self.lit(ops[0]) if ops else None
            return kinds("date" if layout in LITERALS_DATE_LAYOUTS else "runtime")
        if fn in ("index", "collections.Index"):
            if not ops:
                return UNKNOWN
            value = ev(ops[0])
            for key in ops[1:]:
                name = self.lit(key)
                value = field(value, name) if name is not None and all(
                    isinstance(s, tuple) and s[0] == "dict" for s in value) else element(value)
            return value
        if fn in ("where", "sort", "collections.Where", "collections.Sort"):
            value = ev(ops[0]) if ops else UNKNOWN
            return join(*(kinds(("list", element(kinds(s)))) if isinstance(s, tuple)
                          and s[0] == "dict" else kinds(s) for s in value)) if value else value
        if fn in ("first", "last", "after", "collections.First"):
            return ev(ops[-1]) if ops else UNKNOWN
        if fn in ("slice", "collections.Slice"):
            return kinds(("list", join(*(ev(op) for op in ops))))
        if fn in ("append", "collections.Append"):
            if not ops:
                return UNKNOWN
            return kinds(("list", join(element(ev(ops[-1])), *(ev(op) for op in ops[:-1]))))
        if fn in ("dict", "collections.Dictionary"):
            # One value per key (fix round 2, delta review 2): a repeated key
            # (L3 fails a literal one) and the computed keys ("*") join their
            # values, so no lookup depends on the order of a frozenset.
            items = {}
            for i in range(0, len(ops) - 1, 2):
                key = self.lit(ops[i])
                key = "*" if key is None else key
                items[key] = join(items.get(key, frozenset()), ev(ops[i + 1]))
            return kinds(("dict", frozenset(items.items())))
        if fn in ("merge", "collections.Merge"):
            values = [ev(op) for op in ops]
            dicts = [s for v in values for s in v if isinstance(s, tuple) and s[0] == "dict"]
            rest = [frozenset(s for s in v if not (isinstance(s, tuple) and s[0] == "dict"))
                    for v in values]
            merged = {}
            for d in dicts:
                for key, value in d[1]:
                    merged[key] = join(merged.get(key, frozenset()), value)
            out = join(*rest)
            return join(out, kinds(("dict", frozenset(merged.items())))) if dicts else out
        if fn in ("split", "strings.Split"):
            return kinds(("list", ev(ops[0]))) if ops else UNKNOWN
        if fn in ("int", "len", "add"):
            values = [ev(op) for op in ops]
            return kinds("content") if values and all(
                v and v <= {"content", "params"} for v in values) else kinds("number")
        if fn in LITERALS_URL_FUNCS:
            return kinds("url")
        if fn in LITERALS_COMPARE_ONLY:
            return kinds("runtime")
        if fn.startswith("resources."):
            return kinds("resource")
        if fn in LITERALS_MESSAGE_FUNCS:
            return EMPTY
        return UNKNOWN

    def data_value(self, pipeline, st):
        """The value a JSON data block action hands to jsonify (`$x | jsonify`
        or `jsonify $x`), or unknown."""
        commands = pipeline.commands
        for k in range(len(commands) - 1, -1, -1):
            if command_head(commands[k]) in ("jsonify", "encoding.Jsonify"):
                if len(commands[k]) > 1:
                    return self.operand(commands[k][-1], st)
                return self.pipeline(Pipeline(commands[:k], False), st) if k else UNKNOWN
        return UNKNOWN

    def printf(self, ops, st):
        """printf: every verb in the page text or a visible attribute of the
        format takes a listed source (or markup it builds), an element name a
        literal tag name; the result is formatted, or the kinds that broke
        it."""
        fmt, args = ops[0], ops[1:]
        text = self.lit(fmt)
        bad = []
        if text is not None:
            verbs, has_tags = printf_sinks(text)
        else:
            fmt_value = self.operand(fmt, st)
            if not fmt_value <= LITERALS_PRINT_SOURCES["visible"]:
                return frozenset(s for s in fmt_value
                                 if s not in LITERALS_PRINT_SOURCES["visible"])
            verbs, has_tags = [("%s", ("text", "the page text"))] * len(args), False
        markup = has_tags
        for i, (verb, (sink, _)) in enumerate(verbs):
            value = kinds("runtime") if verb == "%T" or i >= len(args) \
                else self.operand(args[i], st)
            if sink == "text":
                allowed = LITERALS_PRINT_SOURCES["text"] | SINK_REPORTED | {
                    "markup-raw", "formatted-markup-raw"}
            elif sink == "visible":
                allowed = LITERALS_PRINT_SOURCES["visible"] | SINK_REPORTED
            elif sink == "tag":
                bad.extend(s for s in value if s not in SINK_REPORTED and not (
                    isinstance(s, tuple) and s[0] == "lit" and SINK_TAG_NAME.fullmatch(s[1])))
                continue
            else:
                continue
            bad.extend(s for s in value if s not in allowed)
            markup = markup or bool(value & MARKUP_KINDS)
        if len(args) > len(verbs):
            bad.append("runtime")  # %!(EXTRA ...)
        if bad:
            return frozenset(bad)
        return kinds("formatted-markup-raw" if markup else "formatted")

    # -- statements -----------------------------------------------------
    def partial(self, name, ctx):
        rel = f"layouts/_partials/{name}"
        info = self.files.get(rel)
        if info is None or info.get("tree") is None:
            return UNKNOWN
        key = (rel, ctx)
        if key in self.memo:
            return self.memo[key]
        if key in self.running:
            return UNKNOWN
        self.running.add(key)
        returns = []
        self.run(rel, info["tree"], SinkState(ctx, {}, ctx), returns)
        self.running.discard(key)
        result = join(*returns) if info["returns"] else kinds("output")
        if info["returns"] and not returns:
            result = EMPTY
        self.memo[key] = result
        return result

    def define(self, rel, name, ctx):
        info = self.files.get(rel)
        body = info["defines"].get(name) if info else None
        if body is None:
            return
        key = (rel, "define", name, ctx)
        if key in self.memo or key in self.running:
            return
        self.running.add(key)
        self.run(rel, body, SinkState(ctx, {}, ctx), [])
        self.running.discard(key)
        self.memo[key] = True

    def run(self, rel, steps, st, returns):
        for stmt in steps:
            st = self.step(rel, stmt, st, returns)
        return st

    def flagged(self, rel, index):
        return index in self.files[rel]["flagged"]

    def group_binds(self, rel, index, tokens, st):
        """An assignment inside parentheses (`ne ($x := …) ""`), which the
        position rules fail, binds its variable to flagged or unknown."""
        st = st.copy()
        for i, t in enumerate(tokens or ()):
            if t.kind == "assign" and i and tokens[i - 1].text.startswith("$") \
                    and any(x.kind == "lparen" for x in tokens[:i]):
                st.env[tokens[i - 1].text] = kinds("flagged") if self.flagged(rel, index) \
                    else UNKNOWN
        return st

    def value(self, rel, index, pipeline, st):
        return kinds("flagged") if self.flagged(rel, index) else self.pipeline(pipeline, st)

    def step(self, rel, stmt, st, returns):
        if stmt.kind == "print":
            key = (rel, stmt.index)
            if self.files[rel]["sinks"][stmt.index][0] == "data":
                value = self.data_value(stmt.pipeline, st)
            else:
                value = self.pipeline(stmt.pipeline, st)
            self.printed[key] = join(self.printed.get(key, frozenset()), value)
            return st
        if stmt.kind == "assign":
            value = self.value(rel, stmt.index, stmt.pipeline, st)
            if stmt.names:
                st = st.copy()
                st.env[stmt.names[0]] = value
            return st
        if stmt.kind == "return":
            returns.append(self.pipeline(stmt.pipeline, st))
            return st
        if stmt.kind == "template":
            ctx = self.pipeline(stmt.pipeline, st) if stmt.pipeline.commands \
                and stmt.pipeline.commands[0] else NIL
            for other in self.files:
                if stmt.name in self.files[other]["defines"]:
                    self.define(other, stmt.name, ctx)
            return st
        if stmt.kind == "block":
            ctx = self.pipeline(stmt.pipeline, st)
            self.run(rel, stmt.body, SinkState(ctx, dict(st.env), ctx), returns)
            return st
        if stmt.kind == "define":
            return st  # run on its own, with the page as its dot
        if stmt.kind == "range":
            return self.loop(rel, stmt, st, returns)
        exits, decided = [], False
        for head, pipeline, names, body, at in stmt.branches:
            st = self.group_binds(rel, at, self.files[rel]["actions"][at][2], st)
            value = self.value(rel, at, pipeline, st)
            test = truth(value)
            inner = st.copy(truthy(value) if head == "with" else None)
            if names:
                inner.env[names[0]] = truthy(value)
            if test is not False:
                exits.append(self.run(rel, body, inner, returns).env)
            if test is True:
                decided = True
                break
        if not decided:
            exits.append(self.run(rel, stmt.orelse, st.copy(), returns).env
                         if stmt.orelse is not None else st.env)
        out = st.copy()
        out.env = join_env(*exits) if exits else st.env
        return out

    def loop(self, rel, stmt, st, returns):
        _, pipeline, names, body, at = stmt.branches[0]
        value = self.value(rel, at, pipeline, st)
        elem = element(value)
        env = dict(st.env)
        for _ in range(self.MAX_ROUNDS):
            inner = SinkState(elem, dict(env), st.top)
            if len(names) == 1:
                inner.env[names[0]] = elem
            elif len(names) >= 2:
                inner.env[names[0]] = range_keys(value)
                inner.env[names[1]] = elem
            after = self.run(rel, body, inner, returns).env
            grown = join_env(env, {k: v for k, v in after.items() if k in env})
            if grown == env:
                break
            env = grown
        else:
            self.problems.append((rel, stmt.index, "the print-sink analysis of this range "
                                  "did not settle; fails closed (L3 print sinks)"))
        exits = [env]
        if stmt.orelse is not None:
            exits.append(self.run(rel, stmt.orelse, st.copy(), returns).env)
        out = st.copy()
        out.env = join_env(*exits)
        return out

    def run_root(self, rel):
        info = self.files[rel]
        page = kinds("page")
        self.run(rel, info["tree"], SinkState(page, {}, page), [])
        for name in info["defines"]:
            self.define(rel, name, page)


def mark_define(steps, name, out):
    """out[action index] = the define name a print, template call or block
    sits in."""
    for stmt in steps:
        if stmt.kind in ("print", "template", "block"):
            out[stmt.index] = name
        for _, _, _, body, _ in stmt.branches:
            mark_define(body, name, out)
        mark_define(stmt.body, name, out)
        if stmt.orelse:
            mark_define(stmt.orelse, name, out)


def collect_defines(steps, out):
    for stmt in steps:
        if stmt.kind == "define" and stmt.name is not None:
            out[stmt.name] = stmt.body
        for _, _, _, body, _ in stmt.branches:
            collect_defines(body, out)
        collect_defines(stmt.body, out)
        if stmt.orelse:
            collect_defines(stmt.orelse, out)
    return out


def walk_steps(steps):
    for stmt in steps:
        yield stmt
        for _, _, _, body, _ in stmt.branches:
            yield from walk_steps(body)
        yield from walk_steps(stmt.body)
        if stmt.orelse:
            yield from walk_steps(stmt.orelse)


def has_return(steps):
    return any(stmt.kind == "return" or has_return(stmt.body)
               or any(has_return(b) for _, _, _, b, _ in stmt.branches)
               or (stmt.orelse is not None and has_return(stmt.orelse)) for stmt in steps)


def data_text_problems(value, depth=0):
    """The shapes a JSON-LD block would show as text under name or
    description (LITERALS_DATA_TEXT_KEYS), at any depth."""
    bad = set()
    allowed = LITERALS_PRINT_SOURCES["visible"] | {"nil"} | SINK_REPORTED
    for s in value:
        if not isinstance(s, tuple) or depth > 20:
            continue
        if s[0] == "list":
            bad |= data_text_problems(s[1], depth + 1)
        elif s[0] == "dict":
            for key, sub in s[1]:
                if key in LITERALS_DATA_TEXT_KEYS or key == "*":
                    bad |= {(key, x) for x in sub if x not in allowed
                            and not (isinstance(x, tuple) and x[0] in ("dict", "list"))}
                bad |= data_text_problems(sub, depth + 1)
    return bad


def jsonify_action(pipeline):
    """The action prints `… | jsonify` (with safeJS after it, or not)."""
    heads = [command_head(c) for c in pipeline.commands]
    while heads and heads[-1] in ("safeJS",):
        heads.pop()
    return bool(heads) and heads[-1] in ("jsonify", "encoding.Jsonify")


def print_sink_problems(files, findings):
    """Runs the analysis on every template of files (rel -> record of
    template_literal_problems plus its text) and adds the findings; returns
    the counts of printing actions by sink."""
    for rel, info in files.items():
        info["states"] = {}
        info["sinks"] = action_sinks(rel, info["text"], info["actions"], info["states"])
        try:
            info["tree"] = sink_tree(info["actions"])
        except TemplateError as exc:
            info["tree"] = None
            findings.add(rel, f"unbalanced {exc.what}: the print sinks cannot read the "
                         "template's blocks, so it fails closed (L3 print sinks)")
            continue
        info["defines"] = collect_defines(info["tree"], {})
        info["returns"] = has_return(info["tree"])
        info["define_of"] = {}
        for name, body in info["defines"].items():
            mark_define(body, name, info["define_of"])
    # A define prints where it is called (M3 PR 9 fix round 1, review 3):
    # html/template escapes its body in the context of each `template` call
    # and of the `block` of the same name, not where the define sits in its
    # own file. So the call sites decide: one in a visible attribute (baseof's
    # description) makes every print of the body a visible-attribute print,
    # the strictest; with only page-text call sites a print keeps the sink
    # its body gives it, read from the define, which itself must sit in the
    # page text (so its body is read from the text context it is called in).
    # A define written anywhere else (a comment, an attribute, a script), a
    # define nobody calls, and a call site anywhere but the page text, the
    # text of a raw-text element or a visible attribute fail closed.
    # The end context (M3 PR 9 fix round 2, delta review 1): html/template
    # carries the context at the end of a define back to its call site, and
    # the caller goes on from there, while this reading takes the text after
    # the call from the caller's own file. So a define or block body must end
    # in the parse state it starts in (a define: the page text), and its
    # template text must not move the caller out of the call site's context:
    # called from a visible attribute it holds no template text at all (`"`,
    # `'` or a space would end the attribute and put the caller's next print
    # in the page text), called from a raw-text element no `<` (an end tag
    # would close the element). Both carry through a define that calls
    # another.
    call_sites = {}  # define name -> [(kind, where, at, inside, place)]
    for rel, info in files.items():
        for stmt in walk_steps(info.get("tree") or []):
            if stmt.kind in ("block", "template") and stmt.name is not None:
                kind, where = info["sinks"][stmt.index]
                state = info["states"].get(stmt.index)
                at = f"{rel}:{line_of(info['text'], info['actions'][stmt.index][0])}"
                inside = info["define_of"].get(stmt.index)
                if kind == "visible" and state is not None and state[0] == "attr":
                    place = "attribute"
                elif kind == "text" and state == SINK_PLAIN:
                    place = "text"
                elif kind == "text" and state is not None and state[0] == "data" \
                        and state[1][0] in LITERALS_RAWTEXT_ELEMENTS:
                    place = "raw-text"
                else:
                    place = None
                call_sites.setdefault(stmt.name, []).append(
                    (kind, state_where(state, kind, where), at, inside, place))
    failed = set()  # define names that failed closed (their prints are not reported again)
    bodies = {}  # define name -> [(at, template text)]
    for rel, info in files.items():
        for stmt in walk_steps(info.get("tree") or []):
            if stmt.kind not in ("define", "block") or stmt.name is None:
                continue
            at = f"{rel}:{line_of(info['text'], info['actions'][stmt.index][0])}"
            kind, where = info["sinks"][stmt.index]
            start = info["states"].get(stmt.index)
            if stmt.kind == "define" and start != SINK_PLAIN:
                findings.add(at, f"define {show(stmt.name)} sits in "
                             f"{state_where(start, kind, where)}; a define "
                             "prints where it is called, so it must sit in the page text "
                             "for the print sinks to read its body; fails closed (L3 print "
                             "sinks)")
                failed.add(stmt.name)
                continue
            end = info["states"].get(stmt.end) if stmt.end is not None else None
            if start is not None and end != start:
                end_kind, end_where = info["sinks"].get(stmt.end, ("text", "the page text"))
                end_where = state_where(end, end_kind, end_where) if end is not None \
                    else "a tag, a comment or past the end of the file"
                findings.add(at, f"{stmt.kind} {show(stmt.name)} starts in "
                             f"{state_where(start, kind, where)} and ends in {end_where}; "
                             "html/template carries the context at the end of a body back "
                             "to the caller, which goes on from there, so a body must end "
                             "in the context it starts in; fails closed (L3 print sinks, "
                             "#31 delta review 1)")
                if stmt.kind == "define":
                    failed.add(stmt.name)
                continue
            if stmt.kind != "define":
                continue
            if stmt.name not in call_sites:
                findings.add(at, f"define {show(stmt.name)} has no call site (no `template "
                             f"{show(stmt.name)}` and no block of that name); the print "
                             "sinks cannot tell where it prints; fails closed (L3 print "
                             "sinks)")
                failed.add(stmt.name)
            bodies.setdefault(stmt.name, []).append(
                (at, body_text(info["text"], info["actions"], stmt.index, stmt.end)))
    defined = {name for info in files.values() for name in info.get("defines", {})}
    # define name -> its strictest call site, a visible attribute; a call
    # site inside a define called from a visible attribute is one too.
    define_sinks = {}
    for _ in range(len(call_sites) + 1):
        grown = False
        for name, sites in sorted(call_sites.items()):
            for kind, where, at, inside, place in sites:
                if name in defined and name not in define_sinks and kind == "text" \
                        and inside in define_sinks:
                    define_sinks[name] = define_sinks[inside]
                    grown = True
                elif name in defined and name not in define_sinks and kind == "visible":
                    define_sinks[name] = (kind, where, at)
                    grown = True
        if not grown:
            break
    # A `template` call of a name a block gives runs the block's own body
    # in the call's context, while this reading takes that body only where
    # the block sits; no layout calls one, so it fails closed (fix round 2).
    blocks = {stmt.name for info in files.values()
              for stmt in walk_steps(info.get("tree") or [])
              if stmt.kind == "block" and stmt.name is not None}
    for rel, info in files.items():
        for stmt in walk_steps(info.get("tree") or []):
            if stmt.kind == "template" and stmt.name in blocks:
                findings.add(f"{rel}:{line_of(info['text'], info['actions'][stmt.index][0])}",
                             f"the template call names {show(stmt.name)}, which a block gives: "
                             "the call runs the block's own body in the call's context, "
                             "which the print sinks read only where the block sits; fails "
                             "closed (L3 print sinks)")
    # T1 and T2 (M3 PR 10, ADR-0004 part 13; #31 fix round 2 delta
    # re-review, comment 6713575984, finding 1). text/template runs a named
    # body only through `template` and `block`, and a block is a define plus
    # a template call of it, so a second `block` of a name is a call of the
    # first one's body: Go keeps a non-empty body (an empty one never
    # replaces it) and runs it in the second block's context, where the
    # print sinks never read it. T1: a name is given by at most one `block`
    # statement in all of layouts/, whatever its body; each later one is a
    # finding. T2: every define and block name is plain
    # (LITERALS_TEMPLATE_NAME), because Hugo also resolves a name with `/`
    # or `.` by path (an inline partial `define "_partials/x.html"` runs at
    # `partial "x.html"`), a call site this reading never maps to the define.
    first_block = {}  # block name -> where its first block statement sits
    for rel, info in files.items():
        for stmt in walk_steps(info.get("tree") or []):
            if stmt.kind not in ("define", "block"):
                continue
            at = f"{rel}:{line_of(info['text'], info['actions'][stmt.index][0])}"
            if stmt.name is None or not LITERALS_TEMPLATE_NAME.fullmatch(stmt.name):
                name = show(stmt.name) if stmt.name is not None else "that is no string literal"
                findings.add(at, f"the {stmt.kind} name {name} is not a plain name "
                             "(lower-case ASCII letters, digits, `_` and `-`, starting with "
                             "a letter); Hugo also resolves a name with `/` or `.` by path, "
                             "at a call site the print sinks do not map to it, so it fails "
                             "closed (L3 print sinks T2; #31 comment 6713575984, finding 1; "
                             "ADR-0004 part 13)")
            if stmt.kind != "block" or stmt.name is None:
                continue
            if stmt.name in first_block:
                findings.add(at, f"block {show(stmt.name)} is given a second time (first at "
                             f"{first_block[stmt.name]}); a second block of a name runs the "
                             "first block's non-empty body in its own context, which the "
                             "print sinks read only where that body sits; one block "
                             "statement per name, whatever its body (L3 print sinks T1; #31 "
                             "comment 6713575984, finding 1; ADR-0004 part 13)")
            else:
                first_block[stmt.name] = at
    for name, sites in sorted(call_sites.items()):
        for kind, where, at, inside, place in sites:
            if name in defined and place is None:
                findings.add(at, f"the call of define {show(name)} sits in {where}; a "
                             "define is checked only where it is called in the page text, "
                             "the text of a raw-text element (LITERALS_RAWTEXT_ELEMENTS) "
                             "or a visible attribute; fails closed (L3 print sinks)")
                failed.add(name)
    # define name -> the places it prints into: its own call sites, and
    # those of every define it is called from.
    places = {}
    for _ in range(len(call_sites) + 1):
        grown = False
        for name, sites in sorted(call_sites.items()):
            for kind, where, at, inside, place in sites:
                got = {(place, at)} if place in ("attribute", "raw-text") else set()
                got |= places.get(inside, set())
                if not got <= places.get(name, set()):
                    places[name] = places.get(name, set()) | got
                    grown = True
        if not grown:
            break
    for name in sorted(places):
        if name in failed:
            continue
        for at, body in bodies.get(name, ()):
            for place, site in sorted(places[name]):
                if place == "attribute" and body:
                    findings.add(at, f"define {show(name)} is called in a visible attribute "
                                 f"({site}), and its template text holds {show(body)}; called "
                                 "from an attribute a define holds only actions, because a "
                                 "quote or a space ends the attribute and moves the caller's "
                                 "next print into the page text; fails closed (L3 print "
                                 "sinks, #31 delta review 1)")
                elif place == "raw-text" and "<" in body:
                    findings.add(at, f"define {show(name)} is called in a raw-text element "
                                 f"({site}), and its template text holds '<'; called from a "
                                 "raw-text element a define holds no `<`, because an end tag "
                                 "closes the element and moves the caller's next print into "
                                 "the page text; fails closed (L3 print sinks, #31 delta "
                                 "review 1)")
                else:
                    continue
                failed.add(name)
                break
    analysis = SinkAnalysis(files)
    for rel in sorted(files):
        if files[rel].get("tree") is not None and not rel.startswith("layouts/_partials/"):
            analysis.run_root(rel)
    counts = {"text": 0, "visible": 0, "data": 0, "other": 0}
    for (rel, index), value in sorted(analysis.printed.items(), key=lambda x: x[0]):
        info = files[rel]
        start, _, tokens, _ = info["actions"][index]
        kind, where = info["sinks"][index]
        name = info.get("define_of", {}).get(index)
        if name in define_sinks:
            site_kind, site_where, site_at = define_sinks[name]
            kind, where = site_kind, (f"{site_where} (where define {show(name)} is "
                                      f"called, {site_at})")
        pipeline = parse_pipeline(tokens)[0]
        head = command_head(pipeline.commands[0]) if pipeline.commands else None
        counts[kind if kind in counts else "other"] += 1
        stray = sorted({s[0] if isinstance(s, tuple) else s for s in value}
                       - SINK_KINDS, key=str)
        if stray:
            findings.add(f"{rel}:{line_of(info['text'], start)}", f"the action prints a "
                         f"value of kind {', '.join(map(str, stray))}, which is not on "
                         "SINK_KINDS; fails closed until the kind is registered with its "
                         "self-test row (L3 print sinks)")
        if index in info["flagged"] or head in LITERALS_MESSAGE_FUNCS or name in failed:
            continue  # name in failed: the define failed closed above (one defect, one finding)
        at = f"{rel}:{line_of(info['text'], start)}"
        if kind in ("text", "visible"):
            bad = sorted({s for s in value if s not in LITERALS_PRINT_SOURCES[kind]
                          and s not in SINK_REPORTED}, key=repr)
            if bad:
                takes = ("a label partial, the output of a partial, a content field, "
                         "site.Title, site.Params.operator or .contact, a date in the "
                         "pinned layout, or markup built from those" if kind == "text" else
                         "a label partial, a content field, site.Title, "
                         "site.Params.operator or .contact, a date in the pinned layout, "
                         "or printf of those without markup")
                findings.add(at, f"the action prints {', '.join(describe(s) for s in bad)} "
                             f"into {where}; {SINK_WHERE[kind]} takes only {takes} "
                             f"(LITERALS_PRINT_SOURCES, L3 print sinks); {LITERALS_FIX}")
        elif kind == "tag":
            if any(not (isinstance(s, tuple) and s[0] == "lit"
                        and SINK_TAG_NAME.fullmatch(s[1])) and s not in SINK_REPORTED
                   for s in value):
                findings.add(at, "the action prints into an element name something other "
                             "than a literal tag name (L3 print sinks)")
        elif kind == "data":
            if not jsonify_action(pipeline):
                findings.add(at, f"the action prints into {where} without `| jsonify`; a "
                             "JSON data block takes only jsonify output (L3 print sinks)")
            elif where == "a JSON-LD block":
                for key, s in sorted(data_text_problems(value), key=repr):
                    findings.add(at, f"the JSON-LD block shows {describe(s)} as its {key}; "
                                 "under name and description (LITERALS_DATA_TEXT_KEYS) it "
                                 "takes only what a visible attribute takes "
                                 "(LITERALS_PRINT_SOURCES, L3 print sinks)")
    for rel, index, message in analysis.problems:
        info = files[rel]
        findings.add(f"{rel}:{line_of(info['text'], info['actions'][index][0])}", message)
    return counts


# L7 (M3 PR 9, #29 Known limit 4): a script under assets/ is not a
# template; its string and template literals get the L3 test, as the
# literals of an action do (markup with its visible attributes, then the
# remainder: no letter or digit, one lowercase token, or a vocabulary word),
# plus the symbol and data: URL rules. Comments are skipped (the minifier
# drops them). What fails closed: a template action ({{), a template
# literal with a substitution and a regular expression literal, which this
# reading cannot follow; an unterminated string, template or comment (L6).
JS_ESCAPE = re.compile(r"\\(?:u\{([0-9A-Fa-f]+)\}|u([0-9A-Fa-f]{4})|x([0-9A-Fa-f]{2})"
                       r"|\r\n|(.))", re.S)
JS_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0",
             "\n": "", "\r": "", "\u2028": "", "\u2029": ""}
JS_WORD = re.compile(r"[A-Za-z0-9_$]+")
JS_VALUE_WORDS = frozenset("this super null true false undefined".split())
JS_SUFFIXES = {".js", ".mjs"}
# L7's one exception (M4 PR 3 fix round 4): a script string literal that is
# the source of a regular expression, accepted exactly, by file and value.
# search.js keeps a key or query form only when it holds a letter or digit
# (Unicode \p{L} or \p{N}); JavaScript has no other way to test a Unicode
# category, and a regular expression literal fails L7. The value is a
# character class, which a script passes to RegExp and never prints.
LITERALS_SCRIPT_PATTERNS = frozenset({("assets/js/search.js", "[\\p{L}\\p{N}]")})
# The script pin (M3 PR 9 fix round 1, review 4, #31 Known limit 1): L7
# reads a script's literals, not what its code computes (a join of tokens,
# String.fromCharCode, an identifier, the DOM), so every script under
# assets/ is pinned by the SHA-256 of its bytes here. A script that is not
# on the list, or whose bytes differ, is a finding: a script change is then
# a change of tools/, which gets the safety-net review (sdlc-reviewer), and
# CI enforces that, not a convention. Why a hash and not a list of allowed
# identifiers: computed text passes any identifier list
# (`String(target.id) + button.type`), a hash catches every change. L7
# still runs, so a new pin never admits a copy literal.
# The stylesheet pin (M4 PR 3 fix round 4, delta review 3 finding 2),
# mirroring the script pin: CSS can degrade text in more ways than an
# outcome check short of reading the pixels can close (opacity, blur, a
# tiny font, line clipping, transforms, letter-spacing, near-background
# colours), so CSS is a reviewed surface, as images (#29) and scripts (#31)
# are. Every stylesheet source is pinned by the SHA-256 of its bytes: the
# two CSS files under assets/ and data/tokens.toml, whose values
# assets/css/tokens.css turns into the custom properties site.css uses.
# `guard` fails a stylesheet source that is not pinned (any .css file under
# assets/ or static/, any case) or whose bytes differ, and `site` rule (l)
# allows only the exact built path of the one built stylesheet. So no
# stylesheet can change or be added without a tools/ change, which gets the
# safety-net review. Inline CSS is refused elsewhere: `site` rule (c) fails
# every style attribute and <style> element of a built page, and the CSP's
# style-src 'self' would block them.
STYLESHEET_SHA256 = {
    "assets/css/site.css": "692d492f09fa807f81d2b9fc4a83c13eb00c9e16c952d9e85fd70cf3a378c866",
    "assets/css/tokens.css": "725a7b2808e32866e206468f43b1097c8b34e879e13baeee309391f1fe53ad27",
    "data/tokens.toml": "b867bb5bae4cc1a95bf730e132b3e2d4f0744a984308835837b73279dce39182",
}
STYLESHEET_SOURCE_DIRS = ("assets", "static")
# The built stylesheets by stem: baseof.html concatenates tokens.css and
# site.css into the resource css/site.css, minified and fingerprinted.
BUILT_STYLESHEETS = frozenset({"site"})
BUILT_STYLE_DIR = "/css/"
BUILT_STYLE_INFIX = ".min."
BUILT_STYLE_SUFFIX = ".css"


# The built pins (M4 PR 3 fix round 5, delta review 4 finding 1): the bytes
# of every built stylesheet and script, pinned by hash, so any input route
# that changes them fails, whatever it took: a second data file that Hugo
# merges into hugo.Data.tokens (data/tokens.yaml, data/tokens/color.toml),
# a config or a module, not only an edit of a pinned source. The source
# pins stay; they name what a reviewer reads. A stylesheet by the SHA-256
# that names its file, a script by the SHA-384 of its integrity attribute.
# `site --no-built-pins` turns them off for the hand-made site fixtures,
# whose files are no build (the --no-feed precedent); check.sh never
# passes it (wiring/site-built-pins).
# The script tag of baseof.html (rule (j), fix round 6) and the scripts each
# page kind loads, by stem, in order.
SCRIPT_SRC_ATTRS = ("src", "integrity", "defer")
SCRIPTS_BY_PAGE_KIND = {"home": ("copy", "search"), "other": ("copy",)}
# Rule (m), the head by position (M4 PR 3 fix round 7, delta review 6
# finding 1). An element whose effect depends on its place and namespace
# (script, link, meta, base) works only as a direct child of the one <head>:
# inside <math> or <svg> a script is no HTMLScriptElement and never runs, a
# CSP meta outside the head or in foreign content is ignored, a link in a
# wrapper may apply to nothing. So these elements are direct children of
# the head and appear nowhere else (every page, hand-made fixtures too),
# and with the built pins on the head holds exactly the children
# baseof.html emits for the page kind, in order, with exactly their
# attribute names and fixed values (the HOME_CHAIN mechanism applied to the
# head); None stands for a value another rule pins (the CSP content against
# params.csp, rule (c); the canonical href, rule (d); the theme colour, rule
# (f); the description, render; the stylesheet href, rules (k) and (l); the
# script src and integrity, rule (j)). A JSON-LD block is the last child of
# the head on a record page and a section page (one each, as jsonld.html
# emits it) and absent elsewhere. Exact positions, not a list of wrappers.
HEAD_ONLY_TAGS = ("script", "link", "meta", "base")
# Fix round 8 (delta review 7 finding 1): the tree of parse_render_page
# does not model the end of the head that the HTML parser implies, so
# rule (m) fails closed on everything that makes a browser end the head
# early: text that is not ASCII whitespace before <html>, inside <html>
# before <body> or inside <head> (a stray "." after the charset moves every
# later head element into the body, the CSP meta included, which is then
# ignored), an element in <html> before <body> other than <head>, and a
# head child outside the head content model. Reflow case (9) reads the
# browser's own head, so a differential this list misses is still caught.
ASCII_WHITESPACE = "\t\n\f\r "
HEAD_CONTENT_MODEL = frozenset({"base", "link", "meta", "noscript", "script", "style",
                                "template", "title"})
HEAD_PREFIX = [
    ("meta", {"charset": "utf-8"}),
    ("meta", {"http-equiv": "Content-Security-Policy", "content": None}),
    ("meta", {"name": "viewport", "content": "width=device-width,initial-scale=1"}),
    ("meta", {"name": "color-scheme", "content": "light"}),
    ("meta", {"name": "description", "content": None}),
    ("title", {}),
]
HEAD_CANONICAL = ("link", {"rel": "canonical", "href": None})
HEAD_SUFFIX = [
    ("meta", {"name": "theme-color", "content": None}),
    ("link", {"rel": "icon", "href": None, "type": "image/svg+xml"}),
    ("link", {"rel": "stylesheet", "href": None}),
]
HEAD_SCRIPT = ("script", {"src": None, "integrity": None, "defer": ""})
HEAD_JSONLD = ("script", {"type": JSON_LD})
NOT_FOUND_REL = "public/404.html"
RECORD_SECTIONS_REL = ("public/reports/", "public/campaigns/")


def head_spec(rel):
    """The direct children of <head> that baseof.html emits for the page
    rel (`public/...`), in order: (tag, {attribute: value or None})."""
    spec = list(HEAD_PREFIX)
    if rel != NOT_FOUND_REL:
        spec.append(HEAD_CANONICAL)
    spec += HEAD_SUFFIX
    kind = SCRIPTS_BY_PAGE_KIND["home" if rel == "public/index.html" else "other"]
    spec += [HEAD_SCRIPT] * len(kind)
    if rel.startswith(RECORD_SECTIONS_REL) and rel.endswith("/index.html"):
        spec.append(HEAD_JSONLD)  # a section page or a record page
    return spec


def head_problems(text, rel, built):
    """Rule (m) on one HTML page (see HEAD_ONLY_TAGS). built: also the exact
    head of baseof.html (the built pins are on)."""
    tree = parse_render_page(text)
    htmls = [el for el in tree.root.children if isinstance(el, Element) and el.tag == "html"]
    heads = [el for el in htmls[0].children if isinstance(el, Element) and el.tag == "head"] \
        if len(htmls) == 1 else []
    head = heads[0] if len(heads) == 1 else None
    problems = []
    html = htmls[0] if len(htmls) == 1 else None
    for owner, what in ((tree.root, "before <html>"), (html, "in <html> before <body>"),
                        (head, "in <head>")):
        if owner is None:
            continue
        for child in owner.children:
            if isinstance(child, Element):
                if owner is tree.root and child.tag == "html":
                    break
                if owner is html:
                    if child.tag == "body":
                        break
                    if child.tag != "head":
                        problems.append(f"(m) <{child.tag}> {what}: the browser ends the head "
                                        "there and puts it and everything after it in the body")
                if owner is head and child.tag not in HEAD_CONTENT_MODEL:
                    problems.append(f"(m) <{child.tag}> {what} is outside the head content "
                                    "model; the browser ends the head there and moves it and "
                                    "every later head element into the body")
            elif child.strip(ASCII_WHITESPACE):
                problems.append(f"(m) the text {show(child, 60)} {what}: the browser ends the "
                                "head at text that is not ASCII whitespace and moves every later "
                                "head element into the body, the CSP meta included, which is "
                                "then ignored")
    if head is None:
        problems.append("(m) the page has no single <head> right inside its single <html>; "
                        "script, link, meta and base work only as children of that head")
    for el in tree.root.walk():
        if el.tag in HEAD_ONLY_TAGS and (head is None or el.parent is not head):
            chain, parent = [], el.parent
            while parent is not None and parent.tag != "#document":
                chain.append("<" + parent.tag + ">")
                parent = parent.parent
            where = " in ".join(chain)
            problems.append(f"(m) <{el.tag} {show(el.attrs, 160)}> sits in {where or 'nothing'}"
                            "; it is a direct child of <head>, where its place and namespace "
                            "give it its effect (inside <math> or <svg> a script never runs, "
                            "a CSP meta outside the head is ignored)")
    if head is None or not built:
        return problems
    got = [(el.tag, el.attrs) for el in head.children if isinstance(el, Element)]
    want = head_spec(rel)

    def matches(item, spec):
        tag, attrs = item
        stag, sattrs = spec
        return tag == stag and set(attrs) == set(sattrs) and all(
            v is None or attrs.get(k) == v for k, v in sattrs.items())
    if len(got) != len(want) or not all(matches(g, w) for g, w in zip(got, want)):
        def shown(items):
            return ", ".join("<" + t + "".join(f" {k}" + ("" if v is None else f"={show(v, 40)}")
                                             for k, v in a.items()) + ">" for t, a in items)
        problems.append(f"(m) the head holds {shown([(t, {k: None for k in a}) for t, a in got])}"
                        f"; baseof.html emits exactly {shown(want)} for this page, in this "
                        "order (values shown are pinned here, the others by their own rule)")
    return problems
BUILT_STYLESHEET_SHA256 = {
    "site": "470be46f742fb0e78ec74a50fb4760c6c8ff56e9ab80f27762e41059b559bc38",
}
BUILT_SCRIPT_SHA384 = {
    "copy": "64df53ed5d62c8c5c8be3aee6bd39c1171a2bb88742b3424790354056657c3faf100ea7cc044affe06e76164b883b924",
    "search": "2b9f7b42bbac16efb718132e221f2214be1478c3c99660e158b61c5c629d70fca54748d3055c7e96ca415ba59abe1483",
}


def built_style_path(stem, data):
    """The path Hugo writes for the stylesheet stem whose built bytes are
    data: resources.Fingerprint without an algorithm uses SHA-256."""
    return (BUILT_STYLE_DIR + stem + BUILT_STYLE_INFIX + hashlib.sha256(data).hexdigest()
            + BUILT_STYLE_SUFFIX)


SCRIPT_SHA256 = {
    "assets/js/copy.js": "5cca51768d7caa004240fccdcfe84cd588f2686f3e4481da5561673d8592cc89",
    "assets/js/search.js": "48915ad64fddd4044a734fa3ef938523e61f5476083b67d8a061e3e4e932332e",
}


def js_unquote(raw):
    """The value of a JavaScript string literal body."""
    def one(match):
        brace, u4, xx, simple = match.groups()
        if brace or u4 or xx:
            try:
                return chr(int(brace or u4 or xx, 16))
            except (ValueError, OverflowError):
                return "\ufffd"
        if simple is None:
            return ""
        return JS_SIMPLE.get(simple, simple)
    return JS_ESCAPE.sub(one, raw)


def script_literal_problems(rel, text, findings, counts):
    """L7 on one script file under assets/."""
    def add(offset, message):
        findings.add(f"{rel}:{line_of(text, offset)}", message)

    if "{{" in text:
        add(text.index("{{"), "a template action in a script: assets/**/*.js is no "
            "template, and one run through ExecuteAsTemplate would print what L7 does "
            "not read; fails closed (L7)")
    i, n, value_before = 0, len(text), False
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                add(i, "unterminated comment (L6); the script cannot be read")
                return
            i = end + 2
            continue
        if c in "'\"`":
            k = i + 1
            while k < n and text[k] != c and (c == "`" or text[k] != "\n"):
                k += 2 if text[k] == "\\" else 1
            if k >= n or text[k] != c:
                add(i, "unterminated string (L6); the script cannot be read")
                return
            raw = text[i + 1:k]
            counts["literals"] += 1
            if c == "`" and "${" in raw:
                add(i, "a template literal with a substitution: L7 cannot read what it "
                    "prints; fails closed (L7)")
                i, value_before = k + 1, True
                continue
            value = js_unquote(raw)
            if (rel, value) in LITERALS_SCRIPT_PATTERNS:
                i, value_before = k + 1, True
                continue
            for problem in literal_problems(value, False):
                add(i, problem.replace("(L3)", "(L7, the L3 test on a script literal)")
                    + f"; {LITERALS_FIX}")
            if DATA_URL.search(value):
                add(i, f"the script literal {show(value)} holds a data: URL, which can "
                    "embed an image or document that draws text no check reads; fails "
                    "closed (L7)")
            bad = symbol_problems(value)
            if bad:
                add(i, f"the script literal {show(value)} holds non-ASCII symbols that "
                    f"are not on LITERALS_SYMBOLS ({bad}) (L7)")
            i, value_before = k + 1, True
            continue
        if c == "/":
            if not value_before:
                add(i, "a regular expression literal: L7 cannot read it as text; fails "
                    "closed (L7)")
                end = text.find("\n", i)
                i = n if end < 0 else end
                continue
            i, value_before = i + 1, False
            continue
        if c.isspace():
            i += 1
            continue
        match = JS_WORD.match(text, i)
        if match:
            word = match.group(0)
            value_before = word in JS_VALUE_WORDS or not word.isalpha() or not word.islower() \
                or word not in ("return", "typeof", "case", "do", "else", "in", "of", "new",
                                "delete", "void", "throw", "instanceof", "yield", "await")
            i = match.end()
            continue
        value_before = c in ")]"
        i += 1


def cmd_literals(args):
    root = Path(args.root).resolve()
    if not root.is_dir():
        raise UsageError(f"--root {root} is not a directory")
    findings = Findings()
    counts = {"layouts": 0, "other": 0, "actions": 0, "literals": 0}
    templates = {}  # rel -> the template's actions, for the print sinks
    # The names `define` and `block` give: the only names `template` may call.
    defines = set()
    for path in sorted((root / "layouts").rglob("*")) if (root / "layouts").is_dir() else []:
        if path.is_file():
            try:
                defines.update(re.findall(r"\{\{-?\s*(?:define|block)\s+\"([^\"]+)\"",
                                          path.read_text(encoding="utf-8")))
            except (OSError, UnicodeDecodeError):
                pass  # the scan below reports it
    for top in ("layouts", "assets", "static"):
        base = root / top
        if not base.is_dir():
            continue
        for path in sorted(p for p in base.rglob("*") if p.is_file()):
            rel = path.relative_to(root).as_posix()
            suffix = path.suffix.lower()
            if top != "layouts" and suffix in RASTER_SUFFIXES:
                # An image can draw text that no check reads. None exists
                # today; the first one comes with its own review rule.
                findings.add(rel, "a raster image: it can draw text this check "
                             "cannot read, so it fails closed until an image rule "
                             "exists (L6)")
                continue
            if top == "static" and suffix not in MARKUP_SUFFIXES | {".css"}:
                # robots.txt included (A2): M6 adds it with its own rule.
                findings.add(rel, "a static file this check cannot read for copy "
                             "(script, plain text, any type but HTML, SVG, XML and "
                             "CSS); the browser can still show or run it, so it fails "
                             "closed (L6)")
                continue
            counts["layouts" if top == "layouts" else "other"] += 1
            if top == "assets" and suffix in JS_SUFFIXES:
                try:
                    digest = hashlib.sha256(path.read_bytes()).hexdigest()
                except OSError:
                    digest = None  # the read below reports it
                pinned = SCRIPT_SHA256.get(rel)
                if digest is not None and pinned is None:
                    findings.add(rel, "a script that is not pinned: every script under "
                                 "assets/ is pinned by its SHA-256 in tools/sitecheck.py "
                                 "(SCRIPT_SHA256), so adding one is a tools/ change with "
                                 "the safety-net review (L7 script pin)")
                elif digest is not None and digest != pinned:
                    findings.add(rel, f"the script's SHA-256 is {digest}, not the one pinned "
                                 "in tools/sitecheck.py (SCRIPT_SHA256); a script change "
                                 "updates the pin there, so it is a tools/ change with the "
                                 "safety-net review (L7 script pin)")
            try:
                text = path.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                findings.add(rel, "not UTF-8 (L6); the check cannot read it, so it "
                             "fails closed")
                continue
            except OSError as exc:
                findings.add(rel, f"cannot read: {exc}")
                continue
            if top == "assets" and suffix in JS_SUFFIXES:
                # L7: a script, not a template (M3 PR 9).
                script_literal_problems(rel, text, findings, counts)
                continue
            if top == "static":
                # Copied as is, never run as a template.
                bare, holes = text, []
                if suffix != ".css":
                    markup_page_problems(rel, text, findings)
            else:
                record = {}
                bare, holes = template_literal_problems(
                    rel, text, findings, counts, suffix != ".css", root, defines,
                    css=suffix == ".css", record=record)
                if suffix != ".css":
                    templates[rel] = dict(record, text=text)
            if suffix == ".css":
                for offset, problem in css_text_problems(bare, holes):
                    findings.add(f"{rel}:{line_of(bare, offset)}",
                                 f"{problem}; {LITERALS_FIX}")
    # L4 (review3 6): a shortcode in content prints template output. The
    # embedded `param` falls back to site params, so `{{< param csp >}}`
    # would print the CSP as page text; content may call exactly the two
    # forms it uses, for the D1 params.
    content = root / "content"
    for path in sorted(p for p in content.rglob("*") if p.is_file()) if content.is_dir() else []:
        rel = path.relative_to(root).as_posix()
        text = path.read_bytes().decode("utf-8", errors="replace")
        for match in SHORTCODE_OPEN.finditer(text):
            if not CONTENT_SHORTCODE.match(text, match.start()):
                findings.add(f"{rel}:{line_of(text, match.start())}",
                             f"shortcode {show(text[match.start():match.start() + 40].split(chr(10))[0])}: "
                             "content may call only `{{< param operator >}}` and "
                             "`{{< param contact >}}`; any other shortcode prints template "
                             "or config output (params.csp through `param`) that no copy "
                             "check reads (L4, review3 6)")
    sinks = print_sink_problems(templates, findings)
    return findings.report(
        f"literals checked: {counts['layouts']} layout files, {counts['actions']} "
        f"actions, {counts['literals']} literals; {counts['other']} asset and static "
        f"files; print sinks: {sinks['text']} text, {sinks['visible']} visible "
        f"attribute, {sinks['data']} data block, {sinks['other']} other")


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
# The budget of the first answer of every launch (Browser.getVersion, both
# attempts; ADR-0003 part 6 and Numbers, amended for #24). Lower bound: one
# attempt alone outlasts the longest stall seen, at most 70.3 s (PR 5 job
# 20, image 20261101), so it is absorbed whether a killed Chrome keeps its
# progress, the stall lies outside the VM, or only a fresh Chrome helps.
# Upper bound: the 13-minute workflow cap (re-derived in M3 PR 10 fix
# round 1, ADR-0004 Numbers) holds the slowest green run of that round
# (370 s), a fully used window (2 x L) and one more 70 s stall, so L is at
# most 170 s; 75 s leaves 190 s of the cap. Below 71 s job 20's shape
# depends on a restart helping again; above 170 s an absorbed window plus
# a second stall is cancelled at 13 minutes.
REFLOW_LAUNCH_TIMEOUT = 75
# The budget of every later answer (ADR-0003 Numbers). A 23-page call makes
# about 70 page-level calls in 1.9 to 2.8 s on the runner, and no later call
# has run out in any job. A stall can reach past the first answer (PR 5 job
# 11: its 8 pages took at least 4.8 s against about 2 s), and 30 s covers
# that by a factor above 6. Shorter: the tail of a stall fails a page call,
# which never retries. Longer: a hung page waits longer for no data.
REFLOW_TIMEOUT = 30
# Launches of Chrome per run (ADR-0003 part 6 and Numbers, amended for #24).
# With REFLOW_LAUNCH_TIMEOUT one launch absorbs every stall seen; the second
# covers a Chrome that exits at start or wedges where a fresh one does not
# (after #23's cuts and PR 5 job 7's, the fresh Chrome finished a normal
# call), and it doubles the window to 150 s, 2.1 times the longest stall.
# 1: an early exit or a wedged launch fails the job. 3: a hang waits 225 s
# per call, which with the 196.4 s base passes the 7-minute cap (421.4 s).
# Only NoAnswerError from the first answer retries.
REFLOW_LAUNCH_ATTEMPTS = 2
# A probe at each fifth of the launch budget (15 s at 75 s), four while
# waiting plus one before a kill, so at most 5 per launch. The first comes
# after every normal first answer sampled so far (whole tree-1 calls up to
# 10.2 s in 18 stall-free jobs, the timing line up to 12.34 s, c0ba6f4's
# acceptance dispatch 2, run 42208254148) and before 30 s, where every stall
# so far was cut. A tenth (7.5 s) would probe ordinary cold starts; a half
# (37.5 s) could miss a stall that ends between 30 and 37.5 s, as jobs 7 and
# 11 did, the 2 of the 7 stalls seen with a known duration in that range.
REFLOW_PROBES = 5
# The tail of a launch's Chrome log that a dump prints. A normal startup
# logs about 17.7 KB up to its first answer with --v=1 (one local run), so
# 64 KiB shows a stalled startup that logs several times as much; a whole
# call logs up to 0.9 MB, which would flood the job log.
REFLOW_LOG_DUMP_BYTES = 64 * 1024
# Where Chrome's logs go (ADR-0003 part 6 and Numbers, #25 review): a fresh
# directory on this tmpfs. With --v=1 Chrome writes its log synchronously,
# and Google Chrome's launcher relays it through cat into the log file; on
# the runner's disk a stall would block cat, fill the pipe and block
# Chrome's logging threads, the DevTools ones included. A tmpfs write does
# not wait for the disk unless memory runs short (reclaim can then wait on
# the disk, through swap or through other files' writeback; the probe line
# reports memory pressure), and a full one fails at once (ENOSPC), so a log
# line is lost, not time. One call's logs take about 1 MB (0.9 MB for a 23-page
# call) and go with the call. Where this is no tmpfs mount or no directory
# can be made in it, the logs stay in the work directory, as before.
REFLOW_LOG_DIR = "/dev/shm"
# At most this many elements are named per page and case, so one broken
# template cannot flood the log; the count is always printed.
REFLOW_NAMED = 10
# Sub-pixel tolerance: layout positions are fractional, and a box that ends
# at 320.3 px because of rounding hides nothing.
REFLOW_EPSILON = 0.5
# Case (7) (M3 PR 10, ADR-0003 Numbers): the box of the focused skip link
# must be wider and taller than this. The definition pins 1 x 1 px with
# !important, and only the reveal's !important declarations can grow it
# (!important is allowed nowhere else), so a larger box shows that the
# reveal applied; 1.5 adds the 0.5 px tolerance. A revealed skip link is a
# line of text with padding, tens of px each way. At 1 or below a reveal
# that does not apply could pass on rounding; far above (40 px) a short
# label in a small size could fail although revealed.
REFLOW_REVEAL_MIN = 1.5
# Case (7), the paint (M3 PR 10 fix round 1, ADR-0003 Numbers): two
# screenshots of the focused element's box match when no channel of any
# pixel differs by more than this (of 255). Measured on Chrome for Testing
# 143: two captures of the same revealed skip link, one before and one after
# the opacity round trip, differ by 1 at 6 anti-aliased pixels of the
# rounded corners (the raster path changes), while the link against its
# box without it differs by far more (its text, primary on card at 6.87:1).
# At 0 that raster noise fails every page; far above (64) a faint but
# readable link could count as painting nothing, the safe direction but
# red on a working page. 8 is eight times the measured noise.
REFLOW_PAINT_TOLERANCE = 8
# Case (6), state S1 (ADR-0003 part 6): the script URLs blocked, so the page
# loads with scripting on and its script not run, as after a failed load.
REFLOW_BLOCKED_SCRIPTS = ("*.js", "*.mjs")
# Case (7): what the page needs focus moved by, one Tab key press.
REFLOW_TAB_KEY = {"key": "Tab", "code": "Tab", "windowsVirtualKeyCode": 9,
                  "nativeVirtualKeyCode": 9}
# Case (7): read after the Tab press. The focused element, its label as the
# measuring script writes it, whether it has the class, its box, the scroll
# position and, for the paint finding's message, its computed opacity,
# visibility, clip and clip-path and the element at the box centre.
# Case (6), the revealed search results (M4 PR 3 fix round 1, review
# finding 3): in S0, on a page with #search-results, each result section is
# revealed in turn as search.js reveals it (the box and that one section
# lose their hidden attribute), and then it must be perceivable and
# operable: the box and every element of the section that holds text pass
# checkVisibility with its opacity and visibility checks, focus moves to
# the section heading, and elementFromPoint at the heading's centre (after
# scrolling it into view) is the heading or inside it. That reads the
# outcome of any mechanism, a popover or inert wrapper, pointer-events, an
# overlay or CSS that hides part of a section, not a list of them.
REFLOW_REVEAL_SCRIPT = r"""
(function () {
  var results = document.getElementById("search-results");
  if (!results) { return {present: false}; }
  var ids = %(ids)s;
  var opts = {opacityProperty: true, visibilityProperty: true};
  function label(el) {
    if (!el) { return "nothing"; }
    var text = el.localName || el.nodeName;
    if (el.id) { text += "#" + el.id; }
    if (el.classList && el.classList.length) { text += "." + Array.from(el.classList).join("."); }
    return text;
  }
  function hideAll() {
    ids.forEach(function (id) {
      var el = document.getElementById(id);
      if (el) { el.hidden = true; }
    });
  }
  var out = [];
  ids.forEach(function (id) {
    hideAll();
    results.hidden = false;
    var section = document.getElementById(id);
    if (!section) { out.push({id: id, missing: true}); return; }
    section.hidden = false;
    var found = {id: id, region: results.checkVisibility(opts), hiddenText: []};
    [section].concat(Array.from(section.querySelectorAll("*"))).forEach(function (el) {
      var own = Array.from(el.childNodes).some(function (n) {
        return n.nodeType === 3 && n.textContent.trim() !== "";
      });
      if (own && !el.checkVisibility(opts)) { found.hiddenText.push(label(el)); }
    });
    var heading = section.querySelector("h2");
    if (heading) {
      // The scroll is the step's own (focus without its scroll), so the
      // hit test reads the heading where the scroll puts it.
      heading.scrollIntoView({block: "center"});
      heading.focus({preventScroll: true});
      found.focus = document.activeElement === heading;
      found.focused = label(document.activeElement);
      var box = heading.getBoundingClientRect();
      var hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
      found.hit = !!hit && heading.contains(hit);
      found.hitLabel = label(hit);
    }
    out.push(found);
  });
  hideAll();
  results.hidden = true;
  window.scrollTo(0, 0);
  return {present: true, sections: out};
})()
"""
# Case (9), the head in the browser (M4 PR 3 fix round 8, delta review 7
# finding 1): the browser's own DOM, not a Python model of it. For every
# page loaded in S0, document.head's element children (tag, order, every
# attribute) must equal the head that parse_render_page reads in the file,
# which rule (m) of `site` pins to the head baseof.html emits for the page
# kind; script, link, meta and base exist only as HTML children of
# document.head; and every CSP meta's parent is document.head. So a parser
# differential nobody modelled (a stray text, an element that ends the
# head) is caught by its outcome.
REFLOW_HEAD_SCRIPT = r"""
(function () {
  var head = document.head;
  function attrs(el) {
    var out = {};
    Array.prototype.forEach.call(el.attributes, function (a) { out[a.name] = a.value; });
    return out;
  }
  function label(el) {
    var where = el.parentElement ? el.parentElement.localName : "nothing";
    return el.localName + " in " + where +
      (el.namespaceURI === "http://www.w3.org/1999/xhtml" ? "" : " (" + el.namespaceURI + ")");
  }
  var stray = Array.prototype.filter.call(
    document.querySelectorAll("script, link, meta, base"), function (el) {
      return el.parentElement !== head || el.namespaceURI !== "http://www.w3.org/1999/xhtml";
    }).map(label);
  var csp = Array.prototype.filter.call(document.querySelectorAll("meta"), function (el) {
    return (el.getAttribute("http-equiv") || "").toLowerCase() === "content-security-policy";
  });
  return {
    head: head ? Array.prototype.map.call(head.children, function (el) {
      return [el.localName, attrs(el)];
    }) : null,
    stray: stray,
    cspOutside: csp.filter(function (el) { return el.parentElement !== head; }).map(label)
  };
})()
"""


def static_head(text):
    """[(tag, attributes)] of the element children of the one <head> right
    inside the one <html> of the page as parse_render_page reads it, or
    None without such a head."""
    tree = parse_render_page(text)
    htmls = [el for el in tree.root.children if isinstance(el, Element) and el.tag == "html"]
    heads = [el for el in htmls[0].children if isinstance(el, Element) and el.tag == "head"] \
        if len(htmls) == 1 else []
    if len(heads) != 1:
        return None
    return [[el.tag, dict(el.attrs)] for el in heads[0].children if isinstance(el, Element)]


REFLOW_FOCUS_SCRIPT = r"""
(() => {
  const exempt = %(exempt)s;
  const label = (el) => {
    let s = el.tagName.toLowerCase();
    if (el.id) s += "#" + el.id;
    for (const c of el.classList) s += "." + c;
    return s;
  };
  const focusable = [...document.querySelectorAll("." + exempt)].some((e) => e.tabIndex >= 0);
  const a = document.activeElement;
  if (!a || a === document.body || a === document.documentElement)
    return {focusable, label: null};
  const r = a.getBoundingClientRect();
  const cs = getComputedStyle(a);
  const hit = document.elementFromPoint((r.left + r.right) / 2, (r.top + r.bottom) / 2);
  return {focusable, label: label(a), hidden: a.classList.contains(exempt),
          left: r.left, top: r.top, right: r.right, bottom: r.bottom,
          width: r.width, height: r.height, x: scrollX, y: scrollY,
          opacity: cs.opacity, visibility: cs.visibility, clip: cs.clip,
          clipPath: cs.clipPath, centre: hit ? label(hit) : null};
})()
"""
# Case (7), the paint (M3 PR 10 fix round 1, PR #33 review, finding 1): a
# box with a size can still draw nothing (clip, clip-path, opacity, an
# ancestor's opacity or filter, a covering element, and causes on no list),
# so the focused element's box is captured (Page.captureScreenshot, clipped
# to the box, scale 1), then again with the element's inline opacity at 0
# !important, then again restored. Equal first and second images mean the
# element contributes no visible pixel there, whatever the cause. Opacity,
# not visibility, because an element with visibility hidden loses focus;
# `transition: none` with it, so the change is instant both ways (opacity
# is restored and the style flushed before the transition, so no
# transition starts). The third image must equal the first (the box holds
# still), and the scroll position must be the same for all three. mode
# "hide" returns the inline values it replaced, which "restore" puts back.
REFLOW_PAINT_SCRIPT = r"""
(() => {
  const a = document.activeElement;
  const mode = %(mode)s, saved = %(saved)s;
  const props = ["opacity", "transition"];
  let old = null;
  if (a && a.style) {
    if (mode === "hide") {
      old = props.map((p) => [a.style.getPropertyValue(p), a.style.getPropertyPriority(p)]);
      a.style.setProperty("transition", "none", "important");
      a.style.setProperty("opacity", "0", "important");
    } else if (mode === "restore" && saved) {
      props.forEach((p, i) => {
        if (saved[i][0]) a.style.setProperty(p, saved[i][0], saved[i][1]);
        else a.style.removeProperty(p);
        getComputedStyle(a).opacity;
      });
    }
  }
  return {x: scrollX, y: scrollY, saved: old};
})()
"""
CHROME_FLAGS = (
    "--headless=new", "--remote-debugging-pipe", "--no-first-run",
    "--no-default-browser-check", "--disable-extensions", "--disable-sync",
    "--disable-background-networking", "--disable-component-update",
    "--disable-default-apps", "--hide-scrollbars", "--mute-audio",
    # Chrome's own log, verbose (ADR-0003 part 6): without --v=1 the log is
    # empty up to the first answer, so a startup stall would show nothing.
    "--enable-logging=stderr", "--v=1",
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


class NoAnswerError(UsageError):
    """No answer from Chrome within the budget, or the pipe closed before
    one (on the first answer of a launch also a closed pipe on the write).
    Exit 2 like every UsageError; cmd_reflow retries it only on the first
    answer of a launch (Browser.getVersion), never on a later call."""


class DevTools:
    """A minimal DevTools-protocol client over the two pipe ends."""

    def __init__(self, write_fd, read_fd):
        self.write_fd, self.read_fd = write_fd, read_fd
        self.next_id = 0
        self.buffer = b""
        self.events = []
        # When the current wait began, for the diagnostics only.
        self.sent_at = time.monotonic()
        # How often first_answer called on_wait.
        self.waited = 0
        # The budget of the current wait, for the diagnostics only.
        self.budget = REFLOW_TIMEOUT

    def close(self):
        for fd in (self.write_fd, self.read_fd):
            os.close(fd)

    def _read(self, deadline, budget, ticks=None, on_wait=None):
        # ticks: the times (time.monotonic) at which on_wait(elapsed) runs
        # while no message has come; only first_answer passes them. The
        # deadline stays fixed, so a probe never ends the wait early.
        self.budget = budget
        while b"\0" not in self.buffer:
            now = time.monotonic()
            left = deadline - now
            if left <= 0:
                raise NoAnswerError("reflow: no answer from Chrome within "
                                    f"{budget:g} s")
            if ticks and now >= ticks[0]:
                ticks.pop(0)
                self.waited += 1
                on_wait(now - self.sent_at)
                continue
            if ticks:
                left = min(left, ticks[0] - now)
            ready, _, _ = select.select([self.read_fd], [], [], left)
            if not ready:
                continue
            chunk = os.read(self.read_fd, 1 << 16)
            if not chunk:
                raise NoAnswerError("reflow: Chrome closed the DevTools pipe")
            self.buffer += chunk
        message, self.buffer = self.buffer.split(b"\0", 1)
        return json.loads(message)

    def _write(self, method, params, session):
        self.next_id += 1
        message = {"id": self.next_id, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        data = json.dumps(message).encode("utf-8") + b"\0"
        self.sent_at = time.monotonic()
        while data:
            data = data[os.write(self.write_fd, data):]

    def _answer(self, method, budget, ticks=None, on_wait=None):
        deadline = time.monotonic() + budget
        while True:
            reply = self._read(deadline, budget, ticks, on_wait)
            if reply.get("id") == self.next_id:
                if "error" in reply:
                    raise UsageError(f"reflow: {method} failed: {reply['error']}")
                return reply.get("result", {})
            if "method" in reply:
                self.events.append(reply)

    def send(self, method, params=None, session=None, budget=REFLOW_TIMEOUT):
        """A later call: a closed pipe on the write stays a BrokenPipeError
        (exit 2 through main, never retried)."""
        self._write(method, params, session)
        return self._answer(method, budget)

    def first_answer(self, budget, on_wait):
        """The launch's first answer, to Browser.getVersion, within budget
        seconds. A closed pipe on the write (Chrome exited before it read
        the command) is the same launch failure as a closed pipe on the
        read, whichever side sees the close first (#25 Known limit 2).
        on_wait(elapsed) runs at each REFLOW_PROBES-th of the budget while
        no answer has come; a protocol error is a UsageError, as in send."""
        self.budget = budget
        try:
            self._write("Browser.getVersion", None, None)
        except BrokenPipeError as exc:
            raise NoAnswerError("reflow: Chrome closed the DevTools pipe") from exc
        start = time.monotonic()
        ticks = [start + budget * k / REFLOW_PROBES for k in range(1, REFLOW_PROBES)]
        return self._answer("Browser.getVersion", budget, ticks, on_wait)

    def wait_event(self, method, session):
        self.sent_at = time.monotonic()
        deadline = time.monotonic() + REFLOW_TIMEOUT
        while True:
            for event in self.events:
                if event.get("method") == method and event.get("sessionId") == session:
                    self.events.remove(event)
                    return event
            reply = self._read(deadline, REFLOW_TIMEOUT)
            if "method" in reply:
                self.events.append(reply)


def start_chrome(chrome, profile, log):
    """Chrome headless with its DevTools pipe on fds 3 and 4 of the child
    and its stdout and stderr in the file log. Returns (process, DevTools)."""
    to_chrome_r, to_chrome_w = os.pipe()
    from_chrome_r, from_chrome_w = os.pipe()
    # Move all four ends above 10, so none of them is fd 3 or 4.
    ends = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10)
            for fd in (to_chrome_r, to_chrome_w, from_chrome_r, from_chrome_w)]
    for fd in (to_chrome_r, to_chrome_w, from_chrome_r, from_chrome_w):
        os.close(fd)
    to_chrome_r, to_chrome_w, from_chrome_r, from_chrome_w = ends
    # The same for the log (#25 Known limit 1): the log may sit on fd 3 or 4
    # itself, and the dup2 below would then point Chrome's output at a pipe
    # end (on 3 it was lost, on 4 it went into the DevTools pipe). The
    # duplicate above 10 is Chrome's stdout and stderr.
    log_fd = fcntl.fcntl(log.fileno(), fcntl.F_DUPFD_CLOEXEC, 10)
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
            stdin=subprocess.DEVNULL, stdout=log_fd, stderr=log_fd, pass_fds=(3, 4))
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
        os.close(log_fd)
    return process, DevTools(to_chrome_w, from_chrome_r)


# Stall diagnostics of the reflow launch (ADR-0003 part 6, #24). Read-only:
# /proc and the Chrome logs, every read catches only OSError and ValueError,
# and nothing here changes an exit code, a retry or a finding.

def proc_text(path):
    """The text of a /proc (or log) file, or None when it is unreadable."""
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    except OSError:
        return None


def proc_stat(pid):
    """(name, state, parent PID) from /proc/<pid>/stat, or None."""
    text = proc_text(f"/proc/{pid}/stat")
    if text is None:
        return None
    head, sep, rest = text.rpartition(")")
    fields = rest.split()
    if not sep or "(" not in head or len(fields) < 2:
        return None
    try:
        return head.partition("(")[2], fields[0], int(fields[1])
    except ValueError:
        return None


def proc_tree(root):
    """root and every descendant, from the parent PIDs in /proc/*/stat."""
    children = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        names = []
    for name in names:
        if name.isascii() and name.isdigit():
            stat = proc_stat(int(name))
            if stat is not None:
                children.setdefault(stat[2], []).append(int(name))
    tree, todo = [], [root]
    while todo:
        pid = todo.pop(0)
        if pid not in tree:
            tree.append(pid)
            todo.extend(sorted(children.get(pid, [])))
    return tree


def pressure_avg10(kind):
    """The `some avg10` value of /proc/pressure/<kind>, or ?."""
    for line in (proc_text(f"/proc/pressure/{kind}") or "").splitlines():
        fields = line.split()
        if fields and fields[0] == "some":
            for field in fields[1:]:
                key, _, value = field.partition("=")
                if key == "avg10":
                    return value
    return "?"


def reflow_probe(process, tools, where, elapsed):
    """One stderr line on a launch that has not answered: the budget of the
    wait (tools.budget, the value first_answer or the later call got), the
    load, the pressure stall figures and each Chrome process with its
    state, kernel wait channel and syscall number. A process in state D under I/O
    pressure points at the disk; an idle Chrome blocked in a wait points
    outside the VM."""
    load = (proc_text("/proc/loadavg") or "").split()
    parts = [f"load {load[0] if load else '?'}",
             "pressure some avg10 " + " ".join(
                 f"{kind} {pressure_avg10(kind)}" for kind in ("cpu", "io", "memory"))]
    for pid in proc_tree(process.pid):
        stat = proc_stat(pid) or ("?", "?", 0)
        wchan = (proc_text(f"/proc/{pid}/wchan") or "").strip() or "?"
        syscall = (proc_text(f"/proc/{pid}/syscall") or "").split()
        parts.append(f"process {pid} ({stat[0]}) {stat[1]} wchan {wchan} "
                     f"syscall {syscall[0] if syscall else '?'}")
    print(f"reflow: no answer after {elapsed:.2f} s {where} "
          f"(budget {tools.budget:g} s): " + "; ".join(parts),
          file=sys.stderr, flush=True)


def tmpfs_mounted(path):
    """True when path is the mount point of a tmpfs, by the last mount of
    it in /proc/self/mounts (False when that is unreadable)."""
    real = os.path.realpath(path)
    found = False
    for line in (proc_text("/proc/self/mounts") or "").splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[1] == real:
            found = fields[2] == "tmpfs"
    return found


def reflow_log_dir(work):
    """The directory of a call's Chrome logs: a fresh one on the tmpfs
    REFLOW_LOG_DIR, or work itself where REFLOW_LOG_DIR is no tmpfs mount
    or no directory can be made in it."""
    if tmpfs_mounted(REFLOW_LOG_DIR):
        try:
            return Path(tempfile.mkdtemp(prefix="reflow-log-", dir=REFLOW_LOG_DIR))
        except OSError:
            pass
    return work


def log_lines(path):
    """The line count of a Chrome log, or ? when it is unreadable."""
    text = proc_text(path)
    return "?" if text is None else str(text.count("\n"))


def reflow_dump(path, attempt):
    """The last REFLOW_LOG_DUMP_BYTES of one launch's Chrome log, on stderr."""
    launch = f"launch {attempt} of {REFLOW_LAUNCH_ATTEMPTS}"
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as exc:
        print(f"reflow: Chrome log of {launch} unreadable: {exc}", file=sys.stderr)
        return
    lines = data.count(b"\n")
    print(f"reflow: Chrome log of {launch} ({lines} lines, {len(data)} bytes):",
          file=sys.stderr)
    text = data[-REFLOW_LOG_DUMP_BYTES:].decode("utf-8", errors="replace")
    if text:
        print(text, end="" if text.endswith("\n") else "\n", file=sys.stderr)
    sys.stderr.flush()


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


# Case (6) (M3 PR 10): S0 the script running (today's measurement), S1
# scripting on with the script blocked, S2 scripting off. They differ in
# what the parser and the CSS see: <noscript> content is markup and
# (scripting: none) matches only in S2. S1 stands for every way the script
# does not run with scripting on (a failed load, no clipboard API, an
# insecure context), because copy.js changes no style before it reveals.
REFLOW_STATES = ("with the script running", "with the script blocked",
                 "with scripting off")


def reflow_value(tools, session, expression, where):
    """The value of a page expression (Runtime.evaluate, returnByValue)."""
    reply = tools.send("Runtime.evaluate", {"expression": expression,
                                            "returnByValue": True}, session=session)
    if "exceptionDetails" in reply:
        raise UsageError(f"reflow: the focus script failed on {where}: "
                         f"{reply['exceptionDetails'].get('text')}")
    return reply.get("result", {}).get("value") or {}


def png_rows(data):
    """(width, height, channels, the decoded rows) of a screenshot: an 8-bit,
    non-interlaced RGB or RGBA PNG, as Chrome writes it (no other is read)."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise UsageError("reflow: a screenshot is not a PNG")
    pos, idat, head = 8, [], None
    while pos + 8 <= len(data):
        size, kind = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + size]
        pos += 12 + size
        if kind == b"IHDR":
            head = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT":
            idat.append(body)
        elif kind == b"IEND":
            break
    if head is None or head[2] != 8 or head[3] not in (2, 6) or head[6]:
        raise UsageError(f"reflow: a screenshot PNG is not 8-bit RGB or RGBA, "
                         f"non-interlaced ({head})")
    width, height, channels = head[0], head[1], 4 if head[3] == 6 else 3
    raw, stride, rows = zlib.decompress(b"".join(idat)), width * channels, []
    prev = bytearray(stride)
    for y in range(height):
        start = y * (stride + 1)
        kind, line = raw[start], bytearray(raw[start + 1:start + 1 + stride])
        for i in range(stride):
            left = line[i - channels] if i >= channels else 0
            up = prev[i]
            if kind == 1:
                line[i] = (line[i] + left) & 255
            elif kind == 2:
                line[i] = (line[i] + up) & 255
            elif kind == 3:
                line[i] = (line[i] + (left + up) // 2) & 255
            elif kind == 4:
                corner = prev[i - channels] if i >= channels else 0
                guess = left + up - corner
                pa, pb, pc = abs(guess - left), abs(guess - up), abs(guess - corner)
                line[i] = (line[i] + (left if pa <= pb and pa <= pc
                                      else up if pb <= pc else corner)) & 255
            elif kind:
                raise UsageError(f"reflow: a screenshot PNG has filter {kind}")
        rows.append(line)
        prev = line
    return width, height, channels, rows


def png_difference(first, second):
    """The largest difference of one channel of one pixel between two
    screenshots (base64 PNG), 255 when their sizes differ."""
    a = png_rows(base64.b64decode(first))
    b = png_rows(base64.b64decode(second))
    if a[:3] != b[:3]:
        return 255
    return max((max(abs(x - y) for x, y in zip(ra, rb)) for ra, rb in zip(a[3], b[3])
                if ra), default=0)


# Case (6) per class of HIDDEN_UNTIL_SCRIPT (M4 PR 3, ADR-0005 part 6): the
# tag its elements are counted on (None: any element) and the display wanted
# in S0, the page loaded with its script running and no visitor action.
# Every class is display none in S1 and S2. A Copy button is revealed in S0;
# the search results stay hidden in S0, because no query was made.
# The noun names an element in the findings.
REFLOW_HIDDEN = {"copy": ("button", "shown", "Copy button"),
                 "search-out": (None, "hidden", "search result element")}


def reflow_hidden_class(tag, classes, cls):
    """An element of tag (lowercase) and class list counts for cls."""
    want_tag = REFLOW_HIDDEN[cls][0]
    return cls in classes and (want_tag is None or tag == want_tag)


def reflow_copy_buttons(tools, session):
    """Case (6): ({class: [(label, computed display)]} of every element that
    counts for a class of REFLOW_HIDDEN (a <button> whose class holds
    `copy`, any element whose class holds `search-out`), [(label, type)] of
    every shadow root that is not the browser's own), read from the whole
    tree with the DOM and CSS domains, which run no page script. Shadow
    roots are pierced; template content is inert and skipped."""
    root = tools.send("DOM.getDocument", {"depth": -1, "pierce": True},
                      session=session)["root"]
    buttons, shadows, stack = {cls: [] for cls in REFLOW_HIDDEN}, [], [root]
    while stack:
        item = stack.pop()
        raw = item.get("attributes") or []
        attrs = dict(zip(raw[::2], raw[1::2]))
        label = item.get("localName") or item.get("nodeName", "?").lower()
        if attrs.get("id"):
            label += "#" + attrs["id"]
        classes = [c for c in re.split(r"[\t\n\f\r ]+", attrs.get("class", "")) if c]
        label += "".join("." + c for c in classes)
        for cls in REFLOW_HIDDEN:
            if item.get("nodeType") == 1 \
                    and reflow_hidden_class(item.get("localName"), classes, cls):
                style = tools.send("CSS.getComputedStyleForNode",
                                   {"nodeId": item["nodeId"]},
                                   session=session).get("computedStyle", [])
                display = next((p.get("value") for p in style
                                if p.get("name") == "display"), "?")
                buttons[cls].append((label, display))
        for shadow in item.get("shadowRoots") or []:
            if shadow.get("shadowRootType") != "user-agent":
                shadows.append((label, shadow.get("shadowRootType", "?")))
        children = list(item.get("children") or [])
        children += item.get("shadowRoots") or []
        if item.get("contentDocument"):
            children.append(item["contentDocument"])
        stack.extend(reversed(children))
    return buttons, shadows


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
    logs = work
    server = None
    processes = []
    log_path = None
    launched = False
    n_items = 0
    n_copy = n_search = n_reveals = n_revealed = n_heads = 0
    try:
        # The launch: start Chrome and wait for its first answer, within
        # args.launch_timeout (REFLOW_LAUNCH_TIMEOUT). Only the two launch
        # failures of that answer (NoAnswerError: no answer within the
        # budget, or the pipe closed before it, on the write or the read)
        # start a fresh Chrome, with its own profile and log; a protocol
        # error here, every later call and every page finding fail as
        # before. The local server starts only after the launch. The
        # diagnostics (probes, the timing line, dumps) only print. Chrome's
        # logs go to a tmpfs (REFLOW_LOG_DIR), so a disk stall cannot block
        # Chrome's log writes unless memory runs short (reclaim can then
        # wait on the disk, through swap or through other files'
        # writeback; the probe line reports memory pressure).
        logs = reflow_log_dir(work)
        for attempt in range(1, REFLOW_LAUNCH_ATTEMPTS + 1):
            where = f"on launch {attempt} of {REFLOW_LAUNCH_ATTEMPTS}"
            log_path = logs / f"chrome-{attempt}.log"
            with open(log_path, "wb") as log:
                process, tools = start_chrome(chrome, work / f"profile-{attempt}", log)
            processes.append(process)
            probe = functools.partial(reflow_probe, process, tools, where)
            try:
                version = tools.first_answer(args.launch_timeout, probe)
            except NoAnswerError as exc:
                reflow_probe(process, tools, where, time.monotonic() - tools.sent_at)
                process.kill()
                process.wait()
                tools.close()
                if attempt == REFLOW_LAUNCH_ATTEMPTS:
                    raise UsageError(f"{exc} {where}") from exc
                reflow_dump(log_path, attempt)
                print(f"{exc} {where}; starting it again with a fresh profile",
                      file=sys.stderr)
                continue
            print(f"reflow: first answer after {time.monotonic() - tools.sent_at:.2f} s "
                  f"{where} (budget {tools.budget:g} s, Chrome log "
                  f"{log_lines(log_path)} lines in {logs.parent})", file=sys.stderr,
                  flush=True)
            if tools.waited:
                reflow_dump(log_path, attempt)
            launched = True
            break
        SiteHandler.errors = []
        handler = functools.partial(SiteHandler, directory=str(public))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        origin = f"http://127.0.0.1:{server.server_address[1]}"

        print(f"reflow: {version.get('product', '?')}, viewport {REFLOW_WIDTH}x"
              f"{REFLOW_HEIGHT} CSS px, mobile", flush=True)
        target = tools.send("Target.createTarget", {"url": "about:blank"})["targetId"]
        session = tools.send("Target.attachToTarget",
                             {"targetId": target, "flatten": True})["sessionId"]
        tools.send("Page.enable", session=session)
        # Cases (6) and (7) (M3 PR 10): the DOM and CSS domains read the
        # tree and computed styles without running page script, so they
        # work with scripting off too; focus emulation lets a headless page
        # take keyboard focus.
        tools.send("DOM.enable", session=session)
        tools.send("CSS.enable", session=session)
        tools.send("Emulation.setFocusEmulationEnabled", {"enabled": True},
                   session=session)
        tools.send("Emulation.setDeviceMetricsOverride",
                   {"width": REFLOW_WIDTH, "height": REFLOW_HEIGHT,
                    "screenWidth": REFLOW_WIDTH, "screenHeight": REFLOW_HEIGHT,
                    "deviceScaleFactor": 1, "mobile": True}, session=session)
        script = REFLOW_SCRIPT % {"width": REFLOW_WIDTH, "limit": REFLOW_NAMED,
                                  "exempt": json.dumps(VISUALLY_HIDDEN),
                                  "eps": json.dumps(REFLOW_EPSILON)}
        def load(url):
            tools.events.clear()
            nav = tools.send("Page.navigate", {"url": url}, session=session)
            if nav.get("errorText"):
                return nav["errorText"]
            tools.wait_event("Page.loadEventFired", session)
            return None

        def copy_state(where, state, first):
            """Case (6) in one state, per class of REFLOW_HIDDEN: every
            element's computed display, the count against the page's file,
            and in S1 the shadow roots. first: S0, where a class wants its
            REFLOW_HIDDEN display; in S1 and S2 every class is hidden."""
            found, shadows = reflow_copy_buttons(tools, session)
            for cls, (_, s0_want, noun) in REFLOW_HIDDEN.items():
                until = HIDDEN_UNTIL_SCRIPT[cls][1]
                want = s0_want if first else "hidden"
                if len(found[cls]) != len(static_hidden[cls]):
                    findings.add(where, f"(6) {state}: the browser sees {len(found[cls])} "
                                 f"{noun}(s), the page's file holds "
                                 f"{len(static_hidden[cls])}; the browser built another "
                                 "tree than the static checks read (inert template "
                                 "content, a shadow root, foreign content)")
                for label, display in found[cls]:
                    if want == "hidden" and display != "none":
                        findings.add(where, f"(6) {state}: {noun} {show(label, 80)} is "
                                     f"shown (display {show(display)}); it must stay hidden "
                                     f"until {until}"
                                     + ("" if first else ", and its script does not run"))
                    elif want == "shown" and display == "none":
                        findings.add(where, f"(6) {state}: {noun} {show(label, 80)} is "
                                     "still hidden (display none) after the script ran; a "
                                     "rule hides it for good, so its hiding is not shown to "
                                     f"depend on the script ({until})")
            if state == REFLOW_STATES[1]:
                for label, kind in shadows:
                    findings.add(where, f"(6) {state}: {show(label, 80)} holds a{'n' if kind == 'open' else ''} "
                                 f"{kind} shadow root; the page script and the static "
                                 "checks see no element inside it (ADR-0003 part 6)")

        def reveal_paint(where, focus, box):
            """Case (7), the paint: the focused element's box captured as is,
            with the element at opacity 0, and restored (REFLOW_PAINT_SCRIPT).
            The scroll position holds for all three, the first and third
            images are equal, and the first and second differ."""
            clip = {"x": focus["left"] + focus["x"], "y": focus["top"] + focus["y"],
                    "width": focus["width"], "height": focus["height"], "scale": 1}
            shots, scrolls, saved = [], [], None
            for mode in ("hide", "restore", "read"):
                shots.append(tools.send("Page.captureScreenshot",
                                        {"format": "png", "clip": clip},
                                        session=session).get("data"))
                state = reflow_value(tools, session, REFLOW_PAINT_SCRIPT % {
                    "mode": json.dumps(mode), "saved": json.dumps(saved)}, where)
                scrolls.append((state.get("x"), state.get("y")))
                saved = state.get("saved") if mode == "hide" else saved
            label = show(focus["label"], 80)
            if any(xy != (focus["x"], focus["y"]) for xy in scrolls):
                findings.add(where, f"(7) the page scrolled while the paint of the focused "
                             f"{label} was compared (from x {focus['x']}, y {focus['y']} to "
                             f"{', '.join(f'x {x}, y {y}' for x, y in scrolls)}); the "
                             "revealed skip link must hold still on keyboard focus")
            elif (noise := png_difference(shots[0], shots[2])) > REFLOW_PAINT_TOLERANCE:
                findings.add(where, f"(7) the box of the focused {label} ({box}) changes by "
                             f"itself: two screenshots of it with the same style differ by "
                             f"up to {noise} of 255 in a channel (tolerance "
                             f"{REFLOW_PAINT_TOLERANCE}), so its paint cannot be compared; "
                             "the revealed skip link must hold still on keyboard focus")
            elif (paint := png_difference(shots[0], shots[1])) <= REFLOW_PAINT_TOLERANCE:
                findings.add(where, f"(7) the focused {label} ({box}) paints no visible "
                             "pixel in its box: the box looks the same with the element at "
                             f"opacity 0 (largest difference {paint} of 255, tolerance "
                             f"{REFLOW_PAINT_TOLERANCE}; computed opacity {show(focus.get('opacity'))}, "
                             f"visibility {show(focus.get('visibility'))}, clip "
                             f"{show(focus.get('clip'))}, clip-path "
                             f"{show(focus.get('clipPath'))}; at its centre the page shows "
                             f"{show(focus.get('centre') or 'nothing', 80)}), so it is "
                             "clipped, transparent, filtered or covered, and the skip link "
                             "stays invisible on keyboard focus (WCAG 2.2 SC 2.4.7)")

        focus_script = REFLOW_FOCUS_SCRIPT % {"exempt": json.dumps(VISUALLY_HIDDEN)}
        for rel, path in pages:
            where = f"public/{rel}"
            elements = parse_page((public / rel).read_text(encoding="utf-8",
                                                           errors="replace")).elements
            static_hidden = {
                cls: [attrs for tag, attrs in elements if reflow_hidden_class(
                    tag, re.split(r"[\t\n\f\r ]+", attrs.get("class") or ""), cls)]
                for cls in REFLOW_HIDDEN}
            error = load(origin + path)
            if error:
                findings.add(where, f"did not load: {error}")
                continue
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
            # (9) the head in the browser, S0 (fix round 8).
            seen = reflow_value(tools, session, REFLOW_HEAD_SCRIPT, where)
            parsed = static_head((public / rel).read_text(encoding="utf-8", errors="replace"))
            if seen.get("head") != parsed:
                findings.add(where, f"(9) the browser's head holds {show(seen.get('head'), 300)}; "
                             f"the file's head is {show(parsed, 300)}, which rule (m) pins: the "
                             "browser read the page another way than the static checks (an "
                             "implied end of the head, foreign content), so an element the "
                             "head needs did not reach it")
            else:
                n_heads += 1
            for label in seen.get("stray", []):
                findings.add(where, f"(9) the browser has a {show(label, 120)}; script, link, "
                             "meta and base work only as HTML children of document.head")
            for label in seen.get("cspOutside", []):
                findings.add(where, f"(9) the browser has the CSP meta as a {show(label, 120)}; "
                             "outside document.head the policy is ignored")
            # (6) S0: the script ran, so every Copy button is revealed, and
            # the search results stay hidden: no query was made.
            copy_state(where, REFLOW_STATES[0], True)
            # (7) The skip link's reveal applies on keyboard focus: one Tab
            # press from the loaded page focuses the first focusable
            # element, which must carry the class and grow past 1 x 1 px
            # inside the viewport.
            focus = reflow_value(tools, session, focus_script, where)
            if focus.get("focusable"):
                for kind in ("keyDown", "keyUp"):
                    tools.send("Input.dispatchKeyEvent", dict(REFLOW_TAB_KEY, type=kind),
                               session=session)
                focus = reflow_value(tools, session, focus_script, where)
                n_reveals += 1
                box = (f"{focus.get('width', 0):.1f} x {focus.get('height', 0):.1f} CSS px at "
                       f"x {focus.get('left', 0):.1f} to {focus.get('right', 0):.1f}, y "
                       f"{focus.get('top', 0):.1f} to {focus.get('bottom', 0):.1f}")
                if not focus.get("hidden"):
                    findings.add(where, f"(7) one Tab press focuses "
                                 f"{show(focus.get('label') or 'nothing', 80)}, not the "
                                 "element of class visually-hidden; the skip link must be "
                                 "the first focusable element (WCAG 2.2 SC 2.4.1, 2.4.7)")
                elif not (focus["width"] > REFLOW_REVEAL_MIN
                          and focus["height"] > REFLOW_REVEAL_MIN):
                    findings.add(where, f"(7) the focused {show(focus['label'], 80)} is "
                                 f"{box}; its :focus reveal does not apply, so the skip link "
                                 "stays hidden on keyboard focus (WCAG 2.2 SC 2.4.7)")
                elif focus["left"] < -REFLOW_EPSILON or focus["top"] < -REFLOW_EPSILON \
                        or focus["right"] > REFLOW_WIDTH + REFLOW_EPSILON \
                        or focus["bottom"] > REFLOW_HEIGHT + REFLOW_EPSILON:
                    findings.add(where, f"(7) the focused {show(focus['label'], 80)} is "
                                 f"{box}, outside the {REFLOW_WIDTH} x {REFLOW_HEIGHT} "
                                 "viewport; the revealed skip link must be on screen")
                else:
                    reveal_paint(where, focus, box)
            # (6) In S0, each search result section revealed must be
            # perceivable and operable (REFLOW_REVEAL_SCRIPT).
            if static_hidden["search-out"]:
                revealed = reflow_value(tools, session, REFLOW_REVEAL_SCRIPT % {
                    "ids": json.dumps([sid for sid, _ in SEARCH_SECTIONS])}, where)
                if not revealed.get("present"):
                    findings.add(where, f"(6) {REFLOW_STATES[0]}: the page has search result "
                                 f"elements but no #{SEARCH_RESULTS} the browser can reveal")
                for item in revealed.get("sections", []):
                    sid = item.get("id")
                    if item.get("missing"):
                        findings.add(where, f"(6) revealed: no #{sid} to reveal")
                        continue
                    n_revealed += 1
                    if not item.get("region"):
                        findings.add(where, f"(6) revealed #{sid}: #{SEARCH_RESULTS} is not "
                                     "visible once revealed (checkVisibility with opacity and "
                                     "visibility); a wrapper, popover or style hides it, so "
                                     "the answer never shows (ADR-0005 part 4)")
                    for label in item.get("hiddenText", []):
                        findings.add(where, f"(6) revealed #{sid}: {show(label, 80)} holds "
                                     "text but is not visible (checkVisibility with opacity "
                                     "and visibility); the revealed answer must show all of "
                                     "its text (ADR-0005 part 4)")
                    if not item.get("focus"):
                        findings.add(where, f"(6) revealed #{sid}: focus does not move to its "
                                     f"heading (it is on {show(item.get('focused'), 80)}); "
                                     "an inert or hidden ancestor or a missing heading "
                                     "keeps the answer from screen readers and keyboards")
                    if not item.get("hit"):
                        findings.add(where, f"(6) revealed #{sid}: the centre of its heading "
                                     f"hits {show(item.get('hitLabel'), 80)}, not the "
                                     "heading; an overlay, pointer-events or a hidden "
                                     "heading keeps the answer from the visitor")
            # (6) S1: scripting on, the script URLs blocked.
            tools.send("Network.enable", session=session)
            tools.send("Network.setBlockedURLs", {"urls": list(REFLOW_BLOCKED_SCRIPTS)},
                       session=session)
            error = load(origin + path)
            if error:
                findings.add(where, f"did not load with the script blocked: {error}")
            else:
                copy_state(where, REFLOW_STATES[1], False)
            tools.send("Network.setBlockedURLs", {"urls": []}, session=session)
            tools.send("Network.disable", session=session)
            # (6) S2: scripting off.
            tools.send("Emulation.setScriptExecutionDisabled", {"value": True},
                       session=session)
            error = load(origin + path)
            if error:
                findings.add(where, f"did not load with scripting off: {error}")
            else:
                copy_state(where, REFLOW_STATES[2], False)
            tools.send("Emulation.setScriptExecutionDisabled", {"value": False},
                       session=session)
            n_copy += len(static_hidden["copy"])
            n_search += len(static_hidden["search-out"])
        for error in sorted(set(SiteHandler.errors)):
            findings.add("public", f"the local server answered {error}; a page was "
                         "measured without one of its files")
        tools.send("Browser.close")
    except BaseException as exc:
        # Diagnostics of the error that ends the run; the error itself is
        # re-raised unchanged. A later call without an answer gets one probe
        # of the Chrome that did not answer, before the reap below.
        if launched and isinstance(exc, NoAnswerError):
            reflow_probe(process, tools, where, time.monotonic() - tools.sent_at)
        if log_path is not None:
            reflow_dump(log_path, attempt)
        raise
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        for process in processes:
            try:
                process.wait(timeout=REFLOW_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if logs != work:
            shutil.rmtree(logs, ignore_errors=True)
        shutil.rmtree(work, ignore_errors=True)
    return findings.report(f"reflow checked: {len(pages)} pages at {REFLOW_WIDTH} "
                           f"CSS px, {n_items} words and replaced elements; Copy buttons "
                           f"hidden without the script: {n_copy} in 2 states; search "
                           f"results hidden until a query: {n_search} in 3 states, "
                           f"{n_revealed} sections revealed and reachable; "
                           f"skip-link reveals: {n_reveals}; heads as parsed: {n_heads}")


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
# Closed world for hugo.toml (fix round 2, review2 2): every key it may set,
# with the value it has today; a missing key keeps Hugo's default. Any other
# key fails, so config that prints on a page (the goldmark typographer
# quotes and footnote backlinks, [sitemap], outputFormats, menus,
# copyright, cascade, ...) cannot appear without a guard change. The
# identity keys title, params.operator and params.contact (copy, D1) and
# params.csp (the CSP, checked by site) take any string.
HUGO_CONFIG_PINNED = {
    "baseURL": "https://interviewscam.com/",
    "locale": "en",
    "disableKinds": ["taxonomy", "term", "rss"],
    "disableHugoGeneratorInject": True,
    "refLinksErrorLevel": "ERROR",
    # The data feed /feed.json (ADR-0004 part 7, M3 PR 8): the home page's
    # second output and its format. A plain-text JSON format prints only
    # what layouts/home.feed.json prints, and application/json is a
    # built-in media type, so no [mediaTypes] key is allowed.
    "outputs.home": ["html", "feed"],
    "outputFormats.feed.mediaType": "application/json",
    "outputFormats.feed.baseName": "feed",
    "outputFormats.feed.isPlainText": True,
    "markup.goldmark.renderer.unsafe": False,
    "markup.goldmark.extensions.linkify": False,
    "markup.highlight.noClasses": False,
    "security.exec.allow": ["none"],
    "security.http.urls": ["none"],
    **{f"privacy.{key}.disable": True for key in HUGO_PRIVACY},
}
HUGO_CONFIG_STRINGS = ("title", "params.operator", "params.contact", "params.csp")
# The HUGO_* environment variables the build may see: this repo's own tool
# variables (tools/pins.env, tools/fetch-tools.sh), which Hugo maps to no
# config key. Any other one (HUGO_TITLE, HUGO_PARAMS_OPERATOR,
# HUGO_MARKUP_..., HUGO_ENVIRONMENT) overrides config without touching
# hugo.toml, so it fails, in the guard's environment and in the text of a
# workflow or tools/ script. Hugo reads every name that starts with HUGO and
# takes the next character as the key delimiter, so HUGOxTITLE and
# HUGO.TITLE set the title too (review3 A2, measured with the pinned Hugo),
# and so do HUGO:TITLE and HUGO TITLE (review4 A2), and HUGO::TITLE and
# HUGO::PARAMS:OPERATOR (review5 A2: Hugo cuts the first character after HUGO
# as the delimiter and turns every further one into a key dot). The text scan
# takes HUGO, then either a run of letters, digits, '_', '.' and '-' that ends
# in a letter or digit, or one delimiter character d (any other but a newline
# or '=') and a run of letters, digits, '_' and d that ends in a letter or
# digit.
# hugo_build in check.sh refuses the same names at run time, where no text
# scan reaches (`export "HUGO_""TITLE=..."`).
HUGO_ENV_ALLOWED = ("HUGO_BIN", "HUGO_VERSION", "HUGO_URL", "HUGO_SHA256")
HUGO_ENV_NAME = re.compile(r"(?<![A-Za-z0-9_])HUGO(?:[A-Za-z0-9_.-]*[A-Za-z0-9]"
                           r"|([^A-Za-z0-9_.\n=-])(?:\1|[A-Za-z0-9_])*[A-Za-z0-9])")
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

    def flatten(table, prefix=""):
        for key, value in table.items():
            if isinstance(value, dict) and value:
                yield from flatten(value, f"{prefix}{key}.")
            else:
                yield f"{prefix}{key}", value

    for key, value in flatten(source):
        if key in HUGO_CONFIG_STRINGS:
            if not isinstance(value, str):
                findings.add(f"hugo.toml: {key}", f"must be a string, is {json.dumps(value)}")
        elif key not in HUGO_CONFIG_PINNED:
            findings.add(f"hugo.toml: {key}", "is not on the guard's list of hugo.toml "
                         "keys (HUGO_CONFIG_PINNED); config such as typographer quotes, "
                         "[sitemap] or outputFormats can print on a page, so a new key "
                         "comes with its own guard rule (review2 2)")
        else:
            expect(f"hugo.toml: {key}", value, HUGO_CONFIG_PINNED[key],
                   "the value pinned in HUGO_CONFIG_PINNED")
    for name in sorted(os.environ):
        if name.startswith("HUGO") and name not in HUGO_ENV_ALLOWED:
            findings.add(f"environment: {name}", "a HUGO_* variable overrides the Hugo "
                         "config without touching hugo.toml; only "
                         f"{', '.join(HUGO_ENV_ALLOWED)} may be set (review2 2)")

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
        origin = str(dig(mount, "source") or "").strip("/")
        if target == "content" or target.startswith("content/"):
            if dig(mount, "source") != "content" or target != "content":
                findings.add(where, f"content mount {json.dumps(mount)}: every "
                                    "content mount must be source \"content\" to "
                                    "target \"content\" (the records check reads "
                                    "only content/)")
        elif origin != target:
            # A layouts, assets, static, data or i18n mount from another
            # directory (or layoutDir, staticDir, ... set elsewhere) builds
            # files that sitecheck literals never reads and the fixture
            # build never copies (M3 PR 7 review).
            findings.add(where, f"mount {json.dumps(mount)}: every mount must read "
                                "the directory it targets (source equal to target); "
                                "sitecheck literals and the fixture build read only "
                                "those")
    # Git data is a copy source no check reads (.GitInfo prints commit
    # subjects), and the fixture build has no .git; Hugo omits false.
    gitinfo = effective.get("enablegitinfo")
    if gitinfo not in (None, False):
        findings.add(where, f"enableGitInfo is {json.dumps(gitinfo)}, must be false or "
                            "absent (commit data would be page copy outside "
                            "data/labels.toml)")
    csp = dig(source, "params", "csp")
    if dig(effective, "params", "csp") != csp:
        findings.add(where, "params.csp differs from params.csp in hugo.toml "
                            "(the single source of the CSP, D9)")
    # The identity keys print on every page; the effective value must be
    # the one the content-PR rule reviews in hugo.toml (review2 2).
    for path in (("title",), ("params", "operator"), ("params", "contact")):
        if dig(effective, *path) != dig(source, *path):
            findings.add(where, f"{'.'.join(path)} differs from hugo.toml (an "
                         "environment variable or another config source changes "
                         "copy, D1)")


def guard_hugo_env_names(root, files, findings):
    """No HUGO_* name outside HUGO_ENV_ALLOWED in a workflow or a tools/
    script (review2 2): a workflow env line or an export in check.sh would
    change the config every build reads."""
    for rel in files:
        if not (rel.startswith(".github/workflows/") or (
                rel.startswith("tools/") and rel != "tools/sitecheck.py")):
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            findings.add(rel, f"cannot read: {exc}")
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for match in HUGO_ENV_NAME.finditer(line):
                if match.group(0) not in HUGO_ENV_ALLOWED:
                    findings.add(f"{rel}:{n}", f"{match.group(0)}: a HUGO_* variable "
                                 "overrides the Hugo config without touching hugo.toml; "
                                 f"only {', '.join(HUGO_ENV_ALLOWED)} (review2 2)")


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


def guard_stylesheet_pins(root, findings):
    """The stylesheet source pin (M4 PR 3 fix round 4): every .css file
    under assets/ and static/ (any case, read from the disk, as Hugo reads
    it) and data/tokens.toml must be a key of STYLESHEET_SHA256 with the
    SHA-256 of its bytes. A pinned source that is missing is the build's
    failure, not this one's."""
    sources = []
    for top in STYLESHEET_SOURCE_DIRS:
        base = root / top
        if base.is_dir():
            sources += [p for p in sorted(base.rglob("*"))
                        if p.is_file() and p.suffix.lower() == ".css"]
    tokens = root / "data" / "tokens.toml"
    if tokens.is_file():
        sources.append(tokens)
    for path in sources:
        rel = path.relative_to(root).as_posix()
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            findings.add(rel, f"cannot read a stylesheet source: {exc}")
            continue
        pinned = STYLESHEET_SHA256.get(rel)
        if pinned is None:
            findings.add(rel, "a stylesheet source that is not pinned: every .css file "
                         "under assets/ and static/ and data/tokens.toml is pinned by its "
                         "SHA-256 in tools/sitecheck.py (STYLESHEET_SHA256), so adding one "
                         "is a tools/ change with the safety-net review (CSS is a reviewed "
                         "surface, M4 PR 3)")
        elif digest != pinned:
            findings.add(rel, f"the stylesheet source's SHA-256 is {digest}, not the one "
                         "pinned in tools/sitecheck.py (STYLESHEET_SHA256); a stylesheet "
                         "change updates the pin there, so it is a tools/ change with the "
                         "safety-net review (CSS is a reviewed surface, M4 PR 3)")


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
    guard_hugo_env_names(root, files, findings)
    guard_workflows(root, files, findings)
    guard_lighthouse_workflow(root, files, findings)
    guard_stylesheet_pins(root, findings)
    n_workflows = sum(f.startswith(".github/workflows/") for f in files)
    return findings.report(f"guard checked: {len(files)} files, "
                           f"{n_workflows} workflows")


# ---------------------------------------------------------------------------

def positive_seconds(text):
    """A finite number of seconds above 0 (argparse type: exit 2 otherwise)."""
    try:
        value = float(text)
    except ValueError:
        value = math.nan
    if not (math.isfinite(value) and value > 0):
        raise argparse.ArgumentTypeError(f"{text!r} is not a positive number of seconds")
    return value


def build_parser():
    """The command line. allow_abbrev=False on every parser (each subparser
    takes its own): argparse would read --no as --no-feed and switch rules
    11 to 13 off (M3 PR 8 review 2). The self-test walks this tree, so a new
    parser without it fails wiring/sitecheck-no-abbreviations."""
    parser = argparse.ArgumentParser(prog="sitecheck", description=__doc__.split("\n")[0],
                                     allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("records", allow_abbrev=False)
    p.add_argument("--root", default=".")
    p.add_argument("--schemas")
    p.set_defaults(func=cmd_records)
    p = sub.add_parser("site", allow_abbrev=False)
    p.add_argument("--records", required=True)
    p.add_argument("--schemas")
    p.add_argument("--no-built-pins", action="store_true")
    p.add_argument("public")
    p.set_defaults(func=cmd_site)
    p = sub.add_parser("render", allow_abbrev=False)
    p.add_argument("--records", required=True)
    p.add_argument("--schemas")
    p.add_argument("--fixtures")
    p.add_argument("--no-feed", action="store_true")
    p.add_argument("--no-search", action="store_true")
    p.add_argument("public")
    p.set_defaults(func=cmd_render)
    p = sub.add_parser("tokens", allow_abbrev=False)
    p.add_argument("--root", default=".")
    p.set_defaults(func=cmd_tokens)
    p = sub.add_parser("literals", allow_abbrev=False)
    p.add_argument("--root", default=".")
    p.set_defaults(func=cmd_literals)
    p = sub.add_parser("reflow", allow_abbrev=False)
    p.add_argument("--chrome", required=True)
    # Self-test only: check.sh never passes it, so CI keeps
    # REFLOW_LAUNCH_TIMEOUT.
    p.add_argument("--launch-timeout", type=positive_seconds,
                   default=REFLOW_LAUNCH_TIMEOUT)
    p.add_argument("public")
    p.set_defaults(func=cmd_reflow)
    p = sub.add_parser("guard", allow_abbrev=False)
    p.add_argument("--root", default=".")
    p.add_argument("--hugo")
    p.set_defaults(func=cmd_guard)
    p = sub.add_parser("lighthouse", allow_abbrev=False)
    p.add_argument("--reports", required=True)
    p.add_argument("--version", required=True)
    p.set_defaults(func=cmd_lighthouse)
    p = sub.add_parser("tree-digest", allow_abbrev=False)
    p.add_argument("lockfile")
    p.add_argument("--expect", required=True)
    p.set_defaults(func=cmd_tree_digest)
    return parser


def main(argv):
    parser = build_parser()
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
