# ADR-0009: Link preview metadata and cards

## Status

Accepted, 2026-11-24 (operator, Replikanti/interviewscam#44, STOP 1: the SPEC §6 paragraph and the §5 pointer as written, report cards with the D6 state sentence, campaign cards with type, name, dates and brand). The plan splits the work into three PRs. This document holds parts 1 to 3, the text metadata of the first PR; the second PR adds parts 4 to 6 (the site card: generator, font and drawable set, layout and pixel check) and the third parts 7 and 8 (the record cards and their fallback), each with its Numbers.

## Context

- **A pasted link shows no card today.** Candidates share a report link in chat apps and on social networks, where the link shows only as a bare URL, because no page carries Open Graph or Twitter card metadata. The page's own `<title>` and meta description already state the record's name and summary, but card scrapers read their own keys first.
- **Card scrapers read the head only, with their own keys.** Open Graph names its keys with `<meta property>` (`og:title`, `og:description`, `og:url`, `og:type`, `og:site_name`); Twitter cards name theirs with `<meta name>` (`twitter:card`, `twitter:title`, `twitter:description`). A card travels without the page it came from, so its text carries the D6, D7 and D10 wording on its own.
- **`property` is an RDFa attribute, which ADR-0004 part 8 banned outright.** Render rule 8 refused every `property`, and its comment stated that the base layout had no Open Graph `<meta property>`, so no exception existed.
- **No check read `<meta content>` as a link.** lychee 0.24.2 does not extract URLs from `<meta content>` (`lychee-lib/src/extract/html/html5gum.rs`, `extract_urls_from_elem_attr`), so a broken or foreign `og:url` would pass the link check.
- **The pinned Nu Html Checker accepts the tags.** `html_check` runs the image's `vnu` CLI without `--schema`, which then validates against `html5-all.rnc` ("HTML + SVG + MathML + RDFa", validator/validator `resources/presets.txt`); `schema/html5/rdfa.rnc` defines `meta.property.elem` in the head, and `schema/html5/meta.rnc` takes any non-empty `name`. `tests/fixtures/html/pass-preview-meta/`, committed alone first, proved it on the pinned image in CI before any template printed a tag.

## Decision

### 1. The tag set and the source of each value

`layouts/_partials/preview-meta.html`, called from `baseof.html` right after the canonical link and only where the canonical link is (every page but the 404), prints, in this order: `og:type` = `website`, `og:site_name` = the site title, `og:title`, `og:description`, `og:url` = the page's permalink, `twitter:card` = `summary`, `twitter:title`, `twitter:description`; the Open Graph keys as `<meta property>`, the Twitter keys as `<meta name>`, each with `content`.

- **Title:** Home `home.title`; the `reports` and `campaigns` section pages their fixed title (`record-title.html`); a record page the `<title>` form (`record-title.html` with `head`: the label-first form of a visible persona, the hidden title of a hidden one); every other page its `.Title`. So the card title is always the page `<title>` without " · interviewscam.com".
- **Description:** on a record page `preview.description` over the record's fact and its summary, the fact being a report's D7 label (`report-label.html`) or a campaign's `preview.campaign_fact` over its first and last seen dates; every other page its meta description (`.Description`, or `site.description`).
- The two `twitter:` text values are the `og:` ones, so both scrapers show the same card. The values reach the attributes as returned partial values, never as printed partial output.

**Why:** the card is the page as a link. Reusing the `<title>` keeps the D10 label in front of a persona name where a card cuts a long title, as a search result does (ADR-0004 part 4). A report's summary alone states no D7 fact, and a card travels without the page's label, so the fact comes first; a campaign has no D7 label, and its dates are the facts its page states. `og:type` = `website` describes a page, never a person or an organisation (D6). `summary` is the card type without an image; the second PR changes it with the image. No tags on the 404: it answers for every missing URL, as it has no canonical link (ADR-0003 part 3).

**Rejected:** the summary alone as the record description (a card then states no D7 fact); `og:type` = `article` or `profile` (a claim about the content's kind, `profile` about a person); `twitter:site` and `twitter:creator` (an account claim the site does not make); `og:locale` (one language, the default); per-template blocks instead of one partial (four copies of the same rules).

### 2. One closed RDFa exception in render rule 8

`property` passes rule 8 only on a `<meta>` that is a direct child of `<head>`, carries exactly `property` and `content`, and whose `property` is one of the Open Graph keys of part 1 (`PREVIEW_PROPERTIES`, compared as written). Every other use of the six RDFa attributes (`property` on any other element, in the body, with another key, with another attribute such as `lang`, `prefix` on `<html>`) stays a finding, and so does a `rel` CURIE.

**Why:** Open Graph needs `property`, and the only RDFa a parser can build from these tags is a description of the page as a link, never of a record's subject, so it is no structured data in the sense of SPEC §5 and ADR-0004 part 8. Each condition closes a route back to general RDFa: the place (an RDFa processor reads `property` anywhere), the attribute set (`about`, `resource`, `typeof` or `lang` change the subject or the literal) and the closed key list.

**Rejected:** lifting the ban on `property` (any RDFa statement about any subject); an exception by prefix `og:` (`og:see_also`, `og:audio` and keys of other vocabularies such as `article:author` would follow); Twitter keys as `property` (Twitter documents `name`).

### 3. The checks

- **Site rule (o)** (`preview_problems`, on every HTML page of both builds): (o1) every page but `404.html` holds exactly one `<meta>` per key, matched on the exact attribute value, and `404.html` none; a `<meta>` whose `property`, `name` or `itemprop`, folded (`guard_fold`, ASCII whitespace stripped), starts with `og:` or `twitter:` without being a key on its own attribute is a finding; (o2) the fixed values; (o3) `og:url` is the page's canonical URL as a whole string; (o4) each `twitter:` text value equals its `og:` twin as a whole string; (o5) `og:title` is the `<title>` with exactly one trailing " · interviewscam.com" removed, and `og:site_name` is `interviewscam.com`; (o6) on every page that is not a record's own page, `og:description` equals the meta description, both whitespace-collapsed; (o7) no text value gives an R11 or R12 finding (a live dotted name, IPv4, `www.`, an email on a live host; only the site's own host is exempt) or, in any reading of `rendered_variants`, holds a live URL, a protocol-relative `//host`, or a `mailto:` or file scheme (`data:`, `blob:`, `javascript:`, `vbscript:`, `file:`) followed by a non-space, and `og:url` is the site origin, `/`, a path and nothing else; (o8) the number of `<meta>` start tags that a regular-expression scraper reads as a preview key in the raw page equals the number the parsed tree holds, so a key in a comment or an attribute value is a finding. With `--no-built-pins` (hand-made fixtures) only the look-alikes of (o1), (o7) and (o8) run. Rule (m) pins the eight children in place in the exact head.
- **Render rule 4** gains one own-page exemption: on a visible persona's own page the content of the single `og:title` and the single `twitter:title` meta, when it reads exactly the label-first `<title>` form. Every other copy of the form, on that page or any other, stays in the scan.
- **Render rule 8**: part 2.
- **Render rule 20** (`preview_record_problems`, on a record's own page with the real-build pins on, as rule 17): `og:title` is the record's `<title>` form, and `og:description` is `PREVIEW_DESCRIPTION` over the fact and the summary, where a report's fact is its D7 label and equals the page's `record-label` element, and a campaign's is `PREVIEW_CAMPAIGN_FACT` over `first_seen` and `last_seen`, which equal the page's First seen and Last seen facts. The two label strings are pinned a second time in `sitecheck.py`.
- **`literals`**: `property` joins `LITERALS_PLAIN_ATTRS` (its value is a key, never shown); a `property` meta on `LITERALS_META_PLAIN_PROPERTIES` (`og:type`, `og:url`, exactly as written) or a `name` meta on `LITERALS_META_PLAIN_NAMES` (now with `twitter:card`), with no other of `name`, `property`, `itemprop` and `http-equiv`, has content that is no text: one lowercase token or an action; every other `property` meta keeps visible content (L2 and the print sinks).

**Why:** a card is copy that travels without its page, so its text is held to the page it describes (o2 to o6, rule 20) and to D8 (o7), and no key can reach a scraper without a check reading it (o1, o8). Rule 20 needs the records, so it is a render rule; rule (o) needs only the built page, so it runs on every page. Rule 20 runs only with the real-build pins because the self-test's hand-made render pages predate the metadata, and both builds always run it (`wiring/render-report-pins`). The exemption of rule 4 is exactly the one the `<title>` already has, for the same reason. Rule (o5) compares whitespace-collapsed text because the `<title>` text the parser gives is collapsed.

**Rejected:** a key allowlist without look-alikes (a scraper may fold case or trim); checking the values only in render (the section and static pages have no record); counting scraper matches per attribute instead of per tag (a scraper reads a tag once).

## Numbers

None in parts 1 to 3: every value is a fixed string or derived from the page. The card size, the font metrics and the layout numbers come with parts 4 to 8.

## Consequences

- Every page but the 404 grows by eight head children; rule (m)'s exact head, the head fixtures of the self-test and every real-build fixture copy carry them.
- A wording change of a title, a description or the two `preview` labels changes the cards; the labels are pinned a second time in `sitecheck.py`, so such a change is a safety-net diff too.
- A card an app has already fetched keeps its old text until the app reads the page again. A removal or a hidden name therefore does not reach copies held by those apps (SPEC §6).
- The second PR replaces `twitter:card` = `summary` with `summary_large_image` and adds the image keys; the Nu Html Checker fixture already holds them.
