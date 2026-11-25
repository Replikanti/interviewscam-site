# ADR-0010: Data licence, CC BY 4.0 for the records and the feed

## Status

Accepted, 2026-11-25 (operator, Replikanti/interviewscam#19, STOP 1: the licence is CC BY 4.0 and the scope is as recommended in the plan). Nothing in this ADR is legally reviewed. The M6 legal review (Replikanti/interviewscam#7) reads it before launch and can still change the licence, because no copy of the data has been licensed before then (Context).

## Context

- **The feed and its page exist, the terms do not.** M3 (ADR-0004 part 7) publishes `/feed.json` and the page `/data-feed/` for researchers and tools (SPEC §2), and states no terms. ADR-0004 part 7 deferred the licence to Replikanti/interviewscam#19, and SPEC §10 listed data licensing as out of scope for the MVP. A careful re-user, such as a job board or a security vendor, cannot tell what it may take.
- **What a record holds.** Mostly facts: domains, URLs, hashes, handles, file names and dates. Copyright does not protect a fact. On top of the facts each record holds text the operator wrote (the summary, the evidence summary, the state basis and the body), and the registry as a whole is a compilation.
- **The database right.** In the EU the maker of a database in which there has been a substantial investment in obtaining, verifying or presenting the contents holds a sui generis right against the extraction of a substantial part (Directive 96/9/EC, Art. 7; in Czech law §§ 88 to 94 of the Copyright Act, 121/2000 Coll.). Without a licence, extracting a substantial part of the registry is the operator's to allow, which is the situation today.
- **Nothing is published yet.** Checked on 2026-11-25: GitHub Pages is off in both repos (the Pages API answers 404) and `interviewscam.com` has no A record at a public resolver. No record and no feed has ever been served, so the licence takes effect at the M6 launch (Replikanti/interviewscam#7).
- **What comparable feeds do.** Checked on 2026-11-25: abuse.ch states that Feodo Tracker, SSL Blacklist and YARAify are free for commercial and non-commercial use under CC0, while its other platforms (MalwareBazaar and URLhaus among them) set query and export limits sized for non-commercial use and route commercial use through Spamhaus.
- **Removals and hidden names are part of the record model.** A report can be removed, a name can be hidden on request (SPEC §6, D10), and a correction changes a record. A downstream copy taken before such a change keeps the old text unless its holder refreshes it.

## Decision

### 1. The licence is CC BY 4.0

The records as published and the feed are licensed under the Creative Commons Attribution 4.0 International licence (SPDX `CC-BY-4.0`, legal code `https://creativecommons.org/licenses/by/4.0/legalcode.en`). The licensor is the operator named under D1.

**Why:** the goal is that warnings reach candidates wherever they look (SPEC §2), and the channels that reach them at scale (job boards, platforms, security vendors and their blocklists) are commercial. CC BY 4.0 allows commercial reuse and adaptation, and its section 4 licenses the sui generis database right, so the compilation is covered, not only the text. Its attribution condition (section 3(a)) keeps a link back to the licensed material where that is reasonably practicable, which is how a correction, a removal or a hidden name later reaches a reader of a copy. Section 5 disclaims warranties, and section 2(b)(1) states that it grants no privacy or personality rights.
**Weak point:** a licence cannot require a re-user to keep the D6 state and the D10 label with a name, or to refresh its copy: a CC BY 4.0 with an added condition is no longer CC BY 4.0. The site can only ask (parts 3 and 4). The grant is irrevocable for every copy (part 4), so the raw data can never later be sold exclusively, only services around it.
**Rejected:**
- *CC0 1.0*: the widest reach, and some threat-intelligence feeds use it (Context). It loses the credit and the link back, so a downstream copy never leads a reader to a correction, a removal or a hidden name, and the operator has no lever against a copy that distorts a record.
- *CC BY-NC 4.0*: keeps a paid data channel open (SPEC §3 names possible data customers, and abuse.ch moved that way), but job boards, platforms and vendors are commercial, so it blocks exactly the channel that warns candidates at scale. "Non-commercial" is also unclear at the edges, and outside the EU the facts are free anyway, so it mostly deters the careful re-users.
- *ODbL 1.0*: a publicly used derived database must be offered under ODbL (share-alike), which deters the vendors and platforms that merge feeds, and the contents need a second licence beside it.
- *CC BY-SA 4.0*: the same share-alike friction as ODbL.
- *Terms of use of our own*: could require the D6 state, the D10 label and a refresh, but they need legal drafting (nothing is legally reviewed before M6), every re-user needs its own legal review of them, they have no SPDX id, and terms on a static file are hard to enforce.
- *No licence (the status quo)*: leaves re-users with the facts alone and leaves the issue's problem unsolved.

### 2. Scope: the records and the feed, nothing else

Covered: the report and campaign records as published, on their pages and in `/feed.json`, and the feed document itself. The same summary text appears in both places, so a licence for the feed alone would leave a reader of a page with no terms.

Not covered:
- the site's code, templates, checks and `schema/feed.schema.json` (the public code repo has no licence file, so they stay all rights reserved; the records never enter that repo, ADR-0007, so the two never mix);
- the copy of the static pages;
- the name, the wordmark and the favicon (section 2(b)(2) licenses no trademark);
- the cited third-party sources: only the citation data (title, publisher, date, URL) is the operator's, and an attribution statement given "as the source states it" (D6) is licensed only as far as the operator holds rights in it;
- the lookup pages a hash links to (MalwareBazaar, VirusTotal), which are third-party pages;
- any right in personal data (section 2(b)(1); part 3).

**Why:** the records and the feed are what the issue's readers want to reuse, and they are the operator's own work. The code is a separate question with its own trade-offs, and the static pages are the site's voice, not data. **Rejected:** a licence for the feed alone (the pages carry the same text without terms); one licence for the whole repo (it would decide the code's licence by accident, and the records are not in that repo).

### 3. Personal data and hidden names

The licence grants no rights in personal data. A re-user that processes a name in the data is a controller of its own processing under the GDPR and needs its own legal basis. A `null` name in the feed is hidden on request and stays hidden in a copy. `/data-feed/` asks re-users to show a recruiter name with its `name_label` and every name with its state, because the label and the state are what keep a name from reading as an accusation (D6, D10).

**Why:** a licence that seemed to pass on rights in a person's name would contradict D10 and the GDPR, and the CC licence itself excludes them. Asking for the label and the state is all a CC BY licence allows (part 1, weak point). **Rejected:** dropping persona names from the feed (search and the issue's readers need exactly these names, SPEC §5, and the label travels with them in `name_label`); a licence condition requiring the label (no longer CC BY 4.0).

### 4. Removals and corrections

The grant is irrevocable for every copy already shared (section 6(c) lets the licensor stop distributing, but that does not end the licence of a copy). The feed is always the current state of the registry: a removed record leaves it, a hidden name becomes `null` and a corrected field changes. `/data-feed/` asks re-users to fetch the feed at least once every 24 hours and to drop entries that are gone and names that became `null`. This request, the feed itself and the link back of part 1 are the reasonable steps of GDPR Art. 17(2) for a name erased or hidden here.

**Why:** a licence cannot recall a copy, so the only working mechanism is a current feed plus a request that re-users follow it. **Rejected:** tombstones for removed records in the feed (a removed slug can name a company, which is what the removal took away); a licence condition to refresh (no longer CC BY 4.0).

### 5. No warranty

Records describe artifacts as they were reported and reviewed on the stated date. They are not verdicts about a company or a person (D6, D7). `/data-feed/` says so next to the licence, and section 5 of the licence disclaims warranties.

**Why:** a re-user that drops the date and the state could turn a record into a claim the registry never made; saying it next to the licence puts it where a re-user reads before copying. **Rejected:** a separate disclaimer page (one more page to keep in step, read by fewer re-users).

### 6. The `license` field of the feed, and the version

`/feed.json` gets a top-level object `license` with `id` (`CC-BY-4.0`, the SPDX id), `name` (`Creative Commons Attribution 4.0 International`), `url` (the legal code above) and `terms_url` (`https://interviewscam.com/data-feed/#licence`, the section of `/data-feed/` with the scope and the requests). `schema/feed.schema.json` requires it and pins every sub-field with `const`, so render rule 11 fails a feed without it or with another value. `layouts/home.feed.json` builds it from the table `feed_license` of `data/labels.toml`. `version` stays 1, and the change list on `/data-feed/` gets no new line.

**Why the name `license`:** schema.org, DCAT, SPDX and GitHub all use the US spelling for this key; the prose of the site keeps "licence". **Why an object:** a reader gets the SPDX id for tools, the name for people, the legal code and the site's own terms. **Why the version stays:** an addition keeps it (SPEC §5), and until launch every feed change folds into version 1 (operator decision, #30 STOP 2, 2026-11-07, recorded in `CLAUDE.md`); no consumer exists before M6. **Rejected:** a bare string (no scope and no URL for the reader); a `terms` field holding prose (that is copy, and it would drift from the page); a new change-list line (no published version 1 exists to differ from).

### 7. Render rule 13 ties the page to the licence

Render rule 13 reads the four `const` values of `license` from the schema (rule 11 holds the feed to them) and requires:

- **The schema:** each of `id`, `name`, `url` and `terms_url` has a string `const`; a missing or non-string one is a finding, not an exception. `id`, `name` and `url` are one row of the table `FEED_LICENCES` in `tools/sitecheck.py` (SPDX id, name, legal code; one row today, `CC-BY-4.0`). `terms_url` is `https://interviewscam.com/data-feed/` with a non-empty fragment.
- **The page `/data-feed/`:** a visible `<code>` whose text is exactly the `id`; a visible `<a>` whose `href` is exactly the `url` and whose text is exactly the `name`, and no visible `<a>` to the `url` with other text; the first element whose `id` is the fragment (the one a browser scrolls to) is a visible `<h2>` with visible text, and the section it heads (its following siblings up to the next `<h1>` or `<h2>`) holds that link.
- **Every page:** no link, hidden ones included, names the host of the `url` or a subdomain of it, read as a browser reads it (case, a trailing dot, a protocol-relative form), except the `url` itself on `/data-feed/`. So the site links one licence, and only from the page that states it.

**Why:** rule 11 holds the feed to the schema's values, and this branch holds the schema to one known licence and the page to the same values, so the feed and the page cannot name different licences: an `id` or `name` changed without the `url`, a link text that names another licence, or a second licence link each fail. The terms the feed points to are the heading of the section that links the licence, not any element that happens to carry the id. The table costs a `tools/` change for a licence change, which is the safety-net review this decision should get anyway. **Rejected:** a rule 12 comparison of the feed with a constant of `sitecheck.py`, which rule 11's `const` would always shadow (the pattern of #30 Known limit 3); deriving the legal code from the SPDX id by a pattern (CC's URL scheme is not the SPDX scheme, and a pattern would accept ids no one reviewed); a check of the page's prose, beyond the link, the id and the heading (copy belongs to the D7 review, not to a pattern: a sentence that names another licence in plain text is the reviewer's, as every other page copy is).

## Numbers

| Number | Derivation | At another value |
|---|---|---|
| Licence version 4.0 | The first version of the CC licences whose own text licenses the sui generis database right (section 4); the 3.0 unported licences leave that right out, so the EU compilation would stay unlicensed. 4.0 is the current version. | 3.0: the database right is not covered. A later version: none exists today. |
| Feed `version` 1 | An addition keeps the version (SPEC §5), and before launch every change folds into version 1 (part 6). | 2: consumers would be told of a breaking change that is not one. |
| 79 field paths | 74 before this ADR (ADR-0004 part 7) plus `license`, `license.id`, `license.name`, `license.url` and `license.terms_url`. Render rule 13 counts them on every build and the four passing feed fixtures pin the count. | Any other count means a field is undocumented or documented without a schema field. |
| 7 required top-level fields | The 6 of ADR-0004 part 7 plus `license`. | 6: a feed without its terms validates. |
| 1 row in `FEED_LICENCES` | The one licence of part 1. A row is added only with a licence change (Consequences). | 0: rule 13 refuses every schema. 2 or more: the schema could switch to another reviewed licence without touching `tools/`, which is harmless but leaves an unused row to review. |
| Refresh at least every 24 hours | The feed's dates have day resolution, so a fetch more often than daily shows nothing new in the dates; a hidden name (D10 hide-first) should leave downstream copies within a day; one fetch a day of one JSON document costs a re-user nothing. | Longer: a hidden name stays in copies for days. Shorter: no gain at day resolution, and more load on the host for nothing. |

## Consequences

- From the M6 launch the grant is irrevocable for every copy shared; changing the licence later applies only to what is published after the change.
- The M6 legal review (Replikanti/interviewscam#7) reads this ADR and the `## Licence` section of `/data-feed/`; the privacy page may need a line on re-users as recipients, which that review decides.
- schema.org `Dataset` markup, which ADR-0004 part 8 rejected for want of a licence, can now be reconsidered in a separate issue.
- A licence for the code repo stays a separate decision.
- A change of the licence changes five places in one PR: the `feed_license` table of `data/labels.toml`, the four `const` values of `schema/feed.schema.json`, the `## Licence` section of `content/data-feed.md` (its link, the `id` in the field list, the heading), the row of `FEED_LICENCES` in `tools/sitecheck.py` (a safety-net change) and part 1 of this ADR; rules 11 and 13 fail until the first four agree on the id, the name, the legal code and the anchor. The prose of the section is held by the D7 review only (part 7).
