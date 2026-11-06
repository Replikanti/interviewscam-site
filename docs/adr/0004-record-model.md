# ADR-0004: Record model

## Status

Accepted, 2026-11-05 (operator, issue #4, STOP 1; decisions 1 to 9 of the plan, of which decision 3 was changed by the operator). Implements SPEC §5 and the Data rows of §8, changes D6 and D8, and amends ADR-0002 part 4 (the validator keywords and the `x-defang` modes) and ADR-0003 parts 2, 4 and 5 (the fixture build, the `lighthouse` path filter and the Lighthouse page set and timeout). The implementation lands in sequenced PRs under milestone 3 (#4): this ADR and the SPEC edits in PR 1, the record schema and record rules in PR 2, the built-site `render` check in PR 3, the record pages and the fixture build in PR 4, the feed in PR 5, the Copy button in PR 6.

*Amended 2026-11-06 (operator, #23 STOP 2; plan amendment on #4):* three PRs join before the feed: PR 5 the reflow launch retry (#24), PR 6 the own-record `render` rules, PR 7 the fixture-build inputs and the fixed copy. The feed is now PR 8 and the Copy button PR 9. Where this ADR says PR 5 for the feed or PR 6 for the Copy button, read PR 8 or PR 9.

## Context

Milestone 3 turns the M1 placeholder schemas into the real record model and builds the report, campaign and index pages, the JSON feed, structured data and the Copy button. Several of its choices change a §4 decision (D6, D8), so they are decided here before any code.

Inputs used as given: the carried M1 QA item on undeclared hostnames (issue #4, comment 6634957215), the carried M2 decisions 6, 8 and 10 (comment 6641089373) with the pick constraints of issue #3 comment 6627640277, the ADR-0003 consequence "M3 decides which record pages Lighthouse measures", and the Methodology copy approved at #3 STOP 2. That copy already commits to three things: a campaign family is named only when a cited source links the name or its artifacts, otherwise the page is unattributed; the family is named as the campaign that used the name; the site never labels anything a verified scam. M3 writes these into the SPEC and does not reopen them.

Verified facts (tree at `587245d`, pinned Hugo 0.169.0):

- `schema/report.schema.json` and `schema/campaign.schema.json` are M1 placeholders ("Milestone 3 replaces it").
- `VALIDATION_KEYWORDS` in `tools/sitecheck.py` (`schema_problems`) has no `if`/`then`/`else`, `oneOf`, `allOf`, `dependentRequired` or `minimum`. Any of them fails closed today.
- `load_records` skips `_index.md` entirely, so section pages get no body or URL rule (the gap in the carried M1 item).
- The guard asserts neither `disableKinds` nor `outputs`, so a JSON output format relaxes no ADR-0001 hardening key. The `hugo.toml` comment and the ADR-0001 table both say "Milestone 3 revisits" `disableKinds`.
- Checked with the pinned binary on a scratch copy:
  - A record section without a section layout fails the build under `--panicOnWarning` ("found no layout file ... kind section").
  - A record without `title` renders `<title>· interviewscam.com`, so record titles must come from a template block.
  - A record with a future `date` is silently not built.
  - `[outputFormats.feed]` (`mediaType = "application/json"`, `baseName = "feed"`, `isPlainText = true`) plus `[outputs] home = ["html", "feed"]` and `layouts/home.feed.json` produce `/feed.json`. `--minify` minifies it and `jsonify` sorts keys.
  - `where … "Params.campaign.slug" $slug` works.
  - `{{ $d | jsonify }}` inside a `ld+json` script is double-encoded into a JSON string. `{{ $d | jsonify | safeJS }}` emits a parseable object with `<`, `>` and `&` escaped as `<` and so on.
- `tools/lighthouse.sh` audits every `index.html` under `public/`. From M5 on, that means every record page, and ADR-0003 asks for one page per template.
- Production `content/` has no records until M5, and record-only PRs skip the path-filtered `lighthouse` workflow (ADR-0003 part 4). Without a fixture build, the record templates would get no reflow, HTML or Lighthouse check before M5. The risk ADR-0003 part 6 names (64-character hashes, long defanged URLs) arrives exactly with these templates.
- `LIVE_HOST` matches any dotted token that ends in 2 to 63 letters. In the SPEC's prose with URLs removed, the text closest to future campaign copy, it flags `Dr.Web` (§1, §12), `abuse.ch` (§3), `Next.js` (D3) and `interviewscam.com`. All of them are legitimate.
- The SPEC's own D6 example is a product name: JobStealer uses the Webex name, which is a meeting app, not a company or person.
- The 2025 registry compromises in ADR-0003's Context (`chalk`/`debug`, Nx) shipped malware under legitimate package names.
- A package can be named like a live domain: `socket.io` is both. `LIVE_HOST` also matches file names (`.exe`, `.dmg`), and `.zip`, `.app`, `.sh` and `.py` are real TLDs.
- SPEC §1 lists about eleven app and site names from vendor reports (Meeten, Meetio, Meetone, Clusee, Cuesee, GrassCall, Relay, MeetLab, Juseo, Meetix, Carolla).
- Google retired ClaimReview from Search in June 2025 (SPEC §12).
- The 50 cases under `tests/fixtures/records/` and the 12 cases under `tests/fixtures/site/` that carry a `content/` record are written against the placeholder schema.

## Decision

Twelve parts. Each has its own reason and rejected alternatives.

### 1. Every report name has a D6 state

Every report has `state`, one of `name_abused` or `front`, and `state_basis`, a list of at least one "What was checked" entry, whatever the name type (`company`, `persona`, `meeting_app`, `domain`, `repository`, `package`). This changes D6, which gave a state only to company and person names.

**Why:** the goal is D6, that no page reads as a verdict on an uninvolved real party.

- The SPEC's own D6 example is a product name (the Webex name in JobStealer), which is neither a company nor a person.
- The 2025 registry compromises shipped malware under legitimate package names, so a package or repository page without a state reads as if its owner were the attacker.
- With a state on every name, the D6 rule is a plain `required: ["state"]`, and the schema needs no conditional keyword (part 2).

**Weak points:**

- Every domain, repository and package record needs a state and a "What was checked" list, so each record costs the moderator more work.
- "Front" on a throwaway domain reads a little odd ("No real owner was found behind this name").
- Methodology's "When a page shows the name of a company or a person" needs a copy edit (PR 4).

**Rejected:** D6 as written (a state only for company and persona). It needs an `if`/`then` validator extension to say "when the name type is company, a state is required", and it leaves Webex-type names unprotected.

### 2. A structural schema plus record rules in code; the validator gains only `minimum`

The schemas describe the structure: types, `required`, `enum`, patterns and `additionalProperties: false` at every level. The validator gains one keyword, `minimum` (numbers only). It gains no `if`/`then`/`else`, `oneOf` or `allOf`. Everything a structural schema cannot say is a record rule R4 to R15 in `sitecheck records`, and each rule has a fail fixture. This amends ADR-0002 part 4, whose keyword list stays the same apart from `minimum`.

**Why:** the goal is ADR-0002 part 4, a validator that stays small and fails closed, with every rule backed by a fixture.

- With part 1, "a name without a D6 state" is `required: ["state"]`.
- Typed artifact lists (`domains`, `sha256`, …) give each artifact type its own `x-defang` mode and pattern without a discriminator.
- A campaign link is an optional table (absent means unattributed), so it needs no condition.
- What remains is cross-field or cross-record: references between records, date order, persona names in free text, `hide_name` only on persona records. JSON Schema cannot express cross-record references at all, so code is needed anyway.

**Weak point:** validity lives in two places, the schema and the rules. The schema alone therefore under-describes a valid record. `CLAUDE.md` lists every rule, and each rule has a fail fixture.

**Rejected:**

- `if`/`then`/`else` with `allOf`: the semantics are subtle (an absent property satisfies an `if` on `properties`), and they would still not cover cross-record rules.
- `oneOf`: ambiguous error messages.
- One record section per name type: it changes the §5 URL `/reports/<slug>/`.

If part 1 were rejected, this part would become "add `if`/`then`/`else`", with pass and fail fixtures for each keyword.

### 3. D8 in record text: the site's own host is the only live host, every other dotted name is defanged

**Record text (R11)** is every record body, every `_index.md`, and every front-matter string except artifact fields and `params.sources[].url`. Source titles and publishers are record text. In record text, a live hostname, a live dotted IPv4, a `www.` prefix and an email address on a live host fail, unless the folded host equals the site's own host (`interviewscam.com`, taken from `SITE_ORIGIN`). There is no other exemption: no allowlist, and no exemption for declared artifacts.

Every dotted name in record text is written defanged: vendor, tool and brand names (`Dr[.]Web`, `Next[.]js`, `Booking[.]com`), the publisher and title fields of sources, and file names. File names stay a defanged artifact type (`Setup[.]zip`). Moderator guidance: prefer an undotted form where it reads naturally ("Doctor Web").

**Artifact fields:** every artifact type is `x-defang: host`, `handles[].value` and `packages[].name` included (`socket[.]io`). The mode `url-only` leaves `DEFANG_MODES`, so a schema that still uses it fails closed.

**R12, IP literal forms:** a host part that is a bare integer, hex, octal or short numeric form (`3232235777`, `0xc0a80001`, `127.1`) fails everywhere a host is read: `host` artifact values, URLs in record text, and `params.sources[].url`. The fix is to write the dotted IPv4, defanged.

**R15, source hosts:** `params.sources[].url` stays a live link with its existing `^https://` pattern. Its host must not equal, be a subdomain of, or be a parent of any `artifacts.domains` value of any report. Only `artifacts.domains` counts, because URL, email and repository hosts are often shared platforms that also carry sources.

**Why:** the goal is D8. No live attacker domain, IP or email host anywhere in a record, including text that is not a link, and no exemption through which a live attacker host can reach the site.

- The carried M1 QA item names five gaps: a bare hostname in prose, an email address on an undeclared host, a live hostname in a non-URL front-matter string, a decimal-integer IP, and any of these in `_index.md`. R11 and R12 close all five.
- Legitimate dotted names occur in real prose (`Dr.Web`, `abuse.ch`, `Next.js`), so a fail-closed rule needs a defanged spelling from day one or an exemption.
- A package can be named like a live domain (`socket.io`), so a declared package name proves nothing about the domain of the same name.
- `LIVE_HOST` also matches file names, and `.zip`, `.app`, `.sh` and `.py` are real TLDs, so an exemption by file extension would be unsafe.
- A source cited to support a record must not point at a host the record declares as an artifact, and R15 makes the one deliberately live link in a record safe against that. The rule is deliberately strict: it applies to every declared `artifacts.domains` value, including a victim domain declared in the "name abused" state, so there is no exception that an attacker-written submission could ask for.

**Weak points:**

- Legitimate names look odd when defanged (`Dr[.]Web`, `Booking[.]com`). The undotted form is preferred where it reads naturally.
- `[.]` does not tell attacker from victim, because a compromised victim domain is defanged too. Only the D6 state chip carries ownership, and Methodology says so (PR 4).
- A package name or handle with a dot is shown, copied and published in the feed defanged. A reader refangs it before use.
- R15 compares only `artifacts.domains`. An attacker host that appears only inside a URL, email or repository artifact is not compared, so the moderator declares every attacker-owned host in `domains`.
- R15 also blocks a victim's own advisory. If a "name abused" record declares the victim's domain (`shop.victim[.]example`), the victim's page on that host (`https://victim.example/…`) is equal to or a parent of a declared domain, so R15 rejects it as a source. It then backs neither R7 nor R9, which both need a source. The record uses a third-party source instead, and without one the claim that advisory would support is not made. A defanged, non-link mention in the body is allowed by the SPEC §5 body rule and R11, which reject only live forms, but it is not a source.
- IPv6 literals in record text are not detected. The schema accepts IPv4 artifacts only, so an IPv6 artifact cannot be declared. This is an accepted weak point.

**Rejected:**

- An exact-token allowlist (`prose_allowlist` in `schema/record-policy.json`), which was the recommendation before STOP 1. It lost for four reasons:
  1. The risks are asymmetric. A wrong entry puts a live attacker host on the site, while the cost of no list is that some names look odd.
  2. An allowlist is a second path to green CI for whoever fixes a red check, agents included, and submission text can be attacker-written.
  3. `[.]` does not separate attacker from victim even with a list, because a compromised victim domain is defanged anyway. Only the state chip carries that.
  4. A listed legitimate domain can change owner.
- A `url-only` exemption for declared handles and packages: an attacker could register a package and the same-named domain and pass it live.
- A suffix allowlist of legitimate platforms: an attacker subdomain on such a platform, for example on `github.io`, would pass.
- The IANA TLD list: a data file to keep current, and `.py`, `.sh` and `.zip` still collide.
- The status quo: the five gaps stay open.

### 4. URLs, titles and a locked set of top-level keys

The only top-level front-matter keys are `date` (the publication date) and `params`. `additionalProperties: false` therefore locks out `title`, `url`, `slug`, `aliases`, `draft`, `build`, `outputs`, `layout`, `type`, `cascade`, `publishDate` and `expiryDate`. Titles come from a template, never from front matter, in the fixed formats of SPEC §5.

Slugs follow R4:

- A report slug equals `slugify(name)` or `slugify(name)-N` with N ≥ 2. `slugify` means NFKD ASCII folding, lowercase, `[.]` and every non-alphanumeric run as `-`, trimmed.
- A persona report's slug is `persona-N` with N ≥ 1 (part 5).
- A campaign slug follows the report rule.
- No slug may appear in `retired_slugs` in `schema/record-policy.json`. A name that slugifies to nothing fails.

**Why:** the goal is SPEC §5, that URLs and titles stay neutral, and that nothing in a record changes how its page is addressed or whether it is built.

- Each locked key could change a URL (`url`, `slug`, `aliases`, `type`, `layout`), hide or time-shift a page (`draft`, `build`, `publishDate`, `expiryDate`, `outputs`) or retitle it (`title`). A record with a future `date` is silently not built (verified), which is why PR 3's render rule 1 turns a missing page into a red check.
- A record without `title` renders `<title>· interviewscam.com` (verified), so the title must come from a template block.
- A slug derived from the name makes the URL checkable: the check recomputes it. A free slug could carry a verdict word.
- `retired_slugs` keeps a removed slug from being reused, so a cached link never points at another record.

**Weak point:** the policy file is a second place to edit when a record is removed (the moderator adds the slug in the removal PR).

**Rejected:** a `slug` or `title` key in front matter (the check could not tell a neutral one from a verdict, and a missing title builds an empty one); a section per name type (it changes the §5 URL).

### 5. The person-name switch: `hide_name`, and persona URLs without a name

A persona record sets `params.hide_name = true` to hide the person's name at once, in one line. The name then leaves the title, the page, the feed and any index, while the artifacts and the rest of the record stay up and the URL does not change.

- Persona reports live at `/reports/persona-<n>/`. `n` counts from 1 and is never reused. A removed slug goes into `retired_slugs` (R4).
- A persona's name and aliases render only from `params.name` through one partial. R5 bans them (NFKC, case-folded, whitespace collapsed, whole word) from every free-text string and body of every record.
- R6: `hide_name` only with `name_type = "persona"`.
- Render rule 9 (PR 3) scans every built file for a hidden name: pages, `/feed.json`, and whatever index M4 adds.

**Why:** the goal is SPEC §6 and GDPR Art. 18(1)(d): the name is hidden first, before the review, and the rest of the record stays up.

- With name-based slugs, hiding means renaming the file. The old URL then 404s, search caches keep a URL that contains the name, and Hugo aliases would keep the name in a URL path.
- If the name may also appear in free text, hiding needs copy edits across records at the urgent moment.

**Weak points:**

- `persona-3` tells a human reader nothing.
- A name that also forms part of an artifact blocks the hide until the operator resolves it (the check names the field).
- A person's name in free text with no persona record behind it is not detected. Review covers that.

**Rejected:**

- Name slugs with a rename on hide (the reasons above).
- `noindex` on hide: the name stays on the page.
- Unpublishing the record: the corrections procedure in SPEC §6 keeps the artifacts up.

### 6. Campaign links and attribution only through cited sources

`params.campaign` is an optional table (`slug`, `source`, `basis`, `artifact`). Its absence means the report is unattributed. A report names a campaign family only when a cited source of the same record either names this name (`basis = "named"`) or lists one of its artifacts (`basis = "artifact"`, with `artifact` equal to one declared artifact value). A campaign's `attribution` entries each carry a `statement` and a `source` that resolves to a source of the same record. The page says "Campaign family that used this name", never that the name belongs to the family. Related reports on a campaign page are computed from the reports, not stored.

**Why:** the goal is D7 and D6. This codifies the Methodology copy approved at #3 STOP 2.

- An attribution is a claim about a real party. A claim that rests on our own judgement turns third-party content into the operator's own claim, the exact thing the D7 label rule avoids.
- The artifact route covers renamed campaigns, where a source lists a domain but not the name the candidate saw.

**Weak point:** a report without a source that names it or lists its artifacts stays unattributed even when the moderator is fairly sure. That is intended.

**Rejected:** attribution by moderator judgement without a source; a stored list of related reports (it goes stale, and a computed one cannot disagree with the records).

### 7. The feed is a custom JSON document; `disableKinds` stays as it is

`/feed.json` is a custom JSON document with an integer `version`, validated in CI against `schema/feed.schema.json`, with its fields documented on a public page `/data-feed/` (a new page in SPEC §6). Render rule 13 keeps the page in sync with the schema. A hidden name appears in the feed as `null`.

Versioning: `version` starts at 1 and increments only on a breaking change: a field removed, renamed or retyped, or its meaning changed. An addition keeps the version and is listed in the page's change list with its date.

It is a custom output format of the home page (`[outputFormats.feed]`, `[outputs] home = ["html", "feed"]`, verified above). `disableKinds` keeps `taxonomy`, `term` and `rss`. This is the ADR-0001 revisit: unchanged. The guard asserts neither `disableKinds` nor `outputs`, so no ADR-0001 hardening key changes.

**Why:** the goal is SPEC §2 and §5, machine-readable data for researchers and tools with stable field names and a version field.

- JSON Feed 1.1 is item-oriented (`id`, `title`, `content_html`, `date_published`) for feed readers, and would bury artifacts in extension objects.
- The repo is private (D4), so field docs that exist only in the repo cannot reach a consumer. A public page that is also in the repo satisfies "documented in the repo" and reaches users.
- Nothing in M3 uses RSS or taxonomies, and the empty generated pages would still be built and checked.

**Weak point:** no off-the-shelf reader support, and a consumer that rejects unknown fields breaks on an addition.

**Rejected:** JSON Feed 1.1; docs only in `docs/` (invisible to users); a semver string (only breaking changes need a signal, so one integer carries all the information needed). The data licence is deferred to issue #19 (P2; SPEC §10 already lists data licensing as out of MVP scope). M3 decides no licence.

### 8. Structured data: `WebPage` and `BreadcrumbList`, as JSON-LD only

Record pages carry a `WebPage` and a `BreadcrumbList`. Section pages carry a `BreadcrumbList` only. Date keys: a report's `WebPage` carries `datePublished` (`date`) and `lastReviewed` (`last_reviewed`, the date of the D7 evidence review), a campaign's only `datePublished`, because a campaign states no review date, and no page carries `dateModified`, because no record states when it was last changed (a `last_reviewed` before `date` or a later edit such as `hide_name` would make it false). No field may claim a review or modification that the record does not state. The breadcrumb is also rendered visibly. No `Article`, `ClaimReview`, `Review`, `Rating` or `Person`, no node about a record's subject, and no microdata or RDFa. JSON-LD is emitted through `jsonify | safeJS` (verified above).

**Why:** the goal is SPEC §5, types that search engines support and no markup that turns a record into a claim about a real party.

- Google retired ClaimReview in June 2025 (SPEC §12).
- `BreadcrumbList` remains a supported rich result.
- `WebPage.lastReviewed` means "date on which the content was last reviewed for accuracy", which is D7's "evidence reviewed on".
- Google's Article guidance targets news, blog and sports articles.
- A `Person` or `Organization` node for a record's name would assert an entity about a real party (D6) and would carry a hidden name.

**Weak point:** no rich result beyond breadcrumbs. Google wants markup to match visible content, so the breadcrumb is also visible.

**Rejected:** `Article` (authored-news framing); `Dataset` for the feed (it wants a licence, and none is decided, see part 7); microdata or RDFa (a second syntax to check).

### 9. Hash lookups and external links on record pages

Each SHA-256 declares `listed_on`, a list of `malwarebazaar` and `virustotal` with at least one entry, and only those links render. The URL forms are `https://bazaar.abuse.ch/sample/<sha256>/` and `https://www.virustotal.com/gui/file/<sha256>`. On a record page, every external `<a href>` is one of that record's source URLs or one of its lookup URLs, and no `download` attribute exists anywhere (render rule 7).

**Why:** the goal is D8, that a hash links to a lookup page and never to a file, and that every lookup link works.

- A MalwareBazaar sample page exists only for samples submitted there. VirusTotal's interface answers for any hash.
- The moderator checks a lookup page, which is not a download.
- Declaring `listed_on` per hash means the page never renders a link the moderator did not check.

**Weak point:** a later listing does not get a link until someone edits the record.

**Rejected:** always both links (dead MalwareBazaar pages for samples it does not have); VirusTotal only (a single vendor).

### 10. A fixture build and browser checks on the record templates

`check.sh` assembles `.fixture-site/` from `hugo.toml`, `layouts/`, `assets/`, `data/`, `static/` (if present), the top-level `content/*.md` and `tests/fixtures/records/pass-fixture-site/content/`, and builds that into `public-fixtures/` with the same flags as the real build.

- `site`, `render`, lychee (offline only) and the CI-only reflow and Nu Html Checker steps run on that tree too.
- `lighthouse.yml` uploads `public-fixtures/` next to `public/` and `tools/`.
- `lighthouse.sh` skips individual record pages of `public/` and audits five fixture pages: home with lists, `/reports/`, `/campaigns/`, one report, one campaign. That is one page per record template, as ADR-0003 asks.
- The deploy artifact stays `public/` only.

- The `lighthouse` PR path filter gains `tests/fixtures/records/pass-fixture-site/**` (PR 4). The fixture set changes the five audited fixture pages, and without the filter entry a fixture-only PR would change them with no `lighthouse` run.

This amends ADR-0003 parts 2 (the artifact carries a second tree), 4 (the path filter) and 5 (the page count and the timeout inputs) and settles its Consequences item "M3 decides which record pages Lighthouse measures".

**Why:** the goal is SPEC §8 and ADR-0003 part 6 on the record templates before M5, and the issue's requirement that fixture records are never built into the production site.

- Production has 0 records until M5, record-only PRs skip `lighthouse`, and the overflow risk (64-character hashes, long defanged URLs) sits in these templates.

**Weak points:**

- `check.sh` gets slower: a second tree goes through reflow and the HTML checker.
- Fixture data is not real data, so the fixture set carries deliberate worst cases: a name token of at least 59 characters, a 64-character hash and a URL with a segment of at least 43 unbreakable characters. The Numbers table derives both thresholds from the 320 px viewport, and the fixture tokens of PR 2 and PR 4 must be at or above them.

**Rejected:** measuring record templates first in M5 (they would merge unmeasured); building fixtures into `public/` behind a flag (one wrong flag puts them in the deploy artifact); auditing every real record page (the job grows with every record, against ADR-0003).

### 11. The Copy button

`assets/js/copy.js`, a script of about 30 lines, adds a Copy button to artifact boxes and to the contact address. The button is in the markup as `<button type="button" class="copy" hidden data-copy-target="…">`. The script reveals it only when `navigator.clipboard` and a secure context exist, writes the `textContent` of the target unchanged, and sets a polite live-region status. It has no timers, no inline handlers and no URL literals. A `site` rule allows at most one `.js` file with every `<script src>` naming it, and render rule 14 checks every button and its target. Proof is static checks plus review. Lighthouse's best-practices category on the fixture pages shows there are no console errors.

**Why:** the goal is the carried pick constraints: a candidate copies an artifact or the contact address without selecting a long defanged string on a phone. The button is hidden by default so a page without the script is unchanged, and D9 holds because the script is first-party and fingerprinted.

**Weak point:** no local run is possible (D3 forbids node on the operator's machine), so the script is proven only in CI by its size, review, render rule 14 and Lighthouse's console-error audit.

**Rejected:** a Chrome behaviour test for Copy. It would be a third CI-only step and a new final local line for a script of about 30 lines. A copy that rewrites the text (refanging, trimming) is also out: it would put live artifacts on the clipboard.

### 12. Source-only reports

`independent_reports` is an integer with `minimum` 0. A report is valid with 0 independent reports when it cites at least one source (R9). The D7 label then reads "Named in 1 cited source, reviewed on …" for one source and "Named in K cited sources, reviewed on …" for K ≥ 2, instead of "Reported N times, evidence reviewed on …". The singular is its own fixed string, as "Reported once" is for N = 1, so the label never reads "1 cited sources" or carries a literal "(s)".

**Why:** the goal is SPEC §1 and §2, one page per name a candidate sees.

- SPEC §1 lists about eleven app and site names from vendor reports. With a minimum of 1 community report, none of them could get its own page until someone reports it to us.
- D7 requires evidence and review, and a cited vendor report is evidence.

**Weak points:**

- The moderator reviews a source, not first-hand evidence, and the label says so.
- A generic name (for example Relay) can collide with a legitimate product of the same name. A source-only report therefore rests on the source's artifacts and on the D6 state with its "What was checked" list, not on the name alone.

**Rejected:** a minimum of 1. Vendor names would then appear only in campaign text. M5 adds no source-only record (out of its scope); the model only has to allow it.

### Record rules R4 to R15

R1 to R3 are the M1 rules (body URLs, the live form of an artifact outside its field, the live form of an artifact in the built site). The rules below are added by this ADR and implemented in PR 2. Parts 1 to 12 give the reason for each; this table only defines them, so that a reviewer can check a rule number against one place.

| Rule | Definition |
|---|---|
| R4, slugs | A report slug is `slugify(name)` or `slugify(name)-N` with N ≥ 2. A persona report's slug is `persona-N` with N ≥ 1. A campaign slug follows the report rule. No slug appears in `retired_slugs`, and a name that slugifies to nothing fails. `slugify` is NFKD ASCII folding, lowercase, `[.]` and every non-alphanumeric run as `-`, trimmed. |
| R5, persona names | The name and aliases of every persona record (NFKC, case-folded, whitespace collapsed, whole word) appear in no free-text string and no body of any record. |
| R6, `hide_name` | `hide_name` is allowed only with `name_type = "persona"`. |
| R7, references | `campaign.slug` resolves to a campaign record. `campaign.source` and every `attribution[].source` resolve to a source `id` of the same record, and source ids are unique per record. `related` entries resolve to other report records, never the record itself. `basis = "artifact"` requires `campaign.artifact`, equal to one of the record's declared artifact values; `basis = "named"` forbids it. |
| R8, date order | Reports: `first_seen ≤ last_seen ≤ last_reviewed`. Campaigns: `first_seen ≤ last_seen`. |
| R9, evidence | `independent_reports ≥ 1`, or at least one source (part 12). |
| R10, artifacts | A report declares at least one artifact. |
| R11, hostnames in record text | In record text a live hostname, a live dotted IPv4, a `www.` prefix and an email address on a live host fail, unless the folded host equals the site's own host. No other exemption (part 3). |
| R12, IP literal forms | A host part that is a bare integer, hex, octal or short numeric form fails wherever a host is read: `host` artifact values, URLs in record text and `params.sources[].url` (part 3). |
| R13, `_index.md` | TOML front matter with only `title` and `description` strings, plus the body rule and R11. |
| R14, verdict phrases | Free-text strings and bodies contain none of "verified scam", "confirmed scam", "is a scam", "scam company" or "fraudulent company" (case-insensitive). This is a heuristic net for the D7 label rule, not a proof. Review stays binding. |
| R15, source hosts | The host of every `params.sources[].url` must not equal, be a subdomain of, or be a parent of any `artifacts.domains` value of any report (part 3). |

*Amended in M3 PR 2 (#21), after its QA and review, where the table above left the reading open. (1) Hosts are read the way a browser reads them, in R2, R11, R12 and R15 alike: every Default_Ignorable_Code_Point (U+FE0F, U+034F, U+180B, U+E0100 and the rest of Unicode's set) stripped before every check, because a browser drops them from a host (UTS #46) and `attacker` + U+FE0F + `.example` opens `attacker.example`; they are stripped, not rejected, so emoji in prose still pass; percent-decoded, `\` read as `/`, userinfo and port cut, dot look-alikes folded, lowercase, trailing dot stripped. A Unicode label has two `xn--` forms: the transitional one (IDNA2003, which maps `ß` to `ss` and `ς` to `σ` and drops the joiners) and the UTS #46 nontransitional one, which browsers use and which keeps those deviation characters (`faß` is `xn--fa-hia`; a ZWJ only after a virama). R2 and R15 compare both, and a match on either counts. A source URL host must also be ASCII, written in its `xn--` form, because only an ASCII host has one reading. Otherwise a source URL such as `https://attacker%2Eexample/`, `https://faß.example/` or a Unicode spelling of a declared `xn--` domain passes R15, while the browser opens the declared host. (1a) `x-defang: host` scans the whole value, a path, query, file name or repository shorthand included, in every reading (as written, with `[://]`, `[:]` and `[@]` read through the table `refang()` uses, and percent-decoded): every dotted name anywhere in an artifact field is defanged, as R11 requires of record text. So `hxxps://x[.]example/setup.zip` fails until it reads `setup[.]zip`, and `attacker/interview.task` until it reads `attacker/interview[.]task`. Every `urls` value must have exactly this form: the scheme `hxxp` or `hxxps`, then `://` or one of its `DEFANGS` spellings (`[://]` or `[:]//`), then a non-empty authority (a host name or a dotted IPv4, optionally with userinfo and port), then an optional path, query or fragment. A value that does not have this form gets a format finding. So does an authority whose host is a bracketed IPv6 literal (`hxxps://[::ffff:7f00:1]/` opens 127.0.0.1). In every `host` field, `urls` included, an IPv6 literal, bracketed or bare, is a finding, because this part says an IPv6 artifact cannot be declared. The literal is looked for after the defang separators are read and the default-ignorables are stripped, and it counts only when it parses as IPv6 (Python's `ipaddress`), so a handle or name that merely holds a colon (`dead:beef`, `Fixture::Utils`) passes. IPv6 in record text stays an accepted weak point. R12 reads a URL's host only from that authority. Why: three review rounds each found another scheme spelling (`hxxps//`, `hxxps%3A//`, `hxxps.//`, `hxxps(://)`, …) that hid the host from a parser that had to guess where the host starts. An allowlist of forms plus a scan that needs no host ends the family instead of fixing one spelling at a time. And a raw dot in a path is not harmless: `.zip`, `.app`, `.sh` and `.py` are real TLDs, so `setup.zip` is itself a live host name. (2) R11 reads the whole text, a URL's path, query and fragment included, because part 3 has no path exemption ("every dotted name in record text is defanged"). A quoted artifact URL therefore writes its path dots as `[.]` in record text, while the artifact field itself keeps its path (`x-defang: host` reads only the host part). (3) R11, R5 and R14 also read the text with inline Markdown and HTML markup removed (emphasis, code, links, tags, comments, entities), because `**attacker**.example` renders as a live name and `**Avery** Fixture` as a whole persona name. A check of the rendered pages remains the stronger backstop. (4) R12 reads a bare single decimal or octal number (no dot, no `0x`, not after a scheme) as an integer IPv4 when it is the whole value or the whole first part of it (`3232235777`, `2130706433/setup`), in every `host` field except `handles[].value`. Messaging platforms use numeric account IDs, so a number there is a handle. A number inside a longer value, such as a name like "Studio 54", is not something a browser resolves. (5) R13 covers the home page `content/_index.md` as well as the section pages, and runs the front-matter URL rules on `title` and `description` together with the body rule.*

## Numbers

| Number | Derivation | What breaks at another value |
|---|---|---|
| Feed `version` 1 | The first published form of the document. It increments only on a breaking change (part 7). | Starting higher claims a history that does not exist. Incrementing on additions makes every consumer re-check for no reason. |
| Slug suffix starts at 2 | The first record holds the bare slug `slugify(name)`, so a second record with the same slug is the second of that name (part 4). | Starting at 1 gives the first record two valid spellings. Starting at 3 or later skips a free slug. |
| `persona-N` starts at 1, never reused | A persona URL carries no name, so it has no bare slug to count from. Counting from 1 is the natural first record. A retired number goes into `retired_slugs`, so a cached link never reaches another person (part 5). | Reuse points an old link at another person. Starting at 0 adds an unneeded special case. |
| SHA-256 as 64 lowercase hex | 256 bits ÷ 4 bits per hex digit = 64. Lowercase because the lookup URLs use that form and a single form keeps duplicates detectable. | 63 or 65 characters is not a SHA-256. Uppercase gives one hash two spellings and breaks the dedup. |
| `listed_on` has at least 1 entry | A hash with no lookup would be a string a reader cannot check. The moderator confirms at least one lookup page (part 9). | Zero entries: an unverifiable hash on the page. Requiring both lookups: forces dead MalwareBazaar links for samples it does not hold. |
| Home list of 5 reports | One list item (name, chip, date) is about two lines at the 16 px body and 1.55 line height, roughly 58 px with its gap. Five items take about 290 px, under half of the 640 px reference viewport of ADR-0003 part 6, below the search card and the checklist. At launch there is one report, so the number binds only later. | Ten items take about 580 px and fill the screen. Fewer than five shows too little of the registry for the space available. |
| Lighthouse page count 16 | Home, 404 and the seven static pages (the six of §6 plus `/data-feed/`), the two production section pages from M5 on, and the five fixture pages of part 10: 1 + 1 + 7 + 2 + 5 = 16. It holds through M5. | A different count changes the `lighthouse` timeout. Counting every real record page makes the job grow with each record. |
| `lighthouse` timeout `ceil(factor × (T_setup + 16 × 3 × T_run))` | The method of ADR-0003 part 5. 16 is the page count above and 3 is the runs per page of ADR-0003 part 3. The factor is the smallest whole factor above the slowest-to-fastest spread of the green runs of this job on the same page set. Data of 2026-11-05: the 9 green `lighthouse` jobs on the current 8-page set took 271 to 298 s, a spread of 1.10, so the factor is 2. The 17 minutes that were in `lighthouse.yml` before PR 4 replaced ADR-0003's provisional 30 in #15, from 4 measured runs (T_setup 18.6 to 21.6 s, T_run 11.4 to 12.6 s, 8 pages) with the provisional factor 3: 3 × (21.6 + 8 × 3 × 12.6) = 972 s, rounded up to 17 minutes. That factor 3 is not carried here, because its provisional condition (10 green runs) is met and the data gives 2. **Measured in PR 4 (#23, 2026-11-05):** the 16-page set does not exist before M5, so the inputs come from the 13 pages it has now (Home, 404 and the six static pages of production, plus the five fixture pages), and the formula keeps 16. The six green `lighthouse` jobs of this PR on that set (runs 42095775227, 42099591193, 42105047980, 42108437792, 42112011524 and 42114958661; the two QA mutant runs left out) took 482, 473, 455, 466, 462 and 487 s, a spread of 487 / 455 = 1.07, so the factor stays 2. Per job, `T_setup` is the job time minus its 39 audits (39 × the mean audit): 25.7, 24.5, 22.1, 21.4, 29.1 and 26.8 s, at most 29.1 s. `T_run`, the mean audit per job, was 11.1 to 11.8 s, at most 11.8 s (single audits up to 40.2 s). With the maxima, 2 × (29.1 + 16 × 3 × 11.8) s = 1191 s, rounded up to **20 minutes**. The value in `lighthouse.yml` must equal this row. The next PR that changes the page set re-derives it with the spread of its runs. | Too low: runner variance turns into red runs. Too high: a hung run blocks merges for long. A factor at or below the spread kills the slowest normal run. |
| `check.sh` workflow timeouts: the factor times the slowest green run of PR 4 (`ci.yml`, `deploy.yml`, `links-external.yml`, `lighthouse.yml` job `build`) | Each timeout is a hang cap, and every workflow runs `check.sh`, which gets a second tree in PR 4. The factor is the smallest whole factor above the slowest-to-fastest spread of the green runs of one version of the script, so that even if the measured run is the fastest, the slowest normal run still fits. Data of 2026-11-05: the 16 green `check` jobs since the reflow step landed (2026-11-04 23:09 UTC) took 78 to 109 s, a spread of 1.40, so the factor is 2. The M1 sample (11 jobs, 20 to 44 s, spread 2.2, factor 3) is not carried: that script has since changed. All 44 green runs of the day span 20 to 109 s (5.45), but that mixes script versions as steps were added, so it is not a spread of one script. PR 4 has no spread of the new script yet, so it applies factor 2 to the slowest of its own green runs. `pages-artifact` is on the deploy path, so a cap that is too low there would block a deploy after M6. **Measured in PR 4 (#23, 2026-11-05):** green runs of the new script: `check` 161 s (run 42095775647), `lighthouse` job `build` 154 s (run 42095775227), `links-external` 181 s (run 42095780993, a manual start on the branch); spread 181 / 154 = 1.18, so the factor is 2. 2 × 181 s = 362 s, rounded up to **7 minutes** for each of `ci.yml`, `deploy.yml`, `links-external.yml` and the `lighthouse.yml` job `build`, which all run the same `check.sh`. The first run of each of these jobs on PR 4 went red on one reflow start (Chrome gave no DevTools answer within `REFLOW_TIMEOUT`, 30 s, on its first launch; the re-runs were green), the slowest after 220 s: 7 minutes still holds such a run. Re-derive them in the next PR that changes `check.sh`. **Re-checked in M3 PR 5 (#24, 2026-11-06), for the launch budget of ADR-0003 part 6:** base: the slowest green run of PR 4 above, 181 s (#25's slowest stall-free job took 165 s), plus the `reflow-launch` self-test cases, which PR 4 did not have and so are not in the 181 s: 13.4 s for the first six in CI (`bc50e26` `check` job, 09:20:00.57 to 09:20:14.00) at most 2 s for `default-budget`, `log-dir-fallback` and `first-answer-deadline` together (0.4 s for the first two locally; the third waits 0.5 s in each of its two sub-cases by design, 1.3 s locally), so 181 + 13.4 + 2 = 196.4 s. 26 launches per job take the launch path: the 2 trees and 24 of the 25 reflow self-test fixtures (`fail-no-html` stops before the launch), all with the default `REFLOW_LAUNCH_TIMEOUT` of 75 s; the stub cases use a fixed 1 s budget, except `default-budget`, whose stub exits at once. A fully used launch window costs 2 × 75 = 150 s: 196.4 + 150 = 346.4 s, and with one more 70 s stall elsewhere (the longest seen) 416.4 s, under 420 s by 3.6 s; the same sum bounds the launch budget at 76.8 s (ADR-0003 Numbers). A second fully used window (496.4 s) ends `cancelled`, which is red, and never occurred (no job had two stalls). A Chrome that never answers fails the tree-1 call with exit 2 and the diagnostics about 163 s into `check.sh` (about 13 s to the reflow step plus 150 s), but `check.sh` goes on to tree 2 and the 24 fixture launches at 150 s each, so the job ends `cancelled` at the cap, red, as on `b80a307`, where 26 × 30 s also passed it. So the timeouts stay **7 minutes**; at 6 minutes (360 s) one absorbed window plus a second stall (416.4 s) would be cancelled. PR 5 does not change `check.sh`. PR 7 changes it and re-derives the timeouts with cap ≥ max(2 × slowest green run, slowest stall-free green run + 2 × `REFLOW_LAUNCH_TIMEOUT` + 70 s). | Below the observed spread: the slowest normal run is killed. Far above: a hang blocks for long. |
| Unbreakable monospace token (a hash, an artifact value, a URL segment) of at least 43 characters | The reflow check measures horizontal overflow only (ADR-0003 part 6; vertical clipping is not measured), and it fails a word only when the word leaves the 320 px viewport (tolerance 0.5 px) or a clipping ancestor. A container that does not clip lets an unbroken token run past its own edge without a finding. So a fixture token must reach past the viewport edge from the leftmost point a line can start, the 16 px gutter (`layout.gutter` in `data/tokens.toml`, the `padding-left` of `.container` in `assets/css/site.css`): it must be wider than 320 − 16 + 0.5 = 304.5 px. Cards and code boxes start further right and need fewer characters (`layout.container_max` 760 only caps wider viewports). Size: 13 px, the smallest in the type scale (`type.chip`), because a smaller size fits more characters per line. Advance: 0.55 em, the advance of the narrowest monospace face in the font stack (Consolas; Menlo, SF Mono and Liberation Mono are about 0.6 em), so 7.15 px per character, which is conservative because a narrower advance needs a longer token. 304.5 ÷ 7.15 = 42.6, so the threshold is 43 characters: 42 characters end at x = 16 + 300.3 = 316.3 px, inside the viewport, and 43 end at 323.5 px. Hashes (64) are above it. A URL fixture must also contain one segment of at least 43 characters made of letters and digits only, with no `/`, `-` or space, because those give the browser break opportunities. The code-box size does not exist yet (`tokens.toml` has no monospace size): PR 4 checks this derivation against the size it sets and re-derives the threshold if the size is below 13 px. The fixture tokens of PR 2 and PR 4 must be at or above this threshold. | Below 43: an unbroken token can end inside the viewport, so a missing break rule (`overflow-wrap`) goes unnoticed. Far above: more width than any real artifact proves nothing more. |
| Unbreakable name token (a name or alias) of at least 59 characters | Same measure as the row above: past the viewport edge from the 16 px gutter, so wider than 304.5 px, at 13 px (`type.chip`), the smallest size in the scale and so the conservative one, though names render larger (the h1 at 28 px). Advance: 0.4 em for a proportional system sans, below the roughly 0.5 em average of lower-case Latin letters in common system faces, so 5.2 px per character (a narrower advance needs a longer token). 304.5 ÷ 5.2 = 58.6, so the threshold is 59 characters: 58 characters end at x = 16 + 301.6 = 317.6 px, inside the viewport, and 59 end at 322.8 px. The fixture token is built from ordinary letters and digits, not runs of narrow glyphs such as `i` or `l`, so the stated advance holds. PR 4 checks this against the sizes and faces it sets. The fixture names of PR 2 and PR 4 must be at or above this threshold. | Below 59: an unbroken token can end inside the viewport, so a missing break rule goes unnoticed. |
| `independent_reports` minimum 0 | Part 12: a source-only report has no community report, and a cited source is the evidence. | Minimum 1: about eleven §1 names cannot get a page until someone reports them. |
| Hidden-name matching: whole words after NFKC and case folding, no minimum length | A hide must not leak. A short or common name fails closed and the message names the field, so the operator can rephrase. | A minimum length lets a short name slip through. Substring matching flags innocent words. |

## Consequences

- Validity of a record lives in the schema and in rules R4 to R15. `CLAUDE.md` lists every rule, and each rule has a fail fixture. PR 2 rewrites about 60 existing fixture cases to the new schema, so each fails for its one defect only.
- Every name in record text with a dot is written defanged, and a moderator reads two kinds of weak point: odd-looking vendor names, and `[.]` carrying no ownership information. Methodology says so (PR 4).
- The moderator declares every attacker-owned host in `artifacts.domains`, because R15 compares only that list. IPv6 literals in record text are not detected.
- Each record costs more moderator work: a state and a "What was checked" list on every name.
- The `lighthouse` workflow, its path filter, the Lighthouse page set and every `check.sh` workflow timeout are re-derived in PR 4. PR 4 writes the measured inputs and the resulting minutes into the Numbers table above.
- `check.sh` gains a second tree and is slower. The final local line stays `LOCAL PASS, HTML validation and reflow not run (CI only)`.
- The labels of D6, D7 and D10 live in `data/labels.toml` and, independently, as constants in `tools/sitecheck.py` (PR 3, PR 4). A wording change needs both, so it shows up in a safety-net diff.
- The data licence (issue #19), search (M4), real records (M5) and the report form (issue #13) are outside this ADR. Search builds its index from the same records, and render rule 9 covers any index file it adds.
- If issue #13 lands an ADR first, this ADR takes the next free number and every reference to it shifts.
