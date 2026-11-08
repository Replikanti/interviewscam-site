# ADR-0005: Search

## Status

Accepted, 2026-11-08 (operator, issue #5, STOP 1; the plan's three open decisions, each decided as recommended, are recorded in parts 2 and 6). Implements SPEC §6 (the Home search and the no-JavaScript fallback), the Mobile and Accessibility rows of §8 and §11 item 4, under D3, D6, D7, D8, D9 and D10. Amends [ADR-0004](0004-record-model.md) part 11 (at most one script) and its Numbers rows "Script pin: SHA-256, one entry per script" and "Lighthouse page count 16", and adds reflow case (8) to [ADR-0003](0003-browser-checks.md) part 6. The implementation lands in sequenced PRs under milestone 4 (#5): this ADR and the SPEC edits in PR 1, the A to Z page and the no-JavaScript path in PR 2, the search script and the hidden result sections in PR 3, the CI outcome proof (reflow case (8) and the Lighthouse emulation pin) in PR 4.

## Context

- **Goal.** SPEC §2: a candidate who types a name, an app or a domain into the site search gets the answer in one step on a phone, within the minutes between the meeting link and the call (§1). SPEC §6: Home has one search box and shows the answer for an exact match on the same page; search works without a server, from a static index, and without JavaScript an alphabetical index of all reports and campaigns is the fallback. SPEC §8 Mobile row: from the home page to the answer in one search on a phone.
- **Acceptance criteria of #5** (2026-11-04): an exact name, alias or domain of a fixture record answers on Home without loading another page and without a request outside the site's own origin (D9); a pasted live URL or bare domain matches the record's defanged artifact; a query without a match says the registry has no report for it, does not suggest the name is safe, and links to Before your call and Report a scam; with JavaScript disabled, Home links to the alphabetical index, which lists every report and campaign; search code and index are self-hosted and built without npm (D3), and the CSP allows same-origin scripts only; Lighthouse stays at least 95 in all four categories on Home; in Lighthouse's mobile viewport one query and one submit show the answer.
- **No server** (D4, GitHub Pages) and **no npm outside CI** (D3).
- **The CSP** (`params.csp` in `hugo.toml`, 2026-11-08) already holds `script-src 'self'`, `connect-src 'self'` and `form-action 'self'`, so a same-origin script, its same-origin fetches and a `get` form to a page of the site need no CSP change. `site` refuses every source but `'self'` and `'none'` (`CSP_SOURCES` in `tools/sitecheck.py`).
- **The feed exists.** `/feed.json` (ADR-0004 part 7, M3 PR 8) lists every report and campaign with its name, aliases and, for reports, the defanged artifacts. Render rules 11 to 13 prove it equal to the records field by field (rule 12), with a hidden name as `null` and `name_label` set for a visible persona; rule 9 keeps a hidden name out of every file of `public/`, a search index included; rule 4 holds every visible persona name in every page to the D10 label.
- **One script today.** ADR-0004 part 11 allows at most one script (`copy.js`); `site` rule (j) allows one `.js` file; `literals` pins every script under `assets/` by SHA-256 (`SCRIPT_SHA256`), reads its literals with L7 (no regular-expression literal, no template literal with a substitution, no copy literal), and bans a `resources.*` target with a script name (`LITERALS_RESOURCE_TARGETS`), so a served script comes only from one pinned source file.
- **Browser checks run in CI only.** `sitecheck reflow` (ADR-0003 part 6) drives the runner's Chrome over the DevTools pipe; the operator's machine has no browser on `PATH`, and the local run prints `NOT RUN` for it. Lighthouse 13.6.0 is pinned in `tools/pins.env` and runs in the `lighthouse` job, and `tools/lighthouse.sh` passes no throttling, preset or config flag, so the defaults apply: the mobile form factor and screen emulation, and the `simulate` throttling method with the `mobileSlow4G` profile.
- **Fixtures.** All 216 render fixture cases (`tests/fixtures/render/*/`, counted on `28d624a`) hold a Home page and none holds `/a-z/`. Production `content/` has no records until M5 (#6).
- **Open neighbour.** #32 rewrites `site_path`, the link reader the render rules of this milestone call; it starts after PR 4 merges (Consequences).

## Decision

Every word the search shows comes from statically checked markup: the match keys come from `/feed.json`, the displayed entries are copies of the entries of a new page `/a-z/`, and the script carries no copy of its own.

### 1. Index and display

**Keys from `/feed.json`.** Per entry of `reports[]` and `campaigns[]`: the `name`, every `aliases[]` value, and, for reports, every value under `artifacts`: `domains`, `urls`, `ips`, `emails`, `repositories`, `file_names`, `handles[].value`, `packages[].name`, `sha256[].value` and `sha256[].file_name` (campaign entries have no `artifacts`). The path of the entry's `url` maps it to its `/a-z/` entry. **Display:** the `/a-z/` entries (part 2), cloned into Home's result sections (part 4).

**Why:** rules 9, 11 and 12 already pin the feed field by field against the records, D10 and hidden names included, and rule 4 pins every persona name on `/a-z/`, so the search needs no new data file and no new guard for one. The match keys are the published, defanged values, so no live form is ever stored or served.

**Weak point:** the search depends on the public feed contract. A breaking feed change (a new `version`) breaks the search; the script refuses any `version` but 1 and hands over to `/a-z/` (part 4), which reflow case (8) reports as a navigation in the same PR.

**Rejected:**

- A dedicated `/search.json` with pre-rendered strings: it needs a second set of field-by-field, D10 and hidden-name rules, which the feed already has.
- Composing the answer in JavaScript from the feed's enum values (state, type): the D6 and D10 wording would be assembled by code that no static check reads; L7 reads a script's literals, not what it composes from them.
- Pagefind, a Rust tool. Its browser runtime is WebAssembly, so `script-src` would need `'wasm-unsafe-eval'`, a source the `site` check refuses (`CSP_SOURCES` holds only `'self'` and `'none'`) and a relaxation of the criterion "same-origin scripts only"; it emits a generated multi-file bundle, against one pinned source file per script (part 5); and its full-text ranking has no refang or host semantics (part 3).
- A Rust build-time index generator: it would parse the records a second time next to Hugo, which already publishes every key in `/feed.json`, and add a toolchain pin to `tools/pins.env` and to CI.
- A Rust matcher compiled to WebAssembly: the same `'wasm-unsafe-eval'` relaxation, and a binary that neither L7 nor a review reads, against the reviewable source that `SCRIPT_SHA256` pins.
- npm search libraries: D3.

### 2. The A to Z page

`/a-z/` (`content/a-z.md`, with the front-matter switch `a_z = true` read by `layouts/page.html`, the pattern of `channel` and `checklist`). One `ul.index-list` with one `li` per report and campaign record:

- A report entry keeps the list-item contract of render rule 3 (one record link, its D6 chip, its `record-date`) and adds its type (`name_type.*`), its visible aliases (`record.also_seen_as`, each through `record-name.html`, so a persona alias carries the D10 label; none for a hidden name) and its campaign family (`campaign_line.named` plus the campaign link, or `campaign_line.unattributed`).
- A campaign entry: its link, date, the type `a_z.campaign_type` and its aliases.
- After the list, the no-report block (part 4).

Order: the plain-text name as `record-name.html` renders it, lowercased, then the section, then the slug. This is the key of `record-list.html` plus the section, because a report and a campaign may share a slug, and it sorts a hidden name by its placeholder, so its position leaves no trace of the name.

No-JavaScript path: the Home search form submits `get` to `/a-z/`, and a visible link to `/a-z/` sits in the search card whether the script runs or not.

**What an entry shows (STOP 1 decision 1, operator, 2026-11-08, as recommended):** name (with the D10 label), D6 chip, date, type, aliases and the campaign family named without its source; no state sentence and no D7 label. Why: the entry is also what an exact answer and every partial candidate show (part 4), and an answer has to fit one phone screen (SPEC §2, §8 Mobile). The state sentence (82 characters in the name abused state, 62 in the front state) would add a paragraph to every entry, at least one more line at the 412 CSS px viewport, against the one-screen height that `SEARCH_PARTIAL_CAP` is derived from (Numbers). The entry also keeps the list-item contract of render rule 3 that every record list already follows: Home and `/reports/` show the chip without the sentence. The D6 chip carries the state, and the report page, one tap away, holds the state sentence, the D7 label and the source. The fetch size is no reason either way: the sentence is one of two fixed strings, which gzip stores as back-references, 1.6 bytes per entry on a synthetic list of 550 entries at level 6 (19,160 bytes without the sentence, 20,054 with it). **Weak point:** an exact answer for a real company's name carries only the two-word chip ("Name abused"); the sentence that says the name was used without the company's involvement is one tap away on the report page.

**No lookup by artifact without JavaScript (STOP 1 decision 3, operator, 2026-11-08, as recommended; decided scope, not an open limit).** SPEC §6's fallback stays as written: `/a-z/` lists names and campaign families, not artifacts, and no follow-up issue is filed. Why:

- (a) D10 and render rule 4: a persona's artifacts can contain the persona's name (a handle, an email address), and rule 4 exempts them only inside that persona's own artifact boxes on its own report page. On `/a-z/` each would need the label or would be a finding.
- (b) `/a-z/` is also what `search.js` fetches, so artifacts there would cut the record ceiling of `SEARCH_FETCH_BUDGET` (Numbers), and a separate artifact list would need its own page, its own render rules and its own Lighthouse audit.
- (c) The share of visits without JavaScript is small. GOV.UK measured in 2013 that 1.1 % of 509,314 visits did not receive JavaScript enhancement: 0.9 % had JavaScript enabled but it did not run, 0.2 % had it disabled or unsupported (GDS blog, "How many people are missing out on JavaScript enhancement?", 2013-10-21, https://gds.blog.gov.uk/2013/10/21/how-many-people-are-missing-out-on-javascript-enhancement/). The figure is from 2013, and no newer public measurement is known.
- (d) Report pages carry every artifact, and search engines index them (SPEC §2), so a web search for an artifact reaches its report page without the site's script.

**Weak point, stated:** a visitor without JavaScript who holds only a hash, a repository or a domain that does not carry the app's name has to use a web search, and a brand-new record may not be indexed yet.

**Rejected:**

- A `<noscript>` link to the index: `site` rule (i) and `render` read `<noscript>` content as raw text and as hidden content, and a visible link serves both states with no new rule.
- `/reports/` plus `/campaigns/` as the fallback: two lists without aliases, type or family, where the issue asks for one alphabetical index of every report and campaign.
- Showing the state sentence and the D7 label in every entry (decision 1): the height per entry above, for wording one tap away.
- Artifacts on `/a-z/` or on an artifact page without JavaScript (decision 3): reasons (a) to (d).

### 3. Matching rules

The contract that `search.js` (PR 3) and the independent Python oracle `search_expect` of reflow case (8) (PR 4) both implement:

- `fold(s)`: NFKC; every code point of `DEFAULT_IGNORABLE` (the ranges `tools/sitecheck.py` already uses, Unicode's Default_Ignorable_Code_Point) removed; every `DOT_CHARS` member to `.`; Unicode default lowercase (`toLowerCase` in JavaScript, `str.lower` in Python); runs of whitespace to one space; trimmed.
- `refang(s)`: the `DEFANGS` table of `sitecheck.py` (`[.]`, `[://]`, `[:]`, `[@]`) and `hxxp` to `http`, applied after `fold`.
- `bare(s)`: a leading `http://` or `https://` removed, then a leading `www.`, then a trailing `/`.
- Keys of an entry: the name keys `fold(name)` and `fold(alias)` (a `null` name gives none); the value keys `bare(refang(fold(v)))` for every artifact value, handles also without a leading `@`; the domain keys, the value keys of `domains[]` without a trailing `.`.
- Query forms: `f = fold(q)`; `r = bare(refang(f))`; `r0`, `r` cut at the first `?` or `#`; `r_at`, `r` without a leading `@`; and the host `h`, which is `r0` cut at the first `/`, after its last `@`, before its `:`, without a trailing `.`, formed only when `r0` holds a `.` and no space.
- **Exact:** `f` is a name key, or `r`, `r0` or `r_at` is a value key, or `h` is a domain key or ends with `.` plus a domain key. URL artifacts give no host key, because a payload on a shared host would otherwise answer for every link on that host. Exact answers are all shown, in `/a-z/` order: a key shared by several records is rare, and each record is an exact hit.
- **Partial**, only without an exact match and only when `fold(q)` has at least `SEARCH_PARTIAL_MIN` code points: `f` or `r` is a substring of a name key or a value key; the first `SEARCH_PARTIAL_CAP` matches in `/a-z/` order.
- **None:** neither. An empty `f` shows no section, and focus stays in the input.

**Why:** a candidate pastes what they received, a live URL with a scheme, `www.`, a path or a query, a handle with or without `@`, or types a name in any case. Each query form strips one such difference, and the feed holds the defanged form, so both sides are folded and refanged to meet in the middle (#5 criterion "a pasted live URL or bare domain matches the record's defanged artifact"). The fold reuses the tables the record checks already use, so the search and the defang checks agree on what a dot and an invisible character are. Exact match has no minimum length, because D6 names Nx, a two-character package name.

**Weak point:** JavaScript and Python may disagree on an edge of `fold`, because Chrome and the runner's Python can ship NFKC tables of different Unicode versions. Case (8) types the fixture records' own values and every member of the two tables, which both versions know, and a disagreement is a finding that names the query, not a silent pass.

**Rejected:** a host key from URL artifacts (the shared-host answer above).

### 4. Result display

Home holds `div#search-results.search-out[hidden]` with three hidden sections: `#search-answer` (heading, an empty `ul.index-list`, the What to do now panel of the report pages), `#search-partial` (heading, an empty `ul.index-list`, the `/a-z/` link, the no-report block) and `#search-none` (heading, the no-report block). The script fetches `/feed.json` and the form's `action` page in parallel on the first `focus` of the input or the first submit, never on load, sets `aria-busy` on `#search-results` while it waits, then clones the matching `/a-z/` entries (`document.importNode`), reveals exactly one section and moves focus to its heading (`tabindex="-1"`), which also scrolls the answer into view. The query is never echoed into the page. A failed fetch, or a feed `version` other than 1, hands over to the no-JavaScript path (`form.submit()` to `/a-z/`). No `innerHTML`, no timers, and no URL other than `/feed.json` and the form's `action`.

**Why:** no request is made before the visitor acts, so Lighthouse's performance measure of Home is unchanged; the fetch starts on focus, so it runs while the visitor types (`SEARCH_FETCH_BUDGET`, Numbers). The query may be a live attacker URL (D8), and the input already shows it, so echoing it would only put a live form into page text. Moving focus to the heading tells a screen-reader user that the answer came and puts it at the top of a phone screen. The no-report block says the registry has no report and that this does not mean the name is safe, with links to Before your call and Report a scam (#5 criterion). Cloning keeps the script free of copy and of markup strings.

**Weak point:** between PR 3 and PR 4 the revealed sections are proven only by their static rules (render rule 16 and the hiding rule); case (8) is their outcome half. Pages stays off until M6, so nothing is public in between.

**Rejected:** search as you type: it needs a debounce constant with no data behind it, and the criterion is one query and one submit.

### 5. Scripts

*Amends ADR-0004 part 11 ("at most one script").* Two pinned scripts: `copy.js` on every page and `search.js` on Home only (`eq .Kind "home"` in `baseof.html`), both through `resources.Get | resources.Minify | resources.Fingerprint "sha384"`, printed with `integrity` and `defer`. `site` rule (j) becomes: every built `.js` or `.mjs` file is `/js/<stem>.min.<96 hex>.js` for a stem of a `SCRIPT_SHA256` key under `assets/js/`, at most one file per stem, and every `<script src>` names one of them in the closed path form of `resource_path`.

**Why:** one pin per feature keeps each script's review and re-pin to its own change, and record pages do not load search code they never run.

**Weak point:** a second script on Home costs Lighthouse performance; it is deferred, a few KB minified and makes no request before the visitor acts, and the PR's `lighthouse` run measures Home at 95 or more.

**Rejected:**

- Merging the search into `copy.js`: one pin for two features, so a Copy fix re-pins the search, and every record page loads search code it never runs.
- A `resources.Concat` bundle: it reopens the ban of `LITERALS_RESOURCE_TARGETS`, which exists so that a served script comes only from one pinned source file.

### 6. Checks

- **Render rule 15** (PR 2): `/a-z/` exists; its one `ul.index-list` holds exactly one `li` per report and campaign record, each with one record link outside `.index-campaign`; each report entry names its campaign family in the pinned wording or `unattributed`; one visible no-report block in the pinned wording links both pages; Home has a visible link to `/a-z/` and its one `form[role=search]` submits `get` to `/a-z/`.
- **Site rule (j) for the pinned set and the hiding rule for a table of classes** (PR 3): `copy` and `search-out`, each needing exactly one top-level `.<class>[hidden]` rule that is exactly `display: none !important`, in a stylesheet every page with such an element applies under rule (k); `!important` is allowed only there and in `.visually-hidden`.
- **Render rule 16** (PR 3): the hidden result markup on Home, exactly as the script reveals it, with empty lists, so no report link, chip or name sits hidden on Home.
- **Reflow case (6)** for that class table (PR 3): `search-out` computes `display: none` in S0 (no query made), S1 and S2.
- **Reflow case (8)** "search" and the Lighthouse emulation pin (PR 4): at `SEARCH_VIEWPORT` with touch emulation, queries derived from the tree's `feed.json` are typed and submitted, and each answer is compared with `search_expect` (part 3): no navigation, no request outside the served origin (D9), exactly the expected section, entries and order, entry text equal to the `/a-z/` entry, focus on the section heading, the first answer's heading and first entry inside the viewport, the revealed sections reflowing at 320 × 640, and the gzip size of the two fetched files within `SEARCH_FETCH_BUDGET` (finding (g)). The score gate pins `configSettings.screenEmulation` (`mobile`, `disabled`, `width`, `height`), `throttlingMethod` and `throttling` (`rttMs`, `throughputKbps`), so a Lighthouse upgrade or a flag that moves any of them turns the gate red.

Both new rule groups run by default and are switched off per fixture with `--no-search`, the `--no-feed` precedent, and the wiring lines prove that `check.sh` never passes the flag.

**`SEARCH_FETCH_BUDGET` is enforced in CI (STOP 1 decision 2, operator, 2026-11-08, as recommended):** finding (g) of case (8) fails a tree whose `feed.json` plus `a-z/index.html` exceed the budget after gzip. Why: the budget is what keeps the Mobile criterion true as records are added, and a number nobody enforces drifts until a candidate waits. Scaling point: about 550 records, if a record takes about 0.7 KB of the two files after gzip (KB = 1,000 bytes here: 385,655 / 700 ≈ 551), an estimate that PR 4 replaces with the measured bytes per record. **Weak point:** once the registry gets there, CI blocks content PRs until a split index lands. Rejected: reporting the size without a gate (the regression shows only in a visitor's wait).

**Why the checks look like this:** every one of the 216 render fixture cases has a Home page and none has `/a-z/`, so a rule that ran everywhere would turn them all red; `--no-search` is per fixture, never in `check.sh`. Case (8) lives inside `sitecheck reflow` for the reason of ADR-0003 part 6's M3 PR 10 amendment (its plan decision 3): a separate subcommand adds a Chrome launch per tree, a CI-only step and a final local line. That also answers ADR-0004 part 11's rejection of a Chrome test for Copy, "a third CI-only step and a new final local line": case (8) adds neither. Its oracle is independent Python, so the script cannot pass by agreeing with itself, and its queries are derived from the feed, which rule 12 proved equal to the records, so a record added in M5 is searched for without a fixture edit. The `search-out` class gets the Copy button's hiding rule for the Copy button's reason (ADR-0004 part 11), restated here: an author `display` beats the browser's `[hidden]` rule, and a selector need not name the class to match the element, so without `display: none !important` the result sections could show, empty, without the script.

**Weak points:** render rule 15 does not check the `/a-z/` order: the order is presentation, no D rule depends on it (a hidden name's position is fixed by sorting on the rendered placeholder, as on `/reports/`, whose order `render` does not check either), and checking it would need a second implementation of Hugo's `lower` and `sort` string comparison in Python for no D-rule gain. Case (8) runs only in CI, in one engine (the runner's unpinned Chrome, ADR-0003 part 7) and at one viewport; locally the reflow `NOT RUN` line names it. Live artifact forms are typed in CI: they are computed in memory only, never written or printed (findings print the defanged form), and finding (b) proves the page requested nothing for them.

**Rejected:** a separate subcommand for case (8), for the reason above.

## Numbers

| Number | Derivation | What breaks at another value |
|---|---|---|
| `SEARCH_PARTIAL_MIN` 3 code points | Exact match has no minimum, because D6 names Nx, a 2-character package name. For partial matches, of the 13 names in SPEC §1 (Meeten, Meetio, Meetone, Clusee, Cuesee, GrassCall, Relay, MeetLab, Juseo, Meetix, Carolla, Webex, Saifuro), the 2-character substring "ee" is in 7, while the 3-character "mee" is in exactly 5, the "Meet…" meeting apps of two families (Meeten, Meetio and Meetone of the Meeten family, MeetLab and Meetix of JobStealer), which a candidate holding a "Meet…" link would want to see together. | At 2 a short fragment lists more than half the registry, above the cap, so the candidates carry no signal. At 4 the fragment "mee" that a hurried candidate types finds nothing. |
| `SEARCH_PARTIAL_CAP` 5 entries | The largest set of SPEC §1 names that share a 3-character fragment is those 5 ("eet" marks the same 5; every other 3-character fragment is in at most 2). Five entries of at most about three lines each (about 90 px each), plus the heading, the no-report block and the `/a-z/` link, stay under the 823 px viewport height once focus scrolls the heading to the top; PR 4 prints the measured height of the partial section. | At 4 one "Meet…" app is cut. At 10 the list runs past one phone screen. |
| `SEARCH_VIEWPORT`: Lighthouse's mobile emulation, 412 × 823 CSS px, mobile, for the current pin | Read from `configSettings.screenEmulation` in the pinned Lighthouse's own reports, and pinned by the score gate (part 6). Its own reason here: #5's criterion is the answer in the viewport Lighthouse measures, not a viewport of this ADR's choosing. | Another size proves the answer visible on a screen Lighthouse never measures, which is not what the issue's mobile criterion asks. |
| Answer wait: `REFLOW_TIMEOUT` (30 s) | Its own reason here: on loopback both fetches take milliseconds, so the wait only bounds a hung script; the existing per-call ceiling of `sitecheck reflow` avoids a second constant with no measurement behind it. | Shorter adds an unmeasured constant; longer only delays a failing run. |
| `SEARCH_FETCH_BUDGET` 385,655 bytes (gzip, `feed.json` plus `a-z/index.html`) | (T_type − RTT) × throughput. T_type is the time to type a median name: the median length of the 13 SPEC §1 names is 6 characters (lengths 5, 5, 5, 6, 6, 6, 6, 6, 7, 7, 7, 7, 9), and mobile typing averages 36.2 words per minute (Palin et al., "How do People Type on Mobile Devices? Observations from a Study with 37,000 Volunteers", MobileHCI 2019, doi:10.1145/3338286.3340120), at the text-entry convention of 5 characters per word 36.2 × 5 / 60 = 3.0167 characters per second, so T_type = 6 / 3.0167 = 1.989 s (exactly 360 / 181 s, used unrounded below). RTT 150 ms and `throughputKbps` 1,638.4 (1.6 × 1,024) are Lighthouse's `mobileSlow4G` profile, which the `lighthouse` job measures under the default `throttlingMethod` `simulate` (`tools/lighthouse.sh` passes no throttling, preset or config flag); the gate pins all three (part 6). Lantern converts with 1 kbit = 1,024 bit: `options.throughput = throttling.throughputKbps * 1024` in `Simulator.createSimulator` (case `simulate`), and `bytesPerSecond = this.throughput / 8` in `TCPConnection`, so 1,638.4 × 1,024 / 8 = 209,715.2 bytes per second. Source checked: `models/trace/lantern/simulation/Simulator.js` and `TCPConnection.js` of `@paulirish/trace_engine` 0.0.67, read from the npm registry's tarball (its sha512 equals the registry's `dist.integrity`); Lighthouse 13.6.0 (`tools/pins.env`, tag commit `edc407d`) depends on exactly 0.0.67 and re-exports it in `core/lib/lantern/lantern.js`, and the pinned tree (PR #15) holds `@paulirish/trace_engine@0.0.67`. floor((360 / 181 − 0.15) × 209,715.2) = floor(385,655.82) = 385,655. Gzip at level 6, zlib's default; a server that compresses harder only makes the transfer smaller. PR 4 prints the bytes per record. The gate pins the profile and the method but not lantern's code, so a Lighthouse re-pin re-checks this conversion in its `@paulirish/trace_engine` version. | Above it the fetch outlasts the typing of a median name, and the answer waits after the submit on the profile Lighthouse measures. Below it CI fails before the visitor waits. |
| Scaling point about 551 records (STOP 1 decision 2) | 385,655 / 700 ≈ 551, with an estimated 0.7 KB (700 bytes) per record of the two files after gzip; PR 4 replaces the estimate with the measured bytes per record. | A record larger than estimated reaches the budget earlier; the gate then fails at the measured point, not at this estimate. |
| Feed `version` accepted by the script: 1 | The only version the feed has (ADR-0004 part 7); any other means a breaking change the matching rules of part 3 were not written for. | Accepting a later version would match against fields whose meaning may have changed. Rejecting 1 would hand every search over to `/a-z/`. |
| Pinned scripts: 2, one per feature (amends ADR-0004 Numbers, "Script pin: SHA-256, one entry per script") | Part 5: `copy.js` and `search.js`, each its own `SCRIPT_SHA256` entry. SHA-256 stays, for ADR-0004's reason restated here: a pin needs collision resistance, and the repo pins its downloads with SHA-256. | One script: the merge part 5 rejects. More: a feature split across files with no reader that needs it. |
| Lighthouse page count 16 to 18 (amends ADR-0004 Numbers, "Lighthouse page count 16") | The production `/a-z/`, audited automatically as every directory with an `index.html`, and the fixture `/a-z/index.html` in `LH_FIXTURE_PAGES`. The `lighthouse` timeout is re-derived in PR 2 with ADR-0004's formula, because it is the same job with two more pages; its inputs come from PR 2's own measured runs, not from ADR-0004's. | A stale count keeps a timeout derived for 16 pages, and the slowest normal run can be cancelled. |
| Case (8) variant queries: one per `DOT_CHARS` member (3) and per `DEFAULT_IGNORABLE` range (17, its first and its last code point) | The per-member rule of the routing table, applied to the script's two tables: each member is exercised once. | Fewer members: the script can drop one and stay green, as QA showed for the L2 attribute set on #29. |

## Consequences

- PRs 2 to 4 are safety-net PRs (`tools/`), PR 2 and PR 3 also content PRs (`data/labels.toml`, `content/a-z.md`, a new `assets/**/*.js`), so they get `sdlc-reviewer` with QA and the operator's D7 wording approval at their STOP 2.
- The search depends on the feed: a field change that the matching rules read edits `search.js`, `search_expect` and this ADR's part 3 in the same PR, and a breaking feed change (a new `version`) needs a search change before it merges, or case (8) turns red.
- `/a-z/` is a load-bearing page: `search.js`, render rules 15 and 16 and case (8) read it by name, as they read the ids `q`, `search-results`, `search-answer`, `search-partial` and `search-none` and the classes `index-list`, `no-report` and `search-out` (PR 3 lists them in `CLAUDE.md`).
- Once the registry approaches the scaling point, CI blocks content PRs until a split index lands (decision 2).
- A Lighthouse re-pin re-reads `SEARCH_VIEWPORT` and the throttling profile from its reports and re-checks the lantern conversion of `SEARCH_FETCH_BUDGET` in its `@paulirish/trace_engine` version.
- PR 4 updates the Numbers above with the measured values: gzip bytes per record, the viewport and throttling from the pinned report, the measured height of the partial section.
- `check.sh` gains no step and no final line; its reflow `NOT RUN` line names the search's hidden state (PR 3) and case (8) (PR 4).
- #32 (the CSP `http-equiv` trim and render's `urljoin`) starts after PR 4 merges, rebased on `main`: it rewrites `site_path`, the one reader rules 15 and 16 call, so its closed form is derived from trees that already hold `/a-z/`, the new form action and the Home link. This milestone does NOT address #32.
