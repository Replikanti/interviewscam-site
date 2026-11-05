# ADR-0003: Browser checks

## Status

Accepted, 2026-11-04 (operator, issue #3, STOP 1; decisions 1 to 5 of the plan). Implements the Lighthouse and accessibility rows of SPEC §8 and tightens D3. The implementation lands in sequenced PRs under milestone 2 (#3): the Lighthouse workflow in PR 2, the reflow check in PR 3.

## Context

SPEC §8 requires Lighthouse scores of at least 95 in performance, accessibility, best practices and SEO on the mobile profile, and WCAG 2.2 AA. D3 says that tooling which exists only on npm (Lighthouse, for example) may run only in CI jobs that hold no write token and do not produce the deploy artifact. M1 (ADR-0002) built the checks that need no browser. Milestone 2 is the first one that can measure a layout, so it needs a browser check, and Lighthouse is npm-only.

Facts, as of 2026-11-04:

- `lighthouse` 13.6.0 was published on 2026-10-27 and needs `engines.node >=22.19`. It has 22 direct dependencies, among them `puppeteer-core` and `@sentry/node`, so most of the code that would run is transitive.
- The runner image `ubuntu-24.04` (image version 20261026) ships Node.js 22.23.4, npm 10.9.9 and Google Chrome 156.
- The 2025 registry compromises (the `chalk`/`debug` maintainer phishing in September, the Nx release in August, the Shai-Hulud worm waves in September) shipped malicious versions of widely used packages. Those versions were pulled within hours to a few days.
- In the tj-actions/changed-files compromise (March 2025), injected code read the tokens of its own job from the runner process memory.
- The D3 text before this ADR: "...may run only in CI jobs that hold no write token and do not produce the deploy artifact".
- The campaigns this site documents spread through npm packages, so a registry compromise is the threat model, not an abstract risk.
- The operator's host has Google Chrome only as a flatpak (`com.google.Chrome`), not on `PATH`, and no container runtime. No browser check runs locally.
- Lighthouse has no audit for WCAG 2.2 SC 1.4.10 (reflow).
- Lighthouse 13.6.0's `canonical` audit (`core/audits/seo/canonical.js` at tag v13.6.0) reports Conflict, Invalid, Relative, PointsElsewhere (hreflang) and Root. Its only origin rule, "points to the root", fires only when the canonical URL's origin equals the audited page's origin. It has no different-domain failure. A page `https://interviewscam.com/about/` audited at `http://localhost:<port>/about/` therefore scores 1 (reproduced in the PR 1 review).
- The existing workflows (`ci.yml`, `deploy.yml`, `links-external.yml`) all run `check.sh`, each with `timeout-minutes: 2`. The 11 green `check` jobs on 2026-11-04 took 20 to 44 s (median 35 s).

## Decision

Seven parts. Each has its own reason and rejected alternatives.

### 1. Lighthouse pin: exact version, a 7-day cooldown date and a digest of the resolved dependency tree, no lockfile in the repo

`tools/pins.env` gets `LIGHTHOUSE_VERSION`, `LIGHTHOUSE_BEFORE` (the pin date minus 7 days, ISO UTC) and `LIGHTHOUSE_TREE_SHA256`. The job resolves the tree in lock-only mode with `--before` and install scripts off. `sitecheck tree-digest` hashes the sorted `name@version sha512-integrity` lines and compares the result to the pin. Only then does the job install from that lock, again with scripts off. No registry code runs before the digest matches. On the first run and on every upgrade the job prints the digest and the resolved list and fails, and the pin PR copies the digest in. For a pin made on 2026-11-04 the date is `2026-10-28T00:00:00Z`, and 13.6.0 (published 2026-10-27) qualifies.

**Why:** the goal is D3. The registry code that runs in CI is exactly the tree recorded at pin time and cannot drift between runs. The digest proves the tree is unchanged. It does not prove the tree is benign, and nobody reviews the code of 22 direct dependencies and their transitive tree: the printed list shows only `name@version` lines. The data is in Context: most of the code is transitive, so pinning only the top-level version leaves almost all of it floating. A cooldown date makes the resolver ignore versions published after it, so a malicious release has days to be noticed and pulled before it can be resolved. A digest of the resolved tree makes any change in that resolution visible.

**Why 7 days:** the incidents above were pulled within hours to a few days. Seven days leaves a margin over the multi-day worm waves, at the cost of running each release one week late. A shorter window can resolve a version that has not been detected yet. A longer one only delays upgrades.

**Weak points:**

- A slow-burn compromise passes the cooldown and is then locked in by the digest. A malicious insertion older than 7 days at pin time (event-stream 2018: flatmap-stream 0.1.1 published 2018-09-09, found 2018-11-20, about 10 weeks live) resolves, matches the digest and runs on every CI run until the next re-pin. The boundary for this case is the isolation in part 2: the job has no secrets, no source and does not produce the deploy artifact. The cooldown narrows the window for fast-caught incidents only.
- The digest depends on the runner's resolver. A runner image whose npm resolves the same ranges differently fails the job loudly and forces a re-pin PR.

**Rejected:**

- A committed lockfile. The guard's file rule rejects lockfiles by name, D3 forbids generating one on a developer machine, and generating one in CI needs a dispatch workflow that only works once it is on `main`.
- The exact top-level version alone. Every transitive dependency floats on every run.
- A container image with Lighthouse. The Lighthouse project publishes none, so a third-party publisher would become the trust root.
- The PageSpeed Insights API. It needs a public URL while Pages is off until M6, and it is a third-party service.

### 2. Isolation: the registry code runs in its own job whose `GITHUB_TOKEN` has no permissions and that sees only the built site and the check scripts

D3 is tightened to: "...may run only in CI jobs whose `GITHUB_TOKEN` has no permissions (`permissions: {}`), that see only the built site and the check scripts (never the repository source), and that do not produce the deploy artifact, never on a developer machine. Every job still carries the Actions runtime token (artifact and cache services), so no workflow restores a cache and the deploy path never reads anything that job can write ([ADR-0003](adr/0003-browser-checks.md) part 2)." The SPEC and this part say the same thing.

Design:

- Job `build`: `contents: read`, checkout with `persist-credentials: false`, `bash tools/check.sh`, then it uploads `public/` and `tools/` as an artifact that is not named `github-pages`, with 1-day retention.
  *Amended by ADR-0004 part 10: from M3 the artifact also carries `public-fixtures/`, the fixture build of the record templates. The deploy artifact stays `public/` only.*
- Job `lighthouse`: `needs: build`, `permissions: {}`, no checkout. It downloads that artifact, runs `bash tools/lighthouse.sh` and uploads nothing.
- No workflow restores an Actions cache, and no cache action is allowlisted. The deploy path builds its own artifact with `check.sh` and never reads the artifact of `lighthouse.yml`. So a runtime token stolen in the `lighthouse` job cannot poison the deploy path. M6 must keep it that way.
- The guard enforces the read side (added in the PR 2 review). The runtime token can delete and replace an artifact of its own run, so in that run nothing that holds a token, and nothing on the deploy path, may read an artifact after the `lighthouse` job has started. `actions/download-artifact` is allowed only in the job `lighthouse` of `lighthouse.yml`. No workflow may use a `workflow_run` trigger, which would let another workflow download this run's artifacts. No job may `needs:` the `lighthouse` job, so it stays a leaf. The `lighthouse` job uploads nothing.
- No credential other than the empty `GITHUB_TOKEN` reaches the `lighthouse` job. In `lighthouse.yml` any `secrets` or `github.token` reference fails the guard (in `with:`, `env:` or `run:`, comments included), and so do the download inputs `github-token`, `run-id` and `repository`, which read other runs or repositories.

**Why:** the goal is D3 and D4. Drafts and history stay private, and nothing from the registry can reach the deploy path. Because injected code can read the tokens of its own job from process memory (Context), every token in a job that runs registry code must count as readable by that code, and `persist-credentials: false` alone does not help. A job that runs registry code cannot be made token-free, because every job carries the Actions runtime token. It can be made harmless: a `GITHUB_TOKEN` with no permissions, no source in the workspace, and nothing it can write that the deploy path later reads.

**Weak points:**

- The `lighthouse` job still holds the Actions runtime token, which injected code can read and which reaches the cache and artifact services. The rule "no cache restore anywhere, and the deploy path never reads this artifact" is the only thing that makes it harmless.
- Two more action pins (`actions/upload-artifact`, `actions/download-artifact`). PR 2 must prove that the download works under `permissions: {}`. The fallback is `actions: read`, which still grants no repository contents. Using it is allowed only if PR 2 amends the D3 wording and this part in the same PR, because "no permissions" would no longer be true.
- The score gate runs in the same job as the tool, so a compromised tool could fake its own scores. The gate is a quality gate, and the security boundary is the pin plus the isolation.

**Rejected:**

- One job with a full checkout. The registry code would read the private source and the `GITHUB_TOKEN`.
- Deleting the checkout before the install. The ordering is fragile, and the token stays in runner memory.
- A sparse checkout of `tools/`. It still needs `contents: read` in that job.

### 3. The gate: median of 3 runs per page, at least 95 in each of the four categories, mobile profile asserted, same-origin requests only

`sitecheck lighthouse` takes exactly 3 reports per page and fails otherwise. It fails on any `runtimeError`, on a `lighthouseVersion` other than the pin, on a `formFactor` other than `mobile`, and on a missing or null category score. The median of each category per page must be at least `LIGHTHOUSE_MIN_SCORE` (95), a constant in the script and not a flag, so a workflow cannot lower it. Every `network-requests` item must be on the local origin, a runtime D9 check next to the static one. For each category under the threshold it prints the failing audits.

Lighthouse's `canonical` audit runs normally; no audit is skipped. Next to it, a `sitecheck site` canonical rule (PR 3) stays as an extra guard: every HTML page except `404.html` has exactly one `<link rel="canonical">` equal to `https://interviewscam.com` plus its own path, and `404.html` has none. Lighthouse does not check that a canonical equals the page's own path, so the rule adds a check and replaces none. Verification: the Lighthouse run of PR 2 or PR 3 (whichever first has canonical tags on the audited pages) shows the `canonical` audit passing, and the run URL goes into the PR body.

**Why:** the goal is a §8 score that measures the site as Lighthouse defines it, with canonical tags checked on top. An earlier draft skipped the `canonical` audit on the claim that Lighthouse fails a canonical URL on another domain than the audited page (CI audits `http://localhost:<port>/`, canonicals are `https://interviewscam.com/...`). The v13.6.0 source has no such failure (Context), so the skip had no cause and is dropped. The version and form-factor assertions stop a silently changed tool or profile from producing a green that means something else. The threshold 95 comes from SPEC §8 (a static page scores about 100, so lower means a regression). A single run is noisy, and the median of an odd number of runs absorbs one bad run without ignoring a real drop.

**Weak point:** a newer Lighthouse could add a different-domain rule and fail every page at `localhost`. The version is pinned (part 1), so it would surface in the upgrade PR, and the answer then is a new decision, not a silent skip.

**Rejected:**

- Skipping the `canonical` audit (`--skip-audits=canonical`). Its stated reason does not exist in the pinned version, and a skip that is not needed hides a real SEO audit.
- Serving under the production hostname with a local TLS certificate and Chrome host-resolver rules. Not needed, and certificate handling would become harness behaviour that needs its own proof.
- No canonical tags. It is an SEO loss, and M3 record pages need them.
- Relative canonical URLs. They are invalid for search engines and Lighthouse reports them (Relative).

### 4. Trigger: PRs that change site-shaping paths, every push to `main`, manual start; not a required check

The workflow runs on pull requests that touch `layouts/**`, `assets/**`, `static/**`, `data/**`, `i18n/**`, `archetypes/**`, `content/*.md` (the static pages, not the record sections), `hugo.toml`, `tools/**` or `.github/workflows/lighthouse.yml`, on every push to `main`, and on manual start. `check` stays the only required status check.

**Why:** the goal is that §8 is measured before merge for every PR that can change the layout, and that a registry outage never blocks a D7 removal PR (the principle of ADR-0002 part 7). The job depends on the public package registry on every run. A required check must report on every PR, which a path-filtered workflow cannot do. Agent sessions still treat a `lighthouse` run, once it exists on a PR, as blocking: never merge it red or pending.

*Amended by ADR-0004 part 10: PR 4 adds `tests/fixtures/records/pass-fixture-site/**` to the PR path filter, because that fixture set changes the five audited fixture pages. The production record sections stay outside the filter.*

**Weak point:** a record-only PR is measured only after merge, by the push run on `main`. After M6 that is after the deploy. Template and CSS changes, the plausible way to break a score, always run before merge.

**Rejected:**

- Every PR with a required check. A registry outage would block a removal, and the §9 emergency path names only `check`.
- A weekly schedule only. A regression would merge unmeasured.

### 5. Timeouts derived from data

Every job sets `timeout-minutes` (the 360-minute default would let a hung run block merges for hours). A timeout is a hang cap: too low turns runner variance into red runs, too high lets a hang block for long.

- Job `build` (it runs the same `check.sh` as `ci.yml`): 3 times its first green run, rounded up to whole minutes. The factor comes from data: the 11 green `check` jobs of 2026-11-04 took 20 to 44 s, so the slowest took 2.2 times the fastest and 1.26 times the median. 3 is the smallest whole factor above 2.2, so even if the first green run happens to be the fastest, the slowest observed run still fits. The current cap of 120 s is 2.7 times the slowest observed run. Caveat: the sample is M1 runs of a script that grew, and `check.sh` still gets steps in M2.
  *Amended by ADR-0004 (Numbers): the factor 3 is not carried. The 16 green `check` jobs since the reflow step took 78 to 109 s, a spread of 1.40, so the factor is 2 times the slowest green run.*
- Job `lighthouse`: this job is dominated by CPU-bound Chrome audits and a cold registry resolve and install, so `ci.yml`'s reason (downloads and an image pull) does not carry over, and no variance data exists for it yet. Provisional value, 30 minutes, labelled provisional until PR 2 measures it: setup 4 min (assumed: a cold resolve and install of a tree rooted in 22 direct dependencies, plus the artifact download, doubled from an assumed 2 min for headroom) plus 2 pages (Home and 404 on the M1 skeleton) × 3 runs × 60 s (assumed: a cold Chrome start and a mobile run with simulated throttling on a 2-vCPU runner, twice an assumed 30 s) = 10 min, times a margin of 3 (the check-job factor, used here only until the job has its own data) = 30 min. Before merge it is replaced by `ceil(3 × (T_setup + 8 pages × 3 runs × T_run))`, from the times `lighthouse.sh` prints. Once 10 green runs exist, the factor is re-derived from their observed slowest-to-fastest ratio the way it was for `build`; until then 3 stays. Eight is the page count at the end of M2 (Home, 404 and the six static pages), so the value holds through PR 5. M3 re-derives it.

*Amended by ADR-0004 part 10: the page count becomes 16 (five fixture pages join) and the formula uses 16 pages.*

**Rejected:** the default of 360 minutes (a hung run blocks for hours), and a guessed fixed value with no estimate behind it.

### 6. Reflow at 320 CSS px: an automated, CI-only check in `check.sh`

`sitecheck reflow` (standard library only) serves `public/` on localhost, starts the runner's Google Chrome headless with `--remote-debugging-pipe` (no websocket, no registry code), sets a 320×640 mobile viewport, loads each page and measures geometry, not CSS properties. It fails in five cases, naming what it found: (1) page-level overflow, `document.documentElement.scrollWidth` exceeds 320; (2) a word of text (one DOM range per run of non-space characters) or the box of a replaced element (`img`, the outermost `svg`, `video`, `audio`, `iframe`, `canvas`, `object`, `embed`, `input`, `select`, `textarea`, `meter`, `progress`) does not lie horizontally within [0, 320]; (3) such a word or element does not lie horizontally within the box of every clipping ancestor, meaning an ancestor whose computed `overflow-x` is not `visible`, whose `contain` includes paint (`paint`, `content`, `strict`), whose `content-visibility` is not `visible` (padding box for these three), or that has a `clip-path` or a `clip` (border box); (4) an element with the class `visually-hidden` whose box is larger than 1 × 1 px or whose computed `display` is `contents`; (5) an `input`, `textarea` or `select` whose `scrollWidth` exceeds its `clientWidth` (text inside a form control has no DOM range, so case (2) cannot measure it). The tolerance is 0.5 px for fractional layout. Cases (2) and (3) compare positions, so they do not depend on which property moved or clipped the content; the fixtures pin clipping, scrolling, paint containment, `content-visibility`, `clip-path`, `position: fixed`, negative margins and right-to-left overflow. The clip box of case (3) is the padding or border box, not a `clip-path` or `mask-image` shape. `site` rule (h) bans `<textarea wrap="off">`. A 4xx or 5xx answer of the local server (except `/favicon.ico`, which Chrome requests on its own) fails too, because the page was measured without one of its files. The MVP therefore wraps long hashes and URLs instead of clipping or scrolling them, and there is no allowlist for two-dimensional content (a table or code box that is meant to scroll). That is revisited if M3 brings tables. One exemption exists, by class and not by heuristic: the site has exactly one sanctioned utility class, `visually-hidden` (the standard pattern: `position: absolute`, 1 px box, `overflow: hidden`, `clip-path`). The check skips an element that carries it, and its subtree, only while the element's own box is at most 1 × 1 px at 320 px and its computed `display` is not `contents` (case (4) otherwise). The skip link on every page (PR 4) uses it and is shown on `:focus` and `:focus-visible`; it needs the exemption because its text lies outside its 1 px clipping box. A static `sitecheck site` rule backs the runtime one, counted across ALL built CSS files, not per file: exactly one top-level `.visually-hidden` rule whenever a page uses the class (at most one otherwise), with `display: block`, `position: absolute`, `width: 1px`, `height: 1px`, `overflow: hidden`, `clip-path: inset(50%)` and `white-space: nowrap`, each exactly once and `!important` (`display: block` keeps `display: contents`, which has no box but still paints the text, from applying; an absolutely positioned box is blockified anyway); besides those only `margin`, `padding`, `border` and `clip` may appear (the runtime check catches a value that grows the box); at most one reveal whose selectors are `.visually-hidden:focus` and/or `.visually-hidden:focus-visible`, all `!important`. The class may not be nested inside any at-rule (`@media`, `@container`, `@supports` and every other), no compound or descendant selector may contain it, no declaration may name it, and no attribute selector on `class` is allowed at all (`[class*=ually-hid]` would match it without naming it). The same rule bans `!important` everywhere else in the site's CSS, and inline `style` attributes are already banned (`site` rule (c), and the CSP). What is enforced: in the built CSS only the definition and the reveal carry `!important`, and the definition holds the pinned declarations; a declaration that the definition does not pin (for example `transform` or `zoom` from another rule) can still apply, and the runtime case (4) is what catches it when it grows the box. It runs in `check.sh` under `GITHUB_ACTIONS=true` only. A missing Chrome in CI is FAIL. Locally it prints a loud `NOT RUN` line, and the final line becomes `LOCAL PASS, HTML validation and reflow not run (CI only)`. The check does not look for the operator's flatpak Chrome.

**Why:** the goal is the horizontal part of WCAG 2.2 SC 1.4.10 (reflow) on every page, including the M3 and M5 record pages. Lighthouse has no reflow audit. The main overflow risk arrives with M3 and M5: 64-character SHA-256 hashes and long defanged URLs in mono boxes. Record PRs skip the path-filtered Lighthouse workflow (part 4), so a reflow check there would miss them, while `check.sh` runs on every PR. Using only the runner's Chrome keeps every result from one browser source, as with the Nu Html Checker (ADR-0002 part 1).

**Weak points:**

- The check detects horizontal loss, not every loss of information SC 1.4.10 covers. It does not see overlapping elements, vertical clipping (a box with a fixed height and `overflow: hidden`), content hidden by `display`, `visibility`, `opacity` or a zero size, nor a `clip-path` or `mask-image` shape smaller than its box (case (3) uses the padding or border box, not the shape). Text inside form controls is measured only through case (5), as a whole, not word by word. Text drawn by CSS (`content`) or inside a closed `select` has no DOM range and is not measured. Review covers those. An earlier version (PR #16 before review) checked CSS properties: `overflow-x` and the root scroll width. The review showed a 64-character hash cut off or out of reach under `contain: paint`, `content-visibility: auto`, `position: fixed`, a negative margin and `direction: rtl`, all passing; the geometry cases replace that list.
- Someone could misuse `visually-hidden` to hide content. Review catches that. The mechanism above (one definition across all CSS with the pinned hiding declarations including `display: block`, `!important` only there and in the reveal, no attribute selector on `class`, no inline style, and the runtime check of a box at most 1 × 1 px with `display` not `contents`) turns a stylesheet that un-hides it into a check failure at 320 px; other widths are not measured. What remains: a future first-party script could still toggle the class, and a descendant positioned out of the clipped box is exempt with its ancestor (the `clip-path` of the class still clips it). The only planned script is Copy (M3), and it does not touch the class. It stays the only exemption.
- Content hidden by other `display` or `visibility` rules, including inside media queries, is still not seen (see the first weak point).
- Chrome is not pinned (part 7), and a second CI-only step widens the gap between a local green and a CI green.

**Rejected:**

- A manual check only. There would be no regression net for M3 and M5.
- A script on the Lighthouse side. It is registry code, and it is skipped on record PRs.
- Pinning a Chrome for Testing build through `fetch-tools.sh`. It costs about 150 MB per run for a layout measurement that is stable across Chrome versions.

### 7. Node and Chrome come from the runner image, unpinned

The `lighthouse` job uses the Node.js and Google Chrome that ship with the `ubuntu-24.04` image, and the reflow step of `check.sh` (part 6) uses the same Chrome. They are not pinned, and `actions/setup-node` is not used.

**Why:** the goal is the smallest trusted surface. The image's Node 22.23.4 satisfies the Lighthouse engine floor (`>=22.19`), and the image is already the root of trust for the whole job. Chrome affects a score by a point or two, not by the 5 points between 100 and the threshold.

**Weak point:** a weekly image change can move scores slightly or change npm's resolver (part 1). Both fail loudly and are handled by a PR.

**Rejected:** `actions/setup-node`. The guard rejects it by name, and it adds a download of a Node build that the image already provides.

## Numbers

| Number | Derivation | What breaks at another value |
|---|---|---|
| Lighthouse 13.6.0 | Published 2026-10-27, which is 8 days before the pin date 2026-11-04 and so passes the 7-day cooldown. Engine floor Node 22.19, runner has 22.23.4. | A newer version is under the cooldown and may be undetected malicious. An older one only misses fixes. A different version changes the digest and the job fails until re-pinned. |
| Cooldown 7 days, `LIGHTHOUSE_BEFORE=2026-10-28T00:00:00Z` | The 2025 incidents were pulled within hours to a few days. Pin date 2026-11-04 minus 7 days. It does not cover slow-burn cases (part 1, weak point). | Shorter: can resolve a version not yet detected. Longer: upgrades come later and nothing else improves. |
| `LIGHTHOUSE_TREE_SHA256` | Computed by the job from the sorted `name@version integrity` lines of the resolved tree, printed on the first run and copied in by the pin PR. | A different value means a different tree. The job fails before any registry code runs. |
| 3 runs per page, median | Smallest odd count that absorbs one outlier. Five runs would cut the noise further but cost 5/3 of the run time (8 pages × 5 runs = 40 instead of 24 audits) for a static site whose scores sit near 100. | One run: one bad run fails the page. Even counts: no single median. More: longer job for a margin that is not needed. |
| Threshold 95 per category | SPEC §8: a static page without JavaScript scores about 100, so lower means something regressed. | Lower hides regressions. 100 fails on one-point Chrome noise. |
| Artifact retention 1 day | The artifact is read by the `lighthouse` job in the same run, minutes after upload. 1 day is the shortest retention GitHub allows. | Longer keeps a copy of the built site, which holds only public content, for no use. |
| Page count 8 | Home, 404 and the six §6 pages (Before your call, Report a scam, Methodology, About, Corrections and removal, Privacy) at the end of M2. | A different count changes the `lighthouse` timeout. M3 re-derives it. |
| `lighthouse` timeout: provisional 30 minutes, then `ceil(3 × (T_setup + 8 × 3 × T_run))` | Part 5: (4 min setup + 2 pages × 3 runs × 60 s) × margin 3 = 30 min, every input an assumption until PR 2 measures it. Final value from measured times. *Amended: #15 replaced the provisional 30 with 17 minutes, from 4 measured runs (T_setup 18.6 to 21.6 s, T_run 11.4 to 12.6 s, 8 pages, provisional factor 3: 3 × (21.6 + 8 × 3 × 12.6) = 972 s). ADR-0004 (Numbers) re-derives the factor from the observed spread and sets the formula for 16 pages.* | Too low: red runs from runner variance. Too high: a hang blocks for long. |
| `build` timeout: 3 × first green run, whole minutes | Part 5: 11 green `check` jobs took 20 to 44 s, a 2.2 times spread, and 3 is the smallest whole factor above it. *Amended by ADR-0004 (Numbers): 2 × the slowest green run, from a spread of 1.40 over the 16 green `check` jobs since the reflow step.* | Below 2.2: the slowest normal run is killed. Far above: a hang blocks for long. |
| Existing workflow timeouts, 2 minutes each (`ci.yml`, `deploy.yml`, `links-external.yml`) | Set in M1 from the same `check.sh` run. 120 s is 2.7 times the slowest observed 44 s. | Reflow makes `check.sh` slower, so each must be re-derived in PR 3 (Consequences). |
| Reflow viewport width 320 CSS px | WCAG 2.2 SC 1.4.10 sets 320 CSS px as the width of vertical-scrolling content without horizontal scrolling. It equals a 1280 px window at 400 % zoom. | Wider: passes pages that fail the criterion. Narrower: fails pages the criterion allows. |
| Reflow viewport height 640 px | Not load-bearing: the check reads widths only, and 640 is the height of a typical phone at that width. | None for the check. |
| Reflow tolerance 0.5 px | Layout positions are fractional; a word that ends at 320.3 px because of rounding is not lost. Half a pixel is below one device pixel at any scale factor of 1 or more. | Larger: real overflow of up to that width passes. Zero: rounding noise fails pages that reflow. |
| `visually-hidden` exemption box at most 1 × 1 px | The standard pattern's box is exactly 1 × 1 px (`width: 1px`, `height: 1px`, no padding or border). `display: contents` gives a 0 × 0 box with visible text, so it is excluded separately. | Larger: a definition or another rule that grows the box (padding, `transform`, `zoom`) would keep the exemption while showing content. Smaller: the standard pattern itself fails. |
| Runner `ubuntu-24.04`, image 20261026 facts | Fixed image label from ADR-0002 part 5. The image version is recorded as Context, not pinned. | A new image can change Node, npm and Chrome (part 7). |

## Consequences

- Upgrading Lighthouse is a PR: bump the version and the cooldown date, let CI print the digest and the resolved tree, check the printed list against the expected set of packages (names and versions only, not code), and pin the digest. Between pins nothing changes.
- A runner image change can fail the digest or move a score by a point or two. Both are loud, and the fix is a re-pin PR or a threshold-neutral re-run.
- No workflow may restore an Actions cache. M6 (#7) must keep it that way when it adds the deploy job.
- `tools/lighthouse.sh` is the only file that may name the registry tools, and only `lighthouse.yml` may run it. The guard enforces both (PR 2).
- `lighthouse` is not a required check, so it blocks merges only by the agent rule in part 4. A record-only PR is measured after merge.
- `check.sh` has a second CI-only step (reflow). Local greens cover neither HTML validity nor reflow, and the final line says so.
- Adding a step to `check.sh` slows every workflow that runs it: `ci.yml` (`check`), `deploy.yml` (`pages-artifact`), `links-external.yml` and, from PR 2, the `build` job of `lighthouse.yml`. PR 3 re-derives the timeout of each of them (part 5 method), not only `ci.yml`. `pages-artifact` builds the deploy artifact, so a cap that is too low there blocks a deploy.
- Decided in ADR-0004 part 10: M3 measures five fixture pages (one per record template) and no individual record page, and re-derives the timeout. One page per template is enough, not every record.
- The `check` and `lighthouse` job names, and the job names `build` and `lighthouse` inside the workflow, are load-bearing once the guard and branch protection refer to them.
