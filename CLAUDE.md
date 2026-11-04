# CLAUDE.md: interviewscam

Community registry of fake job-interview scams that target developers, built as a static Hugo site for interviewscam.com. The repo is private and the site is public, so everything that builds into the site is public content.

## Source of truth

- [docs/SPEC.md](docs/SPEC.md) is the source of truth. Anything not written there is not agreed. A scope change is a PR that edits the SPEC.
- A change to a SPEC §4 decision (D1 to D10) also adds an ADR in [docs/adr/](docs/adr/README.md). Every ADR decision states why and which alternatives lost, and every number states where it comes from and what breaks at another value. A number copied from another ADR needs its own reason.

## Local check

One entry point, and CI runs it verbatim:

```sh
bash tools/check.sh             # internal links offline
bash tools/check.sh --external  # links online, third-party sources included
bash tools/selftest.sh          # the fixtures alone (check.sh runs it too)
```

Prerequisites: bash, python3 3.11 or newer, curl, sha256sum, tar and shellcheck. No container runtime. `tools/fetch-tools.sh` downloads Hugo and lychee into `.tools/` and verifies each against the SHA-256 in `tools/pins.env` before extracting.

**HTML validation runs only in CI** ([ADR-0002](docs/adr/0002-check-toolchain.md) part 1). Locally the Nu Html Checker step prints a `NOT RUN` line and the final line reads `LOCAL PASS, HTML validation not run (CI only)`. A local green does not mean the HTML is valid; the SPEC §8 HTML row comes only from the `check` job in CI.

Steps, in order: fetch and verify the toolchain, shellcheck `tools/*.sh` (prints `shellcheck OK`; required under `CI=true`), `sitecheck guard`, `sitecheck records`, the Hugo build into `public/` with `--panicOnWarning`, `sitecheck site` on `public/`, the Nu Html Checker (CI only), lychee on `public/`, and the self-test. Every step runs even after a failure, and the summary lists each result.

Self-test: every `tests/fixtures/<check>/<pass|fail>-<case>/` runs through the same function as the real step. A `pass-` case must exit 0, and when it has an `expect.txt` its output must contain that substring too (so a pass that checked nothing, for example zero records, is caught). A `fail-` case must exit non-zero and print the substring in its `expect.txt`. Fixture directories: `html`, `links`, `records` (against the real `schema/`), `schema` (each case brings its own `schema/`), `site` (`hugo.toml` with `params.csp`, `content/` records, the built tree in `public/`) and `guard` (the case stands in for the repo root; an optional `env.txt` holds `HUGO_*` overrides for the run).

## Safety nets (`tools/sitecheck.py`)

Python 3.11+ standard library, one file, always run as `python3 -I` ([ADR-0002](docs/adr/0002-check-toolchain.md) parts 3 and 4). Exit 0 clean, 1 on findings, 2 on a usage or internal error. A finding never prints an artifact live: values are shown defanged.

- `records`: every `content/reports/*.md` and `content/campaigns/*.md` except `_index.md` is a record with TOML front matter between `+++` lines, validated against `schema/report.schema.json` or `schema/campaign.schema.json` (M1 placeholders, M3 replaces them). Any other directory under `content/`, a nested file or YAML front matter fails closed. The validator implements `type`, `required`, `properties`, `additionalProperties`, `items`, `enum`, `const`, `pattern`, `minLength`, `minItems`, `format: date`, annotations and `x-defang`; any other keyword is an error. `x-defang: "host"` rejects a live scheme anywhere, and a `www.` prefix, a live hostname (dot look-alikes included) or a live dotted IPv4 in the host part of each token (after `scheme://`, `//` or `\\`, before the first `/`, `?`, `#` or `\`), so a dot in a defanged URL's path or query (`/GoogleMeet.exe`, `?id=abc.def`) is not a hostname; `x-defang: "url-only"` rejects only the live scheme (package names with dots). The live form of an artifact (`[.]`, `hxxp`, `[:]`, `[@]` refanged) must not appear in any other string or body of any record (R2). Bodies carry no bare URLs (any scheme except `hxxp`/`hxxps`, `//host`, `www.`, `mailto:`), no `hxxp(s)://` with a live host after it, no live dotted IPv4, no Markdown links, images, reference links or definitions (a definition label may span lines or hold `\]`), no `<…>` autolinks and no Hugo shortcodes (`{{<`, `{{%`: their output, for example `param` or `figure link=`, is invisible to this check), also not after entity or backslash decoding (SPEC §5). The rule fails closed: links in code spans count too, and even a defanged URL in an autolink is a link. Every front-matter string outside `params.sources` that is not an artifact field gets the URL rules too (bare URL, half-defanged URL, `//host`): live links live only in `params.sources`.
- `site`: on every HTML page under `public/`, no URL to another origin or scheme (after stripping C0 controls and spaces, as the WHATWG URL parser does) in the attributes that make the browser fetch (`script`, every `link`, `img`/`source` incl. `srcset`, media, frames, `embed`, `object`, `a[ping]`, SVG `image`/`use`, `meta` refresh, any `<base>`, `background`), nor in CSS (`url()`, `@import`, quoted strings, escapes decoded, comments stripped without touching strings), `.js` URL literals, or any attribute, `<?xml-stylesheet?>` or declaration of an `.svg`, `.xml`, `.xsl`, `.xslt`, `.rss` or `.atom` file (no CSP applies to those). `<a href>` is allowed: a click is a navigation. Exactly one CSP meta per page, the first element after `<meta charset>`, equal to `params.csp`; the policy may only use `'self'` and `'none'` and must set `default-src`. The live form of any record artifact appears nowhere in `public/`: raw, entity-decoded, percent-decoded, as joined page text, and as every string of every `.json` file (the stand-in for M3's `/feed.json`).
- `guard`: no JavaScript package-manager files in the tracked or untracked (not ignored) files, and no tool names from its pattern table in `tools/`, `.github/workflows/`, `.github/actions/` or any script elsewhere (by suffix, make/just file name or `#!` line; site sources under `assets/`, `layouts/`, `static/`, `content/`, `data/`, `i18n/`, `archetypes/`, plus `docs/` and `tests/fixtures/` are not executed and not scanned). Write comments there without those names; only the table lines in `sitecheck.py` are skipped, and the guard's own `tests/fixtures/guard/fail-*` cases, which the self-test proves, are skipped for the file rule. A workflow `run:` may only be `bash tools/<name>.sh` with plain `--flags` (no inline scripts or block scalars), `shell:` only `bash`, and no `container:`, `services:`, `entrypoint:`, `working-directory:`, `env:` or `defaults:` (a working directory or `BASH_ENV` can point a run step at unscanned code), so everything a workflow executes is a scanned `tools/` script. YAML forms the per-line rules cannot read fail closed: a `pages:`/`id-token:` value on the next line or behind an anchor, alias, tag or block scalar, any double-quoted string with a `\` escape anywhere on the line (block or flow style), a `? ` complex key. The Hugo hardening keys are asserted in `hugo.toml` AND in the effective config from `"$HUGO_BIN" config --format json`, which sees `config/` directories, `HUGO_*` environment variables and case-variant keys; `params.csp` must match too. A `config/` directory or a second root config file (`hugo.*`, `config.*`) fails. The effective config must keep `contentdir = "content"`, no `theme`, no `module.imports`, and every content mount `content` to `content`, because the records check reads only `content/`. Every `uses:` is `actions/<name>@<40-hex SHA>` AND equals one of the `ACTION_*` pins in `tools/pins.env` (a commit that exists only in a fork resolves under `actions/` too). Every workflow has a top-level `permissions:` block, and none contains `deploy-pages`, `configure-pages`, `pages: write`, `id-token: write` or `write-all` (Pages off until M6, which removes that rule deliberately).

## Invariants

- **No npm (D3).** Never run `npm`, `npx` or `node` on a developer machine, not even for a quick Lighthouse run. No `package.json` or lockfile in the repo. The `[security]` and `[privacy]` keys in `hugo.toml` stay (ADR-0001 hardening keys). npm-only tools run only in CI jobs that hold no write token and do not build the deploy artifact.
- **Neutral, artifact-based records (D6, D7, D10).** A record describes artifacts, not a verdict about a company. A company or person name is either "name abused" (used without their involvement) or "front" (listing what was checked). Labels state facts, for example "reported 3 times, evidence reviewed on 2026-11-10", never "verified scam". A recruiter persona name appears only with the label "name used by the campaign, possibly a stolen identity". Attribution only as the cited source states it.
- **Nothing live (D8).** Attacker URLs and domains are always defanged: `hxxp://` or `hxxps://`, and every dot in a hostname or IP as `[.]`, for example `hxxps://login[.]meeting[.]example/join`. This applies to records, page copy, issues, PR bodies and QA reports. Record bodies carry no bare URLs, no Markdown links and no `<…>` autolinks; live links appear only in `sources`. No malware binaries, only SHA-256 hashes linking to MalwareBazaar or VirusTotal; never download a sample to check a hash. Fixtures use only RFC 2606 reserved names (`.example`, `.test`, `.invalid`, `example.com`).
- **No third-party requests (D9).** No external scripts, stylesheets, fonts, analytics or cookies. The Content Security Policy is a meta tag right after `<meta charset>` (Pages cannot set headers), and its single source is `params.csp` in `hugo.toml`.
- **Pages stays off until M6 (#7).** On the Team plan a Pages site from this private repo is public as soon as it deploys. `deploy.yml` only builds and uploads the artifact with a read-only token; no workflow may deploy or enable Pages before M6.
- **No raw evidence or personal data** in the repo, issues or PRs: no reporter identity, unredacted screenshots or mail headers. They stay in the operator's mailbox (D5, D7). Issues carry only defanged artifacts and an evidence summary.

## Load-bearing names

- The CI job `check` in `.github/workflows/ci.yml`. Branch protection requires exactly this context, so a rename must update the protection in the same session.
- The schema keyword `x-defang` and its modes `host` and `url-only`, which mark the record fields that carry attacker artifacts ([ADR-0002](docs/adr/0002-check-toolchain.md) part 4).
- `RECORD_SCHEMAS` in `tools/sitecheck.py`, which maps `content/<section>/` to its schema. A new record section needs an entry, or the records check fails closed.

## Workflows

- `ci.yml`: job `check`, on every PR and every push to `main`, runs `bash tools/check.sh`.
- `deploy.yml`: job `pages-artifact`, on pushes to `main` and on PRs that change it, runs `bash tools/check.sh` and uploads `public/` as the Pages artifact. It does not deploy.
- `links-external.yml`: weekly and on manual start, runs `bash tools/check.sh --external`. Not a required check.

Every action is owned by `actions/`, pinned to a 40-hex commit SHA with the tag as a comment, and listed as an `ACTION_*` pin in `tools/pins.env`. Runners are `ubuntu-24.04`, not `ubuntu-latest` (ADR-0002 part 5). Tokens are read-only.

## Upgrading a tool

Hugo: the pinning procedure in [ADR-0001](docs/adr/0001-static-site-generator.md). lychee and the Nu Html Checker image: [ADR-0002](docs/adr/0002-check-toolchain.md) parts 1 and 2, including the fallback when the pinned image digest disappears upstream. Actions: resolve the upstream tag ref (`GET /repos/actions/<name>/git/ref/tags/<tag>`), then change the `ACTION_*` pin in `tools/pins.env` and the `uses:` line together. Every pin changes only in its own PR, which runs the full check.

## Content scrub

Before every commit, the staged diff (`git diff --cached`) must contain no client names and no paths from a developer machine (home directories, worktree paths). Envelope SDLC sessions run the scrub grep from their repo routing table. The pattern is not written here, because a file that spells out the names would itself match the scrub.
