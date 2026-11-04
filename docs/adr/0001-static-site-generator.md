# ADR-0001: Static site generator

## Status

Accepted, 2026-11-04 (operator, issue #2, STOP 1). Implements SPEC D3.

## Context

SPEC D3 requires a single-binary static site generator without npm and leaves the pick, Hugo or Zola, to this ADR. The criteria come from the SPEC:

- D8 and D7: text copied from scammer messages must not turn into markup or live links, and a defamatory or live record can do real harm.
- D3: the groups this site writes about attack developers through npm packages, so npm must not come back into the build chain, and it should be hard to bring back by accident.
- D3 and milestone 1: the tool is pinned and verified.
- SPEC §5: `/feed.json` and the milestone 4 index, with artifact and alias fields, must be possible.
- D9: the generator's built-in third-party surface.
- Cost of upgrading a pinned tool.

Evidence is pinned to the tags Hugo v0.169.0 (2026-10-27) and Zola v0.23.6 (2026-09-12).

| Criterion (SPEC) | Hugo v0.169.0 | Zola v0.23.6 | Edge |
|---|---|---|---|
| D8/D7: content cannot become markup | Raw HTML in Markdown is omitted by default (`Unsafe: false`, [`markup/goldmark/goldmark_config/config.go`](https://github.com/gohugoio/hugo/blob/v0.169.0/markup/goldmark/goldmark_config/config.go)), and content is treated as untrusted (`security.allowContent` denies `text/html`, [`config/security/securityConfig.go`](https://github.com/gohugoio/hugo/blob/v0.169.0/config/security/securityConfig.go)). **But** `Linkify: true` by default turns bare `https://`/`www.` text into live links, so it must be set to false. Markdown links and `<…>` autolinks are core CommonMark syntax in goldmark, not part of `Linkify`, and render as live links by default in both generators. Hugo could neutralise them with a link render hook; this ADR relies on the SPEC §5 body rule instead (see Why). | Raw HTML passes through verbatim (`Event::Html \| Event::InlineHtml => push_html`, [`components/markdown/src/markdown.rs`](https://github.com/getzola/zola/blob/v0.23.6/components/markdown/src/markdown.rs)), and the v0.23.6 `[markdown]` config has no switch for it. Since 0.23.0, Markdown content is rendered as a Tera template by default ([CHANGELOG](https://github.com/getzola/zola/blob/v0.23.6/CHANGELOG.md); opt-out globs in `skip_content_templating`). | Hugo |
| D3: no npm, and hard to bring back | The default `security.exec.allow` permits `sass`, `go`, `git`, `node` and `postcss`, and Hugo ships PostCSS/Tailwind/Babel functions. All of it can be switched off: `security.exec.allow = ["none"]` (the `none` keyword is in [`config/security/whitelist.go`](https://github.com/gohugoio/hugo/blob/v0.169.0/config/security/whitelist.go)), and `security.http.urls = ["none"]` stops build-time remote fetches. The guard asserts both keys. | No template function runs external programs; Sass is built in. `load_data(url=…)` fetches remote data at build time, and the v0.23.6 config docs show no off-switch. | Zola (Hugo equalised by config + guard) |
| D3/M1 scope: pin + verify | Versioned release, not marked immutable (`immutable: false`), so assets can be replaced; a SHA-256 `hugo_0.169.0_checksums.txt` in the same release. GitHub's asset digest matches it (this proves the download equals what the release stores, not that the release is untampered): `linux-amd64.tar.gz` = `2d2f0bfe…66765a7`. No attestation: `GET /repos/gohugoio/hugo/attestations/sha256:2d2f…` returns 404. | Versioned release, not marked immutable (`immutable: false`), with no checksum file, but Sigstore build-provenance attestations (`gh attestation verify --owner getzola`; the API returns 1 attestation for both Linux tarballs). | Zola |
| §5 `/feed.json`, M4 index with artifact and alias fields | Custom output formats write arbitrary files (any base name, media type) from all pages and sections. | Custom JSON only through the feed-template trick (`feed_filenames`, which are "used as the template filenames, too"). Feeds hold "only pages with a date and `include_in_feeds = true`" and no sections. The built-in search index has fixed fields (title, description, content, path, date) and cannot include front-matter extras. | Hugo |
| D9: built-in third-party surface | Embedded `youtube`, `vimeo`, `x`, `instagram` shortcodes and `google_analytics`/`disqus` partials (under [`tpl/tplimpl/embedded/templates`](https://github.com/gohugoio/hugo/tree/v0.169.0/tpl/tplimpl/embedded/templates)). They stay inert unless used, and `[privacy]` disables each one. `twitter` and `gist` are removed stubs that fail the build when used. | No embeds (built-ins: 404, anchor-link, atom, rss, robots, sitemap); shortcodes were removed in 0.23.0. | Zola (Hugo closed by `[privacy]` + the third-party check) |
| Upgrade cost of a pinned tool | 12 releases in the six months before this ADR (2026-05-04 to 2026-11-04; v0.162.0 on 2026-05-26 to v0.169.0 on 2026-10-27), with deprecations in most (e.g. 0.169.0 deprecates `.Params.title` and similar lookups). 357 commits in the same window: `bep` 217, `jmooring` 40, dependabot 73. | 0.23.0 is "probably the most breaking version of Zola" (Tera v2, shortcodes removed); 6 regression-fix patches followed in 5 weeks, none since 2026-09-12. 163 commits in the same window (2026-05-04 to 2026-11-04), 131 of them by `Keats`. | Hugo (a second regular maintainer) |
| Licence (we only run the binary) | Apache-2.0 | EUPL-1.2 since 2026-01-09 (was MIT) | neutral |

## Decision

The site is built with **Hugo, standard edition**, pinned to one version and verified by SHA-256 (v0.169.0 at the time of this ADR; see Numbers). The platform is linux-amd64 only.

### Hardening keys

PR 2 of milestone 1 puts these into `hugo.toml`, and the guard check of PR 3 asserts the security and privacy ones. Each exists for one reason.

| Key | Why |
|---|---|
| `[markup.goldmark.extensions] linkify = false` | Hugo's default turns bare `https://` and `www.` text in a record into a live link. A scammer-supplied string must stay inert text (D8). |
| `[markup.goldmark.renderer] unsafe = false` | This is already the default. Writing it down makes the guard able to assert it, so a later change cannot go unnoticed (D8, D7). |
| `[security.exec] allow = ["none"]` | The default allow-list permits `sass`, `go`, `git`, `node` and `postcss`. Switching it off means no Hugo function can start npm-based tooling (D3). |
| `[security.http] urls = ["none"]` | Stops build-time remote fetches (D3, D9). |
| `[privacy]` `disable = true` for disqus, googleAnalytics, instagram, vimeo, x and youtube | Each is an embedded third-party surface. They are inert unless used. With the switch on, a use renders nothing: no third-party request is made and the build stays green, so D9 holds, but the content is dropped silently. The `twitter` and `gist` shortcodes are already removed stubs that fail the build, and `[privacy]` has no keys for them (D9). |
| `disableHugoGeneratorInject = true` | Hugo would otherwise inject a generator meta tag into `<head>`. The CSP meta tag must be the first element after `<meta charset>`, because a meta CSP applies only to content after it (D9). |
| `disableKinds = ["taxonomy", "term", "rss"]` | Nothing in milestone 1 uses taxonomies or RSS, and the empty generated pages would still be built and checked. Milestone 3 revisits this. |
| `refLinksErrorLevel = "ERROR"` | A broken internal reference fails the build instead of producing a warning. |
| `[params] csp = "..."` | The single source of the Content Security Policy that every page carries (D9). |

### Pinning procedure

1. Download the release asset.
2. Compare its `sha256sum` against the release's `checksums.txt` AND against the `digest` GitHub shows for the asset. Both must match.
3. Write the version, URL and hash to `tools/pins.env`.
4. Upgrade only by a PR that changes the pin and runs the full check. `--panicOnWarning` is part of the build, so deprecations surface in that PR and not later.

## Why

The deciding SPEC risks are D8 and D7: scammer-supplied text must not become live links or markup, and a defamatory or live record can do real harm. Hugo's content defaults are safe, and its needed hardenings are config keys that a guard can assert. Zola's raw-HTML passthrough cannot be switched off, so we would have to own a parser-level raw-HTML check over every record body forever. Zola's wins (provenance, a smaller built-in surface) are real, but config and the checks close them for Hugo.

Goal: D3 holds because npm cannot come back in, D9 holds because no built-in third-party feature can make a request, and §5 `/feed.json` and the milestone 4 index are possible.

D8 for record bodies rests on two layers. Hugo's defaults plus the asserted keys stop raw HTML and bare-URL linkify. Markdown links (`[text](url)`) and `<…>` autolinks are core CommonMark syntax, so they render as live links by default in both generators. Hugo could neutralise them with a link render hook; this ADR relies on the SPEC §5 body rule instead. The SPEC §5 rule that record bodies contain no live URLs, enforced by the record check (fails closed), is what holds D8 for links. Only an ADR can relax that rule. The Hugo-versus-Zola difference is therefore the raw-HTML passthrough and the content templating, not links.

Weak points:

- Hugo's `checksums.txt` comes from the same release as the binary, and Hugo publishes no build-provenance attestation. A compromised Hugo release would therefore match our pin. Zola has Sigstore attestations.
- Hugo deprecates something in almost every release, so each upgrade is a deliberate PR.

## Rejected alternatives and why they lost

- **Zola v0.23.6.** It lost on D8 and D7: raw HTML in Markdown passes through verbatim with no switch to stop it, and since 0.23.0 Markdown is rendered as a Tera template by default. We would have to own a parser-level raw-HTML check over every record body, on top of the link rule that both generators need, and keep it correct, forever. It also lost on the milestone 4 index (fixed search-index fields) and on maintainer breadth (131 of 163 commits in the 2026-05-04 to 2026-11-04 window are by one author). It won on provenance (Sigstore attestations) and on the built-in surface, which config and checks close for Hugo.
- **Astro, Next.js and other npm-based stacks.** Rejected by SPEC D3: the build chain must not depend on npm.
- **Hugo extended edition.** Extended only adds libsass and WebP encoding. We use plain CSS, so it adds nothing we use.

Had Zola been chosen instead, the skeleton would have changed as follows: `zola.toml` with `skip_content_templating` covering all of `content/`, `templates/` instead of `layouts/`, the pin verified with `gh attestation verify --owner getzola`, and a raw-HTML-in-record-body rule in the record check.

## Numbers

| Number | Derivation | What breaks at another value |
|---|---|---|
| Hugo v0.169.0 | The latest stable release on 2026-11-04. It carries the 0.169.0 hardening of front-matter escaping and Go 1.27.3. The implementer re-reads the latest stable at PR time and takes it if it is newer, re-verifying both digests. | An older version lacks that hardening. A newer one has a different hash, so both digests must be re-verified, and its deprecations fail the build under `--panicOnWarning` until fixed. |
| SHA-256 of `linux-amd64.tar.gz` = `2d2f0bfe…66765a7` | Same value in `hugo_0.169.0_checksums.txt` and in GitHub's asset digest. The full hash is written to `tools/pins.env` by the PR that adds the skeleton. | A different hash means a different file. The fetch step deletes the download and fails. |
| One platform: linux-amd64 | The two build environments, the CI runner and the operator's x86_64 laptop, both need it. Every extra platform adds pins to re-verify on each upgrade. | Another platform (for example macOS) needs its own pin and a fetch branch, and it would be re-verified on every upgrade. |
| Comparison window 2026-05-04 to 2026-11-04 | Six months before this ADR, used for both the Hugo release count (12) and the commit counts for both generators, so the figures are comparable. | A shorter window drops releases (a window starting 2026-06-15 would drop 4 of the 12 Hugo releases) and makes the upgrade-cost figures less comparable. |
| Zola v0.23.6 (2026-09-12) | The comparison baseline for the table above. Not used by the site. | Nothing, because the site does not use it. |

## Consequences

- The pin is trust on first use. It guards against a later replacement of the asset, not against a release that was already compromised when we pinned it. GitHub's asset digest only proves the download equals what the release stores, and it is not independent of a compromised release. A Sigstore attestation would be independent, and Hugo has none.
- Every Hugo upgrade is its own PR, because of the deprecation rate in the comparison table.
- Record bodies carry no raw HTML (Hugo's defaults plus the asserted config keys, which the guard must keep asserting) and no live URLs (the SPEC §5 rule, enforced by the record check).
- A disabled embedded shortcode renders nothing and does not fail the build, so a record that uses one loses that content silently. No new check covers this in milestone 1.
- The guard check (PR 3) must assert `security.exec.allow`, `security.http.urls`, `linkify`, `unsafe` and the six `[privacy]` disables.
