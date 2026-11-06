# interviewscam.com specification

Status: draft for approval. Owner: Martin Holý (Replikanti). Created 2026-11-04.

This document is the source of truth for the MVP. Anything not written here is not agreed. A change goes through a PR that edits this file. When a decision in §4 changes, the PR also adds an ADR in `docs/adr/`.

## 1. Problem

Fake job interviews have become a standard way to infect developers. A "recruiter" offers a role, often in web3. Shortly before the call they send a link to an unknown meeting platform, or they send a take-home coding test. The meeting app or the test repository installs an info-stealer that takes browser sessions, saved passwords, wallet extensions, SSH keys and Telegram sessions.

Known campaign families (sources in §12):

- **Contagious Interview** (DPRK-linked). Coding tests, GitHub repositories and npm packages that carry BeaverTail and InvisibleFerret. The payloads are JavaScript and Python, so Linux is affected too.
- **The Meeten family.** A fake meeting app renamed again and again (Meeten, Meetio, Meetone, Clusee, Cuesee), GrassCall, and Relay (SlowMist, July 2026). Windows and macOS installers.
- **JobStealer** (Dr.Web, May 2026). Fake meeting sites MeetLab, Juseo, Meetix and Carolla, some using the Webex name. The Linux download button is inactive or serves the Windows build.

The trigger for this project: in early November 2026 the operator was invited to an interview with a "web3 company Saifuro". The meeting link arrived 15 minutes before the call and pointed to an unknown platform that only worked on Windows and macOS. On 2026-11-04 a web search for "Saifuro" returned nothing relevant.

The gap: a candidate has minutes between getting the link and the call. Security vendors publish thorough reports, but later, for SOC teams, and named after malware families instead of the names a candidate sees. Campaigns rename faster than reports appear. Nobody maintains one public page per name (company, app, domain, recruiter persona) mapped to the campaign family behind it.

## 2. Goal and users

**Goal:** a candidate who types a name, an app or a domain into the site search, or into a search engine, gets the answer in one step on a phone. Is this a known fake interview, which campaign family uses it, what does it do, what should I do now.

**Users:**

- Primary: developers and other candidates who received an invitation. They decide within minutes, often on mobile.
- Secondary: security researchers and tools that want the data in machine-readable form. Search engines and AI agents read the same pages and the JSON feed.
- Later: companies whose names are abused in these campaigns (alerts). Not in the MVP.

## 3. Positioning (checked 2026-11-04)

| Who | What it does | Difference |
|---|---|---|
| RecruScam (recruscam.fr) | Community registry and checker, French, launched 2026, 21 verified reports | Same idea, French only, general recruitment fraud |
| PhishFort | Web3 brand protection. A static list of 6 fake agencies (02/2026) and a takedown form | Lead generation for their service, not a database |
| GhostCheck | Chrome extension that flags companies on job boards, 2 users | Extension, no public pages |
| JobVerify | Open-source MCP server that checks a company, link or email against registries and blocklists | No community reports, AI agent channel only |
| BBB Scam Tracker | Large public US scam registry, includes job scams | Generic, not about developer malware |
| Chainabuse (TRM Labs) | Crypto scam reports in 16 categories | No job or interview category |
| Vendor reports, abuse.ch | Free IOCs for SOC teams | Not searchable by the names candidates see |
| Doppel, PhishFort | Paid takedowns of brand impersonation | B2B, possible data customers later |

Our niche is one public page per name, mapped to its campaign family, in English, built for the minutes before a call.

## 4. Decisions

Each decision states why and which alternatives lost.

**D1. The operator is named.** The site names Martin Holý (Replikanti) as operator, with a contact address.
Why: a site that warns about scams has to be accountable itself, and an anonymous scam registry looks like a scam. Rejected: brand only (weaker trust, and a company identity is needed anyway once the site earns money), anonymous (no accountability, incompatible with paid operation and with the DSA contact duty). When the site starts earning money, the identification required by § 435 of the Czech Civil Code (name, registered office, ID number) is added.

**D2. English only.**
Why: the campaigns are global and people search in English. One language halves the content upkeep. Rejected for the MVP: English and Czech, because every record would exist twice. Czech can be added later.

**D3. Static site, generator without npm.** A single-binary static site generator: Hugo, standard edition, chosen in [ADR-0001](adr/0001-static-site-generator.md). GitHub's own JavaScript actions (`actions/*`), pinned to commit SHAs, are not npm tooling in this sense ([ADR-0002](adr/0002-check-toolchain.md) part 6).
Why: the groups this site writes about attack developers through npm packages, so the build chain must not depend on npm. Tooling that only exists on npm (Lighthouse, for example) may run only in CI jobs whose `GITHUB_TOKEN` has no permissions (`permissions: {}`), that see only the built site and the check scripts (never the repository source), and that do not produce the deploy artifact, never on a developer machine. Every job still carries the Actions runtime token (artifact and cache services), so no workflow restores a cache and the deploy path never reads anything that job can write ([ADR-0003](adr/0003-browser-checks.md) part 2).
Rejected: Astro, Next.js and other npm-based stacks.

**D4. GitHub Pages from the private repo `Replikanti/interviewscam`, deployed by GitHub Actions.**
Why: static hosting with HTTPS and a CDN at no extra cost. A private source repo keeps drafts, intake and history out of public view, so a removed report really disappears from the site (caches aside). Publishing Pages from a private org repo needs GitHub Team, which the org has since 2026-11-04. Deploying via Actions keeps the custom domain in the repo settings, so a build cannot drop a `CNAME` file and unlink the domain.
Limits from the GitHub docs: published site at most 1 GB, soft bandwidth limit 100 GB per month, deployment timeout 10 minutes. GitHub does not allow Pages for a site primarily directed at commercial transactions or SaaS, so a paid B2B part would be hosted elsewhere.
Rejected: a public repo (unverified drafts and removed reports would stay in public git history and in forks), a public build-only repo next to the private one (two repos and a deploy token for no gain once Team is paid), Cloudflare Pages (another provider and account).

**D5. Report intake is private.** MVP: email to `report@interviewscam.com`, forwarded by Namecheap. Later: a form that stores into a private place, for example a Cloudflare Worker with Turnstile that opens issues in this private repo.
Why: an issue in a public repo is public the moment it is filed, under the reporter's GitHub account, and search engines can index it before anyone reviews it. That breaks moderation before publication and exposes the reporter to the people they reported. Rejected: public GitHub issues or PRs as intake.

**D6. Records are about artifacts, wording is neutral.** A record describes the artifacts a campaign used (domain, app name, file hash, handle, repository, package), not a verdict about a company. Every report name, whatever its type, has one of two states.
- *Name abused*: a real company, person or product whose name the scammers used. The page says the name was used without their involvement.
- *Front*: no real existence found (no registry entry, no history, no footprint). The page lists what was checked.
Why: these campaigns routinely use the names of real companies and real executives. PhishFort lists an impersonated firm, and JobStealer uses the Webex name, which is a meeting app and not a company. Registry compromises such as `chalk`/`debug` and Nx (2025) shipped malware under legitimate package names, so a package page without a state reads as if its owner were the attacker. A page that calls a real company a scam defames the victim. The reputation of a legal person is protected by the Czech Civil Code, and names of people fall under the GDPR. Rejected: one page per company titled as a scam, and a state only for company and person names, which leaves product and package names unprotected ([ADR-0004](adr/0004-record-model.md) part 1).

**D7. Moderation before publication, with evidence.** Nothing is published without evidence (screenshots with personal data redacted, message headers, URLs, hashes) and a moderator review. Reporters stay anonymous to the public, not to the moderator. Every page links to a correction and removal request. Labels state facts ("reported 3 times, evidence reviewed on 2026-11-10"), not an editorial verdict.
Why: open anonymous reporting invites fake reports against competitors. The DSA hosting exemption covers third-party content only for a provider that offers a notice channel and acts on notices. A label like "verified scam" turns third-party content into the operator's own claim.

**D8. Nothing live on the site.** Attacker URLs and domains are always defanged (`hxxps://example[.]com`), and a CI check enforces it. In record text every dotted name is written defanged (hostnames, IP addresses, file names, and vendor, tool and brand names such as `Dr[.]Web`), and the only live host in record text is the site's own. Package names and handles are stored defanged like every other artifact. Source URLs stay live links, and their host may not overlap any domain a record declares as an artifact ([ADR-0004](adr/0004-record-model.md) part 3). No malware binaries live in the repo or on the site, only hashes with links to MalwareBazaar or VirusTotal.
Why: accidental clicks, link previews in chat apps, the risk of the site itself being listed as a source of malicious links, and GitHub's policy against delivering malicious executables. Plain text on the site is not a link, but chat apps, mail clients and crawlers turn a live name into one once it is copied or crawled. There is no allowlist of safe names; [ADR-0004](adr/0004-record-model.md) part 3 gives the reasons.

**D9. No third-party requests.** No external scripts, trackers, analytics, cookies, ads or web fonts. Search data comes from Google Search Console, which needs no script on the site.
Why: trust and privacy for a security audience, no cookie banner, and nothing on the site that a third party can change. GitHub logs visitor IP addresses for security purposes, and the privacy page says so.

**D10. Persona names only with a label.** A recruiter persona's name is published only when the evidence shows it in the scam contact, and only as "name used by the campaign, possibly a stolen identity". The real person can ask for removal.
Why: recruiter identities are often stolen from real people, yet candidates search for exactly these names.

## 5. Content model

Records are structured files in the repo, validated against a schema in CI.

**Campaign family**, page `/campaigns/<slug>/`

- name, aliases, attribution (each entry a statement tied to a cited source, as that source states it, never our own), first seen, last seen
- delivery (fake meeting app, coding test repository, npm package, terminal command), targeted operating systems, what it steals
- sources (vendor reports with date and link)
- related reports, computed from the reports that name this family, not stored

**Report**, page `/reports/<slug>/`, one per name a candidate sees

- the name, its aliases ("also seen as") and its type (company, meeting app, domain, recruiter persona, repository, package)
- for every name, the state from D6 and the list of what was checked
- campaign family, only when a cited source of the record names this name or lists one of its artifacts, otherwise "unattributed"
- artifacts, defanged: domains, URLs, IP addresses, email addresses, repositories, file names, handles, packages and SHA-256 file hashes (each hash lists the lookup services that list it)
- a short summary, what happened (optional detail, short and factual), first seen, last seen, last reviewed
- evidence summary (what was reviewed, never raw personal data)
- sources, and the number of independent reports. A report may have 0 independent reports when it cites at least one source (a source-only report); its label then reads "Named in 1 cited source, reviewed on …" for one source and "Named in K cited sources, reviewed on …" for K ≥ 2 ([ADR-0004](adr/0004-record-model.md) part 12)
- related names
- correction and removal link

A recruiter persona page lives at `/reports/persona-<n>/` and its URL never contains a person's name. A persona record can carry a `hide_name` switch that removes the name from the page, the title, the feed and any index in one line, without changing the URL (§6, [ADR-0004](adr/0004-record-model.md) part 5).

**Record bodies contain no live URLs** (D8): no bare URLs, no Markdown links, no `<…>` autolinks. This rule binds the Markdown body of a record. Live links appear only in `sources`. Template output may also link to MalwareBazaar or VirusTotal from SHA-256 artifacts (D8); that is not body text. The record check fails closed on any live URL in a body, because it cannot tell an attacker URL in prose from a source URL in prose. Relaxing this rule needs an ADR.

The same text rule covers every `_index.md` and every front-matter string except artifact fields and source URLs ("record text"): in record text a live hostname, a live dotted IPv4 address (also as an integer, hex, octal or short numeric host), a `www.` prefix and an email address on a live host fail, unless the host is the site's own (D8). IPv6 literals are not detected; review covers them ([ADR-0004](adr/0004-record-model.md) part 3). `_index.md` files carry only `title` and `description`. A source URL stays a live link, and its host must not equal, be a subdomain of, or be a parent of any domain a record declares as an artifact, including a victim domain in the "name abused" state. A victim's own advisory on such a host therefore cannot be a source, and the record cites a third-party source instead; without one, the claim that advisory would support is not made ([ADR-0004](adr/0004-record-model.md) part 3).

**Feed**, `/feed.json`: all published reports and campaigns with defanged artifacts, for researchers and tools. Stable field names and an integer `version` field. The version increments only on a breaking change (a field removed, renamed or retyped, or its meaning changed); an addition keeps it and is listed with its date. The fields are described by `schema/feed.schema.json`, validated in CI, and documented on the public page `/data-feed/` ([ADR-0004](adr/0004-record-model.md) part 7). A hidden name (§6) appears as `null`.

URLs and titles stay neutral, for example `/reports/saifuro/` titled "Saifuro, a name used in fake job interviews", never "<company> scam". A report title is "<name>, a name used in fake job interviews", a campaign title "<name>, a campaign family that uses fake job interviews". A visible persona name always carries the D10 label in the title and wherever it renders, and a hidden one reads "A person's name used in fake job interviews, hidden on request". Titles come from the page template, never from a record.

**Structured data** is JSON-LD only: a `WebPage` and a `BreadcrumbList` on record pages, a `BreadcrumbList` on section pages. A report's `WebPage` carries `datePublished` and `lastReviewed` (the D7 "evidence reviewed on" date), a campaign's only `datePublished`, and no page carries `dateModified`: no field may claim a review or modification that the record does not state. There is no `Article`, `ClaimReview`, `Review`, `Rating` or `Person`, and no node about a record's subject, because that would assert an entity about a real party (D6). ClaimReview is not used because Google retired it from Search in June 2025 and it was meant for fact-checking publishers ([ADR-0004](adr/0004-record-model.md) part 8).

## 6. Pages in the MVP

- **Home**: one search box ("company, app, domain or recruiter"), the answer for an exact match on the same page, a short "before your call" checklist, the five latest reports and the campaign families.
- **Report and campaign pages** from §5, and their index pages `/reports/` and `/campaigns/`.
- **Data feed** (`/data-feed/`): what `/feed.json` is, its fields, its versioning rule and a dated change list.
- **Before your call**: warning signs (unknown meeting app, link sent minutes before the call, "run this repo or command", installers only for Windows and macOS) and what to do instead.
- **Report a scam**: what to send to `report@interviewscam.com`, shown as plain text with no `mailto:` link and with a fixed subject line ("Report: <name>"), which evidence helps, how reporters are protected. The page describes only the intake channel that exists and announces no other.
- **Methodology**: how reports are reviewed, what the states mean, how sources are used.
- **About**: who runs the site (D1), why it exists, how to get in touch.
- **Corrections and removal**: how to ask and what happens next. The same address, as plain text, with the subject line "Correction: <page URL>". Every request is acknowledged and reviewed, and the outcome is correct, remove or keep, with the reason given to the requester. Requests under data protection law (access, erasure, objection and the like) are answered within one month, as GDPR Art. 12(3) requires. Other correction requests have no fixed response time, because there is one moderator and no request-volume data. The page stays up during review, so a front cannot hide itself by filing a request. Exception: when a natural person whose name a campaign used asks (a D10 persona name, or a person's name in the D6 "name abused" state), that name is hidden first, before the review. The hidden name leaves the page, the title, the feed and the search index, and the URL never contains a person's name. The review checks that the request comes from the named person (the controller may ask for proof of identity, GDPR Art. 12(6)), and if it does not, the name returns. Accepted weak point: until the review, an impostor can hide an active persona name, and the review restores it. The basis is GDPR Art. 18(1)(d), restriction while an objection under Art. 21 to processing based on legitimate interest is verified. The artifacts and the rest of the record stay up throughout, until the decision, so the record stays findable by company name and artifacts. Companies keep the general rule.
- **Privacy**: what the site and GitHub log, what happens with reports.
  - Controller: Martin Holý as a natural person, contact `report@interviewscam.com`. No postal or home address appears on the site.
  - Legal basis: legitimate interest (GDPR Art. 6(1)(f)), namely warning candidates and moderating reports.
  - Retention: evidence behind a published record is kept while the record is published and for 3 years after it is removed. A report that is not published is deleted once that decision is made. A reporter can ask for deletion at any time, and if that leaves a record without evidence, the record is unpublished (D7).
  - Why 3 years: the general limitation period of the Czech Civil Code is 3 years (§ 629(1)). For damages it runs from when the claimant learned of the harm and of the liable person (§ 620(1)), with an objective cap of 10 years (§ 636(1)). Removal plus 3 years covers the typical case, a claimant who learns of the page while it is up. It does not cover late discovery from archive copies within the 10-year cap, and the operator accepts that gap for data minimisation. A second gap: when a reporter asks for deletion, the evidence is deleted and the record is unpublished, so a claim that arrives later (for the time the page was up) meets no evidence. The alternative is to keep only what a legal claim needs, restricted, under GDPR Art. 17(3)(e). Whether to do that is a question for the milestone 6 legal review. The policy above stays as approved until then.
  - Also on the page (review of PR #18): the recipients (GitHub hosts the site and logs IPs, Namecheap forwards the address, the operator's email provider stores the mailbox), the fact that some of them process data in the United States (the transfer mechanism is verified in the milestone 6 legal review), that providing data is voluntary, and a section for people named on pages (Art. 14: the name as the campaign used it, from reports and cited sources, to warn candidates, legitimate interest, kept while published with its evidence for 3 years after, an objection hides the name first). Correction and removal requests have the basis legitimate interest, or Art. 6(1)(c) with Art. 12 for GDPR requests, and are kept as long as the evidence of the record they concern, while proof of identity is used only to check a request and is deleted once it is decided.
  - This text is not legally reviewed. Legal review is a step of milestone 6.
- **404**.

Search works without a server, from a static index. Without JavaScript, an alphabetical index of all reports and campaigns is the fallback.

## 7. Design

- Minimalist. Blue is the main colour. Orange marks warnings and calls to action only.
- Common orange text on white fails the WCAG AA contrast ratio of 4.5:1 for normal text. Orange is used for non-text accents, or as a darker orange that passes.
- No hacker clichés (hoodies, green-on-black code), no stock photos, no red alarm overload.
- System font stack, or one self-hosted font.
- Before the design milestone starts, the operator picks one of two or three visual directions from mockups. The chosen direction becomes design tokens in the repo.
- Picked 2026-11-04 on issue #3: direction C (Signal). The tokens live in `data/tokens.toml`, and every listed colour pair is contrast-checked in CI. Where a pair is placed is covered by Lighthouse's rendered-text contrast audit and by review. Non-text colours rest on review alone: for example the input border is 2.91:1 on the page ground and 3.15:1 on a card, so inputs sit only on cards. Light theme only; a dark theme may come after launch. No `mailto:` links anywhere on the site: the contact address is plain text.

## 8. Quality bar for the MVP

| Criterion | Threshold | Why this value |
|---|---|---|
| Lighthouse (performance, accessibility, best practices, SEO) | at least 95 in each, mobile profile, measured in CI on the built site ([ADR-0003](adr/0003-browser-checks.md)) | A static page without JavaScript scores about 100, so anything lower means something regressed |
| Accessibility | WCAG 2.2 AA. In CI: Lighthouse accessibility, the contrast of the listed token pairs, and horizontal overflow at 320 CSS px (page level, and boxes that clip or scroll, except the one `visually-hidden` utility class, whose use in CSS is restricted by a static rule and which is the only place `!important` is allowed, [ADR-0003](adr/0003-browser-checks.md) part 6). Review covers the rest | Credibility, and readable for everyone. Orange contrast is the known risk. Long hashes and defanged URLs are the reflow risk |
| HTML | valid in the Nu Html Checker | Clean markup for search engines and agents |
| Links | no broken internal links, checked on every PR. External links are checked weekly and before content merges (lychee) | Broken sources undermine trust. A third-party outage must not block a removal PR, so external links are not a PR gate ([ADR-0002](adr/0002-check-toolchain.md)) |
| Data | every record passes the schema and the record rules, every attacker artifact is defanged; record pages render the D6, D7 and D10 wording, checked on fixture records | D6, D8 |
| Third-party requests | none in the built site, checked in CI | D9 |
| Mobile | from the home page to the answer in one search on a phone | The 15-minute window from §1 |

The Content Security Policy is set with a meta tag, because GitHub Pages cannot set response headers.

## 9. Security and operations

- The domain is verified for GitHub Pages in the Replikanti org settings (TXT record `_github-pages-challenge-Replikanti`, kept permanently). Order: verify the domain, set the custom domain in the repo, then create the DNS records. No wildcard DNS records.
- DNS at Namecheap: A records `185.199.108.153`, `185.199.109.153`, `185.199.110.153`, `185.199.111.153`, AAAA records `2606:50c0:8000::153` to `2606:50c0:8003::153`, `www` as a CNAME to `replikanti.github.io`. HTTPS enforced.
- Branch protection on `main`: PR required, CI required, no force-push. The agreed profile:
  - The required status check is the CI job `check`, pinned to the GitHub Actions app, with the branch required to be up to date before merge. Pinning to the app stops a commit status posted by any other token from satisfying the check. The up-to-date rule stops a PR that was green on an old base from breaking `main`.
  - A PR is required with 0 approvals. The org has one seat, and an author cannot approve their own PR, so 1 or more approvals would block every merge.
  - The rules apply to administrators too (`enforce_admins`), because the only member is an admin and without it the rules would bind nobody.
  - Linear history, with squash-only merges and automatic deletion of merged branches.
  - Conversations must be resolved before merge, which makes review and QA findings blocking.
  - No force-push and no branch deletion.
- Emergency removal: if `check` is red for a cause outside the PR (for example a deleted Nu Html Checker image digest or a registry outage) and an urgent D7 removal is pending, only the operator personally, never an agent session, may lift `enforce_admins` through the API for that one removal PR. This is allowed only when the run log shows every `check.sh` step green except the one with the outside cause. The PR body records the reason and the failing run URL, and `enforce_admins` is restored immediately after the merge. The bypass covers the merge only. The deploy builds its artifact with the same `check.sh`, so milestone 6 defines the operator-only deploy path for an emergency removal before Pages goes on ([ADR-0002](adr/0002-check-toolchain.md)).
- Accounts: passkey or hardware-key 2FA on GitHub and Namecheap. Domain lock and WHOIS privacy on the domain.
- Email: `report@interviewscam.com` forwarded to the operator.

## 10. Out of scope for the MVP

Report form, accounts and logins, an API beyond the JSON feed, MCP server, browser extension, alerts for impersonated companies, data licensing, Czech version.

## 11. Milestones

1. **Bootstrap**: generator ADR (Hugo or Zola), repo skeleton, CI (build, HTML validation, link check, schema and defang checks, third-party request check), deploy workflow that does not publish yet, branch protection.
2. **Design**: mockup choice, design tokens, base layout, the static pages from §6, and the Lighthouse CI job.
3. **Data**: schema, report and campaign pages, JSON feed, structured data, state chips, artifact code boxes and the Copy button.
4. **Search**: static index and the no-JavaScript fallback.
5. **Seed content**: the three campaign families from §1 with sources, and the Saifuro report. The operator supplies the Saifuro artifacts (meeting domain, messages).
6. **Launch**, mostly manual: email forwarding, domain verification, DNS, HTTPS, Search Console, and the link on the org profile.

## 12. Sources

- SlowMist via KuCoin, Relay fake AI meeting app (2026-07-29): https://www.kucoin.com/blog/relay-malware-fake-ai-interview-crypto-theft
- Dr.Web, JobStealer (2026-05-07): https://news.drweb.com/show/?i=15253
- Meeten family coverage: https://cointelegraph.com/news/crypto-stealing-scammers-target-web3-workers-fake-meeting-apps
- PhishFort, fake recruitment agencies (2026-02-05): https://phishfort.com/list-of-fake-recruitment-agencies-web3-scams/
- RecruScam: https://recruscam.fr and https://www.producthunt.com/products/recruscam
- Chainabuse scam categories: https://docs.trmlabs.com/guides/chainabuse/scam-categories.md
- Google Search Central, retired structured data (2025-06-12): https://developers.google.com/search/blog/2025/06/simplifying-search-results
- GitHub Pages limits: https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits
- GitHub Pages domain verification: https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages
