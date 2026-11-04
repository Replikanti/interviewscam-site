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
Why: the groups this site writes about attack developers through npm packages, so the build chain must not depend on npm. Tooling that only exists on npm (Lighthouse, for example) may run only in CI jobs that hold no write token and do not produce the deploy artifact, never on a developer machine.
Rejected: Astro, Next.js and other npm-based stacks.

**D4. GitHub Pages from the private repo `Replikanti/interviewscam`, deployed by GitHub Actions.**
Why: static hosting with HTTPS and a CDN at no extra cost. A private source repo keeps drafts, intake and history out of public view, so a removed report really disappears from the site (caches aside). Publishing Pages from a private org repo needs GitHub Team, which the org has since 2026-11-04. Deploying via Actions keeps the custom domain in the repo settings, so a build cannot drop a `CNAME` file and unlink the domain.
Limits from the GitHub docs: published site at most 1 GB, soft bandwidth limit 100 GB per month, deployment timeout 10 minutes. GitHub does not allow Pages for a site primarily directed at commercial transactions or SaaS, so a paid B2B part would be hosted elsewhere.
Rejected: a public repo (unverified drafts and removed reports would stay in public git history and in forks), a public build-only repo next to the private one (two repos and a deploy token for no gain once Team is paid), Cloudflare Pages (another provider and account).

**D5. Report intake is private.** MVP: email to `report@interviewscam.com`, forwarded by Namecheap. Later: a form that stores into a private place, for example a Cloudflare Worker with Turnstile that opens issues in this private repo.
Why: an issue in a public repo is public the moment it is filed, under the reporter's GitHub account, and search engines can index it before anyone reviews it. That breaks moderation before publication and exposes the reporter to the people they reported. Rejected: public GitHub issues or PRs as intake.

**D6. Records are about artifacts, wording is neutral.** A record describes the artifacts a campaign used (domain, app name, file hash, handle, repository, package), not a verdict about a company. A company or person name has one of two states.
- *Name abused*: a real company or person whose name the scammers used. The page says the name was used without their involvement.
- *Front*: no real existence found (no registry entry, no history, no footprint). The page lists what was checked.
Why: these campaigns routinely use the names of real companies and real executives. PhishFort lists an impersonated firm, and JobStealer uses the Webex name. A page that calls a real company a scam defames the victim. The reputation of a legal person is protected by the Czech Civil Code, and names of people fall under the GDPR. Rejected: one page per company titled as a scam.

**D7. Moderation before publication, with evidence.** Nothing is published without evidence (screenshots with personal data redacted, message headers, URLs, hashes) and a moderator review. Reporters stay anonymous to the public, not to the moderator. Every page links to a correction and removal request. Labels state facts ("reported 3 times, evidence reviewed on 2026-11-10"), not an editorial verdict.
Why: open anonymous reporting invites fake reports against competitors. The DSA hosting exemption covers third-party content only for a provider that offers a notice channel and acts on notices. A label like "verified scam" turns third-party content into the operator's own claim.

**D8. Nothing live on the site.** Attacker URLs and domains are always defanged (`hxxps://example[.]com`), and a CI check enforces it. No malware binaries live in the repo or on the site, only hashes with links to MalwareBazaar or VirusTotal.
Why: accidental clicks, link previews in chat apps, the risk of the site itself being listed as a source of malicious links, and GitHub's policy against delivering malicious executables.

**D9. No third-party requests.** No external scripts, trackers, analytics, cookies, ads or web fonts. Search data comes from Google Search Console, which needs no script on the site.
Why: trust and privacy for a security audience, no cookie banner, and nothing on the site that a third party can change. GitHub logs visitor IP addresses for security purposes, and the privacy page says so.

**D10. Persona names only with a label.** A recruiter persona's name is published only when the evidence shows it in the scam contact, and only as "name used by the campaign, possibly a stolen identity". The real person can ask for removal.
Why: recruiter identities are often stolen from real people, yet candidates search for exactly these names.

## 5. Content model

Records are structured files in the repo, validated against a schema in CI.

**Campaign family**, page `/campaigns/<slug>/`

- name, aliases, attribution only as stated by the cited sources (never our own), first seen, last seen
- delivery (fake meeting app, coding test repository, npm package, terminal command), targeted operating systems, what it steals
- sources (vendor reports with date and link), related reports

**Report**, page `/reports/<slug>/`, one per name a candidate sees

- the name and its type (company, meeting app, domain, recruiter persona, repository, package)
- for company and person names, the state from D6
- campaign family, or "unattributed"
- artifacts, defanged: domains, URLs, SHA-256 file hashes, handles, repositories, packages
- what happened (short and factual), first seen, last seen, last reviewed
- evidence summary (what was reviewed, never raw personal data)
- sources and the number of independent reports
- correction and removal link

**Record bodies contain no live URLs** (D8): no bare URLs, no Markdown links, no `<…>` autolinks. This rule binds the Markdown body of a record. Live links appear only in `sources`. Template output may also link to MalwareBazaar or VirusTotal from SHA-256 artifacts (D8); that is not body text. The record check fails closed on any live URL in a body, because it cannot tell an attacker URL in prose from a source URL in prose. Relaxing this rule needs an ADR.

**Feed**, `/feed.json`: all published reports and campaigns with defanged artifacts, for researchers and tools. Stable field names and a version field.

URLs and titles stay neutral, for example `/reports/saifuro/` titled "Saifuro, a name used in fake job interviews", never "<company> scam". Structured data uses schema.org types that search engines still support. ClaimReview is not used, because Google retired it from Search in June 2025 and it was meant for fact-checking publishers.

## 6. Pages in the MVP

- **Home**: one search box ("company, app, domain or recruiter"), the answer for an exact match on the same page, a short "before your call" checklist, the latest reports.
- **Report and campaign pages** from §5.
- **Before your call**: warning signs (unknown meeting app, link sent minutes before the call, "run this repo or command", installers only for Windows and macOS) and what to do instead.
- **Report a scam**: what to send to `report@interviewscam.com`, which evidence helps, how reporters are protected.
- **Methodology**: how reports are reviewed, what the states mean, how sources are used.
- **About**: who runs the site (D1), why it exists, how to get in touch.
- **Corrections and removal**: how to ask and what happens next.
- **Privacy**: what the site and GitHub log, what happens with reports.
- **404**.

Search works without a server, from a static index. Without JavaScript, an alphabetical index of all reports and campaigns is the fallback.

## 7. Design

- Minimalist. Blue is the main colour. Orange marks warnings and calls to action only.
- Common orange text on white fails the WCAG AA contrast ratio of 4.5:1 for normal text. Orange is used for non-text accents, or as a darker orange that passes.
- No hacker clichés (hoodies, green-on-black code), no stock photos, no red alarm overload.
- System font stack, or one self-hosted font.
- Before the design milestone starts, the operator picks one of two or three visual directions from mockups. The chosen direction becomes design tokens in the repo.

## 8. Quality bar for the MVP

| Criterion | Threshold | Why this value |
|---|---|---|
| Lighthouse (performance, accessibility, best practices, SEO) | at least 95 in each, mobile profile | A static page without JavaScript scores about 100, so anything lower means something regressed |
| Accessibility | WCAG 2.2 AA | Credibility, and readable for everyone. Orange contrast is the known risk |
| HTML | valid in the Nu Html Checker | Clean markup for search engines and agents |
| Links | no broken internal links, checked on every PR. External links are checked weekly and before content merges (lychee) | Broken sources undermine trust. A third-party outage must not block a removal PR, so external links are not a PR gate ([ADR-0002](adr/0002-check-toolchain.md)) |
| Data | every record passes the schema, every attacker artifact is defanged | D6, D8 |
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
2. **Design**: mockup choice, design tokens, base layout, the static pages from §6.
3. **Data**: schema, report and campaign pages, JSON feed.
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
