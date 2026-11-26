+++
title = "Privacy"
description = "What the site, GitHub and Cloudflare log, and what happens with reports."
+++

This page explains what the site collects, what GitHub and Cloudflare log, what happens with the reports and requests you send, and what applies to people named on a page.

## Who is responsible

The controller under the GDPR is Martin Holý, a natural person. Questions about your data go to {{< param contact >}}.

## Visiting the site

The site sets no cookies and runs no analytics. It loads no scripts, fonts or images from other servers.

The site is hosted on GitHub Pages. GitHub logs the IP address of every visitor for security purposes. [GitHub's documentation](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages#data-collection) describes this.

Search data comes from Google Search Console. It reports which searches led to the site and needs no script on the site.

## Reports you send

You can send a report with the form on [Report a scam](/report-a-scam/) or by email to {{< param contact >}}. Either way, the moderator receives your email address, your message and the evidence you attach. The legal basis is legitimate interest (GDPR Art. 6(1)(f)), namely warning candidates about fake interviews and moderating reports.

Providing data is voluntary. Without evidence, nothing is published.

Your report and evidence are not published. A published page shows only the artifacts and a short summary of the evidence, never your raw messages or your personal data.

## Correction and removal requests

When you ask for a correction or removal, the moderator receives your email address, your request and any evidence you send. The legal basis is legitimate interest (GDPR Art. 6(1)(f)), namely handling corrections and notices about the pages of the site. For a request under the GDPR, such as access, deletion or an objection, the legal basis is compliance with that law (GDPR Art. 6(1)(c) with Art. 12).

Proof of identity is used only to check a request. It is deleted once the decision on the request is made.

## The forms and the email address

The forms on Report a scam and Corrections send what you enter to an endpoint at Cloudflare, `intake.interviewscam.com`. It mails your submission to the operator's mailbox and stores none of it. It sets no cookies.

- **Your IP address.** To limit how often one network can send, the endpoint keeps a keyed hash of your IPv4 address, or of the /64 network of your IPv6 address, for about 1 hour. After a submission that was mailed, it keeps that hash until the end of the day in UTC, at most 24 hours, to count the submissions of the day. Without the endpoint's secret key, the hash cannot be turned back into the address.
- **Its logs.** They hold event codes only, such as "sent" or "too large", never what you typed or your IP address. Cloudflare keeps them for 3 days.
- **Cloudflare's mail log.** For every message, Cloudflare's mail activity log records its subject, sender, recipients, message ID and time, for 31 days. For a form submission, the subject holds what you typed as the scam's name, or the page URL on the correction form, and the sender and recipient are the site's own sending address and the operator's mailbox. For an email to {{< param contact >}}, the sender is your email address.
- **Cloudflare's security logs.** They keep samples of the requests to the endpoint, form submissions included, and every request its rate limit blocks, each with the IP address, for 31 days.
- **No copy of the mail at Cloudflare.** Cloudflare's preview of sent mail, which keeps a copy for about seven days, applies only to a sending domain, and this site has none.

## People named on a page

A page can show the name of a person that a scam campaign used, as a recruiter or as someone at a company the campaign impersonated. Wherever a recruiter's name is shown as a name, it carries the label "name used by the campaign, possibly a stolen identity". On the report page about that recruiter, and in that recruiter's entry of the [data feed](/data-feed/), the name can also appear inside the handles, email addresses and other artifacts the campaign used. The heading of that page and the `name_label` field of that entry carry the label.

- **What is shown.** The name, as the campaign used it.
- **Where it comes from.** The reports and their evidence, and the public sources the page cites.
- **Why.** To warn candidates who search for that name.
- **Legal basis.** Legitimate interest (GDPR Art. 6(1)(f)).
- **How long.** The name stays while the page is published. The evidence behind it is kept for 3 years after the page is removed.

If this is your name, you have the rights listed below. If you object, your name is hidden first, before the review. [Corrections and removal](/corrections/) explains what happens next.

## Who receives the data

- **GitHub** hosts the site and logs visitor IP addresses, as described above.
- **Cloudflare** runs the site's DNS, the endpoint of the forms and the routing of email sent to {{< param contact >}} to the operator's mailbox, as described above.
- **Namecheap** is only the domain's registrar.
- **The operator's email provider** stores that mailbox.

Some of these providers process data in the United States. Each provider's own privacy statement explains its safeguards for that.

## How long data is kept

- Evidence behind a published page is kept while the page is published and for 3 years after it is removed. The purpose is to let the moderator respond to legal claims about a page. Three years is the general limitation period under Czech civil law.
- A report that is not published is deleted once that decision is made.
- Correction and removal requests are kept as long as the evidence of the page they concern, so while it is published and for 3 years after it is removed.
- Proof of identity is deleted once the decision on the request is made.
- You can ask for your report and your evidence to be deleted at any time. If that leaves a published page without evidence, the page is unpublished.

## Your rights

Under the GDPR you can ask for access to your data, for its correction or deletion, and for a restriction of its use. You can also object to its use based on legitimate interest.

To use any of these rights, email {{< param contact >}} and say which right you use. You get an answer within one month, as GDPR Art. 12(3) requires. You may be asked to prove your identity. If your name appears on a page, [Corrections and removal](/corrections/) explains what happens.

You can also complain to a data protection authority. In the Czech Republic that is the Office for Personal Data Protection (Úřad pro ochranu osobních údajů).
