+++
date = 2026-11-01
[params]
name = "Avery Exampleton"
aliases = ["A. Exampleton"]
name_type = "persona"
state = "front"
state_basis = [
  "No professional profile under this name predates the first message.",
  "The profile photo appears under other names on other sites.",
]
summary = "A recruiter persona that contacts candidates on a business network and moves the talk to a messaging app."
evidence = "Two candidate submissions were reviewed: the first messages and the profile, both matching the front company record."
first_seen = 2026-09-14
last_seen = 2026-10-28
last_reviewed = 2026-11-01
independent_reports = 2

[params.campaign]
slug = "example-campaign-family"
source = "recruiter-accounts"
basis = "artifact"
artifact = "avery-exampleton-4b2a1"

[params.artifacts]
handles = [
  { platform = "telegram", value = "@talent_lead_frontco" },
  { platform = "linkedin", value = "avery-exampleton-4b2a1" },
  { platform = "other", value = "avery-exampleton-zoë" },
]
emails = ["lead[@]frontco-careers[.]example", "avery[.]exampleton[@]frontco-careers[.]example"]

[[params.sources]]
id = "recruiter-accounts"
title = "Recruiter accounts that hand out fake meeting apps"
publisher = "Vendor Example Research"
date = 2026-10-24
url = "https://vendor.example/research/recruiter-accounts"
+++

The persona sent the meeting link from the front company record.
