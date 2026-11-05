+++
date = 2026-10-30
[params]
name = "Example Abused Company"
name_type = "company"
state = "name_abused"
state_basis = [
  "The company exists and lists its open roles on its own careers page.",
  "Its hiring team said in public that it did not send these messages.",
]
summary = "Messages that copy the name and logo of a real company invite candidates to a video interview on a fake meeting site."
evidence = "One candidate submission was reviewed: the invitation and the meeting link, which matches the cited vendor analysis."
first_seen = 2026-10-02
last_seen = 2026-10-21
last_reviewed = 2026-10-30
independent_reports = 1

[params.campaign]
slug = "example-unattributed-family"
source = "vendor-analysis"
basis = "named"

[params.artifacts]
domains = ["abused-hiring[.]example"]
emails = ["recruiting[@]abused-hiring[.]example"]

[[params.sources]]
id = "vendor-analysis"
title = "Fake meeting apps that target job seekers"
publisher = "Vendor Example Research"
date = 2026-10-20
url = "https://vendor.example/research/fake-meeting-apps"
+++
