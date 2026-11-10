+++
date = 2026-11-02
[params]
name = "Example Front Company"
aliases = ["Example Front Co", "EFC Hiring"]
name_type = "company"
state = "front"
state_basis = [
  "No company register in the countries named on its website lists this name.",
  "Its website went online eleven days before the first report.",
  "None of the staff it names could be found outside its own pages.",
]
related = ["persona-1", "persona-2"]
summary = "A recruiting company with no trace outside its own website. It sends candidates a meeting app to install before a video interview."
evidence = "Three candidate submissions were reviewed: the recruiter messages, the meeting invitation and the hash of the installer, compared with the cited vendor analysis."
first_seen = 2026-09-14
last_seen = 2026-10-28
last_reviewed = 2026-11-02
independent_reports = 3

[params.campaign]
slug = "example-campaign-family"
source = "vendor-analysis"
basis = "artifact"
artifact = "frontco-meet[.]pages[.]example"

[params.artifacts]
domains = ["frontco-meet[.]pages[.]example", "frontco-careers[.]example"]
urls = [
  "hxxps://frontco-meet[.]pages[.]example/join/candidate",
  "hxxps://download[.]frontco-careers[.]example/files/Q7x2Lm9Pa4Rt8Vb1Nc6Hd3Kf5Jg0Ws7Ye2Ui9Oz4Xq8Mp",
]
ips = ["198[.]51[.]100[.]23"]
emails = ["talent[@]frontco-careers[.]example"]
repositories = ["git[.]frontco-careers[.]example/hiring/take-home-task"]
file_names = ["FrontCoMeet-Setup[.]exe", "FrontCoMeet[.]dmg"]
handles = [
  { platform = "telegram", value = "@frontco_talent" },
  { platform = "linkedin", value = "example-front-company-hiring" },
]
packages = [{ registry = "npm", name = "frontco-meeting-sdk" }]
sha256 = [
  { value = "193e081078047d86ba2b1417cc3e80ad6d3c8e75c7d9f7ab66929e04cd564bd6", file_name = "FrontCoMeet-Setup[.]exe", listed_on = ["malwarebazaar", "virustotal"] },
  { value = "aaf3f631a833b757820fa2005bf19e5e1fd2b559ae60c795bb2d4c680eb10a5c", listed_on = ["virustotal"] },
]

[[params.sources]]
id = "vendor-analysis"
title = "Fake meeting apps that target job seekers"
publisher = "Vendor Example Research"
date = 2026-10-20
url = "https://vendor.example/research/fake-meeting-apps"

[[params.sources]]
id = "platform-notice"
title = "Abuse notice for a site hosted on our pages service"
publisher = "Pages Example"
date = 2026-10-25
url = "https://abuse.pages.example/notices/2026-10-25"
+++

The recruiter wrote on a messaging app and offered a well-paid remote role. Before the interview, the candidate was asked to install a meeting app from hxxps://frontco-meet[.]pages[.]example/join/candidate. The installer FrontCoMeet-Setup[.]exe matches the first hash above.

The take-home task in git[.]frontco-careers[.]example/hiring/take-home-task also pulled the package frontco-meeting-sdk.
