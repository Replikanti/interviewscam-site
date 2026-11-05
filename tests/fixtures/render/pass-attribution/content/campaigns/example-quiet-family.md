+++
date = 2026-11-02
[params]
name = "Example Quiet Family"
aliases = ["ECF"]
summary = "A campaign family that reaches developers through fake job offers and delivers malware through meeting apps, coding tests, packages and terminal commands."
first_seen = 2026-08-15
last_seen = 2026-10-31
delivery = ["fake_meeting_app", "coding_test_repository", "npm_package", "terminal_command"]
targeted_os = ["windows", "macos", "linux"]
steals = ["Browser passwords", "Crypto wallet files", "Session cookies"]

[[params.sources]]
id = "vendor-analysis"
title = "Fake meeting apps that target job seekers"
publisher = "Vendor Example Research"
date = 2026-10-20
url = "https://vendor.example/research/fake-meeting-apps"
+++

The cited sources describe the family as using several delivery routes at once.
