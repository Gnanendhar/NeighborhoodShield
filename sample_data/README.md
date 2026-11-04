# Sample businesses

Four **fictional** businesses (three from the brief plus a control case) that run **real, dated** software. Regenerate with `python sample_data/generate.py`; output is deterministic.

| Business | Segment (Chicago licence category) | Designed weaknesses | Expected findings |
|---|---|---|---|
| Taqueria Luna Azul | Retail Food Establishment | shared register login, RDP open to internet, ScreenConnect (KEV), Windows 11 24H2 Home past end of servicing, flat Wi-Fi | 34 |
| Little Sprouts Home Daycare | Children's Services Facility | no backups, unencrypted shared laptop with children's and health records, no email MFA, WinRAR (KEV) | 39 |
| Fade & Shine Salon | Limited Business License | Windows 10 22H2, no antivirus, TP-Link TL-WR841N (KEV) with DMZ allow-all, backups on same PC | 42 |
| Northside Community Pantry (control) | Not-For-Profit Club | well run; only personal phones read email | 1 |

Each folder has `profile.yaml` (story), `answers.yaml` (questionnaire), `uploads/*.csv` (template format), and `expected_findings.yaml` (hand-labelled from the rule specs). From Week 2 the engine's output must equal these labels. Together the four businesses exercise all 62 rules.

Uploads sometimes **contradict** the answers on purpose (e.g. the taqueria owner says no computer is outdated; the device list says otherwise). That gap is the value of the Full Assessment.

Each business also has `lookups/email_domain_check.csv` (except the salon, which uses free webmail) using reserved `.example` domains, and `expected_legal_flags` in `expected_findings.yaml`.
