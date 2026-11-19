# Changelog

## 0.3.0 (2026-11-19)

* Modules 2 (network, 15 rules) and 3 (patching, 10 rules) implemented and shown in the app, each rule with a firing and a clear test. 41 of 62 rules are now live.
* End-of-life checks understand how owners write versions: "Windows 11 Home 24H2", "10 Pro 22H2", "macOS Sonoma 14.6", "iOS 18.1", "Android 8.1". Unknown versions are never guessed.
* Fix: the Windows export script wrote "11 24H2" without the edition, which never matched the end-of-life snapshot. It now writes "11 Pro 24H2".
* Firewall ports are read exactly (`port_in`): ranges, service names and `any` are understood, and port 8000 no longer counts as port 80. The salon sample's inbound allow-all rule now correctly raises NET-002 (remote desktop and file sharing exposed); its hand label was updated.
* Email domain check (`engine/lookups.py`): reads only public SPF, DMARC, MX and DKIM records for the owner's own domain, skips free webmail, feeds NET-013 to NET-015. Adds `dnspython`.
* Results page grouped by area. 802 tests.

## 0.2.0 (2026-11-14)

* Upload parsing (`engine/ingest.py`): CSV or Excel, column and value checks with plain-language messages, extra columns dropped on read, size and row limits, Excel read without running formulas.
* Redaction on read: user IDs hashed with a per-session salt, IP addresses shortened to their network, device and system names replaced with role labels.
* Rules engine (`engine/evaluate.py`): evaluates the YAML triggers with three outcomes (fired, clear, not evaluable), end-of-life and CISA KEV lookups, plain-language evidence for every finding.
* Module 1 (identity, 16 rules) marked implemented and shown in the app; the engine also matches the hand-labelled findings for all 62 rules and the legal flags on every sample business.
* App: Results page, optional file uploads in the Full Assessment, and a one-click sample business.
* 659 tests.

## 0.1.1 — Week 1 extension (2026-11-04)

* Ten extensions specified in docs/extensions.md (ADR 0006 to 0008).
* Rules 58 → 62 (IAM-016 leaked-password check; NET-013..015 email domain SPF/DMARC). Questions 49 → 52; Quick Check unchanged at 36.
* New real-world datasets: published SMB benchmarks, Illinois incident contacts, Chicago Special Service Areas, mailbox sender requirements, free tools, beyond-IG1 safeguards.
* Legal flags (BIPA, PIPA, PCI DSS, childcare, HIPAA scope, FTC Safeguards), insurance readiness controls, benchmark links.
* Monthly reference-data refresh workflow and link checker. App "Real-world data" page.

## 0.1.0 — Week 1 (2026-11-02 to 2026-11-06)

* Rule catalog: 58 rules across five modules, validated schema, generated XLSX mapping sheet.
* Questionnaire v1 (49 questions, 36 in the Quick Check) in `content/strings.yaml`.
* Five upload templates, guides, worked examples, and read-only PowerShell exporters.
* Reference data snapshots: endoflife.date, CISA KEV, CIS v8.1 IG1, MITRE ATT&CK, Chicago business licenses.
* Four sample businesses with hand-labelled expected findings exercising every rule.
* Streamlit design preview, 536 tests, GitHub Actions CI.
