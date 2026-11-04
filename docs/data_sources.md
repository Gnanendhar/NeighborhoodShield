# Data sources and provenance

Everything the product knows comes from (1) public frameworks encoded as rules, (2) the owner's own answers and uploads, processed in session, and (3) the dated public-data snapshots below. **No real business's data is in this repository.**

| File | Source | Snapshot | Rows | Licence / terms | Refresh |
|---|---|---|---|---|---|
| `data/reference/cis_v81_ig1_safeguards.csv` | CIS Controls v8.1 IG1 list (cisecurity.org); cross-checked against a secondary v8.1 index | 2026-11-04 | 56 | CIS Controls are free to use with attribution; confirm against the official v8.1 workbook after free registration | When CIS publishes a new version |
| `data/reference/eol_table.csv` | endoflife.date product files (GitHub `endoflife-date/endoflife.date`, commit `46d14de`, 2026-11-04) for 16 products | 2026-11-04 | 971 | MIT | Monthly: `python tools/refresh_reference_data.py eol` |
| `data/reference/kev_smb_snapshot.csv` | CISA Known Exploited Vulnerabilities catalog, version 2026.11.03 (1,767 entries), filtered to 908 SMB-relevant vendors/products. Fetched from the official `cisagov/kev-data` mirror because the cisa.gov feed was blocked from the build environment; the script tries cisa.gov first | 2026-11-04 | 908 | U.S. Government work, public domain | Monthly: `... kev` |
| `data/reference/attack_techniques_used.csv` | MITRE ATT&CK Enterprise STIX bundle (`mitre/cti`, enterprise-attack.json) — only the 24 techniques the rules cite | 2026-11-04 | 24 | ATT&CK terms of use (attribution) | When rules add techniques |
| `data/reference/chicago_license_counts_by_type.csv` | City of Chicago Data Portal, *Business Licenses – Current Active* (`uupf-x98q`), aggregate SODA query `license_status='AAI' AND expiration_date > '2026-11-04'` grouped by type | 2026-11-04 | 58 | City of Chicago open data terms | Quarterly: `... chicago` (also writes counts by community area) |

| `data/reference/smb_benchmarks.csv` | Published small-business surveys: Cyber Readiness Institute (2022, n=1,403), Nationwide (2019 n=400; 2024), Guardz (2025, n=800), EasyDMARC (2026, 1.8M domains), Verizon DBIR 2026 (via CRI) | 2026-11-04 | 14 | Facts cited with attribution | When new surveys publish |
| `data/reference/incident_contacts_illinois.csv` | fbi.gov/chicago, cisa.gov, illinoisattorneygeneral.gov, ilga.gov | 2026-11-04 | 10 (5 public, 5 owner-filled) | Public information | Quarterly link check |
| `data/reference/chicago_ssa_partners.csv` | City of Chicago DPD, Special Service Areas and provider list (expired SSAs excluded) | 2026-11-04 | 55 | Public list; prospects only | Twice a year |
| `data/reference/email_auth_requirements.csv` | Mailbox-provider sender requirements (Google, Yahoo, Microsoft May 5 2025, Apple), via SpamResource | 2026-11-04 | 4 | Facts with attribution | When providers change rules |
| `data/reference/free_tools.csv` | Vendor pages for 13 free tools | 2026-11-04 | 13 | Links only; **not reachable from the build environment, verify with `tools/check_links.py`** | Monthly (workflow) |
| `data/reference/cis_v81_beyond_ig1_used.csv` | CIS v8.1 safeguard 9.5 Implement DMARC (IG2) | 2026-11-04 | 1 | Confirm against official workbook | With CIS updates |

## Notable facts surfaced by the real data (Week 1)

* **Windows 11 24H2 Home/Pro reached end of servicing on 2026-10-13**, three weeks before this snapshot, and Windows 11 23H2 Enterprise ends 2026-11-10. Owners who believe "Windows 11 is current" may be running an unsupported release. The taqueria sample business is built on exactly this case (questionnaire says fine, upload says end-of-life).
* **Windows 10 22H2 end of support: 2025-10-14.**
* **macOS 14 Sonoma end of support: 2026-09-14.**
* The KEV catalog includes small-business staples: TP-Link TL-WR841N (CVE-2023-50224), ConnectWise ScreenConnect (4 entries), SimpleHelp, WinRAR (CVE-2025-8088, known ransomware use), 7-Zip, Veeam Backup & Replication (known ransomware use). 212 of the 908 SMB-relevant entries are marked as used in ransomware campaigns.
* KEV contains an entry whose *product* field is "Microsoft". Naive name matching would flag every Microsoft program; the `in_kev` match rule excludes products equal to their vendor name.
* Chicago market sizing: 11,253 active Retail Food Establishment licenses, 854 Children's Services Facility licenses, 16,062 Limited Business Licenses (covers salons and many shops), 1,559 Motor Vehicle Services. These are license records, not unique businesses.

* **81% of small-business owners believe an attack would cost them under $5,000; the average small-business cyber claim is $18,000–21,000** (Nationwide, 2024).
* **Only 22.9% of the top 1.8 million domains enforce DMARC** (EasyDMARC 2026), while Google, Yahoo and Microsoft (since May 5, 2025) require it from bulk senders.
* **Illinois BIPA was amended on Aug 2, 2024**: repeat scans of the same person by the same method are one violation, and electronic signatures count as consent.

## Published statistics for Planner calibration (Week 5)

Secondary summaries were used in Week 1; confirm each figure against the primary report before it appears in the app or pitch. See `docs/calibration_notes.md`.

## What we will never use

Scraped data about named businesses; breach data about named people; any pilot business's answers or files (pilot notes are anonymized and kept out of the repo unless the business gives written permission).
