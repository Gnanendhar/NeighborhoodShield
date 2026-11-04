# Known issues and open items (Week 1)

| # | Item | Plan |
|---|---|---|
| 1 | PowerShell exporters pass the PowerShell 7.4 parser but have not yet run on a real Windows machine | Run `Export-NSLocalDevice.ps1` on the builder's own laptop and `Export-NSADUsers.ps1` in the home-lab domain; fix and record results (Week 2) |
| 2 | CIS safeguard titles cross-checked against a secondary index | Confirm against the official v8.1 workbook after free CIS registration |
| 3 | NIST CSF 2.0 subcategory per rule is the author's mapping | Cross-check in CIS Controls Navigator before external publication |
| 4 | Calibration statistics taken from secondary summaries | Confirm against IC3, DBIR, IBM primary reports in Week 5 |
| 5 | `os_version` must currently match endoflife.date labels (e.g. `11 24H2 (W)`) | Week 3: normalizer for edition and wording variants |
| 6 | Chicago by-community-area counts not yet captured (portal blocked from build environment) | Run `python tools/refresh_reference_data.py chicago` locally |
| 7 | NET-002 and NET-003 can both fire on the same questionnaire answers | Planner de-duplicates by shared fix (Week 5) |
| 8 | Free-tool URLs could not be reached from the build environment | Run `python tools/check_links.py` locally before Week 6 |
| 9 | LEG-004 cites DCFS Parts 406/407 from memory | Confirm against current DCFS rules before showing to owners |
| 10 | Benchmarks mix years (2019 to 2026) and populations | Each row carries its own date and caveat; refresh when newer surveys publish |
| 11 | Insurance controls come from secondary underwriting guides | Compare with 2 or 3 real carrier applications (e.g. via a ChiEAC insurance partner) in Week 5 |
| 12 | Extensions add about 32 hours to a 75-hour plan | Cut first if a gate slips (ADR 0006) |
