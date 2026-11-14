# Calibration notes for the Business Survival Security Planner

Every disruption scenario in `rules/scenarios.yaml` is either:

* **calibrated**: taken from published small-business data, or
* **estimated**: worked out from cited inputs, with the working written next to the value.

Last reviewed **2026-11-14**. Primary sources were opened directly where marked (primary); the others were read through the publisher's own press release or reputable coverage, as noted.

## Scenario values

| Scenario | Days closed (low–high) | Recovery cost | Status | Basis |
|---|---|---|---|---|
| Ransomware on the main computer | 3–30 | $18,000 | calibrated | Sophos 2025 recovery times; Nationwide 2024 average small-business claim |
| Email or bank account taken over | 0–2 | $600 | estimated | Hiscox 2026 disruption (32 hours); 4 hours of IT help |
| Records lost for good | 7–30 | $1,500 | estimated | Sophos 2025 recovery times as a guide; 10 hours of IT help |
| Register tampered with or down | 1–5 | $1,200 | estimated | Hiscox 2026 disruption; 8 hours of IT and provider time |
| Router taken over | 1–3 | $600 | estimated | Hiscox 2026 disruption; 4 hours of IT help |
| Laptop or phone lost or stolen | 1–3 | $1,300 | estimated | Omdia U.S. PC price (> $1,000); 2 hours of IT help |
| Virus spreads across computers | 1–5 | $1,200 | estimated | Hiscox 2026 disruption; 8 hours of IT help |
| No plan for a bad day | +1–2 days | — | estimated | Time to find outside help, about one average disruption (Hiscox 2026) |

**Recovery cost excludes lost sales.** The Planner adds lost sales from days closed × the owner's own daily sales range, so they are not counted twice. Money stolen by fraud and card-breach investigation costs are shown as text warnings, not added to the number, because they vary too widely to estimate for one business.

**Labor rate:** $150 per hour for outside IT help, the middle of the $101–$200 break-fix band most chosen (56%) in Kaseya's MSP pricing survey (2020). The U.S. median wage for computer support specialists was $30.24 per hour in May 2025 (BLS), so in-house help would cost less.

## Sources

| Figure | Value | Source | How it was checked |
|---|---|---|---|
| Ransomware recovery time | 53% fully recovered within a week; 18% took more than a month | Sophos, *State of Ransomware 2025* (3,400 organizations of 100–5,000 employees, 17 countries, survey Jan–Mar 2025) | Sophos press release (primary) |
| Average small-business cyber claim | $18,000–$21,000; recovery up to 75 days | Nationwide small-business survey and claims data (survey July 26–Aug 14, 2024; 1–50 employees, under $10M revenue) | Press coverage of the Nationwide release (Insurance Journal, PropertyCasualty360) |
| Average disruption per incident | about 32 hours; average cost $52,000 a year | Hiscox *Cyber Readiness Report 2026* (10th edition; 6,800 firms under 250 employees, UK, Europe, U.S.) | IT Brief and Infosecurity Magazine coverage, Sept 2026 |
| Business email compromise | 24,768 complaints; $3,046,598,558 adjusted losses | FBI IC3 *2025 Internet Crime Report* | Report PDF (primary), ic3.gov |
| Ransomware complaints | 3,611 complaints; $32,320,105 losses, excluding lost business, time, wages, files, equipment and remediation | FBI IC3 *2025 Internet Crime Report* | Report PDF (primary), ic3.gov |
| IT support wage | $30.24 per hour median (May 2025) | U.S. Bureau of Labor Statistics, Occupational Outlook Handbook | bls.gov (primary) |
| Outside IT break-fix rate | 56% of MSPs chose $101–$200 per hour | Kaseya MSP pricing survey (2020) | Kaseya blog |
| Replacement computer price | average U.S. PC sell-in price passed $1,000 (Q2 2026) | Omdia | The Next Web coverage of the Omdia release |
| PCI forensic investigation (small merchant) | about $8,000 | SecurityMetrics (a PCI forensic investigator) | Vendor blog; used in a text warning only |
| Edge-device vulnerabilities cited | 29% | Verizon DBIR 2026 via Cyber Readiness Institute | Secondary summary; context only |
| SME claim averages | ransomware $660K, BEC $100K (SMEs = under $2B revenue) | NetDiligence *Cyber Claims Study 2026* | NetDiligence blog (primary). **Not used**: "SME" here includes companies far larger than a neighborhood business |
| Global average breach cost | $4.99M | IBM *Cost of a Data Breach 2026* | Secondary. **Not used**: enterprise-scale |

## Limits

* No large published dataset reports days closed for businesses with fewer than 20 staff. Sophos surveys organizations of 100+ employees and Hiscox reports one average across firms under 250, so the day ranges for the smallest businesses remain estimates.
* Before showing dollar figures to owners, sanity-check them with at least one real owner: "If your register was down three days, does $X feel right?"
* Review these figures when Sophos, Hiscox, Nationwide or the FBI publish new editions.
