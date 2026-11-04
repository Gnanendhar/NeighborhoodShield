# Calibration notes for the Business Survival Security Planner

Status: **Week 1 research log.** Scenario values in `rules/scenarios.yaml` are the brief's Appendix D placeholders. In Week 5, each value is checked against the sources below, updated if needed, and marked `calibrated` with the date.

| Figure | Value | Source (as found 2026-11-04) | Primary to confirm | Used for |
|---|---|---|---|---|
| Total reported U.S. cybercrime losses, 2025 | ≈ $20.9B; 1,008,597 complaints | FBI IC3 2025 report via The Record and other coverage (Apr 2026) | ic3.gov Annual Report 2025 | README / pitch context |
| Business email compromise losses, 2025 | "over $3 billion" | FBI IC3 2025 via The Record | IC3 report BEC table | `account_takeover_fraud` text flag, IAM-013 |
| Ransomware complaints, 2025 | 3,611 complaints, > $32M reported losses | FBI IC3 2025 via The Record | IC3 report | `ransomware_primary_system` note (complaint losses exclude downtime) |
| Small orgs' share of ransomware victims | 96% | Verizon DBIR 2026 via Cyber Readiness Institute | DBIR 2026 SMB section | pitch, scenario likelihood narrative |
| SMBs not paying ransom, citing backups | 69% | Verizon DBIR 2026 via CRI | DBIR 2026 | BKP rules narrative |
| Human element in breaches | 62% | Verizon DBIR 2026 via CRI | DBIR 2026 | IAM-012 narrative |
| Edge-device vulnerabilities cited | 29% | Verizon DBIR 2026 via CRI | DBIR 2026 | `router_compromise` |
| Average small-business cyber claim | $18,000–21,000; recovery up to 75 days | Nationwide press release, Sep 25, 2024 | Nationwide survey report PDF | **Primary small-business anchor** for ransomware and data-loss scenarios |
| Owners who think an attack would cost < $5K | 81% | Nationwide, 2024 | same | Pitch: the gap between belief and claims data |
| Global average breach cost | $4.99M (U.S. $11.5M) | IBM Cost of a Data Breach 2026 via eSecurity Planet (Jul 2026) | IBM report | Context only: enterprise-scale, **not** used for small-business dollar estimates |

## Calibration approach (Week 5)

1. Prefer **downtime in days** from small-business-specific reporting (ransomware recovery case studies, insurer claim summaries, CISA/MS-ISAC guidance) over enterprise breach costs.
2. Keep ranges wide and visible; the Planner's purpose is prioritization, not prediction.
3. Sanity-check with at least one real owner (Gate 3 requirement): "If your register was down three days, does $X feel right?"
