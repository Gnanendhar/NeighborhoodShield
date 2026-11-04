# Design (Week 1)

This document is the Gate 1 design record. It explains how the pieces fit, why they are shaped the way they are, and what is deliberately left out.

## 1. Data flow

```
Owner answers  ─┐
                ├─► app (Streamlit) ─► engine.ingest ─► engine.evaluate ─► engine.score ─► engine.planner ─► engine.report
Owner uploads  ─┘        │                 │                  ▲                                  ▲
                         │          validate + redact     rules/*.yaml                   rules/scenarios.yaml
                         │          (Pydantic)            data/reference/*.csv
                         ▼
                  st.session_state only (never disk)
```

* **One `Assessment` object** per session holds answers plus any uploaded, already-redacted DataFrames. Rules evaluate against it and return `Finding`s with sanitized evidence.
* **The engine never imports Streamlit.** It can be called from tests, a CLI, or a FastAPI wrapper unchanged.

## 2. Rules as data

Rules live in `rules/<module>.yaml` and are validated at load by `engine/schemas.py::RuleSpec`. A malformed rule raises at start-up.

**Trigger DSL** (evaluated from Week 2):

| Node | Meaning |
|---|---|
| `{kind: answer, q, in: [...]}` | Answer is one of the codes |
| `{kind: answer, q, contains_any / lacks_all: [...]}` | For multi-select answers |
| `{kind: rows, table, where: [...], match: any \| none \| ratio}` | Rows of an upload matching every `where` |
| `any_of: [...]`, `all_of: [...]` | Composition |

Row operators: `eq ne in not_in gt lt gte lte older_than_days newer_than_days is_empty not_empty contains_any is_end_of_life in_kev`. Two are lookups into dated reference snapshots:

* `is_end_of_life` — matches `os_version` against `release_label` in `data/reference/eol_table.csv` (endoflife.date) and fires if `eol` ≤ assessment date. Week 3 adds normalization (e.g. "Windows 11 Home 24H2" → `11 24H2 (W)`).
* `in_kev` — the KEV product name (4+ characters, not equal to its vendor name, not a generic term) appears in `key_software_name`. Advisory only (name, not version). Week 1 testing found a KEV entry whose product is literally "Microsoft", which would flag every Microsoft program; the rule above excludes it.

**Integrity checks enforced by tests:** IDs sequential per module; every safeguard is a real IG1 safeguard; every ATT&CK ID exists in the official STIX bundle; every question ID and answer code exists; every upload column and enum value exists in the template; `evidence` field matches what the trigger actually uses; owner-facing text has no unexplained acronyms and stays under 50 words.

## 3. Questionnaire design

* 52 questions in six sections (49 from Week 1 design + 3 extension questions, all Full Assessment). **Quick Check = 36 core questions; 32 always shown, 4 follow-ups** shown only when relevant (remote-access MFA, always-on remote tool, backup locations, restore test).
* "Don't know" is a first-class answer and, for most rules, fires the finding ("you can't protect what you can't confirm"); the plan tells the owner how to find out.
* Daily sales is a **range**, optional, with "I'd rather not say". The Planner shows text-only exposure if it is skipped.
* Added beyond Appendix A, each mapped to a real control gap common in small businesses: payment-change call-back (business email compromise), unique passwords, account list, staff training, DNS filtering, software list, device list, incident owner, service-provider list, device count, cyber insurance.

## 4. Privacy by design

| Risk | Control |
|---|---|
| Server stores customer data | No writes: uploads are read from memory (`st.file_uploader` buffer) into DataFrames; no database; Streamlit `maxUploadSize = 5` MB |
| Personal data in uploads | Redact on ingest per `REDACT_COLUMNS`: hash user IDs (salted per session), truncate IPs to network, map device names to role labels. Owners are also told to use labels; export scripts do it for them |
| Personal data in the repository | Only public reference data and fictional businesses; tests block email/phone patterns in sample uploads; `.gitignore` blocks `KEEP_PRIVATE_*`, `*_real.csv`, `pilot_data/` |
| Owner mistakes a self-assessment for a certification | Self-assessment statement on every page and in the PDF footer |
| Assessing someone else's systems | Acceptable-use statement; no scanning, no agents; export scripts are read-only (tested) |

## 5. Threat model of the app itself (STRIDE, short)

| Threat | Example | Mitigation |
|---|---|---|
| Spoofing | Fake "NeighborhoodShield" link collecting data | Official URL published by ChiEAC only; no logins to steal in v1 |
| Tampering | Malicious XLSX (formula injection, zip bomb) | Read values only (`openpyxl` data mode via pandas), size cap, row cap, strict schema; JSON/CSV exports prefix cells starting with `= + - @` |
| Repudiation | n/a (no accounts) | — |
| Information disclosure | Data left in logs | No logging of answers or rows; Streamlit usage stats disabled |
| Denial of service | Huge upload | 5 MB cap, row limit per template (Week 2) |
| Elevation of privilege | Code execution from YAML | `yaml.safe_load` only; no `eval` in the trigger DSL |

## 6. Scoring and Planner (spec for Weeks 4 and 5)

* Module score = `100 − 100 × Σ weight(fired) / Σ weight(all rules evaluable for that business)`, weights critical 10, high 6, medium 3, low 1. Only rules whose evidence was available count in the denominator, so a Quick Check is not penalized for missing uploads.
* Posture tier from the lowest module score and the count of critical findings (exact thresholds tuned on the four sample businesses in Week 4).
* Planner formula per brief Appendix D; scenarios in `rules/scenarios.yaml` are placeholders until Week 5 calibration (`docs/calibration_notes.md`).

## 7. Out of scope (v1)

Active scanning, agents, penetration testing, compliance claims, server-side storage, accounts, payments, mobile app, required LLM. Spanish strings later (structure ready now).

## 8. Extensions

Ten extensions beyond the brief are specified in `docs/extensions.md` (ADR 0006 to 0008). They add a public-lookup evidence type (`evidence: lookup`, table `email_domain_check`), text-only legal flags, an insurance readiness view, and published-survey benchmarks. None of them stores customer data.
