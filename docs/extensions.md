# Extensions beyond the brief (Week 1 specification)

Ten additions that make NeighborhoodShield more useful to owners and easier for ChiEAC to sell. Each one stays inside the brief's guardrails: free tools only, no scanning of customer networks, no server-side storage of customer data, and no required AI model. Each is grounded in real, dated, public data stored in `data/reference/`.

| # | Extension | Week | Est. hours | Real data behind it | Status in repo |
|---|---|---|---|---|---|
| 1 | Email domain check (SPF / DMARC) | 3 | 4 | Mailbox-provider sender rules (Google, Yahoo, Microsoft, Apple); EasyDMARC 2026 adoption | Rules NET-013/014/015, lookup schema, sample lookups |
| 2 | Illinois & Chicago legal flags | 5 | 3 | 740 ILCS 14 (BIPA, amended Aug 2, 2024); 815 ILCS 530/10 (PIPA); PCI DSS v4.0.1; HIPAA scope; FTC Safeguards Rule | `rules/legal_flags.yaml` (6 flags), new question `bp_biometrics` |
| 3 | Cyber-insurance readiness view | 5 | 4 | Common underwriting controls; Nationwide 2024: 42% of small businesses carry cyber coverage | `rules/insurance_readiness.yaml` (12 controls) |
| 4 | Calendar reminders (.ics) | 6 | 2 | RFC 5545 standard; CIS 11.1 (quarterly restore test), 5.3, 6.2 | Spec below |
| 5 | Printable "bad day" card | 6 | 3 | FBI Chicago, IC3, CISA, Illinois AG contacts (verified 2026-11-04) | `data/reference/incident_contacts_illinois.csv` |
| 6 | Workshop mode (QR + phone layout) | 7 | 4 | 55 active Chicago Special Service Areas and their service providers | `data/reference/chicago_ssa_partners.csv` |
| 7 | Automatic monthly data refresh | 6 | 2 | endoflife.date, CISA KEV, Chicago licenses | `.github/workflows/refresh-reference-data.yml`, `tools/check_links.py` |
| 8 | A free tool for every fix | 6 | 3 | 13 free tools mapped to rules | `data/reference/free_tools.csv` |
| 9 | Leaked-password check (safe design) | 3 | 4 | Have I Been Pwned / Pwned Passwords k-anonymity model | Rule IAM-016, question `iam_breach_check` |
| 10 | "How you compare" (peer benchmarks) | 5 | 3 | 14 published, dated survey metrics (CRI, Nationwide, Guardz, EasyDMARC, Verizon DBIR) | `data/reference/smb_benchmarks.csv`, `rules/benchmarks.yaml` |
| | **Total** | | **32** | | |

**Time budget.** The brief plans about 75 hours. These extensions add about 32. They sit **above** the brief's scope-cut list: if any gate slips, extensions are cut first (order: 6, 10, 3, 8, 4, 2, 9, 5, 1, 7), before anything in the brief's own list. The core product (questionnaire, five modules, Planner, PDF) is never traded for an extension.

---

## 1. Email domain check

**What the owner sees.** An optional box: "What comes after the @ in your business email address?" If they type a domain, a button reads its *public* DNS records and reports in plain language whether criminals can send email pretending to be them.

**Why.** Business email compromise is one of the costliest categories in FBI IC3 data: over $3 billion in reported losses in 2025. Since 2024 Google and Yahoo, and since May 5, 2025 Microsoft, require SPF, DKIM and DMARC from bulk senders. EasyDMARC's 2026 report found only 22.9% of the top 1.8 million domains *enforce* DMARC, so small businesses are very likely worse.

**Design.**
- Reads only `TXT` (SPF, `_dmarc`), `MX`, and a few common DKIM selectors with `dnspython` (free). This is the same public information every receiving mail server reads; it is **not** a scan of the business's network, so it does not breach the brief's "no active scanning" rule.
- Result goes into the lookup table `email_domain_check` (schema `EmailDomainCheckRow`), which rules NET-013/014/015 evaluate. Nothing is stored after the session.
- Free webmail (gmail.com, yahoo.com, outlook.com) is detected and skipped with a short explanation.
- CIS v8.1 **9.5 Implement DMARC** is an IG2 safeguard. It is cited on purpose and declared in `data/reference/cis_v81_beyond_ig1_used.csv`; tests allow beyond-IG1 safeguards only when declared there.

**Acceptance.** Sample domains use the reserved `.example` TLD (RFC 2606), so tests never look up a real business. Unit tests mock DNS answers for missing, `p=none`, `p=quarantine`, `p=reject`, `+all`, and `-all`.

## 2. Illinois and Chicago legal flags

**What the owner sees.** Text-only notices with what to do next and a "not legal advice" line. Never a dollar estimate (brief Appendix D).

| Flag | Fires when | Key fact (source) |
|---|---|---|
| LEG-001 BIPA | Fingerprint or face scanning used, or unsure | Written policy and written (now also electronic) consent required before collection; private lawsuits; SB 2979 (Aug 2, 2024) made repeat scans of the same person one violation (740 ILCS 14; DWT summary) |
| LEG-002 PIPA | Card numbers, children's, health, or SSN/tax data kept | Notify residents "in the most expedient time possible and without unreasonable delay"; notify the Attorney General if more than 500 Illinois residents are affected (815 ILCS 530/10) |
| LEG-003 PCI DSS | Card data kept or card payments critical | Annual self-assessment through the payment processor (PCI DSS v4.0.1) |
| LEG-004 Childcare records | Childcare business or children's records | DCFS licensing record duties (Part numbers to confirm) plus PIPA |
| LEG-005 Health information | Health information kept | HIPAA applies only to covered entities; PIPA covers medical information for everyone |
| LEG-006 FTC Safeguards Rule | Professional services (tax, loans) | Written security program; FTC notice for breaches of 500 or more consumers (effective May 13, 2024) |

**Why it matters for Chicago.** Fingerprint time clocks are common in restaurants and salons, and BIPA is an Illinois-only risk no generic tool explains. New question: `bp_biometrics` (Full Assessment).

## 3. Cyber-insurance readiness view

Twelve controls commonly asked about on small-business cyber-insurance applications (MFA on email, remote access and admin accounts; endpoint protection; separate and tested backups; supported software; email spoofing protection; limited admin rights; training; incident plan; payment call-back and bank MFA; laptop encryption). Each control is **Ready** when none of its mapped rules fired, **Gap** otherwise, and **Unknown** if the needed answers were skipped. A test makes sure every critical rule appears in at least one control.

Sales angle: insurers, credit unions and CDFIs are on the brief's sponsored-assessment list; this view gives them a reason to sponsor. Caveat shown on screen: every insurer's form is different, and this does not predict approval or price.

## 4. Calendar reminders

One download, `neighborhoodshield_reminders.ics`, generated in memory with the standard library (no new dependency):
- the 30-day re-check (brief §3.5);
- "test one restore" every 3 months (CIS 11.1; BKP-003);
- "check who still has logins" every 3 months (CIS 5.3, 6.2; IAM-003/004);
- "update the router" every 6 months (CIS 12.1; NET-006).

Works with Google Calendar, Outlook and Apple Calendar. Nothing is stored and there are no accounts. This supports the recurring revenue tier: people return when reminded.

## 5. Printable "bad day" card

A one-page PDF (fpdf2) built from the owner's answers and `incident_contacts_illinois.csv`:
- **First hour:** unplug the affected computer from the network, but do not turn it off; call the bank fraud line if money moved; do not pay anyone.
- **Who to call:** owner-filled rows (bank, internet provider, register company, IT help, insurer) plus verified public contacts: FBI Chicago Field Office (312) 421-6700; IC3 at ic3.gov; CISA Central at 1-844-SAY-CISA; Illinois Attorney General Identity Theft Hotline at 1-866-999-5630.
- **Where the backup is,** and how to keep taking payments (for example a phone card reader).

It directly closes BKP-005 and BKP-006, and it is the workshop take-home.

## 6. Workshop mode

- A presenter screen shows a QR code (`segno`, free) linking to the Quick Check with `?mode=workshop`.
- Workshop mode is phone-first: one question per screen and large buttons, with no uploads.
- An optional room tally is kept **only in the presenter's own session**, from answers participants choose to show by scanning back a results QR. Nothing is written to a server.
- Partner prospect list: 55 active Chicago Special Service Areas and their service providers (chambers and business associations) from the City of Chicago list. These are prospects only: none have been contacted and no endorsement is implied.

## 7. Automatic monthly data refresh

`.github/workflows/refresh-reference-data.yml` runs on the 3rd of every month (and on demand). It re-downloads the snapshots, checks links, runs the tests, rebuilds the mapping sheet, and **opens a pull request** for a human to review. Nothing merges by itself. This keeps end-of-life and KEV data current after handoff to ChiEAC. `tools/check_links.py` lists any broken source links.

## 8. A free tool for every fix

`data/reference/free_tools.csv` maps 13 free tools to the rules they help fix: Microsoft Defender, BitLocker, FileVault, Microsoft/Google Authenticator, Bitwarden free, Google Password Checkup, Have I Been Pwned, Quad9, CISA Cyber Hygiene, CISA Secure Our World, Windows File History/OneDrive, and free DMARC checkers. Each fix in the plan shows "Free tool: …" with a link. These links could not be reached from the build environment, so each is marked for manual verification and `tools/check_links.py` verifies them from your machine.

## 9. Leaked-password check (safe by design)

The concern is real: asking owners to type passwords into a website teaches the wrong habit. So:

1. **The app never asks for a password.** IAM-016 asks only whether anyone has checked in the last year.
2. **The guided check** points to free checkers the owner already has: Google Password Checkup, Edge Password Monitor, Apple Passwords' compromised-password alerts, and Bitwarden's reports. It also points to Have I Been Pwned's free "notify me" alerts for each business email address.
3. **Optional in-browser check (stretch, Week 3):** a small Streamlit component hashes a password **inside the browser** (SHA-1 via Web Crypto) and sends only the first 5 hex characters to `api.pwnedpasswords.com/range/` directly from the browser (k-anonymity). The password and full hash never reach NeighborhoodShield's server. Server-side code has no input that could receive it, and a test asserts that. The screen still says: "You don't need to do this. Your password manager can."

## 10. "How you compare"

Peer comparison **without storing anyone's data** (brief §4):
- **Published surveys:** each relevant answer is shown next to a dated, sourced statistic from `smb_benchmarks.csv`. For example: "In a 2022 survey of 1,403 small business owners (Cyber Readiness Institute), 46% said they use recommended MFA." Where surveys disagree, both are shown with their populations: incident-response plans are 69% (Nationwide 2024) vs 34% (Guardz 2025).
- **Your own past:** the baseline file the owner keeps (brief §3.2) gives before-and-after progress.
- **Sample businesses:** "a restaurant like the fictional Taqueria Luna Azul usually…" for workshops.
- **Never** compared against other customers' stored answers.

A useful fact for the pitch from the same data: 81% of owners believe an attack would cost them under $5,000, while the average small-business cyber claim is $18,000–21,000 (Nationwide 2024).

---

## What changed in the repository (Week 1 extension)

- **Rules:** 58 → 62 (IAM-016, NET-013, NET-014, NET-015). The brief's 40-to-60 range is documented as exceeded on purpose (ADR 0006).
- **Questions:** 49 → 52 (`bp_biometrics`, `bp_email_domain` as free text, `iam_breach_check`). All three are Full Assessment only, so the Quick Check stays at 36.
- **Schemas:** a lookup-table type (`email_domain_check`), `LegalFlag`, `InsuranceControl`, and `BenchmarkLink`.
- **Reference data:** 6 new files (benchmarks, contacts, SSA partners, email requirements, free tools, beyond-IG1 safeguards).
- **Sample businesses:** domain lookups and expected legal flags, cross-checked with an independent evaluator.
- **App:** a new "Real-world data" page.
