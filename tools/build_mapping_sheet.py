"""Build docs/mapping/CIS_IG1_mapping.xlsx from the YAML rule catalog.

The YAML in rules/ is the single source of truth; this workbook is a readable,
reviewable view of it for Gate 1 (and for non-developers). Re-run after any
rule change:  python tools/build_mapping_sheet.py
"""

from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path

import yaml
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.loader import (  # noqa: E402
    load_insurance_controls,
    load_legal_flags,
    load_rules,
    load_scenarios,
    load_sources,
    load_strings,
)
from engine.schemas import AllOf, AnswerCondition, AnyOf, RowsCondition  # noqa: E402

OUT = ROOT / "docs" / "mapping" / "CIS_IG1_mapping.xlsx"
FONT = "Arial"
HEAD_FILL = PatternFill("solid", start_color="1F3A5F")
HEAD_FONT = Font(name=FONT, bold=True, color="FFFFFF", size=10)
BODY = Font(name=FONT, size=10)
BOLD = Font(name=FONT, size=10, bold=True)
TITLE = Font(name=FONT, size=14, bold=True)
THIN = Side(style="thin", color="D0D7DE")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
SEV_FILL = {
    "critical": PatternFill("solid", start_color="F8D7DA"),
    "high": PatternFill("solid", start_color="FCE5CD"),
    "medium": PatternFill("solid", start_color="FFF2CC"),
    "low": PatternFill("solid", start_color="E2F0D9"),
}
COST_ORDER = ["free", "low", "moderate", "contractor"]


def trigger_text(t, depth: int = 0) -> str:
    if isinstance(t, AnyOf):
        return "ANY OF (" + " | ".join(trigger_text(c, depth + 1) for c in t.any_of) + ")"
    if isinstance(t, AllOf):
        return "ALL OF (" + " & ".join(trigger_text(c, depth + 1) for c in t.all_of) + ")"
    if isinstance(t, AnswerCondition):
        if t.in_ is not None:
            return f"answer {t.q} in {t.in_}"
        if t.contains_any is not None:
            return f"answer {t.q} includes any {t.contains_any}"
        return f"answer {t.q} includes none of {t.lacks_all}"
    if isinstance(t, RowsCondition):
        w = " and ".join(f"{x.col} {x.op}{'' if x.value is None else ' ' + str(x.value)}" for x in t.where)
        if t.match == "none":
            return f"{t.table}: NO row where {w}"
        if t.match == "ratio":
            return f"{t.table}: >= {t.min_ratio:.0%} of rows where {w}"
        return f"{t.table}: any row where {w}"
    return str(t)


def header(ws, row: int, cols: list[str], widths: list[int]) -> None:
    for i, (c, w) in enumerate(zip(cols, widths, strict=True), start=1):
        cell = ws.cell(row=row, column=i, value=c)
        cell.font, cell.fill, cell.border = HEAD_FONT, HEAD_FILL, BORDER
        cell.alignment = Alignment(wrap_text=True, vertical="center")
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.freeze_panes = ws.cell(row=row + 1, column=3)
    ws.auto_filter.ref = f"A{row}:{get_column_letter(len(cols))}{row}"


def body(cell) -> None:
    cell.font, cell.border = BODY, BORDER
    cell.alignment = Alignment(wrap_text=True, vertical="top")


def main() -> None:
    rules = load_rules()
    scenarios = load_scenarios()
    sources = load_sources()
    strings = load_strings()
    ig1 = list(csv.DictReader((ROOT / "data/reference/cis_v81_ig1_safeguards.csv").open(encoding="utf-8")))
    ig1_title = {r["safeguard_id"]: r["safeguard_title"] for r in ig1}

    fires_in: dict[str, list[str]] = {}
    for f in sorted((ROOT / "sample_data/businesses").glob("*/expected_findings.yaml")):
        for rid in yaml.safe_load(f.read_text())["expected_rule_ids"]:
            fires_in.setdefault(rid, []).append(f.parent.name)

    wb = Workbook()

    # ---------------------------------------------------------------- README
    ws = wb.active
    ws.title = "README"
    lines = [
        ("NeighborhoodShield AI — CIS Controls v8.1 IG1 rule mapping (Week 1 specification)", TITLE),
        ("Generated from rules/*.yaml by tools/build_mapping_sheet.py. Edit the YAML, not this file.", BODY),
        ("", BODY),
        ("Tabs", BOLD),
        ("Rules — one row per rule: safeguard, NIST CSF 2.0, MITRE ATT&CK, trigger, severity, scenario, finding text, fixes.", BODY),
        ("IG1_Coverage — all 56 IG1 safeguards with a live count of rules citing each one, and the reason for any gap.", BODY),
        ("Summary — rule counts by module and severity (formulas over the Rules tab).", BODY),
        ("Scenarios — disruption scenarios used by the Business Survival Security Planner (starting values, Week 5 calibration).", BODY),
        ("Questionnaire — every question, its tier (core = Quick Check), and the rules it feeds.", BODY),
        ("Sources — citation registry used by the rules.", BODY),
        ("Legal_Flags, Insurance_Readiness, Benchmarks — Week 1 extensions (docs/extensions.md).", BODY),
        ("Rules NET-013/014/015 cite CIS 9.5 (IG2) on purpose; declared in data/reference/cis_v81_beyond_ig1_used.csv.", BODY),
        ("", BODY),
        ("Conventions", BOLD),
        ("Safeguard cells are written ;5.3;6.2; (leading/trailing semicolons) so COUNTIF never confuses 1.1 with 11.1 or 17.1.", BODY),
        ("NIST CSF 2.0 subcategories are the author's mapping; confirm with the CIS Controls Navigator before external publication.", BODY),
        ("Status 'spec' = specified in Week 1; becomes 'implemented' when the rule has passing fire / no-fire tests (Weeks 2-4).", BODY),
        ("'Fires in sample' = hand-labelled ground truth in sample_data/businesses/*/expected_findings.yaml.", BODY),
        ("Severity colours: red = critical, orange = high, yellow = medium, green = low.", BODY),
        ("", BODY),
        ("Prepared by Gyanendhar Reddy Reddymalla for ChiEAC. Self-assessment logic only; not an audit or certification.", BODY),
    ]
    for i, (text, font) in enumerate(lines, start=1):
        c = ws.cell(row=i, column=1, value=text)
        c.font = font
    ws.column_dimensions["A"].width = 120

    # ----------------------------------------------------------------- Rules
    ws = wb.create_sheet("Rules")
    cols = ["Rule ID", "Module", "Title", "Evidence", "CIS v8.1 IG1 safeguards", "Safeguard titles",
            "NIST CSF 2.0", "MITRE ATT&CK", "Trigger (declarative)", "Severity", "Severity weight",
            "Disruption scenario", "Finding (owner, plain language)", "Finding (contractor, technical)",
            "Fix options (cost tier / effort / who)", "Cheapest fix tier", "Fastest fix (minutes)",
            "Sources", "Status", "Fires in sample business"]
    widths = [9, 10, 30, 13, 14, 38, 16, 18, 55, 9, 9, 22, 55, 55, 60, 11, 10, 22, 9, 30]
    header(ws, 1, cols, widths)
    dv = DataValidation(type="list", formula1='"critical,high,medium,low"', allow_blank=False)
    ws.add_data_validation(dv)
    for r_i, r in enumerate(rules, start=2):
        cheapest = min((f.cost_tier.value for f in r.fixes), key=COST_ORDER.index)
        vals = [
            r.id, r.module.value, r.title, r.evidence,
            ";" + ";".join(r.cis_safeguards) + ";",
            "\n".join(f"{s} {ig1_title.get(s, '(not IG1)')}" for s in r.cis_safeguards),
            ", ".join(r.nist_csf), ", ".join(r.attack), trigger_text(r.trigger), r.severity.value,
            f'=IF(J{r_i}="critical",10,IF(J{r_i}="high",6,IF(J{r_i}="medium",3,1)))',
            r.scenario, r.finding_plain, r.finding_technical,
            "\n".join(f"• {f.action} [{f.cost_tier.value} / {f.effort} / {f.who.value}]" for f in r.fixes),
            cheapest, min(f.effort_minutes for f in r.fixes), ", ".join(r.sources), r.status,
            ", ".join(fires_in.get(r.id, [])) or "(unit tests only)",
        ]
        for c_i, v in enumerate(vals, start=1):
            cell = ws.cell(row=r_i, column=c_i, value=v)
            body(cell)
        ws.cell(row=r_i, column=10).fill = SEV_FILL[r.severity.value]
        dv.add(ws.cell(row=r_i, column=10))
    last_rule_row = len(rules) + 1

    # --------------------------------------------------------------- Summary
    ws = wb.create_sheet("Summary")
    ws["A1"] = "Rule counts by module and severity (live formulas over the Rules tab)"
    ws["A1"].font = TITLE
    sevs = ["critical", "high", "medium", "low"]
    mods = ["identity", "network", "patching", "endpoint", "recovery"]
    hdr = ["Module"] + sevs + ["Total", "Questionnaire-capable", "Upload-only", "Public lookup"]
    for i, h in enumerate(hdr, start=1):
        c = ws.cell(row=3, column=i, value=h)
        c.font, c.fill, c.border = HEAD_FONT, HEAD_FILL, BORDER
        ws.column_dimensions[get_column_letter(i)].width = 20 if i == 1 else 14
    rng = f"$2:${last_rule_row}"
    for m_i, m in enumerate(mods, start=4):
        ws.cell(row=m_i, column=1, value=m).font = BODY
        for s_i, s in enumerate(sevs, start=2):
            ws.cell(row=m_i, column=s_i,
                    value=f'=COUNTIFS(Rules!$B$2:$B${last_rule_row},$A{m_i},Rules!$J$2:$J${last_rule_row},"{s}")').font = BODY
        ws.cell(row=m_i, column=6, value=f"=SUM(B{m_i}:E{m_i})").font = BOLD
        ws.cell(row=m_i, column=7, value=f'=COUNTIFS(Rules!$B$2:$B${last_rule_row},$A{m_i},Rules!$D$2:$D${last_rule_row},"questionnaire")+COUNTIFS(Rules!$B$2:$B${last_rule_row},$A{m_i},Rules!$D$2:$D${last_rule_row},"both")').font = BODY
        ws.cell(row=m_i, column=8, value=f'=COUNTIFS(Rules!$B$2:$B${last_rule_row},$A{m_i},Rules!$D$2:$D${last_rule_row},"upload")').font = BODY
        ws.cell(row=m_i, column=9, value=f'=COUNTIFS(Rules!$B$2:$B${last_rule_row},$A{m_i},Rules!$D$2:$D${last_rule_row},"lookup")').font = BODY
    tot = 4 + len(mods)
    ws.cell(row=tot, column=1, value="Total").font = BOLD
    for col in range(2, 10):
        L = get_column_letter(col)
        ws.cell(row=tot, column=col, value=f"=SUM({L}4:{L}{tot - 1})").font = BOLD
    ws.cell(row=tot + 2, column=1, value="IG1 safeguards covered").font = BOLD
    ws.cell(row=tot + 2, column=2, value='=COUNTIF(IG1_Coverage!$F$2:$F$57,">0")').font = BOLD
    ws.cell(row=tot + 2, column=3, value="of").font = BODY
    ws.cell(row=tot + 2, column=4, value="=COUNTA(IG1_Coverage!$A$2:$A$57)").font = BOLD
    ws.cell(row=tot + 2, column=5, value='=B{0}/D{0}'.format(tot + 2)).number_format = "0.0%"
    ws.cell(row=tot + 3, column=1, value="Brief target: 40 to 60 rules. Week 1 extension adds 4 (IAM-016, NET-013..015), see ADR 0006.").font = BODY
    _ = rng

    # ---------------------------------------------------------- IG1 coverage
    ws = wb.create_sheet("IG1_Coverage")
    gap_reason = {
        "3.1": "Data management process: governance document, not observable by a 10-minute self-assessment. Candidate for v2 'policy pack'.",
        "3.2": "Data inventory: partly prompted by bp_sensitive_data; no rule in v1.",
        "3.3": "Data access control lists: needs file-share permission export; out of v1 scope.",
        "3.4": "Data retention: policy item; candidate for v2.",
        "4.6": "Secure management of assets (e.g. HTTPS/SSH admin): partly covered by NET-008; dedicated rule deferred.",
        "7.1": "Vulnerability management process: the 30-day plan itself acts as the owner's process; no separate rule.",
        "8.1": "Audit log process: rarely feasible for 1-25 staff without IT; v2 could check M365/Workspace sign-in alerts.",
        "8.2": "Collect audit logs: see 8.1.",
        "8.3": "Audit log storage: see 8.1.",
        "10.3": "Autorun/autoplay: owners cannot answer; will be read by Export-NSLocalDevice.ps1 in a later version (registry NoDriveTypeAutoRun).",
        "14.3": "Authentication training: behaviour covered technically by IAM-002/011; training topic folded into IAM-012 fix.",
        "14.4": "Data handling training: folded into IAM-012 staff huddle.",
        "14.5": "Unintentional data exposure training: folded into IAM-012.",
        "14.7": "Reporting missing updates training: folded into IAM-012.",
        "14.8": "Insecure networks training: folded into IAM-012.",
    }
    cols = ["Safeguard", "Control", "Control name", "Safeguard title", "Lookup key", "Rules citing (live)", "Rule IDs", "Coverage note"]
    header(ws, 1, cols, [10, 8, 34, 60, 10, 12, 30, 80])
    for i, r in enumerate(ig1, start=2):
        sid = r["safeguard_id"]
        ids = [x.id for x in rules if sid in x.cis_safeguards]
        vals = [sid, int(r["control_number"]), r["control_name"], r["safeguard_title"], f";{sid};",
                f'=COUNTIF(Rules!$E$2:$E${last_rule_row},"*"&E{i}&"*")', ", ".join(ids),
                "Covered" if ids else gap_reason.get(sid, "Not covered in v1")]
        for c_i, v in enumerate(vals, start=1):
            body(ws.cell(row=i, column=c_i, value=v))
        if not ids:
            for c_i in range(1, 9):
                ws.cell(row=i, column=c_i).fill = PatternFill("solid", start_color="F2F2F2")

    # ------------------------------------------------------------- Scenarios
    ws = wb.create_sheet("Scenarios")
    cols = ["Key", "Name", "Plain description", "Downtime low (days)", "Downtime high (days)",
            "Recovery cost (USD)", "Multiplier?", "Extra days low", "Extra days high", "Systems affected",
            "ATT&CK", "Rules mapped (live)", "Calibration", "Source notes"]
    header(ws, 1, cols, [26, 28, 50, 10, 10, 11, 10, 9, 9, 40, 26, 10, 12, 80])
    for i, s in enumerate(scenarios.values(), start=2):
        vals = [s.key, s.name, s.description_plain, s.downtime_days_low, s.downtime_days_high, s.recovery_cost_usd,
                "yes" if s.is_multiplier else "no", s.extra_days_low, s.extra_days_high, ", ".join(s.systems_affected),
                ", ".join(s.attack), f"=COUNTIF(Rules!$L$2:$L${last_rule_row},A{i})", s.calibration_status,
                "\n".join(s.source_notes)]
        for c_i, v in enumerate(vals, start=1):
            cell = ws.cell(row=i, column=c_i, value=v)
            body(cell)
            if c_i in (4, 5, 6, 8, 9):
                cell.font = Font(name=FONT, size=10, color="0000FF")  # inputs to calibrate
        ws.cell(row=i, column=6).number_format = "$#,##0"
    note_row = len(scenarios) + 3
    ws.cell(row=note_row, column=1, value="Blue values are placeholders from brief Appendix D; calibrate in Week 5 and record the source in rules/scenarios.yaml.").font = BODY

    # --------------------------------------------------------- Questionnaire
    ws = wb.create_sheet("Questionnaire")
    cols = ["Question ID", "Section", "Tier", "Type", "Shown if", "Question text", "Rules using it"]
    header(ws, 1, cols, [26, 11, 10, 8, 30, 80, 30])
    uses: dict[str, list[str]] = {}
    for r in rules:
        stack = [r.trigger]
        while stack:
            t = stack.pop()
            if isinstance(t, AnyOf):
                stack.extend(t.any_of)
            elif isinstance(t, AllOf):
                stack.extend(t.all_of)
            elif isinstance(t, AnswerCondition):
                uses.setdefault(t.q, []).append(r.id)
    for i, q in enumerate(strings["questions"], start=2):
        si = q.get("show_if")
        vals = [q["id"], q["section"], q["tier"], q["type"], f"{si['q']} in {si['in']}" if si else "",
                q["text"], ", ".join(sorted(set(uses.get(q["id"], [])))) or ("(Planner input)" if q["section"] == "profile" else "")]
        for c_i, v in enumerate(vals, start=1):
            body(ws.cell(row=i, column=c_i, value=v))

    # --------------------------------------------------------------- Sources
    ws = wb.create_sheet("Sources")
    cols = ["Key", "Title", "Publisher", "URL", "Accessed", "Cited by (rules)"]
    header(ws, 1, cols, [22, 60, 26, 70, 11, 12])
    for i, (k, s) in enumerate(sources.items(), start=2):
        vals = [k, s["title"], s["publisher"], s["url"], s["accessed"],
                f'=COUNTIF(Rules!$R$2:$R${last_rule_row},"*"&A{i}&"*")']
        for c_i, v in enumerate(vals, start=1):
            body(ws.cell(row=i, column=c_i, value=v))
        ws.cell(row=i, column=4).hyperlink = s["url"]

    # ------------------------------------------------- Week 1 extensions
    ws = wb.create_sheet("Legal_Flags")
    header(ws, 1, ["Flag", "Title", "Jurisdiction", "Fires when", "Owner notice (text only)", "What to do", "Citation", "Verified"],
           [9, 30, 16, 45, 60, 60, 70, 11])
    for i, f in enumerate(load_legal_flags(), start=2):
        vals = [f.id, f.title, f.jurisdiction, trigger_text(f.trigger), f.notice_plain,
                "\n".join(f"• {x}" for x in f.what_to_do), f.citation, f.verified_on.isoformat()]
        for c_i, v in enumerate(vals, start=1):
            body(ws.cell(row=i, column=c_i, value=v))

    ws = wb.create_sheet("Insurance_Readiness")
    ins = load_insurance_controls()
    header(ws, 1, ["Control", "Name", "Typical application question", "Gap if any of these rules fire", "Rules (live count)", "Why insurers ask"],
           [9, 34, 60, 30, 10, 60])
    for i, c in enumerate(ins.controls, start=2):
        vals = [c.id, c.control, c.typical_application_question, ", ".join(c.gap_if_rules),
                f'=SUMPRODUCT(--ISNUMBER(MATCH(TRIM(MID(SUBSTITUTE(D{i},",",REPT(" ",100)),(ROW($A$1:$A$6)-1)*100+1,100)),Rules!$A$2:$A${last_rule_row},0)))',
                c.why_insurers_ask]
        for c_i, v in enumerate(vals, start=1):
            body(ws.cell(row=i, column=c_i, value=v))
    ws.cell(row=len(ins.controls) + 3, column=1, value=ins.caveat).font = BODY

    ws = wb.create_sheet("Benchmarks")
    bm = list(csv.DictReader((ROOT / "data/reference/smb_benchmarks.csv").open(encoding="utf-8")))
    cols = ["metric_id", "metric", "value_pct", "population", "sample_size", "fieldwork", "publisher", "source_url", "caveat"]
    header(ws, 1, cols, [22, 60, 10, 30, 12, 22, 30, 60, 50])
    for i, r in enumerate(bm, start=2):
        for c_i, col in enumerate(cols, start=1):
            v = float(r[col]) / 100 if col == "value_pct" else r[col]
            cell = ws.cell(row=i, column=c_i, value=v)
            body(cell)
            if col == "value_pct":
                cell.number_format = "0.0%"

    OUT.parent.mkdir(parents=True, exist_ok=True)
    wb.save(OUT)
    sev = Counter(r.severity.value for r in rules)
    print(f"wrote {OUT.relative_to(ROOT)}: {len(rules)} rules {dict(sev)}")


if __name__ == "__main__":
    main()
