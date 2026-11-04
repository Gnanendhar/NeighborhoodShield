"""NeighborhoodShield AI — Streamlit front end.

Week 1 build: a working *design preview* for Gate 1. It renders the real
questionnaire from content/strings.yaml (with Quick Check / Full Assessment
tiers and follow-up logic) and shows the rule catalog and its CIS IG1 coverage.
Scoring, the Planner, and the PDF arrive in Weeks 2 to 6.

Privacy: answers live only in st.session_state (this browser session). Nothing
is written to disk.

Run locally:  streamlit run app/streamlit_app.py
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.loader import (  # noqa: E402
    load_benchmark_links,
    load_insurance_controls,
    load_legal_flags,
    load_rules,
    load_scenarios,
    load_strings,
)
from engine.paths import REFERENCE_DIR, SAMPLE_DIR  # noqa: E402

S = load_strings()
st.set_page_config(page_title=S["app"]["name"], page_icon="🛡️", layout="centered")

SEV_ORDER = ["critical", "high", "medium", "low"]
SEV_COLORS = {"critical": "#B42318", "high": "#DC6803", "medium": "#CA8504", "low": "#3B7C0F"}


def footer() -> None:
    st.divider()
    st.caption(S["statements"]["self_assessment"])
    st.caption(S["app"]["builder_credit"])


def is_shown(q: dict, answers: dict) -> bool:
    cond = q.get("show_if")
    return cond is None or answers.get(cond["q"]) in cond["in"]


def render_question(q: dict, key: str):
    help_text = q.get("help")
    if q["type"] == "ynd":
        labels = S["answers"]["ynd"]
        return st.radio(q["text"], list(labels), format_func=labels.get, key=key, index=None,
                        help=help_text, horizontal=True)
    if q["type"] == "text":
        return st.text_input(q["text"], key=key, help=help_text).strip() or None
    opts = q["options"]
    if q["type"] == "single":
        short = all(len(v) <= 14 for v in opts.values())
        return st.radio(q["text"], list(opts), format_func=opts.get, key=key, index=None, help=help_text,
                        horizontal=short)
    return st.multiselect(q["text"], list(opts), format_func=opts.get, key=key, help=help_text)


# ---------------------------------------------------------------- pages
def page_start() -> None:
    st.title(f"🛡️ {S['app']['name']}")
    st.subheader(S["app"]["tagline"])
    st.info("Week 1 design preview: the questionnaire works; results, the Planner, and the PDF are built in Weeks 2 to 6.")
    for key in ("privacy", "acceptable_use", "self_assessment"):
        st.markdown(f"**{key.replace('_', ' ').title()}.** {S['statements'][key]}")
    footer()


def page_questionnaire() -> None:
    st.title("Questionnaire")
    mode = st.segmented_control("Path", ["Quick Check", "Full Assessment"], default="Quick Check")
    tiers = {"core"} if mode == "Quick Check" else {"core", "extended"}
    st.caption(S["app"]["dont_know_note"])

    answers = st.session_state.setdefault("answers", {})
    questions = [q for q in S["questions"] if q["tier"] in tiers]
    for section in S["sections"]:
        sq = [q for q in questions if q["section"] == section["id"]]
        with st.expander(section["title"], expanded=section["id"] == "profile"):
            st.caption(section["intro"])
            for q in sq:
                if not is_shown(q, answers):
                    answers.pop(q["id"], None)
                    continue
                val = render_question(q, key=f"q_{q['id']}")
                if val not in (None, []):
                    answers[q["id"]] = val
                else:
                    answers.pop(q["id"], None)

    shown = [q for q in questions if is_shown(q, answers)]
    done = sum(1 for q in shown if q["id"] in answers)
    st.progress(done / len(shown), text=S["app"]["progress"].format(current=done, total=len(shown)))
    if done:
        st.download_button("Download my answers (stays on your device)",
                           yaml.safe_dump(answers, sort_keys=False), file_name="neighborhoodshield_answers.yaml")
    footer()


def page_catalog() -> None:
    st.title("Rule catalog (Week 1 specification)")
    rules = load_rules()
    df = pd.DataFrame([{
        "id": r.id, "module": r.module.value, "title": r.title, "severity": r.severity.value,
        "CIS v8.1 IG1": ", ".join(r.cis_safeguards), "evidence": r.evidence, "scenario": r.scenario,
    } for r in rules])
    c1, c2, c3 = st.columns(3)
    c1.metric("Rules", len(rules))
    ig1 = pd.read_csv(REFERENCE_DIR / "cis_v81_ig1_safeguards.csv", dtype=str)
    covered = {s for r in rules for s in r.cis_safeguards}
    c2.metric("IG1 safeguards covered", f"{len(covered & set(ig1.safeguard_id))} / {len(ig1)}")
    c3.metric("Disruption scenarios", len(load_scenarios()))

    counts = df.groupby(["module", "severity"]).size().reset_index(name="rules")
    fig = px.bar(counts, x="module", y="rules", color="severity", category_orders={"severity": SEV_ORDER},
                 color_discrete_map=SEV_COLORS, title="Rules by module and severity")
    fig.update_layout(legend_title_text="", margin=dict(t=50, b=10))
    st.plotly_chart(fig, use_container_width=True)
    st.dataframe(df, hide_index=True, use_container_width=True)
    footer()


def page_samples() -> None:
    st.title("Sample businesses")
    st.caption("Fictional businesses running real, dated software (end-of-life dates from endoflife.date, "
               "vulnerable products from the CISA KEV catalog). Expected findings are hand-labelled ground truth.")
    for biz in sorted(p for p in (SAMPLE_DIR / "businesses").iterdir() if p.is_dir()):
        prof = yaml.safe_load((biz / "profile.yaml").read_text(encoding="utf-8"))
        exp = yaml.safe_load((biz / "expected_findings.yaml").read_text(encoding="utf-8"))["expected_rule_ids"]
        with st.expander(f"{prof['name']} — {len(exp)} expected findings"):
            st.write(prof["story"])
            st.markdown("\n".join(f"- {w}" for w in prof["designed_weaknesses"]))
            by_mod = Counter(rid.split("-")[0] for rid in exp)
            st.caption("Expected by module: " + ", ".join(f"{k} {v}" for k, v in sorted(by_mod.items())))
    footer()


def page_extensions() -> None:
    st.title("Real-world data and extensions")
    st.caption("Week 1 specification of the extensions in docs/extensions.md. Every figure has a source and a date.")
    tabs = st.tabs(["How you compare", "Legal flags", "Insurance readiness", "Who to call", "Chicago partners"])
    with tabs[0]:
        st.caption(load_benchmark_links().principle)
        bm = pd.read_csv(REFERENCE_DIR / "smb_benchmarks.csv")
        st.dataframe(bm[["metric", "value_pct", "publisher", "fieldwork", "sample_size", "caveat"]],
                     hide_index=True, use_container_width=True)
    with tabs[1]:
        st.caption(S["extensions"]["not_legal_advice"])
        for f in load_legal_flags():
            with st.expander(f"{f.id} · {f.title} ({f.jurisdiction})"):
                st.write(f.notice_plain)
                st.markdown("\n".join(f"- {x}" for x in f.what_to_do))
                st.caption(f.citation.replace("$", "\\$"))  # stop Streamlit reading $ as math
    with tabs[2]:
        ins = load_insurance_controls()
        st.caption(ins.caveat)
        st.dataframe(pd.DataFrame([{"control": c.control, "insurer asks": c.typical_application_question,
                                    "gap if": ", ".join(c.gap_if_rules)} for c in ins.controls]),
                     hide_index=True, use_container_width=True)
    with tabs[3]:
        st.dataframe(pd.read_csv(REFERENCE_DIR / "incident_contacts_illinois.csv", dtype=str).fillna("")
                     [["organization", "purpose", "phone", "web_or_email"]], hide_index=True, use_container_width=True)
    with tabs[4]:
        ssa = pd.read_csv(REFERENCE_DIR / "chicago_ssa_partners.csv", dtype=str)
        st.caption(f"{len(ssa)} active Special Service Areas (City of Chicago list): workshop host prospects, not contacted.")
        st.dataframe(ssa[["ssa", "ssa_name", "service_provider"]], hide_index=True, use_container_width=True)
    footer()


PAGES = {"Start": page_start, "Questionnaire": page_questionnaire,
         "Rule catalog": page_catalog, "Sample businesses": page_samples,
         "Real-world data": page_extensions}
choice = st.sidebar.radio("Go to", list(PAGES))
st.sidebar.caption(S["statements"]["privacy"])
PAGES[choice]()
