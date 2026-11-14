"""NeighborhoodShield AI — Streamlit front end.

Renders the questionnaire from content/strings.yaml (Quick Check / Full
Assessment tiers with follow-up logic), accepts the optional upload templates,
and shows findings from every implemented rule (engine/evaluate.py).

Privacy: answers and uploads live only in st.session_state (this browser
session). Uploads are validated and redacted the moment they are read
(engine/ingest.py). Nothing is written to disk.

Run locally:  streamlit run app/streamlit_app.py
"""

from __future__ import annotations

import secrets
import sys
from collections import Counter
from datetime import date
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.evaluate import Assessment, evaluate  # noqa: E402
from engine.ingest import ingest  # noqa: E402
from engine.loader import (  # noqa: E402
    load_benchmark_links,
    load_insurance_controls,
    load_legal_flags,
    load_rules,
    load_scenarios,
    load_strings,
)
from engine.paths import REFERENCE_DIR, SAMPLE_DIR  # noqa: E402
from engine.samples import load_profile, load_sample, sample_businesses  # noqa: E402
from engine.schemas import TEMPLATE_MODELS  # noqa: E402

S = load_strings()
st.set_page_config(page_title=S["app"]["name"], page_icon="🛡️", layout="centered")

SEV_ORDER = ["critical", "high", "medium", "low"]
SEV_COLORS = {"critical": "#B42318", "high": "#DC6803", "medium": "#CA8504", "low": "#3B7C0F"}
SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
TEMPLATE_TITLES = {
    "users_permissions": "Logins and permissions (users_permissions)",
    "firewall_rules": "Router and firewall rules (firewall_rules)",
    "patch_inventory": "Devices and updates (patch_inventory)",
    "endpoint_protection": "Antivirus, encryption, screen lock (endpoint_protection)",
    "backup_jobs": "Backups (backup_jobs)",
}

state = st.session_state
state.setdefault("answers", {})
state.setdefault("uploaded_tables", {})   # validated + redacted rows from the owner's files
state.setdefault("sample_tables", {})     # rows from a sample business
state.setdefault("salt", secrets.token_bytes(16))  # per-session: hashed IDs cannot be linked across sessions


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
    st.info("Preview: answer the questions (and optionally upload files), then open **Results**. This version "
            "checks logins and access; more areas are being added.")
    for key in ("privacy", "acceptable_use", "self_assessment"):
        st.markdown(f"**{key.replace('_', ' ').title()}.** {S['statements'][key]}")
    footer()


def load_sample_into_session() -> None:
    """Callback: fill answers and uploads from a sample business (runs before widgets render)."""
    name = state.get("sample_choice")
    biz = next((b for b in sample_businesses() if load_profile(b)["name"] == name), None)
    if biz is None:
        return
    a = load_sample(biz, salt=state["salt"])
    for key in [k for k in state.keys() if str(k).startswith("q_")]:
        del state[key]
    state["answers"] = dict(a.answers)
    for qid, val in a.answers.items():
        state[f"q_{qid}"] = val
    state["sample_tables"] = {k: v for k, v in a.tables.items() if k in TEMPLATE_MODELS}
    state["sample_as_of"] = a.as_of
    state["mode"] = "Full Assessment"


def clear_session() -> None:
    for key in [k for k in state.keys() if str(k).startswith(("q_", "up_"))]:
        del state[key]
    state["answers"], state["uploaded_tables"], state["sample_tables"] = {}, {}, {}
    state.pop("sample_as_of", None)


def render_uploads() -> None:
    st.subheader("Files (optional)")
    st.caption("Upload any of the templates to check every account and device instead of relying on memory. "
               "Files are read in memory, names are replaced with labels straight away, and nothing is saved.")
    for table, title in TEMPLATE_TITLES.items():
        f = st.file_uploader(title, type=["csv", "xlsx"], key=f"up_{table}")
        if f is None:
            state["uploaded_tables"].pop(table, None)
            if table in state["sample_tables"]:
                st.caption(f"Using the sample business's {table} file ({len(state['sample_tables'][table])} rows).")
            continue
        res = ingest(table, f.getvalue(), f.name, state["salt"])
        for note in res.notes:
            st.caption(note)
        if res.ok:
            state["uploaded_tables"][table] = res.rows
            st.success(f"Read {len(res.rows)} rows. Names and addresses were replaced with labels.")
        else:
            state["uploaded_tables"].pop(table, None)
            st.error("This file was not used:\n\n" + "\n".join(f"- {e}" for e in res.errors))


def page_questionnaire() -> None:
    st.title("Questionnaire")
    with st.expander("Try it with a sample business (created for testing)"):
        st.selectbox("Sample business", [load_profile(b)["name"] for b in sample_businesses()], key="sample_choice")
        c1, c2 = st.columns(2)
        c1.button("Fill in the answers and files", on_click=load_sample_into_session)
        c2.button("Clear everything", on_click=clear_session)
    mode = st.segmented_control("Path", ["Quick Check", "Full Assessment"], default="Quick Check", key="mode")
    tiers = {"core"} if mode != "Full Assessment" else {"core", "extended"}
    st.caption(S["app"]["dont_know_note"])

    answers = state["answers"]
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
    if mode == "Full Assessment":
        render_uploads()
    if done:
        st.download_button("Download my answers (stays on your device)",
                           yaml.safe_dump(answers, sort_keys=False), file_name="neighborhoodshield_answers.yaml")
        st.info(f"When you are ready, open **Results** in the sidebar ({S['app']['finish']}).")
    footer()


def current_assessment() -> Assessment:
    tables = {**state["sample_tables"], **state["uploaded_tables"]}
    return Assessment(answers=dict(state["answers"]), tables=tables, as_of=state.get("sample_as_of", date.today()))


def render_finding(r) -> None:
    rule = r.rule
    sev = rule.severity.value
    with st.expander(f"{SEV_ICON[sev]} {S['results']['severity'][sev]} · {rule.title}"):
        st.write(rule.finding_plain)
        st.markdown("**What to do**")
        for fx in rule.fixes:
            st.markdown(f"- {fx.action}  \n  _{S['results']['cost_tiers'][fx.cost_tier.value]} · about "
                        f"{fx.effort} · {fx.who.value.replace('_', ' ')}_")
        st.caption("Why we flagged this: " + "; ".join(r.evidence))
        st.caption(f"CIS Controls v8.1: {', '.join(rule.cis_safeguards)} · rule {rule.id}")


def page_results() -> None:
    st.title("Results")
    a = current_assessment()
    if not a.answers and not a.tables:
        st.info("Answer some questions first (or try a sample business on the Questionnaire page).")
        footer()
        return
    if "sample_as_of" in state:
        st.caption(f"Sample business, checked as of {a.as_of.isoformat()}.")
    results = evaluate(a)
    fired = [r for r in results if r.fired]
    skipped = [r for r in results if r.status == "not_evaluated"]

    st.subheader("Logins and access")
    cols = st.columns(4)
    for col, sev in zip(cols, SEV_ORDER, strict=True):
        col.metric(f"{SEV_ICON[sev]} {S['results']['severity'][sev]}", sum(r.rule.severity.value == sev for r in fired))
    if not fired:
        st.success("No problems found in the checks we could run. Keep checking every three months.")
    for r in fired:
        render_finding(r)
    st.caption(f"{len(results) - len(skipped)} of {len(results)} checks could be run with what you provided.")
    if skipped:
        with st.expander(f"{len(skipped)} checks need more information"):
            st.caption("These need an answer you skipped or one of the optional files. They are not counted against you.")
            st.markdown("\n".join(f"- {r.rule.title}" for r in skipped))
    footer()


def page_catalog() -> None:
    st.title("Rule catalog")
    rules = load_rules()
    df = pd.DataFrame([{
        "id": r.id, "module": r.module.value, "title": r.title, "status": r.status, "severity": r.severity.value,
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
    st.caption("Sample businesses created for testing, running real, dated software (end-of-life dates from endoflife.date, "
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
    st.caption("Extensions in docs/extensions.md. Every figure has a source and a date.")
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


PAGES = {"Start": page_start, "Questionnaire": page_questionnaire, "Results": page_results,
         "Rule catalog": page_catalog, "Sample businesses": page_samples,
         "Real-world data": page_extensions}
choice = st.sidebar.radio("Go to", list(PAGES))
st.sidebar.caption(S["statements"]["privacy"])
PAGES[choice]()
