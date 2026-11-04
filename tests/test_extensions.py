"""Week 1 extensions: legal flags, insurance readiness, benchmarks, contacts, partners, free tools."""

import csv

import pytest

from engine.loader import load_benchmark_links, load_insurance_controls, load_legal_flags, load_rules
from engine.paths import REFERENCE_DIR
from engine.schemas import AnswerCondition, iter_conditions
from tests.helpers import questions, valid_codes

RULE_IDS = {r.id for r in load_rules()}


def _rows(name):
    with (REFERENCE_DIR / name).open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# ------------------------------------------------------------- legal flags
FLAGS = load_legal_flags()


@pytest.mark.parametrize("flag", FLAGS, ids=[f.id for f in FLAGS])
def test_legal_flag_triggers_are_valid(flag):
    qs = questions()
    for c in iter_conditions(flag.trigger):
        assert isinstance(c, AnswerCondition), "legal flags use questionnaire answers only"
        codes = c.in_ or c.contains_any or c.lacks_all
        assert set(codes) <= valid_codes(qs[c.q]), (flag.id, c.q, codes)


@pytest.mark.parametrize("flag", FLAGS, ids=[f.id for f in FLAGS])
def test_legal_flag_owner_text_has_no_dollar_amounts(flag):
    """Brief: compliance exposure is shown as text, never as a dollar figure."""
    assert "$" not in flag.notice_plain
    assert all("$" not in step for step in flag.what_to_do)


def test_not_legal_advice_string_exists():
    from engine.loader import load_strings

    assert "not legal advice" in load_strings()["extensions"]["not_legal_advice"]


# -------------------------------------------------------- insurance view
def test_insurance_controls_reference_real_rules():
    ins = load_insurance_controls()
    assert len(ins.controls) >= 10
    for c in ins.controls:
        assert set(c.gap_if_rules) <= RULE_IDS, c.id


def test_every_critical_rule_appears_in_an_insurance_control_or_is_explained():
    covered = {r for c in load_insurance_controls().controls for r in c.gap_if_rules}
    critical = {r.id for r in load_rules() if r.severity.value == "critical"}
    assert critical <= covered, sorted(critical - covered)


# ---------------------------------------------------------- benchmarks
def test_benchmark_links_point_to_real_metrics_and_questions():
    metrics = {r["metric_id"] for r in _rows("smb_benchmarks.csv")}
    qs = questions()
    for link in load_benchmark_links().links:
        assert link.question in qs
        assert set(link.metric_ids) <= metrics


def test_benchmarks_are_sourced_and_dated():
    for r in _rows("smb_benchmarks.csv"):
        assert r["source_url"].startswith("https://") and r["retrieved"] and r["publisher"], r["metric_id"]
        assert 0 <= float(r["value_pct"]) <= 100


# ------------------------------------------------- contacts, partners, tools
def test_incident_contacts_have_real_public_entries():
    rows = _rows("incident_contacts_illinois.csv")
    public = [r for r in rows if r["scope"] != "Business-specific"]
    assert len(public) >= 4 and all(r["source_url"] and r["verified_on"] for r in public)
    assert any(r["contact_id"] == "fbi_chicago" and r["phone"] == "(312) 421-6700" for r in rows)


def test_ssa_partner_list():
    rows = _rows("chicago_ssa_partners.csv")
    assert len(rows) >= 50 and all("not contacted" in r["note"] for r in rows)


def test_free_tools_map_to_real_rules():
    for r in _rows("free_tools.csv"):
        assert set(r["related_rules"].split(";")) <= RULE_IDS, r["tool_id"]
