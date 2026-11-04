"""The YAML rule catalog is the product specification. These tests keep it honest."""

import re
from collections import Counter

import pytest

from engine.loader import load_rules, load_scenarios, load_sources
from engine.schemas import (
    ALL_TABLE_MODELS,
    MODULE_PREFIX,
    AnswerCondition,
    RowsCondition,
    RuleSpec,
    iter_conditions,
    template_columns,
)
from tests.helpers import attack_ids, beyond_ig1_ids, ig1_ids, questions, valid_codes

RULES = load_rules()
IDS = [r.id for r in RULES]


def test_rule_count():
    """Brief: 40 to 60. Week 1 extension (ADR 0006) adds IAM-016 and NET-013..015; cap raised to 70."""
    assert 40 <= len(RULES) <= 70


def test_ids_unique_and_sequential_per_module():
    assert len(IDS) == len(set(IDS))
    for module, prefix in MODULE_PREFIX.items():
        nums = sorted(int(r.id[4:]) for r in RULES if r.module == module)
        assert nums == list(range(1, len(nums) + 1)), f"{prefix} ids have gaps: {nums}"


def test_every_module_answerable_from_questionnaire_alone():
    for module in MODULE_PREFIX:
        assert any(r.module == module and r.evidence in ("questionnaire", "both") for r in RULES), module


def test_every_severity_used():
    assert set(Counter(r.severity.value for r in RULES)) == {"critical", "high", "medium", "low"}


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_safeguards_are_ig1_or_declared_beyond(rule):
    """IG1 is the anchor. A rule may cite a higher-IG safeguard only if it is declared in
    data/reference/cis_v81_beyond_ig1_used.csv with a reason (e.g. 9.5 Implement DMARC)."""
    assert set(rule.cis_safeguards) <= ig1_ids() | beyond_ig1_ids(), f"{rule.id} cites an undeclared safeguard"


def test_most_rules_anchor_in_ig1():
    anchored = [r for r in RULES if set(r.cis_safeguards) & ig1_ids()]
    assert len(anchored) / len(RULES) >= 0.9


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_attack_ids_verified(rule):
    assert set(rule.attack) <= attack_ids(), f"{rule.id}: ATT&CK id not in verified snapshot"


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_scenario_and_sources_exist(rule):
    assert rule.scenario in load_scenarios()
    assert set(rule.sources) <= set(load_sources())


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_trigger_references_real_questions_and_columns(rule):
    qs = questions()
    for c in iter_conditions(rule.trigger):
        if isinstance(c, AnswerCondition):
            assert c.q in qs, f"{rule.id}: unknown question {c.q}"
            codes = c.in_ or c.contains_any or c.lacks_all
            allowed = valid_codes(qs[c.q])
            assert allowed is not None, f"{rule.id}: cannot test a free-text question with codes"
            assert set(codes) <= allowed, f"{rule.id}: invalid answer code for {c.q}: {codes}"
        else:
            assert isinstance(c, RowsCondition)
            cols = set(template_columns(c.table))
            for w in c.where:
                assert w.col in cols, f"{rule.id}: {c.table} has no column {w.col}"


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_row_values_are_allowed_by_template(rule):
    """A rule comparing against a value the template forbids could never fire."""
    for c in iter_conditions(rule.trigger):
        if not isinstance(c, RowsCondition):
            continue
        model = ALL_TABLE_MODELS[c.table]
        for w in c.where:
            if w.op not in ("eq", "in") or w.value is None:
                continue
            ann = model.model_fields[w.col].annotation
            allowed = getattr(ann, "__args__", None)
            enum_vals = getattr(ann, "__members__", None)
            vals = w.value if isinstance(w.value, list) else [w.value]
            if enum_vals:
                assert {str(v) for v in vals} <= {m.value for m in ann}, (rule.id, w.col, vals)
            elif allowed and all(isinstance(a, str) for a in allowed):
                assert set(vals) <= set(allowed), (rule.id, w.col, vals)


JARGON = re.compile(r"\b(MFA|RDP|SMB|VPN|EDR|SSID|VLAN|DNS|OS|CVE|KEV|IAM|BEC|RMM|WAN|LAN)\b")


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_owner_text_has_no_unexplained_jargon(rule):
    assert not JARGON.search(rule.finding_plain), f"{rule.id}: jargon in owner-facing finding"
    for f in rule.fixes:
        assert not JARGON.search(f.action) or "(" in f.action, f"{rule.id}: jargon in fix '{f.action}'"


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_owner_text_is_short(rule):
    assert len(rule.finding_plain.split()) <= 50, f"{rule.id}: owner finding over 50 words"


def test_brief_sample_rules_match_appendix_c():
    by = {r.id: r for r in RULES}
    assert by["IAM-004"].cis_safeguards == ["5.3"] and by["IAM-004"].severity.value == "high"
    assert by["NET-002"].severity.value == "critical" and {"4.4", "6.4"} <= set(by["NET-002"].cis_safeguards)
    assert by["BKP-003"].cis_safeguards == ["11.1"] and by["BKP-003"].scenario == "permanent_data_loss"


def test_malformed_rule_fails_loudly():
    with pytest.raises(ValueError):
        RuleSpec.model_validate({
            "id": "IAM-999", "module": "network", "title": "x", "evidence": "questionnaire",
            "trigger": {"kind": "answer", "q": "iam_mfa_email", "in": ["no"]}, "severity": "high",
            "cis_safeguards": ["6.3"], "scenario": "account_takeover_fraud", "finding_plain": "x",
            "finding_technical": "x", "sources": ["cis_ig1"],
            "fixes": [{"action": "x", "cost_tier": "free", "effort": "1 minute", "effort_minutes": 1, "who": "owner"}],
        })


def test_evidence_field_must_match_trigger():
    with pytest.raises(ValueError, match="evidence"):
        RuleSpec.model_validate({
            "id": "IAM-999", "module": "identity", "title": "x", "evidence": "upload",
            "trigger": {"kind": "answer", "q": "iam_mfa_email", "in": ["no"]}, "severity": "high",
            "cis_safeguards": ["6.3"], "scenario": "account_takeover_fraud", "finding_plain": "x",
            "finding_technical": "x", "sources": ["cis_ig1"],
            "fixes": [{"action": "x", "cost_tier": "free", "effort": "1 minute", "effort_minutes": 1, "who": "owner"}],
        })


def test_scenarios_cover_appendix_d():
    assert set(load_scenarios()) == {
        "ransomware_primary_system", "account_takeover_fraud", "permanent_data_loss", "pos_tampering_or_outage",
        "router_compromise", "stolen_or_lost_device", "malware_outbreak", "no_incident_plan",
    }
