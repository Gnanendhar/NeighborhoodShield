"""Sample businesses: valid answers, valid uploads, hand-labelled ground truth, reproducible."""

import filecmp
import re
from pathlib import Path

import pandas as pd
import pytest
import yaml

from engine.loader import load_legal_flags, load_rules
from engine.paths import SAMPLE_DIR
from engine.schemas import LOOKUP_MODELS, TEMPLATE_MODELS
from tests.helpers import questions, valid_codes

BUSINESSES = sorted(p for p in (SAMPLE_DIR / "businesses").iterdir() if p.is_dir())
IDS = [b.name for b in BUSINESSES]


def test_at_least_three_businesses_plus_control():
    assert len(BUSINESSES) >= 4
    assert any("control" in yaml.safe_load((b / "profile.yaml").read_text())["name"] for b in BUSINESSES)


@pytest.mark.parametrize("biz", BUSINESSES, ids=IDS)
def test_answers_are_valid_codes(biz):
    answers = yaml.safe_load((biz / "answers.yaml").read_text())
    qs = questions()
    for qid, ans in answers.items():
        assert qid in qs, f"{biz.name}: unknown question {qid}"
        allowed = valid_codes(qs[qid])
        if allowed is None:
            assert isinstance(ans, str), (biz.name, qid)
            continue
        vals = ans if isinstance(ans, list) else [ans]
        assert set(vals) <= allowed, (biz.name, qid, ans)


@pytest.mark.parametrize("biz", BUSINESSES, ids=IDS)
def test_every_core_question_answered_respecting_show_if(biz):
    answers = yaml.safe_load((biz / "answers.yaml").read_text())
    for q in questions().values():
        if q["tier"] != "core" or q.get("optional"):
            continue
        cond = q.get("show_if")
        shown = cond is None or answers.get(cond["q"]) in cond["in"]
        assert (q["id"] in answers) == shown, (biz.name, q["id"])


@pytest.mark.parametrize("biz", BUSINESSES, ids=IDS)
def test_uploads_validate_against_templates(biz):
    for f in (biz / "uploads").glob("*.csv"):
        df = pd.read_csv(f, dtype=str, keep_default_na=False)
        for row in df.to_dict("records"):
            TEMPLATE_MODELS[f.stem].model_validate(row)


EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
PHONE = re.compile(r"\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}")


@pytest.mark.parametrize("biz", BUSINESSES, ids=IDS)
def test_no_personal_data_in_uploads(biz):
    for f in (biz / "uploads").glob("*.csv"):
        text = f.read_text(encoding="utf-8")
        assert not EMAIL.search(text) and not PHONE.search(text), f.name


@pytest.mark.parametrize("biz", BUSINESSES, ids=IDS)
def test_expected_findings_reference_real_rules(biz):
    expected = yaml.safe_load((biz / "expected_findings.yaml").read_text())["expected_rule_ids"]
    assert set(expected) <= {r.id for r in load_rules()}


def test_samples_exercise_every_rule():
    fired = set()
    for b in BUSINESSES:
        fired |= set(yaml.safe_load((b / "expected_findings.yaml").read_text())["expected_rule_ids"])
    missing = {r.id for r in load_rules()} - fired
    assert not missing, f"rules never exercised by sample data: {sorted(missing)}"


def test_generator_is_deterministic(tmp_path: Path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("gen", SAMPLE_DIR / "generate.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    gen.main(tmp_path / "a")
    gen.main(tmp_path / "b")
    cmp = filecmp.dircmp(tmp_path / "a", tmp_path / "b")
    stack, diffs = [cmp], []
    while stack:
        c = stack.pop()
        diffs += c.diff_files + c.left_only + c.right_only
        stack += c.subdirs.values()
    assert not diffs, diffs


@pytest.mark.parametrize("biz", BUSINESSES, ids=IDS)
def test_lookups_validate_and_use_reserved_domains(biz):
    """Sample domains end in .example (RFC 2606) so no real business is ever looked up."""
    for f in (biz / "lookups").glob("*.csv"):
        df = pd.read_csv(f, dtype=str, keep_default_na=False)
        for row in df.to_dict("records"):
            LOOKUP_MODELS[f.stem].model_validate(row)
            assert row["domain"].endswith(".example")


@pytest.mark.parametrize("biz", BUSINESSES, ids=IDS)
def test_expected_legal_flags_exist(biz):
    exp = yaml.safe_load((biz / "expected_findings.yaml").read_text())["expected_legal_flags"]
    assert set(exp) <= {f.id for f in load_legal_flags()}
