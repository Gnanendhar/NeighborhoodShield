"""Scoring: module formula, skipped checks, posture tiers, and the sample-business ordering from ADR 0005."""

import pytest

from engine.evaluate import Assessment, RuleResult, evaluate
from engine.loader import load_rules
from engine.samples import load_sample, sample_businesses
from engine.schemas import Module
from engine.score import score, tier_for

RULES = {r.id: r for r in load_rules()}
SAMPLES = {b.name: b for b in sample_businesses()}


def rr(rule_id, status):
    return RuleResult(rule=RULES[rule_id], status=status)


def test_module_score_formula():
    # IAM-002 critical (10) fired, IAM-001 high (6) clear, IAM-014 low (1) clear -> 100 - 100*10/17 = 41
    card = score([rr("IAM-002", "fired"), rr("IAM-001", "clear"), rr("IAM-014", "clear")])
    m = card.modules[Module.identity]
    assert (m.score, m.fired, m.checked, m.critical) == (41, 1, 3, 1)


def test_skipped_checks_do_not_count_against_the_business():
    with_skip = score([rr("IAM-001", "clear"), rr("IAM-004", "not_evaluated")])
    assert with_skip.modules[Module.identity].score == 100
    nothing = score([rr("IAM-004", "not_evaluated")])
    assert nothing.modules[Module.identity].score is None


def test_no_tier_until_every_area_has_a_score():
    card = score(evaluate(Assessment(answers={"iam_mfa_email": "yes"})))
    assert card.modules[Module.identity].score == 100
    assert card.tier is None and not card.complete and "Not enough answers" in card.reason


@pytest.mark.parametrize("lowest, critical, tier", [
    (100, 2, "exposed"), (39, 0, "exposed"),
    (100, 1, "fragile"), (40, 0, "fragile"), (59, 0, "fragile"),
    (60, 0, "developing"), (79, 0, "developing"),
    (80, 0, "resilient"), (100, 0, "resilient"),
])
def test_tier_thresholds(lowest, critical, tier):
    assert tier_for(lowest, critical)[0] == tier


def _overall(name, uploads=True):
    return score(evaluate(load_sample(SAMPLES[name], with_uploads=uploads)))


@pytest.mark.parametrize("uploads", [True, False], ids=["full", "quick"])
def test_sample_ordering_matches_adr_0005(uploads):
    """Expected: pantry (Resilient) > taqueria > daycare ~ salon."""
    pantry = _overall("northside_community_pantry", uploads)
    taqueria = _overall("taqueria_luna_azul", uploads)
    daycare = _overall("little_sprouts_daycare", uploads)
    salon = _overall("fade_and_shine_salon", uploads)
    assert pantry.tier == "resilient"
    assert pantry.overall > taqueria.overall > max(daycare.overall, salon.overall)
    assert abs(daycare.overall - salon.overall) <= 10  # "about the same"
    for card in (taqueria, daycare, salon):
        assert card.tier == "exposed"  # each was built with several fix-now weaknesses


def test_every_sample_gets_a_complete_scorecard():
    for b in sample_businesses():
        card = score(evaluate(load_sample(b)))
        assert card.complete and card.tier and 0 <= card.overall <= 100
        assert set(card.modules) == set(Module)
