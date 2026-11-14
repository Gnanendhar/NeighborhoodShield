"""Rules engine: operators, three-state logic, reference lookups, and the hand-labelled oracle."""

from datetime import date

import pytest

from engine.evaluate import (
    Assessment,
    evaluate,
    evaluate_legal_flags,
    evaluate_trigger,
    is_end_of_life,
    kev_matches,
)
from engine.loader import load_rules
from engine.samples import load_expected, load_sample, sample_businesses
from engine.schemas import AnswerCondition, RowsCondition, Where, iter_conditions

AS_OF = date(2026, 11, 4)
BUSINESSES = sample_businesses()
IDS = [b.name for b in BUSINESSES]


def rows(table, where, match="any", **kw):
    return RowsCondition(table=table, where=[Where(**w) for w in where], match=match, **kw)


def ans(q, **kw):
    return AnswerCondition.model_validate({"kind": "answer", "q": q, **kw})


# ---------------------------------------------------------------- three-state logic
def test_missing_answer_and_missing_table_are_not_evaluable():
    a = Assessment(as_of=AS_OF)
    assert evaluate_trigger(ans("iam_mfa_email", **{"in": ["no"]}), a) is None
    assert evaluate_trigger(rows("users_permissions", [{"col": "status", "op": "eq", "value": "active"}]), a) is None


def test_any_of_is_clear_when_one_side_is_checked_and_clear():
    from engine.schemas import AnyOf

    t = AnyOf(any_of=[ans("iam_shared_logins", **{"in": ["yes"]}),
                      rows("users_permissions", [{"col": "account_type", "op": "eq", "value": "shared"}])])
    assert evaluate_trigger(t, Assessment(answers={"iam_shared_logins": "no"}, as_of=AS_OF)) is False
    assert evaluate_trigger(t, Assessment(as_of=AS_OF)) is None
    assert evaluate_trigger(t, Assessment(answers={"iam_shared_logins": "yes"}, as_of=AS_OF)) is True


def test_all_of_needs_every_part():
    from engine.schemas import AllOf

    t = AllOf(all_of=[ans("a", **{"in": ["yes"]}), ans("b", **{"in": ["yes"]})])
    assert evaluate_trigger(t, Assessment(answers={"a": "yes", "b": "yes"})) is True
    assert evaluate_trigger(t, Assessment(answers={"a": "yes", "b": "no"})) is False
    assert evaluate_trigger(t, Assessment(answers={"a": "yes"})) is None
    assert evaluate_trigger(t, Assessment(answers={"a": "no"})) is False  # one clear part is enough


def test_multiselect_answers():
    a = Assessment(answers={"bp_sensitive_data": ["card_numbers", "health_info"]})
    assert evaluate_trigger(ans("bp_sensitive_data", contains_any=["health_info"]), a) is True
    assert evaluate_trigger(ans("bp_sensitive_data", lacks_all=["health_info"]), a) is False
    assert evaluate_trigger(ans("bp_sensitive_data", lacks_all=["ssn_tax_ids"]), a) is True


# ---------------------------------------------------------------- row operators
USERS = [
    {"user_id": "user-1", "status": "active", "last_login_date": date(2026, 1, 1), "is_admin": "Y", "n": 3},
    {"user_id": "user-2", "status": "active", "last_login_date": date(2026, 11, 1), "is_admin": "N", "n": 0},
    {"user_id": "user-3", "status": "disabled", "last_login_date": None, "is_admin": "N", "n": None},
]


@pytest.mark.parametrize("where, expected", [
    ({"col": "status", "op": "eq", "value": "active"}, {"user-1", "user-2"}),
    ({"col": "status", "op": "ne", "value": "active"}, {"user-3"}),
    ({"col": "is_admin", "op": "in", "value": ["Y"]}, {"user-1"}),
    ({"col": "is_admin", "op": "not_in", "value": ["Y"]}, {"user-2", "user-3"}),
    ({"col": "n", "op": "gt", "value": 0}, {"user-1"}),
    ({"col": "n", "op": "lte", "value": 0}, {"user-2"}),
    ({"col": "last_login_date", "op": "older_than_days", "value": 90}, {"user-1"}),
    ({"col": "last_login_date", "op": "newer_than_days", "value": 30}, {"user-2"}),
    ({"col": "last_login_date", "op": "is_empty"}, {"user-3"}),
    ({"col": "last_login_date", "op": "not_empty"}, {"user-1", "user-2"}),
    ({"col": "user_id", "op": "contains_any", "value": ["-3"]}, {"user-3"}),
])
def test_row_operators(where, expected):
    a = Assessment(tables={"users_permissions": USERS}, as_of=AS_OF)
    for u in USERS:
        single = Assessment(tables={"users_permissions": [u]}, as_of=AS_OF)
        hit = evaluate_trigger(rows("users_permissions", [where]), single)
        assert hit == (u["user_id"] in expected), (where, u["user_id"])
    assert evaluate_trigger(rows("users_permissions", [where]), a) is bool(expected)


def test_match_none_and_ratio():
    a = Assessment(tables={"users_permissions": USERS}, as_of=AS_OF)
    admin = [{"col": "is_admin", "op": "eq", "value": "Y"}]
    assert evaluate_trigger(rows("users_permissions", admin, match="none"), a) is False
    assert evaluate_trigger(rows("users_permissions", [{"col": "n", "op": "gt", "value": 9}], match="none"), a) is True
    assert evaluate_trigger(rows("users_permissions", admin, match="ratio", min_ratio=0.3), a) is True
    assert evaluate_trigger(rows("users_permissions", admin, match="ratio", min_ratio=0.5), a) is False
    empty = Assessment(tables={"users_permissions": []}, as_of=AS_OF)
    assert evaluate_trigger(rows("users_permissions", admin, match="ratio", min_ratio=0.5), empty) is False


def test_every_operator_used_by_the_catalog_is_implemented():
    """An operator added to the schema but not the engine would raise during evaluation."""
    used = {w.op for r in load_rules() for c in iter_conditions(r.trigger) if isinstance(c, RowsCondition)
            for w in c.where}
    from engine.evaluate import _row_matches

    for op in used:
        _row_matches(Where(col="x", op=op, value=[] if op in ("in", "not_in", "contains_any") else 1),
                     {"x": None, "os_name": None}, AS_OF)


def test_evidence_lists_redacted_labels_only():
    a = Assessment(tables={"users_permissions": USERS}, as_of=AS_OF)
    ev: list[str] = []
    evaluate_trigger(rows("users_permissions", [{"col": "status", "op": "eq", "value": "active"}]), a, ev)
    assert ev == ["Your file: 2 of 3 logins: user-1, user-2"]


def test_answer_evidence_uses_the_owners_wording():
    ev: list[str] = []
    evaluate_trigger(ans("iam_mfa_email", **{"in": ["no"]}), Assessment(answers={"iam_mfa_email": "no"}), ev)
    assert len(ev) == 1 and ev[0].startswith('You answered "') and ev[0].endswith(": No")
    assert "iam_mfa_email" not in ev[0]


# ---------------------------------------------------------------- reference lookups
@pytest.mark.parametrize("os_name, version, expected", [
    ("Windows", "10 22H2", True),          # ended 2025-10-14
    ("Windows", "11 24H2 (W)", True),      # ended 2026-10-13, owner thinks it is current
    ("Windows", "11 25H2 (W)", False),
    ("windows", "11 23h2 (w)", True),      # case does not matter
    ("iPadOS", "18", False),
    ("TP-Link firmware", "v14", False),    # not in the snapshot: never guessed
    ("Windows", "11 Home 24H2", False),    # wording variant: not normalized yet
    (None, "10 22H2", False),
])
def test_end_of_life_lookup(os_name, version, expected):
    assert is_end_of_life(os_name, version, AS_OF) is expected


def test_end_of_life_depends_on_assessment_date():
    assert is_end_of_life("Windows", "11 24H2 (W)", date(2026, 10, 12)) is False
    assert is_end_of_life("Windows", "11 24H2 (W)", date(2026, 10, 13)) is True


@pytest.mark.parametrize("software, hit", [
    ("ConnectWise ScreenConnect Client", "screenconnect"),
    ("TP-Link TL-WR841N", "tl-wr841n"),
    ("WinRAR", "winrar"),
    ("Microsoft 365 Apps", None),          # vendor-only KEV product "Microsoft" is excluded
    ("Square Point of Sale", None),
    (None, None),
])
def test_kev_lookup(software, hit):
    got = kev_matches(software)
    assert (hit in got) if hit else not got, got


# ---------------------------------------------------------------- hand-labelled oracle
@pytest.mark.parametrize("biz", BUSINESSES, ids=IDS)
def test_whole_catalog_matches_hand_labelled_findings(biz):
    """The labels were written from the rule specs before the engine existed."""
    exp = load_expected(biz)
    a = load_sample(biz)
    fired = {r.rule.id for r in evaluate(a, load_rules()) if r.fired}
    assert fired == set(exp["expected_rule_ids"]), {
        "extra": sorted(fired - set(exp["expected_rule_ids"])),
        "missing": sorted(set(exp["expected_rule_ids"]) - fired)}


@pytest.mark.parametrize("biz", BUSINESSES, ids=IDS)
def test_legal_flags_match_hand_labelled(biz):
    flags = {f.id for f in evaluate_legal_flags(load_sample(biz))}
    assert flags == set(load_expected(biz)["expected_legal_flags"])


def test_results_are_sorted_most_severe_first():
    res = evaluate(load_sample(BUSINESSES[0]), load_rules())
    fired = [r for r in res if r.fired]
    weights = [{"critical": 4, "high": 3, "medium": 2, "low": 1}[r.rule.severity.value] for r in fired]
    assert weights == sorted(weights, reverse=True)
    assert [r.status for r in res] == sorted((r.status for r in res),
                                             key={"fired": 0, "clear": 1, "not_evaluated": 2}.get)
