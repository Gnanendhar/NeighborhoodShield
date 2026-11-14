"""Module 1 (identity): every rule has a case that fires and a case that stays clear."""

from datetime import date

import pytest

from engine.evaluate import Assessment, evaluate, evaluate_rule, implemented_rules
from engine.loader import load_rules
from engine.samples import load_expected, load_sample, sample_businesses

AS_OF = date(2026, 11, 4)
RULES = {r.id: r for r in load_rules()}


def user(**kw):
    base = {"user_id": "user-a", "account_type": "staff", "is_admin": "N", "mfa_enabled": "Y", "status": "active",
            "created_date": date(2024, 1, 1), "last_login_date": date(2026, 11, 1), "role_or_department": "Register"}
    return base | kw


def A(answers=None, users=None):
    tables = {} if users is None else {"users_permissions": users}
    return Assessment(answers=answers or {}, tables=tables, as_of=AS_OF)


# rule id -> (assessment that fires, assessment that stays clear)
CASES = {
    "IAM-001": (A({"iam_shared_logins": "yes"}), A({"iam_shared_logins": "no"}, [user()])),
    "IAM-001/upload": (A(users=[user(account_type="shared")]), A(users=[user(account_type="shared", status="disabled")])),
    "IAM-002": (A({"iam_mfa_email": "dont_know"}), A({"iam_mfa_email": "yes"})),
    "IAM-003": (A({"iam_former_staff_access": "yes"}), A({"iam_former_staff_access": "no"})),
    "IAM-004": (A(users=[user(last_login_date=date(2026, 7, 1))]), A(users=[user(last_login_date=date(2026, 9, 1))])),
    "IAM-005": (A({"iam_mfa_banking": "no"}), A({"iam_mfa_banking": "yes"})),
    "IAM-006": (A({"iam_mfa_pos_admin": "no"}), A({"iam_mfa_pos_admin": "yes"})),
    "IAM-007": (A({"iam_admin_count": "everyone"}), A({"iam_admin_count": "two_three"})),
    "IAM-007/upload": (A(users=[user(is_admin="Y", user_id="a"), user(user_id="b")]),
                       A(users=[user(is_admin="Y", user_id="a"), user(user_id="b"), user(user_id="c")])),
    "IAM-008": (A(users=[user(is_admin="Y")]), A(users=[user(is_admin="Y", account_type="admin")])),
    "IAM-009": (A(users=[user(is_admin="Y", account_type="admin", mfa_enabled="unknown")]),
                A(users=[user(is_admin="Y", account_type="admin", mfa_enabled="Y")])),
    "IAM-010": (A(users=[user(mfa_enabled="N")]), A(users=[user(account_type="service", mfa_enabled="N")])),
    "IAM-011": (A({"iam_password_manager": "yes", "iam_unique_passwords": "no"}),
                A({"iam_password_manager": "yes", "iam_unique_passwords": "yes"})),
    "IAM-012": (A({"iam_phished_before": "yes", "iam_security_training": "yes"}),
                A({"iam_phished_before": "no", "iam_security_training": "yes"})),
    "IAM-013": (A({"iam_payment_verification": "dont_know"}), A({"iam_payment_verification": "yes"})),
    "IAM-014": (A({"iam_account_list": "no"}), A({"iam_account_list": "yes"})),
    "IAM-015": (A(users=[user(role_or_department=None)]), A(users=[user(role_or_department=None, status="disabled")])),
    "IAM-016": (A({"iam_breach_check": "no"}), A({"iam_breach_check": "yes"})),
}


def test_every_identity_rule_has_cases_and_is_implemented():
    iam = {r.id for r in load_rules() if r.module.value == "identity"}
    assert iam == {k.split("/")[0] for k in CASES}
    assert iam == {r.id for r in implemented_rules()}


def test_admin_count_codes_used_here_exist():
    from tests.helpers import questions

    assert "two_three" in questions()["iam_admin_count"]["options"]


@pytest.mark.parametrize("case", sorted(CASES))
def test_rule_fires(case):
    fires, _ = CASES[case]
    res = evaluate_rule(RULES[case.split("/")[0]], fires)
    assert res.status == "fired" and res.evidence


@pytest.mark.parametrize("case", sorted(CASES))
def test_rule_stays_clear(case):
    _, clear = CASES[case]
    res = evaluate_rule(RULES[case.split("/")[0]], clear)
    assert res.status == "clear" and not res.evidence


def test_quick_check_without_uploads_skips_upload_only_rules():
    res = {r.rule.id: r.status for r in evaluate(A({"iam_shared_logins": "no"}))}
    for rid in ("IAM-004", "IAM-008", "IAM-009", "IAM-010", "IAM-015"):
        assert res[rid] == "not_evaluated"
    assert res["IAM-001"] == "clear"


@pytest.mark.parametrize("biz", sample_businesses(), ids=lambda b: b.name)
@pytest.mark.parametrize("uploads", [True, False], ids=["full", "quick"])
def test_module1_end_to_end_on_samples(biz, uploads):
    """Full Assessment matches the hand labels; a Quick Check never invents upload-only findings."""
    expected = {r for r in load_expected(biz)["expected_rule_ids"] if r.startswith("IAM-")}
    fired = {r.rule.id for r in evaluate(load_sample(biz, with_uploads=uploads)) if r.fired}
    if uploads:
        assert fired == expected
    else:
        upload_only = {r.id for r in implemented_rules() if r.evidence == "upload"}
        assert fired <= expected and not (fired & upload_only)
