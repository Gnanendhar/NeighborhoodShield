"""Modules 4 (devices) and 5 (backups and recovery): every rule has a case that fires and a case that stays clear."""

from datetime import date

import pytest

from engine.evaluate import Assessment, evaluate, evaluate_rule, implemented_rules
from engine.loader import load_rules
from engine.samples import load_expected, load_sample, sample_businesses

AS_OF = date(2026, 11, 24)
RULES = {r.id: r for r in load_rules()}


def ep(**kw):
    base = {"device_id": "laptop-a1", "device_type": "laptop", "protection_product": "Microsoft Defender",
            "protection_enabled": "Y", "definitions_date": date(2026, 11, 23), "disk_encryption": "Y",
            "screen_lock": "Y", "last_seen_date": date(2026, 11, 23)}
    return base | kw


def job(**kw):
    base = {"job_id": "nightly", "source_system": "system-a1", "destination_type": "cloud", "schedule": "daily",
            "last_success_date": date(2026, 11, 23), "last_restore_test_date": date(2026, 9, 1), "encrypted": "Y",
            "retention_days": 90}
    return base | kw


def A(answers=None, **tables):
    return Assessment(answers=answers or {}, tables=tables, as_of=AS_OF)


CASES = {
    # ------------------------------------------------------------------ devices
    "END-001": (A({"end_antivirus": "dont_know"}), A({"end_antivirus": "yes"})),
    "END-001/upload": (A(endpoint_protection=[ep(protection_product=None)]),
                       A(endpoint_protection=[ep(protection_product=None, device_type="phone")])),
    "END-002": (A({"end_encryption": "no"}), A({"end_encryption": "yes"})),
    "END-003": (A({"end_screen_lock": "dont_know"}), A({"end_screen_lock": "yes"})),
    "END-004": (A({"end_personal_phones_email": "yes"}), A({"end_personal_phones_email": "no"})),
    "END-005": (A({"end_old_devices": "yes"}), A({"end_old_devices": "no"})),
    "END-006": (A(endpoint_protection=[ep(protection_enabled="N")]),
                A(endpoint_protection=[ep(protection_enabled="N", device_type="tablet")])),
    "END-007": (A(endpoint_protection=[ep(definitions_date=date(2026, 11, 1))]),
                A(endpoint_protection=[ep(definitions_date=date(2026, 11, 20))])),
    "END-008": (A(endpoint_protection=[ep(disk_encryption="unknown")]),
                A(endpoint_protection=[ep(disk_encryption="N", device_type="desktop")])),
    "END-009": (A(endpoint_protection=[ep(screen_lock="N")]), A(endpoint_protection=[ep()])),
    "END-010": (A(endpoint_protection=[ep(last_seen_date=date(2026, 9, 1))]), A(endpoint_protection=[ep()])),
    "END-011": (A({"end_device_list": "no"}), A({"end_device_list": "yes"})),
    # ------------------------------------------------------------------ backups and recovery
    "BKP-001": (A({"bkp_backed_up": "no"}), A({"bkp_backed_up": "yes", "bkp_locations": ["cloud"]})),
    "BKP-001/locations": (A({"bkp_backed_up": "yes", "bkp_locations": ["external_drive_onsite", "dont_know"]}),
                          A({"bkp_backed_up": "yes", "bkp_locations": ["external_drive_onsite"]})),
    "BKP-002": (A({"bkp_backed_up": "yes", "bkp_locations": ["same_computer", "external_drive_onsite"]}),
                A({"bkp_backed_up": "yes", "bkp_locations": ["external_drive_onsite", "offsite"]})),
    "BKP-002/upload": (A(backup_jobs=[job(destination_type="local_external")]), A(backup_jobs=[job()])),
    "BKP-003": (A({"bkp_restore_tested": "dont_know"}), A({"bkp_restore_tested": "yes"})),
    "BKP-003/upload": (A(backup_jobs=[job(last_restore_test_date=date(2026, 1, 1))]), A(backup_jobs=[job()])),
    "BKP-004": (A({"bkp_recovery_time": "days"}), A({"bkp_recovery_time": "a_day"})),
    "BKP-005": (A({"bkp_contact_list": "no"}), A({"bkp_contact_list": "yes"})),
    "BKP-006": (A({"bkp_incident_owner": "dont_know"}), A({"bkp_incident_owner": "yes"})),
    "BKP-007": (A(backup_jobs=[job(last_success_date=date(2026, 11, 10))]),
                A(backup_jobs=[job(schedule="monthly", last_success_date=date(2026, 11, 10))])),
    "BKP-008": (A(backup_jobs=[job(encrypted="unknown")]),
                A(backup_jobs=[job(encrypted="N", destination_type="same_device")])),
    "BKP-009": (A(backup_jobs=[job(retention_days=14)]), A(backup_jobs=[job(retention_days=30)])),
    "BKP-010": (A({"bkp_vendor_list": "no"}), A({"bkp_vendor_list": "yes"})),
}


def test_every_device_and_backup_rule_has_cases_and_is_implemented():
    ids = {r.id for r in load_rules() if r.module.value in ("endpoint", "recovery")}
    assert ids == {k.split("/")[0] for k in CASES}
    assert ids <= {r.id for r in implemented_rules()}


def test_all_62_rules_are_implemented():
    assert {r.id for r in implemented_rules()} == {r.id for r in load_rules()}


@pytest.mark.parametrize("case", sorted(CASES))
def test_rule_fires(case):
    res = evaluate_rule(RULES[case.split("/")[0]], CASES[case][0])
    assert res.status == "fired" and res.evidence


@pytest.mark.parametrize("case", sorted(CASES))
def test_rule_stays_clear(case):
    res = evaluate_rule(RULES[case.split("/")[0]], CASES[case][1])
    assert res.status == "clear" and not res.evidence


@pytest.mark.parametrize("biz", sample_businesses(), ids=lambda b: b.name)
def test_modules_4_and_5_end_to_end_on_samples(biz):
    expected = {r for r in load_expected(biz)["expected_rule_ids"] if r[:3] in ("END", "BKP")}
    fired = {r.rule.id for r in evaluate(load_sample(biz)) if r.fired and r.rule.id[:3] in ("END", "BKP")}
    assert fired == expected
