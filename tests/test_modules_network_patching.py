"""Modules 2 (network) and 3 (patching): every rule has a case that fires and a case that stays clear."""

from datetime import date

import pytest

from engine.evaluate import Assessment, evaluate, evaluate_rule, implemented_rules
from engine.loader import load_rules
from engine.samples import load_expected, load_sample, sample_businesses

AS_OF = date(2026, 11, 19)
RULES = {r.id: r for r in load_rules()}


def fw(**kw):
    base = {"rule_id": "r1", "enabled": "Y", "action": "allow", "direction": "inbound", "source": "lan",
            "destination": "lan", "service_or_port": "443", "comment": "Office"}
    return base | kw


def dev(**kw):
    base = {"device_id": "desktop-a1", "device_type": "desktop", "os_name": "Windows", "os_version": "11 Pro 25H2",
            "auto_update_enabled": "Y", "last_patch_date": date(2026, 11, 10), "pending_critical_updates": 0,
            "key_software_name": "Microsoft 365 Apps", "key_software_version": "2510", "vendor_supported": "Y"}
    return base | kw


def mail(**kw):
    base = {"domain": "shop.example", "mx_provider": "google", "spf_present": "Y", "spf_all_qualifier": "-all",
            "dmarc_present": "Y", "dmarc_policy": "reject", "dmarc_rua_present": "Y", "dkim_found": "Y",
            "checked_on": AS_OF}
    return base | kw


def A(answers=None, **tables):
    return Assessment(answers=answers or {}, tables=tables, as_of=AS_OF)


CASES = {
    # ------------------------------------------------------------------ network
    "NET-001": (A({"net_guest_wifi_separate": "no"}), A({"net_guest_wifi_separate": "yes"})),
    "NET-002/upload": (A(firewall_rules=[fw(source="wan", service_or_port="tcp/3389")]),
                       A(firewall_rules=[fw(source="wan", service_or_port="13389")])),
    "NET-002/answers": (A({"net_remote_access_used": "yes", "net_remote_access_mfa": "dont_know"}),
                        A({"net_remote_access_used": "yes", "net_remote_access_mfa": "yes"})),
    "NET-003": (A({"net_remote_access_used": "dont_know", "net_remote_access_mfa": "no"}),
                A({"net_remote_access_used": "no", "net_remote_access_mfa": "no"})),
    "NET-004": (A({"net_remote_tool_always_on": "yes"}), A({"net_remote_tool_always_on": "no"})),
    "NET-005": (A({"net_router_default_password": "no", "net_router_admin_logged_in": "no"}),
                A({"net_router_default_password": "no", "net_router_admin_logged_in": "yes"})),
    "NET-006": (A({"net_router_updated": "longer"}), A({"net_router_updated": "last_year"})),
    "NET-007": (A(firewall_rules=[fw(source="any", destination="any", service_or_port="*")]),
                A(firewall_rules=[fw(source="any", destination="any", service_or_port="*", enabled="N")])),
    "NET-008": (A(firewall_rules=[fw(source="wan", service_or_port="8080-8090")]),
                A(firewall_rules=[fw(source="wan", service_or_port="8000")])),  # 8000 is not port 80
    "NET-009": (A(firewall_rules=[fw(source="guest", destination="lan")]),
                A(firewall_rules=[fw(source="guest", destination="wan")])),
    "NET-010": (A(firewall_rules=[fw(comment=None)]), A(firewall_rules=[fw(comment=None, action="deny")])),
    "NET-011": (A({"net_dns_filtering": "dont_know"}), A({"net_dns_filtering": "yes"})),
    "NET-012": (A(patch_inventory=[dev(key_software_name="AnyDesk")]), A(patch_inventory=[dev()])),
    "NET-013": (A(email_domain_check=[mail(dmarc_present="N", dmarc_policy="missing")]), A(email_domain_check=[mail()])),
    "NET-014": (A(email_domain_check=[mail(dmarc_policy="none")]), A(email_domain_check=[mail(dmarc_policy="quarantine")])),
    "NET-015": (A(email_domain_check=[mail(spf_all_qualifier="?all")]), A(email_domain_check=[mail(spf_all_qualifier="~all")])),
    # ----------------------------------------------------------------- patching
    "PAT-001": (A({"pat_auto_updates": "no"}), A({"pat_auto_updates": "yes"}, patch_inventory=[dev()])),
    "PAT-001/upload": (A(patch_inventory=[dev(auto_update_enabled="N")]),
                       A(patch_inventory=[dev(auto_update_enabled="N", device_type="pos_terminal")])),
    "PAT-002": (A({"pat_old_os": "dont_know"}), A({"pat_old_os": "no"})),
    "PAT-003": (A({"pat_pos_supported": "no"}), A({"pat_pos_supported": "yes"})),
    "PAT-004": (A({"pat_update_reminder_month": "yes"}), A({"pat_update_reminder_month": "no"})),
    "PAT-005": (A(patch_inventory=[dev(pending_critical_updates=2, last_patch_date=date(2026, 9, 1))]),
                A(patch_inventory=[dev(pending_critical_updates=2, last_patch_date=date(2026, 11, 1))])),
    "PAT-006": (A(patch_inventory=[dev(os_version="11 Home 24H2")]), A(patch_inventory=[dev(os_version="11 Home 25H2")])),
    "PAT-006/mac": (A(patch_inventory=[dev(os_name="macOS", os_version="Sonoma 14.6")]),
                    A(patch_inventory=[dev(os_name="macOS", os_version="Sequoia 15.1")])),
    "PAT-007": (A(patch_inventory=[dev(vendor_supported="unknown")]), A(patch_inventory=[dev()])),
    "PAT-008": (A(patch_inventory=[dev(key_software_name="WinRAR")]), A(patch_inventory=[dev(key_software_name="7-Zip")])),
    "PAT-009": (A({"pat_browser_updates": "no"}), A({"pat_browser_updates": "yes"})),
    "PAT-010": (A({"pat_software_list": "dont_know"}), A({"pat_software_list": "yes"})),
}


def test_every_network_and_patching_rule_has_cases_and_is_implemented():
    ids = {r.id for r in load_rules() if r.module.value in ("network", "patching")}
    assert ids == {k.split("/")[0] for k in CASES}
    assert ids <= {r.id for r in implemented_rules()}


@pytest.mark.parametrize("case", sorted(CASES))
def test_rule_fires(case):
    res = evaluate_rule(RULES[case.split("/")[0]], CASES[case][0])
    assert res.status == "fired" and res.evidence


@pytest.mark.parametrize("case", sorted(CASES))
def test_rule_stays_clear(case):
    res = evaluate_rule(RULES[case.split("/")[0]], CASES[case][1])
    assert res.status == "clear" and not res.evidence


@pytest.mark.parametrize("biz", sample_businesses(), ids=lambda b: b.name)
def test_modules_2_and_3_end_to_end_on_samples(biz):
    expected = {r for r in load_expected(biz)["expected_rule_ids"] if r[:3] in ("NET", "PAT")}
    fired = {r.rule.id for r in evaluate(load_sample(biz)) if r.fired and r.rule.id[:3] in ("NET", "PAT")}
    assert fired == expected
