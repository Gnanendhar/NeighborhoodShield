"""Email domain check: input cleaning, record parsing, and the rules it feeds. DNS is always simulated, never real."""

from datetime import date

import pytest

from engine.evaluate import Assessment, evaluate_rule
from engine.loader import load_rules
from engine.lookups import LookupProblem, check_email_domain, clean_domain

RULES = {r.id: r for r in load_rules()}
TODAY = date(2026, 11, 19)


def stub_dns(records: dict[tuple[str, str], list[str]]):
    calls = []

    def resolve(name, rtype):
        calls.append((name, rtype))
        return records.get((name, rtype), [])

    resolve.calls = calls
    return resolve


def check(spf=None, dmarc=None, mx=("aspmx.l.google.com",), dkim=False):
    recs = {("shop.example", "MX"): list(mx)}
    if spf is not None:
        recs[("shop.example", "TXT")] = ["google-site-verification=abc", spf]
    if dmarc is not None:
        recs[("_dmarc.shop.example", "TXT")] = [dmarc]
    if dkim:
        recs[("google._domainkey.shop.example", "TXT")] = ["v=DKIM1; k=rsa; p=MIIB"]
    return check_email_domain("shop.example", stub_dns(recs), TODAY)


@pytest.mark.parametrize("typed", ["shop.example", "@shop.example", "Owner@Shop.Example", "https://www.shop.example/",
                                   " shop.example. "])
def test_domain_is_cleaned(typed):
    assert clean_domain(typed) == "shop.example"


@pytest.mark.parametrize("typed, says", [
    ("", "after the @"), ("gmail.com", "free email service"), ("Me@Yahoo.com", "free email service"),
    ("localhost", "does not look like"), ("192.168.0.1", "does not look like"), ("bad_domain.com", "does not look like"),
])
def test_bad_or_free_domains_are_refused_with_a_reason(typed, says):
    with pytest.raises(LookupProblem, match=says):
        clean_domain(typed)


def test_only_public_dns_records_are_read():
    r = stub_dns({})
    check_email_domain("shop.example", r, TODAY)
    assert {t for _, t in r.calls} <= {"TXT", "MX"}
    assert all(n.endswith("shop.example") for n, _ in r.calls)


@pytest.mark.parametrize("spf, expected", [
    (None, ("N", "none")), ("v=spf1 include:_spf.google.com -all", ("Y", "-all")),
    ("v=spf1 include:_spf.google.com ~all", ("Y", "~all")), ("v=spf1 +all", ("Y", "+all")),
    ("v=spf1 a mx all", ("Y", "+all")), ("v=spf1 ?all", ("Y", "?all")), ("v=spf1 mx", ("Y", "?all")),
])
def test_spf_parsing(spf, expected):
    row = check(spf=spf, dmarc="v=DMARC1; p=reject")
    assert (str(row["spf_present"]), row["spf_all_qualifier"]) == expected


@pytest.mark.parametrize("dmarc, expected", [
    (None, ("N", "missing", "N")), ("v=DMARC1; p=none", ("Y", "none", "N")),
    ("v=DMARC1; p=quarantine; rua=mailto:d@shop.example", ("Y", "quarantine", "Y")),
    ("v=DMARC1;p=REJECT", ("Y", "reject", "N")), ("v=DMARC1; p=invalid", ("Y", "none", "N")),
])
def test_dmarc_parsing(dmarc, expected):
    row = check(spf="v=spf1 -all", dmarc=dmarc)
    assert (str(row["dmarc_present"]), row["dmarc_policy"], str(row["dmarc_rua_present"])) == expected


def test_mx_provider_and_dkim():
    assert check(mx=("shop-example.mail.protection.outlook.com",))["mx_provider"] == "microsoft"
    assert check(mx=())["mx_provider"] == "none"
    assert str(check(dkim=True)["dkim_found"]) == "Y"
    assert str(check()["dkim_found"]) == "unknown"  # selectors cannot be listed, so never "N"


@pytest.mark.parametrize("spf, dmarc, fires", [
    (None, None, {"NET-013", "NET-015"}),
    ("v=spf1 ~all", "v=DMARC1; p=none", {"NET-014"}),
    ("v=spf1 +all", "v=DMARC1; p=quarantine", {"NET-015"}),
    ("v=spf1 -all", "v=DMARC1; p=reject", set()),
])
def test_lookup_feeds_the_email_rules(spf, dmarc, fires):
    a = Assessment(tables={"email_domain_check": [check(spf=spf, dmarc=dmarc)]}, as_of=TODAY)
    fired = {rid for rid in ("NET-013", "NET-014", "NET-015") if evaluate_rule(RULES[rid], a).fired}
    assert fired == fires


def test_dns_trouble_is_a_plain_message():
    def broken(name, rtype):
        raise LookupProblem("The check could not reach the internet's address book (DNS). Try again later.")

    with pytest.raises(LookupProblem, match="Try again later"):
        check_email_domain("shop.example", broken, TODAY)
