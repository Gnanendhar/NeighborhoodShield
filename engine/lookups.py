"""Public lookups the owner asks for. Today: their own email domain's SPF, DMARC, MX and DKIM records.

This reads only public DNS records, the same ones every mail server reads when
it receives the business's email. It is not a scan of the business network.
Nothing is stored: the result lives in the session like any other answer.

The DNS resolver is injectable so tests never touch the network.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import date

from .schemas import EmailDomainCheckRow

# Free mailbox providers: their DNS belongs to the provider, not the business.
FREE_MAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "aol.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "gmx.com", "mail.com",
    "zoho.com", "comcast.net", "att.net", "sbcglobal.net", "verizon.net",
}
# Common DKIM selectors (Google Workspace, Microsoft 365, many hosts). Selectors cannot be listed,
# so "not found" means unknown, not missing.
DKIM_SELECTORS = ("google", "selector1", "selector2", "default", "k1", "s1", "dkim")

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class LookupProblem(ValueError):
    """Owner-facing reason a lookup could not run (bad input, free webmail, DNS trouble)."""


# A resolver takes (name, record type) and returns the record texts, [] when none exist.
Resolver = Callable[[str, str], list[str]]


def clean_domain(text: str | None) -> str:
    """Accept 'shop.com', '@shop.com', 'me@shop.com', 'https://www.shop.com/'; return 'shop.com'."""
    if not text or not text.strip():
        raise LookupProblem("Type the part of your email address after the @, for example yourbusiness.com.")
    d = text.strip().lower()
    d = d.split("@")[-1]
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split(":")[0].strip(".")
    if d.startswith("www."):
        d = d[4:]
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise LookupProblem("That does not look like an email domain.") from exc
    labels = d.split(".")
    if len(labels) < 2 or not all(_LABEL.match(x) for x in labels) or labels[-1].isdigit() or len(d) > 253:
        raise LookupProblem("That does not look like an email domain, for example yourbusiness.com.")
    if d in FREE_MAIL:
        raise LookupProblem(f"{d} is a free email service, so its settings belong to the provider, not your business. "
                            "There is nothing for you to change here.")
    return d


def dns_resolver(timeout: float = 3.0) -> Resolver:
    """Real DNS via dnspython. NXDOMAIN or no answer -> []; anything else -> LookupProblem."""
    import dns.exception
    import dns.resolver

    res = dns.resolver.Resolver()
    res.lifetime = timeout

    def resolve(name: str, rtype: str) -> list[str]:
        try:
            answer = res.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.DNSException as exc:
            raise LookupProblem("The check could not reach the internet's address book (DNS). Try again later.") from exc
        if rtype == "TXT":
            return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]
        if rtype == "MX":
            return [str(r.exchange).rstrip(".").lower() for r in answer]
        return [r.to_text() for r in answer]

    return resolve


def _spf(txts: list[str]) -> tuple[str, str]:
    spf = [t for t in txts if t.strip().lower().startswith("v=spf1")]
    if not spf:
        return "N", "none"
    terms = spf[0].lower().split()
    for term in reversed(terms):
        m = re.fullmatch(r"([+\-~?]?)all", term)
        if m:
            return "Y", f"{m.group(1) or '+'}all"
    return "Y", "?all"  # no 'all' term: the default result is neutral, the same as ?all (RFC 7208)


def _dmarc(txts: list[str]) -> tuple[str, str, str]:
    rec = next((t for t in txts if t.strip().lower().startswith("v=dmarc1")), None)
    if rec is None:
        return "N", "missing", "N"
    tags = {k.strip().lower(): v.strip().lower() for k, _, v in (p.partition("=") for p in rec.split(";")) if k.strip()}
    policy = tags.get("p", "none")
    if policy not in ("reject", "quarantine", "none"):
        policy = "none"  # an invalid policy gives no protection
    return "Y", policy, "Y" if tags.get("rua") else "N"


def _mx_provider(hosts: list[str]) -> str:
    if not hosts:
        return "none"
    joined = " ".join(hosts)
    if "google.com" in joined or "googlemail.com" in joined:
        return "google"
    if "outlook.com" in joined or "office365" in joined:
        return "microsoft"
    return "other"


def check_email_domain(text: str, resolver: Resolver | None = None, today: date | None = None) -> dict:
    """Look up a business's own email domain and return one validated ``email_domain_check`` row."""
    domain = clean_domain(text)
    resolve = resolver or dns_resolver()
    spf_present, spf_all = _spf(resolve(domain, "TXT"))
    dmarc_present, policy, rua = _dmarc(resolve(f"_dmarc.{domain}", "TXT"))
    mx = _mx_provider(resolve(domain, "MX"))
    dkim = "unknown"
    for sel in DKIM_SELECTORS:
        if any("p=" in t.lower() for t in resolve(f"{sel}._domainkey.{domain}", "TXT")):
            dkim = "Y"
            break
    row = EmailDomainCheckRow(
        domain=domain, mx_provider=mx, spf_present=spf_present, spf_all_qualifier=spf_all,
        dmarc_present=dmarc_present, dmarc_policy=policy, dmarc_rua_present=rua, dkim_found=dkim,
        checked_on=today or date.today(),
    )
    return row.model_dump()
