"""Evaluate the rule catalog against one assessment.

Each trigger evaluates to one of three outcomes:

* ``True``  - the condition holds (the rule fires)
* ``False`` - the evidence is there and the condition does not hold
* ``None``  - the evidence is missing (question not answered, file not uploaded)

Composition keeps those three states honest:

* ``any_of`` fires if any child fires; it is clear if no child fires and at least
  one child could be checked; otherwise it is not evaluable.
* ``all_of`` is clear if any child is clear; it fires if every child fires;
  otherwise it is not evaluable.

A rule that is not evaluable is reported as such and, in the scoring step, is
left out of the denominator so a Quick Check is not penalized for missing files.

No ``eval``: every operator is an explicit Python function below.
"""

from __future__ import annotations

import csv
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from functools import cache
from typing import Any, Literal

from .loader import load_legal_flags, load_rules, load_strings
from .normalize import candidate_labels, port_matches
from .paths import REFERENCE_DIR
from .schemas import (
    SEVERITY_WEIGHT,
    AllOf,
    AnswerCondition,
    AnyOf,
    LegalFlag,
    RowsCondition,
    RuleSpec,
    Where,
)

Outcome = bool | None

# Column that names a row in owner-facing evidence (already redacted on ingest).
ROW_LABEL = {
    "users_permissions": "user_id",
    "firewall_rules": "rule_id",
    "patch_inventory": "device_id",
    "endpoint_protection": "device_id",
    "backup_jobs": "job_id",
    "email_domain_check": "domain",
}
# What one row is called in owner-facing evidence.
ROW_NOUN = {
    "users_permissions": "logins",
    "firewall_rules": "router rules",
    "patch_inventory": "devices",
    "endpoint_protection": "devices",
    "backup_jobs": "backups",
    "email_domain_check": "email domain checks",
}
MAX_LISTED = 5


@dataclass
class Assessment:
    """Everything one business told us, held in memory for one session."""

    answers: dict[str, Any] = field(default_factory=dict)
    tables: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # validated + redacted
    as_of: date = field(default_factory=date.today)


@dataclass
class RuleResult:
    rule: RuleSpec
    status: Literal["fired", "clear", "not_evaluated"]
    evidence: list[str] = field(default_factory=list)

    @property
    def fired(self) -> bool:
        return self.status == "fired"


# ---------------------------------------------------------------- reference lookups
@cache
def _eol_index() -> dict[tuple[str, str], list[date | None]]:
    idx: dict[tuple[str, str], list[date | None]] = {}
    with (REFERENCE_DIR / "eol_table.csv").open(encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            key = (r["product"].strip().lower(), r["release_label"].strip().lower())
            idx.setdefault(key, []).append(_eol_date(r["eol"]))
    return idx


def _eol_date(v: str) -> date | None:
    """endoflife.date writes a date, or true/false when there is no exact date."""
    v = v.strip().lower()
    if v in ("", "false"):
        return None
    if v == "true":
        return date.min  # already out of support, date not published
    return date.fromisoformat(v)


def eol_release(os_name: str | None, os_version: str | None) -> tuple[str, str] | None:
    """The (product, release label) in the snapshot that this device's OS matches, if any."""
    if not os_version:
        return None
    product, labels = candidate_labels(os_name, os_version)
    if product is None:
        return None
    idx = _eol_index()
    for label in [os_version.strip(), *labels]:
        if (product, label.lower()) in idx:
            return product, label
    return None


def is_end_of_life(os_name: str | None, os_version: str | None, as_of: date) -> bool:
    """True when every matching release in the snapshot ended support on or before ``as_of``.

    Wording variants ("Windows 11 Home 24H2", "macOS Sonoma 14.6") are normalized
    first (engine/normalize.py). Unknown products or versions are never flagged.
    """
    hit = eol_release(os_name, os_version)
    if hit is None:
        return False
    eols = _eol_index()[(hit[0], hit[1].lower())]
    return all(e is not None and e <= as_of for e in eols)


# Product names in the KEV catalog that are too broad to match by name alone.
KEV_GENERIC = {"multiple products", "multiple routers", "windows", "office", "internet explorer", "server",
               "client", "browser", "app", "apps", "firmware", "router", "routers"}


@cache
def _kev_patterns() -> tuple[tuple[re.Pattern[str], str], ...]:
    pats: dict[str, re.Pattern[str]] = {}
    with (REFERENCE_DIR / "kev_smb_snapshot.csv").open(encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            product = r["product"].strip()
            p = product.lower()
            if len(p) < 4 or p == r["vendorProject"].strip().lower() or p in KEV_GENERIC:
                continue
            pats.setdefault(p, re.compile(rf"(?<![\w-]){re.escape(p)}(?![\w-])", re.IGNORECASE))
    return tuple((pat, name) for name, pat in sorted(pats.items()))


def kev_matches(software: str | None) -> list[str]:
    """KEV product names that appear (as whole words) in a software name. Advisory: name, not version."""
    if not software:
        return []
    return [name for pat, name in _kev_patterns() if pat.search(software)]


# ---------------------------------------------------------------- row operators
def _s(v: Any) -> str | None:
    return None if v is None else str(v)


def _num(v: Any) -> float | None:
    try:
        return None if v is None or v == "" else float(v)
    except (TypeError, ValueError):
        return None


def _days_old(v: Any, as_of: date) -> int | None:
    if isinstance(v, date):
        return (as_of - v).days
    if isinstance(v, str) and v:
        try:
            return (as_of - date.fromisoformat(v)).days
        except ValueError:
            return None
    return None


def _row_matches(where: Where, row: dict[str, Any], as_of: date) -> bool:
    v = row.get(where.col)
    target = where.value
    op = where.op
    if op == "eq":
        return _s(v) == _s(target)
    if op == "ne":
        return _s(v) != _s(target)
    if op == "in":
        return _s(v) in {_s(t) for t in target}
    if op == "not_in":
        return _s(v) not in {_s(t) for t in target}
    if op in ("gt", "lt", "gte", "lte"):
        a, b = _num(v), _num(target)
        if a is None or b is None:
            return False
        return {"gt": a > b, "lt": a < b, "gte": a >= b, "lte": a <= b}[op]
    if op == "older_than_days":
        d = _days_old(v, as_of)
        return d is not None and d > int(target)
    if op == "newer_than_days":
        d = _days_old(v, as_of)
        return d is not None and d < int(target)
    if op == "is_empty":
        return v is None or _s(v).strip() == ""
    if op == "not_empty":
        return not (v is None or _s(v).strip() == "")
    if op == "contains_any":
        text = (_s(v) or "").lower()
        return any(str(t).lower() in text for t in target)
    if op == "is_end_of_life":
        return is_end_of_life(_s(row.get("os_name")), _s(v), as_of)
    if op == "in_kev":
        return bool(kev_matches(_s(v)))
    if op == "port_in":
        return port_matches(_s(v), list(target or []))
    raise ValueError(f"operator {op!r} has no implementation")  # schema and engine out of sync


# ---------------------------------------------------------------- conditions
@cache
def _question_index() -> dict[str, dict]:
    return {q["id"]: q for q in load_strings()["questions"]}


def _answer_label(qid: str, code: str) -> str:
    q = _question_index().get(qid)
    if q is None:
        return code
    if q["type"] == "ynd":
        return load_strings()["answers"]["ynd"].get(code, code)
    return q.get("options", {}).get(code, code)


def _fmt_answer(qid: str, v: Any) -> str:
    """'You answered "Question text": Answer label' using the owner's own wording."""
    q = _question_index().get(qid)
    codes = v if isinstance(v, list) else [v]
    label = ", ".join(_answer_label(qid, str(c)) for c in codes)
    return f'You answered "{q["text"]}": {label}' if q else f"{qid} = {label}"


def _answer(c: AnswerCondition, a: Assessment, ev: list[str]) -> Outcome:
    if c.q not in a.answers or a.answers[c.q] in (None, "", []):
        return None
    v = a.answers[c.q]
    selected = {str(x) for x in v} if isinstance(v, list) else {str(v)}
    if c.in_ is not None:
        hit = bool(selected & set(c.in_)) if isinstance(v, list) else str(v) in c.in_
    elif c.contains_any is not None:
        hit = bool(selected & set(c.contains_any))
    else:
        hit = not (selected & set(c.lacks_all or []))
    if hit:
        ev.append(_fmt_answer(c.q, v))
    return hit


def _rows(c: RowsCondition, a: Assessment, ev: list[str]) -> Outcome:
    if c.table not in a.tables:
        return None
    rows = a.tables[c.table]
    matched = [r for r in rows if all(_row_matches(w, r, a.as_of) for w in c.where)]
    if c.match == "any":
        hit = len(matched) >= c.min_count
    elif c.match == "none":
        hit = not matched
    else:
        hit = bool(rows) and len(matched) / len(rows) >= (c.min_ratio or 0)
    if hit:
        label = ROW_LABEL.get(c.table)
        noun = ROW_NOUN.get(c.table, "rows")
        if c.match == "none":
            ev.append(f"Your file: none of the {len(rows)} {noun} meet this")
        else:
            names = [str(r.get(label)) for r in matched[:MAX_LISTED]] if label else []
            more = f" and {len(matched) - MAX_LISTED} more" if len(matched) > MAX_LISTED else ""
            listed = f": {', '.join(names)}{more}" if names else ""
            ev.append(f"Your file: {len(matched)} of {len(rows)} {noun}{listed}")
    return hit


def evaluate_trigger(t, a: Assessment, ev: list[str] | None = None) -> Outcome:
    ev = [] if ev is None else ev
    if isinstance(t, AnswerCondition):
        return _answer(t, a, ev)
    if isinstance(t, RowsCondition):
        return _rows(t, a, ev)
    if isinstance(t, AnyOf):
        outs = [evaluate_trigger(c, a, ev) for c in t.any_of]
        if any(o is True for o in outs):
            return True
        return False if any(o is False for o in outs) else None
    if isinstance(t, AllOf):
        local: list[str] = []
        outs = [evaluate_trigger(c, a, local) for c in t.all_of]
        if any(o is False for o in outs):
            return False
        if all(o is True for o in outs):
            ev.extend(local)
            return True
        return None
    raise TypeError(f"unknown trigger node {type(t).__name__}")


# ---------------------------------------------------------------- rules
def evaluate_rule(rule: RuleSpec, a: Assessment) -> RuleResult:
    ev: list[str] = []
    out = evaluate_trigger(rule.trigger, a, ev)
    status = "fired" if out is True else "clear" if out is False else "not_evaluated"
    return RuleResult(rule=rule, status=status, evidence=ev if out else [])


def implemented_rules() -> tuple[RuleSpec, ...]:
    return tuple(r for r in load_rules() if r.status == "implemented")


def evaluate(a: Assessment, rules: Iterable[RuleSpec] | None = None) -> list[RuleResult]:
    """Evaluate rules (default: every implemented rule), most severe findings first."""
    rules = implemented_rules() if rules is None else tuple(rules)
    results = [evaluate_rule(r, a) for r in rules]
    order = {"fired": 0, "clear": 1, "not_evaluated": 2}
    return sorted(results, key=lambda r: (order[r.status], -SEVERITY_WEIGHT[r.rule.severity], r.rule.id))


def findings(results: Iterable[RuleResult]) -> list[RuleResult]:
    return [r for r in results if r.fired]


def evaluate_legal_flags(a: Assessment, flags: Iterable[LegalFlag] | None = None) -> list[LegalFlag]:
    flags = load_legal_flags() if flags is None else flags
    return [f for f in flags if evaluate_trigger(f.trigger, a) is True]
