"""Typed schemas for NeighborhoodShield.

Week 1 scope: these models are the *contract* that the rest of the build
implements. They validate three things today:

1. Upload templates (one row model per CSV template, Appendix B of the brief).
2. Rule specifications (the YAML rule catalog in ``rules/``).
3. Disruption scenarios (``rules/scenarios.yaml``).

Every model is strict on purpose: a malformed rule or a mistyped column should
fail loudly at startup, not silently produce a wrong finding.
"""

from __future__ import annotations

import re
from datetime import date
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Shared enums
# ---------------------------------------------------------------------------


class Module(StrEnum):
    identity = "identity"
    network = "network"
    patching = "patching"
    endpoint = "endpoint"
    recovery = "recovery"


MODULE_PREFIX = {
    Module.identity: "IAM",
    Module.network: "NET",
    Module.patching: "PAT",
    Module.endpoint: "END",
    Module.recovery: "BKP",
}


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


SEVERITY_WEIGHT = {Severity.critical: 10, Severity.high: 6, Severity.medium: 3, Severity.low: 1}


class CostTier(StrEnum):
    free = "free"            # a setting change you can make today
    low = "low"              # under $100 per year
    moderate = "moderate"    # $100 to $500
    contractor = "contractor"  # a few hours of a local IT contractor's time


class Who(StrEnum):
    owner = "owner"
    contractor = "contractor"
    owner_or_contractor = "owner_or_contractor"


class YN(StrEnum):
    Y = "Y"
    N = "N"


class YNU(StrEnum):
    Y = "Y"
    N = "N"
    unknown = "unknown"


# ---------------------------------------------------------------------------
# Upload template row models (Appendix B)
# ---------------------------------------------------------------------------


class _Row(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("*", mode="before")
    @classmethod
    def _blank_to_none(cls, v):
        if isinstance(v, float) and v != v:  # NaN from pandas
            return None
        if isinstance(v, str) and v.strip() == "":
            return None
        return v


class UserPermissionRow(_Row):
    user_id: str
    account_type: Literal["staff", "admin", "service", "shared"]
    is_admin: YN
    mfa_enabled: YNU
    status: Literal["active", "disabled"]
    created_date: date | None = None
    last_login_date: date | None = None
    role_or_department: str | None = None


class FirewallRuleRow(_Row):
    rule_id: str
    enabled: YN
    action: Literal["allow", "deny"]
    direction: Literal["inbound", "outbound"]
    source: str  # any / lan / guest / wan / address range (CIDR)
    destination: str
    service_or_port: str
    comment: str | None = None


class PatchInventoryRow(_Row):
    device_id: str
    device_type: Literal["desktop", "laptop", "tablet", "phone", "server", "pos_terminal", "router"]
    os_name: str
    os_version: str
    auto_update_enabled: YN
    last_patch_date: date | None = None
    pending_critical_updates: int = Field(ge=0)
    key_software_name: str | None = None
    key_software_version: str | None = None
    vendor_supported: YNU


class EndpointProtectionRow(_Row):
    device_id: str
    device_type: Literal["desktop", "laptop", "tablet", "phone", "server"]
    protection_product: str | None = None
    protection_enabled: YN
    definitions_date: date | None = None
    disk_encryption: YNU
    screen_lock: YNU
    last_seen_date: date | None = None


class BackupJobRow(_Row):
    job_id: str
    source_system: str
    destination_type: Literal["same_device", "local_external", "network_share", "cloud", "offline"]
    schedule: Literal["daily", "weekly", "monthly", "manual"]
    last_success_date: date | None = None
    last_restore_test_date: date | None = None
    encrypted: YNU
    retention_days: int | None = Field(default=None, ge=0)


TEMPLATE_MODELS: dict[str, type[_Row]] = {
    "users_permissions": UserPermissionRow,
    "firewall_rules": FirewallRuleRow,
    "patch_inventory": PatchInventoryRow,
    "endpoint_protection": EndpointProtectionRow,
    "backup_jobs": BackupJobRow,
}

# Columns that identify a person, device or address and are redacted on ingest
# (implemented in Week 2, declared here so the contract is visible from day 1).
REDACT_COLUMNS: dict[str, dict[str, str]] = {
    "users_permissions": {"user_id": "hash"},
    "firewall_rules": {"source": "truncate_ip", "destination": "truncate_ip"},
    "patch_inventory": {"device_id": "role_label"},
    "endpoint_protection": {"device_id": "role_label"},
    "backup_jobs": {"source_system": "role_label"},
}


# ---------------------------------------------------------------------------
# Lookup tables: produced by the app from a public lookup the owner requests
# (never uploaded, never stored). Week 1 extension, built in Week 3.
# ---------------------------------------------------------------------------


class EmailDomainCheckRow(_Row):
    """Result of a public DNS lookup of the owner's own email domain.

    Only public DNS records are read (TXT for SPF and _dmarc, MX, common DKIM
    selectors). This is the same information any mail server reads when it
    receives the business's email; it is not a scan of the business network.
    """

    domain: str
    mx_provider: str | None = None                      # e.g. google, microsoft, other, none
    spf_present: YN
    spf_all_qualifier: Literal["-all", "~all", "?all", "+all", "none"]
    dmarc_present: YN
    dmarc_policy: Literal["reject", "quarantine", "none", "missing"]
    dmarc_rua_present: YN
    dkim_found: YNU                                       # selectors are not discoverable; unknown is common
    checked_on: date


LOOKUP_MODELS: dict[str, type[_Row]] = {
    "email_domain_check": EmailDomainCheckRow,
}

ALL_TABLE_MODELS: dict[str, type[_Row]] = {**TEMPLATE_MODELS, **LOOKUP_MODELS}


def template_columns(name: str) -> list[str]:
    return list(ALL_TABLE_MODELS[name].model_fields.keys())


# ---------------------------------------------------------------------------
# Rule trigger DSL (declarative; evaluated by engine/evaluate.py in Week 2)
# ---------------------------------------------------------------------------

RowOp = Literal[
    "eq", "ne", "in", "not_in", "gt", "lt", "gte", "lte",
    "older_than_days", "newer_than_days", "is_empty", "not_empty",
    "contains_any", "is_end_of_life", "in_kev",
]


class Where(BaseModel):
    model_config = ConfigDict(extra="forbid")
    col: str
    op: RowOp
    value: str | int | float | list[str | int] | None = None


class AnswerCondition(BaseModel):
    """Fires when a questionnaire answer is one of ``in`` (or, for multi-select
    questions, when the selected set contains any of ``contains_any``)."""

    model_config = ConfigDict(extra="forbid")
    kind: Literal["answer"] = "answer"
    q: str
    in_: list[str] | None = Field(default=None, alias="in")
    contains_any: list[str] | None = None
    lacks_all: list[str] | None = None

    @model_validator(mode="after")
    def _one_test(self):
        if sum(x is not None for x in (self.in_, self.contains_any, self.lacks_all)) != 1:
            raise ValueError("answer condition needs exactly one of: in, contains_any, lacks_all")
        return self


class RowsCondition(BaseModel):
    """Fires based on rows of an uploaded template that match every ``where``.

    match = any  -> fires if at least ``min_count`` rows match (default 1)
    match = none -> fires if the table was uploaded and *no* row matches
    match = ratio -> fires if matching rows / all rows >= ``min_ratio``
    """

    model_config = ConfigDict(extra="forbid")
    kind: Literal["rows"] = "rows"
    table: Literal["users_permissions", "firewall_rules", "patch_inventory", "endpoint_protection", "backup_jobs",
                   "email_domain_check"]
    where: list[Where] = Field(default_factory=list)
    match: Literal["any", "none", "ratio"] = "any"
    min_count: int = 1
    min_ratio: float | None = None

    @model_validator(mode="after")
    def _ratio(self):
        if self.match == "ratio" and self.min_ratio is None:
            raise ValueError("match: ratio requires min_ratio")
        return self


class AllOf(BaseModel):
    model_config = ConfigDict(extra="forbid")
    all_of: list[Trigger]


class AnyOf(BaseModel):
    model_config = ConfigDict(extra="forbid")
    any_of: list[Trigger]


Trigger = Annotated[AnswerCondition | RowsCondition | AllOf | AnyOf, Field(union_mode="left_to_right")]
AllOf.model_rebuild()
AnyOf.model_rebuild()


def iter_conditions(t) -> list:
    """Flatten a trigger tree into its leaf conditions."""
    if isinstance(t, (AnswerCondition, RowsCondition)):
        return [t]
    children = t.all_of if isinstance(t, AllOf) else t.any_of
    out: list = []
    for c in children:
        out.extend(iter_conditions(c))
    return out


# ---------------------------------------------------------------------------
# Rule specification
# ---------------------------------------------------------------------------

SAFEGUARD_RE = re.compile(r"^\d{1,2}\.\d{1,2}$")
ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
CSF_RE = re.compile(r"^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$")


class Fix(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str
    cost_tier: CostTier
    effort: str  # human-readable, e.g. "15 minutes", "2 hours", "1 day"
    effort_minutes: int = Field(gt=0)  # numeric for the Planner's ranking
    who: Who


class RuleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    module: Module
    title: str
    status: Literal["spec", "implemented"] = "spec"
    evidence: Literal["questionnaire", "upload", "both", "lookup"]
    trigger: Trigger
    severity: Severity
    cis_safeguards: list[str] = Field(min_length=1)
    nist_csf: list[str] = Field(default_factory=list)
    attack: list[str] = Field(default_factory=list)
    scenario: str
    finding_plain: str
    finding_technical: str
    fixes: list[Fix] = Field(min_length=1)
    sources: list[str] = Field(min_length=1)  # keys into rules/sources.yaml

    @field_validator("id")
    @classmethod
    def _id_format(cls, v: str) -> str:
        if not re.fullmatch(r"(IAM|NET|PAT|END|BKP)-\d{3}", v):
            raise ValueError(f"rule id {v!r} must look like IAM-001")
        return v

    @field_validator("cis_safeguards")
    @classmethod
    def _sg(cls, v):
        for s in v:
            if not SAFEGUARD_RE.match(s):
                raise ValueError(f"bad CIS safeguard id {s!r}")
        return v

    @field_validator("nist_csf")
    @classmethod
    def _csf(cls, v):
        for s in v:
            if not CSF_RE.match(s):
                raise ValueError(f"bad NIST CSF 2.0 subcategory {s!r}")
        return v

    @field_validator("attack")
    @classmethod
    def _attack(cls, v):
        for s in v:
            if not ATTACK_RE.match(s):
                raise ValueError(f"bad ATT&CK technique id {s!r}")
        return v

    @model_validator(mode="after")
    def _prefix_matches_module(self):
        if not self.id.startswith(MODULE_PREFIX[self.module]):
            raise ValueError(f"{self.id} prefix does not match module {self.module.value}")
        leaves = iter_conditions(self.trigger)
        has_q = any(isinstance(c, AnswerCondition) for c in leaves)
        has_u = any(isinstance(c, RowsCondition) and c.table in TEMPLATE_MODELS for c in leaves)
        has_l = any(isinstance(c, RowsCondition) and c.table in LOOKUP_MODELS for c in leaves)
        if has_l and (has_q or has_u):
            raise ValueError(f"{self.id}: lookup rules must not mix with questionnaire/upload conditions")
        actual = "lookup" if has_l else ("both" if has_q and has_u else ("questionnaire" if has_q else "upload"))
        if actual != self.evidence:
            raise ValueError(f"{self.id}: evidence={self.evidence} but trigger uses {actual}")
        return self


class RuleFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    module: Module
    version: str
    rules: list[RuleSpec]


# ---------------------------------------------------------------------------
# Disruption scenarios (Appendix D)
# ---------------------------------------------------------------------------


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    name: str
    description_plain: str
    downtime_days_low: float = Field(ge=0)
    downtime_days_high: float = Field(ge=0)
    recovery_cost_usd: int = Field(ge=0)
    is_multiplier: bool = False
    extra_days_low: float = 0
    extra_days_high: float = 0
    systems_affected: list[str]
    attack: list[str] = Field(default_factory=list)
    text_flags: list[str] = Field(default_factory=list)
    calibration_status: Literal["placeholder", "calibrated"] = "placeholder"
    source_notes: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def _range(self):
        if self.downtime_days_high < self.downtime_days_low:
            raise ValueError(f"{self.key}: high < low")
        return self


class ScenarioFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    scenarios: list[Scenario]


# ---------------------------------------------------------------------------
# Week 1 extensions: text-only legal flags, insurance readiness, benchmarks
# ---------------------------------------------------------------------------


class LegalFlag(BaseModel):
    """A plain-language notice (never a dollar figure, never legal advice)."""

    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^LEG-\d{3}$")
    title: str
    jurisdiction: Literal["Illinois", "Chicago", "United States", "Card brands (PCI SSC)"]
    trigger: Trigger
    notice_plain: str
    what_to_do: list[str] = Field(min_length=1)
    citation: str
    source_urls: list[str] = Field(min_length=1)
    verified_on: date
    disclaimer_key: Literal["not_legal_advice"] = "not_legal_advice"


class LegalFlagFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    flags: list[LegalFlag]


class InsuranceControl(BaseModel):
    """A control commonly asked about on cyber-insurance applications.

    status is READY when none of ``gap_if_rules`` fired, GAP otherwise,
    UNKNOWN when none of the rules could be evaluated.
    """

    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^INS-\d{2}$")
    control: str
    typical_application_question: str
    gap_if_rules: list[str] = Field(min_length=1)
    why_insurers_ask: str
    sources: list[str] = Field(min_length=1)


class InsuranceFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    caveat: str
    controls: list[InsuranceControl]


class BenchmarkLink(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str
    metric_ids: list[str] = Field(min_length=1)
    owner_sentence: str  # template with {value_pct}, {publisher}, {fieldwork}


class BenchmarkFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    principle: str
    links: list[BenchmarkLink]
