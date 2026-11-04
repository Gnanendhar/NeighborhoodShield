"""Load and validate the rule catalog, scenarios, sources, and strings.

A malformed rule fails loudly at import time of the app (fail-fast by design).
"""

from __future__ import annotations

from functools import cache
from pathlib import Path

import yaml

from .paths import CONTENT_DIR, RULES_DIR
from .schemas import RuleFile, RuleSpec, Scenario, ScenarioFile

MODULE_FILES = ["identity.yaml", "network.yaml", "patching.yaml", "endpoint.yaml", "recovery.yaml"]


class CatalogError(ValueError):
    """Raised when the rule catalog is inconsistent."""


def _read(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@cache
def load_strings(locale: str = "en") -> dict:
    name = "strings.yaml" if locale == "en" else f"strings.{locale}.yaml"
    return _read(CONTENT_DIR / name)


@cache
def load_sources() -> dict[str, dict]:
    return _read(RULES_DIR / "sources.yaml")["sources"]


@cache
def load_scenarios() -> dict[str, Scenario]:
    sf = ScenarioFile.model_validate(_read(RULES_DIR / "scenarios.yaml"))
    return {s.key: s for s in sf.scenarios}


@cache
def load_rules(rules_dir: Path = RULES_DIR) -> tuple[RuleSpec, ...]:
    rules: list[RuleSpec] = []
    for fname in MODULE_FILES:
        rf = RuleFile.model_validate(_read(rules_dir / fname))
        for r in rf.rules:
            if r.module != rf.module:
                raise CatalogError(f"{r.id} is in {fname} but declares module {r.module.value}")
        rules.extend(rf.rules)
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise CatalogError(f"duplicate rule ids: {sorted(dupes)}")
    return tuple(rules)


# --------------------------------------------------------------- extensions
@cache
def load_legal_flags():
    from .schemas import LegalFlagFile

    return LegalFlagFile.model_validate(_read(RULES_DIR / "legal_flags.yaml")).flags


@cache
def load_insurance_controls():
    from .schemas import InsuranceFile

    return InsuranceFile.model_validate(_read(RULES_DIR / "insurance_readiness.yaml"))


@cache
def load_benchmark_links():
    from .schemas import BenchmarkFile

    return BenchmarkFile.model_validate(_read(RULES_DIR / "benchmarks.yaml"))
