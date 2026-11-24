"""Turn rule results into a 0-100 score per area and an overall posture tier.

Module score (docs/design.md section 6):

    100 - 100 x (sum of weights of rules that fired) / (sum of weights of rules that could be checked)

with weights critical 10, high 6, medium 3, low 1 (ADR 0005). Rules that could
not be checked (a skipped answer, a file not uploaded) are left out of both
sums, so a Quick Check is not penalized for missing files.

Posture tier, worst first (thresholds checked against the sample businesses;
see tests/test_score.py and ADR 0005):

    Exposed     2 or more critical findings, or any area below 40
    Fragile     1 critical finding, or any area below 60
    Developing  any area below 80
    Resilient   every area 80 or above and no critical finding

The tier needs every area to have a score; otherwise there is not enough
information and no tier is given.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

from .evaluate import RuleResult
from .schemas import SEVERITY_WEIGHT, Module, Severity

Tier = Literal["exposed", "fragile", "developing", "resilient"]
TIERS: tuple[Tier, ...] = ("exposed", "fragile", "developing", "resilient")

EXPOSED_CRITICALS = 2
EXPOSED_BELOW = 40
FRAGILE_BELOW = 60
DEVELOPING_BELOW = 80


@dataclass
class ModuleScore:
    module: Module
    score: int | None          # None when no rule in this area could be checked
    fired: int = 0
    checked: int = 0
    total: int = 0
    critical: int = 0
    fired_weight: int = 0
    checked_weight: int = 0


@dataclass
class Scorecard:
    modules: dict[Module, ModuleScore] = field(default_factory=dict)
    overall: int | None = None   # same formula across every area
    tier: Tier | None = None
    critical: int = 0
    reason: str = ""             # one plain sentence on why this tier

    @property
    def complete(self) -> bool:
        return all(m.score is not None for m in self.modules.values())

    @property
    def lowest(self) -> ModuleScore | None:
        scored = [m for m in self.modules.values() if m.score is not None]
        return min(scored, key=lambda m: m.score) if scored else None


def _pct(fired_w: int, checked_w: int) -> int | None:
    if checked_w == 0:
        return None
    return round(100 - 100 * fired_w / checked_w)


def tier_for(lowest: int, critical: int) -> tuple[Tier, str]:
    if critical >= EXPOSED_CRITICALS:
        return "exposed", f"{critical} findings need fixing now."
    if lowest < EXPOSED_BELOW:
        return "exposed", f"At least one area scored below {EXPOSED_BELOW}."
    if critical == 1:
        return "fragile", "One finding needs fixing now."
    if lowest < FRAGILE_BELOW:
        return "fragile", f"At least one area scored below {FRAGILE_BELOW}."
    if lowest < DEVELOPING_BELOW:
        return "developing", f"Every area scored {FRAGILE_BELOW} or more, but at least one is below {DEVELOPING_BELOW}."
    return "resilient", f"Every area scored {DEVELOPING_BELOW} or more and nothing needs fixing now."


def score(results: Iterable[RuleResult]) -> Scorecard:
    results = list(results)
    card = Scorecard()
    for m in Module:
        rs = [r for r in results if r.rule.module == m]
        if not rs:
            continue
        checked = [r for r in rs if r.status != "not_evaluated"]
        fired = [r for r in checked if r.fired]
        fw = sum(SEVERITY_WEIGHT[r.rule.severity] for r in fired)
        cw = sum(SEVERITY_WEIGHT[r.rule.severity] for r in checked)
        card.modules[m] = ModuleScore(
            module=m, score=_pct(fw, cw), fired=len(fired), checked=len(checked), total=len(rs),
            critical=sum(r.rule.severity == Severity.critical for r in fired), fired_weight=fw, checked_weight=cw)
    card.critical = sum(ms.critical for ms in card.modules.values())
    card.overall = _pct(sum(ms.fired_weight for ms in card.modules.values()),
                        sum(ms.checked_weight for ms in card.modules.values()))
    if card.modules and card.complete:
        card.tier, card.reason = tier_for(card.lowest.score, card.critical)
    else:
        card.reason = "Not enough answers yet: every area needs at least one answer to give a tier."
    return card
