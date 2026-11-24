# ADR 0005 — Severity weights 10 / 6 / 3 / 1

**Status:** accepted; validated on the sample businesses (2026-11-24)

**Decision.** critical 10, high 6, medium 3, low 1. A single critical finding outweighs three mediums, matching how an owner should prioritize (one open remote-desktop port matters more than three missing lists).

**Validation plan.** In Week 4, compute scores for the four sample businesses; expected ordering: pantry (Resilient) > taqueria > daycare ≈ salon. If the ordering is wrong, tune weights before tuning rules.

**Validation result (2026-11-24).** Overall scores with files: pantry 99 (Resilient), taqueria 49, daycare 33, salon 27 (all three Exposed). Quick Check without files: pantry 98, taqueria 44, daycare 41, salon 35. The expected ordering holds in both, so the weights stay as proposed. `tests/test_score.py` keeps it that way.
