# ADR 0005 — Severity weights 10 / 6 / 3 / 1

**Status:** proposed (Week 1), to be confirmed at Gate 1

**Decision.** critical 10, high 6, medium 3, low 1. A single critical finding outweighs three mediums, matching how an owner should prioritize (one open remote-desktop port matters more than three missing lists).

**Validation plan.** In Week 4, compute scores for the four sample businesses; expected ordering: pantry (Resilient) > taqueria > daycare ≈ salon. If the ordering is wrong, tune weights before tuning rules.
