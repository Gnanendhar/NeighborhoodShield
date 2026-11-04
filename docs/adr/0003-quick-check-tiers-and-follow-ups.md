# ADR 0003 — Two questionnaire tiers with conditional follow-ups

**Status:** accepted (Week 1)

**Context.** The brief targets 30 to 36 questions in about ten minutes, but several important controls (payment call-back, account list, DNS filtering, incident owner) are not in Appendix A.

**Decision.** Each question is tagged `core` (Quick Check) or `extended` (Full Assessment), and follow-ups use `show_if`. Quick Check: 36 core questions, 32 always shown. Full Assessment: 49.

**Consequences.** The workshop path stays fast; the paid path is more thorough, which also supports the pricing tiers in brief §10. Rules that depend only on extended questions simply do not fire in a Quick Check, and the scoring denominator excludes them (design.md §6).
