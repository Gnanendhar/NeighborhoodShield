# ADR 0006 — Ten extensions beyond the brief, cut first if time runs short

**Status:** accepted by the builder (Week 1); to be confirmed with Benjamin at Gate 1

**Context.** The builder wants the project to go beyond the brief while still covering it, and to feel real by using real-world data.

**Decision.** Add ten extensions (docs/extensions.md): email domain check, Illinois/Chicago legal flags, insurance readiness, calendar reminders, a "bad day" card, workshop mode, monthly data refresh, free-tool links, a safe leaked-password check, and published-survey benchmarks. This adds 4 rules (58 → 62, above the brief's 40-to-60 range on purpose), 3 Full-Assessment questions (49 → 52; the Quick Check stays at 36), and 6 reference datasets.

**Guardrails kept.** Free tools only; no scanning of customer networks (the email check reads public DNS only); no server-side storage; no required AI model; no dollar figures for legal exposure.

**Time.** About 32 extra hours on a 75-hour plan. Extensions sit above the brief's scope-cut list and are cut first, in the order 6, 10, 3, 8, 4, 2, 9, 5, 1, 7.
