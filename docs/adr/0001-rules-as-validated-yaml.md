# ADR 0001 — Rules are validated YAML; the XLSX mapping sheet is generated from them

**Status:** accepted (Week 1) · **Decider:** G. Reddymalla

**Context.** The brief makes the mapping sheet "the product specification". A hand-maintained spreadsheet and separate YAML rules would drift.

**Decision.** `rules/*.yaml` is the single source of truth, validated by Pydantic (`engine/schemas.py`). `tools/build_mapping_sheet.py` generates `docs/mapping/CIS_IG1_mapping.xlsx`, including live formulas for counts and IG1 coverage. CI rebuilds it on every push.

**Consequences.** Non-developers review the XLSX; changes go through the YAML. The trigger is written once, in a declarative form the engine executes in Week 2.
