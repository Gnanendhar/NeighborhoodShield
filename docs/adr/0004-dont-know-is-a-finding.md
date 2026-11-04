# ADR 0004 — "Don't know" fires the finding for protective controls

**Status:** accepted (Week 1)

**Decision.** For questions about a protective control (MFA on, backups tested, router updated), "Don't know" fires the same rule as "No", with the same severity. The finding text and fix tell the owner how to check.

**Rationale.** The brief: "'Don't know' is itself a finding." An unverified control cannot be relied on during an incident. Exception: questions about the *presence of a risk* (e.g. remote access used) treat "Don't know" as possible exposure only where the follow-up confirms it.

**Revisit** after the Week 7 pilots if owners feel penalized for honesty; option: a separate "unverified" label at lower weight.
