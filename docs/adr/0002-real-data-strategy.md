# ADR 0002 — Real public data, fictional businesses

**Status:** accepted (Week 1)

**Context.** The builder asked to use real-world data instead of purely synthetic data. The brief forbids storing any real business's data, in the repository or anywhere else.

**Decision.** Use real, public, dated data for everything that is *not* a business's private data:
endoflife.date lifecycles, the CISA KEV catalog, CIS v8.1 IG1 safeguards, MITRE ATT&CK technique metadata, City of Chicago active license counts (aggregates only), and published loss statistics (FBI IC3, Verizon DBIR, IBM) for Planner calibration. The sample businesses are fictional but run real products with real end-of-life dates and real KEV entries.

The builder may additionally run the read-only export scripts on **his own** lab machines to produce genuine exports for parser testing; those files stay outside the repository (`.gitignore` covers them).

**Consequences.** Findings on sample data are realistic and defensible. Snapshots must be refreshed (`tools/refresh_reference_data.py`, monthly) and each row carries its source and snapshot date. Live calls to these sites from the app are not allowed (reliability, privacy, free hosting).
