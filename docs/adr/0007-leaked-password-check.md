# ADR 0007 — Leaked-password check that never collects a password

**Status:** accepted (Week 1)

**Context.** Checking for leaked credentials is valuable, but a site that asks for passwords teaches owners the habit phishers rely on.

**Decision.** (1) The questionnaire asks only whether a check was done (IAM-016). (2) The plan points to checkers the owner already has (Google Password Checkup, Edge Password Monitor, Apple Passwords, Bitwarden) and to Have I Been Pwned breach alerts for business email addresses. (3) An optional stretch component hashes in the browser and sends only a 5-character SHA-1 prefix to the Pwned Passwords range API (k-anonymity). The password never reaches our server, and a test asserts the server has no input that could receive it.

**Rejected.** Server-side password entry; the paid HIBP breached-account API (violates "free to run").
