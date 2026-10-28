---
name: w3c-spec-code
description: Map one specification feature bidirectionally to pinned implementation files and tests, with explicit ownership and coverage of discrepancies.
---

# Specification and implementation mapping

<!-- section:scope -->
Require the target snapshot and stable anchors. Discover relevant implementation and test repositories from verified metadata when not supplied, and pin their commits. If none can be resolved, return an unavailable target state and explicit limitations. This is a feature review; do not expand to a whole browser or generic subsystem based on keywords.

<!-- section:workflow -->
Read `references/feature-scope.md` and `references/feature-scope.schema.json`. Identify concrete entry points, owned paths, directly supporting dependencies with call/data/control evidence, exclusions and file/byte budgets. Run `python3 scripts/materialize_pinned_scope.py --repo /path/to/checkout --manifest /path/to/feature-scope.json --out /path/to/new-packet`. It verifies selected bytes against the exact Git revision; the lower-level materializer alone does not establish that correspondence.

Read `references/method.md` and `references/artifact-contract.md`. Inventory specification controls, normative force, protected properties, prerequisites, defaults, exceptions and expected failure/tests. Map each to code and tests; then map implementation controls back to the specification. Keep required controls, platform dependencies, implementation-specific defenses, compensating controls and candidate missing specification requirements distinct. Preserve one-to-many mappings and counterevidence.

Produce the integrated model described in `references/integrated-threat-model.md` and validate `review-bundle.json` with `python3 scripts/validate_review_bundle.py /path/to/review-bundle.json`. Classify discrepancies as specification defect, implementation defect, divergence, ambiguity, test gap, non-issue, not applicable or unable to verify. A missing public implementation is not evidence of absence.

<!-- section:scanner-boundary protected -->
An external security scanner is optional supplementary evidence. Use one only when the user explicitly requests that capability and the exact feature scope is authorized. Otherwise record `scan.status: not_requested`. Do not install or invoke a named security plugin because it appears in this workflow. The baseline mapping can complete without a scan. Keep scanner candidates subordinate to source evidence and ownership analysis.

<!-- section:evidence-contract protected -->
Keep implementation repositories unchanged. Dynamic tests or PoCs must use the caller's authorized isolated environment. Report runtime behavior as verified only when actually observed at that layer. Return the pinned target/control matrix, bidirectional mappings, consistency ledger, implementation vulnerability ledger, optional scan state, counterevidence and coverage to `w3c-horizontal-review`; that layer owns specification finding promotion.
