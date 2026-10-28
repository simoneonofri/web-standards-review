---
name: w3c-webappsec-miner
description: Select traceable WebAppSec controls, defaults and exceptions for a Web API review using the pinned charter and deliverable catalogs. Also use for bounded author support during design and drafting.
---

# WebAppSec controls

<!-- section:scope -->
Use this layer for platform controls such as secure contexts, permission checks, policy delegation, resource integrity and script restrictions. Read `references/method.md`; the catalog is a discovery aid tied to the charter snapshot in `references/charter-deliverables.json`, not a timeless account of Working Group scope.

<!-- section:author-support -->
## Author support

Use this mode when an author asks for help designing, drafting or revising a specification or charter, including before a review request exists. Start from the exact draft and the author's concrete question. Choose an existing platform mechanism for a concrete API entry point, then explain defaults, delegation, failure behavior and exceptions.

Return a compact table: target section or design decision; selected source and applicability; proposed author action; verification or test; evidence status (`evidence_supported`, `open_question`, `already_covered`, `not_applicable`, `unable_to_verify`). Keep normative requirements distinct from optional design choices and reviewer inference. Use the existing evidence rules and helper inputs below; unavailable sources stay unavailable.

Keep the response proportional to the question. Preserve the draft unless editing is requested. This mode does not itself start a full horizontal review, complete threat model, scanner run, corpus refresh or publication workflow. Route a substantiated review candidate through the existing finding gate rather than treating an author suggestion as a finding.

<!-- section:workflow -->
Run `python3 scripts/query_catalog.py --facet powerful-feature --json` from this skill directory, choosing a facet matching the target. Inspect `catalog/security-controls.json`, `catalog/secure-defaults.json` and `catalog/exceptions.json` together. For each selected control, read its exact primary section and verify applicability, normative force, prerequisites, default, failure behavior and opt-outs against the frozen target. The charter establishes scope; it does not prove mechanism behavior.

Return `control_id`, target disposition (`pass`, `partial`, `fail`, `unknown`, `not-applicable`, `not-evaluated`), rationale, exact evidence URL/ID and hash, normative strength, default and exception IDs, and residual uncertainty. Keep an informative recommendation or cross-spec synthesis distinct from a normative requirement. Validate catalog edits with `python3 scripts/validate_catalog.py`; use `scripts/extract_charter.py` on an explicitly selected charter snapshot to review scope changes.

<!-- section:evidence-contract protected -->
Preserve source dates and hashes. A catalog match is not a vulnerability, browser support claim, or group conclusion. Send target-specific candidates to `w3c-horizontal-review`, which owns reconciliation and finding promotion. Keep source captures and generated catalogs in a caller-selected directory outside the installed package; contributions are reviewed changes to the source checkout.
