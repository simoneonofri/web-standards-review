---
name: w3c-security-pattern-miner
description: Mine one exact specification version for source-grounded security observations, derived patterns and actionable checks, or apply the reviewed check catalog. Also use for bounded author support during design and drafting.
---

# Specification security patterns

<!-- section:scope -->
Process one specification ID and version. Consume a complete W3C Knowledge packet or explicitly scoped source artifact. Missing coverage remains `unknown`; this layer does not replace ingestion, broad horizontal orchestration or implementation review.

<!-- section:author-support -->
## Author support

Use this mode when an author asks for help designing, drafting or revising a specification or charter, including before a review request exists. Start from the exact draft and the author's concrete question. Extract the exact draft's control intent and conditions, then suggest a test, clarification or candidate reusable pattern without asserting a confirmed gap.

Return a compact table: target section or design decision; selected source and applicability; proposed author action; verification or test; evidence status (`evidence_supported`, `open_question`, `already_covered`, `not_applicable`, `unable_to_verify`). Keep normative requirements distinct from optional design choices and reviewer inference. Use the existing evidence rules and helper inputs below; unavailable sources stay unavailable.

Keep the response proportional to the question. Preserve the draft unless editing is requested. This mode does not itself start a full horizontal review, complete threat model, scanner run, corpus refresh or publication workflow. Route a substantiated review candidate through the existing finding gate rather than treating an author suggestion as a finding.

<!-- section:workflow -->
Read `references/extraction-method.md` and `references/w3c-knowledge-contract.md`. Establish scope, construct a security surface profile, extract observations across the source, then run the lens pass in `references/security-taxonomy.json`. Consult existing catalog records after source-first extraction. Read `references/implicit-pattern-inference.md` before deriving an implicit pattern and retain every derivation step and assumption.

Adversarially check each observation against counterevidence and applicability. Use the observation, pattern and check models in `references/` to normalize outputs. `scripts/normalize_result.py` validates a mining result; `scripts/select_checks.py` selects catalog checks; `scripts/render_checklist.py` renders selected checks. Consult their `--help` for exact arguments. Treat selectors as candidate routing, not target verification.

Before catalog changes read `references/catalog-policy.md` and copy the catalog to a caller-controlled external workspace. Preview `scripts/merge_catalog.py --catalog /path/to/catalog --result /path/to/result.json --dry-run`; review occurrences and evidence before applying it there. Run `python3 scripts/validate_assets.py` after editing the source package's taxonomy, schemas, fixtures or catalog. Patterns do not become validated because a merge succeeded.

<!-- section:evidence-contract protected -->
Keep explicit normative requirements, informative guidance, derived candidates, hypotheses, review observations and inherited assumptions distinct. A `fail` requires affirmative target evidence, not missing Security Considerations or an unsuccessful search. Preserve source IDs, exact locators, evidence spans and versions. Return `pass`, `partial`, `fail`, `unknown`, `not-applicable` or `not-evaluated`, then let `w3c-horizontal-review` determine finding ownership and publication readiness.
