---
name: w3c-spec-miner
description: Compare source-derived W3C protection patterns and as-is models across the locally available Technical Report corpus, with explicit coverage and editorial-gap handling. Also use for bounded author support during design and drafting.
---

# W3C corpus comparison

<!-- section:scope -->
Read `references/method.md` and `references/schema.md`. Build the target's as-is model from its own exact snapshot before consulting other specifications. This portable package includes pattern definitions and mining code; colleagues generate their own corpus observations. No maintainer database or captured specification corpus is included.

<!-- section:author-support -->
## Author support

Use this mode when an author asks for help designing, drafting or revising a specification or charter, including before a review request exists. Start from the exact draft and the author's concrete question. Compare a draft with observed protections in other specifications. Separate changing behavior from documenting an existing protection in Security or Privacy Considerations.

Return a compact table: target section or design decision; selected source and applicability; proposed author action; verification or test; evidence status (`evidence_supported`, `open_question`, `already_covered`, `not_applicable`, `unable_to_verify`). Keep normative requirements distinct from optional design choices and reviewer inference. Use the existing evidence rules and helper inputs below; unavailable sources stay unavailable.

Keep the response proportional to the question. Preserve the draft unless editing is requested. This mode does not itself start a full horizontal review, complete threat model, scanner run, corpus refresh or publication workflow. Route a substantiated review candidate through the existing finding gate rather than treating an author suggestion as a finding.

<!-- section:workflow -->
Run `python3 scripts/refresh.py --api-url "$W3C_KNOWLEDGE_URL" --output /path/to/run/w3c-patterns` from this skill directory when a corpus refresh is requested or necessary. The API base is caller-selected. The output must be a new external directory. The helper uses the package's full-source capture validation, filters sections to their exact version and records failures instead of treating a partial packet as complete. Coverage is relative to the local service's eligible specification inventory, not proof that every W3C publication is present.

Read generated `coverage.json` before `protection-catalog.json`, `protection-observations.jsonl`, `threat-models.jsonl` and `security-considerations-gaps.jsonl`. Check artifacts with `python3 scripts/validate.py --references /path/to/run/w3c-patterns`. Select a small relevant set of patterns; for each preserve source snapshot, section, hash, default, exceptions, normative strength and target applicability. Reuse a previous generation only with its recorded date and coverage, and compare generations without overwriting the earlier manifest.

<!-- section:evidence-contract protected -->
Frequency is not consensus or a requirement on the target. Imported patterns start `not_evaluated`. A protection implemented in normative behavior but omitted from Security Considerations is `editorial_non_blocking` unless a separately evidenced technical threat supports a stronger finding. Send technical candidates to `w3c-horizontal-review` and `spec-review` for reconciliation and appropriate PoC evidence.
