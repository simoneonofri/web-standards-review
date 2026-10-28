---
name: w3c-horizontal-review-patterns-miner
description: Classify a specification and select recurring TAG, privacy and security review questions while separating precedents, findings and verified resolutions. Also use for bounded author support during design and drafting.
---

# Horizontal review patterns

<!-- section:scope -->
Use normalized W3C Knowledge evidence or an explicitly dated exported packet. The caller supplies normalized target evidence; this skill selects review patterns rather than fetching raw sources. A historical match alone does not establish a defect in the current target. Bundled patterns include seed and derived records whose primary evidence must be rechecked; detailed historical mining caches are excluded.

<!-- section:author-support -->
## Author support

Use this mode when an author asks for help designing, drafting or revising a specification or charter, including before a review request exists. Start from the exact draft and the author's concrete question. Profile the draft and attach relevant historical design, privacy and security questions to its actual design decisions. Historical questions do not predict review acceptance.

Return a compact table: target section or design decision; selected source and applicability; proposed author action; verification or test; evidence status (`evidence_supported`, `open_question`, `already_covered`, `not_applicable`, `unable_to_verify`). Keep normative requirements distinct from optional design choices and reviewer inference. Use the existing evidence rules and helper inputs below; unavailable sources stay unavailable.

Keep the response proportional to the question. Preserve the draft unless editing is requested. This mode does not itself start a full horizontal review, complete threat model, scanner run, corpus refresh or publication workflow. Route a substantiated review candidate through the existing finding gate rather than treating an author suggestion as a finding.

<!-- section:workflow -->
Read `references/specification-taxonomy.json` and build a profile from the supplied normalized evidence of actual target behavior, not its title alone. Record one primary family, secondary families and facets. Run `python3 scripts/select_patterns.py --input /path/to/profile.json` from this skill directory. Inspect selected records in `references/review-patterns.json` and use `references/finding-model.md` and `references/evidence-and-confidence.md` for evidence normalization.

Evaluate TAG/design, privacy and security separately. Extract one atomic concern per finding and link it to source text, review comments, replies and any implemented resolution. Classify each selected pattern as confirmed, possible, covered, not-applicable or unknown. Missing checklist answers remain questions until target evidence supports a defect. Run `python3 scripts/validate_assets.py` after changes to bundled patterns, taxonomy or shape examples.

<!-- section:evidence-contract protected -->
Return the exact specification/profile, selected pattern IDs, target-specific questions, findings, per-domain coverage, missing evidence and limitations. Preserve normative expectations, observed reviewer concerns and validated resolutions as different evidence classes. No reviewer comment, issue closure or label alone establishes group consensus or completion. Supply new reviewed pattern proposals through the repository contribution flow; unavailable historical evidence remains `unable_to_verify`.
