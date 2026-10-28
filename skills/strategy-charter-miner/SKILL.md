---
name: strategy-charter-miner
description: Extract traceable questions from W3C Strategy charter discussions and apply relevant precedents to a current charter or recharter review. Also use for bounded author support during design and drafting.
---

# Charter review precedents

<!-- section:scope -->
Use for an actual charter or recharter, including Strategy issues labeled `charter` and diffs changing charter commitments or deliverables. A normal specification issue does not enter this route merely because it mentions a Working Group. No personal Google document or historical discussion export is bundled.

<!-- section:author-support -->
## Author support

Use this mode when an author asks for help designing, drafting or revising a specification or charter, including before a review request exists. Start from the exact draft and the author's concrete question. Help charter authors explain scope, coordination, deliverables and success criteria using relevant precedents. Keep API implementation details in deliverable workflows.

Return a compact table: target section or design decision; selected source and applicability; proposed author action; verification or test; evidence status (`evidence_supported`, `open_question`, `already_covered`, `not_applicable`, `unable_to_verify`). Keep normative requirements distinct from optional design choices and reviewer inference. Use the existing evidence rules and helper inputs below; unavailable sources stay unavailable.

Keep the response proportional to the question. Preserve the draft unless editing is requested. This mode does not itself start a full horizontal review, complete threat model, scanner run, corpus refresh or publication workflow. Route a substantiated review candidate through the existing finding gate rather than treating an author suggestion as a finding.

<!-- section:workflow -->
Inspect the complete current Strategy discussion and its paginated comments first; preserve exact Security feedback and trace replies or resolutions so new questions do not duplicate existing work. Resolve the candidate charter revision, immediately preceding charter, current template and same-cycle review trackers.

For historical question extraction, run `python3 scripts/update_catalog.py --input /path/to/issues-and-comments.json --json-output /path/to/run/charter-questions.json --markdown-output /path/to/run/charter-questions.md`. Omitting `--input` uses the caller's `gh` CLI for read-only public `w3c/strategy` retrieval. Output paths are explicit and external. The extractor requires both a review label and an explicit group signal for attribution; this is a heuristic, not proof of reviewer authority or consensus.

Select applicable question types, preserve source comment permalinks and attribution basis, then ask the question against current-target evidence. Retain rejected precedents with a reason. Hand the target and comparisons to `w3c-horizontal-review` for independent design, security, privacy, accessibility and internationalization status checks. Missing historical coverage does not prevent an evidence-driven new question.

<!-- section:evidence-contract protected -->
Separate current-target facts, historical prompts, reviewer inference, group conclusions and administrative labels. A closed issue is not a completed review. Severity follows the actual supported consequence and the team's explicit policy; neither any template divergence nor a catalog label automatically establishes criticality. Save results outside the package and contribute reviewed generic extraction changes through the shared repository.
