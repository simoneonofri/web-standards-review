---
name: whatwg-miner
description: Extract and compare WHATWG security controls, defaults, exceptions and cross-spec dependencies from versioned official snapshots. Also use for bounded author support during design and drafting.
---

# WHATWG controls

<!-- section:scope -->
Read `references/schema.md` and `catalog/coverage.json`. The bundled catalog is a dated selection; zero curated controls does not establish irrelevance or completeness. The official index determines the inventory, whose additions and removals must remain visible.

<!-- section:author-support -->
## Author support

Use this mode when an author asks for help designing, drafting or revising a specification or charter, including before a review request exists. Start from the exact draft and the author's concrete question. Check how a proposed design composes with existing platform algorithms, origin checks, lifecycle rules and cross-spec dependencies.

Return a compact table: target section or design decision; selected source and applicability; proposed author action; verification or test; evidence status (`evidence_supported`, `open_question`, `already_covered`, `not_applicable`, `unable_to_verify`). Keep normative requirements distinct from optional design choices and reviewer inference. Use the existing evidence rules and helper inputs below; unavailable sources stay unavailable.

Keep the response proportional to the question. Preserve the draft unless editing is requested. This mode does not itself start a full horizontal review, complete threat model, scanner run, corpus refresh or publication workflow. Route a substantiated review candidate through the existing finding gate rather than treating an author suggestion as a finding.

<!-- section:workflow -->
Use `scripts/query_catalog.py --help` to select `catalog/security-features.json` records by standard or category. Read the exact official anchor before applying a record to a target. Distinguish a security boundary, authority check, isolation or integrity property from generic parsing, queuing or exception mechanics. Record secure defaults and failure behavior separately and follow cross-spec invocations to their own snapshots.

For an explicitly needed refresh, run `python3 scripts/refresh.py --artifacts /path/to/run/whatwg-sources --output-dir /path/to/run/whatwg-catalog`. Add `--offline` to rebuild from a complete saved source inventory. The output directory must be new and outside the package. Review differences against the bundled catalog; do not replace an installed snapshot automatically. The raw sources and keyword mining candidates remain local discovery material.

<!-- section:evidence-contract protected -->
Return standard, snapshot/hash, section URL, category, evidence class, normative strength, applicability, default, failure/exception behavior, dependencies and limitations. Separate semantic summaries from exact quotations. A specification statement does not establish implementation behavior. Return candidates to `w3c-horizontal-review`; retain `not_applicable` and `unable_to_verify` with reasons.
