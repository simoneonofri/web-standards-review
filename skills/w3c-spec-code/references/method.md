# Specification-to-code method

## Evidence layers

Keep these layers separate throughout the review:

1. Specification evidence: exact normative text, algorithms, WebIDL, defaults, exceptions, dependencies, failure behavior, and stated security or privacy properties.
2. Implementation evidence: pinned files, symbols, bindings, bridges, configuration, runtime guards, engine tests, WPT, commits, issues, and observed behavior.
3. Scanner evidence: the exact Codex Security target, plugin version, skill, coverage, candidates, validated findings, deferred surfaces, and artifact hashes.
4. Review judgment: discrepancy ownership, target-specific threat or privacy path, affected property or stakeholder, bounded impact, counterevidence, confidence, and remaining proof gap.

Do not let evidence at one layer silently decide another. A normative requirement does not prove implementation conformance; an implementation guard does not prove that the specification requires it; a scanner finding does not prove a specification defect.

## Required order

1. Freeze the specification and discover every applicable implementation by default. Record the specification URL, revision, section hashes, repository identity, revision, selected paths, feature flags, test revision, and evidence-access state. If no implementation target can be resolved, preserve an unavailable target state and continue to an explicit coverage-limited bundle.
2. Build the specification control inventory. Give each control a stable ID and record its anchor, protected property, actor or stakeholder, trigger, preconditions, behavior, default, exception, failure semantics, dependency, observable result, and expected tests.
3. Build the initial code map. Start from specification interfaces and algorithms, then follow bindings, dispatch, IPC, platform adapters, state transitions, enforcement points, sinks, failure paths, configuration, and tests. Record exact file and symbol anchors.
4. Complete the specification-to-code pass for every control and pinned implementation. Use `absent` only after the selected public source and relevant indirection were inspected; otherwise use `non_public` or `unable_to_verify`.
5. Complete the code-to-spec pass. Inspect validation, normalization, origin or site checks, permissions, user mediation, sandboxing, isolation, lifecycle enforcement, failure handling, rate or resource controls, and compensating defenses. Decide whether each belongs to the specification, the implementation, a platform dependency, or unresolved research.
6. Record scanner evidence only when the user explicitly requests a scan. Without that request, set scan.status to not_requested and complete the specification-to-code baseline independently. If requested, verify the exact repository, bounded source scope, and authorization before invoking the scanner; preserve unavailable or failed preconditions as evidence.
7. Reconcile within and across implementations. Prefer direct source and tests over comments or issue summaries; preserve contrary evidence and discrepancies between code, tests, documentation, and runtime observations.
8. Classify ownership before escalation: `specification`, `implementation`, `interoperability`, `test`, `editorial`, `research_hypothesis`, or `unable_to_verify`.

## Specification-gap gate

A code-side control becomes `candidate_missing_spec_requirement` only when all of the following are recorded:

- a target-specific security, privacy, or harms property;
- a concrete path showing why the property depends on interoperable or specification-level behavior;
- evidence that the control is not merely implementation-specific defense in depth or a platform dependency;
- the strongest counterevidence;
- a bounded consequence if another conforming implementation omits the control;
- proposed ownership and the evidence still needed.

Until this gate is met, keep the control as implementation evidence or a research hypothesis.

## Cross-implementation comparison

Compare Chromium/Blink, Gecko, WebKit, WPT, and other relevant implementations only at pinned revisions. Treat source availability, architecture, test placement, release status, and feature flags as separate dimensions. Do not substitute one engine's implementation for another or infer browser behavior from a shared test alone.

## Horizontal-review gate

Return the reconciled bundle to `w3c-horizontal-review`. Promotion requires target-specific evidence, an explicit threat or privacy path, an affected property or stakeholder, bounded impact, ownership, and any required PoC status. Report `not_applicable`, `unable_to_verify`, `non_issue`, or `context` when that gate is not met.
