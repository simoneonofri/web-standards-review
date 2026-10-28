# Threat Response Analysis Contract v1

This contract defines the public boundary of
`what-are-we-going-to-do-about-it`.

The skill consumes an accepted `threat-package/v1`, canonical model and
assumption references, and source-backed current-response evidence. It produces
`response-package/v1` with exact threat coverage, ERTA decisions or explicit
unresolved rows, owners, transfers, assumptions, remaining threats, and
next actions.

The public skill does not require a private workbench, personal method corpus,
source registry, or writing system.

## Provider interfaces

- `ResponseMethodProvider`: versioned guidance for Eliminate, Reduce, Transfer,
  Accept, and Unresolved decisions;
- `ReviewEvidenceProvider`: exact specification, issue, review, implementation,
  or supplied source evidence for current responses and responsibilities;
- `ArtifactStore`: caller-supplied run directory.

A private installation may register richer providers, but it must not redefine
the public package fields or silently invent evidence.

## Required inputs

- accepted `threat-package/v1`;
- accepted `model-packet/v1` or canonical model-element ID set;
- canonical `A-###` assumption register;
- source corpus or evidence packet for target-specific current responses;
- remediation handoff when produced by `what-can-go-wrong`;
- exact run identity and artifact root.

For a baseline package, the response threat-ID set must equal the baseline
threat-ID set. For an additional package, proposed-response threat IDs must
equal the retained additional-threat set selected for response analysis.

## Response record

Use Response Package Contract v1:

```text
response_id
threat_id
affected_model_elements
threat_story
status
erta
response
mechanism_or_text
owner
evidence_status
evidence
assumptions
transfer_receiver
acceptance_rationale
revisit_trigger
remaining_threat
next_action
```

`affected_model_elements` is a non-empty array of canonical model IDs.
`next_action` is a non-empty, testable string in v1.

## ERTA semantics

### Eliminate

Use only when the design or requirement removes the relevant bad-event path,
not merely when one implementation adds a check. Record what is removed, where
it is enforced, and the evidence that the path no longer applies.

### Reduce

Use when the response lowers likelihood, opportunity, scope, observability, or
impact but leaves a remaining threat. `remaining_threat` is required and must
be specific enough for later review.

### Transfer

Use when responsibility or control is moved to another actor or layer.
Require:

- named receiver;
- exact responsibility or control transferred;
- source or proposed text defining that responsibility;
- assumptions on which the transfer depends;
- what remains with the specification, implementation, deployer, or other
  original owner;
- remaining threat if the receiver fails or cannot act.

Out of scope is not a transfer by itself.

### Accept

Use only when an authorized owner has an evidence-based reason to accept the
remaining threat for the current stage or deployment. Require acceptance
rationale, owner, revisit trigger, and residual consequence. Do not infer
acceptance from silence, lack of mitigation, or an explicit non-goal unless the
source also supports the decision and owner.

### Unresolved

Use when the response, owner, evidence, or decision is not yet sufficient.
Require a decision owner and testable next action. An unresolved row preserves
exact coverage without pretending that a response has been selected.

## Current and proposed responses

Keep `existing` and `proposed` responses distinct.

A source-backed current response can come from:

- normative or informative target text;
- an explicit algorithm, default, exception, validation, permission, policy,
  lifecycle, user-mediation, or failure mechanism;
- an explicit responsibility or deployment requirement;
- verified issue or review resolution evidence;
- a pinned implementation or test when the response is implementation-owned.

A proposal is not evidence that the current target already mitigates the
threat. Preserve response origin and evidence status.

## Assumptions and owners

Every assumption reference resolves to the canonical `A-###` register. Do not
copy prose-only assumptions into the response package after a register exists.

For every row, name the actor responsible for deciding, specifying,
implementing, deploying, verifying, monitoring, accepting, or receiving the
response. Do not use generic owners such as “the ecosystem” when a more
specific role is required.

## Workflow

1. Freeze the threat, model, source, and run identity.
2. Validate threat IDs, affected model IDs, and assumption references.
3. Load source-backed current-response and delegated-responsibility evidence.
4. Create one response row or explicit unresolved row for every in-scope threat.
5. Select ERTA only after the mechanism, owner, evidence, and remaining threat
   are visible.
6. Check transfers, assumptions, acceptance, and remaining threats.
7. Reconcile duplicate mechanisms and shared controls without collapsing
   threat-specific consequences.
8. Validate exact threat coverage and package schema.
9. Produce considerations and next-action handoff for the independent review.

## Validation rules

The package cannot pass when:

- a baseline threat has no response or unresolved row;
- a response references an unknown threat, model element, or assumption;
- `Reduce` lacks a remaining threat;
- `Transfer` lacks a receiver or transfer boundary;
- `Accept` lacks rationale, owner, or revisit trigger;
- `Unresolved` lacks a decision owner or next action;
- a generic best-practice statement replaces a threat-specific mechanism;
- current response evidence is confused with a proposal;
- a response is inferred solely from scanner output, implementation habit, or
  reviewer preference;
- the target/source identity is mixed or unresolved.

## Output

Produce:

- `response-package.json`;
- exact threat-response coverage matrix;
- transfer and responsibility register;
- assumption-use and follow-up register;
- remaining-threat table;
- considerations and next-action handoff;
- validation manifest;
- limitations.

The response package is authoritative for ERTA decisions and unresolved rows.
The independent good-enough gate decides whether the package is sufficient for
the current stage. A later fact check verifies externally checkable claims in
the assembled draft.

## Boundary

This skill does not:

- create new threats;
- change the accepted model silently;
- declare the analysis good enough;
- fact-check dates, status, implementation, or review claims;
- authorize risk acceptance for an unnamed owner;
- publish or create remote issues;
- expose private provider, corpus, or source-registry topology.
