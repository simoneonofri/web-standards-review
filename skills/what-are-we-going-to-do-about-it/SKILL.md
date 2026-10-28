---
name: what-are-we-going-to-do-about-it
description: Map accepted threat stories to source-grounded or proposed responses using Eliminate, Reduce, Transfer, Accept, or explicit Unresolved dispositions. Use to produce exact threat-response coverage, owners, transfers, assumptions, remaining threats, and testable next actions without requiring private knowledge services, inventing acceptance, or confusing out-of-scope responsibility with mitigation.
---

# What Are We Going To Do About It

<!-- section:status -->
## Status

This is an independent threat-response analysis tool maintained by Simone
Onofri. It may be used in W3C-oriented review work, but its output is analysis
for human review and does not represent a W3C, Working Group, Interest Group,
TAG, or horizontal-review group position, response, decision, or acceptance.

<!-- section:contract protected -->
## Contract

Read `contracts/response-analysis-v1.md` and Response Package Contract v1 before
running the skill. Consume an accepted `threat-package/v1` and produce
`response-package/v1` with exact threat coverage.

The public skill consumes typed response-method, review-evidence, and
artifact-store providers. It must operate from supplied files and public
sources without access to a private workbench, personal method corpus, source
registry, or writing system.

<!-- section:boundary -->
## Boundary

This skill answers the third threat-modeling question: **what are we going to
do about it?**

It owns:

- source-backed current-response extraction;
- proposed response formulation;
- ERTA or explicit Unresolved disposition;
- owner and responsibility mapping;
- transfers and assumptions;
- remaining threats;
- testable next actions;
- exact response coverage and validation.

It does not:

- create new threats;
- change the accepted model silently;
- accept risk for an unnamed or unauthorized owner;
- decide whether the complete analysis is good enough;
- fact-check changing external claims;
- publish findings or create remote issues;
- expose private provider or corpus topology.

<!-- section:contract-resolution protected -->
## Contract Resolution

Resolve shared contracts in this order:

1. `STANDARDS_REVIEW_CONTRACTS_ROOT` when explicitly set;
2. package-local `contracts/shared-contract-v1.json`, which identifies the canonical schemas and validator;
3. the bundled `contracts/threat-modeling-flow-v1/` tree;
4. a caller-supplied contract path.

Resolve package-local paths from the physical installed skill path, following any host symlink, rather than from the caller workspace.

Resolve response-method and review-evidence providers from caller configuration
or approved public packs. A private provider may enrich a private installation,
but it must not change the public wire contract or become required for a public
run.

If a required contract or source is unavailable, return `blocked`, `partial`,
or an explicit Unresolved row according to the affected decision. Do not emit a
reduced artifact under the same contract name.

<!-- section:artifact-root -->
## Artifact Root

Use the caller-supplied run directory, preferably:

```text
STANDARDS_REVIEW_ARTIFACT_ROOT=/path/to/run
```

Do not write durable artifacts to a fixed platform temporary path or personal
repository directory.

<!-- section:required-inputs -->
## Required Inputs

Require:

- accepted `threat-package/v1`;
- accepted `model-packet/v1` or canonical model-element ID set;
- canonical `A-###` assumption register;
- target source corpus or evidence packet;
- remediation handoff when available;
- requested response scope;
- exact run identity and artifact root.

For a baseline run, response threat IDs must equal baseline threat IDs exactly.
For an additional run, proposed-response threat IDs must equal the retained
additional-threat set selected for response analysis.

A missing response package blocks the fourth threat-modeling question. Do not
omit a threat to make the response table look complete.

<!-- section:source-boundary -->
## Source Boundary

For target-specific current responses, use the saved source corpus and exact
source locators from the accepted model and threat package. Preserve source
IDs, assurance, evidence status, and delegated-responsibility signals.

Do not replace the reviewed target snapshot with a moving live document unless
the caller refreshes the model and run identity. A current external fact check
belongs to a later step.

A source mechanism can show an existing response, partial response, delegated
responsibility, accepted/non-goal signal, missing response, or need for
clarification. It does not prove that the response is sufficient.

<!-- section:response-record -->
## Response Record

Use Response Package Contract v1. Every response row contains:

- canonical `R-##` response ID;
- canonical threat ID;
- non-empty affected model-element ID array;
- source threat story when useful;
- response status and origin;
- ERTA or `Unresolved`;
- concrete response and mechanism or text;
- responsible owner;
- evidence status and evidence;
- canonical assumption references;
- transfer receiver when applicable;
- acceptance rationale and revisit trigger when applicable;
- remaining threat when applicable;
- non-empty testable `next_action` string.

Do not use a legacy singular `model_element` object. Do not use a structured
`next_action` object in response-package v1.

<!-- section:erta-decisions -->
## ERTA Decisions

### Eliminate

Use `Eliminate` only when the design or requirement removes the relevant
bad-event path. Record what is removed, where it is enforced, who owns the
change, and the evidence that the threat no longer applies.

An implementation-specific guard does not eliminate a specification-level
threat for every conforming implementation unless the specification requires
or otherwise establishes the relevant invariant.

### Reduce

Use `Reduce` when the response lowers likelihood, opportunity, scope,
observability, or impact but does not remove the threat. Require a concrete
`remaining_threat`.

Do not write “residual risk remains” without naming the remaining actor,
condition, pathway, consequence, or deployment dependency.

### Transfer

Use `Transfer` when responsibility or control is moved to another named actor
or layer. Require:

- receiver;
- exact responsibility or control;
- source or proposed text;
- assumptions;
- what remains with the original owner;
- consequence if the receiver cannot or does not act;
- remaining threat where applicable.

“Implementation-defined”, “deployment-specific”, or “out of scope” is not a
complete transfer unless the receiver, responsibility, assumptions, and
remaining threat are explicit.

### Accept

Use `Accept` only when an authorized owner has an evidence-based reason to
accept the remaining threat for the current stage or deployment. Require:

- owner;
- acceptance rationale;
- affected people or property;
- remaining consequence;
- revisit trigger;
- evidence supporting the decision.

Do not infer acceptance from silence, a missing mitigation, a closed issue, or
an explicit non-goal without a supported decision and owner.

### Unresolved

Use `Unresolved` when the response, owner, evidence, or decision is not yet
sufficient. Require a decision owner and testable next action.

An Unresolved row preserves exact threat coverage without pretending that a
response has been selected. It may block or make the independent review
partial depending on the intended stage and decision.

<!-- section:current-and-proposed-responses -->
## Current And Proposed Responses

Keep source-backed `existing` responses separate from `proposed` responses.

Possible current-response evidence includes:

- normative or informative target text;
- explicit algorithm, default, exception, validation, permission, policy,
  lifecycle, user-mediation, or failure behavior;
- explicit implementation or deployment responsibility;
- verified public issue or review resolution;
- pinned implementation or test evidence for an implementation-owned response.

A proposal is not evidence that the current target already mitigates the
threat. Preserve response origin, status, and evidence.

<!-- section:owners-assumptions-and-remaining-threats -->
## Owners, Assumptions, And Remaining Threats

Every assumption reference must resolve to the canonical `A-###` register.
Do not duplicate prose-only assumptions after the register exists.

Name the actor responsible for:

- deciding;
- specifying;
- implementing;
- deploying;
- verifying or testing;
- monitoring;
- accepting;
- receiving a transfer.

Do not assign responsibility to “the ecosystem” when a specific role or
unresolved owner is the accurate state.

For every Reduce, Transfer, or Accept disposition, make the remaining threat or
remaining responsibility visible. A response that merely moves text into a
considerations section may improve documentation while leaving the technical
threat unchanged.

<!-- section:workflow -->
## Workflow

1. Freeze threat, model, source, and run identities.
2. Validate threat IDs, model-element IDs, and assumption references.
3. Load source-backed current responses and delegated responsibilities.
4. Create one response or explicit Unresolved row for every in-scope threat.
5. Separate existing and proposed responses.
6. Select ERTA only after mechanism, owner, evidence, assumptions, and
   remaining threat are visible.
7. Reconcile shared mechanisms without collapsing threat-specific consequences.
8. Validate exact threat coverage and package schema.
9. Produce transfer, assumption, remaining-threat, considerations, and
   next-action handoffs.

<!-- section:validation -->
## Validation

A package cannot pass when:

- a required threat has no response or Unresolved row;
- a response references an unknown threat, model element, or assumption;
- `Reduce` lacks a remaining threat;
- `Transfer` lacks a receiver or transfer boundary;
- `Accept` lacks rationale, owner, or revisit trigger;
- `Unresolved` lacks a decision owner or next action;
- generic best-practice text replaces a threat-specific mechanism;
- source-backed and proposed responses are confused;
- the response is inferred only from scanner output, implementation habit, or
  reviewer preference;
- target or source identity is mixed.

Run the repository or shared response-package validator and record the exact
command, version, inputs, digests, and result. A failed required validator
blocks a complete handoff.

<!-- section:output -->
## Output

Produce:

- `response-package.json`;
- exact threat-response coverage matrix;
- transfer and responsibility register;
- assumption-use and follow-up register;
- remaining-threat table;
- Security/Privacy Considerations and next-action handoff;
- validation manifest;
- limitations.

The response package is authoritative for ERTA decisions and Unresolved rows.
The independent good-enough gate decides whether the response analysis is
sufficient for the current stage. A later fact check verifies externally
checkable claims in the assembled draft.

<!-- section:handoff -->
## Handoff

After validation:

- route missing or unclear threat stories to `what-can-go-wrong`;
- route unknown model elements to `what-are-we-building`;
- route sufficiency and considerations delta to
  `did-we-do-a-good-enough-job`;
- route externally checkable report claims to `fact-check`;
- leave publication, acceptance approval, and remote writes to separate
  authorized workflows.

<!-- section:remote-write-boundary protected -->
## Remote-Write Boundary

Default to read-only source access and local artifact writes under the supplied
artifact root. Creating issues, pull requests, comments, commits, documents, or
published material requires separate explicit approval for the exact target and
payload. Installation, execution, dynamic validation, and PoC activity require
separate authorization and scope.
