# Threat Elicitation Contract v1

This contract defines the public boundary of `what-can-go-wrong`.

The skill consumes an accepted `model-packet/v1`, source packets, assumptions,
and versioned prompt or method providers. It produces `threat-package/v1` plus
complete producing and non-producing trace artifacts. It does not require a
private workbench, personal method corpus, complete source registry, or
particular miner implementation.

## Provider interfaces

- `MethodKnowledgeProvider`: versioned threat-story and stopping-discipline
  guidance;
- `PromptSeedProvider`: curated prompt items with stable IDs, source authority,
  applicability rules, and limitations;
- `ReviewEvidenceProvider`: exact target sources and saved element packets;
- `ArtifactStore`: caller-supplied run directory;
- optional `CardDeckProvider`: canonical validated deck for workshop mode.

Providers may use supplied files, public sources, offline bundles, or private local services. The public contract does not reveal the private provider registry. When a required item is unavailable, record `unable_to_verify` or a model/source gap.

## Required inputs

- accepted `model-packet/v1`;
- canonical model IDs and source packets;
- source-corpus manifest and coverage when the target is a specification;
- canonical `A-###` assumption register;
- requested elicitation mode or method group;
- exact run identity and artifact root.

## Threat record

Every retained threat requires:

```text
threat_id
actor_or_condition
action_or_failure
affected_model_elements
violated_property_or_interest
consequence
threat_story
concern_area
evidence_status
evidence
assumptions
finding_mode
found_by_methods
method_provenance
remaining_question
```

A threat is a concrete bad event. A framework category, harm label, weakness,
missing control, response idea, risk score, or issue title is not sufficient.

## Modes

- `baseline`: source-grounded threats already explicit or implicit in the
  target, its mechanisms, safeguards, delegated responsibilities, review
  material, and considerations text;
- `additional`: one or more independently selected prompt methods used after a
  frozen baseline to find blind spots;
- `workshop`: canonical card deck applied one card/model-element pair per row;
- `focused`: one explicitly requested method or target surface;
- `comparison`: several methods run independently and reconciled.

Use `baseline` in user-facing names and new artifact filenames. Legacy wire
keys may remain where an existing v1 contract requires them, but do not create
new aliases.

## Prompt selection

Prompt sources may include security, privacy, human-rights, harms,
fingerprinting, cross-origin observability, AI/ML, protocol, attack-pattern,
control, or design lenses. Selection follows the model and review goal.

A prompt item records:

- stable source and item ID;
- source version and authority;
- intended model surfaces;
- applicability rule;
- question template;
- expected bad-event shape;
- known limitations.

A prompt label is not evidence that it applies. The question must be adapted to
a specific model element and source packet.

## Trace

For every question or card/model-element pair, retain:

- trace record ID;
- method and prompt provenance;
- model element ID/type/name;
- prompt and expected bad-event shape;
- source packet and applicability basis;
- answer and answer status;
- evidence basis;
- candidate relationship;
- derived or related threat IDs;
- non-producing reason when applicable;
- assumptions and notes.

Allowed answer states:

```text
generated_threat
no_applicable_threat
model_gap
blocked
deferred
```

Non-producing rows are required for complete coverage claims. Do not drop a
question merely because it produced no new threat.

## Reconciliation

Assign final `T-##` IDs only after candidate reconciliation. Classify each
candidate as:

```text
retained_unique
confirmed_existing
refined_existing
duplicate
not_concrete
not_applicable
insufficient_evidence
out_of_scope
blocked
deferred
needs_manual_review
```

Record the relatedness basis and preserve the strongest counterevidence. An
additional method may confirm or refine a baseline threat without creating a
new threat record.

## Output and validation

Produce and validate:

- `threat-package/v1`;
- complete producing trace;
- complete non-producing trace;
- candidate lifecycle ledger for full runs;
- method and coverage summary;
- model/source gaps;
- remediation handoff for the response skill;
- validation manifest and limitations.

Use a caller-supplied artifact root. Do not hard-code personal paths or a fixed
platform temporary directory.

## Boundary

This skill owns threat elicitation and reconciliation. It does not:

- change the accepted model silently;
- select final responses or accept risk;
- declare the analysis good enough;
- fact-check changing external claims;
- publish findings or create remote issues;
- turn source-miner output directly into a finding;
- expose private provider, corpus, or source-registry topology.
