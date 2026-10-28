# Threat Card Deck Contract v1

Use JSON as the canonical source format. The machine-readable contract is
`schemas/threat-card-deck-v1.schema.json`; `scripts/validate_deck.py` provides a
dependency-free validator for the same contract.

The deck contract is the handoff between `threat-card-generator` and consumers
such as `what-can-go-wrong`. Generation provenance belongs in the deck. Card
play, answers, reconciliation, and resulting threat IDs belong in the consumer's
trace artifacts.

## Top-Level Object

Required fields:

- `deck_id`: stable lowercase or uppercase identifier, such as
  `elevation-of-credentials`.
- `title`: human-readable deck title.
- `version`: semantic or date-based version string.
- `status`: `draft`, `playtest`, `stable`, or `retired`.
- `description`: one or two sentences describing deck scope.
- `method_notes`: short array of method notes.
- `suits`: array of suit objects.
- `cards`: array of card objects.
- `playtest_log`: array of short iteration notes.

Optional fields:

- `generation_mode`: the mode that produced or last materially revised the
  canonical deck: `new-deck`, `deck-refinement`, `source-to-cards`,
  `credential-flow-deck`, or `playtest-repair`.
- `play_mode`: `competitive`, `collaborative`, or `hybrid`.
- `license`.
- `attribution`.
- `source_references`.

`render-only` is an operation mode, not deck provenance. Rendering an existing
deck must not replace its `generation_mode`.

## Suit Object

Required fields:

- `id`: compact suit ID, for example `ISS`.
- `name`: suit name.
- `description`: what surface or question the suit covers.

## Card Object

Required fields:

- `id`: stable card ID, for example `EOC-ISS-03`.
- `suit`: one of the suit IDs.
- `rank`: positive integer. Ranks are ordering and game mechanics, not severity.
- `title`: short card title.
- `prompt`: one question, written to elicit a threat.
- `look_for`: array of concrete cues.
- `outputs`: array of expected outputs, such as `threat story`,
  `affected element`, or `response idea`.

Recommended fields:

- `applies_to`: array of likely model elements or surfaces.
- `example`: one short example that illustrates the card without becoming the
  answer.
- `anti_patterns`: array of mistakes the facilitator should avoid.
- `framework_prompts`: array of related framework prompts, such as
  `STRIDE: Spoofing` or `LINDDUN: Linkability`.

## Source And Question-Generation Metadata

Use these fields when a card is derived from a standard, paper, issue, review,
existing deck, prompt table, checklist item, or earlier play-test feedback.
They are the canonical handoff fields used by `what-can-go-wrong`:

- `source_trace`: non-empty array of source-trace objects. Required for every
  card in a `source-to-cards` deck.
- `prompt_template_id`: stable template identifier used to generate the card
  question.
- `prompt_family`: source or generation method family, such as
  `stride_per_element`, `rfc6973_privacy_per_element`, or
  `workshop_prompt_design`. This is canonical provenance and consumers must copy
  it unchanged into card-play traces; the fact that a row is a card play is
  represented by the workshop object and row type.
- `source_item_id`: source section, algorithm, WebIDL member, checklist item,
  RFC item, principle, source card, or other item that shaped the prompt.
- `applicability_rule_id`: stable rule explaining why the prompt applies to the
  declared surfaces.
- `expected_bad_event_shape`: one sentence describing the concrete
  actor/action-or-failure/consequence shape the card is intended to elicit.

When one of the question-generation fields is present, preserve the complete
set. A consumer should not need to reconstruct applicability or intended bad
event shape from the card title alone.

### Source Trace Object

Required fields:

- `source_kind`: one of `primary_source`, `local_snapshot`, `extracted_table`,
  `user_notes`, `assumption`, `existing_deck`, `review_material`, or `other`.
- `source_reference`: public reference, local artifact reference, source ID, or
  an explicit assumption description.

Optional fields:

- `source_item_id`.
- `source_locator`.
- `derivation_notes`.
- `evidence_status`: `verified`, `inferred`, `assumed`, or `unavailable`.
- `license`.
- `attribution`.

`source_kind: assumption` identifies what kind of source record is being used.
`evidence_status: assumed` is the canonical evidence-state vocabulary shared
with the other threat-model contracts.

A public export can redact or replace internal source locations, but it must not
silently remove the distinction between a checked source, an inference, and an
assumption.

## Play-Test And Refinement Metadata

Use:

- `card_status`: `new`, `keep`, `rewrite`, `split`, `merge`, or `retire`.
- `change_notes`: non-empty array of short notes explaining the revision.

`change_notes` is required when `card_status` is `rewrite`, `split`, `merge`, or
`retire`. Preserve stable card IDs unless the change is intentionally breaking.
A split or merge should record the successor or related card IDs in
`change_notes`.

## LINDDUN GO-Style Optional Fields

- `privacy_threat`: source privacy threat name when deriving from a LINDDUN
  GO-style source card.
- `hotspots`: array of system surfaces to inspect, such as user/data flows,
  processes, storage, retrieval actions, observers, recipients, responses, or
  policy decisions.
- `threat_source`: likely source of the privacy threat, such as organizational,
  external, platform, operator, recipient, or system behavior.
- `elicitation_questions`: source or adapted questions used to test whether the
  privacy threat applies to each hotspot.
- `consequences`: array of likely privacy, user, system-user, or stakeholder
  consequences.

When using LINDDUN GO-style fields, also map the same structure into the generic
deck fields: put hotspots in `applies_to`, scan cues in `look_for`, source
labels in `framework_prompts`, and expected recordable artifacts in `outputs`.

## Validation Expectations

- IDs must be unique.
- Every card suit must exist in `suits`.
- Prompts must end with `?`.
- `look_for` and `outputs` must be non-empty arrays.
- Cards should not use copied EoP wording unless a derivative license and
  attribution path is explicit.
- Decks should normally have 4-7 suits.
- Cards should include `applies_to` when the domain has a known model.
- Every card in a `source-to-cards` deck must include `source_trace`.
- Question-generation metadata should be complete when any of its fields is
  present.
- Revised, split, merged, or retired cards must include `change_notes`.
- LINDDUN GO-style cards should preserve hotspot structure instead of using only
  a privacy category label.
- Socio-technical, governance, and harms-oriented cards should include
  `anti_patterns` so play-testers do not stop at abstract harm labels.
- `method_notes` should record when Shostack's Four Question Framework is the
  primary method lens, especially that the deck supports "what can go wrong?"
  rather than replacing the full threat model.
- `play_mode` should be set when facilitation differs materially, especially for
  competitive Shostack/EoP-style decks or collaborative LINDDUN GO-style
  workshop decks.
