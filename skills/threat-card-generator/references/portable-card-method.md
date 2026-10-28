# Portable Card Method

This reference is the complete baseline method for the standalone threat-card generator. It does not require an external skill, downloaded deck, paper archive, web snapshot, or private corpus.

## Start From A Model

A threat deck supports the question "what can go wrong?" only after the review has a bounded answer to "what are we working on?" Start from a scenario, DFD, architecture sketch, specification flow, use case, data-flow table, or equivalent model. If no usable model exists, request one or create a small explicit model and label its assumptions.

Choose the intended play mode before writing cards:

- competitive play uses ranks, turns, scoring, and challenge mechanics to keep elicitation active;
- collaborative play uses each card as a shared prompt and walks every applicable model hotspot;
- a hybrid retains card structure while facilitation notes explain how scoring and systematic coverage interact.

## Derive Suits From Inspectable Surfaces

Use four to seven suits that point players toward different parts of the supplied model. Suitable surfaces include actors, processes, messages, data flows, stores, trust boundaries, authority decisions, lifecycle state, errors, recovery paths, deployment assumptions, and affected stakeholders. Framework categories may seed attention, but they do not replace model attachment.

Split a suit when it combines surfaces that players inspect differently. Merge suits when their cards repeatedly produce the same threat stories. Rank supports gameplay; it is not severity unless the deck explicitly defines that separate meaning.

## Write Original, Traceable Prompts

Prefer questions with this shape:

```text
Could [actor, deputy, system part, policy, or condition] [act, fail, misuse, overreach, expose, infer, exclude, or force] at [model element or flow] so that [property or stakeholder interest] is affected?
```

Each card should focus attention on one surface and produce a threat story or a clearly marked assumption, model gap, or remaining question. Keep threats distinct from harms, vulnerabilities, responses, controls, and risk scores. A harm-oriented card still needs a pathway from a model element or deployment decision to an affected stakeholder.

Use original wording. Caller-supplied sources may provide prompt seeds and evidence, but their prose, art, layouts, and assets are not generator dependencies and must not be copied without an explicit licensing path.

## Preserve Useful Outputs

A played card should yield at least one concrete artifact: a threat story, affected element, affected stakeholder, assumption, response idea, remaining question, test, review item, backlog item, or requirement. Do not score broad assertions unless the player identifies the path from the model to the affected property, person, group, authority, or dependency.

For source-conditioned cards, preserve `source_trace` and the complete question-generation handoff defined in `references/card-schema.md`. Source traces record why a card exists; they do not make the source content part of the portable runtime.

## Skeptic And Play-Test Checks

Before calling a deck ready, ask:

- Did every card attach to an inspectable model surface?
- Did cards produce concrete threat stories instead of framework labels or compliance slogans?
- Did the session keep threat, harm, vulnerability, response, control, and risk distinct?
- Did broad prompts create useful coverage, or only checklist theater?
- Can the outputs support response discussion, review findings, requirements, or tests?

After a play-test, keep cards that produced distinct threats, rewrite unclear cards, split overloaded cards, merge duplicates, and retire abstract or unproductive cards. Preserve stable IDs unless the user requests a breaking deck revision.
