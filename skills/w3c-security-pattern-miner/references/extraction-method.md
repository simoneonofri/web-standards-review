# Extraction Method

## Phase 1: Scope and Source Completeness

Verify `spec_id`, title, and exact version. Inventory specification text, normative sections, algorithms, WebIDL, conformance requirements, Security Considerations, Privacy Considerations, explainer, dependencies, self-review, review material, linked issues, and resolutions. Score completeness without treating it as security quality.

## Phase 2: Security Surface Profile

Extract actors, components, entry points, exposed interfaces, inputs, outputs, assets, capabilities, state, identity, external systems, protocol peers, trusted and untrusted inputs, trust boundaries, origin and site boundaries, browsing contexts, native-platform boundaries, lifecycle transitions, error channels, negotiation, implementation-defined behavior, and referenced security mechanisms. Mark unevidenced elements as modeling hypotheses.

## Phase 3: Source-First Extraction

Inspect the whole specification: scope, terminology, architecture, processing models, algorithms, WebIDL, permissions, origin/site rules, state, lifecycle, worker behavior, errors, network interaction, URL handling, parsing, serialization, extensibility, versioning, cryptography, implementation guidance, security/privacy considerations, examples, dependencies, and review material. Extract atomic observations before catalog alignment.

## Phase 4: Security-Lens Gap Pass

Use `security-taxonomy.json`. For each lens decide: supported by evidence, apparently applicable but unanswered, not applicable with reason, or unknown because evidence is missing.

## Phase 5: Derive Implicit Patterns

Require premises, inference rule, conclusion, alternative interpretation, missing evidence, confidence, and output classification. Do not convert unanswered lenses into defects.

## Phase 6: Adversarial Validation

Ask whether the evidence supports the claim, whether the text is normative, whether inherited mechanisms apply, whether another section contradicts the interpretation, whether privacy is being mislabeled as security, and whether absence of text is being mistaken for unsafe behavior.

## Phase 7: Normalization

Preserve occurrence-level evidence, reusable core pattern, variants, exact evidence, derivation status, uncertainty, and source version.

## Phase 8: Check Generation

Generate checks only when applicability, review action, evidence, expected property, result semantics, and not-applicable conditions can be stated.