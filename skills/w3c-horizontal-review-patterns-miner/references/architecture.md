# Architecture

`w3c-horizontal-review-patterns` is a repository-local Codex Agent Skill. It contains reusable review reasoning assets and deterministic local scripts.

## Responsibility split

`w3c-knowledge` owns source discovery, retrieval, normalization, relationships, raw evidence spans, and source metadata.

This skill owns specification profiling, pattern applicability, finding shape, coverage assessment, and human-readable review output.

The dependency direction is:

```text
agent + w3c-horizontal-review-patterns -> normalized w3c-knowledge bundle
```

The skill must not import implementation modules from `w3c-knowledge`, connect to its database, call live APIs, or create an alternative store.

## Local interface assumption

No sibling `w3c-knowledge` repository was present when this skill was created. A sibling `w3c-horizontal-review` repository documented an API-only dependency on `w3c-knowledge /api/v1/`. This skill therefore documents an implementation-neutral JSON bundle contract and treats all source retrieval as external.

## Determinism boundary

Codex performs semantic interpretation: reading a specification, assigning families/facets, and interpreting evidence. The scripts perform deterministic validation and pattern selection only.