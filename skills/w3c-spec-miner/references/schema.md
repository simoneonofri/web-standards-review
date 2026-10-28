# Derived catalog schema

## `protection-catalog.json`

The top-level object records `schema_version`, corpus metadata, aggregate coverage, and `patterns[]`. Each pattern contains its stable identifier, category, threats addressed, reusable secure-default statement, exception questions, review question, specification count, observation count, normative-strength counts, and bounded source examples.

## `protection-observations.jsonl`

Each line is one specification-pattern observation with specification identity, publication status, pattern identity, normative strength, whether the observation occurs in Security Considerations, source URL, section heading and anchor, section content hash, bounded excerpt, evidence identifiers, detected secure-default signals, and detected exception signals.

## `threat-models.jsonl`

Each line is one derived as-is model with specification identity, snapshot locator, assets, entry points, trust boundaries, threats derived from observed controls, observed protection identifiers, Security Considerations presence, and explicit inference limits.

## `security-considerations-gaps.jsonl`

Each line is an editorial comparison with `disposition: editorial_non_blocking`, target specification identity, pattern identity, evidence outside Security Considerations, and a bounded self-contained question. It never establishes a technical blocker by itself.

## `coverage.json`

This object records the inventory size and hash, requested statuses, successful packets, failures, empty-section packets, specifications with Security Considerations, specifications with observations, and generated artifact hashes.
