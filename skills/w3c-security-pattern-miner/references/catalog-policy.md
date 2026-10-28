# Catalog Policy

Catalog files are `security-patterns.json`, `security-checks.json`, `occurrences.json`, and `processed-specifications.json`.

Promotion policy:

- `seed` to `candidate`: one evidence-backed occurrence or documented derivation.
- `candidate` to `observed`: explicit normative occurrence or review-observed occurrence.
- `observed` to `recurring`: at least two distinct specifications, not two versions of one spec.
- `recurring` to `validated`: explicit review flag plus resolution evidence, normative W3C guidance,
  conformance/test evidence, or multiple independent normative occurrences plus human review.

Never silently promote to `validated`. Reject duplicate processing unless replacement is explicit. Keep occurrence evidence immutable and make catalog changes reviewable as diffs.