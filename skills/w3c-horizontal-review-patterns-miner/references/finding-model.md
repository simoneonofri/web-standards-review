# Finding Model

A finding is atomic: one concern, one triggering condition, one relevant property or harm, and optionally one mitigation.

## Normalized record

```json
{
  "finding_id": "generated-stable-id",
  "spec_id": "example-spec",
  "spec_version": "2026-01-01",
  "review_kind": "privacy",
  "pattern_id": "privacy-stable-identifier",
  "status": "confirmed",
  "facets": ["sensor-device", "third-party", "stable-identifier"],
  "trigger": "The API returns a stable identifier to embedded origins.",
  "asset_or_data": "device identity",
  "actor": "embedded third party",
  "trust_boundary": "cross-origin",
  "failure_mode": "cross-site correlation",
  "expected_property": "identifier scoped and rotated by an appropriate boundary",
  "suggested_mitigation": "partition by top-level site and requesting origin",
  "evidence": [
    {
      "source_id": "normalized-source-id",
      "source_kind": "spec-section",
      "locator": "section-or-comment-identifier",
      "evidence_span": "Exact supporting text",
      "interpretation": "Why this text supports the finding"
    }
  ],
  "provenance_class": "empirical",
  "confidence": 0.92,
  "resolution": {
    "status": "unresolved",
    "source_id": null
  }
}
```

## Rules

- `confirmed` findings require at least one evidence record.
- `possible` findings may use incomplete evidence but must say what is missing.
- An expected pattern with no evidence is a review question or `unknown`.
- Generate stable IDs from spec ID, version, review kind, pattern ID, and a
  short trigger slug.
- Preserve exact evidence spans; keep interpretation separate from quoted text.
- Keep mitigations separate from validation. A proposed mitigation is not
  validated until resolution or specification-change evidence supports it.
