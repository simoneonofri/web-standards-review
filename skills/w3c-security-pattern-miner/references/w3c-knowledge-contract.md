# w3c-knowledge Contract

Prefer the local `w3c-knowledge` Source Packet v1 contract. The repository is available at `simoneonofri/w3c-knowledge`, and its consumer rules require callers to use the versioned `/api/v1/` API rather than importing ORM models or reading the database.

Use:

```text
GET /api/v1/specifications/{id}/source-packet
```

The source packet returns `source_packet_contract_version: 1` and includes:

- `specification_id`, `specification_version_id`, and `source_type`;
- legacy publication fields such as `shortname`, `status`, `latest_tr_url`, and
  `immutable_publication_url`;
- `snapshot_identity` with requested shortname, raw and normalized status, publication date,
  latest URL, immutable URL, canonical URL, and content hash;
- `section_inventory` for compatibility;
- `sections[]` with section text plus `section_type` and `normative`;
- legacy `consideration_presence` plus complete `considerations[]` records;
- WebIDL, references, source URLs, evidence IDs, retrieval timestamp, and content hashes.

Source packets are evidence inputs only. They do not contain inferred controls, threats, ERTA classifications, or review conclusions.

Use `section_limit`, `section_offset`, and `include_evidence_ids=false` for large specifications. Use `GET /api/v1/specifications/{id}/sections`, `/considerations`, `/webidl`, and `/references` when a narrower packet is sufficient.

## Adapter Shape

Use this implementation-neutral v0.1 shape only as a fallback adapter when a source packet has already been exported or transformed. Optional fields may be missing. Missing material is evidence quality information, not a security finding.

```json
{
  "contract_version": "0.1",
  "spec": {
    "spec_id": "string",
    "title": "string",
    "shortname": "string-or-null",
    "version": "string",
    "status": "string-or-null",
    "publication_date": "string-or-null",
    "source_url": "string-or-null"
  },
  "units": [
    {
      "unit_id": "string",
      "artifact_id": "string",
      "kind": "section|algorithm|webidl|definition|conformance|example|issue-comment|resolution|external-reference|other",
      "heading": "string-or-null",
      "text": "string",
      "locator": "string-or-null",
      "normative": true,
      "normative_strength": "must|must-not|should|should-not|may|null",
      "parent_unit_id": "string-or-null",
      "references": [],
      "source_url": "string-or-null"
    }
  ],
  "artifacts": [],
  "relationships": [],
  "optional_spec_profile": {
    "primary_family": "string-or-null",
    "secondary_families": [],
    "facets": []
  }
}
```

Reject or split bundles containing multiple versions. When a normative dependency is unavailable, record inherited behavior as `unknown` or `derived-from-cross-reference` with reduced confidence.