# Review bundle contract

Produce one JSON document conforming to `review-bundle.schema.json` with `schema_version` equal to `w3c-spec-code-review/v1`.

## Identity

Use a stable `review_id`. Record one exact specification target and set `implementation_target_status` to `resolved`, `partial`, `unavailable`, or `not_applicable`. Record every exact implementation target that can be resolved; each must declare its repository, revision, selected scope, test revision when known, and evidence status. An empty implementation array is valid only with an explicit non-resolved status and coverage limitation.

## Controls and mappings

Give each specification control and mapping a stable ID. A mapping links one control or `implementation_only` behavior to one implementation. Preserve exact code and test anchors, both directional dispositions, scanner evidence, counterevidence, ownership, confidence, and limitations.

## Scan state

Use one of `not_requested`, `unavailable`, `disabled`, `not_authorized`, `completed`, `partial`, or `failed`. For `completed` or `partial`, record the plugin version, invoked skill, artifact root, and available hashes for `scan-manifest.json`, `coverage.json`, and `findings.json`.

## Discrepancies

Keep a reconciled discrepancy ledger. Use `specification_defect`, `implementation_defect`, `implementation_divergence`, `specification_ambiguity`, `test_gap`, `candidate_missing_spec_requirement`, `non_issue`, `not_applicable`, or `unable_to_verify`. Record evidence, counterevidence, ownership, and whether the horizontal-review gate remains pending, passed, rejected, or unable to verify.

Run `scripts/validate_review_bundle.py` before handoff. Schema validity establishes artifact shape only; it does not validate factual claims or promote findings.
