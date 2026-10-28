# Fact-Check-Aware Publication Gate

Use this gate after the exact review report or public-facing draft has been
assembled and fact-checked. It combines four different questions without
collapsing them:

1. Does the fact-check result apply to the exact bytes being considered?
2. Are externally checkable claims factually ready?
3. Did the analysis and independent-review gates pass for the required scope?
4. Does the projected public artifact still contain a blocking private/public
   boundary finding?

The gate produces `review-publication-gate/v1`. A passing gate means the
recorded technical and factual preconditions pass. Human approval remains a
separate, required decision and is initialized as `not_recorded`.

## Inputs

Required for a final review publication gate:

- exact report or draft artifact;
- `fact-check-result/v1` for that artifact digest;
- analysis gate;
- independent-review / good-enough gate.

Optional but recommended before external sharing:

- publication-boundary audit for the exact projected directory or artifact
  bundle.

The fact-check result is produced by the independent `fact-check` skill. The
publication gate validates the required cross-skill fields but does not import
personal writing, knowledge, or orchestration systems.

The caller conducting the final review records `analysis-gate.json` from the actual upstream results; it is a run artifact, not a sixth shared handoff automatically produced by the five-stage flow. The extended report assembler consumes and validates this gate rather than creating it. Use `gate: analysis`, an honest aggregate `status`, and named `checks` for `source_corpus`, `model_packet`, `dfd_representation`, `baseline_elicitation`, `response_mapping`, and `independent_review`; include `additional_elicitation_reconciliation` when additional analysis is in scope. Preserve the supporting results and evidence in the run directory. A missing check or unperformed review cannot be replaced with a fabricated passing status.

## Command

```bash
python3 scripts/build_publication_gate.py \
  --artifact /path/to/run/review-report.md \
  --fact-check /path/to/run/fact-check-result.json \
  --analysis-gate /path/to/run/analysis-gate.json \
  --independent-review-gate /path/to/run/independent-review-gate.json \
  --publication-boundary /path/to/run/publication-boundary-audit.json \
  --require-human-reviewed-fact-check \
  --output /path/to/run/publication-gate.json
```

For a draft-only internal artifact, the caller can omit the human-reviewed
requirement. A draft gate still requires the factual-readiness status to be
`pass` unless the caller is deliberately generating a failed gate to explain
what remains.

Use `--allow-missing-analysis-gate` or
`--allow-missing-independent-review-gate` only for a workflow where the
corresponding analysis is genuinely not applicable, such as a narrow editorial
fact check. Do not use these flags to make an incomplete security or privacy
review publishable.

## Checks

### Artifact identity

The SHA-256 digest of the exact artifact must equal the digest in
`fact-check-result/v1`. Editing the draft after fact checking invalidates the
gate.

### Fact check

The fact-check result must:

- use `fact-check-result/v1`;
- satisfy the complete v1 field, vocabulary, reference-integrity, unresolved-claim, and deterministic-status contract;
- have `publication_status: pass`;
- have no unresolved claim IDs;
- have no load-bearing claim that is unsupported, contradicted, or only
  partially supported;
- have `review_status: human_reviewed` when that requirement is selected.

This is factual readiness, not a security or privacy sufficiency decision.

The gate output records portable artifact names and SHA-256 evidence rather than absolute local input paths. The caller retains the run-directory mapping outside the publication artifact.

### Analysis and independent review

Required gate artifacts must expose a passing status. A partial, blocked,
failed, or missing required gate fails publication.

### Publication boundary

When supplied, a boundary audit fails the gate if any `blocker` or `high`
finding remains. This is intended for personal paths, private dependencies,
hidden provider topology, secrets, or unreviewed third-party assets in the
public projection.

## Integration with report assembly

The current report assembler validates report structure and local links, then
writes its existing publication gate. Until the assembler is refactored to call
this module directly, treat `scripts/build_publication_gate.py` as the final
authoritative publication step for external or publication-facing output.

Do not publish merely because the older structural report gate passes. The
fact-check-aware gate binds all required inputs to the exact draft and leaves
human approval explicit.
