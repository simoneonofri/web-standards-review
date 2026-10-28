# Candidate ledger v1

This additive sidecar records how raw candidates become, support or fail to become retained threats. It does not change model-packet/v1 or threat-package/v1. Use it for full runs and whenever candidate reconciliation is claimed. Baseline, additional, comparison and workshop runs can each keep their own frozen ledger; do not expose baseline dispositions to a deliberately independent elicitation pass.

The schema is `../schemas/candidate-ledger-v1.schema.json`. All JSON files remain caller-owned run artifacts. The helper reads only the explicitly selected ledger, model, frozen elicitation and threat package; it never fetches a source_artifact reference, accesses a service, launches agents or writes the inputs.

## Elicitation

Record schema_version `candidate-ledger/v1`, run_id, stage `elicitation`, model_sha256 (lowercase SHA-256 of exact model file bytes), and candidates. Candidate IDs use the separate `C-` namespace. Preserve origin_method, source_artifact, observation, affected_model_elements, disposition, rationale and counterevidence, including non-producing observations and an explicit empty counterevidence array when nothing was recorded. A model gap may have no affected elements yet. A candidate is not a final threat.

The elicitation stage cannot assign retained_threat_id, promotion/relatedness dispositions or reconciliation artifact hashes. Freeze this file before reconciliation; later discovered candidates belong in a new frozen elicitation generation, never silently appended to a reconciled ledger. In multi-producer work, freeze the combined candidate input first and preserve every producer's candidate and trace reference. Parallel execution remains optional and requires the caller's authorization.

## Reconciliation

Use the same run and model identity. Add elicitation_sha256, threat_package_sha256 and explicit baseline_threat_ids; baseline IDs name already accepted threats present in the selected final package. An empty baseline array is valid. Do not use it to disguise newly promoted candidates. The baseline package's own acceptance and provenance remain separate prerequisites; this sidecar does not prove them.

Keep exactly the frozen candidate IDs, original observations, methods, trace references, model attachments and recorded counterevidence. Preserve previously recorded evidence references and assumption IDs when adding new evidence. Use these dispositions:

- `retained_unique`: a new threat, requiring a concrete actor/condition, action/failure, violated property/interest, consequence, model attachment, evidence basis and final retained_threat_id.
- `confirmed_existing`, `refined_existing`, `duplicate`: map to a retained threat and explain the specific relation, preserving their independent provenance without increasing the unique count.
- `not_concrete`, `not_applicable`, `insufficient_evidence`, `out_of_scope`: keep the rejected candidate and reason.
- `pending`, `blocked`, `deferred`, `needs_manual_review`: keep the unresolved work explicit; reconciliation remains partial.

Each retained_unique event and its affected model elements must match the selected canonical threat. All final threat IDs must be either explicit baseline IDs or uniquely promoted IDs. Evidence bases distinguish source_checked, model_inference and assumption_based; source checks need references, inference needs rationale, and assumptions need IDs from the accepted model. These checks establish structure and traceability, not whether a source really supports the claim or a deduplication judgment is correct.

## Commands

Run from the installed skill directory, using absolute run-artifact paths:

```sh
python3 scripts/validate_candidate_ledger.py /path/to/elicitation.json --model /path/to/model.json
python3 scripts/validate_candidate_ledger.py /path/to/reconciliation.json --model /path/to/model.json --elicitation /path/to/elicitation.json --threats /path/to/threats.json
python3 scripts/validate_threat_package.py /path/to/threats.json --model /path/to/model.json --candidate-ledger /path/to/reconciliation.json --elicitation-ledger /path/to/elicitation.json
```

The standalone command exits nonzero on invalid artifacts; a valid ledger reports reconciliation_status `not_started`, `partial` or `complete`. Exit zero alone is not a complete-reconciliation claim. The integrated threat-package command requires complete reconciliation and runs the existing shared threat-package checks. Legacy wire validation without the new flags still works but does not attest to candidate reconciliation. Do not claim full-run readiness when a required ledger or frozen input is unavailable.

The four `tests/fixtures/ledger-*.json` files are synthetic examples of model, final package, frozen elicitation and reconciliation. Copy the complete set for a local demonstration: the hashes depend on exact bytes. No personal corpus, real review history or source deck is included.
