# Threat Modeling Flow Contract v1

This directory is the canonical, dependency-free public contract boundary for the exported threat-modeling flow.

It builds on the maintainer-authored validator, schemas, strict tests, and synthetic fixtures pinned by `contracts/shared-contract-v1.json`. That manifest records the imported baseline; subsequent public changes are tracked in Git. The response contract also supports combined ERTA strategies as documented in `skills/what-are-we-going-to-do-about-it/contracts/response-analysis-v1.md`.

The shared validator owns cross-artifact invariants: contract versions, canonical model and assumption identifiers, model/dictionary equality, model-to-threat and threat-to-response traceability, complete response coverage, and handoff ID authority. Producer validators remain responsible for richer stage-specific semantics.

The paths `contracts/scripts/validate_threat_model_contract.py` and `scripts/validate_threat_model_contract.py` are compatibility entry points only. They must not acquire independent contract semantics.

Publication status: `publication_review_required`.
