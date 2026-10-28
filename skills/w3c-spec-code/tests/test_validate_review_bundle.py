from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "validate_review_bundle.py"
SPEC = importlib.util.spec_from_file_location("validate_review_bundle", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
validate = MODULE.validate


def valid_bundle() -> dict:
    return {
        "schema_version": "w3c-spec-code-review/v1",
        "review_id": "review-1",
        "implementation_target_status": "resolved",
        "target": {
            "specification_url": "https://example.test/spec",
            "specification_revision": "abc123",
            "section_hashes": ["sha256:section"],
        },
        "implementations": [
            {
                "implementation_id": "engine-a",
                "repository": "https://example.test/engine-a.git",
                "revision": "def456",
                "scope": ["src/feature"],
                "test_revision": "ghi789",
                "evidence_status": "available",
            }
        ],
        "controls": [
            {
                "control_id": "CTRL-1",
                "spec_anchor": "#control",
                "protected_property": "origin separation",
                "required_behavior": "reject mismatched origins",
            }
        ],
        "mappings": [
            {
                "mapping_id": "MAP-1",
                "spec_control_id": "CTRL-1",
                "implementation_id": "engine-a",
                "code_anchors": ["src/feature/check.cc:CheckOrigin"],
                "test_anchors": ["tests/origin.any.js"],
                "spec_to_code_status": "implemented",
                "code_to_spec_status": "required_by_spec",
                "scan_evidence": [],
                "counterevidence": [],
                "ownership": "implementation",
                "confidence": "high",
                "limitations": [],
            }
        ],
        "scan": {
            "status": "not_requested",
            "plugin": "codex-security@openai-curated",
            "plugin_version": None,
            "skill": None,
            "artifact_root": None,
            "artifact_hashes": {"scan_manifest": None, "coverage": None, "findings": None},
        },
        "discrepancies": [],
        "limitations": [],
    }


def test_valid_bundle() -> None:
    assert validate(valid_bundle()) == []

def test_resolved_target_requires_an_identified_implementation() -> None:
    bundle = valid_bundle()
    bundle["implementations"] = ["engine-a"]
    bundle["mappings"] = []
    errors = validate(bundle)
    assert "implementations[0]: expected object" in errors
    assert "implementations: resolved status requires at least one target" in errors

def test_valid_target_does_not_hide_a_malformed_implementation() -> None:
    bundle = valid_bundle()
    bundle["implementations"].append(None)
    assert "implementations[1]: expected object" in validate(bundle)


def test_unknown_control_is_rejected() -> None:
    bundle = valid_bundle()
    bundle["mappings"][0]["spec_control_id"] = "CTRL-404"
    assert any("unknown control" in error for error in validate(bundle))


def test_completed_scan_requires_artifact_identity() -> None:
    bundle = valid_bundle()
    bundle["scan"]["status"] = "completed"
    errors = validate(bundle)
    assert any("plugin_version" in error for error in errors)
    assert any("artifact_root" in error for error in errors)


def test_unavailable_implementation_target_is_explicit() -> None:
    bundle = valid_bundle()
    bundle["implementation_target_status"] = "unavailable"
    bundle["implementations"] = []
    bundle["mappings"] = []
    bundle["limitations"] = ["No exact implementation repository could be resolved."]
    assert validate(bundle) == []


def test_mixed_implementation_rows_preserve_original_error_indices():
    import copy
    bundle = valid_bundle()
    implementation = bundle["implementations"][0]
    bundle["implementations"] = ["bad", implementation, copy.deepcopy(implementation)]
    errors = validate(bundle)
    assert "implementations[0]: expected object" in errors
    assert "implementations[2].implementation_id: duplicate value 'engine-a'" in errors


def test_malformed_control_rows_are_rejected_even_without_mappings():
    bundle = valid_bundle()
    bundle["controls"] = [None]
    bundle["mappings"] = []
    assert "controls[0]: expected object" in validate(bundle)


def test_control_requires_source_anchor_property_and_behavior():
    bundle = valid_bundle()
    bundle["controls"] = [{"control_id": "CTRL-1"}]
    errors = validate(bundle)
    for field in ("spec_anchor", "protected_property", "required_behavior"):
        assert any("controls[0]" in error and "missing required key" in error and field in error for error in errors)


def test_implementation_requires_pinned_repository_scope_and_evidence_status():
    bundle = valid_bundle()
    bundle["implementations"] = [{"implementation_id": "engine-a"}]
    errors = validate(bundle)
    for field in ("repository", "revision", "scope", "evidence_status"):
        assert any("implementations[0]" in error and "missing required key" in error and field in error for error in errors)


def test_present_core_fields_must_have_declared_schema_shapes():
    for collection, field, value in (("implementations", "revision", ""), ("implementations", "scope", []), ("implementations", "evidence_status", []), ("controls", "spec_anchor", None)):
        bundle = valid_bundle()
        bundle[collection][0][field] = value
        assert any(collection + "[0]." + field in error for error in validate(bundle)), (collection, field)
