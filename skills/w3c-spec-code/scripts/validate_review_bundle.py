#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SPEC_TO_CODE = {"implemented", "partial", "divergent", "absent", "test_only", "non_public", "not_applicable", "unable_to_verify"}
CODE_TO_SPEC = {"required_by_spec", "implementation_specific_defense_in_depth", "compensating_control", "platform_dependency", "candidate_missing_spec_requirement", "non_security_behavior", "unable_to_verify"}
OWNERSHIP = {"specification", "implementation", "interoperability", "test", "editorial", "research_hypothesis", "unable_to_verify"}
SCAN_STATUS = {"not_requested", "unavailable", "disabled", "not_authorized", "completed", "partial", "failed"}
DISCREPANCY_KIND = {"specification_defect", "implementation_defect", "implementation_divergence", "specification_ambiguity", "test_gap", "candidate_missing_spec_requirement", "non_issue", "not_applicable", "unable_to_verify"}
GATE_STATUS = {"pending", "passed", "rejected", "unable_to_verify"}


def require_keys(value: dict[str, Any], keys: set[str], location: str, errors: list[str]) -> None:
    for key in sorted(keys - value.keys()):
        errors.append(f"{location}: missing required key {key!r}")


def unique_ids(items: list[dict[str, Any]], key: str, location: str, errors: list[str]) -> set[str]:
    seen: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"{location}[{index}]: expected object")
            continue
        value = item.get(key)
        if not isinstance(value, str) or not value:
            errors.append(f"{location}[{index}].{key}: expected non-empty string")
        elif value in seen:
            errors.append(f"{location}[{index}].{key}: duplicate value {value!r}")
        else:
            seen.add(value)
    return seen


def validate(bundle: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(bundle, dict):
        return ["root: expected object"]
    required = {"schema_version", "review_id", "implementation_target_status", "target", "implementations", "controls", "mappings", "scan", "discrepancies", "limitations"}
    require_keys(bundle, required, "root", errors)
    if bundle.get("schema_version") != "w3c-spec-code-review/v1":
        errors.append("root.schema_version: expected 'w3c-spec-code-review/v1'")
    target = bundle.get("target")
    if isinstance(target, dict):
        require_keys(target, {"specification_url", "specification_revision", "section_hashes"}, "target", errors)
    else:
        errors.append("target: expected object")
    implementations = bundle.get("implementations")
    controls = bundle.get("controls")
    mappings = bundle.get("mappings")
    discrepancies = bundle.get("discrepancies")
    if not isinstance(implementations, list):
        errors.append("implementations: expected array")
        implementations = []
    if not isinstance(controls, list):
        errors.append("controls: expected array")
        controls = []
    if not isinstance(mappings, list):
        errors.append("mappings: expected array")
        mappings = []
    if not isinstance(discrepancies, list):
        errors.append("discrepancies: expected array")
        discrepancies = []
    implementation_ids = unique_ids(implementations, "implementation_id", "implementations", errors)
    for index, implementation in enumerate(implementations):
        if not isinstance(implementation, dict):
            continue
        location = f"implementations[{index}]"
        require_keys(implementation, {"implementation_id", "repository", "revision", "scope", "evidence_status"}, location, errors)
        for field in ("repository", "revision"):
            if field in implementation and (not isinstance(implementation[field], str) or not implementation[field].strip()):
                errors.append(f"{location}.{field}: expected non-empty string")
        if "scope" in implementation:
            scope = implementation["scope"]
            if not isinstance(scope, list) or not scope or any(not isinstance(item, str) for item in scope):
                errors.append(f"{location}.scope: expected non-empty array of strings")
        if "evidence_status" in implementation:
            status = implementation["evidence_status"]
            if not isinstance(status, str) or status not in {"available", "partial", "non_public", "unavailable"}:
                errors.append(f"{location}.evidence_status: invalid status")
    target_status = bundle.get("implementation_target_status")
    if target_status not in {"resolved", "partial", "unavailable", "not_applicable"}:
        errors.append("implementation_target_status: invalid status")
    if target_status == "resolved" and not implementation_ids:
        errors.append("implementations: resolved status requires at least one target")
    if target_status in {"unavailable", "not_applicable"} and implementations:
        errors.append(f"implementations: {target_status!r} status requires an empty target array")
    control_ids = unique_ids(controls, "control_id", "controls", errors)
    for index, control in enumerate(controls):
        if not isinstance(control, dict):
            continue
        location = f"controls[{index}]"
        require_keys(control, {"control_id", "spec_anchor", "protected_property", "required_behavior"}, location, errors)
        for field in ("spec_anchor", "protected_property", "required_behavior"):
            if field in control and (not isinstance(control[field], str) or not control[field].strip()):
                errors.append(f"{location}.{field}: expected non-empty string")
    unique_ids(mappings, "mapping_id", "mappings", errors)
    unique_ids(discrepancies, "discrepancy_id", "discrepancies", errors)
    for index, mapping in enumerate(mappings):
        if not isinstance(mapping, dict):
            continue  # unique_ids already reported this row with its original index.
        require_keys(mapping, {"mapping_id", "spec_control_id", "implementation_id", "code_anchors", "test_anchors", "spec_to_code_status", "code_to_spec_status", "scan_evidence", "counterevidence", "ownership", "confidence", "limitations"}, f"mappings[{index}]", errors)
        control_id = mapping.get("spec_control_id")
        if control_id != "implementation_only" and control_id not in control_ids:
            errors.append(f"mappings[{index}].spec_control_id: unknown control {control_id!r}")
        if mapping.get("implementation_id") not in implementation_ids:
            errors.append(f"mappings[{index}].implementation_id: unknown implementation {mapping.get('implementation_id')!r}")
        if mapping.get("spec_to_code_status") not in SPEC_TO_CODE:
            errors.append(f"mappings[{index}].spec_to_code_status: invalid disposition")
        if mapping.get("code_to_spec_status") not in CODE_TO_SPEC:
            errors.append(f"mappings[{index}].code_to_spec_status: invalid disposition")
        if mapping.get("ownership") not in OWNERSHIP:
            errors.append(f"mappings[{index}].ownership: invalid ownership")
    scan = bundle.get("scan")
    if isinstance(scan, dict):
        require_keys(scan, {"status", "plugin", "plugin_version", "skill", "artifact_root", "artifact_hashes"}, "scan", errors)
        status = scan.get("status")
        if status not in SCAN_STATUS:
            errors.append("scan.status: invalid status")
        if scan.get("plugin") != "codex-security@openai-curated":
            errors.append("scan.plugin: expected 'codex-security@openai-curated'")
        if status in {"completed", "partial"}:
            for key in ("plugin_version", "skill", "artifact_root"):
                if not scan.get(key):
                    errors.append(f"scan.{key}: required when status is {status!r}")
    else:
        errors.append("scan: expected object")
    for index, discrepancy in enumerate(discrepancies):
        if not isinstance(discrepancy, dict):
            continue  # unique_ids already reported this row with its original index.
        require_keys(discrepancy, {"discrepancy_id", "kind", "evidence", "counterevidence", "ownership", "gate_status"}, f"discrepancies[{index}]", errors)
        if discrepancy.get("kind") not in DISCREPANCY_KIND:
            errors.append(f"discrepancies[{index}].kind: invalid kind")
        if discrepancy.get("ownership") not in OWNERSHIP:
            errors.append(f"discrepancies[{index}].ownership: invalid ownership")
        if discrepancy.get("gate_status") not in GATE_STATUS:
            errors.append(f"discrepancies[{index}].gate_status: invalid gate status")
    if not isinstance(bundle.get("limitations"), list):
        errors.append("limitations: expected array")
    elif target_status == "unavailable" and not bundle["limitations"]:
        errors.append("limitations: unavailable implementation target requires a coverage limitation")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a W3C specification-to-code review bundle.")
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    try:
        bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"invalid: {error}", file=sys.stderr)
        return 1
    errors = validate(bundle)
    if errors:
        for error in errors:
            print(f"invalid: {error}", file=sys.stderr)
        return 1
    print("valid: w3c-spec-code-review/v1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
