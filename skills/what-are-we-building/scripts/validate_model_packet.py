"""Validate a model-packet v1 JSON file through the shared workbench contract."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ID_PREFIX_BY_COLLECTION = {
    "external_entities": "EE",
    "processes": "PO",
    "data_stores": "DS",
    "data_flows": "DF",
    "trust_boundaries": "TB",
}

TYPE_BY_COLLECTION = {
    "external_entities": "External Entity",
    "processes": "Process",
    "data_stores": "Data Store",
    "data_flows": "Data Flow",
    "trust_boundaries": "Trust Boundary",
}

DICTIONARY_FIELDS = {
    "canonical_id",
    "mermaid_node_id",
    "type",
    "visible_label",
    "name",
    "description",
    "source_id",
    "assurance_level",
    "specification_reference",
    "source_locator",
    "coverage_status",
    "evidence_status",
    "assumptions",
    "boundary_membership",
    "flow_source",
    "flow_destination",
}

DETAIL_LEVELS = {"high-level", "medium-detail", "very-detailed"}
EVIDENCE_STATUSES = {"supplied", "verified", "inferred", "assumed", "untested", "unavailable"}
CANONICAL_ID = re.compile(r"^(EE|PO|DS|DF|TB)-\d{2,}$")
MERMAID_ID = re.compile(r"^(EE|PO|DS|DF|TB)\d+_[A-Za-z0-9_]+$")
ASSURANCE_LEVELS = {"L1", "L2", "L3", "context", "unavailable"}
COVERAGE_STATUSES = {
    "covered",
    "partially-covered",
    "not-covered",
    "out-of-scope",
    "unavailable",
    "context",
}


def resolve_contract_root() -> Path:
    explicit = os.environ.get("STANDARDS_REVIEW_CONTRACTS_ROOT")
    repository_root = Path(__file__).resolve().parents[1]
    candidates = [Path(explicit)] if explicit else []
    candidates.extend([repository_root, repository_root.parents[1]])
    for candidate in candidates:
        if (candidate / "scripts" / "validate_threat_model_contract.py").is_file():
            return candidate
    raise SystemExit(
        "Cannot find the shared threat-model contract validator. Set "
        "STANDARDS_REVIEW_CONTRACTS_ROOT or install the contract tree in the project package."
    )


def _element_id(element: dict[str, Any]) -> Any:
    return element.get("stable_id") or element.get("candidate_id")


def validate_full_spec_handoff(
    packet: dict[str, Any], dictionary: dict[str, Any]
) -> list[str]:
    """Validate the stricter, render-ready profile owned by this skill."""

    errors: list[str] = []
    detail_level = packet.get("dfd_detail_level")
    if detail_level not in DETAIL_LEVELS:
        errors.append(
            "model.dfd_detail_level: must be high-level, medium-detail, or very-detailed"
        )

    model_elements: dict[str, tuple[str, dict[str, Any]]] = {}
    for collection, prefix in ID_PREFIX_BY_COLLECTION.items():
        for index, element in enumerate(packet.get(collection, [])):
            if not isinstance(element, dict):
                continue
            element_id = _element_id(element)
            where = f"model.{collection}[{index}]"
            if not isinstance(element_id, str) or not CANONICAL_ID.fullmatch(element_id):
                errors.append(
                    f"{where}: ID {element_id!r} must use the canonical {prefix}-01 form"
                )
                continue
            if not element_id.startswith(f"{prefix}-"):
                errors.append(f"{where}: ID {element_id!r} has the wrong type prefix")
            if element_id in model_elements:
                errors.append(f"{where}: duplicate model element ID {element_id}")
            model_elements[element_id] = (collection, element)

    if dictionary.get("contract_version") != 1:
        errors.append("dfd_dictionary.contract_version: must be 1")
    if dictionary.get("model_id") != packet.get("model_id"):
        errors.append("dfd_dictionary.model_id: must match the model packet")
    rows = dictionary.get("rows")
    if not isinstance(rows, list):
        errors.append("dfd_dictionary.rows: required for a full specification handoff and must be an array")
        return errors

    dictionary_ids: set[str] = set()
    for index, row in enumerate(rows):
        where = f"dfd_dictionary.rows[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{where}: must be an object")
            continue
        missing = sorted(DICTIONARY_FIELDS - row.keys())
        for field in missing:
            errors.append(f"{where}: missing required dictionary field {field}")

        row_id = row.get("canonical_id")
        if not isinstance(row_id, str) or not CANONICAL_ID.fullmatch(row_id):
            errors.append(f"{where}.canonical_id: {row_id!r} is not a canonical model/report ID")
        elif row_id in dictionary_ids:
            errors.append(f"{where}.canonical_id: duplicate dictionary ID {row_id}")
        else:
            dictionary_ids.add(row_id)

        mermaid_id = row.get("mermaid_node_id")
        if not isinstance(mermaid_id, str) or not MERMAID_ID.fullmatch(mermaid_id):
            errors.append(
                f"{where}.mermaid_node_id: {mermaid_id!r} must be a separate Mermaid-safe renderer ID"
            )
        elif mermaid_id == row_id:
            errors.append(f"{where}.mermaid_node_id: must not replace or equal the canonical ID")
        elif isinstance(row_id, str) and mermaid_id[:2] != row_id[:2]:
            errors.append(f"{where}.mermaid_node_id: type prefix does not match {row_id}")

        if isinstance(row_id, str) and row_id not in str(row.get("visible_label", "")):
            errors.append(f"{where}.visible_label: must contain canonical ID {row_id}")

        for field in (
            "type",
            "visible_label",
            "name",
            "description",
            "source_id",
            "assurance_level",
            "specification_reference",
        ):
            if field in row and not str(row.get(field, "")).strip():
                errors.append(f"{where}.{field}: must not be empty")

        if row.get("evidence_status") not in EVIDENCE_STATUSES:
            errors.append(f"{where}.evidence_status: invalid value {row.get('evidence_status')!r}")
        if row.get("assurance_level") not in ASSURANCE_LEVELS:
            errors.append(f"{where}.assurance_level: invalid value {row.get('assurance_level')!r}")
        if row.get("coverage_status") not in COVERAGE_STATUSES:
            errors.append(f"{where}.coverage_status: invalid value {row.get('coverage_status')!r}")
        for field in ("assumptions", "boundary_membership"):
            if field in row and not isinstance(row[field], list):
                errors.append(f"{where}.{field}: must be an array")

        model_entry = model_elements.get(row_id) if isinstance(row_id, str) else None
        if model_entry:
            collection, element = model_entry
            expected_type = TYPE_BY_COLLECTION[collection]
            if row.get("type") != expected_type:
                errors.append(f"{where}.type: must be {expected_type!r} for {row_id}")
            if row.get("name") != element.get("name"):
                errors.append(f"{where}.name: must preserve the model element name")
            if row.get("description") != element.get("description"):
                errors.append(f"{where}.description: must preserve the model element description")
            if row.get("specification_reference") != element.get("source_reference"):
                errors.append(
                    f"{where}.specification_reference: must preserve source_reference from {row_id}"
                )
            if row.get("evidence_status") != element.get("evidence_status"):
                errors.append(f"{where}.evidence_status: must preserve evidence status from {row_id}")
            if collection == "data_flows":
                endpoints = {
                    "flow_source": element.get("source") or element.get("flow_source"),
                    "flow_destination": element.get("destination") or element.get("target") or element.get("flow_destination"),
                }
                for field, expected in endpoints.items():
                    if row.get(field) != expected:
                        errors.append(f"{where}.{field}: must preserve the model flow endpoint from {row_id}")

        if isinstance(row_id, str) and row_id.startswith("DF-"):
            for field in ("flow_source", "flow_destination"):
                endpoint = row.get(field)
                if not isinstance(endpoint, str) or endpoint not in model_elements:
                    errors.append(f"{where}.{field}: must name a canonical model element ID")
                elif endpoint.startswith(("DF-", "TB-")):
                    errors.append(f"{where}.{field}: data-flow endpoints cannot be flows or boundaries")
        else:
            for field in ("flow_source", "flow_destination"):
                if field in row and row[field] != "":
                    errors.append(f"{where}.{field}: must be an empty string for non-flow dictionary rows")

    missing_rows = sorted(set(model_elements) - dictionary_ids)
    extra_rows = sorted(dictionary_ids - set(model_elements))
    if missing_rows:
        errors.append(f"model.dfd_dictionary: missing rows for {', '.join(missing_rows)}")
    if extra_rows:
        errors.append(f"model.dfd_dictionary: rows without model elements: {', '.join(extra_rows)}")

    valid_boundaries = {element_id for element_id in model_elements if element_id.startswith("TB-")}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        memberships = row.get("boundary_membership", [])
        if not isinstance(memberships, list):
            continue  # The first pass already reports the invalid array.
        for boundary_id in memberships:
            if not isinstance(boundary_id, str) or boundary_id not in valid_boundaries:
                errors.append(
                    f"dfd_dictionary.rows[{index}].boundary_membership: unknown boundary {boundary_id!r}"
                )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model_packet", type=Path)
    parser.add_argument("dictionary", type=Path)
    args = parser.parse_args()
    try:
        packet = json.loads(args.model_packet.read_text(encoding="utf-8"))
        dictionary = json.loads(args.dictionary.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"invalid model packet: {exc}")
        return 1
    if not isinstance(packet, dict) or not isinstance(dictionary, dict):
        print("invalid handoff: model packet and dictionary must both be JSON objects")
        return 1

    contract_root = resolve_contract_root()
    command = [
        sys.executable,
        str(contract_root / "scripts" / "validate_threat_model_contract.py"),
        "--model",
        str(args.model_packet),
        "--dictionary",
        str(args.dictionary),
    ]
    shared = subprocess.run(command, check=False, text=True, capture_output=True)
    if shared.stdout:
        sys.stdout.write(shared.stdout)
    if shared.stderr:
        sys.stderr.write(shared.stderr)

    local_errors = validate_full_spec_handoff(packet, dictionary)
    for error in local_errors:
        print(error)
    if shared.returncode or local_errors:
        return 1
    print("full specification model handoff is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
