"""Validate a TMDC-style Mermaid DFD and its complete dictionary."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


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

TYPE_PREFIX = {
    "External Entity": "EE",
    "Process": "PO",
    "Data Store": "DS",
    "Data Flow": "DF",
    "Trust Boundary": "TB",
}

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
EVIDENCE_STATUSES = {"supplied", "verified", "inferred", "assumed", "untested", "unavailable"}


def load_dictionary(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
        return payload
    raise ValueError("dictionary JSON must contain contract_version, model_id, and a rows array")


def validate_dictionary(rows: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    ids: set[str] = set()
    mermaid_ids: set[str] = set()

    for index, row in enumerate(rows):
        where = f"dictionary[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{where}: must be an object")
            continue
        for field in sorted(DICTIONARY_FIELDS - row.keys()):
            errors.append(f"{where}: missing required dictionary field {field}")

        row_id = row.get("canonical_id")
        if not isinstance(row_id, str) or not CANONICAL_ID.fullmatch(row_id):
            errors.append(f"{where}.canonical_id: {row_id!r} is not a canonical hyphenated ID")
        elif row_id in ids:
            errors.append(f"{where}.canonical_id: duplicate canonical ID {row_id}")
        else:
            ids.add(row_id)

        mermaid_id = row.get("mermaid_node_id")
        if not isinstance(mermaid_id, str) or not MERMAID_ID.fullmatch(mermaid_id):
            errors.append(f"{where}.mermaid_node_id: {mermaid_id!r} is not a Mermaid-safe renderer ID")
        elif mermaid_id in mermaid_ids:
            errors.append(f"{where}.mermaid_node_id: duplicate renderer ID {mermaid_id}")
        else:
            mermaid_ids.add(mermaid_id)

        row_type = row.get("type")
        prefix = TYPE_PREFIX.get(row_type)
        if prefix is None:
            errors.append(f"{where}.type: invalid DFD type {row_type!r}")
        else:
            if isinstance(row_id, str) and not row_id.startswith(prefix + "-"):
                errors.append(f"{where}.canonical_id: prefix does not match {row_type}")
            if isinstance(mermaid_id, str) and not mermaid_id.startswith(prefix):
                errors.append(f"{where}.mermaid_node_id: prefix does not match {row_type}")

        if isinstance(row_id, str) and row_id not in str(row.get("visible_label", "")):
            errors.append(f"{where}.visible_label: must contain canonical ID {row_id}")
        for field in (
            "visible_label",
            "name",
            "description",
            "source_id",
            "assurance_level",
            "specification_reference",
        ):
            if field in row and not str(row.get(field, "")).strip():
                errors.append(f"{where}.{field}: must not be empty")
        for field in ("assumptions", "boundary_membership"):
            if field in row and not isinstance(row[field], list):
                errors.append(f"{where}.{field}: must be an array")
        if row.get("assurance_level") not in ASSURANCE_LEVELS:
            errors.append(f"{where}.assurance_level: invalid value {row.get('assurance_level')!r}")
        if row.get("coverage_status") not in COVERAGE_STATUSES:
            errors.append(f"{where}.coverage_status: invalid value {row.get('coverage_status')!r}")
        if row.get("evidence_status") not in EVIDENCE_STATUSES:
            errors.append(f"{where}.evidence_status: invalid value {row.get('evidence_status')!r}")

    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        where = f"dictionary[{index}]"
        row_id = row.get("canonical_id")
        if isinstance(row_id, str) and row_id.startswith("DF-"):
            for field in ("flow_source", "flow_destination"):
                endpoint = row.get(field)
                if endpoint not in ids:
                    errors.append(f"{where}.{field}: {endpoint!r} is not a dictionary ID")
                elif str(endpoint).startswith(("DF-", "TB-")):
                    errors.append(f"{where}.{field}: flows and boundaries cannot be data-flow endpoints")
        else:
            for field in ("flow_source", "flow_destination"):
                if field in row and row[field] != "":
                    errors.append(f"{where}.{field}: must be an empty string for non-flow rows")
        memberships = row.get("boundary_membership", [])
        if not isinstance(memberships, list):
            continue  # The first pass already reports the invalid array.
        for boundary_id in memberships:
            if not isinstance(boundary_id, str) or boundary_id not in ids or not boundary_id.startswith("TB-"):
                errors.append(f"{where}.boundary_membership: unknown boundary {boundary_id!r}")
    return errors


def validate_mermaid(source: str, rows: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    source = "\n".join(
        line if line.lstrip().startswith("%%{") else line.split("%%", 1)[0]
        for line in source.splitlines()
    )
    compact = re.sub(r"\s+", "", source)
    required_tmdc_fragments = {
        "TMDC init theme": '%%{init:{"theme":"base"',
        "Arial font": "font-family:Arial,sans-serif",
        "22px text": "font-size:22px",
        "linear connectors": '"curve":"linear"',
        "HTML labels": '"htmlLabels":true',
        "node spacing": '"nodeSpacing":80',
        "rank spacing": '"rankSpacing":95',
        "padding": '"padding":18',
        "white 4px nodes": "classDefdefaultfill:#fff,stroke:#000,stroke-width:4px",
        "thick black links": "linkStyledefaultstroke:#000,stroke-width:3px,color:#000",
    }
    for label, fragment in required_tmdc_fragments.items():
        if fragment not in compact:
            errors.append(f"mermaid: missing canonical TMDC {label}")
    if "flowchart" not in source:
        errors.append("mermaid: missing flowchart declaration")
    if "==>" not in source:
        errors.append("mermaid: TMDC flows must use ==> thick arrows")
    if "-->" in source:
        errors.append("mermaid: thin --> arrows are not canonical TMDC flows")
    if "<span" in source or "<b>" in source:
        errors.append("mermaid: HTML styling labels are forbidden; use <br/> only")

    by_id = {row.get("canonical_id"): row for row in rows if isinstance(row, dict)}
    expected_nodes = {
        row.get("mermaid_node_id") for row in rows
        if isinstance(row, dict) and row.get("type") != "Data Flow"
    }
    rendered_nodes = set(re.findall(r"\b(?:EE|PO|DS|TB)\d+_[A-Za-z0-9_]+\b", source))
    extra_nodes = sorted(rendered_nodes - expected_nodes)
    if extra_nodes:
        errors.append(f"mermaid: renderer IDs absent from dictionary: {extra_nodes}")
    flow_ids = re.findall(r"==>\|\s*(DF-\d{2,})<br/>", source)
    expected_flows = {row_id for row_id in by_id if isinstance(row_id, str) and row_id.startswith("DF-")}
    extra_flows = sorted(set(flow_ids) - expected_flows)
    if extra_flows:
        errors.append(f"mermaid: flow IDs absent from dictionary: {extra_flows}")
    if len(flow_ids) != len(set(flow_ids)):
        errors.append("mermaid: duplicate flow IDs in diagram")
    if len(flow_ids) != source.count("==>"):
        errors.append("mermaid: every thick arrow must have a canonical named flow")
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        row_id = row.get("canonical_id")
        mermaid_id = row.get("mermaid_node_id")
        row_type = row.get("type")
        if not isinstance(row_id, str) or not isinstance(mermaid_id, str):
            continue
        if row_type == "Trust Boundary":
            if not re.search(rf"subgraph\s+{re.escape(mermaid_id)}\s*\[\"{re.escape(row_id)}(?:\s|<br/>)", source):
                errors.append(f"mermaid: {row_id} must use a native subgraph label with renderer ID {mermaid_id}")
            style_match = re.search(rf"(?m)^\s*style\s+{re.escape(mermaid_id)}\s+([^\n]+)", source)
            properties = {}
            if style_match:
                for declaration in style_match.group(1).rstrip("; ").split(","):
                    key, separator, value = declaration.partition(":")
                    if separator:
                        properties[key.strip()] = value.strip()
            if not (
                properties.get("stroke") in {"#000", "#000000", "black"}
                and properties.get("stroke-width") == "4px"
                and properties.get("stroke-dasharray", "").split() == ["8", "6"]
            ):
                errors.append(f"mermaid: {row_id} must have a dashed black 4px trust-boundary style")
        elif row_type == "External Entity":
            if not re.search(rf"^\s*{re.escape(mermaid_id)}\[{re.escape(row_id)}<br/>", source, re.MULTILINE):
                errors.append(f"mermaid: {row_id} must use square external-entity syntax")
        elif row_type == "Process":
            if not re.search(rf"^\s*{re.escape(mermaid_id)}\({re.escape(row_id)}<br/>", source, re.MULTILINE):
                errors.append(f"mermaid: {row_id} must use rounded process syntax")
        elif row_type == "Data Store":
            if not re.search(rf"^\s*{re.escape(mermaid_id)}\[\({re.escape(row_id)}<br/>", source, re.MULTILINE):
                errors.append(f"mermaid: {row_id} must use database data-store syntax")
        elif row_type == "Data Flow":
            source_row = by_id.get(row.get("flow_source"), {})
            destination_row = by_id.get(row.get("flow_destination"), {})
            source_renderer = source_row.get("mermaid_node_id")
            destination_renderer = destination_row.get("mermaid_node_id")
            if source_renderer and destination_renderer:
                pattern = (
                    rf"{re.escape(source_renderer)}\s*==>\|{re.escape(row_id)}<br/>"
                    rf"[^|]+\|\s*{re.escape(destination_renderer)}"
                )
                if not re.search(pattern, source):
                    errors.append(
                        f"mermaid: {row_id} must be a named thick flow from {source_renderer} to {destination_renderer}"
                    )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mermaid", type=Path)
    parser.add_argument("dictionary", type=Path)
    args = parser.parse_args()
    try:
        source = args.mermaid.read_text(encoding="utf-8")
        dictionary = load_dictionary(args.dictionary)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"DFD validation failed: {exc}")
        return 1

    rows = dictionary["rows"]
    errors: list[str] = []
    if dictionary.get("contract_version") != 1:
        errors.append("dictionary.contract_version: must be 1")
    if not str(dictionary.get("model_id", "")).strip():
        errors.append("dictionary.model_id: must not be empty")
    errors.extend(validate_dictionary(rows))
    errors.extend(validate_mermaid(source, rows))
    if errors:
        for error in errors:
            print(error)
        return 1
    print(f"DFD validation passed: {len(rows)} complete dictionary rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
