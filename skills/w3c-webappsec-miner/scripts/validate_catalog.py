#!/usr/bin/env python3
"""Validate catalog structure, cross-references, evidence, and charter coverage."""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CHARTER_URL = "https://w3c.github.io/charter-drafts/2026/charter-wg-webappsec-2026.html"
CONTROL_PATTERN = re.compile(r"^WAM-[A-Z]+-[0-9]{2}$")
DEFAULT_PATTERN = re.compile(r"^WAD-[0-9]{2}$")
EXCEPTION_PATTERN = re.compile(r"^WAE-[0-9]{2}$")
EVIDENCE_CLASSES = {"explicit-normative", "explicit-informative", "derived-cross-spec-synthesis", "charter-scope"}
EVIDENCE_STATUSES = {"verified-official-w3c-tr", "verified-official-whatwg", "verified-official-editor-draft", "verified-local-source-packet-v1", "inventory-only"}


def load(relative_path: str) -> dict[str, Any]:
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


def validate_evidence(evidence: Any, context: str, errors: list[str]) -> None:
    if not isinstance(evidence, list) or not evidence:
        errors.append(f"{context}: evidence must be a non-empty list")
        return
    for index, item in enumerate(evidence):
        location = f"{context}.evidence[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{location}: evidence item must be an object")
            continue
        for key in ("source_title", "source_url", "section", "evidence_class", "evidence_status"):
            if not item.get(key):
                errors.append(f"{location}: missing {key}")
        if not str(item.get("source_url", "")).startswith("https://"):
            errors.append(f"{location}: source_url must use https")
        if "#" not in str(item.get("source_url", "")):
            errors.append(f"{location}: source_url must identify an exact section")
        if item.get("evidence_class") not in EVIDENCE_CLASSES:
            errors.append(f"{location}: unsupported evidence_class")
        if item.get("evidence_status") not in EVIDENCE_STATUSES:
            errors.append(f"{location}: unsupported evidence_status")
        if item.get("evidence_status") == "verified-local-source-packet-v1" and not item.get("source_packet_evidence_ids"):
            errors.append(f"{location}: Source Packet v1 evidence requires evidence IDs")


def unique_ids(items: list[dict[str, Any]], key: str, pattern: re.Pattern[str], errors: list[str]) -> set[str]:
    ids = [item.get(key) for item in items]
    for value in ids:
        if not isinstance(value, str) or not pattern.fullmatch(value):
            errors.append(f"invalid {key}: {value!r}")
    duplicates = [value for value, count in Counter(ids).items() if count > 1]
    if duplicates:
        errors.append(f"duplicate {key}: {duplicates}")
    return {value for value in ids if isinstance(value, str)}


def string_array(record: dict[str, Any], key: str, context: str, errors: list[str], *, non_empty: bool = False) -> list[str]:
    value = record.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        errors.append(f"{context}: {key} must be an array of non-empty strings")
        return []
    if non_empty and not value:
        errors.append(f"{context}: {key} must be non-empty")
    if len(value) != len(set(value)):
        errors.append(f"{context}: {key} must not contain duplicates")
    return value


def validate() -> list[str]:
    errors: list[str] = []
    controls_doc = load("catalog/security-controls.json")
    defaults_doc = load("catalog/secure-defaults.json")
    exceptions_doc = load("catalog/exceptions.json")
    deliverables_doc = load("references/charter-deliverables.json")
    for name, document in (("controls", controls_doc), ("defaults", defaults_doc), ("exceptions", exceptions_doc), ("deliverables", deliverables_doc)):
        if document.get("schema_version") != "1.0":
            errors.append(f"{name}: unsupported schema_version")
    if controls_doc.get("charter_url") != CHARTER_URL or deliverables_doc.get("charter_url") != CHARTER_URL:
        errors.append("catalogs must use the exact 2026 charter URL")
    controls = controls_doc.get("controls", [])
    defaults = defaults_doc.get("defaults", [])
    exceptions = exceptions_doc.get("exceptions", [])
    deliverables = deliverables_doc.get("deliverables", [])
    control_ids = unique_ids(controls, "control_id", CONTROL_PATTERN, errors)
    default_ids = unique_ids(defaults, "default_id", DEFAULT_PATTERN, errors)
    exception_ids = unique_ids(exceptions, "exception_id", EXCEPTION_PATTERN, errors)
    for control in controls:
        context = control.get("control_id", "control")
        for key in ("title", "family", "mechanism", "review_question", "normative_strength"):
            if not control.get(key):
                errors.append(f"{context}: missing {key}")
        applicability = string_array(control, "applicability", context, errors, non_empty=True)
        if not applicability or not control.get("limitations"):
            errors.append(f"{context}: applicability and limitations must be non-empty")
        for value in string_array(control, "default_ids", context, errors):
            if value not in default_ids:
                errors.append(f"{context}: unknown default {value}")
        for value in string_array(control, "exception_ids", context, errors):
            if value not in exception_ids:
                errors.append(f"{context}: unknown exception {value}")
        validate_evidence(control.get("evidence"), context, errors)
    for default in defaults:
        context = default.get("default_id", "default")
        for value in string_array(default, "control_ids", context, errors, non_empty=True):
            if value not in control_ids:
                errors.append(f"{context}: unknown control {value}")
        for value in string_array(default, "exception_ids", context, errors):
            if value not in exception_ids:
                errors.append(f"{context}: unknown exception {value}")
        validate_evidence(default.get("evidence"), context, errors)
    for exception in exceptions:
        context = exception.get("exception_id", "exception")
        for value in string_array(exception, "control_ids", context, errors, non_empty=True):
            if value not in control_ids:
                errors.append(f"{context}: unknown control {value}")
        validate_evidence(exception.get("evidence"), context, errors)
    actual_categories = Counter(item.get("category") for item in deliverables)
    declared_categories = deliverables_doc.get("categories", {})
    for category in ("normative", "tentative", "other"):
        if actual_categories[category] != declared_categories.get(category):
            errors.append(f"deliverables: {category} count mismatch")
    if declared_categories != {"normative": 17, "tentative": 3, "other": 4}:
        errors.append("deliverables: expected exact charter counts 17 normative, 3 tentative, 4 other")
    deliverable_ids = [item.get("deliverable_id") for item in deliverables]
    if len(deliverable_ids) != len(set(deliverable_ids)):
        errors.append("deliverables: duplicate deliverable_id")
    for item in deliverables:
        if item.get("category") == "normative" and item.get("mining_status") == "inventory-only":
            errors.append(f"deliverables: normative item not control-mined: {item.get('deliverable_id')}")
    return errors


def main() -> int:
    errors = validate()
    if errors:
        for error in errors:
            print(f"ERROR {error}")
        return 1
    controls = len(load("catalog/security-controls.json")["controls"])
    defaults = len(load("catalog/secure-defaults.json")["defaults"])
    exceptions = len(load("catalog/exceptions.json")["exceptions"])
    print(f"OK controls={controls} defaults={defaults} exceptions={exceptions} charter=17/3/4")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
