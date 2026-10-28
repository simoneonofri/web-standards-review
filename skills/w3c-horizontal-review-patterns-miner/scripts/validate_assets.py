#!/usr/bin/env python3
"""Validate bundled taxonomy, pattern, and example assets."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


SKILL_DIR = Path(__file__).resolve().parents[1]
TAXONOMY_PATH = SKILL_DIR / "references" / "specification-taxonomy.json"
PATTERNS_PATH = SKILL_DIR / "references" / "review-patterns.json"
ASSETS_DIR = SKILL_DIR / "assets"

REVIEW_KINDS = {"tag-design", "privacy", "security"}
PROVENANCE_CLASSES = {"normative", "empirical", "validated", "seed"}
MATURITIES = {"draft", "stable", "deprecated"}
REQUIRED_PATTERN_FIELDS = {
    "pattern_id",
    "title",
    "review_kind",
    "summary",
    "applicable_families",
    "applies_when",
    "trigger_signals",
    "review_questions",
    "failure_modes",
    "expected_properties",
    "common_mitigations",
    "evidence_requirements",
    "related_patterns",
    "provenance_class",
    "maturity",
}
APPLIES_FIELDS = {"facets_all", "facets_any", "facets_none"}


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc


def is_confidence(value: Any) -> bool:
    return isinstance(value, (int, float)) and 0 <= value <= 1


def validate_taxonomy(errors: list[str]) -> tuple[set[str], set[str]]:
    taxonomy = load_json(TAXONOMY_PATH)
    family_ids: set[str] = set()
    facet_ids: set[str] = set()

    for dimension, facets in taxonomy.get("facet_dimensions", {}).items():
        if not isinstance(facets, list) or not facets:
            errors.append(f"facet dimension {dimension!r} must be a non-empty list")
            continue
        for facet in facets:
            if facet in facet_ids:
                errors.append(f"duplicate facet id: {facet}")
            facet_ids.add(facet)

    for family in taxonomy.get("families", []):
        family_id = family.get("family_id")
        if not family_id:
            errors.append("family missing family_id")
            continue
        if family_id in family_ids:
            errors.append(f"duplicate family id: {family_id}")
        family_ids.add(family_id)
        for facet in family.get("typical_facets", []):
            if facet not in facet_ids:
                errors.append(f"{family_id}: unknown typical facet {facet}")
        for related in family.get("common_overlaps", []):
            if related == family_id:
                errors.append(f"{family_id}: common_overlaps references itself")

    for family in taxonomy.get("families", []):
        for related in family.get("common_overlaps", []):
            if related not in family_ids:
                errors.append(f"{family.get('family_id')}: unknown overlap family {related}")

    return family_ids, facet_ids


def require_non_empty_list(pattern: dict[str, Any], key: str, errors: list[str]) -> None:
    if not isinstance(pattern.get(key), list) or not pattern[key]:
        errors.append(f"{pattern.get('pattern_id', '<unknown>')}: {key} must be a non-empty list")


def validate_patterns(family_ids: set[str], facet_ids: set[str], errors: list[str]) -> dict[str, int]:
    data = load_json(PATTERNS_PATH)
    patterns = data.get("patterns", [])
    if len(patterns) < 40:
        errors.append(f"review-patterns.json: expected at least 40 patterns, found {len(patterns)}")

    pattern_ids: set[str] = set()
    counts = {kind: 0 for kind in REVIEW_KINDS}

    for pattern in patterns:
        missing = REQUIRED_PATTERN_FIELDS - set(pattern)
        if missing:
            errors.append(f"{pattern.get('pattern_id', '<unknown>')}: missing fields {sorted(missing)}")
            continue

        pattern_id = pattern["pattern_id"]
        if pattern_id in pattern_ids:
            errors.append(f"duplicate pattern id: {pattern_id}")
        pattern_ids.add(pattern_id)

        review_kind = pattern.get("review_kind")
        if review_kind not in REVIEW_KINDS:
            errors.append(f"{pattern_id}: invalid review_kind {review_kind!r}")
        else:
            counts[review_kind] += 1

        if pattern.get("provenance_class") not in PROVENANCE_CLASSES:
            errors.append(f"{pattern_id}: invalid provenance_class {pattern.get('provenance_class')!r}")
        if pattern.get("maturity") not in MATURITIES:
            errors.append(f"{pattern_id}: invalid maturity {pattern.get('maturity')!r}")

        require_non_empty_list(pattern, "applicable_families", errors)
        for family in pattern.get("applicable_families", []):
            if family not in family_ids:
                errors.append(f"{pattern_id}: unknown applicable family {family}")

        applies = pattern.get("applies_when")
        if not isinstance(applies, dict) or set(applies) != APPLIES_FIELDS:
            errors.append(f"{pattern_id}: applies_when must contain {sorted(APPLIES_FIELDS)}")
        else:
            for key, facets in applies.items():
                if not isinstance(facets, list):
                    errors.append(f"{pattern_id}: applies_when.{key} must be a list")
                    continue
                for facet in facets:
                    if facet not in facet_ids:
                        errors.append(f"{pattern_id}: unknown facet {facet} in applies_when.{key}")

        for key in (
            "trigger_signals",
            "review_questions",
            "failure_modes",
            "expected_properties",
            "common_mitigations",
            "evidence_requirements",
        ):
            require_non_empty_list(pattern, key, errors)

    for pattern in patterns:
        pattern_id = pattern.get("pattern_id")
        for related in pattern.get("related_patterns", []):
            if related not in pattern_ids:
                errors.append(f"{pattern_id}: dangling related pattern {related}")

    for kind, count in sorted(counts.items()):
        if count < 12:
            errors.append(f"{kind}: expected at least 12 patterns, found {count}")

    return counts


def validate_confidence_values(obj: Any, where: str, errors: list[str]) -> None:
    if isinstance(obj, dict):
        if "confidence" in obj and not is_confidence(obj["confidence"]):
            errors.append(f"{where}: invalid confidence {obj['confidence']!r}")
        if obj.get("status") == "confirmed" and "finding_id" in obj and not obj.get("evidence"):
            errors.append(f"{where}: confirmed finding must contain evidence")
        for key, value in obj.items():
            validate_confidence_values(value, f"{where}.{key}", errors)
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            validate_confidence_values(value, f"{where}[{index}]", errors)


def validate_examples(errors: list[str]) -> None:
    for path in sorted(ASSETS_DIR.glob("*.json")):
        obj = load_json(path)
        validate_confidence_values(obj, path.name, errors)


def main() -> int:
    errors: list[str] = []
    try:
        family_ids, facet_ids = validate_taxonomy(errors)
        counts = validate_patterns(family_ids, facet_ids, errors)
        validate_examples(errors)
    except ValueError as exc:
        errors.append(str(exc))
        counts = {}

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("Asset validation passed.")
    for kind in sorted(counts):
        print(f"{kind}: {counts[kind]} patterns")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
