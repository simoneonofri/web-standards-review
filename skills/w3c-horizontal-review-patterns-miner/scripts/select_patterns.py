#!/usr/bin/env python3
"""Deterministically select review patterns for an existing specification profile."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SKILL_DIR = Path(__file__).resolve().parents[1]
TAXONOMY_PATH = SKILL_DIR / "references" / "specification-taxonomy.json"
PATTERNS_PATH = SKILL_DIR / "references" / "review-patterns.json"
REVIEW_KINDS = {"tag-design", "privacy", "security"}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def known_ids() -> tuple[set[str], set[str]]:
    taxonomy = load_json(TAXONOMY_PATH)
    families = {family["family_id"] for family in taxonomy["families"]}
    facets = {
        facet
        for facet_list in taxonomy["facet_dimensions"].values()
        for facet in facet_list
    }
    return families, facets


def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def profile_from_input(obj: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError("profile input must be an object")
    profile = obj.get("spec_profile", obj)
    if not isinstance(profile, dict):
        raise ValueError("spec_profile must be an object")
    return profile


def normalize_facets(raw_facets: Any) -> list[str]:
    facets: list[str] = []
    if raw_facets is None:
        return facets
    if not isinstance(raw_facets, list):
        raise ValueError("facets must be an array")
    for item in raw_facets:
        if isinstance(item, str):
            facets.append(item)
        elif isinstance(item, dict) and isinstance(item.get("facet_id"), str):
            facets.append(item["facet_id"])
        else:
            raise ValueError("facets must contain strings or objects with a string facet_id")
    return sorted(set(facets))


def build_profile(args: argparse.Namespace) -> dict[str, Any]:
    if args.input:
        obj = load_json(Path(args.input))
        profile = profile_from_input(obj)
    elif args.primary_family or args.secondary_families or args.facets:
        profile = {
            "primary_family": args.primary_family,
            "secondary_families": split_csv(args.secondary_families),
            "facets": split_csv(args.facets),
        }
    elif not sys.stdin.isatty():
        profile = profile_from_input(json.load(sys.stdin))
    else:
        profile = {"primary_family": None, "secondary_families": [], "facets": []}
    secondary = profile.get("secondary_families")
    if secondary is None:
        secondary = []
    if not isinstance(secondary, list) or any(not isinstance(item, str) for item in secondary):
        raise ValueError("secondary_families must be an array of strings")
    return {
        "primary_family": profile.get("primary_family"),
        "secondary_families": sorted(set(secondary)),
        "facets": normalize_facets(profile.get("facets", [])),
    }


def validate_profile(profile: dict[str, Any], review_kind: str | None) -> list[str]:
    families, facets = known_ids()
    errors: list[str] = []
    if not isinstance(profile["primary_family"], str) or profile["primary_family"] not in families:
        errors.append(f"invalid primary family: {profile['primary_family']!r}")
    for family in profile["secondary_families"]:
        if family not in families:
            errors.append(f"invalid secondary family: {family!r}")
    for facet in profile["facets"]:
        if facet not in facets:
            errors.append(f"invalid facet: {facet!r}")
    if review_kind and review_kind not in REVIEW_KINDS:
        errors.append(f"invalid review kind: {review_kind!r}")
    return errors


def match_pattern(pattern: dict[str, Any], families: set[str], facets: set[str]) -> dict[str, Any] | None:
    applies = pattern["applies_when"]
    applicable_families = set(pattern["applicable_families"])
    family_matches = sorted(families & applicable_families)
    if not family_matches:
        return None

    facets_all = set(applies["facets_all"])
    facets_any = set(applies["facets_any"])
    facets_none = set(applies["facets_none"])

    if not facets_all <= facets:
        return None
    if facets_none & facets:
        return None
    if facets_any and not (facets_any & facets):
        return None

    matched_all = sorted(facets_all)
    matched_any = sorted(facets_any & facets)
    strength = "strong" if matched_all or matched_any else "broad-fallback"
    reasons = [f"family matched: {', '.join(family_matches)}"]
    if matched_all:
        reasons.append(f"required facets present: {', '.join(matched_all)}")
    if matched_any:
        reasons.append(f"trigger facets present: {', '.join(matched_any)}")
    if strength == "broad-fallback":
        reasons.append("selected as a family-level baseline pattern")

    return {
        "pattern_id": pattern["pattern_id"],
        "title": pattern["title"],
        "review_kind": pattern["review_kind"],
        "match_strength": strength,
        "matched_families": family_matches,
        "matched_facets": sorted(set(matched_all + matched_any)),
        "reasons": reasons,
        "review_questions": pattern["review_questions"],
        "evidence_requirements": pattern["evidence_requirements"],
    }


def select(profile: dict[str, Any], review_kind: str | None) -> dict[str, Any]:
    patterns = load_json(PATTERNS_PATH)["patterns"]
    families = {profile["primary_family"], *profile["secondary_families"]}
    facets = set(profile["facets"])
    selected = []
    for pattern in patterns:
        if review_kind and pattern["review_kind"] != review_kind:
            continue
        match = match_pattern(pattern, families, facets)
        if match:
            selected.append(match)

    strength_rank = {"strong": 0, "broad-fallback": 1}
    selected.sort(key=lambda item: (strength_rank[item["match_strength"]], item["review_kind"], item["pattern_id"]))
    return {
        "profile": profile,
        "review_kind": review_kind,
        "selected_patterns": selected,
        "counts": {
            kind: sum(1 for item in selected if item["review_kind"] == kind)
            for kind in sorted(REVIEW_KINDS)
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", help="JSON file containing a spec_profile or profile")
    parser.add_argument("--primary-family")
    parser.add_argument("--secondary-families", help="Comma-separated family IDs")
    parser.add_argument("--facets", help="Comma-separated facet IDs")
    parser.add_argument("--review-kind", choices=sorted(REVIEW_KINDS))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        profile = build_profile(args)
        errors = validate_profile(profile, args.review_kind)
    except (OSError, ValueError) as exc:
        print(f"ERROR: invalid profile input: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 2
    json.dump(select(profile, args.review_kind), sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
