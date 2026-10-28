#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def slug(value: str) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in value.lower()).strip("-")


def stable_id(prefix: str, *parts: str) -> str:
    raw = "|".join(parts)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}-{slug(parts[0])}-{digest}"


def load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def normalize(result: dict[str, Any], drop_unknown: bool = False) -> dict[str, Any]:
    spec = result.get("specification", {})
    spec_id = spec.get("spec_id")
    version = spec.get("version")
    if not spec_id or not version:
        raise ValueError("specification.spec_id and specification.version are required")

    versions = {version}
    for obs in result.get("observations", []):
        versions.add(obs.get("spec_version"))
        if obs.get("spec_id") != spec_id:
            raise ValueError("all observations must use the same spec_id")
    if len(versions) != 1:
        raise ValueError("mining result contains multiple specification versions")

    normalized = dict(result)
    normalized["observations"] = []
    for obs in result.get("observations", []):
        item = dict(obs)
        item["spec_id"] = spec_id
        item["spec_version"] = version
        if not item.get("observation_id"):
            item["observation_id"] = stable_id("obs", spec_id, version, item.get("statement", ""))
        item["evidence"] = sorted(item.get("evidence", []), key=lambda e: (e.get("source_id", ""), e.get("locator", ""), e.get("evidence_span", "")))
        normalized["observations"].append(item)
    normalized["observations"].sort(key=lambda o: o["observation_id"])

    for key in ("explicit_patterns", "derived_pattern_candidates", "security_checks", "unresolved_questions", "not_applicable_categories", "missing_evidence", "limitations"):
        if key in normalized and isinstance(normalized[key], list):
            normalized[key] = sorted(normalized[key], key=lambda x: json.dumps(x, sort_keys=True) if isinstance(x, dict) else str(x))

    if drop_unknown:
        allowed = {"mode", "specification", "source_completeness", "security_surface_profile", "observations", "explicit_patterns", "derived_pattern_candidates", "security_checks", "unresolved_questions", "not_applicable_categories", "coverage", "missing_evidence", "limitations", "optional_spec_profile"}
        normalized = {k: v for k, v in normalized.items() if k in allowed}
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result")
    parser.add_argument("--drop-unknown", action="store_true")
    args = parser.parse_args()
    try:
        obj = normalize(load(args.result), args.drop_unknown)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    json.dump(obj, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
