#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def dump(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def occurrence_id(spec_id: str, version: str, observation_id: str) -> str:
    digest = hashlib.sha256(f"{spec_id}|{version}|{observation_id}".encode()).hexdigest()[:12]
    return f"occ-{spec_id}-{digest}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--replace-version-run", action="store_true")
    parser.add_argument("--allow-validated-promotion", action="store_true")
    args = parser.parse_args()

    catalog_dir = Path(args.catalog)
    result = load(Path(args.result))
    spec = result.get("specification", {})
    spec_id = spec.get("spec_id")
    version = spec.get("version")
    if not spec_id or not version:
        print("ERROR: result specification requires spec_id and version", file=sys.stderr)
        return 2
    if any(obs.get("spec_id") != spec_id or obs.get("spec_version") != version for obs in result.get("observations", [])):
        print("ERROR: result mixes specification IDs or versions", file=sys.stderr)
        return 2

    patterns = load(catalog_dir / "security-patterns.json")
    checks = load(catalog_dir / "security-checks.json")
    occs = load(catalog_dir / "occurrences.json")
    processed = load(catalog_dir / "processed-specifications.json")
    existing = [p for p in processed["processed_specifications"] if p["spec_id"] == spec_id and p["spec_version"] == version]
    if existing and not args.replace_version_run:
        print("ERROR: duplicate processing; use --replace-version-run to replace", file=sys.stderr)
        return 3
    if args.replace_version_run:
        processed["processed_specifications"] = [p for p in processed["processed_specifications"] if not (p["spec_id"] == spec_id and p["spec_version"] == version)]
        occs["occurrences"] = [o for o in occs["occurrences"] if not (o["spec_id"] == spec_id and o["spec_version"] == version)]

    before = copy.deepcopy({"patterns": patterns, "checks": checks, "occurrences": occs, "processed": processed})
    added = []
    for obs in result.get("observations", []):
        if obs.get("evidence_class") == "hypothesis":
            continue
        oid = occurrence_id(spec_id, version, obs["observation_id"])
        occs["occurrences"].append({
            "occurrence_id": oid,
            "spec_id": spec_id,
            "spec_version": version,
            "observation_id": obs["observation_id"],
            "category": obs["security_category"],
            "evidence_class": obs["evidence_class"],
            "evidence": obs.get("evidence", []),
        })
        added.append(oid)

    categories = sorted({obs["security_category"] for obs in result.get("observations", [])})
    processed["processed_specifications"].append({
        "spec_id": spec_id,
        "spec_version": version,
        "processing_date": date.today().isoformat(),
        "source_completeness": result.get("source_completeness", {}),
        "extraction_method_version": "0.1",
        "result_identifier": f"{spec_id}-{version}",
        "categories_evaluated": categories,
        "status": "processed",
    })
    occs["occurrences"].sort(key=lambda o: o["occurrence_id"])
    processed["processed_specifications"].sort(key=lambda p: (p["spec_id"], p["spec_version"], p["result_identifier"]))

    report = {
        "dry_run": args.dry_run,
        "spec_id": spec_id,
        "spec_version": version,
        "occurrences_added": added,
        "hypotheses_skipped": [obs["observation_id"] for obs in result.get("observations", []) if obs.get("evidence_class") == "hypothesis"],
        "validated_promotion_performed": False,
        "notes": ["patterns and checks are not silently promoted", "occurrence evidence is preserved"],
    }
    if not args.dry_run:
        dump(catalog_dir / "occurrences.json", occs)
        dump(catalog_dir / "processed-specifications.json", processed)
        dump(catalog_dir / "security-patterns.json", patterns)
        dump(catalog_dir / "security-checks.json", checks)
    else:
        assert before["patterns"] == patterns
        assert before["checks"] == checks

    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
