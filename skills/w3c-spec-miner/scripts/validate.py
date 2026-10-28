#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--references", type=Path, required=True)
    args = parser.parse_args()
    coverage = json.loads((args.references / "coverage.json").read_text(encoding="utf-8"))
    errors = []
    for name, expected in coverage.get("artifact_sha256", {}).items():
        path = args.references / name
        actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        if actual != expected:
            errors.append(f"hash mismatch: {name}")
    catalog = json.loads((args.references / "protection-catalog.json").read_text(encoding="utf-8"))
    pattern_ids = [pattern["pattern_id"] for pattern in catalog.get("patterns", [])]
    if len(pattern_ids) != len(set(pattern_ids)):
        errors.append("duplicate pattern_id")
    if coverage.get("successful_packets", 0) + coverage.get("failed_packets", 0) != coverage.get("inventory_count", -1):
        errors.append("packet accounting does not match inventory")
    if "Frequency is descriptive" not in (args.references / "protection-catalog.md").read_text(encoding="utf-8"):
        errors.append("catalog summary is missing the frequency warning")
    for line_number, line in enumerate((args.references / "security-considerations-gaps.jsonl").read_text(encoding="utf-8").splitlines(), 1):
        gap = json.loads(line)
        if gap.get("disposition") != "editorial_non_blocking":
            errors.append(f"gap line {line_number} is not editorial_non_blocking")
    print(json.dumps({"valid": not errors, "errors": errors}, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
