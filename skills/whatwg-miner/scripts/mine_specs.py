#!/usr/bin/env python3
"""Mine security candidates from saved WHATWG snapshots."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from whatwg_miner import dump_json, load_json, mine_candidates


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--per-standard-limit", type=int, default=40)
    args = parser.parse_args()
    inventory = load_json(args.inventory)
    manifest = load_json(args.artifacts / "manifest.json")
    hashes = {record["standard_id"]: record["sha256"] for record in manifest["snapshots"]}
    candidates: list[dict[str, object]] = []
    for standard in inventory["standards"]:
        data = (args.artifacts / f"{standard['id']}.html").read_bytes()
        records = mine_candidates(standard, data, hashes[standard["id"]])
        candidates.extend(records[: args.per_standard_limit])
    category_counts = Counter(category for item in candidates for category in item["categories"])
    class_counts = Counter(str(item["evidence_class"]) for item in candidates)
    dump_json(args.output, {
        "schema_version": "1.0",
        "status": "discovery-only-not-curated",
        "candidate_count": len(candidates),
        "counts_by_category": dict(sorted(category_counts.items())),
        "counts_by_evidence_class": dict(sorted(class_counts.items())),
        "candidates": sorted(candidates, key=lambda item: (item["standard_id"], -item["score"], item["url"])),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
