#!/usr/bin/env python3
"""Fetch official WHATWG single-page snapshots outside the skill repository."""

from __future__ import annotations

import argparse
from pathlib import Path

from whatwg_miner import atomic_write, fetch_bytes, load_json, sha256_bytes, snapshot_url


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    inventory = load_json(args.inventory)
    args.artifacts.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, object] = {"schema_version": "1.0", "snapshots": []}
    snapshots: list[dict[str, object]] = manifest["snapshots"]  # type: ignore[assignment]
    for standard in inventory["standards"]:  # type: ignore[index]
        path = args.artifacts / f"{standard['id']}.html"
        url = snapshot_url(standard)
        if args.offline:
            if not path.exists():
                raise FileNotFoundError(f"offline snapshot missing: {path}")
            data = path.read_bytes()
        else:
            data = fetch_bytes(url)
            atomic_write(path, data.decode("utf-8", errors="replace"))
            data = path.read_bytes()
        snapshots.append({
            "standard_id": standard["id"],
            "url": url,
            "path": path.name,
            "bytes": len(data),
            "sha256": sha256_bytes(data),
        })
    manifest["snapshots"] = sorted(snapshots, key=lambda item: item["standard_id"])
    from whatwg_miner import dump_json
    dump_json(args.artifacts / "manifest.json", manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
