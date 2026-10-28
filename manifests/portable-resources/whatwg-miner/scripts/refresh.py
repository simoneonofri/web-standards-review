#!/usr/bin/env python3
"""Refresh inventory, snapshots, candidates, and curated catalogs."""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import date
from pathlib import Path


def run(*args: str) -> None:
    subprocess.run([sys.executable, *args], check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--index-source", type=Path)
    parser.add_argument("--verified-on", default=date.today().isoformat())
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    catalog = args.output_dir
    if catalog.exists() or catalog.is_symlink() or catalog.resolve().is_relative_to(root.parents[1]) or args.artifacts.resolve().is_relative_to(root.parents[1]):
        parser.error("Use external source storage and a new external catalog directory")
    args.artifacts.mkdir(parents=True, exist_ok=True)
    inventory_args = [str(root / "scripts/inventory.py"), "--output", str(catalog / "inventory.json")]
    saved_index = args.index_source or (args.artifacts / "index.html" if args.offline else None)
    if saved_index:
        inventory_args.extend(["--source", str(saved_index)])
    else:
        inventory_args.extend(["--save-source", str(args.artifacts / "index.html")])
    run(*inventory_args)
    fetch_args = [str(root / "scripts/fetch_specs.py"), "--inventory", str(catalog / "inventory.json"), "--artifacts", str(args.artifacts)]
    if args.offline:
        fetch_args.append("--offline")
    run(*fetch_args)
    run(str(root / "scripts/mine_specs.py"), "--inventory", str(catalog / "inventory.json"), "--artifacts", str(args.artifacts), "--output", str(catalog / "mining-candidates.json"))
    run(
        str(root / "scripts/build_catalog.py"),
        "--inventory", str(catalog / "inventory.json"),
        "--seed", str(root / "references/seed-findings.json"),
        "--coverage-seed", str(root / "references/coverage-seed.json"),
        "--artifacts", str(args.artifacts),
        "--output-dir", str(catalog),
        "--verified-on", args.verified_on,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
