#!/usr/bin/env python3
"""Export the allowlisted standalone threat-card-generator core."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "portable-core.json"


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def resolve_source(relative_path: str) -> Path:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"unsafe portable-core path: {relative_path}")
    source = (ROOT / relative).resolve()
    try:
        source.relative_to(ROOT.resolve())
    except ValueError as error:
        raise ValueError(f"portable-core path escapes repository: {relative_path}") from error
    if not source.is_file():
        raise FileNotFoundError(f"portable-core file is missing: {relative_path}")
    return source


def export_core(destination: Path) -> list[str]:
    destination = destination.resolve()
    if destination == ROOT.resolve() or ROOT.resolve() in destination.parents:
        raise ValueError("destination must be outside the source repository")
    if destination.exists() and any(destination.iterdir()):
        raise FileExistsError(f"destination is not empty: {destination}")
    destination.mkdir(parents=True, exist_ok=True)

    manifest = load_manifest()
    copied: list[str] = []
    for relative_path in manifest["files"]:
        source = resolve_source(relative_path)
        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        copied.append(relative_path)
    return copied


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    copied = export_core(args.destination)
    print(f"Exported {len(copied)} portable-core files to {args.destination.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
