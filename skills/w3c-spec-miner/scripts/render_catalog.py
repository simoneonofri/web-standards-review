#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from mine import render_catalog_markdown  # noqa: E402


def main() -> int:
    references = ROOT / "references"
    catalog = json.loads((references / "protection-catalog.json").read_text(encoding="utf-8"))
    coverage_path = references / "coverage.json"
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    summary_path = references / "protection-catalog.md"
    summary_path.write_text(render_catalog_markdown(catalog, coverage), encoding="utf-8")
    coverage.setdefault("artifact_sha256", {})[summary_path.name] = hashlib.sha256(summary_path.read_bytes()).hexdigest()
    coverage_path.write_text(json.dumps(coverage, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
