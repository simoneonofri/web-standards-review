#!/usr/bin/env python3
"""Run every root, contract, and catalog-listed skill test suite."""

from __future__ import annotations

import subprocess
import sys
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUITES = (
    "tests",
    "contracts/threat-modeling-flow-v1/tests",
    "skills/what-are-we-building/tests",
    "skills/dfd-mermaid/tests",
    "skills/what-can-go-wrong/tests",
    "skills/what-are-we-going-to-do-about-it/tests",
    "skills/did-we-do-a-good-enough-job/tests",
    "skills/threat-card-generator/tests",
    "skills/fact-check/tests",
    "skills/spec-review/tests",
)


def main() -> int:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *SUITES],
        cwd=ROOT,
        check=False,
    )
    if result.returncode:
        return result.returncode
    # Separate processes prevent equally named upstream test modules and helper
    # imports from contaminating each other's suites.
    catalog = json.loads((ROOT / "catalog.yaml").read_text())
    for row in catalog["skills"]:
        tests = ROOT / row["path"] / "tests"
        if tests.is_dir() and str(tests.relative_to(ROOT)) not in SUITES:
            result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(tests)], cwd=tests.parent)
            if result.returncode:
                return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
