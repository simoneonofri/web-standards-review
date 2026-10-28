#!/usr/bin/env python3
"""Validate a bounded local PoC evidence document."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from spec_review.poc_contract import validate_poc_file  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = validate_poc_file(args.evidence)
    payload = {"valid": result.valid, "errors": list(result.errors), "warnings": list(result.warnings)}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("valid" if result.valid else "invalid")
        for message in result.errors:
            print(f"error: {message}")
        for message in result.warnings:
            print(f"warning: {message}")
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
