#!/usr/bin/env python3
"""Validate a focused W3C security reply and its private evidence packet."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from spec_review.focused_review_contract import validate_focused_review_files  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--comment", type=Path, required=True)
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = validate_focused_review_files(args.evidence, args.comment)
    status = "pass" if result.ok else "fail"
    payload = {
        "status": status,
        "word_count": result.word_count,
        "link_count": result.link_count,
        "errors": list(result.errors),
        "warnings": list(result.warnings),
    }
    if args.as_json:
        print(json.dumps(payload, indent=2))
    else:
        print(
            f"{status.upper()}: "
            f"{result.word_count} words, {result.link_count} links"
        )
        for warning in result.warnings:
            print(f"WARNING: {warning}")
        for error in result.errors:
            print(f"ERROR: {error}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
