#!/usr/bin/env python3
"""Build review-publication-gate/v1 for an exact review artifact."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from spec_review.publication_gate import build_publication_gate, write_publication_gate


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--fact-check", type=Path, required=True)
    parser.add_argument("--analysis-gate", type=Path)
    parser.add_argument("--independent-review-gate", type=Path)
    parser.add_argument("--publication-boundary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-missing-analysis-gate", action="store_true")
    parser.add_argument("--allow-missing-independent-review-gate", action="store_true")
    parser.add_argument("--require-human-reviewed-fact-check", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        gate = build_publication_gate(
            artifact_path=args.artifact,
            fact_check_path=args.fact_check,
            analysis_gate_path=args.analysis_gate,
            independent_review_gate_path=args.independent_review_gate,
            publication_boundary_path=args.publication_boundary,
            require_analysis_gate=not args.allow_missing_analysis_gate,
            require_independent_review_gate=not args.allow_missing_independent_review_gate,
            require_human_reviewed_fact_check=args.require_human_reviewed_fact_check,
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: could not build publication gate: {error}")
        return 1
    write_publication_gate(args.output, gate)
    for check in gate["checks"]:
        print(f"{check['check_id']}: {check['status']}")
        for error in check["errors"]:
            print(f"  ERROR: {error}")
    print(f"publication gate: {gate['status']}")
    return 0 if gate["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
