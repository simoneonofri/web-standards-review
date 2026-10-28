#!/usr/bin/env python3
"""Assemble a portable spec-review threat-model report from run artifacts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from spec_review import assemble_report  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path, help="Run artifact directory")
    parser.add_argument("--output", type=Path, help="Output Markdown path")
    parser.add_argument("--title", help="Report title")
    parser.add_argument(
        "--run-scope",
        choices=("baseline", "as-is", "additional", "full", "comprehensive"),
        default="additional",
        help=(
            "Report scope for default filename; defaults to additional. "
            "full/comprehensive are accepted as legacy aliases for additional; "
            "as-is is accepted as a legacy alias for baseline; "
            "--baseline-only overrides this to baseline"
        ),
    )
    parser.add_argument("--spec-slug", help="Specification slug for default report filename")
    parser.add_argument("--diagram-level", help="Diagram level for default report filename")
    parser.add_argument(
        "--categories",
        nargs="+",
        help="Analysis categories for default report filename; accepts repeated values or comma-separated text",
    )
    parser.add_argument("--timestamp", help="Timestamp for default report filename, normally YYYYMMDD-HHMMSS")
    parser.add_argument(
        "--baseline-only",
        action="store_true",
        help="Assemble only the source-grounded baseline while preserving the full report structure",
    )
    parser.add_argument(
        "--as-is-only",
        action="store_true",
        help="Legacy alias for --baseline-only",
    )
    parser.add_argument(
        "--draft",
        action="store_true",
        help=(
            "Assemble a semantically reviewable draft without writing or "
            "requiring the final publication gate."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output = assemble_report(
        args.run_dir,
        output=args.output,
        title=args.title,
        as_is_only=args.baseline_only or args.as_is_only,
        run_scope=args.run_scope,
        spec_slug=args.spec_slug,
        diagram_level=args.diagram_level,
        categories=args.categories,
        timestamp=args.timestamp,
        draft=args.draft,
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
