#!/usr/bin/env python3
"""Portable spec-review pipeline CLI.

This first version assembles an already-produced run directory. Evidence
collection and threat elicitation can be performed by Codex skills or external
tools, then this CLI gives the final report a stable contract.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from spec_review.pipeline import assemble_existing_run  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--title")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output = assemble_existing_run(args.run_dir, output=args.output, title=args.title)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
