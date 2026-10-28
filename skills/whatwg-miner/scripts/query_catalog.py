#!/usr/bin/env python3
"""Query curated WHATWG controls without external dependencies."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from whatwg_miner import load_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=Path(__file__).resolve().parents[1] / "catalog/security-features.json")
    parser.add_argument("--standard")
    parser.add_argument("--category")
    parser.add_argument("--text")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    findings = load_json(args.catalog)["findings"]
    if args.standard:
        needle = args.standard.casefold()
        findings = [item for item in findings if needle in item["standard_id"].casefold() or needle in item.get("standard", "").casefold()]
    if args.category:
        findings = [item for item in findings if item["category"] == args.category]
    if args.text:
        needle = args.text.casefold()
        findings = [item for item in findings if needle in json.dumps(item, ensure_ascii=False).casefold()]
    if args.json:
        print(json.dumps(findings, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        for item in findings:
            print(f"{item['id']}\t{item['category']}\t{item['url']}\t{item['control']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
