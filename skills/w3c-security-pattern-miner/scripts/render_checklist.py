#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def load(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="JSON from select_checks.py or a result containing security_checks")
    args = parser.parse_args()
    data = load(args.input)
    checks = data.get("selected_checks") or data.get("security_checks") or []
    groups = defaultdict(list)
    for check in checks:
        groups[(check.get("category", "uncategorized"), check.get("scope", "unspecified"))].append(check)
    print("# Web Platform Security Checklist\n")
    print("## Target specification\n")
    print(data.get("specification", {}).get("title", "Not supplied"))
    print("\n## Applicability summary\n")
    print(f"{len(checks)} checks rendered.")
    for (category, scope) in sorted(groups):
        print(f"\n## {category} / {scope}\n")
        for check in sorted(groups[(category, scope)], key=lambda c: c.get("check_id", "")):
            print(f"### {check.get('check_id')}: {check.get('title', '')}\n")
            print(f"- Pattern: `{check.get('pattern_id', '')}`")
            print(f"- Status: `{check.get('result', 'not-evaluated')}`")
            print(f"- Question: {check.get('question', '')}")
            evidence = check.get("evidence_to_collect") or []
            if evidence:
                print(f"- Evidence to collect: {', '.join(evidence)}")
            if check.get("evidence"):
                print("- Evidence:")
                for ev in check["evidence"]:
                    print(f"  - `{ev.get('locator', '')}`: {ev.get('evidence_span', '')}")
            reasons = check.get("reasons") or []
            if reasons:
                print(f"- Match reasons: {', '.join(reasons)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
