#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog"
REF = ROOT / "references"
MATURITY_ORDER = {"seed": 0, "candidate": 1, "observed": 2, "recurring": 3, "validated": 4, "deprecated": -1}


def csv(value: str | None) -> set[str]:
    return {item.strip() for item in (value or "").split(",") if item.strip()}


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--categories", default="")
    parser.add_argument("--actors", default="")
    parser.add_argument("--assets", default="")
    parser.add_argument("--trust-boundaries", default="")
    parser.add_argument("--capabilities", default="")
    parser.add_argument("--facets", default="")
    parser.add_argument("--minimum-maturity", default="seed", choices=sorted(MATURITY_ORDER))
    parser.add_argument("--scope", choices=["specification-design", "implementation-conformance", "deployment-operation"])
    args = parser.parse_args()

    taxonomy = load_json(REF / "security-taxonomy.json")
    known_categories = {c["category_id"] for c in taxonomy["categories"]}
    categories = csv(args.categories)
    unknown = categories - known_categories
    if unknown:
        print(f"ERROR: unknown categories: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2

    checks = load_json(CATALOG / "security-checks.json")["checks"]
    patterns = {p["pattern_id"]: p for p in load_json(CATALOG / "security-patterns.json")["patterns"]}
    selected = []
    for check in checks:
        if args.scope and check["scope"] != args.scope:
            continue
        if MATURITY_ORDER[check["maturity"]] < MATURITY_ORDER[args.minimum_maturity]:
            continue
        pattern = patterns.get(check["pattern_id"], {})
        direct = False
        reasons = []
        if categories and check["category"] in categories:
            direct = True
            reasons.append(f"category matched: {check['category']}")
        facets = csv(args.facets)
        pattern_facets = set(pattern.get("applicability", {}).get("facets_any", []))
        if facets and facets & pattern_facets:
            direct = True
            reasons.append(f"facet matched: {', '.join(sorted(facets & pattern_facets))}")
        if not categories and not facets:
            reasons.append("selected as broad catalog fallback")
        elif not direct:
            continue
        selected.append({
            "check_id": check["check_id"],
            "pattern_id": check["pattern_id"],
            "title": check["title"],
            "category": check["category"],
            "scope": check["scope"],
            "match_strength": "direct" if direct else "broad-fallback",
            "reasons": reasons,
            "question": check["question"],
            "evidence_to_collect": check["evidence_to_collect"],
        })
    selected.sort(key=lambda c: (0 if c["match_strength"] == "direct" else 1, c["category"], c["check_id"]))
    json.dump({"selected_checks": selected, "count": len(selected)}, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
