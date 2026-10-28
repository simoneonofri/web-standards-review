#!/usr/bin/env python3
"""Validate curated findings and build JSON/Markdown catalogs."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import date
from pathlib import Path

from whatwg_miner import atomic_write, dump_json, load_json, validate_findings


def markdown_catalog(catalog: dict[str, object]) -> str:
    lines = [
        "# WHATWG reusable security controls",
        "",
        f"Curated controls: {catalog['finding_count']} across {catalog['standards_with_findings']} standards. Evidence snapshot date: {catalog['verified_on']}.",
        "",
        "> This is a review aid, not an exhaustive conformance statement. Follow every official anchor before relying on a finding.",
        "",
    ]
    current = ""
    for finding in catalog["findings"]:
        if finding["standard"] != current:
            current = finding["standard"]
            lines.extend([f"## {current}", ""])
        lines.extend([
            f"### [{finding['control']}]({finding['url']})",
            "",
            f"- Category: `{finding['category']}`",
            f"- Status: `{finding['normative_status']}`; evidence: `{finding['evidence_class']}`; confidence: `{finding['confidence']}`",
            f"- Evidence ({finding['evidence_kind']}): {finding['evidence']}",
            f"- Applies when: {finding['applicability']}",
            f"- Secure default: {finding['secure_default']}",
            f"- Failure or exception: {finding['failure_behavior']}",
            f"- Explicit exceptions: {finding['exceptions']}",
            f"- Dependencies: {', '.join(finding['dependencies']) if finding['dependencies'] else 'none recorded'}",
            f"- Limitation: {finding['limitations']}",
            "",
        ])
    return "\n".join(lines).rstrip() + "\n"


def markdown_coverage(coverage: dict[str, object]) -> str:
    lines = [
        "# WHATWG security-mining coverage",
        "",
        f"Official standards assessed: {coverage['standard_count']}. Curated controls: {coverage['finding_count']}.",
        "",
        "| Standard | Controls | State | Residual gap |",
        "| --- | ---: | --- | --- |",
    ]
    for item in coverage["standards"]:
        lines.append(f"| [{item['title']}]({item['url']}) | {item['finding_count']} | `{item['coverage_state']}` | {item['residual_gap']} |")
    lines.extend(["", "## Counts by category", "", "| Category | Count |", "| --- | ---: |"])
    for category, count in coverage["counts_by_category"].items():
        lines.append(f"| `{category}` | {count} |")
    lines.extend(["", "## Global limitations", "", "- Living Standards change continuously; anchors and semantics require revalidation after refresh.", "- The catalog records specification mechanisms, not browser implementation, interoperability, or deployment.", "- Large cross-cutting standards are intentionally marked `partial` where bounded initial mining cannot establish exhaustiveness.", "- Zero controls means no reusable control was curated under this taxonomy; it does not mean no security relevance.", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--seed", type=Path, required=True)
    parser.add_argument("--coverage-seed", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--verified-on", default=date.today().isoformat())
    args = parser.parse_args()
    inventory = load_json(args.inventory)
    findings = load_json(args.seed)["findings"]
    findings = sorted(findings, key=lambda item: (item["standard_id"], item["id"]))
    errors = validate_findings(findings, inventory, args.artifacts)
    if errors:
        raise SystemExit("\n".join(errors))
    for finding in findings:
        finding["standard"] = next(item["title"] for item in inventory["standards"] if item["id"] == finding["standard_id"])
        finding["verified_on"] = args.verified_on
    counts_by_category = Counter(item["category"] for item in findings)
    counts_by_standard = Counter(item["standard_id"] for item in findings)
    catalog = {
        "schema_version": "1.0",
        "verified_on": args.verified_on,
        "inventory_source_sha256": inventory["source_sha256"],
        "finding_count": len(findings),
        "standards_with_findings": len(counts_by_standard),
        "counts_by_category": dict(sorted(counts_by_category.items())),
        "counts_by_standard": dict(sorted(counts_by_standard.items())),
        "findings": findings,
    }
    coverage_seed = load_json(args.coverage_seed)
    seed_by_id = {item["standard_id"]: item for item in coverage_seed["standards"]}
    coverage_rows = []
    for standard in inventory["standards"]:
        seed = seed_by_id.get(standard["id"], {})
        count = counts_by_standard[standard["id"]]
        state = seed.get("coverage_state", "cataloged" if count else "assessed-no-reusable-control")
        coverage_rows.append({
            "standard_id": standard["id"],
            "title": standard["title"],
            "url": standard["url"],
            "finding_count": count,
            "coverage_state": state,
            "residual_gap": seed.get("residual_gap", "No specific residual gap recorded; revalidate after Living Standard changes."),
        })
    unknown = sorted(set(seed_by_id) - {item["id"] for item in inventory["standards"]})
    if unknown:
        raise SystemExit(f"coverage seed refers to standards absent from inventory: {', '.join(unknown)}")
    coverage = {
        "schema_version": "1.0",
        "verified_on": args.verified_on,
        "standard_count": inventory["standard_count"],
        "finding_count": len(findings),
        "counts_by_category": dict(sorted(counts_by_category.items())),
        "counts_by_standard": dict(sorted(counts_by_standard.items())),
        "standards": coverage_rows,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    dump_json(args.output_dir / "security-features.json", catalog)
    dump_json(args.output_dir / "coverage.json", coverage)
    atomic_write(args.output_dir / "security-features.md", markdown_catalog(catalog))
    atomic_write(args.output_dir / "coverage.md", markdown_coverage(coverage))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
