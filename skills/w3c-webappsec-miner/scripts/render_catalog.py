#!/usr/bin/env python3
"""Render the JSON catalogs into a compact Markdown index."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def load(relative_path: str) -> dict[str, Any]:
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


def evidence_link(record: dict[str, Any]) -> str:
    item = record["evidence"][0]
    return f"[{item['section']}]({item['source_url']})"


def render() -> str:
    controls = load("catalog/security-controls.json")["controls"]
    defaults = load("catalog/secure-defaults.json")["defaults"]
    exceptions = load("catalog/exceptions.json")["exceptions"]
    deliverables_doc = load("references/charter-deliverables.json")
    deliverables = deliverables_doc["deliverables"]
    family_counts = Counter(control["family"] for control in controls)
    lines = [
        "# WebAppSec API security control catalog",
        "",
        "This generated index is scoped by the exact [2026 Web Application Security Working Group charter](https://w3c.github.io/charter-drafts/2026/charter-wg-webappsec-2026.html). Charter inclusion establishes scope only; each mechanism links to specification evidence.",
        "",
        "## Inventory",
        "",
        "| Item | Count |",
        "| --- | ---: |",
        f"| Normative charter deliverables | {deliverables_doc['categories']['normative']} |",
        f"| Tentative charter deliverables | {deliverables_doc['categories']['tentative']} |",
        f"| Named other deliverables | {deliverables_doc['categories']['other']} |",
        f"| Reusable security controls | {len(controls)} |",
        f"| Secure defaults | {len(defaults)} |",
        f"| Exceptions and opt-outs | {len(exceptions)} |",
        "",
        "## Control families",
        "",
        "| Family | Controls |",
        "| --- | ---: |",
    ]
    lines.extend(f"| {family} | {count} |" for family, count in sorted(family_counts.items()))
    lines.extend(["", "## Controls", "", "| ID | Control | Strength | Defaults | Exceptions | Primary evidence |", "| --- | --- | --- | --- | --- | --- |"])
    for control in controls:
        defaults_cell = ", ".join(control["default_ids"]) or "—"
        exceptions_cell = ", ".join(control["exception_ids"]) or "—"
        lines.append(f"| {control['control_id']} | {control['title']} | {control['normative_strength']} | {defaults_cell} | {exceptions_cell} | {evidence_link(control)} |")
    lines.extend(["", "## Secure defaults", "", "| ID | Default | Explicitness | Strength | Controls | Primary evidence |", "| --- | --- | --- | --- | --- | --- |"])
    for default in defaults:
        lines.append(f"| {default['default_id']} | {default['title']} | {default['explicitness']} | {default['normative_strength']} | {', '.join(default['control_ids'])} | {evidence_link(default)} |")
    lines.extend(["", "## Exceptions and opt-outs", "", "| ID | Exception | Strength | Controls | Primary evidence |", "| --- | --- | --- | --- | --- |"])
    for exception in exceptions:
        lines.append(f"| {exception['exception_id']} | {exception['title']} | {exception['normative_strength']} | {', '.join(exception['control_ids'])} | {evidence_link(exception)} |")
    lines.extend(["", "## Charter deliverables", "", "| Category | Deliverable | Draft state | Mining status |", "| --- | --- | --- | --- |"])
    for item in deliverables:
        title = f"[{item['title']}]({item['source_url']})" if item["source_url"] else item["title"]
        lines.append(f"| {item['category']} | {title} | {item['draft_state'] or 'Not stated'} | {item['mining_status']} |")
    lines.extend(["", "## Limits", "", "This is a targeted initial mechanism catalog, not exhaustive clause-level mining, an implementation-support statement, or proof that an API is secure. Apply controls by applicability, preserve evidence class and status, and review linked exceptions before making a finding.", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT / "catalog" / "CATALOG.md"))
    args = parser.parse_args()
    Path(args.output).write_text(render(), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
