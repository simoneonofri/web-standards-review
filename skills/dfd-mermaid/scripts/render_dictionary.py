"""Render the complete DFD dictionary JSON as an inline Markdown table."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from validate_dfd import DICTIONARY_FIELDS, load_dictionary, validate_dictionary


COLUMNS = [
    ("ID", "canonical_id"),
    ("Mermaid node ID", "mermaid_node_id"),
    ("Type", "type"),
    ("Visible label", "visible_label"),
    ("Name", "name"),
    ("Description", "description"),
    ("Source ID", "source_id"),
    ("Assurance Level", "assurance_level"),
    ("Specification Reference", "specification_reference"),
    ("Source Locator", "source_locator"),
    ("Coverage Status", "coverage_status"),
    ("Evidence Status", "evidence_status"),
    ("Assumptions", "assumptions"),
    ("Boundary Membership", "boundary_membership"),
    ("Flow Source", "flow_source"),
    ("Flow Destination", "flow_destination"),
]

assert {key for _, key in COLUMNS} == DICTIONARY_FIELDS


def markdown_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        value = "; ".join(str(item) for item in value)
    return str(value).replace("|", "\\|").replace("\n", "<br/>")


def render(rows: list[dict[str, Any]]) -> str:
    lines = [
        "| " + " | ".join(label for label, _ in COLUMNS) + " |",
        "| " + " | ".join("---" for _ in COLUMNS) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(markdown_cell(row.get(key)) for _, key in COLUMNS) + " |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dictionary", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    dictionary = load_dictionary(args.dictionary)
    rows = dictionary["rows"]
    errors = validate_dictionary(rows)
    if errors:
        for error in errors:
            print(error)
        return 1
    output = render(rows)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
