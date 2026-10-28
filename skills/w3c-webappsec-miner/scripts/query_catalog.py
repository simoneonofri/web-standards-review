#!/usr/bin/env python3
"""Select applicable controls and include linked defaults and exceptions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def load(relative_path: str) -> dict[str, Any]:
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--facet", action="append", default=[], help="Exact applicability facet or family; repeatable")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON")
    args = parser.parse_args()
    controls = load("catalog/security-controls.json")["controls"]
    wanted = set(args.facet)
    if wanted:
        controls = [control for control in controls if control["family"] in wanted or wanted.intersection(control["applicability"])]
    default_ids = {value for control in controls for value in control["default_ids"]}
    exception_ids = {value for control in controls for value in control["exception_ids"]}
    defaults = [item for item in load("catalog/secure-defaults.json")["defaults"] if item["default_id"] in default_ids]
    exception_ids.update(value for default in defaults for value in default["exception_ids"])
    exceptions = [item for item in load("catalog/exceptions.json")["exceptions"] if item["exception_id"] in exception_ids]
    if args.json:
        print(json.dumps({"controls": controls, "defaults": defaults, "exceptions": exceptions}, indent=2, ensure_ascii=False))
    else:
        for control in controls:
            source = control["evidence"][0]
            print(f"{control['control_id']}\t{control['title']}\t{control['normative_strength']}\t{source['source_url']}")
        print(f"selected controls={len(controls)} defaults={len(defaults)} exceptions={len(exceptions)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
