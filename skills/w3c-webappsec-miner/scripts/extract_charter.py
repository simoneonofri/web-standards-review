#!/usr/bin/env python3
"""Extract the named deliverables from the exact WebAppSec 2026 charter."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


CHARTER_URL = "https://w3c.github.io/charter-drafts/2026/charter-wg-webappsec-2026.html"
CATEGORY_BY_SECTION = {"normative": "normative", "incubation": "tentative", "other-deliverables": "other"}


def clean(value: str) -> str:
    return " ".join(value.split())


class CharterParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.category_stack: list[str | None] = []
        self.category: str | None = None
        self.in_spec_dt = False
        self.in_draft_state = False
        self.dt_text: list[str] = []
        self.draft_text: list[str] = []
        self.dt_id: str | None = None
        self.dt_url: str | None = None
        self.deliverables: list[dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "section":
            self.category_stack.append(self.category)
            self.category = CATEGORY_BY_SECTION.get(attributes.get("id", ""), self.category)
        if tag == "dt" and self.category and "spec" in (attributes.get("class") or "").split():
            self.in_spec_dt = True
            self.dt_text = []
            self.dt_id = attributes.get("id")
            self.dt_url = None
        elif tag == "a" and self.in_spec_dt and self.dt_url is None:
            self.dt_url = attributes.get("href")
        if tag == "p" and "draft-status" in (attributes.get("class") or "").split() and self.deliverables:
            self.in_draft_state = True
            self.draft_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "dt" and self.in_spec_dt:
            title = clean("".join(self.dt_text))
            if not self.dt_id or not title or not self.category:
                raise ValueError("Named charter deliverable is missing id, title, or category")
            status = "inventory-only"
            if self.category == "normative":
                status = "editor-draft-control-mined" if self.dt_id == "document-policy" else "control-mined"
            self.deliverables.append(
                {
                    "deliverable_id": self.dt_id,
                    "title": title,
                    "category": self.category,
                    "source_url": self.dt_url,
                    "draft_state": None,
                    "mining_status": status,
                }
            )
            self.in_spec_dt = False
        elif tag == "p" and self.in_draft_state:
            state = clean("".join(self.draft_text))
            state = re.sub(r"^Draft state:\s*", "", state, flags=re.IGNORECASE)
            self.deliverables[-1]["draft_state"] = state or None
            self.in_draft_state = False
        elif tag == "section":
            self.category = self.category_stack.pop() if self.category_stack else None

    def handle_data(self, data: str) -> None:
        if self.in_spec_dt:
            self.dt_text.append(data)
        if self.in_draft_state:
            self.draft_text.append(data)


def read_source(location: str) -> str:
    if location.startswith("https://"):
        if location != CHARTER_URL:
            raise ValueError(f"Remote input must be the exact charter URL: {CHARTER_URL}")
        request = urllib.request.Request(location, headers={"User-Agent": "w3c-webappsec-miner/1.0"})
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8")
    return Path(location).read_text(encoding="utf-8")


def extract(html: str) -> dict[str, Any]:
    parser = CharterParser()
    parser.feed(html)
    categories = {name: sum(1 for item in parser.deliverables if item["category"] == name) for name in ("normative", "tentative", "other")}
    return {"schema_version": "1.0", "charter_url": CHARTER_URL, "categories": categories, "deliverables": parser.deliverables}


def main() -> int:
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("--input", default=CHARTER_URL, help="Exact charter URL or a local HTML snapshot")
    argument_parser.add_argument("--output", help="Write JSON to this path; stdout when omitted")
    args = argument_parser.parse_args()
    try:
        payload = extract(read_source(args.input))
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
