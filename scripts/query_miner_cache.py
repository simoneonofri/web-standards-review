#!/usr/bin/env python3
"""Validate and search an offline Web Standards Review cache ZIP.

Uses only Python standard library; does not call W3C Knowledge or the network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

SCHEMA = "web-standards-review-offline-cache/v1"
REQUIRED = (
    "manifest.json",
    "records.jsonl",
    "records.json",
    "records.csv",
    "index.html",
    "index.md",
    "curation-template.csv",
)


def inspect(path: Path) -> tuple[list[dict], dict]:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if (
            len(names) != len(set(names))
            or any(p.startswith("/") or ".." in Path(p).parts for p in names)
            or not set(REQUIRED).issubset(names)
        ):
            raise ValueError("unsafe or incomplete portable cache archive")
        manifest = json.loads(archive.read("manifest.json"))
        if manifest.get("schema_version") != SCHEMA:
            raise ValueError("unsupported portable cache schema")
        for name, record in manifest.get("artifacts", {}).items():
            if name not in names:
                raise ValueError("missing file declared in manifest: " + name)
            body = archive.read(name)
            actual_hash = hashlib.sha256(body).hexdigest()
            if record.get("sha256") != actual_hash or record.get("bytes") != len(body):
                raise ValueError("cache integrity mismatch: " + name)
        rows = [
            json.loads(line)
            for line in archive.read("records.jsonl").decode("utf-8").splitlines()
            if line.strip()
        ]
        ids = [row["id"] for row in rows]
        if len(set(ids)) != len(ids) or len(rows) != manifest["records"]:
            raise ValueError("duplicate cache IDs or inconsistent record count")
        if any(row["domain"] not in manifest.get("domains", {}) for row in rows):
            raise ValueError("unknown domain in cache index")
    return rows, manifest


def search(
    rows: list[dict], term: str = "", domain: str = "", limit: int = 20
) -> tuple[list[dict], int]:
    term, domain = term.strip().lower(), domain.strip().lower()
    if domain and domain not in {row["domain"] for row in rows}:
        raise ValueError("domain not available in this cache")
    selected = [
        row
        for row in rows
        if (not domain or row["domain"] == domain)
        and (
            not term
            or any(
                term in str(row[key]).lower()
                for key in ("id", "title", "question", "applicability")
            )
        )
    ]
    return selected[:limit], len(selected)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--domain", default="")
    parser.add_argument("--search", default="")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    if not 1 <= args.limit <= 300:
        parser.error("limit must be between 1 and 300")
    try:
        rows, manifest = inspect(args.archive)
        selected, total = search(rows, args.search, args.domain, args.limit)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))
    if args.format == "json":
        print(
            json.dumps(
                {
                    "schema_version": manifest["schema_version"],
                    "total": total,
                    "records": selected,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(f"Cache OK: {manifest['records']} prompts; {total} matches")
        for row in selected:
            print(f"{row['id']} [{row['domain']}] {row['question']}")
            if row["source_url"]:
                print("  " + row["source_url"])
        print("Candidate prompts only, not findings or completed miner runs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
