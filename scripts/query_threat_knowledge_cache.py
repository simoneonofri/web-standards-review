#!/usr/bin/env python3
"""Inspect an offline Threat Knowledge ZIP without downloading source materials."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

SCHEMA = "portable-threat-knowledge/v1"


def load(path: Path) -> tuple[list[dict], dict]:
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if len(names) != len(set(names)) or any(
            n.startswith("/") or ".." in Path(n).parts for n in names
        ):
            raise ValueError("unsafe archive")
        manifest = json.loads(z.read("manifest.json"))
        if manifest.get("schema_version") != SCHEMA:
            raise ValueError("unsupported Threat Knowledge cache schema")
        for name, metadata in manifest["artifacts"].items():
            data = z.read(name)
            if (
                len(data) != metadata["bytes"]
                or hashlib.sha256(data).hexdigest() != metadata["sha256"]
            ):
                raise ValueError("cache artifact checksum mismatch: " + name)
        records = [
            json.loads(line)
            for line in z.read("records.jsonl").decode().splitlines()
            if line.strip()
        ]
        if len(records) != manifest["records"] or len(
            {x["id"] for x in records}
        ) != len(records):
            raise ValueError("cache records inconsistent")
    return records, manifest


def query(
    records: list[dict],
    text: str = "",
    domain: str = "",
    source_id: str = "",
    limit: int = 20,
) -> tuple[list[dict], int]:
    text = text.casefold().strip()
    domain = domain.casefold().strip()
    source_id = source_id.casefold().strip()
    chosen = [
        x
        for x in records
        if (
            not text
            or any(text in str(x[k]).casefold() for k in ("question", "category", "id"))
        )
        and (not domain or x["domain"] == domain)
        and (not source_id or x["source_id"] == source_id)
    ]
    return chosen[:limit], len(chosen)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("archive", type=Path)
    p.add_argument("--search", default="")
    p.add_argument("--domain", default="")
    p.add_argument("--source", default="")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    if not 1 <= args.limit <= 1000:
        p.error("limit must be between 1 and 1000")
    try:
        rows, metadata = load(args.archive)
        selected, n = query(rows, args.search, args.domain, args.source, args.limit)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        p.error(str(error))
    if args.json:
        print(
            json.dumps(
                {"schema_version": SCHEMA, "count": n, "rows": selected},
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(
            f"Threat Knowledge: {metadata['records']} source-linked prompts, {n} matches"
        )
        for x in selected:
            print(f"{x['id']} [{x['domain']}/{x['source_id']}] {x['question']}")
        print("Questions are not target threats; verify applicability and sources.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
