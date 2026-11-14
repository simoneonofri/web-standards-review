#!/usr/bin/env python3
"""Export a portable *private staging* Threat Knowledge prompt cache.

This uses the existing threat-knowledge curated source tables; it never
downloads the original corpus, copies PDFs, or republishes original full text.
Every derived question is explicitly marked rights-review-required.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import zipfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

SCHEMA = "portable-threat-knowledge/v1"
SHEETS = {
    "security-threats-stride": ("security", "stride", "Threat", "Description"),
    "security-attacks-rfc-3552": ("security", "rfc3552", "Name", "Description"),
    "privacy-threats-linddun": ("privacy", "linddun", "Threat Category", "Description"),
    "privacy-threats-rfc-6973": ("privacy", "rfc6973", "Threat", "Description"),
    "rfc9620": ("human-rights", "rfc9620", "Title", "Question"),
    "harms-microsoft": ("harms", "harms", "Harm", "Consideration(s)"),
    "harms-threats-access-now": ("harms", "stakeholders", "Harm", "Description"),
    "harms-threats-corti-et-al-ndi": ("harms", "stakeholders", "HARM", "HARM"),
    "cognitive-threats": ("harms", "harms", "Harm", "Consideration(s)"),
    "stakeholders-access-now": ("human-rights", "stakeholders", "Category", "Story"),
    "privacysecurity-questions-w3c": (
        "combined",
        "w3c-privacy-security",
        "Questions",
        "Questions",
    ),
}
SOURCE_URL = "https://docs.google.com/spreadsheets/d/1WE-xT8fYXfr6yy8de6dav3Ve2G9pB18Eadh6_VqmCuU/edit"
RFC_URL = {
    "rfc3552": "https://www.rfc-editor.org/rfc/rfc3552",
    "rfc6973": "https://www.rfc-editor.org/rfc/rfc6973",
    "rfc9620": "https://www.rfc-editor.org/rfc/rfc9620",
}
HEADERS = (
    "id",
    "source_id",
    "domain",
    "category",
    "question",
    "source_url",
    "source_kind",
    "authority",
    "curation_status",
    "reviewer_note",
)
EDIT_HEADERS = ("id", "question", "curation_status", "reviewer_note")
STATES = {"unreviewed", "proposed", "reviewed", "deprecated"}
BLOCKED = (
    "/Users/",
    "/private/",
    "file://",
    "Bearer ",
    "api_key=",
    "password=",
    "localhost",
    "127.0.0.1",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe(value: object, limit: int = 550) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()[:limit]
    if any(s.lower() in text.lower() for s in BLOCKED):
        raise ValueError("private/credential-like content found in Threat Knowledge")
    return text


def question_for(slug: str, category: str, original: str) -> tuple[str, str]:
    if slug == "stakeholders-access-now":
        return (
            f"Could people in the stakeholder category '{category}' be harmed or excluded by this system?",
            "original_routing_question",
        )
    if slug in {"harms-threats-access-now", "harms-threats-corti-et-al-ndi"}:
        return (
            f"Could this system cause or amplify the harm category '{category}' for affected people?",
            "original_routing_question",
        )
    if original and "?" in original:
        return safe(original, 780), "source_question"
    return (
        f"Could the threat or impact category '{category}' occur at this model element, and with what consequences?",
        "original_routing_question",
    )


def build_records(root: Path) -> tuple[list[dict], list[dict]]:
    table_root = root / "references/corpus/threat-frameworks/google-sheet"
    if not (root / "references/corpus/threat-frameworks/MANIFEST.md").is_file():
        raise ValueError(
            "source corpus manifest missing; a partial source root is not accepted"
        )
    records, sources = [], []
    for slug, (domain, method, title_column, question_column) in SHEETS.items():
        path = table_root / (slug + ".csv")
        if not path.is_file() or path.is_symlink():
            raise ValueError("missing Threat Knowledge source tab: " + slug)
        raw = path.read_bytes()
        source_text = raw.decode("utf-8-sig")
        if slug == "harms-threats-corti-et-al-ndi":
            # This published source table has an attribution preamble, then
            # its actual headers. Blank continuation rows do not add prompts.
            lines = list(csv.reader(io.StringIO(source_text)))
            if len(lines) < 3 or "HARM" not in lines[1]:
                raise ValueError("Corti harms table has an unexpected heading")
            header = lines[1]
            data = [
                dict(zip(header, fields))
                for fields in lines[2:]
                if len(fields) == len(header) and any(fields)
            ]
        else:
            data = list(csv.DictReader(io.StringIO(source_text)))
        if not data:
            raise ValueError("empty tab: " + slug)
        sources.append(
            {
                "source_id": method,
                "tab": slug,
                "sha256": sha(raw),
                "rows": len(data),
                "locator": RFC_URL.get(method, SOURCE_URL),
                "license_review": "required",
            }
        )
        for i, row in enumerate(data, 1):
            category = safe(row.get(title_column, ""), 180)
            if not category:
                # Repeated blank category cells are layout continuation rows,
                # not independent questions or threat observations.
                continue
            if slug == "harms-threats-corti-et-al-ndi":
                question_value = ""
            else:
                question_value = str(row.get(question_column, ""))
            prompt, kind = question_for(slug, category, question_value)
            if not prompt:
                raise ValueError(f"{slug}:{i}: missing prompt")
            records.append(
                {
                    "id": f"tk:{slug}:{i:04d}",
                    "source_id": method,
                    "domain": domain,
                    "category": category,
                    "question": prompt,
                    "source_url": RFC_URL.get(method, SOURCE_URL),
                    "source_kind": kind,
                    "authority": "source_derived_prompt_not_normative_target_requirement",
                    "curation_status": "unreviewed",
                    "reviewer_note": "",
                }
            )
    if len({r["id"] for r in records}) != len(records):
        raise ValueError("Threat Knowledge duplicate IDs")
    return records, sources


def apply_edits(records: list[dict], path: Path | None) -> int:
    if path is None:
        return 0
    by_id = {r["id"]: r for r in records}
    updated = set()
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not set(EDIT_HEADERS).issubset(reader.fieldnames or []):
            raise ValueError("Threat Knowledge curation file lacks columns")
        for row in reader:
            key = (row.get("id") or "").strip()
            if not key:
                continue
            if key not in by_id or key in updated:
                raise ValueError("unknown or duplicate Threat Knowledge override ID")
            state = (row.get("curation_status") or "").strip()
            if state not in STATES:
                raise ValueError("invalid Threat Knowledge curation state")
            updated.add(key)
            item = by_id[key]
            for field, limit in (("question", 780), ("reviewer_note", 350)):
                if row.get(field, "").strip():
                    item[field] = safe(row[field], limit)
            item["curation_status"] = state
    return len(updated)


def csv_blob(rows: list[dict], headers: tuple[str, ...]) -> bytes:
    f = io.StringIO()
    writer = csv.DictWriter(f, fieldnames=headers, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        # Prevent spreadsheet formula injection when opened in CSV editors.
        clean_row = {}
        for key in headers:
            value = str(row.get(key, ""))
            clean_row[key] = (
                "'" + value
                if value.lstrip().startswith(("=", "+", "-", "@"))
                else value
            )
        writer.writerow(clean_row)
    return f.getvalue().encode("utf-8")


def html_blob(rows: list[dict]) -> bytes:
    records = json.dumps(rows, ensure_ascii=False).replace("<", "\\u003c")
    document = """<!doctype html><html lang="en"><meta charset="utf-8">
<title>Threat Knowledge - Portable Prompt Index</title>
<style>body{font:16px/1.5 system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem}
input,select{font:inherit;padding:.5rem}table{border-collapse:collapse;width:100%}
td,th{text-align:left;vertical-align:top;border-bottom:1px solid #ccc;padding:.6rem}
thead{background:#eee}small{color:#666}</style>
<h1>Threat Knowledge — prompt index</h1>
<p>Question sources only, not target findings or complete framework texts.
Public redistribution requires a separate source-rights approval.</p>
<label>Search <input id="q" placeholder="threat, rights, privacy"></label>
<label>Domain <select id="d"><option value="">All</option></select></label>
<p id="count" aria-live="polite"></p>
<table><thead><tr><th>Domain</th><th>Category</th><th>Question</th><th>Source</th></tr></thead><tbody id="body"></tbody></table>
<script>
const data=RECORDS,q=document.getElementById("q"),d=document.getElementById("d"),body=document.getElementById("body");
for(const domain of [...new Set(data.map(r=>r.domain))].sort()){let o=document.createElement("option");o.value=domain;o.textContent=domain;d.append(o)}
function render(){const term=q.value.toLowerCase(),domain=d.value;
const matches=data.filter(r=>(!domain||r.domain===domain)&&
[r.id,r.category,r.question,r.source_id].some(x=>x.toLowerCase().includes(term)));
document.getElementById("count").textContent=matches.length+" questions";body.replaceChildren();
for(const r of matches.slice(0,500)){let tr=document.createElement("tr");
for(const val of [r.domain,r.category,r.question]){let td=document.createElement("td");td.textContent=val;tr.append(td)}
let td=document.createElement("td"),a=document.createElement("a");a.href=r.source_url;a.rel="noopener noreferrer";a.textContent=r.source_id;td.append(a);tr.append(td);body.append(tr)}}
q.addEventListener("input",render);d.addEventListener("change",render);render();</script></html>""".replace(
        "RECORDS", records, 1
    )
    return document.encode("utf-8")


def create(root: Path, destination: Path, edits: Path | None = None) -> dict:
    if destination.exists() or destination.is_symlink():
        raise ValueError("refusing to overwrite a previous Threat Knowledge snapshot")
    records, sources = build_records(root)
    curated = apply_edits(records, edits)
    files = {
        "records.jsonl": "".join(
            json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in records
        ).encode(),
        "records.json": (
            json.dumps(
                {"schema_version": SCHEMA, "records": records},
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        ).encode(),
        "records.csv": csv_blob(records, HEADERS),
        "index.html": html_blob(records),
        "curation-template.csv": csv_blob([], EDIT_HEADERS),
    }
    for name, data in files.items():
        if any(s.lower() in data.decode("utf-8").lower() for s in BLOCKED):
            raise ValueError("private data in Threat Knowledge export: " + name)
    manifest = {
        "schema_version": SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(),
        "publication": "blocked_pending_redistribution_rights_review",
        "records": len(records),
        "domains": dict(sorted(Counter(x["domain"] for x in records).items())),
        "methods": dict(sorted(Counter(x["source_id"] for x in records).items())),
        "sources": sources,
        "curation_overrides": curated,
        "artifacts": {
            name: {"sha256": sha(data), "bytes": len(data)}
            for name, data in files.items()
        },
        "limitations": [
            "Derived category questions are not source texts or complete framework coverage.",
            "Full case-study narratives, sensitive stakeholder stories, raw PDFs and original source files excluded.",
            "Only the maintainer's source corpus can refresh this snapshot.",
            "No vulnerability, harm or W3C position follows from prompt selection.",
            "Sustainability intentionally excluded from active methods.",
        ],
    }
    files["manifest.json"] = (
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    return {
        "archive": str(destination),
        "sha256": sha(destination.read_bytes()),
        "records": len(records),
        "domains": manifest["domains"],
        "methods": manifest["methods"],
        "rights_review": manifest["publication"],
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--threat-knowledge-root",
        type=Path,
        required=True,
        help="Trusted local checkout with references/corpus/threat-frameworks",
    )
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--overrides", type=Path)
    args = p.parse_args()
    print(
        json.dumps(
            create(args.threat_knowledge_root, args.output, args.overrides), indent=2
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
