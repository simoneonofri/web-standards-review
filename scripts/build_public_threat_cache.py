#!/usr/bin/env python3
"""Produce a redistributable routing-only Threat Knowledge cache.

Input is the maintainer's source-derived private cache; output contains only
newly authored generic/category-level prompt formulations, short category
labels, and public source links. No source questions, case narratives or
private spreadsheet URLs are redistributed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from export_threat_knowledge_cache import HEADERS, csv_blob, html_blob

SCHEMA = "portable-threat-knowledge/v1"
URLS = {
    "stride": "https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats",
    "linddun": "https://linddun.org/",
    "rfc3552": "https://www.rfc-editor.org/rfc/rfc3552",
    "rfc6973": "https://www.rfc-editor.org/rfc/rfc6973",
    "rfc9620": "https://www.rfc-editor.org/rfc/rfc9620",
    "harms": "https://www.microsoft.com/en-us/research/publication/harms-modeling/",
    "stakeholders": "https://www.accessnow.org/",
    "w3c-privacy-security": "https://www.w3.org/TR/security-privacy-questionnaire/",
}
SPQ = {
    "2.1": (
        "Information exposure",
        "Which parties might learn sensitive information through this feature, and when?",
    ),
    "2.2": (
        "Data minimization",
        "Could the feature reveal more detail or state than its intended use requires?",
    ),
    "2.3": (
        "Personal data",
        "What personal information is exposed, combined or inferred by this feature?",
    ),
    "2.4": (
        "Persistent identifiers",
        "Does the feature introduce identifiers that might persist or be linked across visits?",
    ),
    "2.5": (
        "Persistent state",
        "Could this feature create origin-specific state lasting beyond a session?",
    ),
    "2.6": (
        "Platform exposure",
        "Can the interface reveal characteristics of the underlying device or environment?",
    ),
    "2.7": (
        "User agent control",
        "Does this feature change who can control or observe user-agent behavior?",
    ),
    "2.8": (
        "User knowledge",
        "Could use of the feature occur without meaningful user awareness?",
    ),
    "2.9": (
        "User choice",
        "Can users control or stop collection and further use of exposed information?",
    ),
    "2.10": (
        "User identifiers",
        "Does this interface increase fingerprinting or linkage across contexts?",
    ),
    "2.11": (
        "Native UI",
        "Could web content manipulate, imitate or confuse trusted interface elements?",
    ),
    "2.12": (
        "Temporary identifiers",
        "What temporary identifiers could be exposed or correlated across parties?",
    ),
    "2.13": (
        "First and third party",
        "Would the protections differ between embedded and top-level documents?",
    ),
    "2.14": (
        "Private browsing",
        "Which effects remain observable or persistent in private browsing mode?",
    ),
    "2.15": (
        "Considerations coverage",
        "Do security and privacy sections explain the feature's actual protections and remaining threats?",
    ),
    "2.16": (
        "Security downgrade",
        "Could a caller weaken a default protection through this feature?",
    ),
    "2.17": (
        "Other concerns",
        "What additional mechanism-specific security or privacy concern needs investigation?",
    ),
    "2.18": (
        "Deployment assumptions",
        "Which operational or deployment assumptions affect privacy and security?",
    ),
}
POSSIBLY_PRIVATE = (
    "docs.google.com/spreadsheets/d/1WE-",
    "/Users/",
    "/private/",
    "file://",
    "Bearer ",
    "api_key=",
    "password=",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
)


def authored_record(record: dict) -> dict:
    item = dict(record)
    source = item.get("source_id")
    if source not in URLS:
        raise ValueError("unexpected source method: " + repr(source))
    label = re.sub(r"\s+", " ", str(item.get("category", ""))).strip()
    if source == "w3c-privacy-security":
        match = re.search(r"\b2\.\d+\b", label)
        section = match.group() if match else "2.18"
        short, prompt = SPQ[section]
        label = "W3C SPQ " + section + " — " + short
        item["question"] = prompt
    elif source == "harms":
        item["question"] = (
            "Could the system create or amplify the harm category "
            + repr(label[:110])
            + " for a particular person or affected group? Which actor and mechanism would cause it?"
        )
    elif source == "rfc9620":
        item["question"] = (
            "For the human-rights topic "
            + repr(label[:110])
            + ", which affected people and protocol actions need an impact assessment?"
        )
    elif source == "stakeholders":
        item["question"] = (
            "Could the stakeholder or impact category "
            + repr(label[:110])
            + " experience a concrete harm from this protocol and how?"
        )
    else:
        item["question"] = (
            "At which model element could the "
            + repr(label[:110])
            + " threat pattern apply, and what bad event could follow?"
        )
    item["category"] = label[:180]
    item["source_url"] = URLS[source]
    item["source_kind"] = "original_routing_question"
    item["authority"] = (
        "review prompt only; target applicability and normative evidence not verified"
    )
    item["curation_status"] = "reviewed_routing_only"
    item["reviewer_note"] = ""
    return item


def build(source: Path, output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError("refusing to overwrite a cache snapshot")
    with zipfile.ZipFile(source) as archive:
        private = json.loads(archive.read("records.json"))
        if private.get("schema_version") != SCHEMA:
            raise ValueError("unexpected input cache format")
        entries = private.get("records", [])
    rows = [authored_record(record) for record in entries]
    if not rows or len({record["id"] for record in rows}) != len(rows):
        raise ValueError("empty or duplicate public records")
    artifacts = {
        "records.jsonl": "".join(
            json.dumps(x, ensure_ascii=False, sort_keys=True) + "\n" for x in rows
        ).encode(),
        "records.json": (
            json.dumps(
                {"schema_version": SCHEMA, "records": rows},
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        ).encode(),
        "records.csv": csv_blob(rows, HEADERS),
        "index.html": html_blob(rows),
        "curation-template.csv": csv_blob(
            [], ("id", "question", "curation_status", "reviewer_note")
        ),
    }
    for name, data in artifacts.items():
        if any(token.lower() in data.decode().lower() for token in POSSIBLY_PRIVATE):
            raise ValueError("private material leaked in " + name)
    manifest = {
        "schema_version": SCHEMA,
        "built_at": datetime.now(UTC).isoformat(),
        "publication": "original_routing_prompts_with_public_source_links",
        "rights": "No original third-party question texts or full source tables included.",
        "records": len(rows),
        "domains": dict(sorted(Counter(r["domain"] for r in rows).items())),
        "methods": dict(sorted(Counter(r["source_id"] for r in rows).items())),
        "sources": [
            {"source_id": method, "locator": url, "redistributed_source_text": False}
            for method, url in sorted(URLS.items())
        ],
        "artifacts": {
            name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            for name, data in artifacts.items()
        },
        "limitations": [
            "Routing questions are not full third-party method texts or target-specific findings.",
            "The target specification must be obtained and verified separately.",
            "A portable cache consultation is not a live miner invocation.",
        ],
    }
    artifacts["manifest.json"] = (
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    ).encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(artifacts.items()):
            archive.writestr(name, data)
    return {
        "status": "public_original_routing_cache",
        "records": len(rows),
        "output": str(output),
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-source-cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.private_source_cache, args.output), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
