#!/usr/bin/env python3
"""Build an offline review-question cache from the Web Standards Review monorepo.

No W3C Knowledge connection, Docker, external miner repositories, or network.
Only a strictly allowlisted set of source catalogs under skills/ is read.
Produces a staging artifact: rights approval is separately required.
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
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[1]
SCHEMA = "web-standards-review-offline-cache/v1"
DOMAINS = (
    "security",
    "privacy",
    "design",
    "accessibility",
    "internationalization",
    "harms",
    "human-rights",
)
SOURCES = {
    "w3c-webappsec-miner": "skills/w3c-webappsec-miner/catalog/security-controls.json",
    "whatwg-miner": "skills/whatwg-miner/catalog/security-features.json",
    "w3c-spec-miner": "skills/w3c-spec-miner/references/pattern-definitions.json",
    "w3c-horizontal-review-patterns-miner": "skills/w3c-horizontal-review-patterns-miner/references/review-patterns.json",
    "w3c-security-pattern-miner": "skills/w3c-security-pattern-miner/catalog/security-checks.json",
}
COLUMNS = (
    "id",
    "skill",
    "domain",
    "kind",
    "title",
    "question",
    "applicability",
    "source_url",
    "authority",
    "maturity",
    "curation_status",
    "reviewer_note",
)
EDIT_COLUMNS = ("id", "question", "applicability", "curation_status", "reviewer_note")
STATUSES = {"unreviewed", "proposed", "reviewed", "deprecated"}
PRIVATE_MARKERS = (
    "/Users/",
    "/private/",
    "file://",
    "local-catalog:",
    "Bearer ",
    "GITHUB_TOKEN",
    "api_key=",
    "password=",
    "127.0.0.1",
    "localhost",
)
LIMITS = {"id": 200, "question": 1200, "applicability": 700, "reviewer_note": 600}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def clean(value: object, limit: int = 1300) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False)
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) > limit:
        text = text[:limit].rstrip()
    if any(item.lower() in text.lower() for item in PRIVATE_MARKERS):
        raise ValueError("private-path or secret-like content detected in cache")
    return text


def source_link(value: object) -> str:
    url = clean(value, 1000) if value else ""
    if not url:
        return ""
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    allowed = (
        host in {"github.com", "w3c.github.io", "wicg.github.io", "www.rfc-editor.org"}
        or host in {"w3.org", "www.w3.org"}
        or host.endswith((".w3.org", ".whatwg.org"))
    )
    return (
        url
        if parsed.scheme == "https"
        and allowed
        and not parsed.username
        and not parsed.password
        else ""
    )


def item(
    skill: str,
    original_id: str,
    domain: str,
    kind: str,
    title: object,
    question: object,
    applicability: object = "",
    url: object = "",
    authority: str = "",
    maturity: str = "",
) -> dict:
    ident = clean(original_id, 140)
    if not ident or not re.fullmatch(r"[a-zA-Z0-9_.:-]+", ident):
        raise ValueError("invalid miner record identifier")
    if domain not in DOMAINS:
        raise ValueError("unsupported review domain")
    question_text, title_text = clean(question, LIMITS["question"]), clean(title, 220)
    if not question_text or not title_text:
        raise ValueError("catalog record lacks a review question or title")
    return {
        "id": f"{skill}:{ident}",
        "skill": skill,
        "domain": domain,
        "kind": kind,
        "title": title_text,
        "question": question_text,
        "applicability": clean(applicability, LIMITS["applicability"]),
        "source_url": source_link(url),
        "authority": clean(authority, 120),
        "maturity": clean(maturity, 75),
        "curation_status": "unreviewed",
        "reviewer_note": "",
    }


def load_sources(root: Path) -> tuple[dict, list[dict]]:
    sources = {}
    provenance = []
    for skill, path in SOURCES.items():
        target = root / path
        if not target.is_file() or target.is_symlink():
            raise ValueError("required portable source catalog missing: " + path)
        content = target.read_bytes()
        sources[skill] = json.loads(content)
        provenance.append(
            {"skill": skill, "source_path": path, "sha256": sha256(content)}
        )
    return sources, provenance


def gather(root: Path) -> tuple[list[dict], list[dict], list[dict]]:
    catalog = json.loads((root / "catalog.yaml").read_text(encoding="utf-8"))
    registered = {row["id"] for row in catalog["skills"]}
    if not set(SOURCES).issubset(registered):
        raise ValueError("portable cache source references an unregistered skill")
    sources, provenance = load_sources(root)
    rows = []

    for entry in sources["w3c-webappsec-miner"]["controls"]:
        urls = [source_link(x.get("source_url")) for x in entry.get("evidence", [])]
        rows.append(
            item(
                "w3c-webappsec-miner",
                entry["control_id"],
                "security",
                "control-check",
                entry["title"],
                entry["review_question"],
                entry.get("applicability", []),
                next((u for u in urls if u), ""),
                "standards-derived review prompt",
                "curated",
            )
        )

    for entry in sources["whatwg-miner"]["findings"]:
        rows.append(
            item(
                "whatwg-miner",
                entry["id"],
                "security",
                "platform-control",
                entry["control"],
                "Does the target preserve or appropriately reuse "
                + entry["control"]
                + "?",
                entry.get("applicability", ""),
                entry.get("url", ""),
                "WHATWG source-linked candidate",
                entry.get("confidence", ""),
            )
        )

    for entry in sources["w3c-spec-miner"]:
        rows.append(
            item(
                "w3c-spec-miner",
                entry["pattern_id"],
                "security",
                "specification-pattern",
                entry["title"],
                entry["review_question"],
                entry.get("category", ""),
                "",
                "W3C-derived observation (not normative)",
                "derived",
            )
        )

    for entry in sources["w3c-horizontal-review-patterns-miner"]["patterns"]:
        kind = str(entry.get("review_kind") or "").lower()
        domain = (
            "design"
            if "tag" in kind or "design" in kind
            else "privacy"
            if "privacy" in kind
            else "security"
        )
        for n, question in enumerate(entry.get("review_questions", []), 1):
            rows.append(
                item(
                    "w3c-horizontal-review-patterns-miner",
                    entry["pattern_id"] + f":q{n}",
                    domain,
                    "horizontal-review-question",
                    entry["title"],
                    question,
                    entry.get("applies_when", {}),
                    "",
                    "review pattern (not W3C consensus)",
                    entry.get("maturity", "seed"),
                )
            )

    for entry in sources["w3c-security-pattern-miner"]["checks"]:
        rows.append(
            item(
                "w3c-security-pattern-miner",
                entry["check_id"],
                "security",
                "security-pattern-check",
                entry["title"],
                entry["question"],
                entry.get("applicability", {}),
                "",
                "derived security check",
                entry.get("maturity", "seed"),
            )
        )

    # These are pointers to methods, not extracted specialist miner results.
    # Explicit maturity prevents the initial seeds from looking like domain coverage.
    for domain, ident, text, url in [
        (
            "accessibility",
            "FAST",
            "Which accessibility requirements and risks apply to this feature?",
            "",
        ),
        (
            "internationalization",
            "i18n-self-review",
            "Which internationalization self-review questions apply?",
            "",
        ),
        (
            "harms",
            "stakeholders",
            "Which stakeholders may experience an identifiable harm from this design?",
            "",
        ),
        (
            "human-rights",
            "RFC9620",
            "Which affected people and rights require investigation under RFC 9620?",
            "https://www.rfc-editor.org/rfc/rfc9620",
        ),
    ]:
        rows.append(
            item(
                "method-reference-index",
                ident,
                domain,
                "reference-only",
                ident,
                text,
                "source discovery only",
                url,
                "not an executed specialist miner",
                "reference-seed",
            )
        )

    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate stable cache record IDs")
    coverage = [
        {
            "skill": name,
            "status": "catalog_exported"
            if name in SOURCES
            else "reference_only"
            if name == "threat-knowledge"
            else "not_bundled",
            "note": "No automatically verified miner execution is implied by this index.",
        }
        for name in sorted(registered)
        if "miner" in name or name == "threat-knowledge"
    ]
    return sorted(rows, key=lambda row: row["id"]), provenance, coverage


def apply_edits(rows: list[dict], csv_path: Path) -> int:
    if not csv_path.is_file():
        raise ValueError("missing committed curation CSV")
    records = {row["id"]: row for row in rows}
    edited = set()
    with csv_path.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if not set(EDIT_COLUMNS).issubset(reader.fieldnames or []):
            raise ValueError("curation CSV has missing fields")
        for edit in reader:
            ident = (edit.get("id") or "").strip()
            if not ident:
                continue
            if ident in edited or ident not in records:
                raise ValueError("duplicate or unknown curation ID: " + ident)
            edited.add(ident)
            state = (edit.get("curation_status") or "").strip()
            if state not in STATUSES:
                raise ValueError("unrecognized curation state")
            target = records[ident]
            for key in ("question", "applicability", "reviewer_note"):
                value = (edit.get(key) or "").strip()
                if value:
                    target[key] = clean(value, LIMITS[key])
            target["curation_status"] = state
    return len(edited)


def encode_csv(rows: list[dict], headers: tuple[str, ...]) -> bytes:
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=headers, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        safe = {}
        for key in headers:
            value = str(row.get(key, ""))
            # A cell with this leading character is executable in some spreadsheets.
            safe[key] = (
                "'" + value
                if value.lstrip().startswith(("=", "+", "-", "@"))
                else value
            )
        writer.writerow(safe)
    return stream.getvalue().encode("utf-8")


def render_md(rows: list[dict]) -> bytes:
    count = Counter(x["domain"] for x in rows)
    lines = [
        "# Web Standards Review — offline question index",
        "",
        "Candidate questions only. Not W3C consensus, target findings or verified controls.",
        "Publication requires a separate rights review.",
        "",
        "| Domain | Records |",
        "|---|---:|",
    ]
    lines.extend(f"| {name} | {n} |" for name, n in sorted(count.items()))
    lines += [
        "",
        "For edits, submit a pull request changing cache/curation/overrides.csv.",
        "",
    ]
    for domain in sorted(count):
        lines += [f"## {domain}", "", "| Question | Source |", "|---|---|"]
        for row in rows:
            if row["domain"] != domain:
                continue
            q = row["question"].replace("|", "/")
            link = (
                f"[source]({row['source_url']})"
                if row["source_url"]
                else "local catalog"
            )
            lines.append(f"| {q} | {link} |")
        lines.append("")
    return ("\n".join(lines) + "\n").encode("utf-8")


def render_html(rows: list[dict]) -> bytes:
    records = json.dumps(rows, ensure_ascii=False).replace("<", "\\u003c")
    page = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Web Standards Review question index</title>
<style>
body{max-width:1100px;margin:2em auto;padding:1em;font:16px/1.5 system-ui}
input,select{font:inherit;padding:.4em}table{width:100%;border-collapse:collapse}
td,th{padding:.6em;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}
small{color:#666}thead{background:#eee}
</style></head><body><h1>Review question index</h1>
<p>Draft prompts, not validated controls, findings or group consensus.
Redistribution is subject to rights approval.</p>
<label>Search <input id="q" placeholder="origin, privacy, accessibility"></label>
<label>Domain <select id="d"><option value="">All</option></select></label>
<p id="count" aria-live="polite"></p>
<table><thead><tr><th>Domain</th><th>Question</th><th>Source</th></tr></thead>
<tbody id="rows"></tbody></table>
<script>
const data=RECORDS;
const q=document.getElementById("q"),d=document.getElementById("d");
for(const x of [...new Set(data.map(r=>r.domain))].sort()){
const o=document.createElement("option");o.value=x;o.textContent=x;d.append(o)}
function render(){
const term=q.value.trim().toLowerCase(),domain=d.value;
const matching=data.filter(r=>(!domain||r.domain===domain)&&
[r.title,r.question,r.applicability,r.id].some(t=>t.toLowerCase().includes(term)));
document.getElementById("count").textContent=matching.length+" questions";
const body=document.getElementById("rows");body.replaceChildren();
for(const r of matching.slice(0,500)){
const tr=document.createElement("tr"),a=document.createElement("td"),
b=document.createElement("td"),c=document.createElement("td");
a.textContent=r.domain;b.textContent=r.question;
if(r.source_url){const link=document.createElement("a");link.href=r.source_url;
link.rel="noopener noreferrer";link.textContent="Source";c.append(link)}
const info=document.createElement("small");info.textContent=" ("+r.skill+")";c.append(info);
tr.append(a,b,c);body.append(tr)}
}q.addEventListener("input",render);d.addEventListener("change",render);render();
</script></body></html>""".replace("RECORDS", records, 1)
    return page.encode("utf-8")


def build(root: Path, destination: Path, edits_path: Path) -> dict:
    rows, provenance, skill_coverage = gather(root)
    applied = apply_edits(rows, edits_path)
    files = {
        "records.jsonl": "".join(
            json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows
        ).encode("utf-8"),
        "records.json": (
            json.dumps(
                {"schema_version": SCHEMA, "records": rows},
                indent=2,
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8"),
        "records.csv": encode_csv(rows, COLUMNS),
        "index.md": render_md(rows),
        "index.html": render_html(rows),
        "curation-template.csv": encode_csv([], EDIT_COLUMNS),
    }
    for name, content in files.items():
        if any(
            mark.lower() in content.decode("utf-8").lower() for mark in PRIVATE_MARKERS
        ):
            raise ValueError("private data detected in generated " + name)
    manifest = {
        "schema_version": SCHEMA,
        "built_at": datetime.now(UTC).isoformat(),
        "catalog_version": json.loads((root / "catalog.yaml").read_text())[
            "catalog_version"
        ],
        "status": "staged_publication_rights_review_required",
        "records": len(rows),
        "domains": dict(sorted(Counter(row["domain"] for row in rows).items())),
        "catalog_sources": provenance,
        "skill_coverage": skill_coverage,
        "human_edits": applied,
        "artifacts": {
            name: {"sha256": sha256(content), "bytes": len(content)}
            for name, content in files.items()
        },
        "not_included": [
            "W3C Knowledge database or source packets",
            "full third-party normative texts or transcripts",
            "personal overlays, secrets and private review artifacts",
            "query-specific vulnerability-intelligence results",
            "sustainability miner (future work)",
        ],
        "limitations": [
            "Cache availability is not evidence that a miner was executed.",
            "Domain-reference seeds are not full accessibility, i18n, harms or human-rights checklists.",
            "No target-specific review, model attachment or disposition has been performed.",
        ],
    }
    files["manifest.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        destination, mode="w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        for name, content in sorted(files.items()):
            archive.writestr(name, content)
    return {
        "file": str(destination),
        "sha256": sha256(destination.read_bytes()),
        "records": len(rows),
        "domains": manifest["domains"],
        "catalogs": len(provenance),
        "human_edits": applied,
        "status": manifest["status"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--curation", type=Path, default=REPO / "cache/curation/overrides.csv"
    )
    args = parser.parse_args()
    print(json.dumps(build(REPO, args.output, args.curation), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
