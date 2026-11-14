"""Source-aware editorial quality checks for specification Considerations drafts.

These checks reject obvious audit-log prose and invalid source anchors. Passing
does NOT approve technical correctness, user-agent conformance or publication.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

HEADING = re.compile(r"(?m)^#{2,4}\s+(.+)$")
LINK = re.compile(r"https://[^\s)\]}>]+")
THREAT_HEADING = re.compile(r"(?m)^#{2,4}\s+.*\b(?:T|R)-\d{2,}\b")
BOILERPLATE = (
    "The response package records a",
    "Its actual enforcement must be confirmed",
    "A potential scenario is that",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sections(markdown: str) -> tuple[str, str]:
    headers = list(
        re.finditer(
            r"(?m)^## (Security Considerations|Privacy Considerations)\s*$", markdown
        )
    )
    if len(headers) != 2 or [h.group(1) for h in headers] != [
        "Security Considerations",
        "Privacy Considerations",
    ]:
        raise ValueError(
            "one Security and one Privacy section, in that order, are required"
        )
    return markdown[headers[0].end() : headers[1].start()], markdown[headers[1].end() :]


def audit(draft: Path, source_packet: Path, ledger: Path | None = None) -> dict:
    md = draft.read_text(encoding="utf-8")
    source = json.loads(source_packet.read_text(encoding="utf-8"))
    if source.get("source_packet_contract_version") != 1:
        raise ValueError("unsupported source corpus")
    snapshot = source.get("snapshot_identity", {}).get("immutable_url")
    if not isinstance(snapshot, str) or not snapshot.startswith("https://"):
        raise ValueError("missing immutable snapshot identity")
    inventory = {
        row["source_url"]: row
        for row in source.get("sections", [])
        if isinstance(row, dict) and row.get("source_url")
    }
    if not inventory or not all(url.startswith(snapshot + "#") for url in inventory):
        raise ValueError(
            "source inventory is incomplete or belongs to a different snapshot"
        )
    security, privacy = sections(md)
    errors = []
    findings = []
    counts = {
        "security_words": len(security.split()),
        "privacy_words": len(privacy.split()),
        "security_topics": sum(
            1 for line in security.splitlines() if line.startswith("### ")
        ),
        "privacy_topics": sum(
            1 for line in privacy.splitlines() if line.startswith("### ")
        ),
        "machine_id_headings": len(THREAT_HEADING.findall(md)),
    }
    if counts["machine_id_headings"]:
        errors.append(
            "machine threat IDs in editorial headings; group by topic or mechanism"
        )
    for phrase in BOILERPLATE:
        times = md.count(phrase)
        counts["boilerplate_" + re.sub(r"[^a-z]+", "_", phrase.lower()).strip("_")] = (
            times
        )
        if times >= 3:
            errors.append(f"repeated mechanical authoring phrase: {phrase}")
    if any(counts[name] < 2 for name in ("security_topics", "privacy_topics")):
        findings.append(
            "one section has fewer than two thematic subsections; this can be appropriate for a short specification"
        )
    if counts["security_words"] < 250 or counts["privacy_words"] < 250:
        findings.append(
            "short Considerations section: check technical coverage rather than enforcing a word quota"
        )
    if "There are no security considerations associated with Geolocation" in security:
        errors.append(
            "copied empty Geolocation Security Considerations without analyzing normative controls"
        )
    if not any(
        term in security.lower()
        for term in (
            "residual",
            "remaining",
            "does not",
            "still possible",
            "not prevent",
        )
    ):
        findings.append(
            "consider clarifying what the documented protections do not address"
        )
    if "retention" not in privacy.lower() or "recipient" not in privacy.lower():
        findings.append(
            "Check whether recipient processing and retention are applicable to this API"
        )
    if "does not" not in md.lower():
        findings.append(
            "check whether security/privacy enforcement limitations are explicit"
        )
    section_links = LINK.findall(security + privacy)
    target_links = {u.rstrip(".,;") for u in section_links if u.startswith(snapshot)}
    unknown = sorted(u for u in target_links if u not in inventory and u != snapshot)
    if unknown:
        errors.append(
            "target-source anchors are absent from exact snapshot: "
            + ", ".join(unknown[:8])
        )
    if not target_links:
        errors.append("no target-specific evidence links in either section")
    coverage = {
        row.get("anchor") for row in source["sections"] if isinstance(row, dict)
    }
    required_for_target = {"request-a-position", "privacy_for_recipients", "security"}
    if "geolocation" in snapshot and not required_for_target.issubset(coverage):
        errors.append("Geolocation's key source sections are missing from the snapshot")
    if ledger is not None:
        record = json.loads(ledger.read_text(encoding="utf-8"))
        if record.get("source_snapshot") != snapshot:
            errors.append(
                "editorial evidence ledger source identity differs from source packet"
            )
        if record.get("publication_authorized") is not False:
            errors.append("editorial evidence may not approve publication")
        if not record.get("draft_sha256"):
            errors.append(
                "editorial evidence ledger is missing its mandatory draft hash"
            )
        elif record["draft_sha256"] != sha(draft.read_bytes()):
            errors.append("editorial evidence ledger no longer matches this draft")
        for row in record.get("entries", []):
            ref = row.get("source", "")
            if not ref or ref not in inventory:
                errors.append(
                    "editorial evidence references a section absent from source packet"
                )
        if not record.get("entries"):
            errors.append("no source-linked editorial evidence rows supplied")
    original_security = next(
        (
            x.get("raw_text", "")
            for x in source["sections"]
            if x.get("anchor") == "security"
        ),
        "",
    )
    original_privacy = next(
        (
            x.get("raw_text", "")
            for x in source["sections"]
            if x.get("anchor") == "privacy"
        ),
        "",
    )
    status = "blocked" if errors else "editorial_checks_passed"
    return {
        "schema_version": "considerations-editorial-check/v1",
        "status": status,
        "publication_authorized": False,
        "source_snapshot": snapshot,
        "old_security_words": len(original_security.split()),
        "old_privacy_words": len(original_privacy.split()),
        "counts": counts,
        "source_anchor_links": len(target_links),
        "errors": errors,
        "technical_followups": [
            "check any unverified normative-source or enforcement claim",
            "preserve existing material that remains technically accurate",
            "reconcile any open threat-model coverage separately",
        ],
        "notes": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--draft", type=Path, required=True)
    parser.add_argument("--source-packet", type=Path, required=True)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        receipt = audit(args.draft, args.source_packet, args.ledger)
        if args.output:
            if args.output.exists():
                raise ValueError("editorial QA output already exists")
            args.output.write_text(
                json.dumps(receipt, indent=2, ensure_ascii=False) + "\n"
            )
        print(json.dumps(receipt, indent=2, ensure_ascii=False))
        return 0 if receipt["status"] != "blocked" else 2
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "publication_authorized": False,
                    "error": str(error),
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
