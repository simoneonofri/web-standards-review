"""Compose specification-facing Security and Privacy Considerations from a source-grounded editorial packet.

This is the normal authoring contract for the skill, not the older per-threat
scaffolder. The agent writes grouped paragraphs after reading the exact
specification; this tool validates associations and assembles final artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
from pathlib import Path

from check_editorial_rewrite import audit
from draft_considerations import load, validate_identity
from validate_remediation_links import validate as validate_pr37_remediation

SCHEMA = "considerations-editorial-packet/v2"
LEGACY_SCHEMA = "considerations-editorial-packet/v1"
THREAT_MARKER = re.compile(r"\b(?:T|R)-\d{2,}\b")
SECURITY_HEADING = "## Security Considerations"
PRIVACY_HEADING = "## Privacy Considerations"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be nonempty prose")
    return value.strip()


def pinned_sections(source: dict, snapshot: str) -> dict[str, dict]:
    if source.get("source_packet_contract_version") != 1:
        raise ValueError("source packet version not supported")
    if source.get("snapshot_identity", {}).get("immutable_url") != snapshot:
        raise ValueError("source packet snapshot differs from the model/manifest")
    entries = source.get("sections", [])
    if not isinstance(entries, list) or not entries:
        raise ValueError("a complete source packet with sections is required")
    items = {}
    for row in entries:
        if not isinstance(row, dict):
            raise TypeError("invalid source section")
        url = row.get("source_url", "")
        if not isinstance(url, str) or not url.startswith(snapshot + "#"):
            raise ValueError("source contains sections from another snapshot")
        if url in items:
            raise ValueError("duplicate source section")
        items[url] = row
    return items


def contains_exact_url(text: str, url: str) -> bool:
    """Do not mistake '#privacy_for_recipients' for a '#privacy' citation."""
    candidates = re.findall(r"""https://[^\s)<>\]"']+""", text)
    return url in {candidate.rstrip(".,;") for candidate in candidates}


def render_remediation(records: list[dict]) -> str:
    """Keep ERTA, actual/proposed remediation and remaining threats in the prose.

    Compact paragraphs are grouped per topic; detailed IDs stay in the ledger.
    """
    phrases: list[str] = []
    seen_remaining: set[str] = set()
    seen_assumptions: set[str] = set()
    for item in records:
        state = item["remediation_state"]
        description = str(item.get("remediation_description") or "").rstrip(".")
        actor = item.get("enforcement")
        recipient = item.get("receiving_actor")
        if state == "specified":
            phrase = "The cited requirement describes " + description + "."
        elif state == "proposed":
            phrase = (
                "The proposed remediation is "
                + description
                + "; this is not yet a requirement of the specification."
            )
        elif state == "delegated":
            phrase = (
                "The documented responsibility is delegated to "
                + str(recipient)
                + ": "
                + description
                + "."
            )
        elif state == "removed":
            phrase = "The enabling condition is removed: " + description + "."
        else:
            phrase = "No response has yet been selected. " + description + "."
        if actor and "Reduce" in item.get("strategies", []):
            phrase += " The enforcing actor is " + str(actor).rstrip(".") + "."
        if recipient and "Transfer" in item.get("strategies", []):
            phrase += " The receiving actor is " + str(recipient).rstrip(".") + "."
            if item.get("delegated_duty"):
                phrase += (
                    " This actor is responsible for "
                    + str(item["delegated_duty"]).rstrip(".")
                    + "."
                )
            if item.get("transfer_assumption"):
                phrase += (
                    " This delegation assumes "
                    + str(item["transfer_assumption"]).rstrip(".")
                    + "."
                )
        for assumption in item.get("assumptions", []):
            if assumption not in seen_assumptions:
                phrase += " This response assumes " + str(assumption).rstrip(".") + "."
                seen_assumptions.add(assumption)
        for remaining in item.get("remaining_threats", []):
            description_remaining = str(remaining.get("description", "")).strip()
            if description_remaining and description_remaining not in seen_remaining:
                phrase += (
                    " The remaining threat is "
                    + description_remaining.rstrip(".")
                    + "."
                )
                if remaining.get("accepted") is True:
                    phrase += (
                        " It was accepted because "
                        + str(remaining.get("rationale", "")).rstrip(".")
                        + "."
                    )
                seen_remaining.add(description_remaining)
        if item.get("acceptance_rationale"):
            phrase += (
                " The acceptance rationale is "
                + str(item["acceptance_rationale"]).rstrip(".")
                + "."
            )
            if item.get("acceptance_scope"):
                phrase += (
                    " The acceptance applies to "
                    + str(item["acceptance_scope"]).rstrip(".")
                    + "."
                )
        if item.get("open_decision_note"):
            phrase += (
                " This remains an open decision: "
                + str(item["open_decision_note"]).rstrip(".")
                + "."
            )
        phrases.append(phrase)
    return " ".join(phrases)


def compose(
    packet_path: Path,
    model_path: Path,
    threats_path: Path,
    responses_path: Path,
    source_manifest_path: Path,
    source_packet_path: Path,
    destination: Path,
) -> dict:
    if destination.exists() or destination.is_symlink():
        raise ValueError("destination already exists; use a unique output directory")
    packet = load(packet_path)
    model = load(model_path)
    threats = load(threats_path)
    responses = load(responses_path)
    manifest = load(source_manifest_path)
    source_packet = load(source_packet_path)
    snapshot, pairs = validate_identity(model, threats, responses, manifest)
    sections = pinned_sections(source_packet, snapshot)
    version = packet.get("schema_version")
    if version not in {SCHEMA, LEGACY_SCHEMA}:
        raise ValueError("invalid editorial packet schema")
    remediation_trace = (
        validate_pr37_remediation(packet, threats, responses, source_packet)
        if version == SCHEMA
        else None
    )
    remediation_by_id = {
        item["threat_id"]: item for item in (remediation_trace or {}).get("records", [])
    }
    if (
        packet.get("model_id") != model["model_id"]
        or packet.get("source_snapshot") != snapshot
    ):
        raise ValueError("editorial packet model/source identity differs")
    if packet.get("threat_package_id") != threats["threat_package_id"]:
        raise ValueError("editorial packet threat package differs")
    if packet.get("response_package_id") != responses["response_package_id"]:
        raise ValueError("editorial packet response package differs")
    by_id = {t["threat_id"]: r for t, r in pairs}
    source_topics = packet.get("sections")
    if not isinstance(source_topics, dict):
        raise TypeError("editorial packet needs security and privacy topic sections")

    lines = [
        "# Proposed Security and Privacy Considerations",
        "",
        "Source: " + snapshot,
        "",
    ]
    ledger = []
    included = set()
    narrated_threats: set[str] = set()
    for kind, name in (("security", SECURITY_HEADING), ("privacy", PRIVACY_HEADING)):
        record = source_topics.get(kind)
        if not isinstance(record, dict):
            raise TypeError(f"editorial section {kind} is missing")
        intro = require_text(record.get("introduction"), kind + ".introduction")
        topics = record.get("topics")
        if not isinstance(topics, list) or not topics:
            raise ValueError(f"editorial section {kind} needs source-grounded topics")
        lines.extend([name, "", intro, ""])
        headings = set()
        for number, topic in enumerate(topics, 1):
            if not isinstance(topic, dict):
                raise TypeError("editorial topic must be an object")
            heading = require_text(topic.get("heading"), "topic.heading")
            if heading in headings or THREAT_MARKER.search(heading):
                raise ValueError(
                    "topic headings must be thematic and unique, not threat IDs"
                )
            headings.add(heading)
            paragraphs = topic.get("paragraphs")
            if not isinstance(paragraphs, list) or not paragraphs:
                raise ValueError("topic needs a readable paragraph")
            prose = [require_text(p, "topic.paragraph") for p in paragraphs]
            if any(
                "The response package records a" in p
                or "A potential scenario is that" in p
                for p in prose
            ):
                raise ValueError(
                    "one-threat-per-row scaffolding is not editor-ready Considerations text"
                )
            t_ids = topic.get("threat_ids")
            response_ids = topic.get("response_ids")
            urls = topic.get("source_urls")
            if (
                not isinstance(t_ids, list)
                or not t_ids
                or len(set(t_ids)) != len(t_ids)
            ):
                raise ValueError("topic needs distinct canonical threat IDs")
            if any(tid not in by_id for tid in t_ids):
                raise ValueError("topic references threat absent from the model")
            if response_ids != [by_id[tid]["response_id"] for tid in t_ids]:
                raise ValueError("topic ERTA response IDs do not match its threat IDs")
            if not isinstance(urls, list) or not urls or len(set(urls)) != len(urls):
                raise ValueError("topic needs distinct source URLs")
            if any(url not in sections for url in urls):
                raise ValueError(
                    "topic cites an unrecognized section of the pinned snapshot"
                )
            enforcement = require_text(topic.get("enforcement"), "topic.enforcement")
            residual = require_text(topic.get("residual"), "topic.residual")
            # The authoring agent handles the actual prose, including the
            # distinction between normative code and informative discussion.
            # The code ensures it does not lose the threat-response mapping.
            lines.extend(
                ["### " + heading, "", *[paragraph + "\n" for paragraph in prose]]
            )
            visible = "\n".join(prose)
            if remediation_trace:
                # The sidecar links threats to *every* relevant topic; the
                # reader-facing prose does not repeat the same trace endlessly.
                newly_explained = [tid for tid in t_ids if tid not in narrated_threats]
                narrated_threats.update(newly_explained)
                if newly_explained:
                    narrative = render_remediation(
                        [remediation_by_id[tid] for tid in newly_explained]
                    )
                    lines.extend([narrative, ""])
                    visible += "\n" + narrative
            for url in urls:
                if not contains_exact_url(visible, url):
                    lines.append(
                        "Source: ["
                        + sections[url].get("heading", "Specification section")
                        + "]("
                        + url
                        + ")."
                    )
            if remediation_trace:
                trace_refs = []
                for tid in t_ids:
                    record = remediation_by_id[tid]
                    trace_refs.extend(record["specification_refs"])
                    trace_refs.extend(record["external_refs"])
                    trace_refs.extend(record["issue_refs"])
                for ref in dict.fromkeys(trace_refs):
                    if not contains_exact_url(visible, ref) and ref not in urls:
                        lines.append(
                            "Remediation or open-decision reference: ["
                            + ref
                            + "]("
                            + ref
                            + ")."
                        )
            lines.append("")
            for tid in t_ids:
                included.add(tid)
                response = by_id[tid]
                ledger.append(
                    {
                        "section": kind,
                        "topic": heading,
                        "threat_id": tid,
                        "response_id": response["response_id"],
                        "erta": response["erta"],
                        "response_status": response.get("status", "unspecified"),
                        "enforcement": enforcement,
                        "residual": residual,
                        "source_urls": urls,
                        "prose_key": kind + ":" + str(number),
                        "remediation_trace": remediation_by_id.get(tid),
                    }
                )
        closing = record.get("closing")
        if closing:
            lines.extend([require_text(closing, kind + ".closing"), ""])
        if kind == "security" and remediation_trace and packet.get("out_of_scope"):
            lines.extend(["### Out-of-scope threats", ""])
            for entry in packet["out_of_scope"]:
                lines.append(
                    "- "
                    + require_text(entry["threat"], "out-of-scope threat")
                    + ": "
                    + require_text(entry["rationale"], "scope rationale")
                    + "."
                )
                for ref in entry.get("specification_refs", []):
                    lines.append("  See [" + ref + "](" + ref + ").")
            lines.append("")
    if included != set(by_id):
        raise ValueError(
            "some retained threats are not mapped to the authored sections: "
            + ", ".join(sorted(set(by_id) - included))
        )

    editorial = packet.get("editing")
    if not isinstance(editorial, dict):
        raise TypeError("editorial packet must specify the rewrite strategy")
    edit_mode = editorial.get("mode")
    if edit_mode not in {"create", "amend", "rewrite", "propose"}:
        raise ValueError("editing.mode must be create, amend, rewrite or propose")
    minimal = [
        "# Minimal-edit proposal for the current specification",
        "",
        "Source: " + snapshot,
        "",
    ]
    minimal.extend(["## Proposed Security Considerations", ""])
    sec_begin = lines.index(SECURITY_HEADING)
    priv_begin = lines.index(PRIVACY_HEADING)
    minimal.extend(lines[sec_begin + 1 : priv_begin])
    policy = (
        require_text(editorial.get("privacy_strategy"), "editing.privacy_strategy")
        if edit_mode in {"amend", "rewrite", "propose"}
        else "No existing Privacy Considerations are being amended."
    )
    minimal.extend(
        ["## Proposed changes to existing Privacy Considerations", "", policy, ""]
    )
    additions = editorial.get("privacy_additions", [])
    if not isinstance(additions, list):
        raise TypeError("editing.privacy_additions must be an array")
    for addition in additions:
        if not isinstance(addition, dict):
            raise TypeError("privacy addition must be a record")
        anchor = addition.get("section_url", "")
        if anchor not in sections:
            raise ValueError("privacy addition does not match a source section")
        minimal.extend(
            [
                "### "
                + require_text(addition.get("heading"), "privacy addition heading"),
                "",
                require_text(addition.get("text"), "privacy addition text"),
                "",
                "Insertion point: " + anchor,
                "",
            ]
        )
    markdown = "\n".join(lines).rstrip() + "\n"
    comparison = "\n".join(minimal).rstrip() + "\n"
    destination.parent.mkdir(parents=True, exist_ok=True)
    working = Path(tempfile.mkdtemp(prefix=".considerations-", dir=destination.parent))
    try:
        draft = working / "considerations.md"
        draft.write_text(markdown)
        if edit_mode in {"amend", "rewrite", "propose"}:
            (working / "minimal-edit.md").write_text(comparison)
        evidence = {
            "schema_version": "considerations-editorial-evidence/v1",
            "source_snapshot": snapshot,
            "model_id": model["model_id"],
            "threat_package_id": threats["threat_package_id"],
            "response_package_id": responses["response_package_id"],
            "source_packet_sha256": sha(source_packet_path.read_bytes()),
            "editorial_packet_sha256": sha(packet_path.read_bytes()),
            "draft_sha256": sha(draft.read_bytes()),
            "publication_authorized": False,
            "entries": [
                {
                    "source": url,
                    "threat_id": row["threat_id"],
                    "response_id": row["response_id"],
                    "section": row["section"],
                    "topic": row["topic"],
                    "erta": row["erta"],
                    "enforcement": row["enforcement"],
                    "residual": row["residual"],
                }
                for row in ledger
                for url in row["source_urls"]
            ],
            "decision_ledger": ledger,
            "remediation_trace_schema": (
                remediation_trace["schema_version"] if remediation_trace else None
            ),
        }
        if remediation_trace:
            (working / "considerations-remediation-trace.json").write_text(
                json.dumps(remediation_trace, indent=2, ensure_ascii=False) + "\n"
            )
        evidence_path = working / "editorial-evidence.json"
        evidence_path.write_text(
            json.dumps(evidence, indent=2, ensure_ascii=False) + "\n"
        )
        qa = audit(draft, source_packet_path, evidence_path)
        (working / "editorial-qa.json").write_text(
            json.dumps(qa, indent=2, ensure_ascii=False) + "\n"
        )
        if qa["status"] == "blocked":
            raise ValueError("editorial QA failed: " + "; ".join(qa["errors"][:5]))
        working.rename(destination)
    except BaseException:
        shutil.rmtree(working, ignore_errors=True)
        raise
    return {
        "status": "authored",
        "source": snapshot,
        "topics": sum(
            len(source_topics[kind]["topics"]) for kind in ("security", "privacy")
        ),
        "threats_covered": len(included),
        "linked_evidence": len(evidence["entries"]),
        "editorial_checks": qa["status"],
        "directory": str(destination),
        "editing_mode": edit_mode,
        "remediation_trace": remediation_trace is not None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "editorial-packet",
        "model",
        "threats",
        "responses",
        "source-manifest",
        "source-packet",
        "output-dir",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        result = compose(
            args.editorial_packet,
            args.model,
            args.threats,
            args.responses,
            args.source_manifest,
            args.source_packet,
            args.output_dir,
        )
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "invalid", "error": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
