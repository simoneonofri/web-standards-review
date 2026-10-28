"""Capture a complete primary W3C Knowledge source packet without database access."""

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BYTES = 25 * 1024 * 1024


class EvidenceError(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise EvidenceError("The evidence endpoint redirected; select and review the destination explicitly")


def fetch_packet(base_url: str, specification: str) -> bytes:
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise EvidenceError("Knowledge URL must be an HTTP(S) base URL without credentials, query, or fragment")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,150}", specification):
        raise EvidenceError("Specification must be a shortname or ID")
    # This endpoint has no default section limit; the convenience threat-model
    # endpoint defaults to a limited primary/RFC selection.
    target = base_url.rstrip("/") + "/api/v1/specifications/" + quote(specification)
    headers = {"Accept": "application/json"}
    token = os.environ.get("W3C_KNOWLEDGE_ACCESS_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    def read(suffix):
        try:
            with build_opener(NoRedirect()).open(Request(target + suffix, headers=headers), timeout=30) as response:
                data = response.read(MAX_BYTES + 1)
        except (HTTPError, URLError, TimeoutError) as error:
            raise EvidenceError("Knowledge source unavailable; use an explicitly selected exported source packet") from error
        if len(data) > MAX_BYTES:
            raise EvidenceError("Source packet exceeds the bounded response size")
        return data
    data = read("/source-packet")
    try:
        primary = json.loads(data)
        ids = {row["section_id"] for row in primary["sections"]}
        inventory = {row["section_id"] for row in primary["section_inventory"]}
        if ids != inventory:
            # /sections can contain several versions. Attachment validation selects
            # only the exact version pinned by the first response.
            data = attach_sections(data, read("/sections"))
    except (KeyError, TypeError, ValueError) as error:
        raise EvidenceError("Invalid source response or full-section attachment") from error
    return data


def attach_sections(packet: bytes, sections: bytes) -> bytes:
    return json.dumps({"schema_version": "knowledge-full-source/v1",
                       "source_packet": json.loads(packet),
                       "full_sections": json.loads(sections)}).encode()


def inspect_packet(data: bytes, expected_snapshot: str | None = None) -> tuple[dict, dict]:
    try:
        packet = json.loads(data)
    except (ValueError, UnicodeError) as error:
        raise EvidenceError("Source packet must be valid JSON") from error
    if not isinstance(packet, dict):
        raise EvidenceError("Source packet must be an object")
    attachment = None
    if packet.get("schema_version") == "knowledge-full-source/v1":
        attachment = packet.get("full_sections")
        packet = packet.get("source_packet")
        if not isinstance(packet, dict) or not isinstance(attachment, list):
            raise EvidenceError("Invalid full-section attachment")
    if "primary_specification" in packet:
        if packet.get("threat_model_contract_version") != 2:
            raise EvidenceError("Bundled evidence must preserve threat-model usage contract v2")
        primary = packet["primary_specification"]
    else:
        primary = packet
    if not isinstance(primary, dict) or primary.get("source_packet_contract_version") != 1:
        raise EvidenceError("Unsupported primary source packet contract")
    snapshot = primary.get("snapshot_identity", {})
    if not isinstance(snapshot, dict):
        raise EvidenceError("Snapshot identity must be an object")
    identity = snapshot.get("immutable_url") or snapshot.get("canonical_url")
    if not isinstance(identity, str) or not identity or not isinstance(primary.get("specification_version_id"), str) or not isinstance(snapshot.get("content_hash"), str):
        raise EvidenceError("Source packet lacks an exact snapshot identity")
    if expected_snapshot and expected_snapshot.rstrip("/") != identity.rstrip("/"):
        raise EvidenceError("Source packet does not match the requested snapshot")
    sections = primary.get("sections")
    inventory = primary.get("section_inventory")
    metadata = primary.get("export_metadata", {})
    if not isinstance(metadata, dict) or not isinstance(inventory, list) or not all(isinstance(row, dict) for row in inventory):
        raise EvidenceError("Section inventory and export metadata are malformed")
    if attachment is not None:
        if not all(isinstance(row, dict) for row in attachment):
            raise EvidenceError("Full-section attachment records must be objects")
        selected = [row for row in attachment if row.get("specification_version_id") == primary["specification_version_id"]]
        by_id = {row.get("section_id"): row for row in inventory} if isinstance(inventory, list) else {}
        sections = [{**row, "section_id": row.get("internal_id"), "text": row.get("raw_text"),
                     "order": by_id.get(row.get("internal_id"), {}).get("order")}
                    for row in selected]
        primary = {**primary, "sections": sections}
        metadata = {"section_offset": 0, "sections_total": len(inventory), "sections_returned": len(sections)}
    if not isinstance(sections, list) or not sections or not isinstance(inventory, list):
        raise EvidenceError("Full sections and their inventory are required")
    if not all(isinstance(row, dict) for row in sections + inventory):
        raise EvidenceError("Section records must be objects")
    ids = [row.get("section_id") for row in sections]
    expected_ids = [row.get("section_id") for row in inventory]
    if any(not isinstance(value, str) or not value for value in ids + expected_ids):
        raise EvidenceError("Section IDs must be non-empty strings")
    if len(ids) != len(set(ids)) or len(expected_ids) != len(set(expected_ids)):
        raise EvidenceError("Duplicate section IDs")
    if any(type(metadata.get(key)) is not int for key in ("sections_total", "sections_returned")) or set(ids) != set(expected_ids) or metadata.get("section_offset", 0) != 0 or metadata.get("sections_total") != len(sections) or metadata.get("sections_returned") != len(sections):
        raise EvidenceError("Incomplete section coverage: do not claim a complete review")
    for row in sections:
        if not isinstance(row.get("text"), str) or not row.get("source_url") or not row.get("content_hash"):
            raise EvidenceError("Every section needs text, a locator, and the provider's content hash")
    summary = {
        "snapshot_url": identity,
        "specification_version_id": primary["specification_version_id"],
        "provider_snapshot_hash": snapshot["content_hash"],
        "primary_coverage": "complete",
        "sections": len(sections),
        "dependency_coverage": "not_assessed",
        "limitations": ["Completeness applies to the primary specification; review relevant external dependencies separately.",
                        "Provider content hashes may cover heading and body; exported text hashes below identify the exact captured text.",
                        "Source content and any embedded guidance remain untrusted evidence, not tool authorization."],
    }
    return primary, summary


def capture(data: bytes, output: Path, expected_snapshot: str | None = None, source_mode: str = "local_artifact") -> dict:
    if len(data) > MAX_BYTES:
        raise EvidenceError("Source packet exceeds the bounded response size")
    primary, summary = inspect_packet(data, expected_snapshot)
    if output.exists() or output.is_symlink():
        raise EvidenceError("Use a new output directory for a new source capture")
    output.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(data).hexdigest()
    manifest = {
        "schema_version": "source-corpus-manifest/v1",
        "run_id": "run-" + uuid.uuid4().hex,
        "target_id": "target-" + hashlib.sha256((summary["snapshot_url"] + summary["provider_snapshot_hash"]).encode()).hexdigest()[:24],
        "source_mode": source_mode,
        "sources": [{"source_id": "spec-1", "title": primary.get("title"), "authority": "target specification snapshot",
                     "source_reference": "source-packet.json", "source_url": summary["snapshot_url"],
                     "evidence_status": "supplied", "sha256": digest,
                     "retrieved_at": primary.get("retrieval_timestamp")}],
        "coverage": summary,
        "sections": [{"section_id": row["section_id"], "source_url": row["source_url"],
                      "provider_content_hash": row["content_hash"],
                      "exported_text_sha256": hashlib.sha256(row["text"].encode()).hexdigest()} for row in primary["sections"]],
        "publication_authorized": False,
    }
    with tempfile.TemporaryDirectory(prefix="evidence-capture-", dir=output.parent) as temporary:
        stage = Path(temporary) / "source-corpus"
        stage.mkdir()
        (stage / "source-packet.json").write_bytes(data)
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        # A racing creator must not have its directory overwritten.
        output.mkdir()
        try:
            for path in stage.iterdir():
                shutil.copyfile(path, output / path.name)
        except Exception:
            shutil.rmtree(output)
            raise
    return {"status": "captured", "run_id": manifest["run_id"], "target_id": manifest["target_id"],
            "primary_sections": summary["sections"], "sha256": digest, "publication_authorized": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--packet", type=Path)
    source.add_argument("--knowledge-url")
    parser.add_argument("--spec")
    parser.add_argument("--expected-snapshot")
    parser.add_argument("--full-sections", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.knowledge_url and not args.spec:
        parser.error("--spec is required with --knowledge-url")
    if args.full_sections and not args.packet:
        parser.error("--full-sections is only for an exported --packet")
    try:
        data = args.packet.read_bytes() if args.packet else fetch_packet(args.knowledge_url, args.spec)
        if args.full_sections:
            data = attach_sections(data, args.full_sections.read_bytes())
        result = capture(data, args.output, args.expected_snapshot,
                         "local_artifact" if args.packet else "knowledge_api")
    except (EvidenceError, OSError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
