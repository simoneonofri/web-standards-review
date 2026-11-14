#!/usr/bin/env python3
"""Offline, fail-closed preflight for issue/review/threat-model workflows.

Uses the monorepo's portable review-question cache, not its original miner
engines. Never claims cached candidate questions are executed miner analyses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from query_miner_cache import inspect

KINDS = ("issue", "review", "threat-model")
DOMAINS = (
    "security",
    "privacy",
    "design",
    "accessibility",
    "internationalization",
    "harms",
    "human-rights",
)
SCOPES = ("editorial", "charter", "combined", *DOMAINS)
ALIASES = {
    "a11y": "accessibility",
    "i18n": "internationalization",
    "tag": "design",
    "human_rights": "human-rights",
    "humanrights": "human-rights",
}
THREAT_DOMAINS = {"security", "privacy", "harms", "human-rights"}
SOURCE_MINERS = (
    "w3c-webappsec-miner",
    "whatwg-miner",
    "w3c-spec-miner",
    "w3c-horizontal-review-patterns-miner",
    "w3c-security-pattern-miner",
    "standards-vulnerability-intel-miner",
)


def digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def select_domains(scope: str, requested: str | None = None) -> list[str]:
    if scope not in SCOPES:
        raise ValueError("unsupported review scope")
    if scope in {"editorial", "charter"}:
        if requested:
            raise ValueError("non-specification scope has no domain selection")
        return []
    if not requested:
        return list(DOMAINS) if scope == "combined" else [scope]
    selected = [
        ALIASES.get(d.strip().lower(), d.strip().lower()) for d in requested.split(",")
    ]
    if not selected or any(d not in DOMAINS for d in selected):
        raise ValueError("unsupported domain; sustainability is not enabled")
    if len(selected) != len(set(selected)):
        raise ValueError("duplicate review domain")
    if scope != "combined" and selected != [scope]:
        raise ValueError("multiple domains require --scope combined")
    return selected


def source_identity(packet: dict) -> dict:
    if not isinstance(packet, dict):
        raise TypeError("source packet must be a JSON object")
    identity = packet.get("snapshot_identity") or {}
    sections = packet.get("sections")
    metadata = packet.get("export_metadata") or {}
    version = packet.get("specification_version_id")
    target = packet.get("specification_id")
    uri = identity.get("immutable_url")
    source_hash = identity.get("content_hash")
    if not (
        str(packet.get("source_packet_contract_version")) == "1"
        and isinstance(version, str)
        and version
        and isinstance(target, str)
        and target
        and isinstance(uri, str)
        and uri.startswith("https://")
        and isinstance(source_hash, str)
        and re.fullmatch(r"[a-f0-9]{64}", source_hash)
        and isinstance(sections, list)
        and sections
    ):
        raise ValueError("incomplete or unversioned source packet")
    if metadata and (
        metadata.get("sections_total") != len(sections)
        or metadata.get("sections_returned") != len(sections)
        or metadata.get("section_offset") != 0
    ):
        raise ValueError("partial source packet; cannot claim exact coverage")
    all_ids = set()
    for part in sections:
        if not isinstance(part, dict):
            raise TypeError("invalid source section")
        if not (
            part.get("section_id")
            and part.get("content_hash")
            and isinstance(part.get("source_url"), str)
            and part["source_url"].startswith(uri + "#")
        ):
            raise ValueError("section is unversioned or missing source reference")
        if part["section_id"] in all_ids:
            raise ValueError("duplicate source section")
        all_ids.add(part["section_id"])
    inventory = packet.get("section_inventory")
    if isinstance(inventory, list):
        source_ids = {row.get("section_id") for row in inventory}
        if not all_ids.issubset(source_ids):
            raise ValueError("missing section inventory entries")
        if any(
            row.get("normative") is True and row.get("section_id") not in all_ids
            for row in inventory
        ):
            raise ValueError("normative source sections omitted from packet")
        nonnorm = sum(row.get("section_id") not in all_ids for row in inventory)
    else:
        nonnorm = None
    return {
        "specification_id": target,
        "specification_version_id": version,
        "immutable_url": uri,
        "content_sha256": source_hash,
        "section_count": len(sections),
        "non_normative_missing_count": nonnorm,
    }


def run_gate(
    kind: str,
    scope: str,
    rows: list[dict],
    manifest: dict,
    archive_sha: str,
    packet: dict | None = None,
    reason: str | None = None,
    domains_text: str | None = None,
    query: str = "",
    limit: int = 100,
) -> tuple[dict, dict, dict]:
    if kind not in KINDS:
        raise ValueError("unsupported workflow kind")
    domains = select_domains(scope, domains_text)
    receipt = {
        "schema_version": "web-standards-review-miner-gate/v1",
        "execution_mode": "offline_cache_preflight_only",
        "created_at": datetime.now(UTC).isoformat(),
        "workflow_kind": kind,
        "scope": scope,
        "domains": domains,
        "cache": {
            "schema_version": manifest["schema_version"],
            "sha256": archive_sha,
            "catalog_version": manifest.get("catalog_version"),
            "records": manifest["records"],
        },
        "miner_ledger": [],
        "target": None,
        "limitations": [
            "A cache lookup is not a live miner invocation, a completed review, or W3C consensus.",
            "Every applicable check remains not_evaluated.",
            "Threat prompts must be attached to a model element with source evidence.",
        ],
    }
    if scope in {"editorial", "charter"}:
        if not reason or not reason.strip() or packet is not None:
            raise ValueError(
                "editorial or charter routing requires a reason and no source packet"
            )
        if scope == "editorial" and kind != "issue":
            raise ValueError("editorial exception applies only to issue/PR triage")
        receipt["status"] = (
            "not_applicable" if scope == "editorial" else "needs_specialist"
        )
        receipt["reason"] = reason.strip()
        if scope == "charter":
            receipt["required_specialist"] = "strategy-charter-miner"
            receipt["limitations"].append(
                "Run the charter specialist and check five-domain status separately."
            )
        return receipt, {"checks": []}, {"items": []}
    if packet is None:
        raise ValueError(
            "substantive specification review requires a pinned source packet"
        )
    receipt["target"] = source_identity(packet)
    selected = [r for r in rows if r["domain"] in domains]
    tokens = {x for x in re.findall(r"[a-z0-9]{3,}", query.lower())}
    ranked = sorted(
        selected,
        key=lambda r: (
            -sum(
                w
                in (r["question"] + " " + r["title"] + " " + r["applicability"]).lower()
                for w in tokens
            ),
            r["id"],
        ),
    )
    selected = ranked[:limit]
    selected_ids = {r["id"] for r in selected}
    checks = []
    threats = []
    for row in selected:
        payload = {
            "id": row["id"],
            "domain": row["domain"],
            "kind": row["kind"],
            "question": row["question"],
            "applicability": row["applicability"],
            "source_url": row["source_url"],
            "authority": row["authority"],
            "source_mode": "portable_cache",
            "cache_sha256": archive_sha,
        }
        if row["domain"] in THREAT_DOMAINS and row["kind"] == "reference-only":
            threats.append(
                {
                    **payload,
                    "queue_status": "pending_model_attachment",
                    "model_elements": [],
                    "threat_story": None,
                }
            )
        else:
            checks.append(
                {
                    **payload,
                    "status": "not_evaluated",
                    "target_evidence": [],
                    "disposition_rationale": "Target-specific applicability has not been evaluated.",
                }
            )
    for miner in SOURCE_MINERS:
        availability = any(r["skill"] == miner for r in rows)
        receipt["miner_ledger"].append(
            {
                "miner": miner,
                "state": "cache_hit" if availability else "unavailable",
                "selected": sum(
                    r["skill"] == miner and r["id"] in selected_ids for r in selected
                ),
                "source_mode": "portable_cache" if availability else "not_bundled",
                "live_miner_executed": False,
            }
        )
    reference_only = any(r["kind"] == "reference-only" for r in selected)
    explicit_unbundled = bool(
        {"harms", "human-rights", "accessibility", "internationalization"}
        & set(domains)
    )
    incomplete = (
        reference_only
        or explicit_unbundled
        or any(d in {"security", "privacy"} for d in domains)
        and not any(r["skill"] == "standards-vulnerability-intel-miner" for r in rows)
    )
    receipt["status"] = "partial" if incomplete else "preflight_ready"
    receipt["checks"] = {"count": len(checks), "all_not_evaluated": True}
    receipt["threat_queue"] = {"count": len(threats), "pending": len(threats)}
    receipt["limitations"].append(
        "Specialist domain sources or query-specific vulnerability intelligence are not bundled."
        if incomplete
        else "Only the portable catalog question selection has been completed."
    )
    return receipt, {"checks": checks}, {"items": threats}


def persist(output: Path, receipt: dict, checks: dict, queue: dict) -> dict:
    if output.is_symlink():
        raise ValueError("symlink output directory refused")
    output.mkdir(parents=True, exist_ok=True)
    artifacts = {}
    for name, content in (("checks.json", checks), ("threat-queue.json", queue)):
        path = output / name
        if path.is_symlink():
            raise ValueError("symlink output file refused")
        blob = (
            json.dumps(content, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode()
        path.write_bytes(blob)
        artifacts[name] = {"sha256": digest(blob), "bytes": len(blob)}
    receipt["artifacts"] = artifacts
    path = output / "miner-gate.json"
    if path.is_symlink():
        raise ValueError("symlink receipt refused")
    path.write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--source-packet", type=Path)
    parser.add_argument("--kind", choices=KINDS, required=True)
    parser.add_argument("--scope", choices=SCOPES, required=True)
    parser.add_argument(
        "--domains", help="Comma-separated domains for --scope combined"
    )
    parser.add_argument("--reason", help="Required for editorial and charter routing")
    parser.add_argument("--query", default="")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.limit <= 2000:
        parser.error("limit must be 1..2000")
    try:
        rows, manifest = inspect(args.cache)
        packet = (
            json.loads(args.source_packet.read_text()) if args.source_packet else None
        )
        receipt, checks, queue = run_gate(
            args.kind,
            args.scope,
            rows,
            manifest,
            digest(args.cache.read_bytes()),
            packet,
            args.reason,
            args.domains,
            args.query,
            args.limit,
        )
        persist(args.output_dir, receipt, checks, queue)
        print(
            json.dumps(
                {
                    "status": receipt["status"],
                    "receipt": str(args.output_dir / "miner-gate.json"),
                    "checks": len(checks["checks"]),
                    "threat_prompts": len(queue["items"]),
                }
            )
        )
        return 0 if receipt["status"] in ("preflight_ready", "not_applicable") else 2
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
