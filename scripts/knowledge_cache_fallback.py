#!/usr/bin/env python3
"""Use both bundled knowledge caches when W3C Knowledge is unavailable.

Never treats a catalog hit as an executed miner or threat finding. Requires
the user's complete, version-pinned specification source packet; this cache
does not replace W3C specification text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from query_miner_cache import inspect as inspect_miner_cache
from query_threat_knowledge_cache import load as inspect_threat_cache
from reconcile_specification_knowledge import prepare as prepare_knowledge
from review_miner_gate import persist, run_gate

ROOT = Path(__file__).resolve().parents[1]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def service_status(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.port is None
    ):
        raise ValueError("Only a local W3C Knowledge HTTP service can be probed")
    req = urllib.request.Request(url.rstrip("/") + "/openapi.json")
    try:
        with urllib.request.urlopen(req, timeout=2) as response:
            return "available" if response.status == 200 else "unavailable"
    except (OSError, urllib.error.URLError, TimeoutError):
        return "unavailable"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-packet", type=Path, required=True)
    parser.add_argument(
        "--model",
        type=Path,
        help="Accepted source-linked model enables all three knowledge passes",
    )
    parser.add_argument("--domains", default="security,privacy")
    parser.add_argument("--mode", choices=("full", "baseline"), default="full")
    parser.add_argument("--per-source", type=int, default=6)
    parser.add_argument(
        "--miner-cache", type=Path, default=ROOT / "cache/miner-knowledge-v1.zip"
    )
    parser.add_argument(
        "--threat-cache", type=Path, default=ROOT / "cache/threat-knowledge-v1.zip"
    )
    parser.add_argument("--knowledge-url", help="Optional explicit local W3C Knowledge endpoint")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output_dir.exists() or args.output_dir.is_symlink():
            raise ValueError("output directory exists; use a fresh run directory")
        miner_rows, miner_manifest = inspect_miner_cache(args.miner_cache)
        threat_rows, threat_manifest = inspect_threat_cache(args.threat_cache)
        if not miner_rows or not threat_rows:
            raise ValueError("both knowledge caches are required")
        state = service_status(args.knowledge_url) if args.knowledge_url else "not_probed"
        domains = [x.strip() for x in args.domains.split(",") if x.strip()]
        if args.model:
            result = prepare_knowledge(
                args.model,
                args.source_packet,
                args.miner_cache,
                args.domains,
                args.per_source,
                args.output_dir,
                args.mode,
                args.threat_cache,
            )
            cache_state = "selected_requires_target_disposition"
        else:
            packet = json.loads(args.source_packet.read_text())
            receipt, checks, queue = run_gate(
                "review",
                "combined",
                miner_rows,
                miner_manifest,
                sha(args.miner_cache),
                packet,
                None,
                args.domains,
                "",
                100,
            )
            persist(args.output_dir, receipt, checks, queue)
            result = {
                "receipt": str(args.output_dir / "miner-gate.json"),
                "checks": len(checks["checks"]),
                "pending_threat_prompts": len(queue["items"]),
            }
            cache_state = "preflight_not_evaluated"
        summary = {
            "schema_version": "portable-knowledge-fallback/v1",
            "w3c_knowledge_service": state,
            "source_mode": "caller_pinned_specification_packet",
            "miner_cache_sha256": sha(args.miner_cache),
            "threat_cache_sha256": sha(args.threat_cache),
            "miner_records": len(miner_rows),
            "threat_records": len(threat_rows),
            "miner_schema": miner_manifest["schema_version"],
            "threat_schema": threat_manifest["schema_version"],
            "domains": domains,
            "selection_status": cache_state,
            "live_miners_executed": False,
            "target_threat_model_complete": False,
            "result": result,
        }
        receipt_path = args.output_dir / "offline-fallback-receipt.json"
        receipt_path.write_text(json.dumps(summary, indent=2) + "\n")
        print(
            json.dumps(
                {
                    "status": "cache_fallback_ready",
                    "w3c_knowledge_service": state,
                    "miner_records": len(miner_rows),
                    "threat_records": len(threat_rows),
                    "selection_status": cache_state,
                    "receipt": str(receipt_path),
                }
            )
        )
        return 0
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        urllib.error.URLError,
        zipfile.BadZipFile,
    ) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
