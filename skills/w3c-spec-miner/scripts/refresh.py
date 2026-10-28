#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from mine import aggregate_catalog, load_patterns, mine_specification, render_catalog_markdown, sha256_json  # noqa: E402
sys.path.insert(0, str(ROOT.parents[1] / "tools/reviewctl"))
from evidence import EvidenceError, fetch_packet as fetch_full_packet, inspect_packet


STATUSES = {"REC", "CR", "CRD", "WD"}


def fetch_json(url: str, timeout: float = 90.0) -> Any:
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "w3c-spec-miner/1.0 local-corpus-refresh"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def fetch_packet(api_url: str, specification: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None, str | None]:
    identifier = urllib.parse.quote(specification["internal_id"], safe="")
    try:
        packet, coverage = inspect_packet(fetch_full_packet(api_url, specification["internal_id"]))
        packet["portable_primary_coverage"] = coverage
        return specification, packet, None
    except (OSError, urllib.error.HTTPError, json.JSONDecodeError, EvidenceError) as exc:
        return specification, None, str(exc)


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, values: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for value in values:
            handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def artifact_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--minimum-coverage", type=float, default=0.95)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink() or args.output.resolve().is_relative_to(ROOT.parents[1]):
        parser.error("Use a new output directory outside the package")
    if not 1 <= args.workers <= 8 or not 0 < args.minimum_coverage <= 1:
        parser.error("Use 1..8 workers and a coverage threshold in (0, 1]")
    api_url = args.api_url.rstrip("/")
    patterns = load_patterns(ROOT / "references" / "pattern-definitions.json")
    inventory_all = fetch_json(f"{api_url}/api/v1/specifications?limit=100000")
    inventory = sorted((item for item in inventory_all if item.get("publication_status") in STATUSES), key=lambda item: (item["shortname"], item["internal_id"]))
    corpus = {
        "api_url": api_url,
        "retrieved_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "statuses": sorted(STATUSES),
        "inventory_count": len(inventory),
        "inventory_sha256": sha256_json(inventory),
    }
    observations: list[dict[str, Any]] = []
    models: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    empty_packets = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(fetch_packet, api_url, specification) for specification in inventory]
        for future in concurrent.futures.as_completed(futures):
            specification, packet, error = future.result()
            if error or packet is None:
                failures.append({"internal_id": specification["internal_id"], "shortname": specification["shortname"], "error": error})
                continue
            if not packet.get("sections"):
                empty_packets += 1
            result = mine_specification(specification, packet, patterns)
            models.append(result.model)
            observations.extend(result.observations)
            gaps.extend(result.gaps)
    observations.sort(key=lambda item: (item["shortname"], item["pattern_id"], str(item["source_url"])))
    models.sort(key=lambda item: (item["shortname"], item["specification_id"]))
    gaps.sort(key=lambda item: (item["shortname"], item["pattern_id"]))
    failures.sort(key=lambda item: (item["shortname"], item["internal_id"]))
    successful = len(models)
    coverage_ratio = successful / len(inventory) if inventory else 0.0
    corpus.update({"successful_packets": successful, "failed_packets": len(failures), "empty_section_packets": empty_packets, "coverage_ratio": coverage_ratio})
    args.output.mkdir(parents=True, exist_ok=True)
    catalog = aggregate_catalog(patterns, observations, corpus)
    write_json(args.output / "protection-catalog.json", catalog)
    write_jsonl(args.output / "protection-observations.jsonl", observations)
    write_jsonl(args.output / "threat-models.jsonl", models)
    write_jsonl(args.output / "security-considerations-gaps.jsonl", gaps)
    write_json(args.output / "refresh-failures.json", failures)
    coverage = {
        "schema_version": 1,
        **corpus,
        "specifications_with_security_considerations": sum(bool(model["security_considerations_present"]) for model in models),
        "specifications_with_observed_protections": sum(bool(model["observed_protections"]) for model in models),
        "observation_count": len(observations),
        "editorial_gap_count": len(gaps),
    }
    (args.output / "protection-catalog.md").write_text(render_catalog_markdown(catalog, coverage), encoding="utf-8")
    write_json(args.output / "coverage.json", coverage)
    artifacts = [args.output / name for name in ("protection-catalog.json", "protection-catalog.md", "protection-observations.jsonl", "threat-models.jsonl", "security-considerations-gaps.jsonl", "refresh-failures.json")]
    coverage["artifact_sha256"] = {path.name: artifact_hash(path) for path in artifacts}
    write_json(args.output / "coverage.json", coverage)
    print(json.dumps({"inventory": len(inventory), "successful": successful, "failures": len(failures), "observations": len(observations), "editorial_gaps": len(gaps), "coverage_ratio": coverage_ratio}, sort_keys=True))
    return 0 if inventory and coverage_ratio >= args.minimum_coverage else 1


if __name__ == "__main__":
    raise SystemExit(main())
