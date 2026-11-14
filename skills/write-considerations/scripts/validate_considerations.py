"""Validate traceability of a draft Security and Privacy Considerations file.

This validator is a structural/evidence-gate only; it never approves
publication, implementer behavior, or W3C consensus.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from draft_considerations import SCHEMA, classify, load, validate_identity


def digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def check(
    draft: Path,
    ledger_path: Path,
    model_path: Path,
    threats_path: Path,
    responses_path: Path,
    source_path: Path,
) -> dict:
    text = draft.read_text(encoding="utf-8")
    ledger = load(ledger_path)
    model = load(model_path)
    threats = load(threats_path)
    responses = load(responses_path)
    source = load(source_path)
    errors = []
    snapshot, pairs = validate_identity(model, threats, responses, source)
    if ledger.get("schema_version") != SCHEMA:
        errors.append("unsupported evidence ledger contract")
    for key, expected in {
        "model_id": model["model_id"],
        "threat_package_id": threats["threat_package_id"],
        "response_package_id": responses["response_package_id"],
        "source_snapshot": snapshot,
        "source_manifest_sha256": digest(source_path.read_bytes()),
        "model_sha256": digest(model_path.read_bytes()),
        "threats_sha256": digest(threats_path.read_bytes()),
        "responses_sha256": digest(responses_path.read_bytes()),
        "draft_sha256": digest(draft.read_bytes()),
    }.items():
        if ledger.get(key) != expected:
            errors.append(f"{key}: identity or content digest mismatch")
    if ledger.get("publication_authorized") is not False:
        errors.append("the editor must not mark a draft publication-authorized")
    if (
        "## Security Considerations" not in text
        or "## Privacy Considerations" not in text
    ):
        errors.append("both distinct Considerations sections are mandatory")
    if "Remaining threat:" not in text and "Residual" not in text:
        errors.append("draft has no residual threat discussion")
    if "enforcement" not in text.lower() and "responsible actor" not in text.lower():
        errors.append("draft does not identify enforcement responsibilities")
    if "not normative" not in text.lower() and "not been verified" not in text.lower():
        errors.append("draft does not distinguish proposal from normative requirement")

    entries = ledger.get("entries")
    if not isinstance(entries, list):
        errors.append("ledger.entries must be a list")
        entries = []
    expected = {
        (t["threat_id"], r["response_id"], section)
        for t, r in pairs
        for section in classify(t)
    }
    actual = [
        (x.get("threat_id"), x.get("response_id"), x.get("section"))
        for x in entries
        if isinstance(x, dict)
    ]
    if len(actual) != len(entries) or len(actual) != len(set(actual)):
        errors.append("ledger contains duplicate or malformed entries")
    if set(actual) != expected:
        errors.append(
            "ledger does not cover every threat/response and applicable section"
        )
    by_threat = {t["threat_id"]: (t, r) for t, r in pairs}
    for i, row in enumerate(entries):
        if not isinstance(row, dict):
            continue
        tid = row.get("threat_id")
        if tid not in by_threat:
            errors.append(f"entry {i}: unknown threat ID")
            continue
        _threat, r = by_threat[tid]
        if row.get("erta") != r["erta"] or row.get("response_id") != r["response_id"]:
            errors.append(f"entry {i}: ERTA/response identity mismatch")
        if (
            row.get("mechanism")
            != str(r.get("mechanism_or_text") or r.get("response") or "").strip()
        ):
            errors.append(f"entry {i}: response mechanism differs from source response")
        if (
            row.get("owner")
            != str(r.get("owner") or "responsible actor not yet identified").strip()
        ):
            errors.append(f"entry {i}: owner differs from the response package")
        if row.get("next_action") != str(r["next_action"]).strip():
            errors.append(f"entry {i}: testable follow-up was lost")
        if row.get("normative_enforcement_verified") is not False:
            errors.append(
                f"entry {i}: cannot infer normative enforcement from a threat source locator"
            )
        if (
            row.get("publication_status")
            != "draft_requires_editorial_and_source_review"
        ):
            errors.append(
                f"entry {i}: draft publication status was prematurely elevated"
            )
        marker = f"<!-- threat:{tid} response:{r['response_id']} -->"
        if text.count(marker) != sum(
            x[0] == tid and x[1] == r["response_id"] for x in actual
        ):
            errors.append(f"entry {i}: prose markers absent or repeated")
        source_url = row.get("source_url") or ""
        if source_url and not source_url.startswith(snapshot.rstrip("/") + "/#"):
            errors.append(f"entry {i}: source URL is not in the pinned snapshot")
    return {
        "schema_version": "considerations-draft-validation/v1",
        "status": "traceable_draft_not_publication_ready" if not errors else "blocked",
        "valid": not errors,
        "publication_authorized": False,
        "source_snapshot": snapshot,
        "threats": len(pairs),
        "ledger_rows": len(entries),
        "section_coverage": dict(
            Counter(row.get("section") for row in entries if isinstance(row, dict))
        ),
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("draft", "ledger", "model", "threats", "responses", "source-manifest"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        result = check(
            args.draft,
            args.ledger,
            args.model,
            args.threats,
            args.responses,
            args.source_manifest,
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "status": "blocked", "error": str(exc)}))
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
