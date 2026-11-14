"""Recommend an evidence-scoped Security/Privacy Considerations writing job.

Used by Did We Do A Good Enough Job? and focused security/privacy PR reviews.
A recommendation is not a separate approval gate and does not write the spec.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


def checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"{path.name} must contain a JSON object")
    return payload


def section_text(packet: dict, name: str) -> tuple[str, list[str]]:
    matches = [
        row
        for row in packet.get("sections", [])
        if isinstance(row, dict)
        and ("security" if name == "security" else "privacy")
        in str(row.get("heading", "")).lower()
        and "consideration" in str(row.get("heading", "")).lower()
    ]
    root = [
        row
        for row in matches
        if str(row.get("heading", ""))
        .lower()
        .strip()
        .startswith(name + " considerations")
    ]
    chosen = root if root else matches
    return (
        " ".join(str(row.get("raw_text") or row.get("text") or "") for row in chosen),
        [row["source_url"] for row in chosen if row.get("source_url")],
    )


RELEVANT_CHANGE = re.compile(
    r"(?ix)\b(?:security|privacy|considerations?|permissions?|authori[sz](?:e|ation)|"
    r"authenticat(?:e|ion)|origins?|credentials?|tokens?|cookies?|storage|"
    r"consent|retention|fingerprint(?:ing)?|linkability|encryption|"
    r"secure\s+contexts?|user\s+activation|"
    r"data\s+(?:flow|processing|sharing|disclosure)|position|geolocation)\b"
)
GAP_STATUSES = {"missing", "partially_covered", "misplaced", "unclear"}
COVERED_STATUSES = {"covered", "not_applicable"}


def changed_relevant_sections(changed: list[str]) -> bool:
    """Match words in the actual PR change, never origin inside 'original'."""
    return any(RELEVANT_CHANGE.search(str(value)) for value in changed)


def relevant_diff_lines(path: Path) -> list[str]:
    if path.stat().st_size > 2_000_000:
        raise ValueError("PR diff exceeds the bounded 2 MB review limit")
    return [
        line[1:]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    ]


def delta_summary(value: list[dict] | None) -> tuple[bool | None, list[str]]:
    """Use the D2D Section 7 comparison when present, not text length."""
    if value is None:
        return None, []
    if not isinstance(value, list):
        raise TypeError("considerations deltas must be an array")
    gap_ids = []
    known = []
    for i, record in enumerate(value):
        if not isinstance(record, dict):
            raise TypeError("considerations delta must be a record")
        state = (
            str(
                record.get("delta")
                or record.get("status")
                or record.get("disposition")
                or ""
            )
            .strip()
            .lower()
        )
        known.append(state)
        if state in GAP_STATUSES:
            gap_ids.append(
                str(record.get("id") or record.get("threat_id") or f"row-{i}")
            )
    if gap_ids:
        return True, gap_ids
    if known and all(state in COVERED_STATUSES for state in known):
        return False, []
    return None, []


def recommend(
    model_path: Path,
    packet_path: Path,
    threats_path: Path,
    responses_path: Path,
    kind: str = "d2d",
    changed: list[str] | None = None,
    considerations_deltas: list[dict] | None = None,
) -> dict:
    if kind not in {"d2d", "pr"}:
        raise ValueError("review kind must be d2d or pr")
    model = read(model_path)
    packet = read(packet_path)
    threats = read(threats_path)
    responses = read(responses_path)
    snapshot = packet.get("snapshot_identity", {}).get("immutable_url")
    if not isinstance(snapshot, str) or not snapshot.startswith("https://"):
        raise ValueError("exact versioned specification snapshot is required")
    if not any(
        isinstance(row, dict)
        and str(row.get("source_reference", "")).rstrip("/") == snapshot.rstrip("/")
        for row in model.get("source_inventory", [])
    ):
        raise ValueError("source packet and model target do not match")
    for artifact in (threats, responses):
        if artifact.get("model_id") != model.get("model_id"):
            raise ValueError("threat or response model identity mismatch")
        if artifact.get("run_id") != model.get("run_id"):
            raise ValueError("threat or response run identity mismatch")
    if responses.get("threat_package_id") != threats.get("threat_package_id"):
        raise ValueError("responses refer to a different threat package")
    th = threats.get("threats", [])
    resp = responses.get("responses", [])
    if not isinstance(th, list) or not isinstance(resp, list):
        raise TypeError("invalid threats/responses lists")
    by_response = {row.get("threat_id"): row for row in resp}
    if len(by_response) != len(resp):
        raise ValueError("duplicate response linkage")
    security, security_urls = section_text(packet, "security")
    privacy, privacy_urls = section_text(packet, "privacy")
    security_present = bool(security.strip())
    privacy_present = bool(privacy.strip())
    security_empty_claim = bool(
        re.search(
            r"\bno\s+(?:specific\s+)?security considerations\b", security, re.IGNORECASE
        )
    )
    visible_threats = sorted(
        {
            row.get("threat_id")
            for row in th
            if isinstance(row, dict) and isinstance(row.get("threat_id"), str)
        }
    )
    has_security_model = any(
        "security" in str(row.get("violated_property_or_interest", "")).lower()
        or "authorization" in str(row.get("violated_property_or_interest", "")).lower()
        or "confidentiality"
        in str(row.get("violated_property_or_interest", "")).lower()
        or "integrity" in str(row.get("violated_property_or_interest", "")).lower()
        for row in th
        if isinstance(row, dict)
    )
    security_action = (
        "propose_security_considerations"
        if not security_present or security_empty_claim
        else "compare_and_update_security_considerations"
    )
    privacy_action = (
        "propose_privacy_considerations"
        if not privacy_present
        else "compare_existing_privacy_considerations_and_preserve_covered_content"
    )
    change_areas = changed or []
    targeted = changed_relevant_sections(change_areas)
    documented_gap = (
        (not security_present or security_empty_claim) and bool(visible_threats)
    ) or (not privacy_present and bool(visible_threats))
    delta_recommendation, missing_delta_ids = delta_summary(considerations_deltas)
    applicable = (
        targeted
        if kind == "pr"
        else documented_gap
        if delta_recommendation is None
        else delta_recommendation
    )
    if kind == "pr" and not targeted:
        next_action = "no_auto_dispatch_outside_security_privacy_scope"
    elif applicable:
        next_action = "propose_writer_job"
    else:
        next_action = "assess_existing_considerations_coverage"
    reasons = []
    if not security_present:
        reasons.append("Security Considerations absent from retrieved source sections")
    if security_empty_claim and visible_threats:
        reasons.append(
            "Security section states no considerations while the model contains conditional bad events"
        )
    if has_security_model:
        reasons.append(
            "Review model links authorization/integrity/confidentiality concerns to target mechanisms"
        )
    if not privacy_present:
        reasons.append("Privacy Considerations absent from retrieved source sections")
    else:
        reasons.append(
            "Preserve existing Privacy Considerations; evaluate only material gaps and new risks"
        )
    if kind == "pr" and targeted:
        reasons.append("PR scope touches security/privacy-relevant text or controls")
    if missing_delta_ids:
        reasons.append(
            "D2D Section 7 identified uncovered Considerations deltas: "
            + ", ".join(missing_delta_ids)
        )
    paths = {
        "model_sha256": checksum(model_path),
        "source_packet_sha256": checksum(packet_path),
        "threats_sha256": checksum(threats_path),
        "responses_sha256": checksum(responses_path),
    }
    return {
        "schema_version": "considerations-authoring-proposal/v1",
        "stage": "did-we-do-a-good-enough-job"
        if kind == "d2d"
        else "w3c-issue-pr-review",
        "review_kind": kind,
        "target_snapshot": snapshot,
        "model_id": model.get("model_id"),
        "run_id": model.get("run_id"),
        "propose_authoring": applicable,
        "decision": next_action,
        "source_sections": {
            "security": security_urls,
            "privacy": privacy_urls,
        },
        "security_action": security_action if applicable else "not_requested",
        "privacy_action": privacy_action if applicable else "not_requested",
        "writer_job": {
            "skill_id": "write-considerations",
            "dispatch": "proposed_for_current_review",
            "run_only_if_requested_in_review_scope": True,
            "inputs": [
                "model-packet/v1",
                "source-corpus/v1",
                "threat-package/v1",
                "response-package/v1",
            ],
            "outputs": [
                "considerations.md",
                "minimal-edit.md",
                "editorial-evidence.json",
                "editorial-qa.json",
            ],
            "style": "FedCM thematic threat-response-enforcement-residual",
        }
        if applicable
        else None,
        "threat_ids_considered": visible_threats,
        "response_coverage": len(
            [tid for tid in visible_threats if tid in by_response]
        ),
        "reasoning": reasons,
        "changed_areas": change_areas,
        "uncovered_considerations_delta_ids": missing_delta_ids,
        "inputs_sha256": paths,
        "automatic_remote_edit": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--source-packet", type=Path, required=True)
    parser.add_argument("--threats", type=Path, required=True)
    parser.add_argument("--responses", type=Path, required=True)
    parser.add_argument("--kind", choices=("d2d", "pr"), default="d2d")
    parser.add_argument("--changed-area", action="append", default=[])
    parser.add_argument("--diff-file", type=Path, help="Bounded actual PR diff text")
    parser.add_argument(
        "--delta-ledger", type=Path, help="D2D Section 7 considerations delta JSON"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        areas = list(args.changed_area)
        if args.diff_file:
            areas.extend(relevant_diff_lines(args.diff_file))
        deltas = None
        if args.delta_ledger:
            document = read(args.delta_ledger)
            deltas = document.get("deltas", document.get("rows"))
        result = recommend(
            args.model,
            args.source_packet,
            args.threats,
            args.responses,
            args.kind,
            areas,
            deltas,
        )
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("refusing to overwrite an existing authoring proposal")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        print(
            json.dumps(
                {
                    "status": "proposed"
                    if result["propose_authoring"]
                    else "not_applicable",
                    "target": result["target_snapshot"],
                    "decision": result["decision"],
                    "output": str(args.output),
                }
            )
        )
        return 0
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "invalid", "error": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
