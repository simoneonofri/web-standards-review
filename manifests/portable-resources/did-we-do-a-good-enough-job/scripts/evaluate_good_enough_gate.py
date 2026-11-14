"""Evaluate the independent-review gate without hiding partial or blocked work."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

PASS_STATUSES = {"pass", "complete"}
PARTIAL_STATUSES = {"partial", "fail", "failed", "draft", "incomplete"}
BLOCKED_STATUSES = {"blocked", "missing", "unavailable"}
BASE_REQUIRED_GATE_ALIASES = {
    "source_corpus": {
        "source_corpus",
        "source_identity",
        "source_corpus_and_source_identity",
    },
    "model_packet": {
        "model_packet",
        "model_source_coverage",
        "model_packet_and_source_coverage",
    },
    "dfd_representation": {
        "dfd_representation",
        "dfd_representation_and_complete_dictionary",
        "dfd_complete_dictionary",
    },
    "baseline_elicitation": {
        "baseline_elicitation",
        "baseline_threat_elicitation",
        "baseline",
    },
    "response_mapping": {"response_mapping", "responses"},
}


def _normalize_name(value: Any) -> str:
    return (
        str(value or "")
        .strip()
        .lower()
        .replace("-", " ")
        .replace("_", " ")
        .replace(" ", "_")
    )


def _normalize_status(value: Any) -> str:
    return str(value or "").strip().lower()


def _id_list(coverage: dict[str, Any], key: str) -> tuple[list[str], str | None]:
    if key not in coverage:
        return [], f"missing coverage field: {key}"
    value = coverage[key]
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        return [], f"coverage field {key} must be a list of non-empty IDs"
    ids = [item.strip() for item in value]
    if len(ids) != len(set(ids)):
        return ids, f"coverage field {key} contains duplicate IDs"
    return ids, None


def evaluate(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a fail-closed independent-review gate result."""

    run_scope = _normalize_name(payload.get("run_scope") or "additional")
    baseline_only = run_scope in {"baseline", "baseline_only", "as_is", "as_is_only"}
    required_gate_aliases = dict(BASE_REQUIRED_GATE_ALIASES)
    if run_scope not in {"baseline", "baseline_only", "as_is", "as_is_only"}:
        required_gate_aliases["additional_elicitation_reconciliation"] = {
            "additional_elicitation_reconciliation",
            "additional_elicitation_and_reconciliation",
        }

    requires_knowledge = (
        payload.get("target_kind") in {"specification", "web_specification"}
        or payload.get("require_dual_knowledge") is True
    )
    if requires_knowledge:
        required_gate_aliases["knowledge_reconciliation"] = {
            "knowledge_reconciliation",
            "miner_threat_knowledge_reconciliation",
        }

    supplied_gates = payload.get("gates")
    checks: list[dict[str, Any]] = []
    blocking_reasons: list[str] = []
    partial_reasons: list[str] = []
    by_name: dict[str, dict[str, Any]] = {}
    if not isinstance(supplied_gates, list):
        blocking_reasons.append("gates must be a list")
        supplied_gates = []
    for gate in supplied_gates:
        if not isinstance(gate, dict):
            partial_reasons.append("gate row must be an object")
            continue
        name = _normalize_name(gate.get("name") or gate.get("gate"))
        status = _normalize_status(gate.get("status"))
        if name:
            by_name[name] = gate
        checks.append({"name": name or "unnamed", "status": status or "missing"})
        if status in BLOCKED_STATUSES:
            blocking_reasons.append(f"{name or 'unnamed'} gate is {status}")
        elif status not in PASS_STATUSES:
            partial_reasons.append(f"{name or 'unnamed'} gate is {status or 'missing'}")
    missing_gates = sorted(
        canonical
        for canonical, aliases in required_gate_aliases.items()
        if not (aliases & set(by_name))
    )
    if missing_gates:
        blocking_reasons.append(f"missing required upstream gates: {missing_gates}")

    if requires_knowledge:
        receipt = payload.get("knowledge_reconciliation")
        if not isinstance(receipt, dict) or receipt.get("status") != "pass":
            blocking_reasons.append(
                "specification reviews require a passing, verified "
                "Miner Knowledge + Threat Knowledge reconciliation receipt"
            )
        else:
            required_phases = (
                {"explicit", "implicit"}
                if baseline_only
                else {"explicit", "implicit", "additional"}
            )
            counts = receipt.get("phase_provider_counts")
            if not isinstance(counts, dict):
                blocking_reasons.append(
                    "knowledge reconciliation lacks provider coverage"
                )
            else:
                for phase in required_phases:
                    phase_counts = counts.get(phase, {})
                    if not isinstance(phase_counts, dict) or any(
                        not isinstance(phase_counts.get(provider), int)
                        or phase_counts[provider] <= 0
                        for provider in ("miner_knowledge", "threat_knowledge")
                    ):
                        blocking_reasons.append(
                            f"knowledge reconciliation missing {phase} dispositions "
                            "from both providers"
                        )
            if receipt.get("unresolved_ids") or receipt.get("errors"):
                blocking_reasons.append(
                    "knowledge reconciliation has unresolved or invalid selected items"
                )

    coverage = payload.get("coverage")
    if not isinstance(coverage, dict):
        coverage = {}
        blocking_reasons.append("coverage must be an object")
    coverage_fields = (
        "model_ids",
        "dictionary_ids",
        "baseline_threat_ids",
        "actual_response_threat_ids",
        "additional_threat_ids",
        "new_response_threat_ids",
    )
    values: dict[str, list[str]] = {}
    for field in coverage_fields:
        if (
            baseline_only
            and field in {"additional_threat_ids", "new_response_threat_ids"}
            and field not in coverage
        ):
            values[field] = []
            continue
        values[field], error = _id_list(coverage, field)
        if error:
            blocking_reasons.append(error)

    set_checks = (
        ("dictionary_model_set_equality", "dictionary_ids", "model_ids"),
        (
            "actual_response_baseline_coverage",
            "actual_response_threat_ids",
            "baseline_threat_ids",
        ),
        (
            "new_response_additional_coverage",
            "new_response_threat_ids",
            "additional_threat_ids",
        ),
    )
    for name, left_key, right_key in set_checks:
        left = set(values[left_key])
        right = set(values[right_key])
        passed = left == right
        checks.append(
            {
                "name": name,
                "status": "pass" if passed else "fail",
                "missing": sorted(right - left),
                "extra": sorted(left - right),
            }
        )
        if not passed:
            partial_reasons.append(
                f"{name} mismatch: missing={sorted(right - left)}, extra={sorted(left - right)}"
            )

    if blocking_reasons:
        status = "blocked"
    elif partial_reasons:
        status = "partial"
    else:
        status = "pass"
    return {
        "schema_version": "independent-review-gate/v1",
        "gate": "independent_review",
        "status": status,
        "checks": checks,
        "blocking_reasons": blocking_reasons,
        "partial_reasons": partial_reasons,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON gate input")
    parser.add_argument("--output", type=Path, help="Output JSON path")
    parser.add_argument("--model", type=Path, help="Exact accepted model")
    parser.add_argument("--knowledge-receipt", type=Path, help="Verified dual-provider knowledge receipt")
    parser.add_argument("--considerations-source-packet", type=Path)
    parser.add_argument("--considerations-threats", type=Path)
    parser.add_argument("--considerations-responses", type=Path)
    parser.add_argument("--considerations-proposal-output", type=Path)
    parser.add_argument(
        "--considerations-delta-ledger",
        type=Path,
        help="Use the D2D Section 7 covered/missing/partially_covered comparison",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = json.loads(args.input.read_text())
    proposal_requested = any((
        args.considerations_source_packet,
        args.considerations_threats,
        args.considerations_responses,
        args.considerations_proposal_output,
    ))
    # Source-pinned *complete threat models* need a knowledge receipt.
    # An optional D2D authoring proposal must not turn a generic gate
    # into a completed-threat-model assertion.
    if args.model and not proposal_requested:
        model = json.loads(args.model.read_text())
        pinned_spec = any(
            isinstance(entry, dict)
            and str(entry.get("source_reference", "")).startswith("https://")
            for entry in model.get("source_inventory", [])
        )
        if model.get("target_kind") in {"specification", "web_specification"} or (
            model.get("abstraction_level") in {"spec-review", "specification-review"}
            and pinned_spec
        ):
            payload["target_kind"] = "specification"
    if args.knowledge_receipt:
        payload["knowledge_reconciliation"] = json.loads(args.knowledge_receipt.read_text())
    result = evaluate(payload)
    proposal_values = [
        args.considerations_source_packet,
        args.considerations_threats,
        args.considerations_responses,
        args.considerations_proposal_output,
    ]
    if any(proposal_values):
        if not all(proposal_values) or not args.model:
            result["considerations_authoring_proposal"] = {
                "status": "unavailable",
                "reason": "D2D proposal requires a model, source packet, threats, responses and output path",
                "blocking": False,
            }
        else:
            try:
                from propose_considerations_authoring import read, recommend

                deltas = None
                if args.considerations_delta_ledger:
                    delta_obj = read(args.considerations_delta_ledger)
                    deltas = delta_obj.get("deltas", delta_obj.get("rows"))
                proposal = recommend(
                    args.model,
                    args.considerations_source_packet,
                    args.considerations_threats,
                    args.considerations_responses,
                    kind="d2d",
                    considerations_deltas=deltas,
                )
                if args.considerations_proposal_output.exists():
                    raise ValueError(
                        "considerations job proposal output already exists"
                    )
                args.considerations_proposal_output.parent.mkdir(
                    parents=True, exist_ok=True
                )
                args.considerations_proposal_output.write_text(
                    json.dumps(proposal, indent=2, ensure_ascii=False) + "\n"
                )
                result["considerations_authoring_proposal"] = {
                    "decision": proposal["decision"],
                    "skill_id": proposal["writer_job"]["skill_id"]
                    if proposal["writer_job"]
                    else None,
                    "path": str(args.considerations_proposal_output),
                    "blocking": False,
                }
            except (
                OSError,
                ValueError,
                TypeError,
                KeyError,
                json.JSONDecodeError,
            ) as exc:
                result["considerations_authoring_proposal"] = {
                    "status": "unavailable",
                    "reason": str(exc),
                    "blocking": False,
                }
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
