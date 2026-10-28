"""Validate candidate provenance and reconciliation against frozen caller artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any

SCHEMA = "candidate-ledger/v1"
DISPOSITIONS = {"pending", "retained_unique", "confirmed_existing", "refined_existing", "duplicate", "not_concrete", "not_applicable", "insufficient_evidence", "out_of_scope", "blocked", "deferred", "needs_manual_review"}
RELATED = {"retained_unique", "confirmed_existing", "refined_existing", "duplicate"}
OPEN = {"pending", "blocked", "deferred", "needs_manual_review"}
EVENT_FIELDS = ("actor_or_condition", "action_or_failure", "violated_property_or_interest", "consequence")
ROOT_FIELDS = {"schema_version", "run_id", "stage", "model_sha256", "candidates", "elicitation_sha256", "threat_package_sha256", "baseline_threat_ids"}
ROW_FIELDS = {"candidate_id", "origin_method", "source_artifact", "observation", "affected_model_elements", "disposition", "rationale", "counterevidence", "concrete_bad_event", "evidence_basis", "retained_threat_id"}


def text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def strings(value: Any) -> bool:
    return isinstance(value, list) and all(text(item) for item in value)


def identifier(value: Any, pattern: str) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def model_ids(model: Any) -> tuple[set[str], set[str], list[str]]:
    if not isinstance(model, dict):
        return set(), set(), ["model must be an object"]
    ids, assumptions, errors = set(), set(), []
    for collection in ("external_entities", "processes", "data_stores", "data_flows", "trust_boundaries", "assumptions"):
        rows = model.get(collection, [])
        if not isinstance(rows, list):
            errors.append(f"model.{collection} must be an array")
            continue
        for row in rows:
            value = (row.get("canonical_id") or row.get("stable_id") or row.get("id")) if isinstance(row, dict) else None
            if not text(value):
                errors.append(f"model.{collection} rows require string IDs")
                continue
            (assumptions if collection == "assumptions" else ids).add(value)
    if not ids:
        errors.append("model has no pointable elements")
    return ids, assumptions, errors


def evidence_errors(value: Any, where: str, assumptions: set[str]) -> list[str]:
    if not isinstance(value, dict):
        return [f"{where}.evidence_basis is required for promotion or relatedness"]
    errors = []
    if set(value) - {"review_basis", "source_references", "inference_rationale", "assumption_ids"}:
        errors.append(f"{where}.evidence_basis has unknown fields")
    basis = value.get("review_basis")
    if not isinstance(basis, str) or basis not in {"source_checked", "model_inference", "assumption_based"}:
        errors.append(f"{where}.evidence_basis has invalid review_basis")
    references = value.get("source_references")
    if not strings(references):
        errors.append(f"{where}.source_references must be a string array")
    if basis == "source_checked" and not (strings(references) and references):
        errors.append(f"{where}: source_checked requires source references")
    if "inference_rationale" in value and not text(value["inference_rationale"]):
        errors.append(f"{where}.inference_rationale must be non-empty")
    if basis in ("model_inference", "assumption_based") and not text(value.get("inference_rationale")):
        errors.append(f"{where}: inferred or assumed evidence needs an explicit rationale")
    selected = value.get("assumption_ids", [])
    if not strings(selected) or any(item not in assumptions for item in selected):
        errors.append(f"{where}.assumption_ids must reference model assumptions")
    if basis == "assumption_based" and not selected:
        errors.append(f"{where}: assumption_based requires assumption IDs")
    return errors


def validate(ledger: Any, model: Any, *, model_digest: str, threats: Any = None,
             threats_digest: str | None = None, elicitation: Any = None,
             elicitation_digest: str | None = None) -> list[str]:
    errors = []
    if not isinstance(ledger, dict):
        return ["candidate ledger must be an object"]
    if set(ledger) - ROOT_FIELDS:
        errors.append("ledger has unknown fields")
    if ledger.get("schema_version") != SCHEMA:
        errors.append(f"schema_version must be {SCHEMA}")
    if not text(ledger.get("run_id")):
        errors.append("run_id is required")
    stage = ledger.get("stage")
    if stage not in ("elicitation", "reconciliation"):
        errors.append("stage must be elicitation or reconciliation")
    if not identifier(ledger.get("model_sha256"), r"[0-9a-f]{64}") or ledger.get("model_sha256") != model_digest:
        errors.append("model hash differs from the selected model bytes")
    ids, assumptions, model_errors = model_ids(model)
    errors.extend(model_errors)
    if isinstance(model, dict) and text(model.get("run_id")) and ledger.get("run_id") != model["run_id"]:
        errors.append("ledger run differs from the model run")
    candidates = ledger.get("candidates")
    if not isinstance(candidates, list):
        return errors + ["candidates must be an array"]
    threat_rows = threats.get("threats") if isinstance(threats, dict) else None
    final = {}
    frozen = {}
    baseline = ledger.get("baseline_threat_ids", [])
    if stage == "elicitation":
        if any(field in ledger for field in ("elicitation_sha256", "threat_package_sha256", "baseline_threat_ids")):
            errors.append("elicitation cannot declare reconciliation artifacts or final threat IDs")
    if stage == "reconciliation":
        if "baseline_threat_ids" not in ledger:
            errors.append("reconciliation must explicitly declare baseline_threat_ids")
        if isinstance(threats, dict):
            if "run_id" in threats and threats["run_id"] != ledger.get("run_id"):
                errors.append("threat package run differs from the ledger run")
            if isinstance(model, dict) and "model_id" in model and threats.get("model_id") != model["model_id"]:
                errors.append("threat package model differs from the selected model")
        if not identifier(ledger.get("threat_package_sha256"), r"[0-9a-f]{64}") or ledger.get("threat_package_sha256") != threats_digest:
            errors.append("reconciliation requires the exact threat package hash")
        if not identifier(ledger.get("elicitation_sha256"), r"[0-9a-f]{64}") or ledger.get("elicitation_sha256") != elicitation_digest:
            errors.append("reconciliation requires the frozen elicitation hash")
        if not isinstance(threat_rows, list):
            errors.append("reconciliation requires a threat package")
        else:
            for row in threat_rows:
                if not isinstance(row, dict) or not identifier(row.get("threat_id"), r"T-\d{2,}"):
                    errors.append("threat package rows require canonical threat IDs")
                elif row["threat_id"] in final:
                    errors.append("threat package repeats an ID")
                else:
                    final[row["threat_id"]] = row
        if not isinstance(elicitation, dict) or elicitation.get("stage") != "elicitation":
            errors.append("reconciliation requires an elicitation-stage ledger")
        else:
            errors.extend("frozen elicitation: " + error for error in validate(elicitation, model, model_digest=model_digest))
            if elicitation.get("run_id") != ledger.get("run_id"):
                errors.append("reconciliation run differs from frozen elicitation")
            for row in elicitation.get("candidates", []) if isinstance(elicitation.get("candidates"), list) else []:
                if isinstance(row, dict) and text(row.get("candidate_id")):
                    frozen[row["candidate_id"]] = row
        if not strings(baseline) or len(baseline) != len(set(baseline)) or not set(baseline).issubset(final):
            errors.append("baseline_threat_ids must be unique IDs from the final threat package")
            baseline = []
    seen, promoted = set(), set()
    for index, row in enumerate(candidates):
        where = f"candidates[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{where} must be an object")
            continue
        if set(row) - ROW_FIELDS:
            errors.append(f"{where} has unknown fields")
        cid = row.get("candidate_id")
        if not identifier(cid, r"C-[A-Za-z0-9_.-]+"):
            errors.append(f"{where}.candidate_id must use the C- namespace")
        elif cid in seen:
            errors.append(f"duplicate candidate_id: {cid}")
        else:
            seen.add(cid)
        for field in ("origin_method", "source_artifact", "observation", "rationale"):
            if not text(row.get(field)):
                errors.append(f"{where}.{field} must be non-empty")
        elements = row.get("affected_model_elements")
        if not strings(elements) or not set(elements).issubset(ids):
            errors.append(f"{where}.affected_model_elements must reference model IDs")
        elif len(elements) != len(set(elements)):
            errors.append(f"{where}.affected_model_elements must be unique")
        if not strings(row.get("counterevidence")):
            errors.append(f"{where}.counterevidence must be a string array, including when empty")
        disposition = row.get("disposition")
        if not isinstance(disposition, str) or disposition not in DISPOSITIONS:
            errors.append(f"{where} has invalid disposition")
            continue
        linked = row.get("retained_threat_id")
        if stage != "reconciliation" and ("retained_threat_id" in row or disposition in RELATED):
            errors.append(f"{where}: only reconciliation may assign final threat IDs or promotion dispositions")
        if stage == "reconciliation":
            previous = frozen.get(cid) if isinstance(cid, str) else None
            if previous:
                for field in ("origin_method", "source_artifact", "observation", "affected_model_elements"):
                    if row.get(field) != previous.get(field):
                        errors.append(f"{where}: frozen provenance changed: {field}")
                if strings(previous.get("counterevidence")) and strings(row.get("counterevidence")) and not set(previous["counterevidence"]).issubset(row["counterevidence"]):
                    errors.append(f"{where}: frozen counterevidence was dropped")
                previous_basis, current_basis = previous.get("evidence_basis"), row.get("evidence_basis")
                if isinstance(previous_basis, dict):
                    for field in ("source_references", "assumption_ids"):
                        old = previous_basis.get(field, [])
                        new = current_basis.get(field, []) if isinstance(current_basis, dict) else []
                        if strings(old) and strings(new) and not set(old).issubset(new):
                            errors.append(f"{where}: frozen evidence provenance was dropped: {field}")
            if disposition in RELATED:
                if not identifier(linked, r"T-\d{2,}") or linked not in final:
                    errors.append(f"{where}: relatedness must reference a retained threat")
                errors.extend(evidence_errors(row.get("evidence_basis"), where, assumptions))
            elif "retained_threat_id" in row:
                errors.append(f"{where}: a non-promoted candidate cannot assign a threat ID")
        if "evidence_basis" in row and not (stage == "reconciliation" and disposition in RELATED):
            errors.extend(evidence_errors(row["evidence_basis"], where, assumptions))
        event = row.get("concrete_bad_event")
        if disposition == "retained_unique" or "concrete_bad_event" in row:
            if not isinstance(event, dict) or set(event) != set(EVENT_FIELDS):
                errors.append(f"{where}.concrete_bad_event must contain the four bad-event fields")
            else:
                for field in EVENT_FIELDS:
                    if not text(event[field]):
                        errors.append(f"{where}.concrete_bad_event.{field} must be non-empty")
                if disposition == "retained_unique" and isinstance(linked, str) and linked in final:
                    if any(event[field] != final[linked].get(field) for field in EVENT_FIELDS) or elements != final[linked].get("affected_model_elements"):
                        errors.append(f"{where}: promoted event differs from the canonical threat")
            if disposition == "retained_unique":
                if not (strings(elements) and elements):
                    errors.append(f"{where}: promotion requires model attachment")
                if isinstance(linked, str):
                    if linked in promoted or linked in baseline:
                        errors.append(f"{where}: final threat ID is assigned more than once")
                    promoted.add(linked)
    if stage == "reconciliation":
        if seen != set(frozen):
            errors.append("reconciliation dropped or invented frozen candidates")
        if set(final) != set(baseline) | promoted:
            errors.append("final threat package includes untraced threats or lacks promoted threats")
    return errors


def load(path: Path) -> tuple[Any, str]:
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate_ledger", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--threats", type=Path)
    parser.add_argument("--elicitation", type=Path)
    args = parser.parse_args()
    try:
        ledger, _ = load(args.candidate_ledger)
        model, model_digest = load(args.model)
        threats, threats_digest = load(args.threats) if args.threats else (None, None)
        elicitation, elicitation_digest = load(args.elicitation) if args.elicitation else (None, None)
        errors = validate(ledger, model, model_digest=model_digest, threats=threats, threats_digest=threats_digest, elicitation=elicitation, elicitation_digest=elicitation_digest)
    except (OSError, ValueError) as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}))
        return 1
    if errors:
        print(json.dumps({"valid": False, "errors": errors}))
        return 1
    status = "not_started" if ledger["stage"] == "elicitation" else "partial" if any(row["disposition"] in OPEN for row in ledger["candidates"]) else "complete"
    print(json.dumps({"valid": True, "reconciliation_status": status, "candidates": len(ledger["candidates"]), "promoted": sum(row["disposition"] == "retained_unique" for row in ledger["candidates"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
