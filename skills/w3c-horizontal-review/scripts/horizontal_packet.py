"""Initialize work orders and verify portable horizontal-review artifact integrity."""
import argparse
import hashlib
import json
import re
from pathlib import Path

REGISTRY = Path(__file__).resolve().parents[1] / "references/extractors.json"
STATES = {"planned", "completed", "not_applicable", "unavailable"}


def require(value, message):
    if not value:
        raise ValueError(message)


def target_valid(target):
    require(isinstance(target, dict), "target must be an object")
    require(target.get("id") and target.get("kind") in {"specification", "charter", "as_is"}, "exact target identity and kind are required")
    require(re.fullmatch(r"[0-9a-f]{64}", target.get("sha256", "")), "target SHA-256 is required")
    require(isinstance(target.get("snapshot_url"), str) and target["snapshot_url"].startswith("https://"), "recoverable snapshot URL is required")


def initialize(target):
    target_valid(target)
    layers = []
    for row in json.loads(REGISTRY.read_text())["extractors"]:
        applies = target["kind"] in row["target_kinds"]
        layers.append({"id": row["id"], "state": "planned" if applies else "not_applicable", "rationale": "Work has not run" if applies else "Outside the selected target kind", "artifacts": []})
    expected = {"specification": {"baseline", "independent", "checklist", "implementation"}, "as_is": {"baseline"}, "charter": {"checklist", "charter_status"}}[target["kind"]]
    flows = {name: {"state": "planned" if name in expected else "not_applicable", "rationale": "Work has not run" if name in expected else "Outside the requested scope", "artifacts": []} for name in ["baseline", "independent", "checklist", "implementation", "charter_status"]}
    return {"schema_version": "horizontal-review-run/v1", "target": target, "extractors": layers, "flows": flows, "independent_before_reconciliation": False, "evidence": [], "checks": [], "threat_queue": [], "findings": [], "public_projection": [], "publication_authorized": False}


def artifact(record, root):
    raw = record.get("path", "")
    path = Path(raw)
    require(raw and not path.is_absolute() and ".." not in path.parts and "\\" not in raw, "artifact path must be relative to the run")
    for i in range(1, len(path.parts)+1):
        require(not (root / Path(*path.parts[:i])).is_symlink(), "artifact symlinks are forbidden")
    path = root / path
    require(path.is_file(), "artifact is missing")
    require(hashlib.sha256(path.read_bytes()).hexdigest() == record.get("sha256"), "artifact hash changed")


def unique(rows, label):
    require(isinstance(rows, list) and all(isinstance(row, dict) and isinstance(row.get("id"), str) and row["id"] for row in rows), label + " must contain named records")
    result = {row["id"]: row for row in rows}
    require(len(result) == len(rows), label + " has duplicate IDs")
    return result


def validate(packet, root):
    require(packet.get("schema_version") == "horizontal-review-run/v1", "unsupported run contract")
    require(packet.get("publication_authorized") is False, "validation cannot authorize publication")
    target_valid(packet["target"])
    template = initialize(packet["target"])
    layers = unique(packet["extractors"], "extractors")
    require(set(layers) == {r["id"] for r in template["extractors"]}, "extractor registry is incomplete")
    require(set(packet["flows"]) == set(template["flows"]), "flow inventory is incomplete")
    states = []
    for name, row in list(layers.items()) + list(packet["flows"].items()):
        require(row.get("state") in STATES and row.get("rationale"), name + " needs a state and rationale")
        if name in template["flows"] and template["flows"][name]["state"] == "planned":
            require(row["state"] != "not_applicable", "requested flow cannot be silently skipped: " + name)
        require(isinstance(row.get("artifacts"), list), name + " needs an artifact list")
        if row["state"] == "completed":
            require(row["artifacts"], name + " completion requires actual artifact evidence")
        for item in row["artifacts"]:
            artifact(item, root)
        states.append(row["state"])
    evidence = unique(packet["evidence"], "evidence")
    for record in evidence.values():
        require(record.get("role") in {"target", "implementation", "precedent", "method", "analysis"} and record.get("locator"), "evidence needs a role and locator")
        artifact(record["artifact"], root)
        if record["role"] == "target":
            require(record["artifact"]["sha256"] == packet["target"]["sha256"], "target evidence belongs to another snapshot")
    def refs(row, field, target=False):
        values = row.get(field)
        require(isinstance(values, list) and len(set(values)) == len(values), "evidence references must be unique arrays")
        require(all(v in evidence for v in values), "unknown evidence reference")
        if target:
            require(all(evidence[v]["role"] == "target" for v in values), "method or precedent evidence cannot substitute for target evidence")
        return values
    pending = False
    for row in unique(packet["checks"], "checks").values():
        require(row.get("extractor") in layers and row.get("rationale"), "check needs an extractor and rationale")
        require(row["extractor"] != "threat-knowledge", "threat prompts belong in the modeling queue, not control checks")
        require(refs(row, "source_evidence_ids"), "check needs source provenance")
        target = refs(row, "target_evidence_ids", True)
        require(row.get("status") in {"not_evaluated", "pass", "partial", "fail", "not_applicable", "unable_to_verify"}, "unknown check disposition")
        if row["status"] in {"pass", "fail"}:
            require(target, "check verdict requires affirmative target evidence")
        pending |= row["status"] in {"not_evaluated", "partial", "unable_to_verify"}
    for row in unique(packet["threat_queue"], "threat queue").values():
        require(row.get("extractor") in layers and row.get("rationale"), "queue item needs provenance and rationale")
        require(refs(row, "source_evidence_ids"), "queue item needs source evidence")
        relation = row.get("as_is_relationship")
        require(relation in {"pending", "new_candidate", "handled_as_is", "duplicate_as_is", "not_applicable", "unable_to_verify"}, "unknown reconciliation state")
        if relation in {"new_candidate", "handled_as_is", "duplicate_as_is"}:
            require(row.get("model_elements") and row.get("story"), "elicited threat requires model attachment and a story")
        pending |= relation in {"pending", "unable_to_verify"}
    findings = unique(packet["findings"], "findings")
    for row in findings.values():
        require(row.get("ownership") in {"specification", "implementation", "charter", "review_request", "context"}, "finding ownership missing")
        require(row.get("disposition") in {"accepted", "candidate", "duplicate", "refinement", "follow_up_existing", "handled", "non_issue", "context", "not_applicable", "unable_to_verify"} and row.get("rationale"), "finding disposition missing")
        support = refs(row, "evidence_ids")
        if row["disposition"] == "accepted":
            require(support and all(row.get(field) for field in ["mechanism", "affected_property", "impact"]), "accepted finding lacks its mechanism and bounded impact")
            if row["ownership"] in {"specification", "charter"}:
                require(any(evidence[v]["role"] == "target" for v in support), "finding lacks target evidence")
    projection = packet["public_projection"]
    require(isinstance(projection, list) and len(set(projection)) == len(projection), "public projection must contain unique IDs")
    for identifier in projection:
        require(identifier in findings, "unknown public finding")
        row = findings[identifier]
        require(row["disposition"] == "accepted" and row["ownership"] in {"specification", "charter"}, "implementation or unvalidated finding cannot enter the specification projection")
    if packet["flows"]["independent"]["state"] == "completed":
        require(packet.get("independent_before_reconciliation") is True, "independent elicitation must precede reconciliation")
    status = "blocked" if all(state in {"planned", "not_applicable"} for state in states) else "partial" if pending or any(state in {"planned", "unavailable"} for state in states) else "complete"
    if status == "complete":
        require(any(row["role"] == "target" for row in evidence.values()), "complete review requires the captured target evidence")
    return {"schema_version": "horizontal-run-validation/v1", "status": status, "publication_authorized": False, "limits": ["Artifact integrity and workflow bookkeeping; factual and LLM judgments require separate review"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    init = subs.add_parser("init")
    init.add_argument("--target", type=Path, required=True)
    init.add_argument("--output", type=Path, required=True)
    check = subs.add_parser("validate")
    check.add_argument("packet", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "init":
            result = initialize(json.loads(args.target.read_text()))
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x") as stream:
                stream.write(json.dumps(result, indent=2) + "\n")
            print(json.dumps({"status": "initialized", "work_executed": False}))
        else:
            result = validate(json.loads(args.packet.read_text()), args.packet.resolve().parent)
            print(json.dumps(result))
            return 0 if result["status"] == "complete" else 2
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
