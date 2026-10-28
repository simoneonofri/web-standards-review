from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"
SPEC = importlib.util.spec_from_file_location("portable_candidate_ledger", ROOT / "scripts/validate_candidate_ledger.py")
LEDGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LEDGER)


def fixture():
    model, model_digest = LEDGER.load(FIXTURES / "ledger-model.json")
    threats, threats_digest = LEDGER.load(FIXTURES / "ledger-threats.json")
    elicitation, elicitation_digest = LEDGER.load(FIXTURES / "ledger-elicitation.json")
    ledger, _ = LEDGER.load(FIXTURES / "ledger-reconciliation.json")
    return ledger, model, dict(model_digest=model_digest, threats=threats, threats_digest=threats_digest, elicitation=elicitation, elicitation_digest=elicitation_digest)


def test_valid_frozen_pair_matches_schema_and_preserves_duplicate_provenance():
    ledger, model, context = fixture()
    schema = json.loads((ROOT / "schemas/candidate-ledger-v1.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    for value in (ledger, context["elicitation"]):
        jsonschema.validate(value, schema)
    assert LEDGER.validate(ledger, model, **context) == []
    assert LEDGER.validate(context["elicitation"], model, model_digest=context["model_digest"]) == []
    assert len(ledger["candidates"]) == len(context["threats"]["threats"]) + 2
    assert ledger["candidates"][-2]["disposition"] == "duplicate"
    assert ledger["candidates"][-1]["disposition"] == "not_concrete"


@pytest.mark.parametrize("field", ["model_sha256", "threat_package_sha256", "elicitation_sha256"])
def test_exact_input_hashes_are_required(field):
    ledger, model, context = fixture()
    ledger[field] = "0" * 64
    assert LEDGER.validate(ledger, model, **context)


@pytest.mark.parametrize("mutation", ["drop", "invent", "observation", "origin_method", "source_artifact", "affected_model_elements"])
def test_reconciliation_cannot_drop_or_rewrite_frozen_candidates(mutation):
    ledger, model, context = fixture()
    if mutation == "drop":
        ledger["candidates"].pop()
    elif mutation == "invent":
        row = copy.deepcopy(ledger["candidates"][-1])
        row["candidate_id"] = "C-invented"
        ledger["candidates"].append(row)
    else:
        ledger["candidates"][0][mutation] = [] if mutation == "affected_model_elements" else "Changed frozen provenance"
    assert LEDGER.validate(ledger, model, **context)


@pytest.mark.parametrize("mutation", ["id", "promotion", "alias", "hash", "baseline"])
def test_elicitation_cannot_assign_final_threat_identity(mutation):
    _, model, context = fixture()
    early = context["elicitation"]
    if mutation == "id":
        early["candidates"][0]["retained_threat_id"] = "T-01"
    elif mutation == "promotion":
        early["candidates"][0]["disposition"] = "retained_unique"
    elif mutation == "alias":
        early["candidates"][0]["threat_id"] = "T-01"
    elif mutation == "hash":
        early["threat_package_sha256"] = context["threats_digest"]
    else:
        early["baseline_threat_ids"] = ["T-01"]
    assert LEDGER.validate(early, model, model_digest=context["model_digest"])


@pytest.mark.parametrize("mutation", ["unknown_model", "duplicate_candidate", "unknown_disposition", "bad_event", "wrong_event", "unknown_threat", "promote_twice", "untraced_threat", "drop_baseline_declaration", "missing_evidence", "wrong_model", "wrong_run"])
def test_invalid_promotion_and_context_fail_closed(mutation):
    ledger, model, context = fixture()
    row = ledger["candidates"][0]
    if mutation == "unknown_model":
        row["affected_model_elements"] = ["PO-99"]
    elif mutation == "duplicate_candidate":
        ledger["candidates"][1]["candidate_id"] = row["candidate_id"]
    elif mutation == "unknown_disposition":
        row["disposition"] = "probably_ok"
    elif mutation == "bad_event":
        del row["concrete_bad_event"]
    elif mutation == "wrong_event":
        row["concrete_bad_event"]["consequence"] = "A different consequence"
    elif mutation == "unknown_threat":
        row["retained_threat_id"] = "T-99"
    elif mutation == "promote_twice":
        duplicate = ledger["candidates"][-2]
        duplicate.update(disposition="retained_unique", concrete_bad_event=copy.deepcopy(row["concrete_bad_event"]))
    elif mutation == "untraced_threat":
        extra = copy.deepcopy(context["threats"]["threats"][0])
        extra["threat_id"] = "T-99"
        context["threats"]["threats"].append(extra)
    elif mutation == "drop_baseline_declaration":
        del ledger["baseline_threat_ids"]
    elif mutation == "missing_evidence":
        del row["evidence_basis"]
    elif mutation == "wrong_model":
        context["threats"]["model_id"] = "different-model"
    else:
        context["threats"]["run_id"] = "different-run"
    assert LEDGER.validate(ledger, model, **context)


@pytest.mark.parametrize("field", ["counterevidence", "source_references", "assumption_ids"])
def test_frozen_counterevidence_and_source_provenance_cannot_be_erased(field):
    ledger, model, context = fixture()
    previous = context["elicitation"]["candidates"][0]
    if field == "counterevidence":
        previous[field] = ["A recorded limiting condition"]
    else:
        previous["evidence_basis"] = copy.deepcopy(ledger["candidates"][0]["evidence_basis"])
        previous["evidence_basis"][field] = ["A-001" if field == "assumption_ids" else "Additional source"]
    assert LEDGER.validate(ledger, model, **context)


@pytest.mark.parametrize("value", [None, [], {}, 42, ""])
@pytest.mark.parametrize("field", ["candidate_id", "disposition", "affected_model_elements", "evidence_basis", "concrete_bad_event"])
def test_malformed_retained_candidate_reports_errors_without_crashing(field, value):
    ledger, model, context = fixture()
    ledger["candidates"][0][field] = value
    assert LEDGER.validate(ledger, model, **context)


def command(path, *, integrated=False):
    script = ROOT / "scripts" / ("validate_threat_package.py" if integrated else "validate_candidate_ledger.py")
    args = [sys.executable, str(script), str(FIXTURES / "ledger-threats.json") if integrated else str(path), "--model", str(FIXTURES / "ledger-model.json")]
    if integrated:
        args += ["--candidate-ledger", str(path), "--elicitation-ledger", str(FIXTURES / "ledger-elicitation.json")]
    else:
        args += ["--threats", str(FIXTURES / "ledger-threats.json"), "--elicitation", str(FIXTURES / "ledger-elicitation.json")]
    return args


def test_integrated_gate_runs_from_an_unrelated_caller_directory(tmp_path):
    result = subprocess.run(command(FIXTURES / "ledger-reconciliation.json", integrated=True), cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_shape_valid_partial_ledger_cannot_pass_complete_handoff(tmp_path):
    ledger, _, _ = fixture()
    ledger["candidates"][-1]["disposition"] = "deferred"
    path = tmp_path / "partial.json"
    path.write_text(json.dumps(ledger))
    standalone = subprocess.run(command(path), cwd=tmp_path, capture_output=True, text=True)
    assert standalone.returncode == 0, standalone.stdout + standalone.stderr
    assert json.loads(standalone.stdout)["reconciliation_status"] == "partial"
    result = subprocess.run(command(path, integrated=True), cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode != 0
    assert "not complete" in result.stdout


def test_cli_rejects_modified_frozen_bytes_and_does_not_rewrite_inputs(tmp_path):
    early = tmp_path / "early.json"
    early.write_bytes((FIXTURES / "ledger-elicitation.json").read_bytes() + b"\n")
    args = command(FIXTURES / "ledger-reconciliation.json")
    args[-1] = str(early)
    before = early.read_bytes()
    result = subprocess.run(args, cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode != 0
    assert "frozen elicitation hash" in result.stdout
    assert early.read_bytes() == before
