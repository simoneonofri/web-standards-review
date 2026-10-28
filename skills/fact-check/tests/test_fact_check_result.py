from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "fact-check-result-valid.json"
SPEC = importlib.util.spec_from_file_location(
    "validate_fact_check_result", ROOT / "scripts" / "validate_fact_check_result.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_valid_result_passes() -> None:
    assert MODULE.validate_result(load_fixture()) == []


def test_load_bearing_unsupported_claim_blocks() -> None:
    payload = load_fixture()
    claim = payload["claims"][0]
    claim["status"] = "unsupported"
    claim["importance"] = "load_bearing"
    claim["source_ids"] = []
    claim["evidence_note"] = "No reliable source found"
    claim["recommended_edit"] = "Remove or rewrite as an open question."
    claim["disposition"] = "remove"
    payload["unresolved_claim_ids"] = [claim["claim_id"]]
    payload["publication_status"] = "blocked"
    assert MODULE.validate_result(payload) == []
    assert MODULE.expected_publication_status(payload["claims"]) == "blocked"


def test_declared_publication_status_must_match_gate() -> None:
    payload = load_fixture()
    claim = payload["claims"][0]
    claim["status"] = "partially_supported"
    claim["recommended_edit"] = "Qualify the date as the snapshot date."
    claim["disposition"] = "qualify"
    payload["unresolved_claim_ids"] = [claim["claim_id"]]
    payload["publication_status"] = "pass"
    errors = MODULE.validate_result(payload)
    assert any("deterministic factual-readiness gate" in error for error in errors)


def test_unsupported_claim_uses_exact_marker() -> None:
    payload = load_fixture()
    claim = payload["claims"][0]
    claim["status"] = "unsupported"
    claim["source_ids"] = []
    claim["evidence_note"] = "Nothing found"
    claim["disposition"] = "open_question"
    payload["unresolved_claim_ids"] = [claim["claim_id"]]
    payload["publication_status"] = "needs_revision"
    errors = MODULE.validate_result(payload)
    assert any("No reliable source found" in error for error in errors)


def test_unknown_source_reference_fails() -> None:
    payload = load_fixture()
    payload["claims"][0]["source_ids"] = ["SRC-MISSING"]
    errors = MODULE.validate_result(payload)
    assert any("unknown sources" in error for error in errors)


def test_artifact_digest_validation(tmp_path: Path) -> None:
    artifact = tmp_path / "review-report.md"
    artifact.write_text("Checked artifact\n", encoding="utf-8")
    payload = load_fixture()
    payload["artifact"]["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert MODULE.validate_result(payload) == []
    assert MODULE.validate_artifact_digest(payload, tmp_path) == []
    artifact.write_text("Changed after fact check\n", encoding="utf-8")
    errors = MODULE.validate_artifact_digest(payload, tmp_path)
    assert any("sha256 mismatch" in error for error in errors)


def test_artifact_path_cannot_escape_root(tmp_path: Path) -> None:
    payload = load_fixture()
    payload["artifact"]["reference"] = "../outside.md"
    errors = MODULE.validate_artifact_digest(payload, tmp_path)
    assert any("outside --artifact-root" in error for error in errors)


def test_inference_must_be_visibly_qualified() -> None:
    payload = load_fixture()
    payload["claims"][1]["disposition"] = "keep"
    payload["publication_status"] = "needs_revision"
    assert MODULE.validate_result(payload) == []
    assert MODULE.expected_publication_status(payload["claims"]) == "needs_revision"


def test_schema_declares_contract_version() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "fact-check-result-v1.schema.json").read_text(encoding="utf-8")
    )
    assert schema["properties"]["schema_version"]["const"] == "fact-check-result/v1"
    assert "not_checkable" in schema["$defs"]["claim"]["properties"]["status"]["enum"]


def test_claim_source_references_must_be_unique():
    payload = load_fixture()
    payload["claims"][0]["source_ids"] *= 2
    assert any("source_ids must not contain duplicates" in error for error in MODULE.validate_result(payload))
