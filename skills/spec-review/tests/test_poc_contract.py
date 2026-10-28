from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from spec_review.poc_contract import validate_poc_document  # noqa: E402


def _document(tmp_path: Path) -> dict[str, object]:
    artifact = tmp_path / "observed.json"
    artifact.write_text('{"result":"bounded"}\n', encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    return {
        "artifact_kind": "bounded_local_poc",
        "schema_version": 1,
        "poc_class": "documentary",
        "verification_scope": "specification_mechanism",
        "verification_status": "verified",
        "environment": {"identity": "pytest", "command": "python verify.py"},
        "safety": {"synthetic_inputs": True, "real_credentials": False, "external_endpoints": False},
        "cases": {
            "positive": {"expected": "gap detected", "observed": "gap detected", "status": "pass"},
            "negative": {"expected": "no gap", "observed": "no gap", "status": "pass"},
            "mitigated": {"expected": "requirement detected", "observed": "requirement detected", "status": "pass"},
        },
        "claims": {
            "demonstrates": ["The preserved source lacks the tested requirement."],
            "does_not_demonstrate": ["Any implementation is vulnerable."],
        },
        "concept": {"concept_id": "bounded-requirement-gap", "description": "A required guard is absent."},
        "artifacts": [{"path": "observed.json", "sha256": digest}],
    }


def test_valid_documentary_poc(tmp_path: Path) -> None:
    result = validate_poc_document(_document(tmp_path), base_dir=tmp_path)
    assert result.valid, result.errors


def test_verified_requires_all_cases_to_pass(tmp_path: Path) -> None:
    document = _document(tmp_path)
    document["cases"]["mitigated"]["status"] = "fail"  # type: ignore[index]
    result = validate_poc_document(document, base_dir=tmp_path)
    assert "verified PoCs require positive, negative, and mitigated cases to pass" in result.errors


def test_model_cannot_claim_implementation_behavior(tmp_path: Path) -> None:
    document = _document(tmp_path)
    document["poc_class"] = "model"
    document["verification_scope"] = "implementation_behavior"
    result = validate_poc_document(document, base_dir=tmp_path)
    assert "model PoCs cannot claim implementation_behavior" in result.errors


def test_artifact_hash_is_enforced(tmp_path: Path) -> None:
    document = _document(tmp_path)
    document["artifacts"][0]["sha256"] = "0" * 64  # type: ignore[index]
    result = validate_poc_document(document, base_dir=tmp_path)
    assert any("does not match" in error for error in result.errors)


def test_cli_validates_document(tmp_path: Path) -> None:
    evidence = tmp_path / "poc-evidence.json"
    evidence.write_text(json.dumps(_document(tmp_path)), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, "scripts/validate_poc.py", "--evidence", str(evidence), "--json"],
        cwd=Path(__file__).parents[1],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["valid"] is True
