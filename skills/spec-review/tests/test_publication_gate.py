from __future__ import annotations

import hashlib
import json
from pathlib import Path

from spec_review.publication_gate import _validate_fact_check_result_v1, build_publication_gate


FIXTURES = Path(__file__).parent / "fixtures"


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def fact_check_for(artifact: Path, *, status: str = "pass", review_status: str = "draft") -> dict:
    unresolved = [] if status == "pass" else ["CLAIM-001"]
    claim_status = "verified" if status == "pass" else "partially_supported"
    return {
        "schema_version": "fact-check-result/v1",
        "fact_check_id": "FC-001",
        "artifact": {
            "artifact_id": "report",
            "artifact_type": "report",
            "reference": artifact.name,
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        },
        "checked_at": "2026-08-06T08:30:00+02:00",
        "review_status": review_status,
        "sources": [
            {
                "source_id": "SRC-001",
                "source_type": "supplied_source",
                "title": "Synthetic review source",
                "reference": "source.txt",
                "authority": "supplied",
                "version_or_date": "2026-08-06",
                "retrieved_at": "2026-08-06T08:00:00+02:00",
                "access_status": "checked",
                "content_sha256": None,
                "limitations": [],
            }
        ],
        "claims": [
            {
                "claim_id": "CLAIM-001",
                "locator": "Review, paragraph 1",
                "claim": "The synthetic review source was supplied for this test.",
                "checkability": "externally_checkable",
                "importance": "material",
                "status": claim_status,
                "source_ids": ["SRC-001"],
                "evidence_note": "The synthetic source is present in the test run.",
                "recommended_edit": "" if status == "pass" else "Qualify the claim.",
                "disposition": "keep" if status == "pass" else "qualify",
            }
        ],
        "unresolved_claim_ids": unresolved,
        "limitations": [],
        "publication_status": status,
    }


def passing_gate() -> dict:
    return {"schema_version": "gate/v1", "status": "pass"}


def test_fact_check_contract_fixtures() -> None:
    valid = json.loads((FIXTURES / "fact-check-valid.json").read_text(encoding="utf-8"))
    invalid = json.loads((FIXTURES / "fact-check-invalid.json").read_text(encoding="utf-8"))
    assert _validate_fact_check_result_v1(valid) == []
    assert any("locator" in error for error in _validate_fact_check_result_v1(invalid))


def test_complete_gate_passes_and_keeps_human_approval_separate(tmp_path: Path) -> None:
    artifact = tmp_path / "review.md"
    artifact.write_text("review\n", encoding="utf-8")
    fact_check = write_json(tmp_path / "fact-check.json", fact_check_for(artifact))
    analysis = write_json(tmp_path / "analysis.json", passing_gate())
    independent = write_json(tmp_path / "independent.json", passing_gate())
    gate = build_publication_gate(
        artifact_path=artifact,
        fact_check_path=fact_check,
        analysis_gate_path=analysis,
        independent_review_gate_path=independent,
    )
    assert gate["status"] == "pass"
    assert gate["human_approval"] == {
        "required": True,
        "status": "not_recorded",
        "approver": None,
        "approved_at": None,
    }
    encoded = json.dumps(gate)
    assert str(tmp_path) not in encoded
    assert gate["artifact"]["reference"] == artifact.name
    assert gate["inputs"]["fact_check_result"] == fact_check.name


def test_structurally_invalid_fact_check_fails(tmp_path: Path) -> None:
    artifact = tmp_path / "review.md"
    artifact.write_text("review\n", encoding="utf-8")
    payload = fact_check_for(artifact)
    del payload["claims"][0]["locator"]
    fact_check = write_json(tmp_path / "fact-check-invalid.json", payload)
    analysis = write_json(tmp_path / "analysis.json", passing_gate())
    independent = write_json(tmp_path / "independent.json", passing_gate())
    gate = build_publication_gate(
        artifact_path=artifact,
        fact_check_path=fact_check,
        analysis_gate_path=analysis,
        independent_review_gate_path=independent,
    )
    assert gate["status"] == "fail"
    check = next(item for item in gate["checks"] if item["check_id"] == "fact_check")
    assert any("locator" in error for error in check["errors"])


def test_artifact_edit_after_fact_check_fails(tmp_path: Path) -> None:
    artifact = tmp_path / "review.md"
    artifact.write_text("checked\n", encoding="utf-8")
    fact_check = write_json(tmp_path / "fact-check.json", fact_check_for(artifact))
    artifact.write_text("changed\n", encoding="utf-8")
    analysis = write_json(tmp_path / "analysis.json", passing_gate())
    independent = write_json(tmp_path / "independent.json", passing_gate())
    gate = build_publication_gate(
        artifact_path=artifact,
        fact_check_path=fact_check,
        analysis_gate_path=analysis,
        independent_review_gate_path=independent,
    )
    assert gate["status"] == "fail"
    identity = next(item for item in gate["checks"] if item["check_id"] == "artifact_identity")
    assert identity["status"] == "fail"


def test_non_passing_fact_check_fails(tmp_path: Path) -> None:
    artifact = tmp_path / "review.md"
    artifact.write_text("review\n", encoding="utf-8")
    fact_check = write_json(
        tmp_path / "fact-check.json",
        fact_check_for(artifact, status="needs_revision"),
    )
    analysis = write_json(tmp_path / "analysis.json", passing_gate())
    independent = write_json(tmp_path / "independent.json", passing_gate())
    gate = build_publication_gate(
        artifact_path=artifact,
        fact_check_path=fact_check,
        analysis_gate_path=analysis,
        independent_review_gate_path=independent,
    )
    assert gate["status"] == "fail"
    check = next(item for item in gate["checks"] if item["check_id"] == "fact_check")
    assert check["status"] == "fail"


def test_required_upstream_gate_cannot_be_omitted(tmp_path: Path) -> None:
    artifact = tmp_path / "review.md"
    artifact.write_text("review\n", encoding="utf-8")
    fact_check = write_json(tmp_path / "fact-check.json", fact_check_for(artifact))
    gate = build_publication_gate(
        artifact_path=artifact,
        fact_check_path=fact_check,
    )
    assert gate["status"] == "fail"
    failed = {item["check_id"] for item in gate["checks"] if item["status"] == "fail"}
    assert {"analysis_gate", "independent_review_gate"} <= failed


def test_boundary_blocker_fails(tmp_path: Path) -> None:
    artifact = tmp_path / "review.md"
    artifact.write_text("review\n", encoding="utf-8")
    fact_check = write_json(tmp_path / "fact-check.json", fact_check_for(artifact))
    analysis = write_json(tmp_path / "analysis.json", passing_gate())
    independent = write_json(tmp_path / "independent.json", passing_gate())
    boundary = write_json(
        tmp_path / "boundary.json",
        {
            "schema_version": 1,
            "findings": [
                {
                    "severity": "blocker",
                    "rule": "private_dependency",
                    "path": "SKILL.md",
                    "line": 10,
                }
            ],
        },
    )
    gate = build_publication_gate(
        artifact_path=artifact,
        fact_check_path=fact_check,
        analysis_gate_path=analysis,
        independent_review_gate_path=independent,
        publication_boundary_path=boundary,
    )
    assert gate["status"] == "fail"


def test_final_gate_can_require_human_reviewed_fact_check(tmp_path: Path) -> None:
    artifact = tmp_path / "review.md"
    artifact.write_text("review\n", encoding="utf-8")
    fact_check = write_json(tmp_path / "fact-check.json", fact_check_for(artifact))
    analysis = write_json(tmp_path / "analysis.json", passing_gate())
    independent = write_json(tmp_path / "independent.json", passing_gate())
    gate = build_publication_gate(
        artifact_path=artifact,
        fact_check_path=fact_check,
        analysis_gate_path=analysis,
        independent_review_gate_path=independent,
        require_human_reviewed_fact_check=True,
    )
    assert gate["status"] == "fail"
    reviewed_fact_check = write_json(
        tmp_path / "fact-check-reviewed.json",
        fact_check_for(artifact, review_status="human_reviewed"),
    )
    gate = build_publication_gate(
        artifact_path=artifact,
        fact_check_path=reviewed_fact_check,
        analysis_gate_path=analysis,
        independent_review_gate_path=independent,
        require_human_reviewed_fact_check=True,
    )
    assert gate["status"] == "pass"
