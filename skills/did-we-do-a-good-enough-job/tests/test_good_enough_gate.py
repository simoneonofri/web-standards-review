from __future__ import annotations

import copy
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT / "scripts"))

from evaluate_good_enough_gate import evaluate  # noqa: E402


def valid_payload() -> dict:
    return {
        "run_scope": "additional",
        "gates": [
            {"name": "source_corpus", "status": "pass"},
            {"name": "model_packet", "status": "pass"},
            {"name": "dfd_representation", "status": "pass"},
            {"name": "baseline_elicitation", "status": "pass"},
            {"name": "additional_elicitation_reconciliation", "status": "pass"},
            {"name": "response_mapping", "status": "pass"},
        ],
        "coverage": {
            "model_ids": ["EE-01", "PO-01", "DF-01", "TB-01"],
            "dictionary_ids": ["EE-01", "PO-01", "DF-01", "TB-01"],
            "baseline_threat_ids": ["T-01", "T-02"],
            "actual_response_threat_ids": ["T-01", "T-02"],
            "additional_threat_ids": ["T-03"],
            "new_response_threat_ids": ["T-03"],
        },
    }


def test_complete_inputs_pass() -> None:
    result = evaluate(valid_payload())
    assert result["schema_version"] == "independent-review-gate/v1"
    assert result["status"] == "pass"
    assert "publication_allowed" not in result


def test_valid_and_invalid_gate_fixtures() -> None:
    valid = json.loads((FIXTURES / "valid-gate-input.json").read_text(encoding="utf-8"))
    invalid = json.loads((FIXTURES / "invalid-gate-input.json").read_text(encoding="utf-8"))
    assert evaluate(valid)["status"] == "pass"
    assert evaluate(invalid)["status"] == "blocked"


def test_partial_upstream_gate_propagates_partial() -> None:
    payload = valid_payload()
    payload["gates"][3]["status"] = "partial"
    result = evaluate(payload)
    assert result["status"] == "partial"
    assert "publication_allowed" not in result


def test_blocked_upstream_gate_propagates_blocked() -> None:
    payload = valid_payload()
    payload["gates"][2]["status"] = "blocked"
    result = evaluate(payload)
    assert result["status"] == "blocked"
    assert "publication_allowed" not in result


def test_missing_required_gate_is_blocked() -> None:
    payload = valid_payload()
    payload["gates"] = payload["gates"][:-1]
    result = evaluate(payload)
    assert result["status"] == "blocked"
    assert any("missing required upstream gates" in reason for reason in result["blocking_reasons"])


def test_truncated_dictionary_is_partial() -> None:
    payload = valid_payload()
    payload["coverage"]["dictionary_ids"] = payload["coverage"]["dictionary_ids"][:-1]
    result = evaluate(payload)
    assert result["status"] == "partial"
    assert any("dictionary_model_set_equality" in reason for reason in result["partial_reasons"])


def test_missing_actual_and_new_responses_are_partial() -> None:
    payload = copy.deepcopy(valid_payload())
    payload["coverage"]["actual_response_threat_ids"] = ["T-01"]
    payload["coverage"]["new_response_threat_ids"] = []
    result = evaluate(payload)
    assert result["status"] == "partial"
    assert any("actual_response_baseline_coverage" in reason for reason in result["partial_reasons"])
    assert any("new_response_additional_coverage" in reason for reason in result["partial_reasons"])


def baseline_payload() -> dict:
    payload = valid_payload()
    payload["run_scope"] = "baseline"
    payload["gates"] = [gate for gate in payload["gates"] if gate["name"] != "additional_elicitation_reconciliation"]
    payload["coverage"].pop("additional_threat_ids")
    payload["coverage"].pop("new_response_threat_ids")
    return payload


def test_baseline_does_not_require_out_of_scope_coverage_fields() -> None:
    assert evaluate(baseline_payload())["status"] == "pass"


def test_additional_run_still_requires_coverage_fields() -> None:
    payload = valid_payload()
    payload["coverage"].pop("additional_threat_ids")
    assert evaluate(payload)["status"] == "blocked"


def test_baseline_still_validates_provided_additional_fields() -> None:
    payload = baseline_payload()
    payload["coverage"]["additional_threat_ids"] = "T-03"
    assert evaluate(payload)["status"] == "blocked"


def test_baseline_preserves_checks_for_provided_additional_coverage() -> None:
    payload = baseline_payload()
    payload["coverage"]["additional_threat_ids"] = ["T-03"]
    payload["coverage"]["new_response_threat_ids"] = []
    assert evaluate(payload)["status"] == "partial"


def test_documented_baseline_threat_elicitation_name_is_recognized():
    payload = valid_payload()
    payload["gates"][3]["name"] = "baseline threat elicitation"
    assert evaluate(payload)["status"] == "pass"
