from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "evals" / "fixtures"
SPEC = importlib.util.spec_from_file_location(
    "validate_response_package", ROOT / "scripts" / "validate_response_package.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def run_fixture(name: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate_response_package.py"),
            str(FIXTURES / name),
            "--threats",
            str(FIXTURES / "threat-package-valid.json"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def run_with_threats(
    response_name: str,
    threat_name: str,
    *extra: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate_response_package.py"),
            str(FIXTURES / response_name),
            "--threats",
            str(FIXTURES / threat_name),
            *extra,
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def load_valid_package() -> dict:
    return json.loads((FIXTURES / "valid-eliminate.json").read_text(encoding="utf-8"))


def test_canonical_v1_record_shape_passes_local_validation() -> None:
    assert MODULE.validate_specific_responses(load_valid_package()) == []


def test_legacy_singular_model_element_fails_local_validation() -> None:
    package = load_valid_package()
    response = package["responses"][0]
    response["model_element"] = {
        "id": response["affected_model_elements"][0],
        "type": "data_flow",
    }
    del response["affected_model_elements"]
    errors = MODULE.validate_specific_responses(package)
    assert any("model_element is a legacy singular field" in error for error in errors)
    assert any("affected_model_elements must be a non-empty array" in error for error in errors)


def test_structured_next_action_fails_local_validation() -> None:
    package = load_valid_package()
    package["responses"][0]["next_action"] = {
        "type": "spec_change",
        "target": "Security Considerations",
        "text": "Document the remaining threat.",
    }
    errors = MODULE.validate_specific_responses(package)
    assert any("structured action objects are not part" in error for error in errors)


def test_valid_eliminate_passes() -> None:
    assert run_fixture("valid-eliminate.json").returncode == 0


def test_shared_contract_does_not_reinterpret_consumer_owned_workshop(tmp_path: Path) -> None:
    threat_package = json.loads((FIXTURES / "threat-package-valid.json").read_text(encoding="utf-8"))
    threat_package["workshop_simulation"] = {
        "mode": "card_workshop",
        "card_plays": [{"card_play_id": "PLAY-001", "model_element_id": "DF-01"}],
    }
    threat_path = tmp_path / "threat-package-with-canonical-workshop.json"
    threat_path.write_text(json.dumps(threat_package), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate_response_package.py"),
            str(FIXTURES / "valid-eliminate.json"),
            "--threats",
            str(threat_path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_prose_assumption_instead_of_canonical_reference_fails(tmp_path: Path) -> None:
    package = load_valid_package()
    package["responses"][0]["assumptions"] = ["The platform behaves as expected."]
    path = tmp_path / "prose-assumption.json"
    path.write_text(json.dumps(package), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate_response_package.py"),
            str(path),
            "--threats",
            str(FIXTURES / "threat-package-valid.json"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "canonical A-### reference" in result.stdout


def test_legacy_assumption_locator_fails(tmp_path: Path) -> None:
    package = load_valid_package()
    package["responses"][0]["evidence"] = [{"locator": "AS-01 in the model packet"}]
    path = tmp_path / "legacy-locator.json"
    path.write_text(json.dumps(package), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate_response_package.py"),
            str(path),
            "--threats",
            str(FIXTURES / "threat-package-valid.json"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "retired assumption reference" in result.stdout


def test_reduce_without_remaining_fails() -> None:
    result = run_fixture("reduce-without-remaining.json")
    assert result.returncode != 0
    assert "remaining_threat" in result.stdout


def test_transfer_without_receiver_fails() -> None:
    result = run_fixture("transfer-without-receiver.json")
    assert result.returncode != 0
    assert "transfer_receiver" in result.stdout


def test_best_practice_response_fails() -> None:
    result = run_fixture("best-practice-response.json")
    assert result.returncode != 0
    assert "best-practice" in result.stdout


def test_missing_baseline_response_row_fails() -> None:
    result = run_with_threats("missing-baseline-response.json", "threat-package-two.json")
    assert result.returncode != 0
    assert "missing response rows for threat IDs ['T-02']" in result.stdout


def test_unresolved_row_still_completes_baseline_coverage() -> None:
    result = run_with_threats(
        "valid-unresolved-coverage.json",
        "threat-package-two.json",
        "--handoff",
        str(FIXTURES / "valid-response-handoff.json"),
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_generic_keyword_routing_response_fails() -> None:
    result = run_fixture("generic-keyword-response.json")
    assert result.returncode != 0
    assert "generic keyword-routing text" in result.stdout


def test_allow_subset_is_explicit() -> None:
    result = run_with_threats(
        "missing-baseline-response.json",
        "threat-package-two.json",
        "--allow-subset",
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_generic_mechanism_is_not_hidden_by_response_summary():
    package = load_valid_package()
    package["responses"][0].update(response="Mitigate", mechanism_or_text="validate inputs")
    errors = MODULE.validate_specific_responses(package)
    assert any("generic keyword-routing text" in error for error in errors)


def test_short_summary_can_use_a_concrete_threat_specific_mechanism():
    package = load_valid_package()
    package["responses"][0]["response"] = "Validate inputs"
    assert MODULE.validate_specific_responses(package) == []


def test_specific_mechanism_is_not_rejected_for_a_generic_introductory_phrase():
    package = load_valid_package()
    package["responses"][0].update(response="Reject replayed requests", mechanism_or_text="Improve security by rejecting stale transaction identifiers before processing the request.")
    assert MODULE.validate_specific_responses(package) == []
