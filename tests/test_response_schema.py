"""Schema-only consumers must reject response rows already rejected by the producer."""

import json
import importlib.util
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "shared_response_contract", ROOT / "contracts/threat-modeling-flow-v1/scripts/validate_threat_model_contract.py"
)
SHARED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHARED)


@pytest.mark.parametrize("field,value", [("affected_model_elements", []), ("next_action", "")])
def test_response_schema_rejects_empty_required_response_fields(field, value):
    schema = json.loads((ROOT / "contracts/threat-modeling-flow-v1/schemas/response-package.schema.json").read_text())
    response = json.loads((ROOT / "fixtures/clean-room-demo/responses.json").read_text())
    validator = Draft202012Validator(schema)
    assert not list(validator.iter_errors(response))
    response["responses"][0][field] = value
    errors = list(validator.iter_errors(response))
    assert any(list(error.path) == ["responses", 0, field] for error in errors)
    assert any(field in error for error in SHARED.validate_responses(response))


def combined_package(strategies):
    package = json.loads((ROOT / "fixtures/clean-room-demo/responses.json").read_text())
    row = package["responses"][0]
    row.update(erta=strategies, transfer_receiver="Service operator",
               remaining_threat="An operator can fail to enforce the control.",
               acceptance_rationale="The deployment owner accepts this bounded consequence.",
               revisit_trigger="Revisit if the deployment assumptions change.")
    if strategies == "Unresolved":
        row["status"] = "blocked"
    return package


def schema_errors(package):
    schema = json.loads((ROOT / "contracts/threat-modeling-flow-v1/schemas/response-package.schema.json").read_text())
    return list(Draft202012Validator(schema).iter_errors(package))


@pytest.mark.parametrize("strategies", [
    "Eliminate", "Reduce", "Transfer", "Accept", "Unresolved",
    ["Reduce"], ["Reduce", "Transfer"], ["Transfer", "Reduce"],
    ["Reduce", "Transfer", "Accept"], ["Eliminate", "Reduce", "Transfer", "Accept"],
])
def test_supported_erta_representations(strategies):
    package = combined_package(strategies)
    assert not schema_errors(package)
    assert SHARED.validate_responses(package) == []
    assert len(package["responses"]) == 5
    assert package["responses"][0]["response_id"] == "R-01"


@pytest.mark.parametrize("strategies", [
    [], ["Reduce", "Reduce"], ["Unknown"], ["Unresolved"],
    ["Reduce", "Unresolved"], "Reduce + Transfer", "Unknown", None,
    [None], [1], [{}], [["Reduce"]], {}, 1,
])
def test_invalid_erta_representations(strategies):
    package = combined_package(strategies)
    assert schema_errors(package)
    assert SHARED.validate_responses(package)


@pytest.mark.parametrize("field,expected", [
    ("remaining_threat", "Reduce needs remaining_threat"),
    ("transfer_receiver", "Transfer needs transfer_receiver"),
    ("assumptions", "Transfer needs explicit assumptions"),
    ("acceptance_rationale", "Accept needs acceptance_rationale"),
    ("owner", "Accept needs owner"),
    ("revisit_trigger", "Accept needs revisit_trigger"),
    ("mechanism_or_text", "Eliminate needs mechanism_or_text"),
])
def test_combined_erta_keeps_every_strategy_obligation(field, expected):
    package = combined_package(["Eliminate", "Reduce", "Transfer", "Accept"])
    package["responses"][0][field] = [] if field == "assumptions" else ""
    assert any(expected in error for error in SHARED.validate_responses(package))


@pytest.mark.parametrize("field", [None, "transfer_receiver", "remaining_threat"])
def test_producer_cli_enforces_combined_strategy_requirements(tmp_path, field):
    import subprocess
    import sys

    package = combined_package(["Reduce", "Transfer"])
    if field:
        package["responses"][0][field] = ""
    path = tmp_path / "responses.json"
    path.write_text(json.dumps(package))
    result = subprocess.run([
        sys.executable,
        str(ROOT / "skills/what-are-we-going-to-do-about-it/scripts/validate_response_package.py"),
        str(path), "--threats", str(ROOT / "fixtures/clean-room-demo/threats.json"),
    ], capture_output=True, text=True, check=False)
    assert (result.returncode == 0) == (field is None), result.stdout + result.stderr
