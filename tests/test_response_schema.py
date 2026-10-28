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
