from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validate_threat_model_contract import (  # noqa: E402
    validate_dfd_dictionary,
    validate_handoff,
    validate_model,
    validate_responses,
    validate_threats,
)

FIXTURES = ROOT / "tests" / "fixtures" / "threat-model-contract"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class ThreatModelContractStrictTests(unittest.TestCase):
    def test_valid_pipeline_and_complete_response_coverage(self) -> None:
        model = load("model-valid.json")
        threats = load("threat-valid.json")
        responses = load("response-valid.json")
        dictionary = load("dictionary-valid.json")

        self.assertEqual(validate_model(model), [])
        self.assertEqual(validate_threats(threats, model), [])
        self.assertEqual(validate_responses(responses, threats, True), [])
        self.assertEqual(validate_dfd_dictionary(dictionary, model), [])

    def test_stripped_model_ids_fail_closed(self) -> None:
        model = load("model-valid.json")
        model["processes"][0]["stable_id"] = "P01"
        errors = validate_model(model)
        self.assertTrue(any("non-canonical model ID" in error for error in errors))

    def test_method_item_title_cannot_pass_concrete_threat_gate(self) -> None:
        model = load("model-valid.json")
        threats = load("threat-valid.json")
        threat = threats["threats"][0]
        threat["actor_or_condition"] = ""
        threat["evidence"] = []
        threat["threat_story"] = "RFC privacy prompt for DF-01"
        errors = validate_threats(threats, model)
        self.assertTrue(any("actor_or_condition" in error for error in errors))
        self.assertTrue(any("evidence" in error for error in errors))
        self.assertTrue(any("too short to be concrete" in error for error in errors))

    def test_truncated_dictionary_fails_exact_set_equality(self) -> None:
        model = load("model-valid.json")
        dictionary = load("dictionary-valid.json")
        dictionary["rows"] = dictionary["rows"][:-1]
        errors = validate_dfd_dictionary(dictionary, model)
        self.assertTrue(any("missing model IDs" in error for error in errors))

    def test_missing_actual_response_row_fails_complete_coverage(self) -> None:
        threats = load("threat-valid.json")
        second = copy.deepcopy(threats["threats"][0])
        second["threat_id"] = "T-02"
        second["action_or_failure"] = "blocks the mediated request indefinitely"
        second["threat_story"] = (
            "A malicious service blocks the mediated request indefinitely, "
            "violating availability and preventing the user action from completing."
        )
        threats["threats"].append(second)
        responses = load("response-valid.json")
        errors = validate_responses(responses, threats, True)
        self.assertTrue(any("missing response rows" in error for error in errors))

    def test_ready_handoff_requires_correct_id_authority_and_evidence(self) -> None:
        handoff = load("handoff-valid.json")
        self.assertEqual(validate_handoff(handoff), [])
        handoff["id_authority"] = "none"
        handoff["validation"]["evidence_paths"] = []
        errors = validate_handoff(handoff)
        self.assertTrue(any("requires id_authority" in error for error in errors))
        self.assertTrue(any("requires validation evidence_paths" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
