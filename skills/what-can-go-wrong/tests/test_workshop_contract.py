from __future__ import annotations

import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SPEC = importlib.util.spec_from_file_location(
    "validate_threat_package", ROOT / "scripts" / "validate_threat_package.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
validate_local = MODULE.validate_local


def base_model() -> dict:
    return {
        "external_entities": [],
        "processes": [],
        "data_stores": [],
        "data_flows": [{"id": "DF-01", "name": "Request flow"}],
        "trust_boundaries": [],
    }


def base_package() -> dict:
    prompt = "Could this message be replayed outside the transaction where it was created?"
    metadata = {
        "prompt_template_id": "STRIDE-TAMPERING-FLOW",
        "prompt_family": "stride_per_element",
        "source_item_id": "request-algorithm",
        "applicability_rule_id": "data_flow_tampering_or_replay",
        "expected_bad_event_shape": "A message is replayed before the receiver acts.",
    }
    return {
        "threats": [
            {
                "threat_id": "T-01",
                "affected_model_elements": ["DF-01"],
                "actor_or_condition": "A replay-capable intermediary",
                "action_or_failure": "reuses a request outside its intended transaction",
                "violated_property_or_interest": "freshness and transaction integrity",
                "consequence": "the receiver acts on stale authority",
                "threat_story": "A replay-capable intermediary reuses a request outside its intended transaction, causing the receiver to act on stale authority.",
                "evidence_status": "inferred",
                "evidence": [{"source_reference": "Spec request algorithm"}],
            }
        ],
        "workshop_simulation": {
            "mode": "card_workshop",
            "deck": {
                "artifact_reference": "artifacts/wapi-deck.json",
                "validation_status": "passed",
                "deck_id": "wapi-deck",
                "title": "Web API Deck",
                "version": "1.0.0",
                "status": "playtest",
                "generation_mode": "source-to-cards",
                "play_mode": "collaborative",
                "cards_used": [
                    {
                        "card_id": "WAPI-MSG-01",
                        "suit": "MSG",
                        "rank": 1,
                        "title": "Replayable message",
                        "prompt": prompt,
                        "applies_to": ["data_flow"],
                        "source_trace": [
                            {
                                "source_kind": "primary_source",
                                "source_reference": "Spec request algorithm",
                                "source_item_id": "request-algorithm",
                                "evidence_status": "verified",
                            }
                        ],
                        **metadata,
                        "card_status": "keep",
                    }
                ],
            },
            "card_plays": [
                {
                    "card_play_id": "PLAY-001",
                    "deck_id": "wapi-deck",
                    "card_id": "WAPI-MSG-01",
                    "suit": "MSG",
                    "rank": 1,
                    "model_element_id": "DF-01",
                    "model_element_type": "data_flow",
                    "model_element_name": "Request flow",
                    "prompt": prompt,
                    "answer": "The request can be replayed unless it is bound to a fresh transaction.",
                    "answer_status": "generated_threat",
                    "candidate_relation": "new_partially_covered_threat",
                    "non_producing_reason": "",
                    "related_threat_ids": [],
                    "relatedness_basis": "",
                    "derived_threat_ids": ["T-01"],
                    "applicability_basis": "The card applies to a transaction-bearing data flow.",
                    "review_basis": "source_checked",
                    "question_generation_inputs": [
                        "Card WAPI-MSG-01",
                        "Model element DF-01",
                    ],
                    "source_reread_status": "cached_source_packet",
                    "source_signal_used": "The algorithm sends a request used as transaction evidence.",
                    "source_to_question_rationale": "The source signal exposes a replay surface.",
                    "question_basis": "source_grounded",
                    "answer_basis_summary": "Answer based on the accepted model and source packet.",
                    "source_reference": "Spec request algorithm",
                    **metadata,
                }
            ],
        },
    }


class WorkshopContractTests(unittest.TestCase):
    def test_valid_workshop_contract_passes(self) -> None:
        self.assertEqual(validate_local(base_package(), base_model()), [])

    def test_legacy_play_id_and_multi_target_shape_fail(self) -> None:
        package = json.loads(
            (FIXTURES / "invalid-workshop-legacy-shape.json").read_text(encoding="utf-8")
        )
        errors = validate_local(package, base_model())
        self.assertTrue(any("play_id is a legacy alias" in error for error in errors), errors)
        self.assertTrue(any("legacy multi-target shape" in error for error in errors), errors)

    def test_unknown_card_reference_fails(self) -> None:
        package = base_package()
        package["workshop_simulation"]["card_plays"][0]["card_id"] = "MISSING-01"
        errors = validate_local(package, base_model())
        self.assertTrue(any("cards_used" in error for error in errors), errors)

    def test_prompt_or_metadata_drift_fails(self) -> None:
        package = base_package()
        play = package["workshop_simulation"]["card_plays"][0]
        play["prompt"] = "Different prompt?"
        play["expected_bad_event_shape"] = "A different shape."
        errors = validate_local(package, base_model())
        self.assertTrue(any("canonical card prompt" in error for error in errors), errors)
        self.assertTrue(any("canonical card metadata" in error for error in errors), errors)

    def test_prompt_family_is_preserved_from_canonical_card(self) -> None:
        package = base_package()
        play = package["workshop_simulation"]["card_plays"][0]
        self.assertEqual(play["prompt_family"], "stride_per_element")
        play["prompt_family"] = "card_play"
        errors = validate_local(package, base_model())
        self.assertTrue(any("prompt_family must match" in error for error in errors), errors)

    def test_source_to_cards_requires_source_trace(self) -> None:
        package = base_package()
        del package["workshop_simulation"]["deck"]["cards_used"][0]["source_trace"]
        errors = validate_local(package, base_model())
        self.assertTrue(any("source_trace" in error for error in errors), errors)

    def test_assumption_source_uses_assumed_evidence_status(self) -> None:
        package = base_package()
        source = package["workshop_simulation"]["deck"]["cards_used"][0]["source_trace"][0]
        source["source_kind"] = "assumption"
        source["evidence_status"] = "assumed"
        self.assertEqual(validate_local(package, base_model()), [])
        source["evidence_status"] = "assumption"
        errors = validate_local(package, base_model())
        self.assertTrue(any("evidence_status must be one of" in error for error in errors), errors)

    def test_assumption_source_requires_evidence_status(self) -> None:
        package = base_package()
        source = package["workshop_simulation"]["deck"]["cards_used"][0]["source_trace"][0]
        source["source_kind"] = "assumption"
        source.pop("evidence_status")
        errors = validate_local(package, base_model())
        self.assertTrue(any("must be assumed when source_kind is assumption" in error for error in errors), errors)

    def test_generic_contract_root_is_supported_without_personal_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            contract_root = Path(temporary_directory)
            script = contract_root / "scripts" / "validate_threat_model_contract.py"
            script.parent.mkdir()
            script.write_text("# synthetic contract validator\n", encoding="utf-8")
            with patch.dict(
                os.environ,
                {"STANDARDS_REVIEW_CONTRACTS_ROOT": str(contract_root)},
                clear=False,
            ):
                self.assertEqual(MODULE.resolve_contract_root(), contract_root)
        source = (ROOT / "scripts" / "validate_threat_package.py").read_text(encoding="utf-8")
        self.assertNotIn("Path.home()", source)

    def test_unknown_model_or_threat_reference_fails(self) -> None:
        package = base_package()
        play = package["workshop_simulation"]["card_plays"][0]
        play["model_element_id"] = "DF-MISSING"
        play["derived_threat_ids"] = ["T-MISSING"]
        errors = validate_local(package, base_model())
        self.assertTrue(any("unknown model element" in error for error in errors), errors)
        self.assertTrue(any("unknown threat IDs" in error for error in errors), errors)

    def test_non_producing_play_requires_reason_and_no_threat(self) -> None:
        package = base_package()
        play = package["workshop_simulation"]["card_plays"][0]
        play["answer_status"] = "model_gap"
        play["candidate_relation"] = "not_applicable_prompt"
        errors = validate_local(package, base_model())
        self.assertTrue(any("non_producing_reason is required" in error for error in errors), errors)
        self.assertTrue(any("must be empty for non-producing" in error for error in errors), errors)

    def test_duplicate_card_element_pair_fails(self) -> None:
        package = base_package()
        duplicate = copy.deepcopy(package["workshop_simulation"]["card_plays"][0])
        duplicate["card_play_id"] = "PLAY-002"
        package["workshop_simulation"]["card_plays"].append(duplicate)
        errors = validate_local(package, base_model())
        self.assertTrue(any("duplicates the card/model-element pair" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()


def test_threat_story_cannot_be_only_one_event_component():
    for field in MODULE.REQUIRED_BAD_EVENT_FIELDS:
        package = base_package()
        package["threats"][0]["threat_story"] = package["threats"][0][field]
        assert any("not a complete concrete bad-event story" in error for error in validate_local(package)), field
