import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "valid_source_to_cards.json"
INVALID_ASSUMPTION_FIXTURE = (
    ROOT / "tests" / "fixtures" / "invalid_assumption_evidence_status.json"
)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


validator = load_module("validate_deck", ROOT / "scripts" / "validate_deck.py")
renderer = load_module("render_markdown", ROOT / "scripts" / "render_markdown.py")


class ThreatCardContractTests(unittest.TestCase):
    def load_fixture(self):
        return json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_valid_source_to_cards_contract(self):
        errors, warnings = validator.validate(self.load_fixture())
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_source_to_cards_requires_source_trace(self):
        deck = self.load_fixture()
        del deck["cards"][0]["source_trace"]
        errors, _ = validator.validate(deck)
        self.assertTrue(any("must include source_trace" in error for error in errors))

    def test_question_generation_metadata_is_atomic(self):
        deck = self.load_fixture()
        del deck["cards"][0]["expected_bad_event_shape"]
        errors, _ = validator.validate(deck)
        self.assertTrue(any("partial question-generation metadata" in error for error in errors))

    def test_rewritten_card_requires_change_notes(self):
        deck = self.load_fixture()
        card = deck["cards"][0]
        card["card_status"] = "rewrite"
        card.pop("change_notes", None)
        errors, _ = validator.validate(deck)
        self.assertTrue(any("change_notes is required" in error for error in errors))

    def test_source_kind_assumption_uses_assumed_evidence_status(self):
        deck = self.load_fixture()
        assumption_source = deck["cards"][2]["source_trace"][0]
        self.assertEqual(assumption_source["source_kind"], "assumption")
        self.assertEqual(assumption_source["evidence_status"], "assumed")
        invalid = json.loads(INVALID_ASSUMPTION_FIXTURE.read_text(encoding="utf-8"))
        errors, _ = validator.validate(invalid)
        self.assertTrue(any("must be assumed when source_kind is assumption" in error for error in errors))

    def test_assumption_source_requires_evidence_status(self):
        deck = self.load_fixture()
        del deck["cards"][2]["source_trace"][0]["evidence_status"]
        errors, _ = validator.validate(deck)
        self.assertTrue(any("must be assumed when source_kind is assumption" in error for error in errors))

    def test_render_includes_handoff_metadata(self):
        output = renderer.render(self.load_fixture())
        self.assertIn("Generation mode: `source-to-cards`", output)
        self.assertIn("**Question-generation metadata:**", output)
        self.assertIn("**Source trace:**", output)
        self.assertIn("Expected bad event shape", output)
        self.assertIn("Card status: `rewrite`", output)

    def test_machine_readable_schema_is_valid_json(self):
        schema_path = ROOT / "schemas" / "threat-card-deck-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(schema["title"], "Threat Card Deck Contract v1")
        self.assertIn("generation_mode", schema["properties"])
        source_statuses = schema["$defs"]["sourceTrace"]["properties"]["evidence_status"]["enum"]
        self.assertIn("assumed", source_statuses)
        self.assertNotIn("assumption", source_statuses)

    def test_render_only_is_not_valid_generation_provenance(self):
        deck = self.load_fixture()
        deck["generation_mode"] = "render-only"
        errors, _ = validator.validate(deck)
        self.assertTrue(any("render-only is an operation" in error for error in errors))


    def test_non_string_card_ids_report_errors_without_crashing(self):
        for value in (101, [], {}, None, True):
            with self.subTest(value=value):
                deck = self.load_fixture()
                deck["cards"][0]["id"] = value
                errors, _ = validator.validate(deck)
                self.assertTrue(any("id must be a non-empty string" in error for error in errors))

    def test_invalid_suit_id_types_report_errors_without_sorting_crashes(self):
        for value in (101, [], {}):
            with self.subTest(value=value):
                deck = self.load_fixture()
                deck["suits"][0]["id"] = value
                errors, _ = validator.validate(deck)
                self.assertTrue(any("suits[0].id must be a non-empty string" in error for error in errors))

    def test_invalid_card_suit_reference_type_reports_error(self):
        deck = self.load_fixture()
        deck["cards"][0]["suit"] = []
        errors, _ = validator.validate(deck)
        self.assertTrue(any("suit must be a non-empty string" in error for error in errors))

    def test_present_top_level_enums_cannot_be_empty_or_malformed(self):
        for field in ("status", "generation_mode", "play_mode"):
            for value in ("", None, [], {}):
                with self.subTest(field=field, value=value):
                    deck = self.load_fixture()
                    deck[field] = value
                    errors, _ = validator.validate(deck)
                    self.assertTrue(any(field + " must be one of" in error for error in errors))

    def test_present_card_and_source_enums_cannot_be_empty_or_malformed(self):
        for field in ("card_status", "source_kind", "evidence_status"):
            for value in ("", None, [], {}):
                with self.subTest(field=field, value=value):
                    deck = self.load_fixture()
                    target = deck["cards"][0] if field == "card_status" else deck["cards"][0]["source_trace"][0]
                    target[field] = value
                    errors, _ = validator.validate(deck)
                    self.assertTrue(any(field + " must be one of" in error for error in errors))

    def test_prompt_question_marker_must_be_final_character(self):
        deck = self.load_fixture()
        deck["cards"][0]["prompt"] += " "
        errors, _ = validator.validate(deck)
        self.assertTrue(any("prompt must be a question ending with" in error for error in errors))

if __name__ == "__main__":
    unittest.main()
