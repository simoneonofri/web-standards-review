from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELECT = ROOT / "scripts" / "select_checks.py"


class CheckSelectionTests(unittest.TestCase):
    def test_selection_explains_every_match(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SELECT), "--categories", "user-intent-and-trusted-ui,device-sensor-and-native-boundaries"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)
        self.assertGreater(data["count"], 0)
        self.assertTrue(all(item["reasons"] for item in data["selected_checks"]))

    def test_selection_rejects_unknown_identifiers(self) -> None:
        result = subprocess.run([sys.executable, str(SELECT), "--categories", "not-a-category"], cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown categories", result.stderr)

    def test_missing_validation_statement_is_unknown_not_fail_in_catalog_criteria(self) -> None:
        result = subprocess.run([sys.executable, str(SELECT), "--categories", "input-validation"], cwd=ROOT, check=True, capture_output=True, text=True)
        data = json.loads(result.stdout)
        self.assertTrue(any("unavailable" in " ".join(item["evidence_to_collect"]) or item["question"] for item in data["selected_checks"]))

    def test_pattern_variants_are_not_collapsed_by_validator_contract(self) -> None:
        catalog = json.loads((ROOT / "catalog" / "security-patterns.json").read_text())
        keys = [p["conceptual_key"] for p in catalog["patterns"]]
        self.assertEqual(len(keys), len(set(keys)))


if __name__ == "__main__":
    unittest.main()
