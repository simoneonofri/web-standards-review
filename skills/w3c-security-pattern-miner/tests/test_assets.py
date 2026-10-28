from __future__ import annotations

import subprocess
import contextlib
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_assets.py"


class AssetTests(unittest.TestCase):
    def _validator(self):
        spec = importlib.util.spec_from_file_location("security_asset_validator", VALIDATOR)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _result_and_categories(self):
        result = json.loads((ROOT / "assets/spec-mining-result.example.json").read_text())
        taxonomy = json.loads((ROOT / "references/security-taxonomy.json").read_text())
        return result, {row["category_id"] for row in taxonomy["categories"]}

    def test_assets_validate(self) -> None:
        result = subprocess.run([sys.executable, str(VALIDATOR)], cwd=ROOT, check=True, capture_output=True, text=True)
        self.assertIn("Asset validation passed.", result.stdout)
        self.assertIn("categories: 36", result.stdout)

    def test_asset_check_cannot_whitelist_its_own_unknown_pattern(self) -> None:
        validator = self._validator()
        with tempfile.TemporaryDirectory() as temporary:
            assets = Path(temporary) / "assets"
            shutil.copytree(ROOT / "assets", assets)
            path = assets / "security-check.example.json"
            check = json.loads(path.read_text())
            check["pattern_id"] = "unknown-pattern-not-declared-anywhere"
            path.write_text(json.dumps(check))
            output = io.StringIO()
            with mock.patch.object(validator, "ASSETS", assets), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                self.assertNotEqual(validator.main(), 0)
            self.assertIn("unknown pattern_id", output.getvalue())

    def test_result_checks_reject_fail_without_evidence(self) -> None:
        result, categories = self._result_and_categories()
        check = json.loads((ROOT / "assets/security-check.example.json").read_text())
        check.update(result="fail", evidence=[])
        result["security_checks"] = [check]
        errors = []
        self._validator().validate_result(result, "result", categories, errors)
        self.assertTrue(any("fail requires affirmative evidence" in error for error in errors))

    def test_result_checks_reject_unknown_pattern_and_malformed_rows(self) -> None:
        result, categories = self._result_and_categories()
        check = json.loads((ROOT / "assets/security-check.example.json").read_text())
        check["pattern_id"] = "unknown-pattern-not-declared-anywhere"
        result["security_checks"] = [check, None]
        errors = []
        self._validator().validate_result(result, "result", categories, errors)
        self.assertTrue(any("unknown pattern_id" in error for error in errors))
        self.assertTrue(any("must be an object" in error for error in errors))

    def test_result_checks_accept_declared_external_catalog_patterns(self) -> None:
        result, categories = self._result_and_categories()
        check = json.loads((ROOT / "assets/security-check.example.json").read_text())
        result.update(explicit_patterns=[], derived_pattern_candidates=[], security_checks=[check])
        errors = []
        self._validator().validate_result(result, "result", categories, errors, {check["pattern_id"]})
        self.assertEqual(errors, [])


    def test_hypothesis_evidence_requires_an_array_of_objects(self) -> None:
        for evidence in (None, [None]):
            with self.subTest(evidence=evidence):
                result, categories = self._result_and_categories()
                result["observations"][0].update(evidence_class="hypothesis", evidence=evidence)
                errors = []
                self._validator().validate_result(result, "result", categories, errors)
                self.assertTrue(any("evidence" in error and "must be" in error for error in errors))

    def test_malformed_result_collections_and_header_report_errors(self) -> None:
        for field, value in (("observations", None), ("observations", [None]), ("specification", None), ("derived_pattern_candidates", [None])):
            with self.subTest(field=field, value=value):
                result, categories = self._result_and_categories()
                result[field] = value
                errors = []
                self._validator().validate_result(result, "result", categories, errors)
                self.assertTrue(any("must be" in error for error in errors))

    def test_result_mode_is_required(self) -> None:
        result, categories = self._result_and_categories()
        result.pop("mode")
        errors = []
        self._validator().validate_result(result, "result", categories, errors)
        self.assertTrue(any("missing or invalid mode" in error for error in errors))

    def test_asset_result_without_mode_is_still_validated(self) -> None:
        validator = self._validator()
        with tempfile.TemporaryDirectory() as temporary:
            assets = Path(temporary) / "assets"
            shutil.copytree(ROOT / "assets", assets)
            path = assets / "spec-mining-result.example.json"
            result = json.loads(path.read_text())
            result.pop("mode")
            path.write_text(json.dumps(result))
            output = io.StringIO()
            with mock.patch.object(validator, "ASSETS", assets), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                self.assertNotEqual(validator.main(), 0)
            self.assertIn("missing or invalid mode", output.getvalue())

    def test_required_security_checks_field_cannot_be_omitted(self) -> None:
        result, categories = self._result_and_categories()
        result.pop("security_checks")
        errors = []
        self._validator().validate_result(result, "result", categories, errors)
        self.assertTrue(any("result missing" in error and "security_checks" in error for error in errors))

if __name__ == "__main__":
    unittest.main()
