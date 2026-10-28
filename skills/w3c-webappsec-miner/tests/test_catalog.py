from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py"), path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CharterExtractionTests(unittest.TestCase):
    def test_extracts_named_categories_and_draft_state(self) -> None:
        module = load_script("extract_charter.py")
        html = (ROOT / "tests" / "fixtures" / "charter-mini.html").read_text(encoding="utf-8")
        result = module.extract(html)
        self.assertEqual(result["categories"], {"normative": 1, "tentative": 1, "other": 1})
        self.assertEqual(result["deliverables"][0]["draft_state"], "Working Draft")
        self.assertEqual(result["deliverables"][2]["source_url"], None)


class CatalogTests(unittest.TestCase):
    def test_validator_passes(self) -> None:
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / "validate_catalog.py")], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("controls=28", result.stdout)

    def test_renderer_contains_all_indexes(self) -> None:
        module = load_script("render_catalog.py")
        rendered = module.render()
        self.assertIn("| Reusable security controls | 28 |", rendered)
        self.assertIn("| Secure defaults | 15 |", rendered)
        self.assertIn("| Exceptions and opt-outs | 20 |", rendered)
        self.assertIn("WAM-SC-01", rendered)
        self.assertIn("WAE-20", rendered)

    def test_query_filters_exact_facet(self) -> None:
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / "query_catalog.py"), "--facet", "passkey", "--json"], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual([item["control_id"] for item in payload["controls"]], ["WAM-WELL-02"])
        self.assertEqual([item["default_id"] for item in payload["defaults"]], ["WAD-15"])

    def test_render_script_writes_requested_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "catalog.md"
            result = subprocess.run([sys.executable, str(ROOT / "scripts" / "render_catalog.py"), "--output", str(output)], cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.read_text(encoding="utf-8").startswith("# WebAppSec API security control catalog"))


    def test_query_includes_exceptions_linked_through_selected_defaults(self) -> None:
        import contextlib
        import io
        from unittest.mock import patch
        module = load_script("query_catalog.py")
        original_load = module.load
        def selected_load(path):
            data = original_load(path)
            if path == "catalog/security-controls.json":
                data["controls"] = [control for control in data["controls"] if control["control_id"] == "WAM-WELL-01"]
            return data
        output = io.StringIO()
        with patch.object(module, "load", side_effect=selected_load), patch.object(sys, "argv", ["query_catalog.py", "--json"]), contextlib.redirect_stdout(output):
            self.assertEqual(module.main(), 0)
        payload = json.loads(output.getvalue())
        expected = {value for default in payload["defaults"] for value in default["exception_ids"]}
        self.assertTrue({"WAE-01", "WAE-02", "WAE-03"} <= expected)
        self.assertTrue(expected <= {item["exception_id"] for item in payload["exceptions"]})

    def test_validator_rejects_missing_required_reference_array(self) -> None:
        from unittest.mock import patch
        module = load_script("validate_catalog.py")
        original_load = module.load
        def incomplete_load(path):
            data = original_load(path)
            if path == "catalog/security-controls.json":
                data["controls"][0].pop("default_ids")
            return data
        with patch.object(module, "load", side_effect=incomplete_load):
            errors = module.validate()
        self.assertTrue(any("default_ids must be an array" in error for error in errors))

    def test_validator_rejects_malformed_applicability_array(self) -> None:
        from unittest.mock import patch
        module = load_script("validate_catalog.py")
        original_load = module.load
        def malformed_load(path):
            data = original_load(path)
            if path == "catalog/security-controls.json":
                data["controls"][0]["applicability"] = "powerful-feature"
            return data
        with patch.object(module, "load", side_effect=malformed_load):
            errors = module.validate()
        self.assertTrue(any("applicability must be an array" in error for error in errors))

if __name__ == "__main__":
    unittest.main()
