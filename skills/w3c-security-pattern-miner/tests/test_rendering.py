from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELECT = ROOT / "scripts" / "select_checks.py"
RENDER = ROOT / "scripts" / "render_checklist.py"


class RenderingTests(unittest.TestCase):
    def test_rendered_checklist_preserves_ids_and_traceability(self) -> None:
        selected = subprocess.run(
            [sys.executable, str(SELECT), "--categories", "script-and-code-loading"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(selected.stdout)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(data, handle)
            path = handle.name
        rendered = subprocess.run([sys.executable, str(RENDER), path], cwd=ROOT, check=True, capture_output=True, text=True)
        first_id = data["selected_checks"][0]["check_id"]
        self.assertIn(first_id, rendered.stdout)
        self.assertIn("Pattern:", rendered.stdout)

    def test_not_applicable_fixture_contains_reason(self) -> None:
        fixture = json.loads((ROOT / "tests" / "fixtures" / "device-capability-api.json").read_text())
        self.assertTrue(all(item.get("reason") for item in fixture["not_applicable_categories"]))


if __name__ == "__main__":
    unittest.main()
