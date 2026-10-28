from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog"


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = json.loads((CATALOG / "inventory.json").read_text(encoding="utf-8"))
        cls.features = json.loads((CATALOG / "security-features.json").read_text(encoding="utf-8"))
        cls.coverage = json.loads((CATALOG / "coverage.json").read_text(encoding="utf-8"))

    def test_inventory_is_complete_and_current_snapshot_is_self_consistent(self) -> None:
        standards = self.inventory["standards"]
        self.assertEqual(self.inventory["standard_count"], len(standards))
        self.assertGreaterEqual(len(standards), 20)
        self.assertEqual(len({item["id"] for item in standards}), len(standards))
        self.assertTrue(all(item["url"].startswith("https://") and ".spec.whatwg.org" in item["url"] for item in standards))

    def test_every_standard_has_coverage(self) -> None:
        inventory_ids = {item["id"] for item in self.inventory["standards"]}
        coverage_ids = {item["standard_id"] for item in self.coverage["standards"]}
        self.assertEqual(inventory_ids, coverage_ids)

    def test_counts_are_derived_from_findings(self) -> None:
        findings = self.features["findings"]
        self.assertEqual(self.features["finding_count"], len(findings))
        self.assertEqual(self.features["counts_by_category"], dict(sorted(Counter(item["category"] for item in findings).items())))
        self.assertEqual(self.features["counts_by_standard"], dict(sorted(Counter(item["standard_id"] for item in findings).items())))

    def test_curated_findings_exclude_candidates_and_privacy_only(self) -> None:
        for finding in self.features["findings"]:
            self.assertIn(finding["confidence"], {"high", "medium"})
            self.assertIn(finding["evidence_class"], {"security_control", "security_rationale"})
            self.assertTrue(finding["url"].startswith("https://"))
            self.assertIn("#", finding["url"])

    def test_catalog_build_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            subprocess.run([
                sys.executable,
                str(ROOT / "scripts/build_catalog.py"),
                "--inventory", str(CATALOG / "inventory.json"),
                "--seed", str(ROOT / "references/seed-findings.json"),
                "--coverage-seed", str(ROOT / "references/coverage-seed.json"),
                "--output-dir", str(output),
                "--verified-on", self.features["verified_on"],
            ], check=True)
            for name in ("security-features.json", "security-features.md", "coverage.json", "coverage.md"):
                self.assertEqual((CATALOG / name).read_bytes(), (output / name).read_bytes())


    def test_standard_filter_handles_findings_without_optional_display_name(self) -> None:
        import copy
        record = copy.deepcopy(self.features["findings"][0])
        record.pop("standard", None)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "catalog.json"
            path.write_text(json.dumps({"findings": [record]}))
            for needle, expected_count in ((record["standard_id"], 1), ("no-matching-standard", 0)):
                with self.subTest(needle=needle):
                    result = subprocess.run([sys.executable, str(ROOT / "scripts/query_catalog.py"), "--catalog", str(path), "--standard", needle, "--json"], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(len(json.loads(result.stdout)), expected_count)

if __name__ == "__main__":
    unittest.main()
