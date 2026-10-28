from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MERGE = ROOT / "scripts" / "merge_catalog.py"


class CatalogMergeTests(unittest.TestCase):
    def make_catalog(self) -> Path:
        tmp = Path(tempfile.mkdtemp(prefix="w3c-spm-catalog-"))
        shutil.copytree(ROOT / "catalog", tmp / "catalog")
        return tmp / "catalog"

    def run_merge(self, catalog: Path, fixture: str, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(MERGE), "--catalog", str(catalog), "--result", str(ROOT / "tests" / "fixtures" / fixture), *extra],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_hypothesis_is_not_merged_into_accepted_catalog(self) -> None:
        catalog = self.make_catalog()
        result = self.run_merge(catalog, "device-capability-api.json", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertIn("obs-device-capability-api-03", report["hypotheses_skipped"])

    def test_multiple_occurrences_same_spec_create_one_processed_entry(self) -> None:
        catalog = self.make_catalog()
        result = self.run_merge(catalog, "persistent-storage-api.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        processed = json.loads((catalog / "processed-specifications.json").read_text())
        entries = [
            p
            for p in processed["processed_specifications"]
            if p["spec_id"] == "persistent-storage-api"
            and p["spec_version"] == "2026-01-01"
        ]
        self.assertEqual(len(entries), 1)

    def test_duplicate_processing_rejected_without_replace(self) -> None:
        catalog = self.make_catalog()
        first = self.run_merge(catalog, "identity-protocol.json")
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.run_merge(catalog, "identity-protocol.json")
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("duplicate processing", second.stderr)

    def test_replace_policy_is_idempotent_for_processed_ledger(self) -> None:
        catalog = self.make_catalog()
        first = self.run_merge(catalog, "identity-protocol.json")
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.run_merge(catalog, "identity-protocol.json", "--replace-version-run")
        self.assertEqual(second.returncode, 0, second.stderr)
        processed = json.loads((catalog / "processed-specifications.json").read_text())
        entries = [p for p in processed["processed_specifications"] if p["spec_id"] == "identity-protocol"]
        self.assertEqual(len(entries), 1)

    def test_two_versions_do_not_establish_recurrence(self) -> None:
        catalog = self.make_catalog()
        self.assertEqual(self.run_merge(catalog, "identity-protocol.json").returncode, 0)
        # The merge script only records processed versions; it never promotes recurrence.
        patterns = json.loads((catalog / "security-patterns.json").read_text())
        self.assertFalse(any(p["maturity"] == "recurring" for p in patterns["patterns"]))


if __name__ == "__main__":
    unittest.main()
