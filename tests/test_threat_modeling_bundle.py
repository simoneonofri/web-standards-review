from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "tools" / "reviewctl"))

from validate_bundle import BundleError, validate_bundle  # noqa: E402

MANIFEST = ROOT / "bundles" / "threat-modeling-flow-v1.json"
FIXTURES = ROOT / "fixtures" / "clean-room-demo"


class ThreatModelingBundleTests(unittest.TestCase):
    def test_complete_fixture(self) -> None:
        result = validate_bundle(MANIFEST, FIXTURES / "fixture-complete.json")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["fixture_outcome"], "complete")
        self.assertFalse(result["publication_authorized"])

    def test_partial_fixture(self) -> None:
        result = validate_bundle(MANIFEST, FIXTURES / "fixture-partial.json")
        self.assertEqual(result["fixture_outcome"], "partial")

    def test_blocked_fixture_fails_closed_as_expected(self) -> None:
        result = validate_bundle(MANIFEST, FIXTURES / "fixture-blocked.json")
        self.assertEqual(result["fixture_outcome"], "blocked")
        self.assertIn("shared-contract:failed-as-expected", result["checks"])

    def _copy_package(self) -> Path:
        temporary = Path(tempfile.mkdtemp(prefix="wsr-bundle-test-"))
        target = temporary / "web-standards-review"
        shutil.copytree(ROOT, target)
        self.addCleanup(shutil.rmtree, temporary)
        return target

    def test_stage_order_drift_is_rejected(self) -> None:
        target = self._copy_package()
        manifest_path = target / "bundles" / "threat-modeling-flow-v1.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["ordered_stages"][0], manifest["ordered_stages"][1] = (
            manifest["ordered_stages"][1],
            manifest["ordered_stages"][0],
        )
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(BundleError, "canonical five-stage order"):
            validate_bundle(manifest_path)

    def test_handoff_must_deliver_required_receiver_artifacts(self) -> None:
        target = self._copy_package()
        manifest_path = target / "bundles" / "threat-modeling-flow-v1.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["handoffs"][-1]["contracts"].remove("dfd-dictionary/v1")
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(BundleError, "missing receiver input contracts.*dfd-dictionary"):
            validate_bundle(manifest_path)

    def test_handoff_cannot_invent_an_upstream_artifact(self) -> None:
        target = self._copy_package()
        manifest_path = target / "bundles" / "threat-modeling-flow-v1.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["handoffs"][0]["contracts"].append("response-package/v1")
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(BundleError, "unavailable artifact contracts.*response-package"):
            validate_bundle(manifest_path)

    def test_workshop_deck_producer_and_optional_consumer_agree(self) -> None:
        manifest = json.loads(MANIFEST.read_text())
        catalog = json.loads((ROOT / "catalog.yaml").read_text())
        inventory = {row["id"]: row for row in catalog["skills"]}
        extension = next(row for row in manifest["optional_extensions"] if row["skill_id"] == "threat-card-generator")
        self.assertEqual(extension["produces"], ["threat-card-deck/v1"])
        self.assertEqual(extension["produces"], inventory["threat-card-generator"]["contracts"]["produces"])
        consumer = inventory[extension["consumed_by"]]["contracts"]
        self.assertIn("threat-card-deck/v1", consumer["optional_consumes"])
        self.assertIn("card-workshop-output/v1", consumer["produces"])

    def test_missing_contract_is_rejected(self) -> None:
        target = self._copy_package()
        manifest_path = target / "bundles" / "threat-modeling-flow-v1.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["shared_contract"]["validator"] = "contracts/missing.py"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(BundleError, "missing required path"):
            validate_bundle(manifest_path)

    def test_identity_mismatch_is_rejected(self) -> None:
        target = self._copy_package()
        fixture_path = target / "fixtures" / "clean-room-demo" / "fixture-complete.json"
        model_path = target / "fixtures" / "clean-room-demo" / "model.json"
        model = json.loads(model_path.read_text(encoding="utf-8"))
        model["target_id"] = "different-target"
        model_path.write_text(json.dumps(model), encoding="utf-8")
        with self.assertRaisesRegex(BundleError, "target_id identity mismatch"):
            validate_bundle(
                target / "bundles" / "threat-modeling-flow-v1.json",
                fixture_path,
            )

    def test_missing_provider_requires_blocked_outcome(self) -> None:
        target = self._copy_package()
        fixture_path = target / "fixtures" / "clean-room-demo" / "fixture-complete.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        fixture["provider_requirements"] = [
            {"interface": "ReviewEvidenceProvider", "available": False}
        ]
        fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
        with self.assertRaisesRegex(BundleError, "unavailable providers require blocked outcome"):
            validate_bundle(
                target / "bundles" / "threat-modeling-flow-v1.json",
                fixture_path,
            )

    def test_publication_approval_cannot_be_inferred(self) -> None:
        target = self._copy_package()
        manifest_path = target / "bundles" / "threat-modeling-flow-v1.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["publication_status"] = "publication_approved"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(BundleError, "not publication approval"):
            validate_bundle(manifest_path)


if __name__ == "__main__":
    unittest.main()
