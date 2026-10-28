from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NORMALIZE = ROOT / "scripts" / "normalize_result.py"


class NormalizationTests(unittest.TestCase):
    def run_normalize(self, fixture: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(NORMALIZE), str(ROOT / "tests" / "fixtures" / fixture)], cwd=ROOT, capture_output=True, text=True)

    def test_one_specification_version_is_accepted(self) -> None:
        result = self.run_normalize("device-capability-api.json")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mixed_versions_are_rejected(self) -> None:
        result = self.run_normalize("mixed-version-invalid.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("multiple specification versions", result.stderr)

    def test_evidence_spans_survive_normalization(self) -> None:
        result = self.run_normalize("device-capability-api.json")
        data = json.loads(result.stdout)
        spans = [ev["evidence_span"] for obs in data["observations"] for ev in obs.get("evidence", [])]
        self.assertIn("If document does not have transient activation, reject with NotAllowedError.", spans)

    def test_normative_algorithm_without_security_considerations_produces_observation(self) -> None:
        result = self.run_normalize("device-capability-api.json")
        data = json.loads(result.stdout)
        self.assertTrue(any(obs["evidence_class"] == "derived-from-algorithm" for obs in data["observations"]))

    def test_informative_text_does_not_become_normative(self) -> None:
        result = self.run_normalize("media-processing-api.json")
        data = json.loads(result.stdout)
        self.assertTrue(any(obs["evidence_class"] == "explicit-informative" for obs in data["observations"]))
        self.assertFalse(any(obs["statement"].startswith("Encoded media") and obs["evidence_class"] == "explicit-normative" for obs in data["observations"]))

    def test_derived_pattern_requires_derivation_chain(self) -> None:
        result = self.run_normalize("device-capability-api.json")
        data = json.loads(result.stdout)
        chain = data["derived_pattern_candidates"][0]["derivation_chain"]
        self.assertIn("premises", chain)
        self.assertIn("inference_rule", chain)

    def test_cross_reference_derivation_has_reduced_confidence(self) -> None:
        result = self.run_normalize("lifecycle-feature.json")
        data = json.loads(result.stdout)
        cross_ref = [obs for obs in data["observations"] if obs["evidence_class"] == "derived-from-cross-reference"]
        self.assertTrue(cross_ref)
        self.assertLess(cross_ref[0]["confidence"], 0.75)


if __name__ == "__main__":
    unittest.main()
