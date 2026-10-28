from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = ROOT / "contracts" / "threat-modeling-flow-v1"
FIXTURES = CONTRACT_ROOT / "tests" / "fixtures" / "threat-model-contract"
CONTRACT_WRAPPER = ROOT / "contracts" / "scripts" / "validate_threat_model_contract.py"
PROJECT_WRAPPER = ROOT / "scripts" / "validate_threat_model_contract.py"


def run(wrapper: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(wrapper), *arguments],
        text=True,
        capture_output=True,
        check=False,
    )


class SharedContractIntegrationTests(unittest.TestCase):
    def test_manifest_points_only_to_the_recovered_canonical_validator(self) -> None:
        manifest = json.loads(
            (ROOT / "contracts" / "shared-contract-v1.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["contract_version"], 1)
        self.assertEqual(
            manifest["canonical_validator"],
            "contracts/threat-modeling-flow-v1/scripts/validate_threat_model_contract.py",
        )
        self.assertEqual(
            manifest["provenance"]["source_commit"],
            "5e0ab09556b35a32df9f15c61005e3b21b14a3fd",
        )
        self.assertTrue((ROOT / manifest["canonical_validator"]).is_file())

    def test_contract_wrapper_accepts_the_phase_a_pipeline(self) -> None:
        result = run(
            CONTRACT_WRAPPER,
            "--model", str(FIXTURES / "model-valid.json"),
            "--dictionary", str(FIXTURES / "dictionary-valid.json"),
            "--threats", str(FIXTURES / "threat-valid.json"),
            "--responses", str(FIXTURES / "response-valid.json"),
            "--require-complete-response-coverage",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_project_wrapper_delegates_to_the_same_contract(self) -> None:
        result = run(PROJECT_WRAPPER, "--handoff", str(FIXTURES / "handoff-valid.json"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
