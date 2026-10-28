from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SELECTOR = ROOT / "scripts" / "select_patterns.py"


def selected_ids(fixture: str) -> set[str]:
    result = subprocess.run(
        [sys.executable, str(SELECTOR), "--input", str(ROOT / "tests" / "fixtures" / fixture)],
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(result.stdout)
    return {pattern["pattern_id"] for pattern in data["selected_patterns"]}


def selected_ids_for_args(*args: str) -> set[str]:
    result = subprocess.run(
        [sys.executable, str(SELECTOR), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(result.stdout)
    return {pattern["pattern_id"] for pattern in data["selected_patterns"]}


class PatternSelectionTests(unittest.TestCase):
    def test_device_api_selects_expected_review_concerns(self) -> None:
        ids = selected_ids("device-api.json")
        expected = {
            "tag-user-activation-intent",
            "privacy-permission-transparency-revocation",
            "privacy-fingerprinting-high-entropy",
            "privacy-device-enumeration",
            "security-secure-context-gating",
            "privacy-sensitive-physical-world-data",
        }
        self.assertTrue(expected <= ids)

    def test_identity_protocol_selects_expected_review_concerns(self) -> None:
        ids = selected_ids("identity-protocol.json")
        expected = {
            "privacy-account-enumeration",
            "privacy-stable-identifier-linkability",
            "security-trusted-ui-spoofing",
            "security-origin-binding-replay-csrf",
            "security-authn-authz-boundary",
        }
        self.assertTrue(expected <= ids)

    def test_persistent_storage_selects_expected_review_concerns(self) -> None:
        ids = selected_ids("persistent-storage.json")
        expected = {
            "privacy-partitioning-site-origin",
            "privacy-persistent-state-expiry-clearability",
            "security-origin-site-isolation",
            "security-resource-exhaustion",
        }
        self.assertTrue(expected <= ids)

    def test_data_format_selects_expected_review_concerns(self) -> None:
        ids = selected_ids("data-format.json")
        expected = {
            "tag-extensibility-forward-compat",
            "security-parser-differential-canonicalization",
            "privacy-metadata-leakage",
            "security-injection-unsafe-url",
        }
        self.assertTrue(expected <= ids)

    def test_rendering_feature_selects_expected_review_concerns(self) -> None:
        ids = selected_ids("rendering-feature.json")
        expected = {
            "tag-rendering-platform-integration",
            "tag-feature-detection",
            "tag-accessibility-i18n-defaults",
            "privacy-fingerprinting-high-entropy",
        }
        self.assertTrue(expected <= ids)

    def test_network_protocol_selects_expected_review_concerns(self) -> None:
        ids = selected_ids("network-protocol.json")
        expected = {
            "tag-url-fetch-http-integration",
            "security-cache-poisoning-integrity",
            "privacy-metadata-leakage",
            "security-downgrade-fail-open",
            "security-authn-authz-boundary",
            "security-cross-origin-information-leakage",
        }
        self.assertTrue(expected <= ids)

    def test_review_derived_media_capability_selects_expected_review_concerns(self) -> None:
        ids = selected_ids("review-derived-media-capability-fingerprinting.json")
        expected = {
            "privacy-fingerprinting-high-entropy",
            "privacy-sensitive-physical-world-data",
            "privacy-bystander-privacy",
            "privacy-permission-transparency-revocation",
            "security-malicious-media-native-input",
            "security-permission-bypass",
            "tag-user-activation-intent",
        }
        self.assertTrue(expected <= ids)

    def test_review_derived_credential_integrity_selects_expected_review_concerns(self) -> None:
        ids = selected_ids("review-derived-credential-integrity-protocol.json")
        expected = {
            "security-origin-binding-replay-csrf",
            "security-key-lifecycle-randomness-exportability",
            "security-parser-differential-canonicalization",
            "security-cache-poisoning-integrity",
            "privacy-stable-identifier-linkability",
            "privacy-network-traffic-correlation",
        }
        self.assertTrue(expected <= ids)

    def test_review_derived_policy_delegation_selects_expected_review_concerns(self) -> None:
        ids = selected_ids("review-derived-policy-delegated-capability.json")
        expected = {
            "security-capability-delegation",
            "security-permission-bypass",
            "security-trusted-ui-spoofing",
            "privacy-third-party-access",
            "privacy-fingerprinting-high-entropy",
            "tag-user-activation-intent",
        }
        self.assertTrue(expected <= ids)

    def test_review_derived_ml_native_computation_selects_expected_review_concerns(self) -> None:
        ids = selected_ids("review-derived-ml-native-computation.json")
        expected = {
            "security-resource-exhaustion",
            "security-input-validation",
            "privacy-data-minimization",
            "privacy-fingerprinting-high-entropy",
            "tag-webidl-js-consistency",
            "tag-window-worker-exposure",
        }
        self.assertTrue(expected <= ids)

    def test_sensitive_native_web_api_selects_powerful_feature_permission_gating(self) -> None:
        ids = selected_ids_for_args(
            "--primary-family",
            "computational-js-webidl-api",
            "--facets",
            "webidl-javascript,computation,window,dedicated-worker,sensitive-data,native-capability,cross-origin",
        )
        self.assertIn("security-powerful-feature-permission-gating", ids)

    def test_review_derived_charter_governance_selects_expected_review_concerns(self) -> None:
        ids = selected_ids("review-derived-charter-governance.json")
        expected = {
            "tag-review-package-readiness",
            "tag-charter-scope-deliverables",
            "tag-conceptual-model-terminology",
            "tag-incubation-implementation-signals",
            "privacy-review-package-considerations-readiness",
            "privacy-charter-scope-risk",
            "security-review-package-threat-readiness",
            "security-charter-scope-risk",
        }
        self.assertTrue(expected <= ids)

    def test_review_derived_semantic_vocabulary_selects_expected_review_concerns(self) -> None:
        ids = selected_ids("review-derived-semantic-vocabulary.json")
        expected = {
            "tag-conceptual-model-terminology",
            "tag-naming-type-design",
            "tag-extensibility-forward-compat",
            "privacy-stable-identifier-linkability",
            "privacy-metadata-leakage",
            "security-parser-differential-canonicalization",
        }
        self.assertTrue(expected <= ids)

    def test_selector_rejects_invalid_identifiers(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(SELECTOR),
                "--primary-family",
                "not-a-family",
                "--facets",
                "webidl-javascript",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid primary family", result.stderr)


    def test_null_secondary_families_match_omitted_optional_list(self) -> None:
        import copy
        import tempfile
        original = json.loads((ROOT / "tests/fixtures/device-api.json").read_text())
        outputs = []
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            for explicit_null in (False, True):
                payload = copy.deepcopy(original)
                profile = payload.get("spec_profile", payload)
                profile.pop("secondary_families", None)
                if explicit_null:
                    profile["secondary_families"] = None
                path.write_text(json.dumps(payload))
                result = subprocess.run([sys.executable, str(SELECTOR), "--input", str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs.append(json.loads(result.stdout))
        self.assertEqual(outputs[0], outputs[1])

    def test_empty_stdin_reports_input_error_without_traceback(self) -> None:
        result = subprocess.run([sys.executable, str(SELECTOR)], input="", capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("ERROR: invalid profile input", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_malformed_profiles_report_errors_without_tracebacks(self) -> None:
        payloads = [[], {"spec_profile": None}, {"primary_family": []}, {"secondary_families": [{}]}, {"facets": [{"facet_id": []}]}]
        for payload in payloads:
            with self.subTest(payload=payload):
                result = subprocess.run([sys.executable, str(SELECTOR)], input=json.dumps(payload), capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn("ERROR:", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

if __name__ == "__main__":
    unittest.main()
