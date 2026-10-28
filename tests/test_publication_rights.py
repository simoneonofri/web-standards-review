"""Rights gate for private beta — no implicit publication approval."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("publication_rights", ROOT / "scripts" / "check_publication_rights.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PublicationRightsGateTests(unittest.TestCase):
    def test_fail_closed_without_publication_approval(self):
        report = module.inspect(ROOT)
        self.assertEqual(report["status"], "blocked")
        self.assertFalse(report["publication_authorized"])
        self.assertEqual(report["skill_count"], 19)
        self.assertFalse(any("distribution license" in item for item in report["blockers"]))
        self.assertTrue(any("publication approval" in item for item in report["blockers"]))
        self.assertTrue(any("fresh-history" in item for item in report["blockers"]))


if __name__ == "__main__":
    unittest.main()
