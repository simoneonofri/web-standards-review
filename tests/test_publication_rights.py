"""Release approval remains scoped to the reviewed content."""
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("publication_rights", ROOT / "scripts/check_publication_rights.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PublicationRightsGateTests(unittest.TestCase):
    def fixture(self, parent):
        target = Path(parent) / "release"
        shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".ruff_cache"))
        return target

    def test_current_release_has_exact_content_approval(self):
        report = module.inspect(ROOT)
        self.assertEqual(report["status"], "approved")
        self.assertTrue(report["publication_authorized"])
        self.assertEqual(report["skill_count"], 19)

    def test_missing_approval_blocks_publication(self):
        with tempfile.TemporaryDirectory() as parent:
            target = self.fixture(parent)
            (target / "docs/PUBLICATION_APPROVAL.json").unlink()
            report = module.inspect(target)
            self.assertFalse(report["publication_authorized"])
            self.assertTrue(any("publication approval" in item for item in report["blockers"]))

    def test_changed_content_requires_new_approval(self):
        with tempfile.TemporaryDirectory() as parent:
            target = self.fixture(parent)
            readme = target / "README.md"
            readme.write_text(readme.read_text() + "\nChanged release content.\n")
            report = module.inspect(target)
            self.assertFalse(report["publication_authorized"])
            self.assertTrue(any("differs" in item for item in report["blockers"]))

    def test_private_beta_stays_blocked(self):
        with tempfile.TemporaryDirectory() as parent:
            target = self.fixture(parent)
            path = target / "catalog.yaml"
            catalog = json.loads(path.read_text())
            catalog["status"] = "private-beta"
            path.write_text(json.dumps(catalog))
            report = module.inspect(target)
            self.assertFalse(report["publication_authorized"])
            self.assertTrue(any("Private beta" in item for item in report["blockers"]))


if __name__ == "__main__":
    unittest.main()
