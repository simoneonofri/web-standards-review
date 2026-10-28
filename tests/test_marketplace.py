from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools" / "reviewctl"))

from reviewctl import (  # noqa: E402
    EXPECTED_PRIVATE_BETA_SKILLS,
    ReviewError,
    audit_marketplace,
    export_marketplace,
    install_marketplace,
    load_catalog,
    marketplace_status,
    uninstall_marketplace,
    update_marketplace,
)


def git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def initialize_marketplace(parent: Path) -> tuple[Path, str]:
    repository = parent / "marketplace"
    shutil.copytree(
        PROJECT,
        repository,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".DS_Store"),
    )
    git(repository, "init", "-q", "-b", "main")
    git(repository, "add", "--", ".")
    git(
        repository,
        "-c",
        "user.name=Marketplace Test",
        "-c",
        "user.email=marketplace@example.invalid",
        "commit",
        "-q",
        "-m",
        "fixture",
    )
    return repository, git(repository, "rev-parse", "HEAD")


def clean_room_environment(root: Path) -> dict[str, str]:
    return {
        "WEB_STANDARDS_REVIEW_CODEX_SKILLS_ROOT": str(root / "codex" / "skills"),
        "WEB_STANDARDS_REVIEW_CLAUDE_SKILLS_ROOT": str(root / "claude" / "skills"),
        "WEB_STANDARDS_REVIEW_STATE_DIR": str(root / "state"),
    }


class CatalogAndAuditTests(unittest.TestCase):
    def test_catalog_is_complete_and_no_unlisted_skill_is_installable(self) -> None:
        catalog = load_catalog(PROJECT)
        self.assertEqual(
            [entry["id"] for entry in catalog["skills"]],
            list(EXPECTED_PRIVATE_BETA_SKILLS),
        )
        self.assertEqual(catalog["bundles"][0]["skills"], list(EXPECTED_PRIVATE_BETA_SKILLS))
        self.assertEqual(catalog["status"], "public-beta")
        self.assertIs(catalog["publication_review_required"], True)

    def test_exact_tree_boundary_and_skill_rights_audit_passes(self) -> None:
        result = audit_marketplace(PROJECT)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["boundary_findings"], [])
        self.assertEqual(result["rights_findings"], [])
        self.assertEqual(set(result["skills"]), set(EXPECTED_PRIVATE_BETA_SKILLS))


class InstallerTests(unittest.TestCase):
    def test_catalog_then_install_dry_run_keeps_checkout_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, _commit = initialize_marketplace(root)
            environment = dict(os.environ)
            environment.update(clean_room_environment(root / "homes"))
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            environment.pop("PYTHONPYCACHEPREFIX", None)
            for arguments in (
                ["catalog"],
                ["install", "--bundle", "threat-modeling-flow-v1", "--host", "all", "--dry-run"],
            ):
                result = subprocess.run(
                    [sys.executable, "tools/reviewctl/reviewctl", *arguments],
                    cwd=repository,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(git(repository, "status", "--porcelain"), "")

    def test_bundle_install_is_dry_runnable_reversible_and_host_equivalent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, commit = initialize_marketplace(root)
            environment = clean_room_environment(root / "homes")
            with mock.patch.dict(os.environ, environment, clear=False):
                dry_run = install_marketplace(
                    repository,
                    skill_id=None,
                    bundle_id="threat-modeling-flow-v1",
                    host="all",
                    dry_run=True,
                    replace_link=False,
                    state_dir=None,
                )
                self.assertEqual(dry_run["status"], "dry-run")
                self.assertEqual(dry_run["commit"], commit)
                self.assertEqual(len(dry_run["actions"]), 2 * len(EXPECTED_PRIVATE_BETA_SKILLS))
                self.assertFalse((root / "homes" / "state" / "install.lock.json").exists())

                installed = install_marketplace(
                    repository,
                    skill_id=None,
                    bundle_id="threat-modeling-flow-v1",
                    host="all",
                    dry_run=False,
                    replace_link=False,
                    state_dir=None,
                )
                self.assertEqual(installed["status"], "installed")
                lock_path = root / "homes" / "state" / "install.lock.json"
                lock = json.loads(lock_path.read_text(encoding="utf-8"))
                self.assertEqual(lock["commit"], commit)
                self.assertEqual(lock["installed_skills"], sorted(EXPECTED_PRIVATE_BETA_SKILLS))
                for identifier in EXPECTED_PRIVATE_BETA_SKILLS:
                    codex = root / "homes" / "codex" / "skills" / identifier
                    claude = root / "homes" / "claude" / "skills" / identifier
                    self.assertTrue(codex.is_symlink())
                    self.assertTrue(claude.is_symlink())
                    self.assertEqual(codex.resolve(), claude.resolve())
                    self.assertEqual(codex.resolve(), Path(lock["snapshot_path"]) / "skills" / identifier)
                    self.assertNotEqual(codex.resolve(), (repository / "skills" / identifier).resolve())
                self.assertEqual(marketplace_status()["status"], "clean")

                preview = uninstall_marketplace(host="all", dry_run=True)
                self.assertEqual(len(preview["actions"]), 2 * len(EXPECTED_PRIVATE_BETA_SKILLS))
                uninstall_marketplace(host="all", dry_run=False)
                self.assertFalse(lock_path.exists())
                self.assertEqual(marketplace_status()["status"], "not-installed")

    def test_non_symlink_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, _commit = initialize_marketplace(root)
            environment = clean_room_environment(root / "homes")
            collision = Path(environment["WEB_STANDARDS_REVIEW_CODEX_SKILLS_ROOT"]) / "fact-check"
            collision.mkdir(parents=True)
            with mock.patch.dict(os.environ, environment, clear=False):
                with self.assertRaisesRegex(ReviewError, "refusing non-symlink"):
                    install_marketplace(
                        repository,
                        skill_id="fact-check",
                        bundle_id=None,
                        host="codex",
                        dry_run=False,
                        replace_link=True,
                        state_dir=None,
                    )

    def test_unrelated_symlink_requires_explicit_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, _commit = initialize_marketplace(root)
            environment = clean_room_environment(root / "homes")
            unrelated = root / "unrelated"
            unrelated.mkdir()
            collision = Path(environment["WEB_STANDARDS_REVIEW_CODEX_SKILLS_ROOT"]) / "fact-check"
            collision.parent.mkdir(parents=True)
            os.symlink(unrelated, collision)
            with mock.patch.dict(os.environ, environment, clear=False):
                with self.assertRaisesRegex(ReviewError, "refusing unrelated symlink"):
                    install_marketplace(
                        repository,
                        skill_id="fact-check",
                        bundle_id=None,
                        host="codex",
                        dry_run=False,
                        replace_link=False,
                        state_dir=None,
                    )
                install_marketplace(
                    repository,
                    skill_id="fact-check",
                    bundle_id=None,
                    host="codex",
                    dry_run=False,
                    replace_link=True,
                    state_dir=None,
                )
                self.assertEqual(collision.resolve().parent.parent.parent.name, "snapshots")
                self.assertEqual((collision / "SKILL.md").read_bytes(), (repository / "skills/fact-check/SKILL.md").read_bytes())

    def test_update_dry_run_reports_exact_commits_and_affected_skill(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, old_commit = initialize_marketplace(root)
            environment = clean_room_environment(root / "homes")
            with mock.patch.dict(os.environ, environment, clear=False):
                install_marketplace(
                    repository,
                    skill_id="fact-check",
                    bundle_id=None,
                    host="all",
                    dry_run=False,
                    replace_link=False,
                    state_dir=None,
                )
                status_path = repository / "skills" / "fact-check" / "PROJECT_STATUS.md"
                status_path.write_text(
                    status_path.read_text(encoding="utf-8") + "\nSynthetic update fixture.\n",
                    encoding="utf-8",
                )
                git(repository, "add", "--", "skills/fact-check/PROJECT_STATUS.md")
                git(
                    repository,
                    "-c",
                    "user.name=Marketplace Test",
                    "-c",
                    "user.email=marketplace@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "update fixture",
                )
                new_commit = git(repository, "rev-parse", "HEAD")
                self.assertNotEqual(old_commit, new_commit)
                installed_link = Path(environment["WEB_STANDARDS_REVIEW_CODEX_SKILLS_ROOT"]) / "fact-check"
                self.assertNotIn("Synthetic update fixture", (installed_link / "PROJECT_STATUS.md").read_text())
                preview = update_marketplace(dry_run=True)
                self.assertEqual(preview["old_commit"], old_commit)
                self.assertEqual(preview["new_commit"], new_commit)
                self.assertEqual(preview["affected_skills"], ["fact-check"])
                self.assertEqual(marketplace_status()["status"], "drift")
                update_marketplace(dry_run=False)
                self.assertIn("Synthetic update fixture", (installed_link / "PROJECT_STATUS.md").read_text())
                self.assertEqual(marketplace_status()["status"], "clean")

                # Shared dependencies are part of the accepted snapshot too.
                shared = installed_link.resolve().parents[1] / "contracts/shared-contract-v1.json"
                shared.write_text(shared.read_text() + "\n")
                self.assertIn("snapshot-drift", [item["code"] for item in marketplace_status()["findings"]])
                with self.assertRaisesRegex(ReviewError, "snapshot has changed"):
                    update_marketplace(dry_run=False)


class ExportTests(unittest.TestCase):
    def test_export_preserves_blobs_despite_git_attributes_and_rejects_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, _commit = initialize_marketplace(root)
            readme = repository / "README.md"
            readme.write_text(readme.read_text() + "\n$Format:%H$\n")
            (repository / ".gitattributes").write_text("README.md export-subst\nPROJECT_STATUS.md export-ignore\n")
            git(repository, "add", ".")
            git(repository, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "attributes")
            output = root / "export"
            export_marketplace(repository, output, git(repository, "rev-parse", "HEAD"))
            self.assertEqual((output / "README.md").read_bytes(), readme.read_bytes())
            self.assertTrue((output / "PROJECT_STATUS.md").exists())
            (repository / "docs/unreviewed-link.md").symlink_to("../README.md")
            git(repository, "add", ".")
            git(repository, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "link")
            with self.assertRaisesRegex(ReviewError, "symlink"):
                export_marketplace(repository, root / "blocked", None)
            self.assertFalse((root / "blocked").exists())

    def test_export_is_fresh_audited_local_only_and_has_no_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, commit = initialize_marketplace(root)
            output = root / "publication-candidate"
            result = export_marketplace(repository, output, commit)
            self.assertEqual(result["source_commit"], commit)
            self.assertEqual(result["publication_status"], "publication_review_required")
            self.assertIs(result["remote_write"], False)
            self.assertFalse((output / ".git").exists())
            self.assertFalse((output / ".github").exists())
            self.assertFalse((output / "docs" / "private-beta.md").exists())
            self.assertTrue(os.access(output / "tools" / "reviewctl" / "reviewctl", os.X_OK))
            manifest = json.loads(
                (output / ".review" / "export-manifest.json").read_text(encoding="utf-8")
            )
            report = json.loads(
                (output / ".review" / "review-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["source_commit"], commit)
            self.assertGreater(len(manifest["files"]), 100)
            self.assertEqual(report["boundary_status"], "pass")
            self.assertEqual(report["rights_status"], "pass")
            self.assertIs(report["human_review_required"], True)

    def test_export_requires_an_exact_commit_and_new_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, commit = initialize_marketplace(root)
            with self.assertRaisesRegex(ReviewError, "exact 40-character commit"):
                export_marketplace(repository, root / "bad-ref", "main")
            existing = root / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(ReviewError, "already exists"):
                export_marketplace(repository, existing, commit)


if __name__ == "__main__":
    unittest.main()
