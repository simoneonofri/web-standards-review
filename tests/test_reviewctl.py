from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools" / "reviewctl"))

from reviewctl import (  # noqa: E402
    ReviewError,
    apply_overlay,
    audit_tree,
    compose,
    drift,
    load_json,
    project,
    promote,
    pull,
    sha256_bytes,
)


PUBLIC_CORE = """---
name: what-can-go-wrong
description: Test public core.
---

<!-- section:contract protected -->
## Contract

Produce `threat-package/v1`.

<!-- section:source-boundary -->
## Source Boundary

Use supplied public evidence.

<!-- section:prompt-selection -->
## Prompt Selection

Public prompt v1.

<!-- section:optional -->
## Optional

Optional public behavior.

<!-- section:tail -->
## Tail

End.
"""


def dump(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=repository, check=True, capture_output=True, text=True
    ).stdout.strip()


def initialize_source(root: Path, extra: dict[str, bytes | str] | None = None) -> tuple[Path, str]:
    repository = root / "source"
    repository.mkdir()
    (repository / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Demo.\n---\n\n# Demo\n",
        encoding="utf-8",
    )
    for name, value in (extra or {}).items():
        path = repository / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(value, encoding="utf-8")
    git(repository, "init", "-q")
    git(repository, "add", "--", ".")
    git(
        repository,
        "-c",
        "user.name=Reviewctl Test",
        "-c",
        "user.email=reviewctl@example.invalid",
        "commit",
        "-q",
        "-m",
        "fixture",
    )
    return repository, git(repository, "rev-parse", "HEAD")


def publication_manifest(commit: str, include: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "publication-manifest/v1",
        "project": "web-standards-review",
        "skill_id": "demo",
        "source": {
            "repository": "example/demo",
            "repository_path": "source",
            "commit": commit,
        },
        "target_path": "skills/demo",
        "include_paths": include,
        "normalizations": [],
        "private_dependency_replacements": [],
        "human_review_decision": "approved",
        "rights_manifest_reference": "fixture#include_paths",
        "expected_public_contracts": [],
        "required_tests": ["boundary-audit"],
        "expected_output_digest": None,
    }


def original(source: str, target: str | None = None, **rights: object) -> dict[str, object]:
    decision: dict[str, object] = {
        "source_class": "original",
        "rights_status": "maintainer-owned",
        "include_decision": "include",
    }
    decision.update(rights)
    return {"source": source, "target": target or source, "rights": decision}


def make_installation(root: Path, *, update_text: str | None = None) -> Path:
    public = root / "public" / "SKILL.md"
    overlay = root / "private" / "overlay.json"
    public.parent.mkdir(parents=True)
    public.write_text(PUBLIC_CORE, encoding="utf-8")
    overlay_payload = {
        "schema_version": "private-overlay/v1",
        "extends": {
            "skill": "what-can-go-wrong",
            "version": "1.0.0",
            "commit": "old-public",
            "digest": sha256_bytes(PUBLIC_CORE.encode("utf-8")),
        },
        "overlay_version": 1,
        "protected_sections": ["contract"],
        "public_optional_sections": ["optional"],
        "patches": [
            {
                "operation": "insert_after",
                "section_id": "source-boundary",
                "content": "\nPrivate extension.\n",
            },
            {
                "operation": "register_private_provider",
                "provider_id": "local-evidence",
                "interface": "ReviewEvidenceProvider",
            },
            {
                "operation": "set_private_default",
                "key": "evidence_provider",
                "value": "local-evidence",
            },
        ],
    }
    dump(overlay, overlay_payload)
    installation: dict[str, object] = {
        "schema_version": "private-installation/v1",
        "skill": "what-can-go-wrong",
        "marketplace": "web-standards-review",
        "public": {
            "version": "1.0.0",
            "commit": "old-public",
            "artifact_digest": sha256_bytes(PUBLIC_CORE.encode("utf-8")),
            "core": "public/SKILL.md",
        },
        "overlay": "private/overlay.json",
        "generated": "private/generated/SKILL.md",
        "lock": "private/review.lock.json",
        "contract_versions": {"threat-package": "threat-package/v1"},
        "provider_interfaces": ["ReviewEvidenceProvider"],
    }
    if update_text is not None:
        update = root / "updates" / "SKILL.md"
        update.parent.mkdir()
        update.write_text(update_text, encoding="utf-8")
        installation["update"] = {
            "version": "1.1.0",
            "commit": "new-public",
            "artifact_digest": sha256_bytes(update_text.encode("utf-8")),
            "core": "updates/SKILL.md",
        }
    path = root / "installation.json"
    dump(path, installation)
    return path


def make_real_slice_installation(root: Path, *, update_text: str | None = None) -> Path:
    public = root / "public" / "SKILL.md"
    overlay = root / "private" / "overlay.json"
    public.parent.mkdir(parents=True)
    overlay.parent.mkdir(parents=True)
    source_core = PROJECT / "skills" / "what-can-go-wrong" / "SKILL.md"
    shutil.copyfile(source_core, public)
    dump(
        overlay,
        {
            "schema_version": "private-overlay/v1",
            "extends": {
                "skill": "what-can-go-wrong",
                "version": "0.1.0-local",
                "commit": "11e28d7d8b45a21b68c31156b1dc7e9b37042e3b",
                "digest": sha256_bytes(public.read_bytes()),
            },
            "overlay_version": 1,
            "protected_sections": ["contract", "contract-resolution"],
            "public_optional_sections": [],
            "patches": [
                {
                    "operation": "insert_after",
                    "section_id": "source-boundary",
                    "content": "\nPrivate provider extension for a synthetic clean-room test.\n",
                }
            ],
        },
    )
    payload: dict[str, object] = {
        "schema_version": "private-installation/v1",
        "skill": "what-can-go-wrong",
        "marketplace": "web-standards-review",
        "public": {
            "version": "0.1.0-local",
            "commit": "11e28d7d8b45a21b68c31156b1dc7e9b37042e3b",
            "artifact_digest": sha256_bytes(public.read_bytes()),
            "core": "public/SKILL.md",
        },
        "overlay": "private/overlay.json",
        "generated": "private/generated/SKILL.md",
        "lock": "private/review.lock.json",
        "contract_versions": {
            "model-packet": "model-packet/v1",
            "threat-package": "threat-package/v1",
            "threat-card-deck": "threat-card-deck/v1",
            "card-workshop-output": "card-workshop-output/v1",
        },
        "provider_interfaces": [
            "ReviewEvidenceProvider",
            "PromptSeedProvider",
            "MethodKnowledgeProvider",
            "ArtifactStore",
            "CardDeckProvider",
        ],
    }
    if update_text is not None:
        update = root / "updates" / "SKILL.md"
        update.parent.mkdir()
        update.write_text(update_text, encoding="utf-8")
        payload["update"] = {
            "version": "0.2.0-local",
            "commit": "simulated-public-update",
            "artifact_digest": sha256_bytes(update_text.encode("utf-8")),
            "core": "updates/SKILL.md",
        }
    path = root / "installation.json"
    dump(path, payload)
    return path


class ProjectionTests(unittest.TestCase):
    def test_unlisted_file_remains_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            forbidden_marker = "private" + "-provider-id\n"
            _repository, commit = initialize_source(root, {"unlisted.md": forbidden_marker})
            manifest_path = root / "manifest.json"
            dump(manifest_path, publication_manifest(commit, [original("SKILL.md")]))
            output = root / "output"
            project(manifest_path, root, output)
            self.assertFalse((output / "skills" / "demo" / "unlisted.md").exists())

    def test_symlink_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, _commit = initialize_source(root)
            (repository / "outside.md").write_text("outside\n", encoding="utf-8")
            (repository / "escape.md").symlink_to("outside.md")
            git(repository, "add", "--", "escape.md", "outside.md")
            git(repository, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "symlink")
            commit = git(repository, "rev-parse", "HEAD")
            manifest_path = root / "manifest.json"
            dump(manifest_path, publication_manifest(commit, [original("SKILL.md"), original("escape.md")]))
            with self.assertRaisesRegex(ReviewError, "symlink source is rejected"):
                project(manifest_path, root, root / "output")

    def test_binary_requires_explicit_rights_decision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _repository, commit = initialize_source(root, {"blob.bin": b"\x00\x01"})
            manifest_path = root / "manifest.json"
            dump(manifest_path, publication_manifest(commit, [original("SKILL.md"), original("blob.bin")]))
            with self.assertRaisesRegex(ReviewError, "lacks an explicit decision"):
                project(manifest_path, root, root / "output")

    def test_staged_projections_pass_exact_tree_audit(self) -> None:
        for skill in ("what-can-go-wrong", "threat-card-generator"):
            with self.subTest(skill=skill):
                root = PROJECT / "skills" / skill
                rights = load_json(root / ".review" / "rights.json")
                audit = audit_tree(root, rights)
                self.assertEqual(audit["status"], "pass", audit["findings"])
                provenance = load_json(root / ".review" / "provenance.json")
                self.assertEqual(provenance["human_review_decision"], "publication_review_required")
                self.assertTrue(provenance["source_commit"])

    def test_threat_card_projection_matches_portable_core_and_excludes_research(self) -> None:
        root = PROJECT / "skills" / "threat-card-generator"
        portable = load_json(root / "portable-core.json")
        projected = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file()
            and ".review" not in path.parts
            and "__pycache__" not in path.parts
            and path.suffix != ".pyc"
            and path.name != "PROJECT_STATUS.md"
        }
        self.assertEqual(projected, set(portable["files"]))
        for excluded in portable["excluded_roots"] + portable["excluded_research_guides"]:
            self.assertFalse((root / excluded).exists(), excluded)


class OverlayTests(unittest.TestCase):
    def test_all_overlay_operations_use_semantic_anchors(self) -> None:
        overlay = {
            "patches": [
                {"operation": "replace", "section_id": "source-boundary", "content": "Replaced.\n"},
                {"operation": "insert_before", "section_id": "prompt-selection", "content": "Before.\n"},
                {"operation": "insert_after", "section_id": "source-boundary", "content": "After.\n"},
                {"operation": "append", "section_id": "tail", "content": "Appended.\n"},
                {"operation": "remove_public_optional_section", "section_id": "optional"},
                {"operation": "register_private_provider", "provider_id": "local-evidence", "interface": "ReviewEvidenceProvider"},
                {"operation": "set_private_default", "key": "provider", "value": "local-evidence"},
            ],
            "public_optional_sections": ["optional"],
            "protected_sections": ["contract"],
        }
        result, private = apply_overlay(PUBLIC_CORE, overlay, Path("."))
        for value in ("Replaced.", "Before.", "After.", "Appended."):
            self.assertIn(value, result)
        self.assertNotIn("Optional public behavior.", result)
        self.assertEqual(private["private_providers"]["local-evidence"], "ReviewEvidenceProvider")
        self.assertEqual(private["private_defaults"]["provider"], "local-evidence")

    def test_invalid_overlay_forms_fail_closed(self) -> None:
        invalid = (
            {"patches": [{"operation": "unknown"}]},
            {"patches": [{"operation": "replace", "section_id": "missing", "content": "x"}]},
            {"patches": [{"operation": "replace", "section_id": "contract", "content": "x"}], "protected_sections": ["contract"]},
            {"patches": [{"operation": "append", "line_number": 4, "content": "x"}]},
            {"patches": [{"operation": "append", "section_id": "tail", "content": "x"}, {"operation": "append", "section_id": "tail", "content": "y"}]},
        )
        for overlay in invalid:
            with self.subTest(overlay=overlay), self.assertRaises(ReviewError):
                apply_overlay(PUBLIC_CORE, overlay, Path("."))


class CompositionTests(unittest.TestCase):
    def test_real_what_can_go_wrong_vertical_slice_is_bidirectional(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installation = make_real_slice_installation(root)
            compose(installation)
            self.assertEqual(drift(installation)["status"], "clean")
            generated = root / "private" / "generated" / "SKILL.md"
            generated_text = generated.read_text(encoding="utf-8")
            self.assertIn("threat-package/v1", generated_text)
            self.assertIn("card-workshop-output/v1", generated_text)
            candidate = root / "private" / "candidate.md"
            candidate.write_text(
                generated_text.replace(
                    "Possible providers may cover security, privacy, human rights, harms,",
                    "Approved public providers may cover security, privacy, human rights, harms,",
                ),
                encoding="utf-8",
            )
            payload = load_json(installation)
            payload["promotion_candidate"] = "private/candidate.md"
            payload["promotion_report"] = "private/promotion/provenance.json"
            payload["promotion_claims"] = {
                "prompt-selection": {
                    "basis": "assumption",
                    "reference": "Proposed public wording for human review",
                }
            }
            dump(installation, payload)
            report = promote(installation)
            patch = root / "private" / "promotion" / "public.patch"
            self.assertEqual(report["candidate_sections"], ["prompt-selection"])
            self.assertNotIn("Private provider extension", patch.read_text(encoding="utf-8"))

        real_core = (PROJECT / "skills" / "what-can-go-wrong" / "SKILL.md").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            updated = real_core.replace(
                "Possible providers may cover security, privacy, human rights, harms,",
                "Approved public providers may cover security, privacy, human rights, harms,",
            )
            installation = make_real_slice_installation(root, update_text=updated)
            compose(installation)
            result = pull(installation)
            self.assertEqual(result["conflicts"], [])
            self.assertIn("prompt-selection", result["public_changed_sections"])
            self.assertEqual(drift(installation)["status"], "clean")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conflicting = real_core.replace(
                "For target-specific claims, use the saved source corpus",
                "For target-specific claims, use an updated public source corpus",
            )
            installation = make_real_slice_installation(root, update_text=conflicting)
            compose(installation)
            with self.assertRaisesRegex(ReviewError, "explicit public/private overlay conflict"):
                pull(installation)

    def test_compose_lock_and_manual_drift_detection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            installation = make_installation(Path(temporary))
            lock = compose(installation)
            self.assertEqual(lock["marketplace"], "web-standards-review")
            generated = installation.parent / "private" / "generated" / "SKILL.md"
            self.assertIn("GENERATED — DO NOT EDIT", generated.read_text(encoding="utf-8"))
            self.assertEqual(drift(installation)["status"], "clean")
            generated.write_text(generated.read_text(encoding="utf-8") + "manual edit\n", encoding="utf-8")
            with self.assertRaisesRegex(ReviewError, "drift detected"):
                drift(installation)

    def test_non_conflicting_pull_updates_generated_file_lock_and_installation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            updated = PUBLIC_CORE.replace("Public prompt v1.", "Public prompt v2.")
            installation = make_installation(root, update_text=updated)
            compose(installation)
            result = pull(installation)
            self.assertEqual(result["conflicts"], [])
            self.assertIn("prompt-selection", result["public_changed_sections"])
            self.assertEqual(load_json(installation)["public"]["version"], "1.1.0")
            self.assertEqual(drift(installation)["status"], "clean")

    def test_conflicting_pull_is_explicit_and_preserves_old_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            updated = PUBLIC_CORE.replace("Use supplied public evidence.", "Changed public evidence behavior.")
            installation = make_installation(root, update_text=updated)
            old_lock = compose(installation)
            with self.assertRaisesRegex(ReviewError, "explicit public/private overlay conflict"):
                pull(installation)
            self.assertEqual(load_json(root / "private" / "review.lock.json"), old_lock)

    def test_promotion_subtracts_overlay_and_emits_local_public_patch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installation = make_installation(root)
            compose(installation)
            generated = root / "private" / "generated" / "SKILL.md"
            candidate = root / "private" / "candidate.md"
            candidate.write_text(
                generated.read_text(encoding="utf-8").replace("Public prompt v1.", "Public prompt improved."),
                encoding="utf-8",
            )
            payload = load_json(installation)
            payload["promotion_candidate"] = "private/candidate.md"
            payload["promotion_report"] = "private/promotion/provenance.json"
            payload["promotion_claims"] = {
                "prompt-selection": {
                    "basis": "assumption",
                    "reference": "Explicitly proposed public method assumption for review",
                }
            }
            dump(installation, payload)
            report = promote(installation)
            patch = root / "private" / "promotion" / "public.patch"
            self.assertEqual(report["remote_write"], False)
            self.assertIn("source-boundary", report["subtracted_overlay_sections"])
            self.assertIn("Public prompt improved.", patch.read_text(encoding="utf-8"))
            self.assertNotIn("Private extension.", patch.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
