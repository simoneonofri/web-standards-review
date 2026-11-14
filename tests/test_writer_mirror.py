"""Regression checks for the privately pinned standalone writer mirror."""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def isolated_mirror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = ROOT / "scripts/check_writer_mirror.py"
    spec = importlib.util.spec_from_file_location("test_writer_mirror_module", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    dest = tmp_path / "checkout"
    (dest / "manifests/portable-entrypoints").mkdir(parents=True)
    (dest / "manifests/portable-resources").mkdir(parents=True)
    shutil.copytree(
        ROOT / "skills/write-considerations",
        dest / "skills/write-considerations",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    shutil.copytree(
        ROOT / "manifests/portable-resources/write-considerations",
        dest / "manifests/portable-resources/write-considerations",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    shutil.copy2(
        ROOT / "manifests/portable-entrypoints/write-considerations.md",
        dest / "manifests/portable-entrypoints/write-considerations.md",
    )
    shutil.copy2(
        ROOT / "manifests/standalone-writer-source.json",
        dest / "manifests/standalone-writer-source.json",
    )
    (dest / "fixtures").mkdir()
    shutil.copytree(
        ROOT / "fixtures/clean-room-demo",
        dest / "fixtures/clean-room-demo",
    )
    monkeypatch.setattr(module, "ROOT", dest)
    monkeypatch.setattr(module, "SKILL_ROOT", dest / "skills/write-considerations")
    monkeypatch.setattr(
        module, "MANIFEST", dest / "manifests/standalone-writer-source.json"
    )
    return module, dest


def test_pinned_mirror_is_verifiable_without_private_checkout(isolated_mirror):
    module, _root = isolated_mirror
    result = module.check()
    assert result["status"] == "pass", result["problems"]
    assert result["same_content_files"] >= 12
    assert result["adapted_tests"] == 2
    assert result["fixture_hashes"] == 3


def test_untracked_source_file_blocks_mirror(isolated_mirror):
    module, root = isolated_mirror
    extra = root / "skills/write-considerations/scripts/untracked.py"
    extra.write_text("def replacement(): return True\n")
    result = module.check()
    assert result["status"] == "blocked"
    assert "monorepo:untracked_or_missing_skill_source" in result["problems"]


def test_modified_adapted_test_and_fixture_block_mirror(isolated_mirror):
    module, root = isolated_mirror
    test = root / "skills/write-considerations/tests/test_composer.py"
    test.write_text(test.read_text() + "\n# altered\n")
    result = module.check()
    assert "monorepo_test:tests/test_composer.py" in result["problems"]
    fixture = root / "fixtures/clean-room-demo/model.json"
    fixture.write_text(fixture.read_text() + " ")
    result = module.check()
    assert (
        "monorepo_fixture:tests/fixtures/clean-room-demo/model.json"
        in result["problems"]
    )
