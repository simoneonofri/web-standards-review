"""Observable host-discovery and private-overlay boundary regressions."""

from pathlib import Path
from unittest.mock import patch

import pytest

from test_reviewctl import PUBLIC_CORE, dump, make_installation
from reviewctl import (ReviewError, apply_overlay, compose, drift, load_json, promote,
                       pull, section_spans, sha256_bytes)
from test_reviewctl import PROJECT


@pytest.mark.parametrize("parts", [
    ("shostack", "knowledge"), ("simone", "knowledge"),
    ("simone", "writing"), ("simone", "twin"),
])
def test_personal_adapters_cannot_enter_export_content_or_paths(tmp_path, parts):
    from reviewctl import audit_tree
    name = "-".join(parts)
    body = tmp_path / "SKILL.md"
    body.write_text("Use " + name.upper() + " as a dependency.")
    result = audit_tree(tmp_path)
    assert result["status"] == "blocked"
    assert any(row["code"] == "private-topology-name" for row in result["findings"])
    body.write_text("Generic shared skill.")
    hidden = tmp_path / "references" / (name + ".md")
    hidden.parent.mkdir()
    hidden.write_text("A private adapter under an otherwise neutral body.")
    assert audit_tree(tmp_path)["status"] == "blocked"


def configure_overlay(root: Path, patches: list[dict]) -> None:
    path = root / "private/overlay.json"
    overlay = load_json(path)
    overlay["patches"] = patches
    dump(path, overlay)


def candidate(root: Path, installation: Path, before: str, after: str, section: str) -> None:
    generated = root / "private/generated/SKILL.md"
    (root / "private/candidate.md").write_text(generated.read_text().replace(before, after))
    data = load_json(installation)
    data["promotion_candidate"] = "private/candidate.md"
    data["promotion_claims"] = {section: {"basis": "assumption", "reference": "Synthetic proposal"}}
    dump(installation, data)


def test_composed_skill_keeps_discoverable_frontmatter(tmp_path):
    installation = make_installation(tmp_path)
    compose(installation)
    text = (tmp_path / "private/generated/SKILL.md").read_text()
    assert text.startswith("---\nname: what-can-go-wrong\n")
    assert text.index("GENERATED — DO NOT EDIT") > text.index("\n---\n", 4)


def test_promotion_rejects_protected_changes_and_output_aliases(tmp_path):
    installation = make_installation(tmp_path)
    compose(installation)
    candidate(tmp_path, installation, "Produce `threat-package/v1`.", "Produce `threat-package/v2`.", "contract")
    with pytest.raises(ReviewError, match="protected"):
        promote(installation)
    candidate(tmp_path, installation, "Public prompt v1.", "Public prompt v2.", "prompt-selection")
    descriptor = load_json(installation)
    descriptor["promotion_report"] = descriptor["public"]["core"]
    dump(installation, descriptor)
    original = (tmp_path / "public/SKILL.md").read_bytes()
    with pytest.raises(ReviewError, match="distinct"):
        promote(installation)
    assert (tmp_path / "public/SKILL.md").read_bytes() == original


def test_maintainer_adaptation_requires_the_reviewed_digest(tmp_path):
    from test_reviewctl import initialize_source, publication_manifest, original
    from reviewctl import project
    _repository, commit = initialize_source(tmp_path)
    manifest = publication_manifest(commit, [original("SKILL.md")])
    adaptation = tmp_path / "adaptation.md"
    adaptation.write_text("Reviewed original adaptation.\n")
    manifest["maintainer_files"] = [{"source": "adaptation.md", "target": "references/adaptation.md",
                                    "sha256": sha256_bytes(adaptation.read_bytes()),
                                    "rights": {"source_class": "original", "rights_status": "maintainer-owned", "include_decision": "include"}}]
    path = tmp_path / "publication.json"
    dump(path, manifest)
    project(path, tmp_path, tmp_path / "pass")
    adaptation.write_text("Unreviewed replacement.\n")
    with pytest.raises(ReviewError, match="digest changed"):
        project(path, tmp_path, tmp_path / "blocked")
    assert not (tmp_path / "blocked").exists()


@pytest.mark.parametrize("operation,anchor,before,after,section", [
    ("insert_before", "optional", "Public prompt v1.", "Public prompt v2.", "prompt-selection"),
    ("append", "", "End.", "Improved end.", "tail"),
])
def test_promotion_never_copies_adjacent_private_text(tmp_path, operation, anchor, before, after, section):
    installation = make_installation(tmp_path)
    configure_overlay(tmp_path, [{"operation": operation, "section_id": anchor,
                                  "content": "Synthetic personal note not intended for sharing."}])
    compose(installation)
    candidate(tmp_path, installation, before, after, section)
    with pytest.raises(ReviewError, match="private overlay"):
        promote(installation)
    assert not (tmp_path / "promotion/public.patch").exists()


def test_private_insert_cannot_change_preceding_protected_section():
    with pytest.raises(ReviewError, match="protected"):
        apply_overlay(PUBLIC_CORE, {"patches": [{"operation": "insert_before",
                      "section_id": "source-boundary", "content": "Unexpected contract extension."}]}, Path("."))


def test_overlay_cannot_introduce_semantic_markers():
    with pytest.raises(ReviewError, match="semantic marker"):
        apply_overlay(PUBLIC_CORE, {"patches": [{"operation": "append",
                      "content": "<!-- section:synthetic -->\nPrivate addition."}]}, Path("."))


def test_pull_refuses_conflict_with_unanchored_private_append(tmp_path):
    installation = make_installation(tmp_path, update_text=PUBLIC_CORE.replace("End.", "New end."))
    configure_overlay(tmp_path, [{"operation": "append", "content": "Synthetic private tail."}])
    compose(installation)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    with pytest.raises(ReviewError, match="overlay conflict"):
        pull(installation)
    assert all(p.read_bytes() == content for p, content in before.items())


def test_changed_frontmatter_is_not_silently_discarded_by_promotion(tmp_path):
    installation = make_installation(tmp_path)
    compose(installation)
    candidate(tmp_path, installation, "description: Test public core.", "description: Changed.", "preamble")
    with pytest.raises(ReviewError, match="preamble|frontmatter"):
        promote(installation)


def test_compose_refuses_output_aliasing_core(tmp_path):
    installation = make_installation(tmp_path)
    data = load_json(installation)
    data["generated"] = data["public"]["core"]
    dump(installation, data)
    original = (tmp_path / "public/SKILL.md").read_bytes()
    with pytest.raises(ReviewError, match="distinct|overlap"):
        compose(installation)
    assert (tmp_path / "public/SKILL.md").read_bytes() == original


def test_pull_rolls_back_all_files_on_write_failure(tmp_path):
    installation = make_installation(tmp_path, update_text=PUBLIC_CORE.replace("Public prompt v1.", "Public prompt v2."))
    compose(installation)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    import reviewctl
    original = reviewctl.os.replace
    failed = False

    def fail_once(source, destination):
        nonlocal failed
        if Path(destination) == installation and not failed:
            failed = True
            raise OSError("synthetic write failure")
        return original(source, destination)

    with patch.object(reviewctl.os, "replace", side_effect=fail_once):
        with pytest.raises(OSError, match="synthetic"):
            pull(installation)
    assert failed
    assert all(p.read_bytes() == content for p, content in before.items())


@pytest.mark.parametrize("skill", [entry["id"] for entry in load_json(PROJECT / "catalog.yaml")["skills"]])
def test_every_real_skill_supports_private_composition_pull_and_promotion(tmp_path, skill):
    core = (PROJECT / "skills" / skill / "SKILL.md").read_text()
    sections = [name for name, (_, _, protected) in section_spans(core).items() if not protected]
    assert len(sections) >= 2
    private_section, public_section = sections[:2]
    marker = f"<!-- section:{public_section} -->"
    updated = core.replace(marker, marker + "\nSynthetic public improvement for review.")
    installation = make_installation(tmp_path, update_text=updated)
    (tmp_path / "public/SKILL.md").write_text(core)
    payload = load_json(installation)
    payload["skill"] = skill
    payload["public"]["artifact_digest"] = sha256_bytes(core.encode())
    payload["contract_versions"] = {}
    dump(installation, payload)
    overlay_path = tmp_path / "private/overlay.json"
    overlay = load_json(overlay_path)
    overlay["extends"]["skill"] = skill
    overlay["extends"]["digest"] = payload["public"]["artifact_digest"]
    overlay["patches"] = [{"operation": "insert_after", "section_id": private_section,
                           "content": "Synthetic personal preference."}]
    dump(overlay_path, overlay)
    compose(installation)
    candidate(tmp_path, installation, marker, marker + "\nSynthetic public improvement for review.", public_section)
    report = promote(installation)
    public_patch = (tmp_path / "promotion/public.patch").read_text()
    assert report["candidate_sections"] == [public_section]
    assert "Synthetic public improvement" in public_patch
    assert "Synthetic personal preference" not in public_patch
    assert pull(installation)["status"] == "updated"
    assert drift(installation)["status"] == "clean"
    composed = (tmp_path / "private/generated/SKILL.md").read_text()
    assert composed.startswith("---\n")
    assert "Synthetic public improvement" in composed
    assert "Synthetic personal preference" in composed
def test_projection_diff_excludes_runtime_caches(tmp_path):
    import reviewctl
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "SKILL.md").write_text("Before\n")
    (new / "SKILL.md").write_text("After\n")
    cache = old / "__pycache__"
    cache.mkdir()
    (cache / "module.pyc").write_bytes(b"\x00runtime cache data")
    diff = reviewctl.exact_tree_diff(old, new)
    assert "Before" in diff and "After" in diff
    assert "runtime cache" not in diff and "\x00" not in diff
