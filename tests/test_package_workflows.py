import json
import subprocess
import shutil
from pathlib import Path

import pytest

from test_marketplace import initialize_marketplace, git
from reviewctl import ReviewError, compose, load_json, write_json, audit_marketplace
from package_workflows import export_native, prepare_private


def test_complete_private_update_preserves_overlay_and_refreshes_resources(tmp_path):
    repository, commit = initialize_marketplace(tmp_path)
    previous = tmp_path / "personal-v1"
    prepare_private(repository, previous)
    overlay_path = previous / "overlays/fact-check.json"
    overlay = load_json(overlay_path)
    overlay["patches"] = [{"operation": "append", "content": "Personal local preference."}]
    write_json(overlay_path, overlay)
    compose(previous / "fact-check.installation.json")
    resource = repository / "skills/fact-check/PROJECT_STATUS.md"
    resource.write_text(resource.read_text() + "\nUpdated helper resource.\n")
    git(repository, "add", ".")
    git(repository, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "resource update")
    updated = tmp_path / "personal-v2"
    result = prepare_private(repository, updated, previous)
    assert result["source_commit"] != commit
    assert "Personal local preference." in (updated / "package/skills/fact-check/SKILL.md").read_text()
    assert "Personal local preference." not in (updated / "public/skills/fact-check/SKILL.md").read_text()
    assert "Updated helper resource." in (updated / "package/skills/fact-check/PROJECT_STATUS.md").read_text()
    assert "Updated helper resource." not in (previous / "package/skills/fact-check/PROJECT_STATUS.md").read_text()
    # Shared contract discovery works from the composed package, without the checkout.
    command = updated / "package/tools/reviewctl/reviewctl"
    subprocess.run([str(command), "validate-bundle", str(updated / "package/bundles/threat-modeling-flow-v1.json")], cwd=tmp_path, check=True, capture_output=True)
    core = repository / "skills/fact-check/SKILL.md"
    core.write_text(core.read_text() + "\nConflicting upstream conclusion.\n")
    git(repository, "add", ".")
    git(repository, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "overlap")
    with pytest.raises(ReviewError, match="overlay conflict"):
        prepare_private(repository, tmp_path / "blocked", updated)
    assert not (tmp_path / "blocked").exists()


def test_native_export_keeps_dependencies_inside_plugin_and_audits_components(tmp_path):
    repository, commit = initialize_marketplace(tmp_path)
    output = tmp_path / "native"
    export_native(repository, output, commit)
    plugin = output / "plugins/web-standards-review"
    assert (plugin / "contracts/threat-modeling-flow-v1").is_dir()
    assert (plugin / "providers/w3c-knowledge/compose.yaml").is_file()
    assert (plugin / ".codex-plugin/plugin.json").is_file()
    assert (plugin / ".claude-plugin/plugin.json").is_file()
    for path in (output / ".agents/plugins/marketplace.json", output / ".claude-plugin/marketplace.json"):
        manifest = json.loads(path.read_text())
        assert manifest["plugins"][0]["name"] == "web-standards-review"
    assert not list(output.rglob(".git"))
    (repository / "providers/w3c-knowledge/unreviewed-note.md").write_text("An unreviewed note.")
    assert audit_marketplace(repository)["status"] == "blocked"


@pytest.mark.parametrize("old_version,old_count", [(2, 8), (3, 18)])
def test_additive_private_migration_preserves_existing_customization(tmp_path, old_version, old_count):
    repository, current = initialize_marketplace(tmp_path)
    catalog = load_json(repository / "catalog.yaml")
    new_skills = catalog["skills"][old_count:]
    old_catalog = {**catalog, "catalog_version": old_version, "skills": catalog["skills"][:old_count]}
    old_catalog["bundles"] = [{**catalog["bundles"][0], "version": old_version, "skills": [s["id"] for s in old_catalog["skills"]]}]
    write_json(repository / "catalog.yaml", old_catalog)
    bundle = load_json(repository / "bundles/threat-modeling-flow-v1.json")
    if old_version == 2:
        bundle.pop("horizontal_layers")
    old_ids = {row["id"] for row in old_catalog["skills"]}
    bundle["entrypoints"] = [row for row in bundle["entrypoints"] if row["skill_id"] in old_ids]
    write_json(repository / "bundles/threat-modeling-flow-v1.json", bundle)
    for row in new_skills:
        shutil.rmtree(repository / row["path"])
    git(repository, "add", ".")
    git(repository, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Legacy inventory fixture")
    previous = tmp_path / "legacy-private"
    prepare_private(repository, previous)
    overlay_path = previous / "overlays/fact-check.json"
    overlay = load_json(overlay_path)
    overlay["patches"] = [{"operation": "append", "content": "Private preference survives the migration."}]
    write_json(overlay_path, overlay)
    compose(previous / "fact-check.installation.json")
    # Restore the new package in this disposable Git fixture only.
    git(repository, "checkout", current, "--", ".")
    git(repository, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Add reviewed layers")
    with pytest.raises(ReviewError, match="allow-new-skills"):
        prepare_private(repository, tmp_path / "unacknowledged", previous)
    updated = tmp_path / "migrated"
    result = prepare_private(repository, updated, previous, allow_new_skills=True)
    assert set(result["added_skills"]) == {row["id"] for row in new_skills}
    assert "Private preference survives" in (updated / "package/skills/fact-check/SKILL.md").read_text()
    assert len(list((previous / "package/skills").glob("*/SKILL.md"))) == old_count
    assert len(list((updated / "package/skills").glob("*/SKILL.md"))) == len(catalog["skills"])
    assert (updated / "package/skills/w3c-issue-pr-review/references/marketplace-integration.md").is_file()
