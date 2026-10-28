"""Fresh native distribution and complete private workspace preparation."""

import shutil
import tempfile
from pathlib import Path

import reviewctl as bridge


def fresh_output(output: Path, root: Path, previous: Path | None = None) -> None:
    if output.exists() or output.is_symlink():
        raise bridge.ReviewError("output must be a new directory")
    if output.resolve().is_relative_to(root.resolve()):
        raise bridge.ReviewError("generated packages belong outside the source checkout")
    if previous and output.resolve().is_relative_to(previous.resolve()):
        raise bridge.ReviewError("new private workspace must be outside the previous workspace")


def export_native(root: Path, output: Path, ref: str | None = None) -> dict:
    fresh_output(output, root)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="reviewctl-native-", dir=output.parent) as temporary:
        stage = Path(temporary) / "marketplace"
        name = "web-standards-review"
        plugin = stage / "plugins" / name
        result = bridge.export_marketplace(root, plugin, ref)
        version = "0.4.0+" + result["source_commit"][:12]
        common = {"name": name, "version": version,
                  "description": "Portable standards issue/PR review, specification review and threat modeling workflows.",
                  "author": {"name": "Simone Onofri"}, "skills": "./skills/"}
        # Codex fields follow the official plugin-creator scaffold. The whole
        # dependency tree stays in the plugin root copied by either host cache.
        bridge.write_json(plugin / ".codex-plugin/plugin.json", {**common, "interface": {
            "displayName": "Web Standards Review", "shortDescription": "Review standards issues, PRs and specifications.",
            "longDescription": "Portable issue/PR and horizontal review skills, shared contracts and an optional local vector evidence service.",
            "developerName": "Simone Onofri", "category": "Productivity", "capabilities": [],
            "defaultPrompt": "Use w3c-issue-pr-review for a standards issue or PR, or spec-review for a specification snapshot."}})
        bridge.write_json(plugin / ".claude-plugin/plugin.json", common)
        bridge.write_json(stage / ".agents/plugins/marketplace.json", {
            "name": name, "interface": {"displayName": "Web Standards Review"}, "plugins": [{
                "name": name, "source": {"source": "local", "path": "./plugins/" + name},
                "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                "category": "Productivity"}]})
        bridge.write_json(stage / ".claude-plugin/marketplace.json", {
            "name": name, "owner": {"name": "Simone Onofri"},
            "plugins": [{"name": name, "source": "./plugins/" + name, "version": version}]})
        audit = bridge.audit_tree(stage)
        if audit["status"] != "pass":
            raise bridge.ReviewError("native package boundary audit failed")
        bridge.write_json(stage / "distribution.json", {
            "schema_version": "native-marketplace/v1", "source_commit": result["source_commit"],
            "publication_status": "publication_review_required", "files": bridge.file_inventory(stage)})
        stage.rename(output)
    return {"status": "exported", "output": str(output), "source_commit": result["source_commit"],
            "publication_status": "publication_review_required", "remote_write": False}


def prepare_private(root: Path, output: Path, previous: Path | None = None, *, allow_new_skills: bool = False) -> dict:
    """Prepare a new full package; never mutate the previous installation."""
    fresh_output(output, root, previous)
    previous_manifest = None
    if previous:
        previous_manifest = bridge.load_json(previous / "workspace.json", "private-workspace/v1")
        bridge.verify_snapshot(previous / "public", previous_manifest["source_commit"], previous_manifest["manifest_digest"])
        # Byte inventory rejects symlinks before copying private overlay resources.
        bridge.file_inventory(previous / "overlays")
        for identifier in previous_manifest["skills"]:
            bridge.safe_relative(identifier, "skill")
            bridge.drift(previous / (identifier + ".installation.json"))
        expected_resources = previous_manifest["package_resources"]
        if package_resources(previous / "package") != expected_resources:
            raise bridge.ReviewError("private package resource drift; preserve changes separately before updating")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="reviewctl-private-", dir=output.parent) as temporary:
        stage = Path(temporary) / "workspace"
        result = bridge.export_marketplace(root, stage / "public", None)
        catalog = bridge.load_catalog(stage / "public")
        identifiers = list(bridge.catalog_entries(catalog, "skills"))
        old_ids = previous_manifest["skills"] if previous_manifest else []
        added = [identifier for identifier in identifiers if identifier not in old_ids]
        if previous_manifest and identifiers != old_ids:
            if not allow_new_skills or not set(old_ids).issubset(identifiers) or [i for i in identifiers if i in old_ids] != old_ids:
                raise bridge.ReviewError("skill inventory changed; use --allow-new-skills for additive migration only")
            for identifier in added:
                if (previous / "overlays" / (identifier + ".json")).exists():
                    raise bridge.ReviewError("new skill collides with an unregistered private overlay")
        if previous and bridge.artifact_digest(previous / "public/contracts") != bridge.artifact_digest(stage / "public/contracts"):
            raise bridge.ReviewError("shared contracts changed; explicit private workspace migration required")
        shutil.copytree(stage / "public", stage / "package")
        if previous:
            shutil.copytree(previous / "overlays", stage / "overlays")
        else:
            (stage / "overlays").mkdir()
        for identifier in identifiers:
            core = stage / "public/skills" / identifier / "SKILL.md"
            core_text = core.read_text()
            digest = bridge.sha256_bytes(core.read_bytes())
            version = str(catalog["catalog_version"])
            overlay_path = stage / "overlays" / (identifier + ".json")
            interfaces = []
            contracts = {}
            if previous and identifier in old_ids:
                prior_descriptor = previous / (identifier + ".installation.json")
                prior, old_core, old_overlay, _generated, _lock = bridge.installation_paths(prior_descriptor)
                overlay = bridge.load_json(old_overlay, "private-overlay/v1")
                if old_overlay != (previous / "overlays" / (identifier + ".json")).resolve():
                    raise bridge.ReviewError("private overlay must stay at its workspace path")
                conflicts = bridge.changed_sections(old_core.read_text(), core_text) & bridge.overlay_owned_sections(old_core.read_text(), overlay, old_overlay.parent)
                if conflicts:
                    raise bridge.ReviewError(f"explicit public/private overlay conflict in {identifier}: {', '.join(sorted(conflicts))}")
                interfaces = prior.get("provider_interfaces", [])
                contracts = prior.get("contract_versions", {})
            else:
                overlay = {"schema_version": "private-overlay/v1", "overlay_version": 1,
                           "protected_sections": [], "patches": []}
            overlay["extends"] = {"skill": identifier, "version": version,
                                  "commit": result["source_commit"], "digest": digest}
            bridge.write_json(overlay_path, overlay)
            descriptor = {"schema_version": "private-installation/v1", "skill": identifier,
                          "marketplace": "web-standards-review", "public": {
                              "version": version, "commit": result["source_commit"],
                              "artifact_digest": digest, "core": f"public/skills/{identifier}/SKILL.md"},
                          "overlay": f"overlays/{identifier}.json", "generated": f"package/skills/{identifier}/SKILL.md",
                          "lock": f"locks/{identifier}.json", "contract_versions": contracts,
                          "provider_interfaces": interfaces}
            descriptor_path = stage / (identifier + ".installation.json")
            bridge.write_json(descriptor_path, descriptor)
            bridge.compose(descriptor_path)
        bridge.write_json(stage / "workspace.json", {
            "schema_version": "private-workspace/v1", "source_commit": result["source_commit"],
            "manifest_digest": bridge.sha256_bytes((stage / "public/.review/export-manifest.json").read_bytes()),
            "skills": identifiers, "added_skills": added, "package_resources": package_resources(stage / "package"),
            "publication_authorized": False})
        stage.rename(output)
    return {"status": "prepared", "source_commit": result["source_commit"], "skills": identifiers,
            "previous_unchanged": True, "added_skills": added, "publication_authorized": False}


def package_resources(package: Path) -> list[dict]:
    return [row for row in bridge.file_inventory(package)
            if not (row["path"].startswith("skills/") and row["path"].endswith("/SKILL.md"))]
