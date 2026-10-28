from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/materialize_feature_scope.py"
SPEC = importlib.util.spec_from_file_location("materialize_feature_scope", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
ScopeError = MODULE.ScopeError
materialize = MODULE.materialize


class FeatureScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        (self.repo / "components/webmcp").mkdir(parents=True)
        (self.repo / "components/webmcp/entry.cc").write_text("entry", encoding="utf-8")
        (self.repo / "components/webmcp/control.cc").write_text("control", encoding="utf-8")
        (self.repo / "content/common").mkdir(parents=True)
        (self.repo / "content/common/ipc.cc").write_text("ipc", encoding="utf-8")
        (self.repo / "v8/src/objects").mkdir(parents=True)
        (self.repo / "v8/src/objects/value.cc").write_text("v8", encoding="utf-8")
        (self.repo / "unrelated").mkdir()
        (self.repo / "unrelated/other.cc").write_text("other", encoding="utf-8")
        (self.repo / ".git").mkdir()
        (self.repo / ".git/config").write_text("secret", encoding="utf-8")

    def manifest(self) -> dict:
        return {
            "schema_version": "w3c-spec-code-feature-scope/v1",
            "feature": {
                "id": "webmcp",
                "name": "WebMCP",
                "specification_url": "https://example.test/spec",
                "specification_revision": "abc123",
                "specification_anchors": ["#registration"],
            },
            "implementation": {"repository": "chromium", "revision": "deadbeef"},
            "entry_points": ["components/webmcp/entry.cc"],
            "feature_paths": ["components/webmcp/control.cc"],
            "supporting_paths": [
                {
                    "path": "content/common/ipc.cc",
                    "rationale": "The feature crosses this IPC trust boundary.",
                    "evidence": ["components/webmcp/entry.cc:42 calls SendMessage"],
                    "control_ids": ["CTRL-1"],
                }
            ],
            "engine_dependencies": [],
            "excluded_paths": [],
            "budgets": {"max_files": 10, "max_bytes": 10000},
        }

    def run_manifest(self, manifest: dict) -> tuple[Path, dict]:
        manifest_path = self.base / "scope.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        output = self.base / "packet"
        lock = materialize(self.repo, manifest_path, output)
        return output, lock

    def test_materializes_only_approved_feature_and_supporting_files(self) -> None:
        output, lock = self.run_manifest(self.manifest())
        self.assertTrue((output / "components/webmcp/entry.cc").is_file())
        self.assertTrue((output / "components/webmcp/control.cc").is_file())
        self.assertTrue((output / "content/common/ipc.cc").is_file())
        self.assertFalse((output / "unrelated/other.cc").exists())
        self.assertFalse((output / "v8/src/objects/value.cc").exists())
        self.assertEqual(lock["file_count"], 3)
        persisted = json.loads((output / "feature-scope.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(persisted["file_count"], 3)
        self.assertTrue(all(item["sha256"] for item in persisted["files"]))

    def test_rejects_repository_root(self) -> None:
        manifest = self.manifest()
        manifest["feature_paths"] = ["."]
        with self.assertRaises(ScopeError):
            self.run_manifest(manifest)

    def test_rejects_generic_v8_root(self) -> None:
        manifest = self.manifest()
        manifest["feature_paths"] = ["v8"]
        with self.assertRaises(ScopeError):
            self.run_manifest(manifest)

    def test_rejects_engine_path_disguised_as_feature_path(self) -> None:
        manifest = self.manifest()
        manifest["feature_paths"] = ["v8/src/objects/value.cc"]
        with self.assertRaises(ScopeError):
            self.run_manifest(manifest)

    def test_accepts_specific_evidenced_v8_dependency(self) -> None:
        manifest = self.manifest()
        manifest["engine_dependencies"] = [
            {
                "engine": "v8",
                "path": "v8/src/objects/value.cc",
                "rationale": "A reachable conversion invokes this specific V8 control.",
                "evidence": ["components/webmcp/control.cc:77 -> v8::Value"],
            }
        ]
        output, lock = self.run_manifest(manifest)
        self.assertTrue((output / "v8/src/objects/value.cc").is_file())
        self.assertIn("engine:v8", {item["category"] for item in lock["files"]})

    def test_rejects_engine_dependency_without_evidence(self) -> None:
        manifest = self.manifest()
        manifest["engine_dependencies"] = [
            {
                "engine": "v8",
                "path": "v8/src/objects/value.cc",
                "rationale": "A reachable conversion invokes this specific V8 control.",
                "evidence": [],
            }
        ]
        with self.assertRaises(ScopeError):
            self.run_manifest(manifest)

    def test_rejects_traversal(self) -> None:
        manifest = self.manifest()
        manifest["feature_paths"] = ["../outside.cc"]
        with self.assertRaises(ScopeError):
            self.run_manifest(manifest)

    def test_rejects_git_metadata(self) -> None:
        manifest = self.manifest()
        manifest["feature_paths"] = [".git/config"]
        with self.assertRaises(ScopeError):
            self.run_manifest(manifest)

    @unittest.skipIf(os.name == "nt", "symlink permissions vary on Windows")
    def test_rejects_symlink(self) -> None:
        link = self.repo / "components/webmcp/link.cc"
        link.symlink_to(self.repo / "unrelated/other.cc")
        manifest = self.manifest()
        manifest["feature_paths"] = ["components/webmcp/link.cc"]
        with self.assertRaises(ScopeError):
            self.run_manifest(manifest)

    def test_rejects_file_budget_overrun_without_partial_output(self) -> None:
        manifest = self.manifest()
        manifest["budgets"]["max_files"] = 2
        output = self.base / "packet"
        with self.assertRaises(ScopeError):
            self.run_manifest(manifest)
        self.assertFalse(output.exists())

    def test_rejects_byte_budget_overrun(self) -> None:
        manifest = self.manifest()
        manifest["budgets"]["max_bytes"] = 2
        with self.assertRaises(ScopeError):
            self.run_manifest(manifest)

    def test_rejects_manifest_budget_above_hard_limit(self) -> None:
        manifest = self.manifest()
        manifest["budgets"]["max_files"] = 5001
        with self.assertRaises(ScopeError):
            self.run_manifest(manifest)

    def test_rejects_directory_as_entry_point(self) -> None:
        manifest = self.manifest()
        manifest["entry_points"] = ["components/webmcp"]
        with self.assertRaises(ScopeError):
            self.run_manifest(manifest)

    def test_rejects_output_inside_implementation_repository(self) -> None:
        manifest = self.manifest()
        manifest_path = self.base / "scope.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(ScopeError):
            materialize(self.repo, manifest_path, self.repo / "review-packet")

    def test_engine_dependency_schema_has_no_conflicting_allof(self) -> None:
        schema_path = SCRIPT.parents[1] / "references/feature-scope.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        engine = schema["$defs"]["engineDependency"]
        self.assertNotIn("allOf", engine)
        self.assertIn("engine", engine["properties"])
        self.assertFalse(engine["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
