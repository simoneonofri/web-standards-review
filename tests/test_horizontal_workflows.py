import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


horizontal = module("portable_horizontal_packet", ROOT / "skills/w3c-horizontal-review/scripts/horizontal_packet.py")


def packet(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("Synthetic target: user permission is required.")
    evidence = {"path": "source.txt", "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
    run = horizontal.initialize({"id": "synthetic", "kind": "specification", "snapshot_url": "https://example.test/v1/", "sha256": evidence["sha256"]})
    run["evidence"] = [{"id": "target-1", "role": "target", "locator": "section 1", "artifact": evidence}]
    for row in [*run["extractors"], *run["flows"].values()]:
        if row["state"] == "planned":
            row.update(state="completed", rationale="Synthetic control-flow fixture", artifacts=[evidence])
    run["independent_before_reconciliation"] = True
    return run


def test_work_order_does_not_claim_execution(tmp_path):
    run = packet(tmp_path)
    fresh = horizontal.initialize(run["target"])
    assert horizontal.validate(fresh, tmp_path)["status"] == "blocked"
    assert horizontal.validate(run, tmp_path)["status"] == "complete"
    run["flows"]["implementation"]["state"] = "unavailable"
    assert horizontal.validate(run, tmp_path)["status"] == "partial"


def test_unknown_evidence_and_false_control_verdict_fail(tmp_path):
    run = packet(tmp_path)
    run["checks"] = [{"id": "c1", "extractor": "w3c-webappsec-miner", "source_evidence_ids": ["target-1"], "target_evidence_ids": [], "status": "pass", "rationale": "Control confirmed"}]
    with pytest.raises(ValueError, match="affirmative"):
        horizontal.validate(run, tmp_path)
    run["checks"][0]["target_evidence_ids"] = ["missing"]
    with pytest.raises(ValueError, match="unknown evidence"):
        horizontal.validate(run, tmp_path)
    run["checks"][0]["target_evidence_ids"] = ["target-1"]
    run["evidence"][0]["role"] = "method"
    with pytest.raises(ValueError, match="substitute"):
        horizontal.validate(run, tmp_path)


def test_prompt_route_and_target_snapshot_cannot_be_bypassed(tmp_path):
    run = packet(tmp_path)
    run["checks"] = [{"id": "c1", "extractor": "threat-knowledge", "source_evidence_ids": ["target-1"], "target_evidence_ids": [], "status": "not_evaluated", "rationale": "A prompt"}]
    with pytest.raises(ValueError, match="modeling queue"):
        horizontal.validate(run, tmp_path)
    run["checks"] = []
    run["evidence"] = []
    with pytest.raises(ValueError, match="captured target"):
        horizontal.validate(run, tmp_path)


def test_public_projection_cannot_promote_implementation_bug(tmp_path):
    run = packet(tmp_path)
    run["findings"] = [{"id": "f1", "ownership": "implementation", "disposition": "accepted", "rationale": "Synthetic mismatch", "evidence_ids": ["target-1"], "mechanism": "Synthetic", "impact": "Bounded", "affected_property": "Permission"}]
    run["public_projection"] = ["f1"]
    with pytest.raises(ValueError, match="implementation or unvalidated"):
        horizontal.validate(run, tmp_path)


def test_artifact_drift_and_skipped_requested_flow_fail(tmp_path):
    run = packet(tmp_path)
    run["flows"]["independent"]["state"] = "not_applicable"
    with pytest.raises(ValueError, match="cannot be silently skipped"):
        horizontal.validate(run, tmp_path)
    run["flows"]["independent"]["state"] = "completed"
    run["independent_before_reconciliation"] = False
    with pytest.raises(ValueError, match="precede"):
        horizontal.validate(run, tmp_path)
    run["independent_before_reconciliation"] = True
    (tmp_path / "source.txt").write_text("Changed snapshot")
    with pytest.raises(ValueError, match="hash changed"):
        horizontal.validate(run, tmp_path)


def test_pending_threat_queue_and_missing_registry_stay_visible(tmp_path):
    run = packet(tmp_path)
    run["threat_queue"] = [{"id": "t1", "extractor": "threat-knowledge", "source_evidence_ids": ["target-1"], "as_is_relationship": "pending", "rationale": "Not elicited yet"}]
    assert horizontal.validate(run, tmp_path)["status"] == "partial"
    run["extractors"].pop()
    with pytest.raises(ValueError, match="registry is incomplete"):
        horizontal.validate(run, tmp_path)


def test_feature_packet_rejects_a_false_commit_label_and_dirty_bytes(tmp_path, monkeypatch):
    scripts = ROOT / "skills/w3c-spec-code/scripts"
    monkeypatch.syspath_prepend(str(scripts))
    wrapper = module("portable_pinned_scope", scripts / "materialize_pinned_scope.py")
    repo = tmp_path / "repository"
    repo.mkdir()
    feature = repo / "feature"
    feature.mkdir()
    (feature / "entry.py").write_text("checked = True\n")
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()
    git("init", "-q")
    git("add", "feature/entry.py")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "Fixture")
    commit = git("rev-parse", "HEAD")
    data = {"schema_version": "w3c-spec-code-feature-scope/v1", "feature": {"id": "example"}, "implementation": {"repository": "fixture", "revision": commit}, "entry_points": ["feature/entry.py"], "feature_paths": ["feature/entry.py"], "supporting_paths": [], "engine_dependencies": [], "excluded_paths": [], "budgets": {"max_files": 10, "max_bytes": 1000}}
    manifest = tmp_path / "scope.json"
    manifest.write_text(json.dumps(data))
    assert wrapper.materialize_pinned(repo, manifest, tmp_path / "good")["revision_verified"] is True
    (feature / "entry.py").write_text("checked = False\n")
    with pytest.raises(ValueError, match="differ from the pinned"):
        wrapper.materialize_pinned(repo, manifest, tmp_path / "dirty")
    assert not (tmp_path / "dirty").exists()
    data["implementation"]["revision"] = "0" * 40
    manifest.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="unavailable"):
        wrapper.materialize_pinned(repo, manifest, tmp_path / "wrong-commit")


def test_corpus_miner_uses_full_packet_validation(monkeypatch):
    scripts = ROOT / "skills/w3c-spec-miner/scripts"
    monkeypatch.syspath_prepend(str(scripts))
    refresh = module("portable_spec_refresh", scripts / "refresh.py")
    monkeypatch.setattr(refresh, "fetch_full_packet", lambda *args: b'{"source_packet_contract_version":1}')
    _, result, error = refresh.fetch_packet("https://knowledge.example.test", {"internal_id": "sample"})
    assert result is None and error
