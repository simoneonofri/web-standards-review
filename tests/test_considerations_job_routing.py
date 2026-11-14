from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    ROOT
    / "skills/did-we-do-a-good-enough-job/scripts/propose_considerations_authoring.py"
)


def helper():
    spec = importlib.util.spec_from_file_location(
        "considerations_authoring_proposal", SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def packet_inputs(tmp_path: Path) -> dict[str, Path]:
    fixture_root = ROOT / "fixtures/clean-room-demo"
    model = json.loads((fixture_root / "model.json").read_text())
    threats = json.loads((fixture_root / "threats.json").read_text())
    responses = json.loads((fixture_root / "responses.json").read_text())
    snapshot = "https://www.w3.org/TR/2026/WD-test-protocol-20261113/"
    model["source_inventory"][0]["source_reference"] = snapshot
    source = {
        "source_packet_contract_version": 1,
        "snapshot_identity": {"immutable_url": snapshot},
        "sections": [
            {
                "anchor": "security",
                "heading": "Security considerations",
                "source_url": snapshot + "#security",
                "raw_text": "There are no security considerations associated with this protocol.",
            },
            {
                "anchor": "privacy",
                "heading": "Privacy considerations",
                "source_url": snapshot + "#privacy",
                "raw_text": "Recipients should minimize retention of user data and disclose its sharing.",
            },
            {
                "anchor": "request",
                "heading": "Request a position",
                "source_url": snapshot + "#request",
                "raw_text": "The user agent checks origin authorization before the request.",
            },
        ],
    }
    files = {}
    for key, payload in (
        ("model", model),
        ("threats", threats),
        ("responses", responses),
        ("source", source),
    ):
        path = tmp_path / (key + ".json")
        path.write_text(json.dumps(payload))
        files[key] = path
    files["directory"] = tmp_path
    return files


def test_d2d_proposes_authoring_without_changing_existing_privacy(packet_inputs):
    m = helper()
    f = packet_inputs
    result = m.recommend(
        f["model"], f["source"], f["threats"], f["responses"], kind="d2d"
    )
    assert result["propose_authoring"] is True
    assert result["writer_job"]["skill_id"] == "write-considerations"
    assert result["security_action"] == "propose_security_considerations"
    assert (
        result["privacy_action"]
        == "compare_existing_privacy_considerations_and_preserve_covered_content"
    )
    assert result["automatic_remote_edit"] is False
    assert result["response_coverage"] == len(result["threat_ids_considered"])


def test_focused_security_privacy_pr_proposes_update_but_editorial_pr_does_not(
    packet_inputs,
):
    m = helper()
    f = packet_inputs
    security = m.recommend(
        f["model"],
        f["source"],
        f["threats"],
        f["responses"],
        "pr",
        ["security considerations"],
    )
    assert security["propose_authoring"] is True
    assert security["stage"] == "w3c-issue-pr-review"
    assert security["decision"] == "propose_writer_job"
    unrelated = m.recommend(
        f["model"],
        f["source"],
        f["threats"],
        f["responses"],
        "pr",
        ["bibliography typo"],
    )
    assert unrelated["propose_authoring"] is False
    assert unrelated["writer_job"] is None


def test_source_version_mismatch_fails(packet_inputs):
    m = helper()
    f = packet_inputs
    model = json.loads(f["model"].read_text())
    model["source_inventory"][0]["source_reference"] = "https://example.test/other/"
    f["model"].write_text(json.dumps(model))
    with pytest.raises(ValueError, match="do not match"):
        m.recommend(f["model"], f["source"], f["threats"], f["responses"])


def test_pr_cli_writes_versioned_job_proposal(packet_inputs):
    f = packet_inputs
    output = f["directory"] / "pr-job.json"
    cmd = [
        sys.executable,
        "-B",
        str(SCRIPT),
        "--kind",
        "pr",
        "--model",
        str(f["model"]),
        "--source-packet",
        str(f["source"]),
        "--threats",
        str(f["threats"]),
        "--responses",
        str(f["responses"]),
        "--changed-area",
        "Privacy Considerations",
        "--output",
        str(output),
    ]
    completed = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30, check=False
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(output.read_text())
    assert result["schema_version"] == "considerations-authoring-proposal/v1"
    assert result["propose_authoring"]
    repeat = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30, check=False
    )
    assert repeat.returncode != 0


def test_d2d_does_not_force_rewriting_good_existing_sections(packet_inputs):
    m = helper()
    f = packet_inputs
    source = json.loads(f["source"].read_text())
    source["sections"][0]["raw_text"] = (
        "Security considerations. Unauthorized access is mitigated by browser "
        "origin checks and permission mediation; authorized misuse remains possible."
    )
    f["source"].write_text(json.dumps(source))
    result = m.recommend(
        f["model"], f["source"], f["threats"], f["responses"], kind="d2d"
    )
    assert result["propose_authoring"] is False
    assert result["writer_job"] is None
    assert result["decision"] == "assess_existing_considerations_coverage"


def test_baseline_d2d_gate_does_not_require_additional_elicitation_fields():
    evaluator_path = (
        ROOT / "skills/did-we-do-a-good-enough-job/scripts/evaluate_good_enough_gate.py"
    )
    spec = importlib.util.spec_from_file_location("gate_for_baseline", evaluator_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    input_path = (
        ROOT / "skills/did-we-do-a-good-enough-job/tests/fixtures/valid-gate-input.json"
    )
    payload = json.loads(input_path.read_text())
    payload["coverage"].pop("additional_threat_ids", None)
    payload["coverage"].pop("new_response_threat_ids", None)
    result = module.evaluate(payload)
    assert result["status"] == "pass", result["blocking_reasons"]


def test_pr_matching_word_boundaries_and_security_diff_semantics():
    m = helper()
    assert not m.changed_relevant_sections(["original wording typo"])
    assert m.changed_relevant_sections(["Check permission algorithm"])
    assert m.changed_relevant_sections(["Cookie storage changes"])
    assert m.changed_relevant_sections(["user activation check"])


def test_d2d_missing_delta_triggers_even_when_sections_are_nonempty(packet_inputs):
    m = helper()
    f = packet_inputs
    source = json.loads(f["source"].read_text())
    source["sections"][0]["raw_text"] = (
        "The user agent checks origin and permission before exposing the API."
    )
    f["source"].write_text(json.dumps(source))
    gap = m.recommend(
        f["model"],
        f["source"],
        f["threats"],
        f["responses"],
        "d2d",
        considerations_deltas=[
            {"id": "T-01", "delta": "partially_covered"},
            {"id": "T-02", "delta": "covered"},
        ],
    )
    assert gap["propose_authoring"]
    assert gap["uncovered_considerations_delta_ids"] == ["T-01"]
    complete = m.recommend(
        f["model"],
        f["source"],
        f["threats"],
        f["responses"],
        "d2d",
        considerations_deltas=[{"id": "T-01", "delta": "covered"}],
    )
    assert not complete["propose_authoring"]


def test_pr_cli_inspects_actual_diff_not_just_index_bs_name(packet_inputs):
    f = packet_inputs
    diff = f["directory"] / "change.diff"
    diff.write_text(
        "diff --git a/index.bs b/index.bs\n"
        "--- a/index.bs\n+++ b/index.bs\n"
        "@@ -1 +1 @@\n"
        "-The user agent might expose the API.\n"
        "+The user agent checks permission before exposing the API.\n"
    )
    output = f["directory"] / "diff-authoring-proposal.json"
    cmd = [
        sys.executable,
        "-B",
        str(SCRIPT),
        "--kind",
        "pr",
        "--model",
        str(f["model"]),
        "--source-packet",
        str(f["source"]),
        "--threats",
        str(f["threats"]),
        "--responses",
        str(f["responses"]),
        "--diff-file",
        str(diff),
        "--output",
        str(output),
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30, check=False
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text())
    assert payload["propose_authoring"] is True


def test_d2d_gate_routes_comparison_deltas_without_extra_authorization(packet_inputs):
    f = packet_inputs
    gate = (
        ROOT / "skills/did-we-do-a-good-enough-job/scripts/evaluate_good_enough_gate.py"
    )
    payload = (
        ROOT / "skills/did-we-do-a-good-enough-job/tests/fixtures/valid-gate-input.json"
    )
    delta_path = f["directory"] / "comparison.json"
    delta_path.write_text(
        json.dumps({"deltas": [{"id": "T-01", "status": "partially_covered"}]})
    )
    job = f["directory"] / "proposal.json"
    output = f["directory"] / "gate.json"
    cmd = [
        sys.executable,
        "-B",
        str(gate),
        str(payload),
        "--model",
        str(f["model"]),
        "--considerations-source-packet",
        str(f["source"]),
        "--considerations-threats",
        str(f["threats"]),
        "--considerations-responses",
        str(f["responses"]),
        "--considerations-delta-ledger",
        str(delta_path),
        "--considerations-proposal-output",
        str(job),
        "--output",
        str(output),
    ]
    response = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30, check=False
    )
    assert response.returncode == 0, response.stderr
    gate_result = json.loads(output.read_text())
    assert gate_result["status"] == "pass"
    assert gate_result["considerations_authoring_proposal"]["blocking"] is False
    assert json.loads(job.read_text())["uncovered_considerations_delta_ids"] == ["T-01"]


def test_bad_d2d_job_input_does_not_erase_independent_gate_result(packet_inputs):
    f = packet_inputs
    gate = (
        ROOT / "skills/did-we-do-a-good-enough-job/scripts/evaluate_good_enough_gate.py"
    )
    payload = (
        ROOT / "skills/did-we-do-a-good-enough-job/tests/fixtures/valid-gate-input.json"
    )
    output = f["directory"] / "gate.json"
    cmd = [
        sys.executable,
        "-B",
        str(gate),
        str(payload),
        "--model",
        str(f["directory"] / "missing-model.json"),
        "--considerations-source-packet",
        str(f["source"]),
        "--considerations-threats",
        str(f["threats"]),
        "--considerations-responses",
        str(f["responses"]),
        "--considerations-proposal-output",
        str(f["directory"] / "job.json"),
        "--output",
        str(output),
    ]
    response = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30, check=False
    )
    assert response.returncode == 0, response.stderr
    gate_result = json.loads(output.read_text())
    assert gate_result["status"] == "pass"
    assert gate_result["considerations_authoring_proposal"]["status"] == "unavailable"
    assert gate_result["considerations_authoring_proposal"]["blocking"] is False
