"""Executable proof that both knowledge providers are applied in three WCGW phases."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def loaded(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location("test_" + name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_packet():
    snapshot = "https://www.w3.org/TR/2026/WD-test-feature-20261113/"
    sections = [
        {
            "section_id": "s-security",
            "heading": "Security Considerations",
            "fragment": "security",
            "source_url": snapshot + "#security",
            "content_hash": "b" * 64,
            "text": "The user agent controls permission before the feature is exposed.",
            "normative": False,
        },
        {
            "section_id": "s-algorithm",
            "heading": "Request authorization",
            "fragment": "algorithm",
            "source_url": snapshot + "#algorithm",
            "content_hash": "c" * 64,
            "text": "The user agent MUST reject unauthorized requests with a denial.",
            "normative": True,
        },
    ]
    return {
        "source_packet_contract_version": 1,
        "specification_id": "synthetic-test-feature",
        "specification_version_id": "fixture-2026-11-13",
        "shortname": "test-feature",
        "snapshot_identity": {"immutable_url": snapshot, "content_hash": "a" * 64},
        "export_metadata": {
            "section_offset": 0,
            "section_limit": None,
            "sections_total": 2,
            "sections_returned": 2,
        },
        "sections": sections,
        "section_inventory": [
            {
                "section_id": item["section_id"],
                "order": index,
                "normative": item["normative"],
            }
            for index, item in enumerate(sections)
        ],
    }


@pytest.fixture()
def inputs(tmp_path):
    module = loaded("export_miner_cache")
    cache = tmp_path / "cache.zip"
    module.build(ROOT, cache, ROOT / "cache/curation/overrides.csv")
    model = json.loads((ROOT / "fixtures/clean-room-demo/model.json").read_text())
    model["source_inventory"][0]["source_reference"] = source_packet()[
        "snapshot_identity"
    ]["immutable_url"]
    model_path = tmp_path / "model.json"
    model_path.write_text(json.dumps(model))
    packet_path = tmp_path / "source.json"
    packet_path.write_text(json.dumps(source_packet()))
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_bytes(
        (ROOT / "fixtures/clean-room-demo/threats.json").read_bytes()
    )
    threats_path = tmp_path / "threats.json"
    threats_path.write_bytes(baseline_path.read_bytes())
    return {
        "root": tmp_path,
        "cache": cache,
        "model": model_path,
        "packet": packet_path,
        "baseline": baseline_path,
        "threats": threats_path,
    }


def prepared(inputs):
    module = loaded("reconcile_specification_knowledge")
    output = inputs["root"] / "selection"
    result = module.prepare(
        inputs["model"],
        inputs["packet"],
        inputs["cache"],
        "security,privacy",
        1,
        output,
    )
    plan = output / "knowledge-selection.json"
    template = output / "knowledge-dispositions.template.json"
    return module, result, plan, template


def fully_reviewed(inputs, plan_path, template_path):
    ledger = json.loads(template_path.read_text())
    seen = set()
    snapshot = source_packet()["snapshot_identity"]["immutable_url"]
    for row in ledger["rows"]:
        key = (row["phase"], row["provider"])
        if key not in seen:
            seen.add(key)
            if row["phase"] == "explicit":
                row["disposition"] = "documented_threat"
                row["threat_ids"] = ["T-01"]
                row["section_urls"] = [snapshot + "#security"]
            elif row["phase"] == "implicit":
                row["disposition"] = "observed_control"
                row["section_urls"] = [snapshot + "#algorithm"]
                row["bad_event"] = (
                    "If authorization is not checked, untrusted requests can disclose "
                    "personal data to the remote service."
                )
            else:
                row["disposition"] = "confirms_existing"
                row["threat_ids"] = ["T-01"]
                row["section_urls"] = [snapshot + "#algorithm"]
        else:
            row["disposition"] = "not_applicable"
            row["section_urls"] = [snapshot + "#algorithm"]
        row["element_ids"] = ["PO-01"]
        row["rationale"] = (
            "This exact synthetic document and model were inspected for the "
            "identified boundary, and this is the disposition for that specific item."
        )
    path = inputs["root"] / "reviewed.json"
    path.write_text(json.dumps(ledger))
    return path


def test_both_providers_selected_for_explicit_implicit_and_additional(inputs):
    _module, info, plan_path, template_path = prepared(inputs)
    assert info["status"] == "requires_dispositions"
    assert info["total"] > 10
    plan = json.loads(plan_path.read_text())
    assert plan["phases"] == ["explicit", "implicit", "additional"]
    for phase in plan["phases"]:
        assert plan["provider_phase_coverage"][phase]["miner_knowledge"] > 0
        assert plan["provider_phase_coverage"][phase]["threat_knowledge"] > 0
    methods = {
        x["source_item_id"] for x in plan["rows"] if x["provider"] == "threat_knowledge"
    }
    assert {"stride", "linddun", "rfc3552", "rfc6973"} <= methods
    assert all(r["section_suggestions"] is not None for r in plan["rows"])
    assert all(
        row["disposition"] == "pending"
        for row in json.loads(template_path.read_text())["rows"]
    )


def test_complete_reconciliation_passes_only_with_all_items_evidenced(inputs):
    module, _info, plan_path, template_path = prepared(inputs)
    ledger_path = fully_reviewed(inputs, plan_path, template_path)
    result = module.validate_dispositions(
        plan_path,
        ledger_path,
        inputs["model"],
        inputs["packet"],
        inputs["cache"],
        inputs["threats"],
        inputs["baseline"],
    )
    assert result["status"] == "pass", result["errors"]
    assert result["adjudicated"] == result["selected"]
    for phase in ("explicit", "implicit", "additional"):
        assert result["phase_provider_counts"][phase] == {
            "miner_knowledge": 5,
            "threat_knowledge": 6,
        }
    assert not result["unresolved_ids"]


def test_missing_one_disposition_blocks_signoff(inputs):
    module, _info, plan_path, template_path = prepared(inputs)
    ledger_path = fully_reviewed(inputs, plan_path, template_path)
    ledger = json.loads(ledger_path.read_text())
    ledger["rows"][0]["disposition"] = "pending"
    ledger_path.write_text(json.dumps(ledger))
    result = module.validate_dispositions(
        plan_path,
        ledger_path,
        inputs["model"],
        inputs["packet"],
        inputs["cache"],
        inputs["threats"],
        inputs["baseline"],
    )
    assert result["status"] == "partial"
    assert result["unresolved_ids"]


def test_source_and_model_reconciliation_fails_for_tampering(inputs):
    module, _info, plan_path, template_path = prepared(inputs)
    ledger_path = fully_reviewed(inputs, plan_path, template_path)
    ledger = json.loads(ledger_path.read_text())
    ledger["rows"][0]["section_urls"] = [
        "https://www.w3.org/TR/2025/WD-test-feature-20251113/#security"
    ]
    ledger_path.write_text(json.dumps(ledger))
    result = module.validate_dispositions(
        plan_path,
        ledger_path,
        inputs["model"],
        inputs["packet"],
        inputs["cache"],
        inputs["threats"],
        inputs["baseline"],
    )
    assert result["status"] == "blocked"
    assert any("pinned source packet" in issue for issue in result["errors"])


def test_plan_cannot_silently_drop_miner_or_threat_knowledge(inputs):
    module, _info, plan_path, template_path = prepared(inputs)
    ledger = json.loads(template_path.read_text())
    plan = json.loads(plan_path.read_text())
    plan["rows"] = [
        row for row in plan["rows"] if row["provider"] != "threat_knowledge"
    ]
    plan_path.write_bytes(module.json_bytes(plan))
    ledger["selection_sha256"] = module.sha(plan_path.read_bytes())
    ledger["rows"] = [
        row for row in ledger["rows"] if row["provider"] != "threat_knowledge"
    ]
    ledger_path = inputs["root"] / "tampered.json"
    ledger_path.write_text(json.dumps(ledger))
    with pytest.raises(ValueError, match="complete deterministic provider selection"):
        module.validate_dispositions(
            plan_path,
            ledger_path,
            inputs["model"],
            inputs["packet"],
            inputs["cache"],
            inputs["threats"],
            inputs["baseline"],
        )


def test_bad_control_observation_needs_actual_bad_event(inputs):
    module, _info, plan_path, template_path = prepared(inputs)
    ledger_path = fully_reviewed(inputs, plan_path, template_path)
    ledger = json.loads(ledger_path.read_text())
    row = next(
        row for row in ledger["rows"] if row["disposition"] == "observed_control"
    )
    row["bad_event"] = ""
    ledger_path.write_text(json.dumps(ledger))
    result = module.validate_dispositions(
        plan_path,
        ledger_path,
        inputs["model"],
        inputs["packet"],
        inputs["cache"],
        inputs["threats"],
        inputs["baseline"],
    )
    assert result["status"] == "blocked"
    assert any("concrete implied bad event" in issue for issue in result["errors"])


def test_missing_threat_knowledge_provider_fails_closed(inputs, monkeypatch):
    module = loaded("reconcile_specification_knowledge")
    monkeypatch.setattr(
        module,
        "source_and_method_registry",
        lambda: ({}, {"questions": []}, b"{}", b"{}"),
    )
    with pytest.raises(ValueError, match="Threat Knowledge returned no"):
        module.prepare(
            inputs["model"],
            inputs["packet"],
            inputs["cache"],
            "security,privacy",
            1,
            inputs["root"] / "empty",
        )


def test_baseline_mode_uses_both_providers_but_not_additional(inputs):
    module = loaded("reconcile_specification_knowledge")
    result = module.prepare(
        inputs["model"],
        inputs["packet"],
        inputs["cache"],
        "security,privacy",
        1,
        inputs["root"] / "baseline-only",
        "baseline",
    )
    plan = json.loads(Path(result["selection"]).read_text())
    assert plan["phases"] == ["explicit", "implicit"]
    assert "additional" not in plan["provider_phase_coverage"]


def test_invalid_domain_is_rejected():
    module = loaded("reconcile_specification_knowledge")
    with pytest.raises(ValueError, match="sustainability"):
        module.domains_from("security,sustainability")


def test_wcgwn_specification_validator_requires_both_sources(inputs):
    import os
    import subprocess

    validator = ROOT / "skills/what-can-go-wrong/scripts/validate_threat_package.py"
    model = inputs["model"]
    command = [
        sys.executable,
        "-B",
        str(validator),
        str(inputs["threats"]),
        "--model",
        str(model),
    ]
    empty = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=50,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert empty.returncode != 0
    assert "requires the exact Miner Knowledge + Threat Knowledge" in empty.stdout

    _module, _summary, plan_path, template_path = prepared(inputs)
    dispositions = fully_reviewed(inputs, plan_path, template_path)
    complete = subprocess.run(
        command
        + [
            "--knowledge-selection",
            str(plan_path),
            "--knowledge-dispositions",
            str(dispositions),
            "--knowledge-source-packet",
            str(inputs["packet"]),
            "--knowledge-cache",
            str(inputs["cache"]),
            "--knowledge-baseline-threats",
            str(inputs["baseline"]),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=65,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert complete.returncode == 0, complete.stdout + complete.stderr
    assert "Dual-provider knowledge reconciliation passed" in complete.stdout


def test_good_enough_gate_fails_without_specification_knowledge_receipt(inputs):
    import os
    import subprocess

    model = json.loads(inputs["model"].read_text())
    elements = [
        row["stable_id"]
        for collection in (
            "external_entities",
            "processes",
            "data_stores",
            "data_flows",
            "trust_boundaries",
        )
        for row in model[collection]
    ]
    baseline = json.loads(inputs["baseline"].read_text())
    threat_ids = [row["threat_id"] for row in baseline["threats"]]
    gate_input = {
        "run_scope": "additional",
        "gates": [
            {"name": name, "status": "pass"}
            for name in (
                "source_corpus",
                "model_packet",
                "dfd_representation",
                "baseline_elicitation",
                "additional_elicitation_reconciliation",
                "response_mapping",
                "knowledge_reconciliation",
            )
        ],
        "coverage": {
            "model_ids": elements,
            "dictionary_ids": elements,
            "baseline_threat_ids": threat_ids,
            "actual_response_threat_ids": threat_ids,
            "additional_threat_ids": [],
            "new_response_threat_ids": [],
        },
    }
    payload = inputs["root"] / "quality-input.json"
    payload.write_text(json.dumps(gate_input))
    validator = (
        ROOT / "skills/did-we-do-a-good-enough-job/scripts/evaluate_good_enough_gate.py"
    )
    command = [
        sys.executable,
        "-B",
        str(validator),
        str(payload),
        "--model",
        str(inputs["model"]),
    ]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    without = subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=50, env=env
    )
    assert without.returncode != 0
    result = json.loads(without.stdout)
    assert result["status"] == "blocked"
    assert "reconciliation receipt" in " ".join(result["blocking_reasons"])

    reconciler, _summary, plan_path, template_path = prepared(inputs)
    dispositions = fully_reviewed(inputs, plan_path, template_path)
    receipt = reconciler.validate_dispositions(
        plan_path,
        dispositions,
        inputs["model"],
        inputs["packet"],
        inputs["cache"],
        inputs["threats"],
        inputs["baseline"],
    )
    assert receipt["status"] == "pass"
    path = inputs["root"] / "receipt.json"
    path.write_text(json.dumps(receipt))
    with_proof = subprocess.run(
        command + ["--knowledge-receipt", str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=50,
        env=env,
    )
    assert with_proof.returncode == 0, with_proof.stdout + with_proof.stderr
    assert json.loads(with_proof.stdout)["status"] == "pass"


def test_complete_web_spec_bundle_requires_dual_knowledge_receipt(inputs):
    path = ROOT / "tools/reviewctl/validate_bundle.py"
    spec = importlib.util.spec_from_file_location("bundle_knowledge_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    model = json.loads(inputs["model"].read_text())

    with pytest.raises(module.BundleError, match="needs a passing"):
        module.validate_complete_specification_knowledge(model, None)

    _reconciler, _info, plan_path, template_path = prepared(inputs)
    ledger_path = fully_reviewed(inputs, plan_path, template_path)
    receipt = _reconciler.validate_dispositions(
        plan_path,
        ledger_path,
        inputs["model"],
        inputs["packet"],
        inputs["cache"],
        inputs["threats"],
        inputs["baseline"],
    )
    assert receipt["status"] == "pass"
    module.validate_complete_specification_knowledge(model, receipt)

    broken = json.loads(json.dumps(receipt))
    broken["phase_provider_counts"]["implicit"]["threat_knowledge"] = 0
    with pytest.raises(module.BundleError, match="implicit dispositions"):
        module.validate_complete_specification_knowledge(model, broken)

    generic_model = json.loads(
        (ROOT / "fixtures/clean-room-demo/model.json").read_text()
    )
    module.validate_complete_specification_knowledge(generic_model, None)


def test_bundle_manifest_declares_enforced_sources_and_phases():
    info = json.loads((ROOT / "bundles/threat-modeling-flow-v1.json").read_text())
    knowledge = info["mandatory_specification_knowledge"]
    assert knowledge["providers"] == ["miner_knowledge", "threat_knowledge"]
    assert knowledge["full_phases"] == ["explicit", "implicit", "additional"]
    assert knowledge["baseline_only_phases"] == ["explicit", "implicit"]
    for field in (
        "prepare_and_verify_script",
        "threat_source_registry",
        "operational_method_questions",
        "threat_package_validator",
        "quality_gate_validator",
    ):
        assert (ROOT / knowledge[field]).is_file()


def test_full_threat_knowledge_corpus_cache_is_pinned_and_reused(inputs):
    import csv
    import io

    tk_exporter = loaded("export_threat_knowledge_cache")
    corpus = inputs["root"] / "threat-knowledge-fixture"
    source = corpus / "references/corpus/threat-frameworks/google-sheet"
    source.mkdir(parents=True)
    (source.parent / "MANIFEST.md").write_text("Synthetic source version for test.")
    for slug, (
        _domain,
        _method,
        category,
        question_column,
    ) in tk_exporter.SHEETS.items():
        output = io.StringIO()
        writer = csv.writer(output)
        if slug == "harms-threats-corti-et-al-ndi":
            writer.writerow(["Attribution", "", "", "", "", "", "", ""])
            writer.writerow(
                [
                    "CATEGORY",
                    "TYPE OF HARM",
                    "HARM",
                    "SOURCE",
                    "STAKEHOLDERS (Specific)",
                    "",
                    "",
                    "",
                ]
            )
            writer.writerow(
                ["Risk", "Physical", "Exclusion", "Synthetic", "Users", "", "", ""]
            )
        elif category == question_column:
            writer.writerow([category])
            writer.writerow(["Can this system expose location without permission?"])
        else:
            writer.writerow([category, question_column])
            writer.writerow(
                [
                    "Authorization",
                    "Can a hostile origin obtain protected location data?",
                ]
            )
        (source / (slug + ".csv")).write_text(output.getvalue())

    full_cache = inputs["root"] / "threat-full.zip"
    tk_exporter.create(corpus, full_cache)
    module = loaded("reconcile_specification_knowledge")
    selected = inputs["root"] / "knowledge-full"
    result = module.prepare(
        inputs["model"],
        inputs["packet"],
        inputs["cache"],
        "security,privacy,human-rights,harms",
        2,
        selected,
        threat_cache_path=full_cache,
    )
    plan_path = selected / "knowledge-selection.json"
    plan = json.loads(plan_path.read_text())
    assert result["total"] > 10
    assert plan["threat_cache_mode"] == "portable_corpus"
    assert plan["threat_cache_sha256"] == module.sha(full_cache.read_bytes())
    assert all(
        plan["provider_phase_coverage"][phase]["threat_knowledge"] > 3
        for phase in ("explicit", "implicit", "additional")
    )

    dispositions = fully_reviewed(
        inputs, plan_path, selected / "knowledge-dispositions.template.json"
    )
    receipt = module.validate_dispositions(
        plan_path,
        dispositions,
        inputs["model"],
        inputs["packet"],
        inputs["cache"],
        inputs["threats"],
        inputs["baseline"],
        full_cache,
    )
    assert receipt["status"] == "pass", receipt["errors"]

    with pytest.raises(ValueError, match="presence"):
        module.validate_dispositions(
            plan_path,
            dispositions,
            inputs["model"],
            inputs["packet"],
            inputs["cache"],
            inputs["threats"],
            inputs["baseline"],
        )
