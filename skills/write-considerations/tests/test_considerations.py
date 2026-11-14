from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))


def mod(name: str):
    path = SCRIPTS / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def inputs(tmp_path: Path):
    fixtures = ROOT / "fixtures/clean-room-demo"
    model = json.loads((fixtures / "model.json").read_text())
    threats = json.loads((fixtures / "threats.json").read_text())
    responses = json.loads((fixtures / "responses.json").read_text())
    snapshot = "https://www.w3.org/TR/2026/WD-synthetic-protocol-20261113/"
    model["source_inventory"][0]["source_reference"] = snapshot
    manifest = {
        "schema_version": "source-corpus-manifest/v1",
        "coverage": {
            "primary_coverage": "complete",
            "snapshot_url": snapshot,
            "sections": 3,
            "specification_version_id": "synthetic-20261113",
        },
    }
    paths = {}
    for name, content in (
        ("model", model),
        ("threats", threats),
        ("responses", responses),
        ("source-manifest", manifest),
    ):
        p = tmp_path / (name + ".json")
        p.write_text(json.dumps(content))
        paths[name] = p
    paths["base"] = tmp_path
    return paths


def build(inputs: dict) -> Path:
    dest = inputs["base"] / "draft"
    mod("draft_considerations").write(
        dest,
        inputs["model"],
        inputs["threats"],
        inputs["responses"],
        inputs["source-manifest"],
    )
    return dest


def check(inputs: dict, dest: Path):
    return mod("validate_considerations").check(
        dest / "considerations.md",
        dest / "considerations-ledger.json",
        inputs["model"],
        inputs["threats"],
        inputs["responses"],
        inputs["source-manifest"],
    )


def test_generates_two_traceable_sections_and_never_approves_publication(inputs):
    dest = build(inputs)
    result = check(inputs, dest)
    assert result["valid"] is True
    assert result["status"] == "traceable_draft_not_publication_ready"
    assert result["publication_authorized"] is False
    ledger = json.loads((dest / "considerations-ledger.json").read_text())
    assert ledger["publication_authorized"] is False
    assert ledger["entries"]
    assert all(
        row["normative_enforcement_verified"] is False for row in ledger["entries"]
    )
    text = (dest / "considerations.md").read_text()
    assert "## Security Considerations" in text
    assert "## Privacy Considerations" in text
    assert "Remaining threat:" in text
    assert "normative requirement" in text
    assert "publication" in text.lower()
    assert not any("The source-verified response" in line for line in text.splitlines())


def test_changed_draft_fails_hash_verification(inputs):
    dest = build(inputs)
    draft = dest / "considerations.md"
    draft.write_text(draft.read_text() + "\nClaim: the implementation is secure.\n")
    assert check(inputs, dest)["valid"] is False
    assert any("draft_sha256" in issue for issue in check(inputs, dest)["errors"])


def test_cannot_drop_threat_or_owner_from_ledger(inputs):
    dest = build(inputs)
    p = dest / "considerations-ledger.json"
    ledger = json.loads(p.read_text())
    ledger["entries"].pop()
    p.write_text(json.dumps(ledger))
    assert any("does not cover every" in x for x in check(inputs, dest)["errors"])


def test_no_draft_for_unpinned_source_or_incomplete_response(inputs):
    mod_script = mod("draft_considerations")
    source = json.loads(inputs["source-manifest"].read_text())
    source["coverage"]["primary_coverage"] = "partial"
    inputs["source-manifest"].write_text(json.dumps(source))
    with pytest.raises(ValueError, match="complete"):
        mod_script.write(
            inputs["base"] / "invalid",
            inputs["model"],
            inputs["threats"],
            inputs["responses"],
            inputs["source-manifest"],
        )


def test_cli_runs_without_private_knowledge_service(inputs):
    command = [
        sys.executable,
        "-B",
        str(SCRIPTS / "draft_considerations.py"),
        "--model",
        str(inputs["model"]),
        "--threats",
        str(inputs["threats"]),
        "--responses",
        str(inputs["responses"]),
        "--source-manifest",
        str(inputs["source-manifest"]),
        "--output-dir",
        str(inputs["base"] / "from-cli"),
    ]
    output = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        cwd=inputs["base"],
    )
    assert output.returncode == 0, output.stderr
    assert "draft_created" in output.stdout
    assert (inputs["base"] / "from-cli" / "considerations.md").is_file()
    second = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        cwd=inputs["base"],
    )
    assert second.returncode != 0


def test_tpac_and_shostack_sources_are_local_references():
    docs = (SCRIPTS.parent / "references/security-by-design-examples.md").read_text()
    assert "Slide 23" in docs
    assert "Slides 27 and 28" in docs
    assert "SecureContext" not in docs or "secure contexts" in docs
    assert "WebAuthn" in docs
    assert "Geolocation" not in docs or "geolocation" in docs.lower()
    assert "the relying party" in docs.lower()


def test_editorial_rewrite_uses_topic_headings_and_source_anchors(tmp_path: Path):
    tool = mod("check_editorial_rewrite")
    snapshot = "https://www.w3.org/TR/2026/CRD-geolocation-20261105/"
    source = {
        "source_packet_contract_version": 1,
        "snapshot_identity": {"immutable_url": snapshot},
        "sections": [
            {
                "anchor": slug,
                "source_url": snapshot + "#" + slug,
                "raw_text": "Original normative or informative source",
            }
            for slug in (
                "security",
                "privacy",
                "request-a-position",
                "privacy_for_recipients",
            )
        ],
    }
    source_path = tmp_path / "source.json"
    source_path.write_text(json.dumps(source))
    words = (
        "A concrete attack scenario can expose sensitive device data. "
        "The user agent checks permission and enforces a specific policy. "
        "The browser does not prevent authorized recipient misuse. "
        "Relevant risks remain for data retention and further disclosure. "
    ) * 12
    draft_text = (
        "# Draft\n\n## Security Considerations\n\n"
        "### Access controls\n\n"
        + words
        + "\n\n### Remaining threats\n\n"
        + "See "
        + snapshot
        + "#request-a-position. "
        + words
        + "\n\n## Privacy Considerations\n\n"
        + "### Actors and disclosure\n\n"
        + words
        + "\n\n### Recipient retention\n\n"
        + "See "
        + snapshot
        + "#privacy_for_recipients. "
        + words
    )
    proposed = tmp_path / "new.md"
    proposed.write_text(draft_text)
    receipt = tool.audit(proposed, source_path)
    assert receipt["status"] == "editorial_checks_passed"
    assert receipt["publication_authorized"] is False
    assert receipt["counts"]["machine_id_headings"] == 0
    assert receipt["source_anchor_links"] == 2

    proposed.write_text(
        draft_text.replace(
            "### Access controls", "### Security risk T-01: Access controls"
        )
    )
    blocked = tool.audit(proposed, source_path)
    assert blocked["status"] == "blocked"
    assert any("machine threat IDs" in error for error in blocked["errors"])

    proposed.write_text(draft_text.replace("#request-a-position", "#not-in-source"))
    blocked = tool.audit(proposed, source_path)
    assert any("absent from exact snapshot" in error for error in blocked["errors"])


def test_fedcm_editorial_reference_rejects_one_heading_per_machine_threat():
    path = SCRIPTS.parent / "references/fedcm-editorial-pattern.md"
    text = path.read_text()
    assert "Security Assumptions" in text or "security assumptions" in text
    assert "threat and mitigation" in text.lower()
    assert "privacy" in text.lower()
    assert "machine-generated threat ID" in text
    skill = (SCRIPTS.parent / "SKILL.md").read_text()
    assert "check_editorial_rewrite.py" in skill
    assert "consolidated rewrite" in skill
