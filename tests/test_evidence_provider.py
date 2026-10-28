import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools/reviewctl"))
from evidence import EvidenceError, attach_sections, capture, fetch_packet, inspect_packet


def packet():
    return {"source_packet_contract_version": 1, "specification_version_id": "v1", "title": "Synthetic spec",
            "snapshot_identity": {"immutable_url": "https://example.invalid/spec/v1/", "content_hash": "synthetic-hash"},
            "section_inventory": [{"section_id": "s1"}],
            "export_metadata": {"section_offset": 0, "sections_total": 1, "sections_returned": 1},
            "sections": [{"section_id": "s1", "text": "Synthetic rule.", "source_url": "https://example.invalid/spec/v1/#s1", "content_hash": "provider-hash"}]}


def test_capture_preserves_original_bytes_and_separate_hash_meanings(tmp_path):
    data = json.dumps(packet()).encode()
    assert capture(data, tmp_path / "run")["primary_sections"] == 1
    assert (tmp_path / "run/source-packet.json").read_bytes() == data
    manifest = json.loads((tmp_path / "run/manifest.json").read_text())
    assert manifest["sections"][0]["provider_content_hash"] == "provider-hash"
    assert len(manifest["sections"][0]["exported_text_sha256"]) == 64
    assert manifest["publication_authorized"] is False
    with pytest.raises(EvidenceError, match="new output"):
        capture(data, tmp_path / "run")


@pytest.mark.parametrize("mutation", ["truncated", "duplicate", "unknown", "no_text", "wrong_version", "bad_snapshot", "bad_inventory", "boolean_count"])
def test_incomplete_or_mismatched_evidence_cannot_become_a_complete_corpus(tmp_path, mutation):
    data = packet()
    if mutation == "truncated": data["export_metadata"]["sections_total"] = 2
    elif mutation == "duplicate": data["sections"].append(dict(data["sections"][0]))
    elif mutation == "unknown": data["section_inventory"][0]["section_id"] = "other"
    elif mutation == "no_text": data["sections"][0].pop("text")
    elif mutation == "bad_snapshot": data["snapshot_identity"] = None
    elif mutation == "bad_inventory": data["section_inventory"] = [None]
    elif mutation == "boolean_count": data["export_metadata"]["sections_total"] = True
    else: data["source_packet_contract_version"] = 3
    with pytest.raises(EvidenceError):
        capture(json.dumps(data).encode(), tmp_path / "run")
    assert not (tmp_path / "run").exists()


def test_dated_snapshot_cannot_silently_become_latest():
    with pytest.raises(EvidenceError, match="requested snapshot"):
        inspect_packet(json.dumps(packet()).encode(), "https://example.invalid/spec/v2/")


def test_legacy_bundle_usage_is_not_accepted():
    with pytest.raises(EvidenceError, match="contract v2"):
        inspect_packet(json.dumps({"primary_specification": packet(), "threat_model_contract_version": 1}).encode())


def test_credential_bearing_provider_url_rejected_before_network():
    with pytest.raises(EvidenceError, match="without credentials"):
        fetch_packet("https://name:synthetic@example.invalid", "example")


def test_full_section_attachment_filters_old_versions_and_checks_inventory():
    row = {"internal_id": "s1", "specification_version_id": "v1", "raw_text": "Exact target text.",
           "source_url": "https://example.invalid/spec/v1/#s1", "content_hash": "provider-hash"}
    old = {**row, "internal_id": "s-old", "specification_version_id": "v0"}
    data = attach_sections(json.dumps(packet()).encode(), json.dumps([row, old]).encode())
    primary, summary = inspect_packet(data)
    assert summary["sections"] == 1
    assert primary["sections"][0]["text"] == "Exact target text."
    data = attach_sections(json.dumps(packet()).encode(), json.dumps([old]).encode())
    with pytest.raises(EvidenceError):
        inspect_packet(data)
