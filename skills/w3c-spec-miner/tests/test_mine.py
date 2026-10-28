from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from mine import aggregate_catalog, load_patterns, mine_specification, render_catalog_markdown  # noqa: E402


def fixture() -> tuple[dict[str, object], dict[str, object]]:
    specification = {"internal_id": "spec-1", "shortname": "synthetic-api", "title": "Synthetic API", "publication_status": "WD", "current_published_url": "https://www.w3.org/TR/synthetic-api/"}
    packet = {
        "snapshot_identity": {"content_hash": "packet"},
        "sections": [
            {"heading": "API", "anchor": "api", "raw_text": "[SecureContext] interface Synthetic { }; Input validation occurs before use and a user agent MUST reject invalid input.", "source_url": "https://www.w3.org/TR/synthetic-api/#api", "content_hash": "a" * 64, "evidence_ids": ["e-1"], "section_type": None},
            {"heading": "Security Considerations", "fragment": "security", "text": "The API uses a secure context.", "source_url": "https://www.w3.org/TR/synthetic-api/#security", "content_hash": "b" * 64, "evidence_ids": ["e-2"], "section_type": "security_considerations"},
        ],
    }
    return specification, packet


def test_mines_as_is_model_and_non_blocking_gap() -> None:
    patterns = load_patterns(ROOT / "references" / "pattern-definitions.json")
    specification, packet = fixture()
    result = mine_specification(specification, packet, patterns)
    assert "wsm-secure-context" in result.model["observed_protections"]
    assert result.model["security_considerations_present"] is True
    input_gap = next(gap for gap in result.gaps if gap["pattern_id"] == "wsm-input-validation")
    assert input_gap["disposition"] == "editorial_non_blocking"
    assert not any(gap["pattern_id"] == "wsm-secure-context" for gap in result.gaps)


def test_catalog_frequency_is_descriptive() -> None:
    patterns = load_patterns(ROOT / "references" / "pattern-definitions.json")
    specification, packet = fixture()
    result = mine_specification(specification, packet, patterns)
    catalog = aggregate_catalog(patterns, list(result.observations), {"inventory_count": 1})
    assert "descriptive" in catalog["interpretation"]
    secure_context = next(pattern for pattern in catalog["patterns"] if pattern["pattern_id"] == "wsm-secure-context")
    assert secure_context["specification_count"] == 1


def test_pattern_definitions_are_unique() -> None:
    patterns = json.loads((ROOT / "references" / "pattern-definitions.json").read_text(encoding="utf-8"))
    identifiers = [pattern["pattern_id"] for pattern in patterns]
    assert len(identifiers) == len(set(identifiers))


def test_reference_urls_do_not_create_transport_observation() -> None:
    patterns = load_patterns(ROOT / "references" / "pattern-definitions.json")
    specification, packet = fixture()
    packet["sections"].append({"heading": "References", "fragment": "refs", "text": "TLS. URL: https://example.test/spec", "source_url": "https://www.w3.org/TR/synthetic-api/#refs", "content_hash": "c" * 64, "evidence_ids": ["e-3"], "section_type": "references"})  # type: ignore[index]
    result = mine_specification(specification, packet, patterns)
    assert "wsm-https-tls" not in result.model["observed_protections"]


def test_markdown_catalog_preserves_frequency_warning() -> None:
    patterns = load_patterns(ROOT / "references" / "pattern-definitions.json")
    specification, packet = fixture()
    result = mine_specification(specification, packet, patterns)
    catalog = aggregate_catalog(patterns, list(result.observations), {"inventory_count": 1})
    coverage = {"inventory_count": 1, "successful_packets": 1, "failed_packets": 0, "retrieved_at": "2026-08-04T00:00:00Z", "observation_count": len(result.observations), "specifications_with_observed_protections": 1, "editorial_gap_count": len(result.gaps)}
    rendered = render_catalog_markdown(catalog, coverage)
    assert "Frequency is descriptive" in rendered
    assert "editorial_non_blocking" in rendered


def test_x509_revocation_is_not_permission_lifecycle() -> None:
    patterns = load_patterns(ROOT / "references" / "pattern-definitions.json")
    specification, packet = fixture()
    packet["sections"] = [{"heading": "Data model", "anchor": "data", "raw_text": "The certificate conforms to the Certificate Revocation List profile.", "source_url": "https://www.w3.org/TR/synthetic-api/#data", "content_hash": "c" * 64, "evidence_ids": ["e-3"], "section_type": None}]
    result = mine_specification(specification, packet, patterns)
    assert "wsm-permission-lifecycle" not in result.model["observed_protections"]


def test_csp_nonce_is_not_anti_replay() -> None:
    patterns = load_patterns(ROOT / "references" / "pattern-definitions.json")
    specification, packet = fixture()
    packet["sections"] = [{"heading": "CSP", "anchor": "csp", "raw_text": "The element has a valid CSP nonce-source.", "source_url": "https://www.w3.org/TR/synthetic-api/#csp", "content_hash": "d" * 64, "evidence_ids": ["e-4"], "section_type": None}]
    result = mine_specification(specification, packet, patterns)
    assert "wsm-anti-replay-freshness" not in result.model["observed_protections"]


def test_generic_error_is_not_input_validation() -> None:
    patterns = load_patterns(ROOT / "references" / "pattern-definitions.json")
    specification, packet = fixture()
    packet["sections"] = [{"heading": "Operation", "anchor": "op", "raw_text": "If the remote service is unavailable, return an error.", "source_url": "https://www.w3.org/TR/synthetic-api/#op", "content_hash": "e" * 64, "evidence_ids": ["e-5"], "section_type": None}]
    result = mine_specification(specification, packet, patterns)
    assert "wsm-input-validation" not in result.model["observed_protections"]


def test_normative_references_are_not_controls() -> None:
    patterns = load_patterns(ROOT / "references" / "pattern-definitions.json")
    specification, packet = fixture()
    packet["sections"] = [{"heading": "Normative References", "anchor": "normative", "raw_text": "[SECURE-CONTEXTS] Secure Contexts.", "source_url": "https://www.w3.org/TR/synthetic-api/#normative", "content_hash": "f" * 64, "evidence_ids": ["e-6"], "section_type": None}]
    result = mine_specification(specification, packet, patterns)
    assert "wsm-secure-context" not in result.model["observed_protections"]


def test_rejected_cors_restriction_is_not_a_protection() -> None:
    patterns = load_patterns(ROOT / "references" / "pattern-definitions.json")
    specification, packet = fixture()
    packet["sections"] = [{"heading": "Privacy", "anchor": "privacy", "raw_text": "This could be restricted via CORS, but this specification chose not to impose such a restriction.", "source_url": "https://www.w3.org/TR/synthetic-api/#privacy", "content_hash": "1" * 64, "evidence_ids": ["e-7"], "section_type": None}]
    result = mine_specification(specification, packet, patterns)
    assert "wsm-cors-opt-in" not in result.model["observed_protections"]


def test_external_resource_definition_is_not_a_retrieval_policy() -> None:
    patterns = load_patterns(ROOT / "references" / "pattern-definitions.json")
    specification, packet = fixture()
    packet["sections"] = [{"heading": "Terminology", "anchor": "terms", "raw_text": "An external resource is an image loaded from another document.", "source_url": "https://www.w3.org/TR/synthetic-api/#terms", "content_hash": "2" * 64, "evidence_ids": ["e-8"], "section_type": None}]
    result = mine_specification(specification, packet, patterns)
    assert "wsm-external-retrieval-policy" not in result.model["observed_protections"]


def test_issues_index_is_not_a_control_section() -> None:
    patterns = load_patterns(ROOT / "references" / "pattern-definitions.json")
    specification, packet = fixture()
    packet["sections"] = [{"heading": "Issues Index", "anchor": "issues-index", "raw_text": "The resource fetch policy should move into another specification.", "source_url": "https://www.w3.org/TR/synthetic-api/#issues-index", "content_hash": "3" * 64, "evidence_ids": ["e-9"], "section_type": None}]
    result = mine_specification(specification, packet, patterns)
    assert "wsm-external-retrieval-policy" not in result.model["observed_protections"]


def test_hypothetical_user_gesture_is_not_a_control() -> None:
    patterns = load_patterns(ROOT / "references" / "pattern-definitions.json")
    specification, packet = fixture()
    packet["sections"] = [{"heading": "Open issue", "anchor": "issue", "raw_text": "We should perhaps provide another option, possibly gated on a user gesture.", "source_url": "https://www.w3.org/TR/synthetic-api/#issue", "content_hash": "4" * 64, "evidence_ids": ["e-10"], "section_type": None}]
    result = mine_specification(specification, packet, patterns)
    assert "wsm-user-activation" not in result.model["observed_protections"]
