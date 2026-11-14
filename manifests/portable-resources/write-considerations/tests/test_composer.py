from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from compose_considerations import compose


@pytest.fixture()
def editorial_inputs(tmp_path: Path):
    fixtures = ROOT / "fixtures/clean-room-demo"
    model = json.loads((fixtures / "model.json").read_text())
    threats = json.loads((fixtures / "threats.json").read_text())
    responses = json.loads((fixtures / "responses.json").read_text())
    snapshot = "https://www.w3.org/TR/2026/WD-sample-20261113/"
    model["source_inventory"][0]["source_reference"] = snapshot
    manifest = {
        "schema_version": "source-corpus-manifest/v1",
        "coverage": {
            "primary_coverage": "complete",
            "snapshot_url": snapshot,
            "sections": 4,
            "specification_version_id": "fixture-20261113",
        },
    }
    section_names = (
        ("security", "Security considerations"),
        ("privacy", "Privacy considerations"),
        ("access-gate", "Request authorization"),
        ("recipient", "Recipient responsibilities"),
    )
    source = {
        "source_packet_contract_version": 1,
        "snapshot_identity": {"immutable_url": snapshot},
        "sections": [
            {
                "anchor": anchor,
                "source_url": snapshot + "#" + anchor,
                "heading": heading,
                "raw_text": (
                    "To request authorization, let document be the relevant context. "
                    "If the user agent finds an unauthorized document, terminate "
                    "this algorithm and return permission denied."
                    if anchor == "access-gate"
                    else "This target describes its requirements and implications."
                ),
                "normative": anchor == "access-gate",
            }
            for anchor, heading in section_names
        ],
    }
    pairs = {r["threat_id"]: r["response_id"] for r in responses["responses"]}
    threat_ids = sorted(pairs)
    first = threat_ids[: max(1, len(threat_ids) // 2)]
    second = threat_ids[len(first) :]
    if not second:
        second = first

    def topic(title, ids, slug, section):
        return {
            "heading": title,
            "paragraphs": [
                (
                    "An attacker could exploit weak authorization and expose confidential state. "
                    "The current specification contains a documented access check; its scope "
                    "and enforcement boundary are described by the source algorithm. "
                    "The remaining risk involves an already authorized but malicious application."
                ),
                (
                    "The recipient and browser have distinct responsibilities. "
                    "Browser enforcement does not guarantee application-side data minimization "
                    "or the accuracy of remote information."
                ),
            ],
            "threat_ids": ids,
            "response_ids": [pairs[x] for x in ids],
            "source_urls": [snapshot + "#" + slug],
            "enforcement": "Browser" if section == "security" else "Recipient",
            "residual": "Authorized misuse and unexpected disclosure remain possible.",
        }

    packet = {
        "schema_version": "considerations-editorial-packet/v1",
        "model_id": model["model_id"],
        "threat_package_id": threats["threat_package_id"],
        "response_package_id": responses["response_package_id"],
        "source_snapshot": snapshot,
        "sections": {
            "security": {
                "introduction": "This specification defines the browser authorization boundary "
                "and explains how an attacker could misuse the interface.",
                "topics": [
                    topic(
                        "Authorization and exposure", first, "access-gate", "security"
                    ),
                    topic("Remaining security risks", second, "security", "security"),
                ],
            },
            "privacy": {
                "introduction": "Recipients may collect personal information. "
                "The application should consider retention, linkability and onward sharing.",
                "topics": [
                    topic("Permission and user agency", first, "privacy", "privacy"),
                    topic(
                        "Recipient retention and onward sharing",
                        second,
                        "recipient",
                        "privacy",
                    ),
                ],
            },
        },
        "editing": {
            "mode": "amend",
            "privacy_strategy": "Retain established privacy obligations, and add the missing recipient boundary.",
            "privacy_additions": [
                {
                    "heading": "Receiver obligations",
                    "section_url": snapshot + "#recipient",
                    "text": "The receiver is responsible for storage and retention after browser disclosure.",
                }
            ],
        },
    }
    names = {
        "editorial-packet": packet,
        "model": model,
        "threats": threats,
        "responses": responses,
        "source-manifest": manifest,
        "source-packet": source,
    }
    paths = {}
    for name, data in names.items():
        path = tmp_path / (name + ".json")
        path.write_text(json.dumps(data))
        paths[name] = path
    paths["output"] = tmp_path / "output"
    return paths


def run(inputs: dict):
    return compose(
        inputs["editorial-packet"],
        inputs["model"],
        inputs["threats"],
        inputs["responses"],
        inputs["source-manifest"],
        inputs["source-packet"],
        inputs["output"],
    )


def test_compose_outputs_reader_prose_minimal_patch_and_auditable_ledger(
    editorial_inputs,
):
    result = run(editorial_inputs)
    assert result["status"] == "authored"
    assert result["editorial_checks"] == "editorial_checks_passed"
    folder = editorial_inputs["output"]
    prose = (folder / "considerations.md").read_text()
    assert "## Security Considerations" in prose
    assert "## Privacy Considerations" in prose
    assert "Threat T-" not in prose
    assert "The response package records a" not in prose
    assert "### Authorization and exposure" in prose
    assert (
        "## Proposed changes to existing Privacy Considerations"
        in (folder / "minimal-edit.md").read_text()
    )
    assert (folder / "editorial-evidence.json").is_file()
    receipt = json.loads((folder / "editorial-qa.json").read_text())
    assert receipt["status"] == "editorial_checks_passed"
    assert receipt["publication_authorized"] is False


def test_invalid_source_anchor_is_rejected(editorial_inputs):
    editorial = json.loads(editorial_inputs["editorial-packet"].read_text())
    editorial["sections"]["security"]["topics"][0]["source_urls"] = [
        "https://www.w3.org/TR/2025/WD-other/#access-gate"
    ]
    editorial_inputs["editorial-packet"].write_text(json.dumps(editorial))
    with pytest.raises(ValueError, match="unrecognized section"):
        run(editorial_inputs)


def test_dropped_retained_threat_is_rejected(editorial_inputs):
    editorial = json.loads(editorial_inputs["editorial-packet"].read_text())
    latest = editorial["sections"]["security"]["topics"][-1]
    latest["threat_ids"] = []
    latest["response_ids"] = []
    editorial_inputs["editorial-packet"].write_text(json.dumps(editorial))
    with pytest.raises(ValueError, match="threat IDs"):
        run(editorial_inputs)


def test_response_id_drift_fails(editorial_inputs):
    editorial = json.loads(editorial_inputs["editorial-packet"].read_text())
    row = editorial["sections"]["security"]["topics"][0]
    row["response_ids"][0] = "R-99"
    editorial_inputs["editorial-packet"].write_text(json.dumps(editorial))
    with pytest.raises(ValueError, match="ERTA response IDs"):
        run(editorial_inputs)


def test_writing_short_sections_has_no_arbitrary_word_quota(editorial_inputs):
    editorial = json.loads(editorial_inputs["editorial-packet"].read_text())
    for section in editorial["sections"].values():
        section["topics"][0]["paragraphs"] = [
            (
                "The browser checks authorization. An authenticated recipient "
                "may nonetheless misuse information: the access policy does not "
                "govern recipient retention or onward sharing."
            )
        ]
        section["topics"][1]["paragraphs"] = [
            (
                "A future specification may reduce additional threats. "
                "At present recipient-side retention remains outside browser "
                "enforcement and must be considered by the application."
            )
        ]
    editorial_inputs["editorial-packet"].write_text(json.dumps(editorial))
    result = run(editorial_inputs)
    assert result["editorial_checks"] == "editorial_checks_passed"


def test_no_overwrite_of_existing_editorial_artifacts(editorial_inputs):
    run(editorial_inputs)
    with pytest.raises(ValueError, match="exists"):
        run(editorial_inputs)


def test_no_separate_signoff_required_for_authored_sections():
    skill = (SCRIPT_DIR.parent / "SKILL.md").read_text()
    assert "normal final output" in skill
    assert "not arbitrary word" in skill
    assert "compose_considerations.py" in skill
    assert "The model performing this skill" in skill


def test_new_specification_generation_does_not_invent_a_minimal_patch(editorial_inputs):
    packet = json.loads(editorial_inputs["editorial-packet"].read_text())
    packet["editing"] = {"mode": "create", "privacy_additions": []}
    editorial_inputs["editorial-packet"].write_text(json.dumps(packet))
    result = run(editorial_inputs)
    assert result["editing_mode"] == "create"
    assert (editorial_inputs["output"] / "considerations.md").is_file()
    assert not (editorial_inputs["output"] / "minimal-edit.md").exists()


def _pr37_packet_from_fixture(editorial_inputs):
    from validate_remediation_links import validate as validate_remediation_links

    packet_path = editorial_inputs["editorial-packet"]
    packet = json.loads(packet_path.read_text())
    packet["schema_version"] = "considerations-editorial-packet/v2"
    threats = json.loads(editorial_inputs["threats"].read_text())
    responses = json.loads(editorial_inputs["responses"].read_text())
    source = json.loads(editorial_inputs["source-packet"].read_text())
    snapshot = source["snapshot_identity"]["immutable_url"]
    traces = []
    for response in responses["responses"]:
        strategy = response["erta"]
        state = {
            "Eliminate": "removed",
            "Reduce": "specified",
            "Transfer": "delegated",
            "Accept": "proposed",
            "Unresolved": "unselected",
        }[strategy]
        row = {
            "threat_id": response["threat_id"],
            "response_id": response["response_id"],
            "strategies": [] if strategy == "Unresolved" else [strategy],
            "remediation": {
                "state": state,
                "description": "Mechanism or open question documented for the selected threat.",
                "specification_refs": [snapshot + "#access-gate"],
                "external_refs": [],
                "enforcing_actor": "Browser implementation",
                "failure_behavior": "Return permission denied; do not expose the information.",
                "source_strength": "normative",
                "normative_basis": "The target request authorization algorithm controls whether the API may disclose data.",
                "normative_evidence": [
                    {
                        "source_url": snapshot + "#access-gate",
                        "quote": (
                            "If the user agent finds an unauthorized document, terminate "
                            "this algorithm and return permission denied."
                        ),
                    }
                ],
            },
            "assumptions": ["The selected actor applies any specified check."],
            "remaining_threats": [
                {
                    "description": "An authorized recipient may still misuse received information.",
                    "accepted": False,
                }
            ],
            "issue_refs": [],
        }
        if strategy == "Eliminate":
            row["remediation"]["removed_feature_or_condition"] = (
                "Unsafe feature removed."
            )
        if strategy == "Transfer":
            row["remediation"]["receiving_actor"] = "Relying application"
            row["remediation"]["delegated_duty"] = (
                "Check origin and reject invalid input."
            )
            row["transfer_assumption"] = (
                "The application implements the delegated check."
            )
        if strategy == "Accept":
            row["acceptance_rationale"] = (
                "This remaining threat is documented and explicitly accepted."
            )
            row["review_conditions"] = ["Revisit if browser assumptions change."]
            row["acceptance_scope"] = (
                "The original implementation limitation is accepted while "
                "other recipient-side misuse may remain unaccepted."
            )
        if strategy == "Unresolved":
            row["remediation"]["description"] = (
                "No response selected; a decision is still open."
            )
            row["issue_refs"] = ["https://example.test/issues/5"]
        traces.append(row)
    # Demonstrate combined Reduce+Transfer, even with an upstream Transfer.
    transfer = next(item for item in traces if "Transfer" in item["strategies"])
    transfer["strategies"] = ["Transfer", "Reduce"]
    transfer["combination_rationale"] = (
        "Protection is delegated to an application whose specific checks reduce the threat."
    )
    packet["threat_responses"] = traces
    packet["out_of_scope"] = [
        {
            "threat": "Compromise of the underlying system storage",
            "rationale": "The storage service is outside the browser API's conformance boundary",
            "specification_refs": [snapshot + "#security"],
        }
    ]
    packet_path.write_text(json.dumps(packet))
    return packet, validate_remediation_links, threats, responses, source


def test_pr37_guide_contract_and_remaining_threats_in_final_output(editorial_inputs):
    packet, validate_links, threats, responses, source = _pr37_packet_from_fixture(
        editorial_inputs
    )
    result = validate_links(packet, threats, responses, source)
    assert result["threats"] == len(threats["threats"])
    assert result["out_of_scope_count"] == 1
    assert any(
        item["strategies"] == ["Transfer", "Reduce"] for item in result["records"]
    )
    assert any(item["strategies"] == [] for item in result["records"])
    output = run(editorial_inputs)
    assert output["status"] == "authored"
    assert output["remediation_trace"] is True
    directory = editorial_inputs["output"]
    assert (directory / "considerations-remediation-trace.json").is_file()
    prose = (directory / "considerations.md").read_text()
    assert "Out-of-scope threats" in prose
    assert "Remediation or open-decision reference" in prose
    assert (
        "minaccia residua"
        in (SCRIPT_DIR.parent / "references/w3c-guide-pr37-pr36.md").read_text()
    )


def test_pr37_rejects_missing_transfer_receiving_actor(editorial_inputs):
    packet, validate_links, threats, responses, source = _pr37_packet_from_fixture(
        editorial_inputs
    )
    row = next(
        item for item in packet["threat_responses"] if "Transfer" in item["strategies"]
    )
    row["remediation"].pop("receiving_actor")
    with pytest.raises(ValueError, match="receiving actor"):
        validate_links(packet, threats, responses, source)


def test_pr37_rejects_missing_acceptance_rationale(editorial_inputs):
    packet, validate_links, threats, responses, source = _pr37_packet_from_fixture(
        editorial_inputs
    )
    row = next(
        item for item in packet["threat_responses"] if "Accept" in item["strategies"]
    )
    del row["acceptance_rationale"]
    with pytest.raises(ValueError, match="acceptance rationale"):
        validate_links(packet, threats, responses, source)


def test_pr37_rejects_mismatched_remediation_snapshot(editorial_inputs):
    packet, validate_links, threats, responses, source = _pr37_packet_from_fixture(
        editorial_inputs
    )
    row = packet["threat_responses"][0]
    row["remediation"]["specification_refs"] = [
        "https://www.w3.org/TR/2025/WD-another-spec-20251113/#security"
    ]
    with pytest.raises(ValueError, match="pinned specification"):
        validate_links(packet, threats, responses, source)


def test_pr37_rejects_omitted_threat_and_unselected_strategy_leak(editorial_inputs):
    packet, validate_links, threats, responses, source = _pr37_packet_from_fixture(
        editorial_inputs
    )
    packet["threat_responses"].pop()
    with pytest.raises(ValueError, match="missing PR37 remediation dispositions"):
        validate_links(packet, threats, responses, source)
    packet, validate_links, threats, responses, source = _pr37_packet_from_fixture(
        editorial_inputs
    )
    row = next(
        item
        for item in packet["threat_responses"]
        if item["remediation"]["state"] == "unselected"
    )
    row["strategies"] = ["Reduce"]
    with pytest.raises(
        ValueError,
        match="unresolved upstream ERTA response|unselected remediation cannot claim",
    ):
        validate_links(packet, threats, responses, source)


def test_pr37_does_not_silently_drop_upstream_reduce(editorial_inputs):
    packet, validate_links, threats, responses, source = _pr37_packet_from_fixture(
        editorial_inputs
    )
    row = next(x for x in packet["threat_responses"] if x["response_id"] == "R-03")
    assert row["strategies"] == ["Reduce"]
    row["strategies"] = []
    row["remediation"]["state"] = "unselected"
    row["open_decision_note"] = "The group has not yet opened a tracking issue."
    with pytest.raises(ValueError, match="selected ERTA response strategy"):
        validate_links(packet, threats, responses, source)


def test_pr37_does_not_promote_unresolved_response_to_specified(editorial_inputs):
    packet, validate_links, threats, responses, source = _pr37_packet_from_fixture(
        editorial_inputs
    )
    row = next(x for x in packet["threat_responses"] if x["response_id"] == "R-05")
    row["strategies"] = ["Reduce"]
    row["remediation"]["state"] = "specified"
    with pytest.raises(ValueError, match="unresolved upstream"):
        validate_links(packet, threats, responses, source)


def test_pr37_informative_guidance_is_not_a_normative_specified_remediation(
    editorial_inputs,
):
    packet, validate_links, threats, responses, source = _pr37_packet_from_fixture(
        editorial_inputs
    )
    row = next(x for x in packet["threat_responses"] if x["response_id"] == "R-03")
    row["remediation"]["source_strength"] = "informative"
    with pytest.raises(ValueError, match="normative"):
        validate_links(packet, threats, responses, source)


def test_pr37_untracked_open_response_can_be_documented_without_issue_url(
    editorial_inputs,
):
    packet, validate_links, threats, responses, source = _pr37_packet_from_fixture(
        editorial_inputs
    )
    row = next(x for x in packet["threat_responses"] if x["response_id"] == "R-05")
    row["issue_refs"] = []
    row["remediation"]["specification_refs"] = []
    row["remediation"]["external_refs"] = []
    row["open_decision_note"] = (
        "The response remains unresolved; no public tracking issue exists yet."
    )
    result = validate_links(packet, threats, responses, source)
    assert result["threats"] == len(threats["threats"])


def test_edit_modes_rewrite_and_propose_compose(editorial_inputs):
    packet = json.loads(editorial_inputs["editorial-packet"].read_text())
    for mode in ("rewrite", "propose"):
        packet["editing"]["mode"] = mode
        editorial_inputs["editorial-packet"].write_text(json.dumps(packet))
        result = run(editorial_inputs)
        assert result["editing_mode"] == mode
        assert (editorial_inputs["output"] / "considerations.md").exists()
        import shutil

        shutil.rmtree(editorial_inputs["output"])


def test_qa_failure_does_not_leave_partial_artifacts(editorial_inputs):
    packet = json.loads(editorial_inputs["editorial-packet"].read_text())
    packet["sections"]["security"]["introduction"] = (
        "There are no security considerations associated with Geolocation."
    )
    editorial_inputs["editorial-packet"].write_text(json.dumps(packet))
    with pytest.raises(ValueError, match="editorial QA failed"):
        run(editorial_inputs)
    assert not editorial_inputs["output"].exists()


def test_pr37_remaining_threats_are_represented_in_reader_prose(editorial_inputs):
    packet, _, _, _, _ = _pr37_packet_from_fixture(editorial_inputs)
    record = next(
        row for row in packet["threat_responses"] if row["response_id"] == "R-03"
    )
    unique = "The still-authorized hostile application can recover the original secret."
    record["remaining_threats"][0]["description"] = unique
    editorial_inputs["editorial-packet"].write_text(json.dumps(packet))
    result = run(editorial_inputs)
    assert result["remediation_trace"] is True
    rendered = (editorial_inputs["output"] / "considerations.md").read_text()
    assert unique in rendered


def test_specified_remediation_rejects_fabricated_normative_excerpt(editorial_inputs):
    packet, validate_links, threats, responses, source = _pr37_packet_from_fixture(
        editorial_inputs
    )
    row = next(
        item for item in packet["threat_responses"] if item["response_id"] == "R-03"
    )
    row["remediation"]["normative_evidence"][0]["quote"] = (
        "The user agent MUST perform a made-up source verification step."
    )
    with pytest.raises(ValueError, match="not found verbatim"):
        validate_links(packet, threats, responses, source)


def test_specified_remediation_rejects_non_normative_quoted_recipient_guidance(
    editorial_inputs,
):
    packet, validate_links, threats, responses, source = _pr37_packet_from_fixture(
        editorial_inputs
    )
    snapshot = source["snapshot_identity"]["immutable_url"]
    recipient = next(s for s in source["sections"] if s["anchor"] == "recipient")
    recipient["raw_text"] = (
        "This section is non-normative. "
        "Recipients are encouraged to delete received information "
        "after completing their application task."
    )
    row = next(
        item for item in packet["threat_responses"] if item["response_id"] == "R-03"
    )
    row["remediation"]["specification_refs"] = [snapshot + "#recipient"]
    row["remediation"]["normative_evidence"] = [
        {
            "source_url": snapshot + "#recipient",
            "quote": (
                "Recipients are encouraged to delete received information "
                "after completing their application task."
            ),
        }
    ]
    with pytest.raises(ValueError, match="non-normative|informative"):
        validate_links(packet, threats, responses, source)


def test_specified_remediation_cannot_rely_solely_on_unpinned_external_url(
    editorial_inputs,
):
    packet, validate_links, threats, responses, source = _pr37_packet_from_fixture(
        editorial_inputs
    )
    row = next(
        item for item in packet["threat_responses"] if item["response_id"] == "R-03"
    )
    row["remediation"]["specification_refs"] = []
    row["remediation"]["external_refs"] = [
        "https://example.org/supposed-normative-mechanism"
    ]
    row["remediation"]["normative_evidence"] = []
    with pytest.raises(ValueError, match="external-only specified remediation"):
        validate_links(packet, threats, responses, source)
