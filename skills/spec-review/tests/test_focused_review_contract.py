from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from spec_review.focused_review_contract import (  # noqa: E402
    ALLOWED_PRIOR_FEEDBACK_DISPOSITIONS,
    ALLOWED_PRIOR_FEEDBACK_RELATIONSHIPS,
    PRIOR_FEEDBACK_RELATIONSHIP_DISPOSITION,
    validate_focused_review,
    validate_focused_review_files,
)


COMMENT = """I found one additional issue beyond the [earlier review](https://example.test/reviews/12). That review covers direct timing observations. In this API, an embedded document that can start a transition may cause its parent to receive a completion signal whose delay differs when a protected resource exists. Only the completion delay is observable, without reading that resource. Browser scheduling may reduce measurement precision. The [API definition](https://example.test/spec#completion) establishes the signal, while an [implementation study](https://research.example.test/timing) documents the observable timing pattern. Could the Security Considerations describe the embedding and timing prerequisites and recommend constant-shape completion?"""


def evidence_packet() -> dict[str, object]:
    return {
        "artifact_kind": "focused_w3c_security_reply_evidence",
        "review_mode": "focused_w3c_reply",
        "output_register": "single_finding_w3c_issue_comment",
        "review_capacity": "individual",
        "publication_decision": "publish_single_finding",
        "target": {
            "specification": "Synthetic Transition API",
            "issue_url": "https://example.test/issues/44",
        },
        "search_evidence": [
            {
                "evidence_id": "prior-review-search-1",
                "source_url": "https://example.test/reviews/search",
            }
        ],
        "prior_feedback": [
            {
                "domain": "privacy",
                "prior_feedback_url": "https://example.test/reviews/12",
                "evidence": [
                    {
                        "evidence_id": "prior-finding-12",
                        "source_url": "https://example.test/reviews/12",
                    }
                ],
                "relationship": "distinct",
                "disposition": "retain_distinct",
                "rationale": "The earlier review covers direct observations, not the completion signal.",
                "distinct_delta": "The completion signal adds an indirect timing observation.",
                "prior_issue_state": "closed",
                "conclusion": "unable_to_verify",
                "conclusion_evidence": [],
            }
        ],
        "finding": {
            "distinct_delta": "The completion signal adds an indirect timing observation.",
            "mechanism": "A parent may receive a completion signal after an embedded transition.",
            "prerequisites": [
                "The attacker controls an embedded document and can start a transition."
            ],
            "consequence": "Protected resource existence becomes observable as a timing class through a completion delay.",
            "limitations": ["Only the completion delay is observable."],
            "non_claims": [
                "The mechanism operates without reading the protected resource."
            ],
            "target_section": "Security Considerations",
            "requested_change": "Document prerequisites and constant-shape completion as a mitigation.",
            "requested_change_strength": "informative_documentation",
            "requested_change_components": [
                "prerequisites",
                "constant-shape completion",
            ],
            "sources": [
                {
                    "url": "https://example.test/spec#completion",
                    "role": "Defines the completion signal.",
                    "public_required": True,
                },
                {
                    "url": "https://research.example.test/timing",
                    "role": "Demonstrates the timing pattern.",
                    "public_required": True,
                },
            ],
            "uncertainties": ["Browser scheduling may reduce measurement precision."],
            "public_projection_markers": {
                "distinct_delta": ["completion signal"],
                "mechanism": ["receive a completion signal"],
                "prerequisites": ["embedded document", "start a transition"],
                "consequence": ["protected resource", "delay"],
                "limitations": ["completion delay"],
                "non_claims": ["without reading"],
                "requested_change": ["constant-shape completion"],
                "requested_change_components": [
                    "prerequisites",
                    "constant-shape completion",
                ],
                "uncertainties": ["Browser scheduling"],
            },
        },
        "consensus_evidence": [],
    }


def test_valid_single_finding_reply() -> None:
    result = validate_focused_review(evidence_packet(), COMMENT)

    assert result.ok, result.errors
    assert 50 <= result.word_count <= 140
    assert result.link_count == 3


def test_all_prior_feedback_relationships_and_dispositions_are_supported() -> None:
    assert ALLOWED_PRIOR_FEEDBACK_RELATIONSHIPS == {
        "duplicate",
        "refinement",
        "distinct",
        "follow_up_existing",
        "unable_to_verify",
    }
    assert ALLOWED_PRIOR_FEEDBACK_DISPOSITIONS == {
        "retain_distinct",
        "exclude_already_raised",
        "merge",
        "follow_up_existing",
        "unable_to_verify",
    }
    assert (
        PRIOR_FEEDBACK_RELATIONSHIP_DISPOSITION["duplicate"] == "exclude_already_raised"
    )
    assert PRIOR_FEEDBACK_RELATIONSHIP_DISPOSITION["refinement"] == "merge"
    assert PRIOR_FEEDBACK_RELATIONSHIP_DISPOSITION["distinct"] == "retain_distinct"


def test_retained_prior_feedback_requires_distinct_delta() -> None:
    evidence = evidence_packet()
    evidence["prior_feedback"][0]["distinct_delta"] = ""  # type: ignore[index]

    result = validate_focused_review(evidence, COMMENT)

    assert not result.ok
    assert any("distinct_delta is required" in error for error in result.errors)


def test_public_projection_rejects_report_shape_and_group_authority() -> None:
    comment = "# Finding\n\n| Item | Value |\n| --- | --- |\n\n" + COMMENT.replace(
        "I found", "We found"
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert "comment.md must not contain headings" in result.errors
    assert "comment.md must not contain tables" in result.errors
    assert any("first-person plural" in error for error in result.errors)


def test_public_projection_rejects_setext_and_html_report_scaffolding() -> None:
    comment = (
        "Finding\n=======\n\n<table><tr><td>hidden report shape</td></tr></table>\n\n"
        + COMMENT
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert "comment.md must not contain headings" in result.errors
    assert "comment.md must not contain tables" in result.errors


def test_focused_route_rejects_group_authorized_capacity() -> None:
    evidence = evidence_packet()
    evidence["review_capacity"] = "group_authorized"
    comment = COMMENT.replace("I found", "We found")

    result = validate_focused_review(evidence, comment)

    assert not result.ok
    assert any(
        "route group-authorized findings through the full-review contract" in error
        for error in result.errors
    )
    assert any("first-person plural" in error for error in result.errors)


def test_individual_route_rejects_on_behalf_group_voice() -> None:
    comment = COMMENT.replace(
        "I found", "On behalf of the Security Interest Group, I found"
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any(
        "must not claim to speak on behalf of a group" in error
        for error in result.errors
    )


def test_individual_route_rejects_other_group_attribution_phrases() -> None:
    for prefix in (
        "Writing for the Security Interest Group, I found",
        "Speaking for the Security Interest Group, I found",
        "Posting for PING, I found",
        "Representing the Security Interest Group, I found",
        "As the Security Interest Group reviewer, I found",
        "I am the Security Interest Group reviewer and I found",
        "The Security Interest Group and I found",
        "The reviewers and I found",
        "My colleagues and I found",
    ):
        comment = COMMENT.replace("I found", prefix)

        result = validate_focused_review(evidence_packet(), comment)

        assert not result.ok
        assert any(
            "must not claim to speak on behalf of a group" in error
            for error in result.errors
        )


def test_individual_voice_phrases_are_not_mistaken_for_group_authority() -> None:
    for prefix in (
        "As the individual reviewer, I found",
        "Writing for the record, I found",
        "Speaking for myself, I found",
        "Posting for the record, I found",
        "Representing my own view, I found",
    ):
        result = validate_focused_review(
            evidence_packet(), COMMENT.replace("I found", prefix)
        )

        assert result.ok, result.errors


def test_group_position_requires_consensus_evidence() -> None:
    comment = COMMENT.replace(
        "I found one additional issue",
        "I note that the Working Group found one additional issue",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any("consensus or disposition claim" in error for error in result.errors)


def test_named_w3c_group_position_requires_consensus_evidence() -> None:
    comment = COMMENT.replace(
        "I found one additional issue", "The PING found one additional issue; I found"
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any("consensus or disposition claim" in error for error in result.errors)


def test_public_projection_rejects_unregistered_source() -> None:
    comment = COMMENT.replace(
        "https://research.example.test/timing",
        "https://unregistered.example.test/timing",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any("not registered" in error for error in result.errors)


def test_public_projection_rejects_private_search_evidence_url() -> None:
    comment = COMMENT.replace(
        "That review covers direct timing observations.",
        "That review covers direct timing observations; the [search record](https://example.test/reviews/search) remains private evidence.",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any(
        "https://example.test/reviews/search" in error and "not registered" in error
        for error in result.errors
    )


def test_public_projection_rejects_non_public_finding_source() -> None:
    evidence = evidence_packet()
    evidence["finding"]["sources"].append(  # type: ignore[index]
        {
            "url": "https://corroboration.example.test/private-note",
            "role": "Private corroboration retained in the evidence packet.",
            "public_required": False,
        }
    )
    comment = COMMENT.replace(
        "documents the observable timing pattern.",
        "documents the observable timing pattern; a [corroborating note](https://corroboration.example.test/private-note) is retained separately.",
    )

    result = validate_focused_review(evidence, comment)

    assert not result.ok
    assert any(
        "https://corroboration.example.test/private-note" in error
        and "not registered" in error
        for error in result.errors
    )


def test_public_projection_rejects_duplicate_urls_and_missing_required_role() -> None:
    comment = COMMENT.replace(
        "https://research.example.test/timing",
        "https://example.test/spec#completion",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert "comment.md must not repeat the same URL" in result.errors
    assert any(
        "omits public_required finding sources" in error for error in result.errors
    )


def test_public_required_sources_need_distinct_roles() -> None:
    evidence = evidence_packet()
    sources = evidence["finding"]["sources"]  # type: ignore[index]
    sources[1]["role"] = sources[0]["role"]

    result = validate_focused_review(evidence, COMMENT)

    assert not result.ok
    assert any("distinct evidence roles" in error for error in result.errors)


def test_finding_sources_cannot_repeat_a_url_under_different_roles() -> None:
    evidence = evidence_packet()
    sources = evidence["finding"]["sources"]  # type: ignore[index]
    sources[1]["url"] = sources[0]["url"]

    result = validate_focused_review(evidence, COMMENT)

    assert not result.ok
    assert "finding.sources must not repeat the same URL" in result.errors


def test_finding_source_dedup_normalizes_scheme_host_and_default_port() -> None:
    evidence = evidence_packet()
    sources = evidence["finding"]["sources"]  # type: ignore[index]
    sources[1]["url"] = "HTTPS://EXAMPLE.TEST:443/spec#completion"

    result = validate_focused_review(evidence, COMMENT)

    assert not result.ok
    assert "finding.sources must not repeat the same URL" in result.errors


def test_duplicate_only_packet_produces_no_public_finding() -> None:
    evidence = evidence_packet()
    evidence["publication_decision"] = "no_new_finding"
    evidence["finding"] = None
    prior = copy.deepcopy(evidence["prior_feedback"][0])  # type: ignore[index]
    prior.update(
        {
            "relationship": "duplicate",
            "disposition": "exclude_already_raised",
            "rationale": "The candidate is already covered by the earlier review.",
            "distinct_delta": "",
        }
    )
    evidence["prior_feedback"] = [prior]

    result = validate_focused_review(evidence, "")

    assert result.ok, result.errors
    assert result.word_count == 0
    assert result.link_count == 0


def test_no_finding_rejects_a_retained_distinct_delta() -> None:
    evidence = evidence_packet()
    evidence["publication_decision"] = "no_new_finding"
    evidence["finding"] = None

    result = validate_focused_review(evidence, "")

    assert not result.ok
    assert any("cannot retain" in error for error in result.errors)


def test_prior_feedback_rejects_inconsistent_relationship_disposition() -> None:
    evidence = evidence_packet()
    evidence["prior_feedback"][0]["disposition"] = "exclude_already_raised"  # type: ignore[index]

    result = validate_focused_review(evidence, COMMENT)

    assert not result.ok
    assert any("for relationship 'distinct'" in error for error in result.errors)


def test_public_projection_requires_one_prior_boundary_link() -> None:
    comment = COMMENT.replace(
        "[API definition](https://example.test/spec#completion)",
        "[earlier review again](https://example.test/reviews/12)",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any("exactly one" in error for error in result.errors)


def test_public_projection_accepts_one_declarative_request() -> None:
    comment = COMMENT.replace(
        "Could the Security Considerations describe the embedding and timing prerequisites and recommend constant-shape completion?",
        "Please describe the embedding and timing prerequisites and recommend constant-shape completion in the Security Considerations.",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert result.ok, result.errors


def test_public_projection_accepts_documentation_question_form() -> None:
    comment = COMMENT.replace(
        "Could the Security Considerations describe the embedding and timing prerequisites and recommend constant-shape completion?",
        "It is possible to document the embedding and timing prerequisites and constant-shape completion in the Security Considerations?",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert result.ok, result.errors


def test_public_projection_rejects_more_than_one_question() -> None:
    comment = COMMENT + " Is a separate implementation note also needed?"

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any("one actionable question or request" in error for error in result.errors)


def test_public_projection_rejects_an_earlier_declarative_request() -> None:
    comment = COMMENT.replace(
        "Browser scheduling may reduce measurement precision.",
        "Please document this in the overview. Browser scheduling may reduce measurement precision.",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any("one actionable question or request" in error for error in result.errors)


def test_public_projection_rejects_an_earlier_bare_imperative() -> None:
    comment = COMMENT.replace(
        "Browser scheduling may reduce measurement precision.",
        "Document this in the overview. Browser scheduling may reduce measurement precision.",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any("one actionable question or request" in error for error in result.errors)


def test_public_projection_rejects_common_review_imperatives_before_final_ask() -> None:
    for verb in ("Fix", "Remove", "Avoid", "Ensure", "Delete", "Replace", "Move"):
        comment = COMMENT.replace(
            "Browser scheduling may reduce measurement precision.",
            f"{verb} this in the overview. Browser scheduling may reduce measurement precision.",
        )

        result = validate_focused_review(evidence_packet(), comment)

        assert not result.ok
        assert any(
            "one actionable question or request" in error for error in result.errors
        )


def test_non_actionable_final_question_is_rejected() -> None:
    comment = COMMENT.replace(
        "Could the Security Considerations describe the embedding and timing prerequisites and recommend constant-shape completion?",
        "Why does this matter for the Security Considerations?",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any("one actionable question or request" in error for error in result.errors)


def test_descriptive_modal_does_not_substitute_for_a_final_request() -> None:
    comment = COMMENT.replace(
        "Could the Security Considerations describe the embedding and timing prerequisites and recommend constant-shape completion?",
        "This matters for the Security Considerations.",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any("one actionable question or request" in error for error in result.errors)


def test_final_request_must_preserve_target_section_and_requested_change() -> None:
    evidence = evidence_packet()
    evidence["finding"]["target_section"] = "Privacy Considerations"  # type: ignore[index]
    comment = COMMENT.replace(
        "Could the Security Considerations describe the embedding and timing prerequisites and recommend constant-shape completion?",
        "Could the Security Considerations document an unrelated spelling preference?",
    )

    result = validate_focused_review(evidence, comment)

    assert not result.ok
    assert any("must name finding.target_section" in error for error in result.errors)
    assert any(
        "must preserve the requested_change marker" in error for error in result.errors
    )


def test_final_request_must_preserve_each_requested_change_component() -> None:
    comment = COMMENT.replace(
        "Could the Security Considerations describe the embedding and timing prerequisites and recommend constant-shape completion?",
        "Could the Security Considerations mention whether constant-shape completion needs a hyphen?",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any(
        "requested_change_components marker 'prerequisites'" in error
        for error in result.errors
    )


def test_requested_change_components_must_be_atomic() -> None:
    evidence = evidence_packet()
    evidence["finding"]["requested_change_components"] = [  # type: ignore[index]
        "prerequisites and constant-shape completion"
    ]
    evidence["finding"]["public_projection_markers"][  # type: ignore[index]
        "requested_change_components"
    ] = ["constant-shape completion"]

    result = validate_focused_review(evidence, COMMENT)

    assert not result.ok
    assert any("must be atomic" in error for error in result.errors)


def test_normative_request_cannot_be_downgraded_in_the_comment() -> None:
    evidence = evidence_packet()
    evidence["finding"]["requested_change"] = (
        "Require implementations to use constant-shape completion."  # type: ignore[index]
    )
    evidence["finding"]["requested_change_strength"] = "normative_requirement"  # type: ignore[index]

    result = validate_focused_review(evidence, COMMENT)

    assert not result.ok
    assert any(
        "does not preserve the normative force" in error for error in result.errors
    )


def test_informative_request_cannot_be_upgraded_in_the_comment() -> None:
    comment = COMMENT.replace(
        "Could the Security Considerations describe the embedding and timing prerequisites and recommend constant-shape completion?",
        "Could the Security Considerations require implementations to use constant-shape completion?",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any(
        "upgrades an informative documentation request" in error
        for error in result.errors
    )


def test_requested_change_wording_must_match_its_declared_strength() -> None:
    evidence = evidence_packet()
    evidence["finding"]["requested_change"] = (
        "Require implementations to use constant-shape completion."  # type: ignore[index]
    )

    result = validate_focused_review(evidence, COMMENT)

    assert not result.ok
    assert any(
        "requested_change uses normative force" in error for error in result.errors
    )


def test_public_projection_must_preserve_packet_markers() -> None:
    comment = COMMENT.replace("embedded document", "caller").replace(
        "without reading", "without observing"
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any(
        "prerequisites marker 'embedded document'" in error for error in result.errors
    )
    assert any(
        "non_claims marker 'without reading'" in error for error in result.errors
    )


def test_each_material_list_entry_requires_a_derived_public_marker() -> None:
    evidence = evidence_packet()
    evidence["finding"]["prerequisites"].append(
        "The parent can observe completion timing."
    )  # type: ignore[index]
    evidence["finding"]["uncertainties"].append(
        "Timer coarsening may collapse nearby classes."
    )  # type: ignore[index]

    result = validate_focused_review(evidence, COMMENT)

    assert not result.ok
    assert any(
        "public_projection_markers.prerequisites must provide a distinct derived public marker for each material entry"
        in error
        for error in result.errors
    )
    assert any(
        "public_projection_markers.uncertainties must provide a distinct derived public marker for each material entry"
        in error
        for error in result.errors
    )


def test_shared_marker_cannot_cover_two_material_entries() -> None:
    evidence = evidence_packet()
    evidence["finding"]["prerequisites"].append(
        "The embedded document can measure a separate response clock."
    )  # type: ignore[index]

    result = validate_focused_review(evidence, COMMENT)

    assert not result.ok
    assert any(
        "public_projection_markers.prerequisites must provide a distinct derived public marker for each material entry"
        in error
        for error in result.errors
    )


def test_recorded_non_claim_requires_a_public_projection_marker() -> None:
    evidence = evidence_packet()
    del evidence["finding"]["public_projection_markers"]["non_claims"]  # type: ignore[index]

    result = validate_focused_review(evidence, COMMENT)

    assert not result.ok
    assert any(
        "public_projection_markers.non_claims" in error for error in result.errors
    )


def test_projection_markers_must_derive_from_their_finding_fields() -> None:
    evidence = evidence_packet()
    evidence["finding"]["public_projection_markers"]["prerequisites"] = ["review"]  # type: ignore[index]

    result = validate_focused_review(evidence, COMMENT)

    assert not result.ok
    assert any("marker 'review' is too generic" in error for error in result.errors)
    assert any(
        "not derived from the corresponding finding field" in error
        for error in result.errors
    )


def test_projection_marker_cannot_be_only_a_stopword() -> None:
    evidence = evidence_packet()
    evidence["finding"]["public_projection_markers"]["limitations"] = ["Only"]  # type: ignore[index]

    result = validate_focused_review(evidence, COMMENT)

    assert not result.ok
    assert any("marker 'Only' is too generic" in error for error in result.errors)


def test_verified_negative_prior_search_allows_a_genuinely_new_finding() -> None:
    evidence = evidence_packet()
    evidence["prior_feedback"] = []
    comment = COMMENT.replace(
        "I found one additional issue beyond the [earlier review](https://example.test/reviews/12). That review covers direct timing observations. ",
        "I found one security issue. ",
    )

    result = validate_focused_review(evidence, comment)

    assert result.ok, result.errors
    assert result.link_count == 2


def test_new_finding_without_prior_search_evidence_is_rejected() -> None:
    evidence = evidence_packet()
    evidence["prior_feedback"] = []
    evidence["search_evidence"] = []
    comment = COMMENT.replace(
        "I found one additional issue beyond the [earlier review](https://example.test/reviews/12). That review covers direct timing observations. ",
        "I found one security issue. ",
    )

    result = validate_focused_review(evidence, comment)

    assert not result.ok
    assert any("search_evidence" in error for error in result.errors)


def test_malformed_urls_return_validation_errors_instead_of_raising() -> None:
    for malformed in ("https://[bad", "https://example.test:bad/path"):
        evidence = evidence_packet()
        evidence["target"]["issue_url"] = malformed  # type: ignore[index]

        result = validate_focused_review(evidence, COMMENT)

        assert not result.ok
        assert "target.issue_url must be an HTTP(S) URL" in result.errors


def test_duplicate_only_packet_cannot_publish_a_new_finding() -> None:
    evidence = evidence_packet()
    prior = evidence["prior_feedback"][0]  # type: ignore[index]
    prior["relationship"] = "duplicate"
    prior["disposition"] = "exclude_already_raised"
    prior["distinct_delta"] = ""

    result = validate_focused_review(evidence, COMMENT)

    assert not result.ok
    assert any("duplicate-only" in error for error in result.errors)


def test_consensus_claim_requires_registered_citation() -> None:
    comment = COMMENT.replace("That review covers", "That accepted review covers")

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any("consensus or disposition" in error for error in result.errors)


def test_html_comments_cannot_hide_the_evidence_projection() -> None:
    comment = f"<!-- {COMMENT} -->\n\nI found one issue. Please document it in Security Considerations."

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert "comment.md must not contain HTML comments" in result.errors


def test_unclosed_html_comment_token_is_rejected() -> None:
    result = validate_focused_review(evidence_packet(), "<!--\n" + COMMENT)

    assert not result.ok
    assert "comment.md must not contain HTML comments" in result.errors


def test_non_http_link_destinations_are_rejected() -> None:
    comment = COMMENT.replace(
        "That review covers direct timing observations.",
        "That review covers direct timing observations; the [local packet](file:///private/tmp/evidence.json) is not public evidence.",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any("non-HTTP(S) link destinations" in error for error in result.errors)


def test_http_autolink_is_not_mistaken_for_raw_html() -> None:
    comment = COMMENT.replace(
        "[API definition](https://example.test/spec#completion)",
        "<https://example.test/spec#completion>",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert result.ok, result.errors


def test_markdown_images_cannot_reference_private_artifacts() -> None:
    comment = COMMENT.replace(
        "That review covers direct timing observations.",
        "That review covers direct timing observations. ![packet](file:///private/tmp/evidence.json)",
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert "comment.md must not contain Markdown images" in result.errors
    assert any("non-HTTP(S) link destinations" in error for error in result.errors)


def test_citation_urls_inside_code_spans_do_not_count_as_links() -> None:
    comment = COMMENT
    for url in (
        "https://example.test/reviews/12",
        "https://example.test/spec#completion",
        "https://research.example.test/timing",
    ):
        comment = comment.replace(f"]({url})", f"](`{url} `)")

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert "comment.md must not put citation URLs inside code spans" in result.errors


def test_reference_style_links_and_images_are_rejected() -> None:
    for usage in ("[local packet][pkt]", "![packet][pkt]"):
        comment = COMMENT.replace(
            "That review covers direct timing observations.",
            f"That review covers direct timing observations. {usage}\n\n[pkt]: file:///private/tmp/evidence.json",
        )

        result = validate_focused_review(evidence_packet(), comment)

        assert not result.ok
        assert (
            "comment.md must not use reference-style Markdown links or images"
            in result.errors
        )
        assert any("non-HTTP(S) link destinations" in error for error in result.errors)


def test_inline_link_title_does_not_hide_non_http_destination() -> None:
    comment = COMMENT.replace(
        "That review covers direct timing observations.",
        'That review covers direct timing observations. [local packet](file:///private/tmp/evidence.json "private")',
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert any("non-HTTP(S) link destinations" in error for error in result.errors)


def test_markdown_link_title_cannot_carry_private_packet_details() -> None:
    comment = COMMENT.replace(
        "[API definition](https://example.test/spec#completion)",
        '[API definition](https://example.test/spec#completion "evidence packet at file:///private/tmp/evidence.json")',
    )

    result = validate_focused_review(evidence_packet(), comment)

    assert not result.ok
    assert "comment.md must not use Markdown link titles" in result.errors
    assert (
        "comment.md must not narrate the private search or review process"
        in result.errors
    )
    assert "comment.md must not expose local paths or file URLs" in result.errors


def test_raw_html_and_code_blocks_are_rejected() -> None:
    variants = (
        "<details><summary>Finding</summary>\n" + COMMENT,
        '<a href="file:///private/tmp/evidence.json">local packet</a>\n' + COMMENT,
        "```text\n" + COMMENT + "\n```",
        "    " + COMMENT,
        "     " + COMMENT,
        "        " + COMMENT,
    )
    for comment in variants:
        result = validate_focused_review(evidence_packet(), comment)

        assert not result.ok
        assert any(
            error in result.errors
            for error in (
                "comment.md must not contain raw HTML",
                "comment.md must not contain code blocks",
            )
        )


def test_block_quotes_cannot_hide_code_or_review_fields() -> None:
    variants = (
        ">     " + COMMENT,
        "> Concern: " + COMMENT,
    )
    for comment in variants:
        result = validate_focused_review(evidence_packet(), comment)

        assert not result.ok
        assert "comment.md must not contain block quotes" in result.errors


def test_full_review_scaffolding_is_rejected() -> None:
    variants = (
        "Dear Group, " + COMMENT,
        "Thanks.\n\nDear Group, " + COMMENT,
        "Concern: "
        + COMMENT.replace("In this API,", "Impact: In this API,").replace(
            "The [API definition]", "Evidence: The [API definition]"
        ),
        "Context\nConcern: " + COMMENT,
        "Context; Concern: " + COMMENT,
    )
    for comment in variants:
        result = validate_focused_review(evidence_packet(), comment)

        assert not result.ok
        assert (
            "comment.md must not contain full-review scaffolding or field labels"
            in result.errors
        )


def test_public_comment_cannot_narrate_private_review_process() -> None:
    prefixes = (
        "I searched the tracker before I found",
        "I reviewed the tracker before I found",
        "I checked the prior issues before I found",
        "I compared and deduplicated prior comments before I found",
    )
    for prefix in prefixes:
        result = validate_focused_review(
            evidence_packet(), COMMENT.replace("I found", prefix)
        )

        assert not result.ok
        assert (
            "comment.md must not narrate the private search or review process"
            in result.errors
        )


def test_public_comment_cannot_expose_bare_local_paths() -> None:
    local_references = (
        "file:///private/tmp/evidence.json",
        "file:/private/tmp/evidence.json",
        "~/review/evidence.json",
        "./evidence.json",
        "/var/folders/packet.json",
    )
    for reference in local_references:
        comment = COMMENT.replace(
            "That review covers direct timing observations.",
            f"That review covers direct timing observations. A local note is at {reference}.",
        )

        result = validate_focused_review(evidence_packet(), comment)

        assert not result.ok
        assert "comment.md must not expose local paths or file URLs" in result.errors


def test_evidence_and_comment_must_be_separate_files(tmp_path: Path) -> None:
    shared = tmp_path / "packet.json"
    shared.write_text(json.dumps(evidence_packet()))

    result = validate_focused_review_files(shared, shared)

    assert not result.ok
    assert result.errors == (
        "evidence packet and public comment must be separate files",
    )


def test_file_validator_reads_utf8_artifacts(tmp_path: Path) -> None:
    evidence_path = tmp_path / "evidence-packet.json"
    comment_path = tmp_path / "comment.md"
    evidence_path.write_text(
        json.dumps(copy.deepcopy(evidence_packet())), encoding="utf-8"
    )
    comment_path.write_text(COMMENT, encoding="utf-8")

    result = validate_focused_review_files(evidence_path, comment_path)

    assert result.ok, result.errors


def test_file_validator_reports_invalid_json_without_traceback(tmp_path: Path) -> None:
    evidence_path = tmp_path / "evidence-packet.json"
    comment_path = tmp_path / "comment.md"
    evidence_path.write_text("not-json", encoding="utf-8")
    comment_path.write_text(COMMENT, encoding="utf-8")

    result = validate_focused_review_files(evidence_path, comment_path)

    assert not result.ok
    assert any("not valid JSON" in error for error in result.errors)


def test_cli_validates_separate_artifacts(tmp_path: Path) -> None:
    evidence_path = tmp_path / "evidence-packet.json"
    comment_path = tmp_path / "comment.md"
    evidence_path.write_text(json.dumps(evidence_packet()), encoding="utf-8")
    comment_path.write_text(COMMENT, encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate_focused_review.py"),
            "--evidence",
            str(evidence_path),
            "--comment",
            str(comment_path),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["status"] == "pass"


def test_cli_reports_malformed_url_without_traceback(tmp_path: Path) -> None:
    evidence = evidence_packet()
    evidence["target"]["issue_url"] = "https://[bad"  # type: ignore[index]
    evidence_path = tmp_path / "evidence-packet.json"
    comment_path = tmp_path / "comment.md"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    comment_path.write_text(COMMENT, encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate_focused_review.py"),
            "--evidence",
            str(evidence_path),
            "--comment",
            str(comment_path),
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "Traceback" not in completed.stderr
    assert "target.issue_url must be an HTTP(S) URL" in completed.stdout
