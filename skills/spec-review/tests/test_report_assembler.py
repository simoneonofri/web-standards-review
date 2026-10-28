from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from spec_review.report_assembler import (  # noqa: E402
    _publication_gate_path,
    _transfer_and_assumption_summary,
    _validate_local_links,
    _what_is_missing,
    _what_can_go_wrong_intro,
    assemble_report,
)
from spec_review.report_contract import ReportExpectations, validate_report_contract  # noqa: E402


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value))


def test_what_can_go_wrong_intro_for_as_is_only() -> None:
    intro = _what_can_go_wrong_intro({}, [])

    assert "reconstructs the as-is threat baseline" in intro
    assert "No later full-elicitation pass is included" in intro
    assert "same DFD model" not in intro
    assert "diagram model" not in intro


def test_publication_gate_uses_direct_repair_layout(tmp_path: Path) -> None:
    (tmp_path / "model").mkdir()
    (tmp_path / "quality").mkdir()

    assert _publication_gate_path(tmp_path) == tmp_path / "quality" / "publication-gate.json"


def test_transfer_summary_is_derived_from_response_data() -> None:
    summary = _transfer_and_assumption_summary([{
        "threat_id": "T-09",
        "erta": "Transfer",
        "transfer_receiver": "HTML integration owners",
        "response": "Maintain cross-document routing invariants.",
        "assumptions": ["A-031", "A-073"],
        "remaining_threat": "An integration defect can still misroute an event.",
    }])

    assert "HTML integration owners" in summary
    assert "Maintain cross-document routing invariants." in summary
    assert "A-031; A-073" in summary
    assert "An integration defect can still misroute an event." in summary
    assert "location data" not in summary


def test_local_link_validation_resolves_from_report_directory(tmp_path: Path) -> None:
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    (tmp_path / "dfd.svg").write_text("<svg/>")

    assert not _validate_local_links("[DFD](../dfd.svg)", report_dir / "review.md")
    assert _validate_local_links("[Missing](../missing.json)", report_dir / "review.md") == [
        "report contains a missing local link target: ../missing.json"
    ]


def test_latest_versioned_skeptic_findings_override_stale_canonical(tmp_path: Path) -> None:
    quality = tmp_path / "quality"
    quality.mkdir()
    (quality / "shostack-skeptic-what-is-missing.md").write_text("- stale finding\n")
    (quality / "shostack-skeptic-v2-what-is-missing.md").write_text("- current finding\n")

    assert _what_is_missing(tmp_path) == "- current finding"


def test_report_contract_rejects_residual_threat_questions() -> None:
    markdown = """# Test
## Introduction
source-grounded baseline plus additional spec-review run
Review categories and lenses:
Model level for What Are We Building:
## What Are We Building
Model coverage:
assumptions-and-follow-up.md
### Diagram
### Dictionary
| ID | Mermaid node ID | Type | Visible label | Name | Description | Source ID | Assurance Level | Specification Reference | Source Locator | Coverage Status | Evidence Status | Assumptions | Boundary Membership | Flow Source | Flow Destination |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| EE-01 | EE1_User | External Entity | EE-01 User | User | Person | SRC-01 | high | Context | Context | covered | explicit | None | None |  |  |
## What Can Go Wrong
### Baseline identified threats
| ID | Threat Description |
| --- | --- |
| T-01 | A concrete bad event. |
### Additional identified threats
| ID | Threat Description |
| --- | --- |
## What Are We Going To Do About It
### Actual Responses
| Response ID | Threat ID | ERTA | Current / Baseline Response | Threat Owner | Decision / To-Do | Remaining Threat | Assumptions Used | Next Action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R-01 | T-01 | Reduce | Keep gate. | user agent | Should editors clarify this? | Should this remain open? | A-001 | Open issue. |
### New Proposed Responses
| Response ID | Threat ID | Proposed ERTA | Reviewer Recommendation | Decision Owner | Decision / To-Do | If No Change, Remaining Threat | Assumptions Used | Next Action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R-02 | T-02 | Reduce | Add text. | spec editors | Should editors add text? | How should this be handled? | A-001 | Open issue. |
## Did We Do A Good Enough Job?
### What We Did
#### Traceability Review Summary
#### Transfer and Assumption Summary
#### Remaining Threat Closure Summary
### What Remains To Do
#### Baseline Specification Update Actions
#### Remaining Review Gaps
#### New Threat and Proposed Response Actions
# Appendix
## Diagram Summary
Total DFD elements
## Threats Per Elements Summary
Total Threats
## Zero-Threat Element Interpretation
## Coverage Notes
## Blocked Elements
## Unresolved Model Gaps
## Techniques Used To Find Threats
## Method Comparison Summary
## Quality Checks
Analysis gate
Publication gate
"""
    result = validate_report_contract(markdown)

    assert not result.ok
    assert any("Residual threat must be declarative" in error for error in result.errors)


def test_assemble_report_contract(tmp_path: Path) -> None:
    write_json(tmp_path / "model-packet.json", {
        "system_under_analysis": "Test API",
        "scenario": "A user agent exposes a permission-gated API to a requesting origin.",
        "dfd_detail_level": "medium-detail",
        "abstraction_level": "API and user-agent behavior",
        "scope": ["requesting origin", "user agent permission mediation"],
        "out_of_scope": ["concrete browser implementation"],
        "source_inventory": [{
            "title": "Test API",
            "status": "Working Draft",
            "publication_date": "2026-06-29",
            "immutable_url": "https://www.w3.org/TR/2026/WD-test-api-20260629/",
            "latest_url": "https://www.w3.org/TR/test-api/",
            "source_mode": "direct_fetch",
        }],
        "external_entities": [{"stable_id": "EE-01"}],
        "processes": [{"stable_id": "PO-01"}],
        "data_stores": [{"stable_id": "DS-01"}],
        "data_flows": [{"stable_id": "DF-01"}],
            "trust_boundaries": [{"stable_id": "TB-01"}],
            "assumptions": [{"assumption_id": "A-001", "statement": "The user agent mediates permission."}],
        "inline_safeguards": [],
        "implicit_threat_model_signals": [],
        "unresolved_questions": [],
    })
    write_json(tmp_path / "evidence-packet.json", {
        "target": "Test API",
        "source_mode": "direct_fetch",
        "source_inventory": [{
            "title": "Test API",
            "status": "Working Draft",
            "publication_date": "2026-06-29",
            "immutable_url": "https://www.w3.org/TR/2026/WD-test-api-20260629/",
            "latest_url": "https://www.w3.org/TR/test-api/",
            "source_mode": "direct_fetch",
        }],
    })
    dictionary_headers = [
        "ID", "Mermaid node ID", "Type", "Visible label", "Name", "Description",
        "Source ID", "Assurance Level", "Specification Reference", "Source Locator",
        "Coverage Status", "Evidence Status", "Assumptions", "Boundary Membership",
        "Flow Source", "Flow Destination",
    ]
    dictionary_rows = [
        ["EE-01", "EE1_User", "External Entity", "EE-01 User", "User", "Person", "SRC-01", "high", "Context", "Context", "covered", "explicit", "None", "None", "", ""],
        ["PO-01", "PO1_Agent", "Process", "PO-01 Agent", "Agent", "Mediates the API", "SRC-01", "high", "Section 1", "#section-1", "covered", "explicit", "None", "TB-01", "", ""],
        ["DS-01", "DS1_State", "Data Store", "DS-01 State", "State", "Stores state", "SRC-01", "high", "Section 1", "#section-1", "covered", "explicit", "None", "TB-01", "", ""],
        ["DF-01", "DF1_Request", "Data Flow", "DF-01 Request", "Request", "Carries a request", "SRC-01", "high", "Section 1", "#section-1", "covered", "explicit", "None", "TB-01", "EE-01", "PO-01"],
        ["TB-01", "TB1_Agent", "Trust Boundary", "TB-01 Agent", "Agent boundary", "Separates principals", "SRC-01", "high", "Context", "Context", "covered", "inferred", "A-001", "None", "", ""],
    ]
    (tmp_path / "dfd-dictionary.md").write_text(
        "| " + " | ".join(dictionary_headers) + " |\n"
        + "| " + " | ".join(["---"] * len(dictionary_headers)) + " |\n"
        + "\n".join("| " + " | ".join(row) + " |" for row in dictionary_rows)
        + "\n"
    )
    (tmp_path / "dfd.mmd").write_text(
        '%%{init: {"theme":"base","themeCSS":".nodeLabel{font-family:Arial;font-weight:bold;}",'
        '"flowchart":{"htmlLabels":true,"curve":"linear"},'
        '"themeVariables":{"fontFamily":"Arial, sans-serif","fontSize":"22px"}}}%%\n'
        "flowchart LR\n"
        "EE1_User[EE-01<br/>User]\n"
        'subgraph TB1_Agent["TB-01 Agent"]\n'
        "PO1_Agent(PO-01<br/>Agent)\n"
        "DS1_State[(DS-01<br/>State)]\n"
        "end\n"
        "EE1_User ==>|DF-01<br/>Request| PO1_Agent\n"
        "classDef default fill:#fff,stroke:#000,stroke-width:4px,color:#000,font-size:22px,font-weight:bold,font-family:Arial\n"
        "style TB1_Agent fill:#fff,stroke:#000,stroke-width:4px,stroke-dasharray:8 6,color:#000\n"
        "linkStyle default stroke:#000,stroke-width:3px,color:#000\n"
    )
    (tmp_path / "dfd.svg").write_text("<svg/>")
    (tmp_path / "dfd-large.png").write_bytes(b"PNG")
    write_json(tmp_path / "analysis-gate.json", {
        "gate": "analysis",
        "status": "pass",
        "checks": [
            {"name": "source_corpus", "status": "pass"},
            {"name": "model_packet", "status": "pass"},
            {"name": "dfd_representation", "status": "pass"},
            {"name": "baseline_elicitation", "status": "pass"},
            {"name": "additional_elicitation_reconciliation", "status": "pass"},
            {"name": "response_mapping", "status": "pass"},
            {"name": "independent_review", "status": "pass"},
        ],
    })
    write_json(tmp_path / "independent-review-gate.json", {
        "gate": "independent_review",
        "status": "pass",
        "publication_allowed": True,
        "checks": [{"name": "semantic_good_enough_review", "status": "pass"}],
    })
    (tmp_path / "assumptions-and-follow-up.md").write_text(
        "| ID | Assumption | Applies to | Evidence status | Why it matters | If wrong | Validation source | Follow-up owner | Follow-up / issue | Status |\n"
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"
        "| A-001 | The user agent mediates permission. | PO-01; T-01; R-01 | inferred | The baseline response depends on mediation. | The threat remains unresolved. | Spec section | WG | Open issue | open |\n"
    )
    write_json(tmp_path / "assumptions-and-follow-up.json", {
        "contract_version": 1,
        "rows": [{
            "ID": "A-001",
            "Assumption": "The user agent mediates permission.",
            "Applies to": "PO-01; T-01; T-02; R-01; R-02",
            "Evidence status": "inferred",
            "Why it matters": "The response depends on mediation.",
            "If wrong": "The threats remain unresolved.",
            "Validation source": "Spec section",
            "Follow-up owner": "WG",
            "Follow-up / issue": "Open issue",
            "Status": "open",
        }],
    })
    write_json(tmp_path / "as-is.threat-package.json", {
        "threats": [{
            "threat_id": "T-01",
            "affected_model_elements": ["EE-01"],
            "threat_name": "Actual threat",
            "threat_type": ["privacy"],
            "threat_analysis_framework": ["as-is baseline"],
            "threat_category": ["Disclosure"],
            "threat_story": "A recipient can receive data unexpectedly.",
            "finding_mode": "as-is",
            "found_by_methods": ["stride_per_element"],
            "question_references": ["Q-01"],
            "specification_reference": "Spec section",
            "assumptions": ["A-001"],
        }],
    })
    write_json(tmp_path / "full-workshop.threat-package.json", {
        "threats": [{
            "threat_id": "T-02",
            "affected_model_elements": ["EE-01"],
            "threat_name": "New threat",
            "threat_type": ["security", "privacy"],
            "threat_analysis_framework": ["STRIDE"],
            "threat_category": ["Information Disclosure"],
            "threat_story": "A later method finds another concrete bad event.",
            "finding_mode": "full workshop",
            "found_by_methods": ["stride_per_element"],
            "specification_reference": "Spec section",
            "coverage_relation": "new_uncovered_threat",
            "related_as_is_threat_ids": ["T-01"],
            "assumptions": ["A-001"],
        }],
    })
    write_json(tmp_path / "as-is.response-package.json", {
        "responses": [{
            "response_id": "R-01",
            "threat_id": "T-01",
            "erta": "Reduce",
            "status": "existing",
            "response_origin": "as-is",
            "response": "Existing response.",
            "owner": "user agent",
            "remaining_threat": "Remaining threat.",
            "next_action": "Update Privacy Considerations.",
            "assumptions": ["A-001"],
        }],
    })
    write_json(tmp_path / "full-workshop.response-package.json", {
        "responses": [{
            "response_id": "R-02",
            "threat_id": "T-02",
            "erta": "Reduce",
            "response": "Proposed response.",
            "decision_owner": "spec editors",
            "owner": "spec editors",
            "decision_question": "Should editors adopt the proposed response?",
            "if_no_change_remaining_threat": "Remaining threat if no change.",
            "assumptions": ["A-001"],
            "next_action": "Open an issue.",
        }],
    })
    write_json(tmp_path / "considerations-delta.json", {
        "artifact_kind": "security_privacy_considerations_delta",
        "allowed_classifications": [
            "covered", "partially_covered", "missing", "misplaced",
            "unclear", "not_applicable", "blocked",
        ],
        "controlled_decisions": {
            "good_enough_judgment": "update_considerations_recommended",
            "security_considerations_update": "draft_now_from_current_evidence",
            "privacy_considerations_update": "draft_now_from_current_evidence",
            "drafting_readiness": "ready_for_editor_draft_and_review",
            "further_elicitation_required_before_drafting": False,
        },
        "counts": {
            "covered": 1,
            "partially_covered": 0,
            "missing": 1,
            "misplaced": 0,
            "unclear": 0,
            "not_applicable": 0,
            "blocked": 0,
            "total": 2,
        },
        "rows": [
            {
                "Delta ID": "CD-01",
                "Threat / Response": "T-01 / R-01",
                "Considerations target": "Privacy Considerations",
                "Classification": "covered",
                "Current specification evidence": "The current text discusses the baseline event.",
                "Source locator": "Spec section",
                "Gap": "Residual risk remains.",
                "Next action": "Review the current text.",
            },
            {
                "Delta ID": "CD-02",
                "Threat / Response": "T-02 / R-02",
                "Considerations target": "Security Considerations",
                "Classification": "missing",
                "Current specification evidence": "The current text does not discuss this event.",
                "Source locator": "Spec section",
                "Gap": "The proposed threat and response are absent.",
                "Next action": "Draft consideration text.",
            },
        ],
    })
    write_json(tmp_path / "full-workshop.statistics.json", {
        "total_trace_rows": 1,
        "stride_paper_matrix_rows": 1,
        "linddun_paper_matrix_rows": 1,
    })
    (tmp_path / "shostack-skeptic-what-is-missing.md").write_text(
        "# Shostack Skeptic: What Is Missing\n\n"
        "- Verify whether the stopping condition is explicit.\n"
        "- Distinguish threat-element mappings from risk ranking.\n"
    )

    output = assemble_report(
        tmp_path,
        title="Test Report",
        spec_slug="test-api",
        diagram_level="medium-detail",
        categories=["security", "privacy"],
        timestamp="20260629-111221",
    )
    assert output.name == "tm-test-api-medium-security-privacy-additional-20260629-111221.md"
    markdown = output.read_text()
    wawb = markdown.split("## What Are We Building", 1)[1].split("## What Can Go Wrong", 1)[0]

    result = validate_report_contract(markdown)
    assert result.ok, result.errors
    assert "### Baseline identified threats" in markdown
    assert "### Additional identified threats" in markdown
    assert "This section separates the threats reconstructed from the current specification baseline" in markdown
    assert "Non-producing prompts are retained as coverage trace, not as proof that an element is safe." in markdown
    assert "### Actual Responses" in markdown
    assert "### New Proposed Responses" in markdown
    assert "### What We Did" in markdown
    assert "#### Run Completion Status" in markdown
    assert "#### Good-Enough Judgment" in markdown
    assert "#### Step 4 Checklist" in markdown
    assert "#### Classified Delta" in markdown
    assert (
        "| ID | Threat/Response IDs | Considerations Section | Delta Classification | "
        "What The Threat Model Says | What The Specification Says | Source Locator | "
        "Gap | Next Action |"
    ) in markdown
    assert "A recipient can receive data unexpectedly. Response: Existing response." in markdown
    assert "The current text discusses the baseline event." in markdown
    assert "#### Security and Privacy Considerations Decision" in markdown
    assert "#### Remaining Question Routing" in markdown
    assert "#### Recommended Next Elicitation" in markdown
    assert "#### Traceability Review Summary" in markdown
    assert "#### Transfer and Assumption Summary" in markdown
    assert "#### Remaining Threat Closure Summary" in markdown
    assert "### What Remains To Do" in markdown
    assert "#### Baseline Specification Update Actions" in markdown
    assert "#### Remaining Review Gaps" in markdown
    assert "#### New Threat and Proposed Response Actions" in markdown
    assert "assumptions-and-follow-up.md" in markdown
    assert "### Assumptions and Follow-up" not in markdown
    assert "| A-001 | The user agent mediates permission." not in markdown
    assert "stopping condition" in markdown
    assert "# Shostack Skeptic: What Is Missing" not in markdown
    assert "The selected model level is adequate" in markdown
    assert "without claiming a concrete browser implementation architecture" in markdown
    assert markdown.find("## Techniques Used To Find Threats") > markdown.find("# Appendix")
    assert "## Diagram Summary" in markdown
    assert "| Total DFD elements | 5 |" in markdown
    assert "## Threats Per Elements Summary" in markdown
    assert "| Element ID | Name | Baseline identified threats | Additional identified threats | Total Threats |" in markdown
    assert "| Element ID | Type | Name | Baseline identified threats | Additional identified threats | Total Threats |" not in markdown
    assert "| EE-01 |  | 1 | 1 | 2 |" in markdown
    assert "source-grounded baseline plus additional spec-review run" in markdown
    assert "Review categories and lenses:" in markdown
    assert "Model level for What Are We Building: `medium-detail`" in markdown
    assert "System under analysis:" not in wawb
    assert "Scenario:" not in wawb
    assert "DFD detail level:" not in wawb
    assert "Abstraction level:" not in wawb
    assert "Threat Owner" in markdown
    assert "Decision / To-Do" in markdown
    assert "If No Change, Remaining Threat" in markdown
    assert "Assumptions Used" in markdown
    assert "Decide whether editors adopt the proposed response." in markdown
    assert "Should editors adopt the proposed response?" not in markdown
    assert "Remaining threat if no change." in markdown
    assert "Owner / Receiver" not in markdown
    assert "NR-" not in markdown
    assert "R-NEW" not in markdown
    assert "| EE-01 |" in markdown
    assert "EE01" not in markdown
    assert "DF26_SetEmulation" not in markdown

    semantic_gate = {
        "gate": "independent_review",
        "status": "pass",
        "publication_allowed": True,
        "checks": [{"name": "package_equality", "status": "pass"}],
    }
    write_json(tmp_path / "independent-review-gate.json", semantic_gate)
    with pytest.raises(ValueError, match="semantic_good_enough_review"):
        assemble_report(tmp_path, output=tmp_path / "blocked.md", title="Blocked Report")
    draft_output = tmp_path / "report" / "semantic-draft.md"
    assemble_report(tmp_path, output=draft_output, title="Semantic Draft", draft=True)
    assert draft_output.exists()
    semantic_gate["checks"] = [{"name": "semantic_good_enough_review", "status": "pass"}]
    write_json(tmp_path / "independent-review-gate.json", semantic_gate)

    nested_output = tmp_path / "report" / "nested.md"
    assemble_report(tmp_path, output=nested_output, title="Nested Test Report")
    nested_markdown = nested_output.read_text()
    assert "![DFD](../dfd-large.png)" in nested_markdown
    assert "[Mermaid source](../dfd.mmd)" in nested_markdown
    assert "[SVG render](../dfd.svg)" in nested_markdown
    assert "[model packet](../model-packet.json)" in nested_markdown
    assert "[dictionary artifact](../dfd-dictionary.md)" in nested_markdown
    assert "[assumptions artifact](../assumptions-and-follow-up.md)" in nested_markdown

    alias = tmp_path.parent / f"{tmp_path.name}-alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    symlink_output = alias / "report" / "symlink.md"
    assemble_report(alias, output=symlink_output, title="Symlinked Test Report")
    symlink_markdown = symlink_output.read_text()
    assert "![DFD](../dfd-large.png)" in symlink_markdown
    assert "[Mermaid source](../dfd.mmd)" in symlink_markdown

    as_is_output = assemble_report(
        tmp_path,
        title="Test As-Is Report",
        as_is_only=True,
        spec_slug="test-api",
        diagram_level="medium-detail",
        categories=["security", "privacy"],
        timestamp="20260629-111221",
    )
    assert as_is_output.name == "tm-test-api-medium-security-privacy-baseline-20260629-111221.md"
    as_is_markdown = as_is_output.read_text()
    as_is_result = validate_report_contract(as_is_markdown)
    assert as_is_result.ok, as_is_result.errors

    additional_output = assemble_report(
        tmp_path,
        title="Test Additional Report",
        run_scope="additional",
        spec_slug="test-api",
        diagram_level="medium-detail",
        categories=["security", "privacy"],
        timestamp="20260629-111221",
    )
    assert additional_output.name == "tm-test-api-medium-security-privacy-additional-20260629-111221.md"
    additional_markdown = additional_output.read_text()
    additional_result = validate_report_contract(additional_markdown)
    assert additional_result.ok, additional_result.errors
    assert "source-grounded baseline plus additional spec-review run" in additional_markdown

    comprehensive_alias_output = assemble_report(
        tmp_path,
        title="Test Comprehensive Alias Report",
        run_scope="comprehensive",
        spec_slug="test-api",
        diagram_level="medium-detail",
        categories=["security", "privacy"],
        timestamp="20260629-111221",
    )
    assert comprehensive_alias_output.name == "tm-test-api-medium-security-privacy-additional-20260629-111221.md"
    comprehensive_alias_markdown = comprehensive_alias_output.read_text()
    comprehensive_alias_result = validate_report_contract(comprehensive_alias_markdown)
    assert comprehensive_alias_result.ok, comprehensive_alias_result.errors
    assert "source-grounded baseline plus additional spec-review run" in comprehensive_alias_markdown
    assert "source-grounded baseline reverse-engineering run" in as_is_markdown
    assert "source-grounded baseline plus additional spec-review run" not in as_is_markdown
    assert "| T-01 |" in as_is_markdown
    assert "| T-02 |" not in as_is_markdown
    assert "| R-02 |" not in as_is_markdown
    assert "No additional threats were produced or reviewed in this as-is-only report." in as_is_markdown
    assert "No new proposed responses were produced or reviewed in this as-is-only report." in as_is_markdown
    assert as_is_markdown.find("## Did We Do A Good Enough Job?") < as_is_markdown.find(
        "### What We Did"
    ) < as_is_markdown.find("For this review stage, this as-is run is good enough")

    expectations = ReportExpectations(
        dictionary_ids=frozenset({"EE-01", "PO-01", "DS-01", "DF-01", "TB-01"}),
        baseline_threat_ids=frozenset({"T-01"}),
        additional_threat_ids=frozenset({"T-02"}),
        actual_response_ids=frozenset({"R-01"}),
        actual_response_threat_ids=frozenset({"T-01"}),
        new_response_ids=frozenset({"R-02"}),
        new_response_threat_ids=frozenset({"T-02"}),
    )
    baseline_heading_only = re.sub(
        r"(?m)^\| T-01 \|.*\n",
        "The baseline is summarized in prose.\n",
        markdown,
        count=1,
    )
    heading_only_result = validate_report_contract(baseline_heading_only, expectations)
    assert not heading_only_result.ok
    assert any("Baseline identified threats" in error for error in heading_only_result.errors)

    missing_dictionary_row = re.sub(r"(?m)^\| DS-01 \|.*\n", "", markdown, count=1)
    dictionary_result = validate_report_contract(missing_dictionary_row, expectations)
    assert not dictionary_result.ok
    assert any("Dictionary ID set mismatch" in error for error in dictionary_result.errors)

    missing_actual_response = re.sub(r"(?m)^\| R-01 \|.*\n", "", markdown, count=1)
    actual_response_result = validate_report_contract(missing_actual_response, expectations)
    assert not actual_response_result.ok
    assert any("Actual Response" in error for error in actual_response_result.errors)

    missing_new_response = re.sub(r"(?m)^\| R-02 \|.*\n", "", markdown, count=1)
    new_response_result = validate_report_contract(missing_new_response, expectations)
    assert not new_response_result.ok
    assert any("New Proposed Response" in error for error in new_response_result.errors)

    analysis_gate_path = tmp_path / "analysis-gate.json"
    valid_analysis_gate = json.loads(analysis_gate_path.read_text())
    write_json(analysis_gate_path, {
        "gate": "analysis",
        "status": "partial",
        "checks": [{"name": "response_coverage", "status": "fail"}],
    })
    with pytest.raises(ValueError, match="analysis gate must pass"):
        assemble_report(tmp_path, output=tmp_path / "must-not-publish.md")
    write_json(analysis_gate_path, valid_analysis_gate)

    mermaid_path = tmp_path / "dfd.mmd"
    valid_mermaid = mermaid_path.read_text()
    mermaid_path.write_text("flowchart LR\nEE1_User[EE-01 User]\n")
    with pytest.raises(ValueError, match="TMDC Mermaid evidence failed"):
        assemble_report(tmp_path, output=tmp_path / "must-not-publish.md")
    mermaid_path.write_text(valid_mermaid)

    baseline_response_path = tmp_path / "as-is.response-package.json"
    valid_baseline_responses = json.loads(baseline_response_path.read_text())
    write_json(baseline_response_path, {"responses": []})
    with pytest.raises(ValueError, match="exact baseline threat ID set"):
        assemble_report(tmp_path, output=tmp_path / "must-not-publish.md")
    write_json(baseline_response_path, valid_baseline_responses)
