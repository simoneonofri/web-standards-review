from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "update_catalog.py"
SPEC = importlib.util.spec_from_file_location("update_catalog", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def issue(number: int, title: str, labels: list[str]) -> dict:
    return {
        "number": number,
        "title": title,
        "labels": [{"name": label} for label in labels],
        "html_url": f"https://github.com/w3c/strategy/issues/{number}",
    }


def comment(number: int, body: str, comment_id: int = 10) -> dict:
    return {
        "id": comment_id,
        "issue_url": f"https://api.github.com/repos/w3c/strategy/issues/{number}",
        "html_url": f"https://github.com/w3c/strategy/issues/{number}#issuecomment-{comment_id}",
        "body": body,
        "user": {"login": "reviewer"},
        "created_at": "2026-07-01T12:00:00Z",
    }


def test_extract_questions_removes_url_query_strings() -> None:
    body = "From TAG: How does this relate to [FedCM](https://example.test/?q=x)?"
    assert MODULE.extract_questions(body) == ["From TAG: How does this relate to FedCM?"]


def test_catalog_requires_charter_label_group_label_and_explicit_signal() -> None:
    issues = [
        issue(1, "[wg/example] Example Charter", ["charter", "TAG review completed"]),
        issue(2, "Not a charter", ["TAG review completed"]),
        issue(3, "No group signal", ["charter", "Privacy review completed"]),
    ]
    comments = [
        comment(1, "From TAG: How does this relate to existing standards?"),
        comment(2, "From TAG: How does this relate to existing standards?", 20),
        comment(3, "How does this affect privacy?", 30),
    ]
    catalog = MODULE.build_catalog(issues, comments, "2026-07-01T00:00:00+00:00")
    assert catalog["summary"]["charter_issue_count"] == 2
    assert catalog["summary"]["attributed_question_record_count"] == 1
    assert catalog["records"][0]["domain"] == "TAG/design"
    assert catalog["records"][0]["question_type_id"] == "relationship-to-existing-work"


def test_charter_index_includes_charters_without_retained_questions() -> None:
    issues = [issue(7, "[wg/quiet] Quiet Charter", ["charter"])]
    catalog = MODULE.build_catalog(issues, [], "2026-07-01T00:00:00+00:00")
    charter = catalog["charters"][0]
    assert charter["charter_title"] == "Quiet Charter"
    assert all(not charter["question_types"][domain] for domain in MODULE.DOMAINS)


def test_markdown_places_charter_index_last() -> None:
    issues = [issue(9, "[wg/example] Example Charter", ["charter", "Privacy review completed"])]
    comments = [comment(9, "From PING: What data is disclosed and to whom?")]
    markdown = MODULE.markdown_catalog(
        MODULE.build_catalog(issues, comments, "2026-07-01T00:00:00+00:00")
    )
    assert markdown.rfind("## Charter-by-charter question-type index") > markdown.rfind(
        "## Traceable source questions"
    )
    assert "Data flows and disclosure" in markdown


def test_extract_questions_preserves_soft_wrapped_sentence():
    assert MODULE.extract_questions("Is the deliverable timeline\nrealistic for the milestone?") == ["Is the deliverable timeline realistic for the milestone?"]


def test_extract_questions_preserves_heading_and_list_boundaries():
    body = "# Security\n- Scope notes without a question\n- Is the deliverable timeline\n  realistic for the milestone?\n- Is the review plan\n  clear for implementers?"
    assert MODULE.extract_questions(body) == ["Is the deliverable timeline realistic for the milestone?", "Is the review plan clear for implementers?"]
