#!/usr/bin/env python3
"""Update the traceable W3C Strategy charter-review question catalog."""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPOSITORY = "w3c/strategy"
REPOSITORY_URL = "https://github.com/w3c/strategy"
DOMAINS = ("TAG/design", "Security", "Privacy")

DOMAIN_RULES: dict[str, dict[str, Any]] = {
    "TAG/design": {
        "labels": {
            "tag review completed",
            "architecture review completed",
            "tag-needs-resolution",
            "tag-tracker",
        },
        "signal": re.compile(r"\b(?:TAG|Technical Architecture Group)\b", re.I),
    },
    "Security": {
        "labels": {
            "security review completed",
            "security-needs-resolution",
            "security-tracker",
        },
        "signal": re.compile(
            r"\bSING\b|Security Interest Group|security review|security point of view|on behalf of security",
            re.I,
        ),
    },
    "Privacy": {
        "labels": {
            "privacy review completed",
            "privacy-needs-resolution",
            "privacy-tracker",
        },
        "signal": re.compile(
            r"\bPING\b|Privacy Working Group|Privacy Interest Group|privacy review|privacy point of view|on behalf of privacy",
            re.I,
        ),
    },
}

QUESTION_TYPES: tuple[dict[str, Any], ...] = (
    {
        "id": "review-status-and-timing",
        "label": "Review status and timing",
        "canonical_question": "What is the status and expected completion date of the relevant horizontal review?",
        "pattern": re.compile(r"(?=.*\b(reviews?|issues?|comments?|satisfied|progress)\b)(?=.*\b(when|status|progress|complete|completed|mark|expect|stalled)\b)", re.I),
    },
    {
        "id": "review-request-and-participation",
        "label": "Review request and participation",
        "canonical_question": "Has the relevant horizontal group been asked to review this charter, and has it provided comments?",
        "pattern": re.compile(r"\b(comments? from|comments? by|additional comments?|interested in reviewing|concerns with .* charter|what to expect regarding .* reviews?)\b", re.I),
    },
    {
        "id": "scope-boundaries-and-consistency",
        "label": "Scope boundaries and consistency",
        "canonical_question": "Are the charter's in-scope and out-of-scope boundaries clear, consistent, and reflected in its deliverables?",
        "pattern": re.compile(r"\b(scope|out of scope|in scope|boundary|boundaries|contradiction|intentional|where's the line|what's now in|what is now in)\b", re.I),
    },
    {
        "id": "deliverables-maturity-and-timeline",
        "label": "Deliverables, maturity, and timeline",
        "canonical_question": "Are the deliverables, maturity expectations, and timeline concrete and realistic?",
        "pattern": re.compile(r"\b(deliverable|timeline|timescale|milestone|maturity|realistic|ambitious|feature|errata)\b", re.I),
    },
    {
        "id": "relationship-to-existing-work",
        "label": "Relationship to existing work",
        "canonical_question": "How does the proposed work relate to existing or in-progress standards and implementations?",
        "pattern": re.compile(r"\b(relate|relationship|alternative|compatible|existing|in-progress|similar|integrat|fedcm|cors|web notifications)\b", re.I),
    },
    {
        "id": "standards-venue-and-coordination",
        "label": "Standards venue and coordination",
        "canonical_question": "Is W3C the appropriate venue, and which groups or standards bodies must coordinate on the work?",
        "pattern": re.compile(r"\b(ietf|venue|standardi[sz]ation|coordinate|coordination|joint deliverable|community group|working group|interest group)\b", re.I),
    },
    {
        "id": "testing-and-interoperability",
        "label": "Testing and interoperability",
        "canonical_question": "What testing and interoperability commitments apply to the deliverables?",
        "pattern": re.compile(r"\b(test|tests|testing|wpt|web platform tests|interoperab|test vector)\b", re.I),
    },
    {
        "id": "design-principles-and-platform-fit",
        "label": "Design principles and platform fit",
        "canonical_question": "How will the work follow Web Platform Design Principles and fit the wider platform?",
        "pattern": re.compile(r"\b(design principles|web platform|browser|platform ecosystem|architecture)\b", re.I),
    },
    {
        "id": "threat-model-and-risk-coverage",
        "label": "Threat model and risk coverage",
        "canonical_question": "What threat model or risk mapping covers the charter's deliverables and affected stakeholders?",
        "pattern": re.compile(r"\b(threat model|threats?|risk mapping|risks? of|misinterpreted|affected stakeholders?)\b", re.I),
    },
    {
        "id": "security-considerations",
        "label": "Security considerations",
        "canonical_question": "Where and when will each deliverable document its Security Considerations?",
        "pattern": re.compile(r"\bsecurity considerations?\b|\bsecurity section\b", re.I),
    },
    {
        "id": "privacy-considerations",
        "label": "Privacy considerations",
        "canonical_question": "Where and when will each deliverable document its Privacy Considerations?",
        "pattern": re.compile(r"\bprivacy considerations?\b|\bprivacy section\b", re.I),
    },
    {
        "id": "security-and-privacy-considerations",
        "label": "Security and privacy considerations",
        "canonical_question": "Where and when will each deliverable document its separate Security Considerations and Privacy Considerations?",
        "pattern": re.compile(r"(?=.*\bsecurity considerations?\b)(?=.*\bprivacy considerations?\b)", re.I),
    },
    {
        "id": "attack-abuse-and-misuse-cases",
        "label": "Attack, abuse, and misuse cases",
        "canonical_question": "Which attack, abuse, or misuse cases are in scope, and how will they be addressed?",
        "pattern": re.compile(r"\b(attack|abuse|misuse|adversar|exploit|malicious)\b", re.I),
    },
    {
        "id": "trust-boundaries-and-authority",
        "label": "Trust boundaries and authority",
        "canonical_question": "What are the trust boundaries, authorities, and security invariants introduced by the work?",
        "pattern": re.compile(r"\b(trust boundar|authority|authorization|permission|privilege|credential|key material|origin)\b", re.I),
    },
    {
        "id": "data-flows-and-disclosure",
        "label": "Data flows and disclosure",
        "canonical_question": "What data is disclosed, to whom, for which purpose, and across which boundaries?",
        "pattern": re.compile(r"\b(data|information)\b.*\b(convey|disclos|share|recipient|to whom|purpose|flow|store|storage)\b", re.I),
    },
    {
        "id": "tracking-linkability-and-fingerprinting",
        "label": "Tracking, linkability, and fingerprinting",
        "canonical_question": "What tracking, linkability, fingerprinting, or cross-context correlation risks arise?",
        "pattern": re.compile(r"\b(track|linkability|fingerprint|correlat|cross-context|cross-site)\b", re.I),
    },
    {
        "id": "user-agency-and-expectations",
        "label": "User agency and expectations",
        "canonical_question": "What user controls, consent, expectations, and meaningful alternatives are required?",
        "pattern": re.compile(r"\b(user|people)\b.*\b(control|consent|expect|choice|alternative|understand|mediat)\b", re.I),
    },
    {
        "id": "auditability-integrity-and-testing",
        "label": "Auditability, integrity, and verification",
        "canonical_question": "What makes the system and its outputs auditable, integrity-protected, and verifiable?",
        "pattern": re.compile(r"\b(audit|auditable|integrity|verify|verifiable|tamper)\b", re.I),
    },
    {
        "id": "security-privacy-review-plan",
        "label": "Security and privacy review plan",
        "canonical_question": "When will the deliverables request security and privacy review, and what evidence will support it?",
        "pattern": re.compile(r"\b(seeking|request|plan|wide review)\b.*\b(security|privacy|ping|sing)\b|\b(security|privacy|ping|sing)\b.*\b(seeking|request|plan|wide review)\b", re.I),
    },
    {
        "id": "change-log-and-risk-delta",
        "label": "Change log and risk delta",
        "canonical_question": "Which security- or privacy-relevant scope changes were made, and are they recorded in the change log?",
        "pattern": re.compile(r"\b(change log|changelog|changed|dropping|removed|added|now in|now out)\b", re.I),
    },
    {
        "id": "charter-history-and-change-traceability",
        "label": "Charter history and change traceability",
        "canonical_question": "Does the charter history accurately trace predecessor groups and material charter changes?",
        "pattern": re.compile(r"\b(history section|history table|charter history|copy over the history)\b", re.I),
    },
    {
        "id": "horizontal-group-coordination",
        "label": "Horizontal-group coordination",
        "canonical_question": "How will the group coordinate with TAG, Security, Privacy, and other relevant review groups?",
        "pattern": re.compile(r"\b(coordinate|coordination|collaborat)\b.*\b(tag|ping|sing|privacy|security)\b", re.I),
    },
)

OTHER_TYPE = {
    "id": "other-charter-specific-question",
    "label": "Other charter-specific question",
    "canonical_question": "What charter-specific point needs clarification?",
}

CLASSIFICATION_ORDER = (
    "security-privacy-review-plan",
    "review-request-and-participation",
    "review-status-and-timing",
    "threat-model-and-risk-coverage",
    "security-and-privacy-considerations",
    "security-considerations",
    "privacy-considerations",
    "attack-abuse-and-misuse-cases",
    "trust-boundaries-and-authority",
    "data-flows-and-disclosure",
    "tracking-linkability-and-fingerprinting",
    "user-agency-and-expectations",
    "auditability-integrity-and-testing",
    "horizontal-group-coordination",
    "scope-boundaries-and-consistency",
    "deliverables-maturity-and-timeline",
    "relationship-to-existing-work",
    "testing-and-interoperability",
    "design-principles-and-platform-fit",
    "charter-history-and-change-traceability",
    "change-log-and-risk-delta",
    "standards-venue-and-coordination",
)
QUESTION_TYPE_BY_ID = {question_type["id"]: question_type for question_type in QUESTION_TYPES}

DOMAIN_SUBJECT_SIGNALS = {
    "TAG/design": re.compile(r"\b(TAG|design|architecture|web platform|browser|standard|IETF|existing work)\b", re.I),
    "Security": re.compile(r"\b(security|SING|threat|attack|abuse|misuse|crypto|key material|integrity|audit|authorization|permission)\b", re.I),
    "Privacy": re.compile(r"\b(privacy|PING|personal data|fingerprint|tracking|linkability|correlation|user freedom|consent|discrimination)\b", re.I),
}

MARKDOWN_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
AUTOLINK = re.compile(r"https?://\S+")
HTML_TAG = re.compile(r"<[^>]+>")
QUESTION = re.compile(r"(?:^|(?<=[.!?]))\s*([^?]{15,700}\?)")


def run_gh(endpoint: str, fields: dict[str, str]) -> list[dict[str, Any]]:
    command = ["gh", "api", "--paginate", "--slurp", "-X", "GET", endpoint]
    for key, value in fields.items():
        command.extend(["-f", f"{key}={value}"])
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    pages = json.loads(completed.stdout)
    return [item for page in pages for item in page]


def fetch_strategy() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    issues = run_gh(f"repos/{REPOSITORY}/issues", {"state": "all", "per_page": "100"})
    comments = run_gh(f"repos/{REPOSITORY}/issues/comments", {"per_page": "100"})
    return issues, comments


def flatten_text(markdown: str) -> str:
    text = re.sub(r"```.*?```", " ", markdown, flags=re.S)
    text = MARKDOWN_LINK.sub(lambda match: match.group(1), text)
    text = AUTOLINK.sub(" ", text)
    text = HTML_TAG.sub(" ", html.unescape(text))
    text = re.sub(r"(?m)^\s*(?:>|[-*+] |#{1,6}\s*|\d+[.)]\s*)", "", text)
    return re.sub(r"\s+", " ", text).strip()


def extract_questions(markdown: str) -> list[str]:
    found: list[str] = []
    without_code = re.sub(r"```.*?```", " ", markdown, flags=re.S)
    blocks: list[str] = []
    pending: list[str] = []

    def flush() -> None:
        if pending:
            blocks.append("\n".join(pending))
            pending.clear()

    for raw_line in without_code.splitlines():
        heading = re.match(r"^\s*#{1,6}\s+", raw_line)
        new_item = re.match(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)", raw_line)
        if not raw_line.strip() or heading or new_item:
            flush()
        if raw_line.strip():
            pending.append(raw_line)
        if heading:
            flush()
    flush()
    for block in blocks:
        text = flatten_text(block)
        if not text:
            continue
        for match in QUESTION.finditer(text):
            question = match.group(1).strip(" -*#>\t")
            if len(re.findall(r"[A-Za-z]{2,}", question)) < 4:
                continue
            if question.count('"') % 2:
                continue
            if question not in found:
                found.append(question)
    return found


def issue_number_from_url(issue_url: str) -> int:
    return int(issue_url.rstrip("/").rsplit("/", 1)[-1])


def issue_labels(issue: dict[str, Any]) -> set[str]:
    labels = issue.get("labels") or []
    return {str(label.get("name", "")).strip().lower() for label in labels}


def domains_for_question(
    labels: set[str], body: str, question: str, question_type_id: str
) -> list[tuple[str, str]]:
    matches: list[tuple[str, str]] = []
    for domain in DOMAINS:
        rule = DOMAIN_RULES[domain]
        if labels & rule["labels"] and rule["signal"].search(body):
            matches.append((domain, "matching Strategy issue label + explicit group signal in comment"))
    if len(matches) == 1:
        candidate_domain, candidate_basis = matches[0]
        candidate_signal = bool(
            DOMAIN_RULES[candidate_domain]["signal"].search(question)
            or DOMAIN_SUBJECT_SIGNALS[candidate_domain].search(question)
        )
        conflicting_signal = any(
            DOMAIN_SUBJECT_SIGNALS[domain].search(question)
            for domain in DOMAINS
            if domain != candidate_domain
        )
        if conflicting_signal and not candidate_signal:
            return []
        if question_type_id == OTHER_TYPE["id"] and not candidate_signal:
            return []
        return [(candidate_domain, candidate_basis)]
    if not matches:
        return []
    local_matches = [
        (domain, "matching Strategy issue label + explicit group signal in the source question")
        for domain, _ in matches
        if DOMAIN_RULES[domain]["signal"].search(question)
    ]
    if local_matches:
        return local_matches
    subject_matches = [
        (domain, "matching Strategy issue label + explicit group signal in comment + domain subject signal in the source question")
        for domain, _ in matches
        if DOMAIN_SUBJECT_SIGNALS[domain].search(question)
    ]
    return subject_matches


def classify_question(question: str) -> dict[str, str]:
    for question_type_id in CLASSIFICATION_ORDER:
        question_type = QUESTION_TYPE_BY_ID[question_type_id]
        if question_type["pattern"].search(question):
            return {key: question_type[key] for key in ("id", "label", "canonical_question")}
    return OTHER_TYPE.copy()


def clean_title(title: str) -> str:
    return re.sub(r"^\[[^]]+\]\s*", "", title).strip()


def build_catalog(
    issues: list[dict[str, Any]],
    comments: list[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    charter_issues: dict[int, dict[str, Any]] = {}
    for issue in issues:
        if issue.get("pull_request") or "charter" not in issue_labels(issue):
            continue
        charter_issues[int(issue["number"])] = issue

    records: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str, str]] = set()
    for comment in comments:
        number = issue_number_from_url(str(comment["issue_url"]))
        issue = charter_issues.get(number)
        if issue is None:
            continue
        labels = issue_labels(issue)
        body = str(comment.get("body") or "")
        if not any(
            labels & DOMAIN_RULES[domain]["labels"] and DOMAIN_RULES[domain]["signal"].search(body)
            for domain in DOMAINS
        ):
            continue
        for question in extract_questions(body):
            question_type = classify_question(question)
            domain_matches = domains_for_question(labels, body, question, question_type["id"])
            for domain, attribution_basis in domain_matches:
                key = (number, str(comment.get("html_url")), question, domain)
                if key in seen:
                    continue
                seen.add(key)
                records.append(
                    {
                        "record_id": f"strategy-{number}-{comment['id']}-{domain.lower().replace('/', '-').replace(' ', '-')}-{len(records) + 1}",
                        "domain": domain,
                        "question_type_id": question_type["id"],
                        "question_type": question_type["label"],
                        "canonical_question": question_type["canonical_question"],
                        "source_question": question,
                        "charter_issue_number": number,
                        "charter_title": clean_title(str(issue.get("title") or f"Issue {number}")),
                        "charter_issue_url": str(issue.get("html_url") or f"{REPOSITORY_URL}/issues/{number}"),
                        "comment_url": str(comment.get("html_url") or ""),
                        "comment_author": str((comment.get("user") or {}).get("login") or "unknown"),
                        "comment_created_at": str(comment.get("created_at") or ""),
                        "attribution_basis": attribution_basis,
                    }
                )

    records.sort(
        key=lambda record: (
            DOMAINS.index(record["domain"]),
            record["question_type"],
            record["charter_title"].lower(),
            record["comment_created_at"],
            record["source_question"],
        )
    )

    by_charter: dict[int, dict[str, Any]] = {}
    for number, issue in sorted(charter_issues.items(), key=lambda item: clean_title(str(item[1].get("title", ""))).lower()):
        matching = [record for record in records if record["charter_issue_number"] == number]
        domain_types = {
            domain: sorted({record["question_type"] for record in matching if record["domain"] == domain})
            for domain in DOMAINS
        }
        by_charter[number] = {
            "charter_issue_number": number,
            "charter_title": clean_title(str(issue.get("title") or f"Issue {number}")),
            "charter_issue_url": str(issue.get("html_url") or f"{REPOSITORY_URL}/issues/{number}"),
            "question_types": domain_types,
            "attributed_question_records": len(matching),
        }

    type_summary: list[dict[str, Any]] = []
    for domain in DOMAINS:
        for question_type in (*QUESTION_TYPES, OTHER_TYPE):
            matching = [
                record
                for record in records
                if record["domain"] == domain and record["question_type_id"] == question_type["id"]
            ]
            if not matching:
                continue
            type_summary.append(
                {
                    "domain": domain,
                    "question_type_id": question_type["id"],
                    "question_type": question_type["label"],
                    "canonical_question": question_type["canonical_question"],
                    "record_count": len(matching),
                    "charter_count": len({record["charter_issue_number"] for record in matching}),
                    "charters": sorted(
                        {
                            (record["charter_issue_number"], record["charter_title"], record["charter_issue_url"])
                            for record in matching
                        },
                        key=lambda value: value[1].lower(),
                    ),
                }
            )

    generated = generated_at or datetime.now(UTC).replace(microsecond=0).isoformat()
    return {
        "schema_version": "1.0",
        "generated_at": generated,
        "source": {
            "repository": REPOSITORY,
            "repository_url": REPOSITORY_URL,
            "selection": "Issue has the exact label charter; question attribution requires a matching group-review label and an explicit group signal in the same comment.",
        },
        "method": {
            "classification": "Transparent ordered regular-expression rules; unmatched questions remain Other charter-specific question.",
            "limitations": [
                "Labels and textual signals are routing evidence, not proof of group consensus or review completion.",
                "Questions without both conservative attribution signals are intentionally omitted from the source-question table.",
                "Canonical questions are normalized prompts; source_question preserves the observed wording.",
            ],
        },
        "summary": {
            "charter_issue_count": len(charter_issues),
            "attributed_question_record_count": len(records),
            "charters_with_attributed_questions": len({record["charter_issue_number"] for record in records}),
            "record_count_by_domain": dict(Counter(record["domain"] for record in records)),
        },
        "question_types": type_summary,
        "records": records,
        "charters": list(by_charter.values()),
    }


def markdown_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def markdown_catalog(catalog: dict[str, Any]) -> str:
    lines = [
        "# W3C Strategy charter-review question catalog",
        "",
        f"Generated: {catalog['generated_at']}",
        "",
        "This local catalog contains traceable questions found in `w3c/strategy` issues labeled `charter`. It is precedent material, not evidence that a concern applies to another charter and not a statement of W3C, TAG, Security, or Privacy consensus.",
        "",
        "## Method",
        "",
        catalog["source"]["selection"],
        "",
        "Canonical question types are assigned with transparent ordered rules. Each source record retains the original question, charter issue, comment URL, author, date, and attribution basis.",
        "",
        "## Canonical question types",
        "",
        "| Domain | Question type | Canonical English question | Charters | Records |",
        "| --- | --- | --- | ---: | ---: |",
    ]
    for row in catalog["question_types"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    markdown_escape(row["domain"]),
                    markdown_escape(row["question_type"]),
                    markdown_escape(row["canonical_question"]),
                    str(row["charter_count"]),
                    str(row["record_count"]),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Traceable source questions",
            "",
            "| Domain | Question type | Source question | Charter | Evidence | Author | Date |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for record in catalog["records"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    markdown_escape(record["domain"]),
                    markdown_escape(record["question_type"]),
                    markdown_escape(record["source_question"]),
                    f"[{markdown_escape(record['charter_title'])}]({record['charter_issue_url']})",
                    f"[comment]({record['comment_url']})",
                    markdown_escape(record["comment_author"]),
                    markdown_escape(record["comment_created_at"][:10]),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Charter-by-charter question-type index",
            "",
            "This final table includes every Strategy issue carrying the exact `charter` label. `None under conservative attribution rule` means that the miner did not retain a question for that domain; it does not establish that no review or question existed.",
            "",
            "| Charter | TAG/design question types | Security question types | Privacy question types |",
            "| --- | --- | --- | --- |",
        ]
    )
    for charter in catalog["charters"]:
        values = []
        for domain in DOMAINS:
            types = charter["question_types"][domain]
            values.append("; ".join(types) if types else "None under conservative attribution rule")
        lines.append(
            f"| [{markdown_escape(charter['charter_title'])}]({charter['charter_issue_url']}) | "
            + " | ".join(markdown_escape(value) for value in values)
            + " |"
        )
    return "\n".join(lines) + "\n"


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def load_input(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data["issues"]), list(data["comments"])


def parse_args() -> argparse.Namespace:
    skill_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="Offline JSON object containing issues and comments arrays")
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    parser.add_argument("--generated-at", help="Fixed ISO timestamp for reproducible tests")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    issues, comments = load_input(args.input) if args.input else fetch_strategy()
    catalog = build_catalog(issues, comments, generated_at=args.generated_at)
    atomic_write(args.json_output, json.dumps(catalog, ensure_ascii=False, indent=2) + "\n")
    atomic_write(args.markdown_output, markdown_catalog(catalog))
    print(json.dumps(catalog["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
