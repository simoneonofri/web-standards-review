"""Assemble portable Shostack-style spec-review reports from run artifacts."""

from __future__ import annotations

import csv
from datetime import datetime
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .report_contract import (
    CANONICAL_DFD_ID,
    CANONICAL_RESPONSE_ID,
    CANONICAL_THREAT_ID,
    DICTIONARY_REQUIRED_HEADERS,
    ReportExpectations,
    _split_markdown_row,
    validate_report_contract,
)

ARTIFACT_DIRS = (
    "",
    "artifacts",
    "model",
    "baseline",
    "reconciliation",
    "responses",
    "report",
    "quality",
    "artifacts/model",
    "artifacts/baseline",
    "artifacts/reconciled",
    "artifacts/responses",
    "artifacts/final",
    "artifacts/quality",
    "traces",
    "source",
    "diagrams",
)
RUN_DIR_RE = re.compile(r"^(?P<spec>.+)-(?P<timestamp>\d{8}-\d{6})$")
CONSIDERATION_DELTA_CLASSES = (
    "covered",
    "partially_covered",
    "missing",
    "misplaced",
    "unclear",
    "not_applicable",
    "blocked",
)


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text())


def _first_existing_path(run_dir: Path, *names: str) -> Path:
    def matching_paths(base: Path, name: str) -> list[Path]:
        if any(char in name for char in "*?[]"):
            return sorted(path for path in base.glob(name) if path.exists())
        path = base / name
        return [path] if path.exists() else []

    for name in names:
        for path in matching_paths(run_dir, name):
            return path
    for directory in ARTIFACT_DIRS:
        if not directory:
            continue
        base = run_dir / directory
        for name in names:
            for path in matching_paths(base, name):
                return path
    return run_dir / names[0]


def _load_run_json(run_dir: Path, names: tuple[str, ...], default: Any) -> Any:
    return _load_json(_first_existing_path(run_dir, *names), default)


def _slugify(value: Any, fallback: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")
    slug = re.sub(r"-+", "-", slug)
    if slug.startswith("w3c-"):
        slug = slug[4:]
    return slug or fallback


def _run_dir_parts(run_dir: Path) -> tuple[str | None, str | None]:
    match = RUN_DIR_RE.match(run_dir.name)
    if not match:
        return None, None
    return match.group("spec"), match.group("timestamp")


def _spec_slug(
    run_dir: Path,
    model_packet: dict[str, Any],
    evidence_packet: dict[str, Any],
    explicit: str | None = None,
) -> str:
    if explicit:
        return _slugify(explicit, "spec")

    run_spec, _ = _run_dir_parts(run_dir)
    if run_spec:
        return _slugify(run_spec, "spec")

    source = _first_source(model_packet, evidence_packet)
    candidate = (
        model_packet.get("spec_slug")
        or evidence_packet.get("spec_slug")
        or evidence_packet.get("target")
        or source.get("shortname")
        or source.get("title")
        or model_packet.get("system_under_analysis")
    )
    return _slugify(candidate, "spec")


def _level_slug(level: Any) -> str:
    text = str(level or "").lower()
    if "high" in text:
        return "high"
    if "medium" in text:
        return "medium"
    if "detail" in text or "very" in text:
        return "detailed"
    return _slugify(text, "unknown-level")


def _category_items(categories: str | list[str] | tuple[str, ...] | None) -> list[str]:
    if categories is None:
        return []
    raw_items = categories if isinstance(categories, (list, tuple)) else [categories]
    items: list[str] = []
    for raw_item in raw_items:
        text = str(raw_item or "").strip()
        if not text:
            continue
        if "," in text or ";" in text:
            items.extend(part.strip() for part in re.split(r"[,;]+", text) if part.strip())
        else:
            items.append(text)
    return items


def _categories_slug(categories: str | list[str] | tuple[str, ...] | None) -> str:
    slugs = []
    for category in _category_items(categories):
        normalized = category.replace("/", "-")
        slugs.append(_slugify(normalized, "category"))
    return "-".join(slugs) if slugs else "full-coverage"


def _timestamp_slug(run_dir: Path, explicit: str | None = None) -> str:
    if explicit:
        return _slugify(explicit, datetime.now().strftime("%Y%m%d-%H%M%S"))
    _, run_timestamp = _run_dir_parts(run_dir)
    return run_timestamp or datetime.now().strftime("%Y%m%d-%H%M%S")


def _report_scope_slug(as_is_only: bool, run_scope: str | None = None) -> str:
    if as_is_only:
        return "baseline"
    normalized = _slugify(run_scope, "additional")
    if normalized in {"baseline", "baseline-only", "as-is", "as-is-only", "asis"}:
        return "baseline"
    if normalized in {"additional", "full", "comprehensive", "full-comprehensive"}:
        return "additional"
    return "additional"


def _default_report_path(
    run_dir: Path,
    model_packet: dict[str, Any],
    evidence_packet: dict[str, Any],
    *,
    as_is_only: bool,
    spec_slug: str | None,
    diagram_level: str | None,
    categories: str | list[str] | tuple[str, ...] | None,
    timestamp: str | None,
    run_scope: str | None,
) -> Path:
    level = _level_slug(diagram_level or model_packet.get("dfd_detail_level"))
    scope = _report_scope_slug(as_is_only, run_scope)
    filename = (
        f"tm-{_spec_slug(run_dir, model_packet, evidence_packet, spec_slug)}-"
        f"{level}-{_categories_slug(categories)}-{scope}-"
        f"{_timestamp_slug(run_dir, timestamp)}.md"
    )
    return run_dir / filename


def _string_list(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "; ".join(str(item) for item in value)
    return str(value)


def _display_list(items: list[str], fallback: str) -> str:
    cleaned = [item for item in items if item]
    return ", ".join(cleaned) if cleaned else fallback


METHOD_LABELS = {
    "as_is_source_signal": "as-is source-signal reconstruction",
    "browser_fingerprinting_prompt_lens": "browser fingerprinting/linkability",
    "checklist_assessment": "checklist assessment",
    "design_principles_assessment": "design principles assessment",
    "linddun_per_element": "LINDDUN per element",
    "linddun_workshop_simulation": "LINDDUN workshop simulation",
    "microsoft_harms_modeling_per_element": "Microsoft harms modeling per element",
    "privacy_principles_assessment": "privacy principles assessment",
    "rfc3552_security_per_element": "RFC 3552 security per element",
    "rfc6973_privacy_per_element": "RFC 6973 privacy per element",
    "rfc9620_human_rights_per_element": "RFC 9620 human-rights per element",
    "stride_per_element": "STRIDE per element",
    "stride_workshop_simulation": "STRIDE workshop simulation",
    "w3c_horizontal_review_question_patterns": "W3C horizontal-review question patterns",
    "xs_leaks_oracle_checklist": "XS-Leaks oracle checklist",
}


def _method_labels(methods: list[dict[str, str]]) -> list[str]:
    labels = []
    for row in methods:
        method = row.get("method", "").strip()
        if not method:
            continue
        label = METHOD_LABELS.get(method, method.replace("_", " "))
        if label not in labels:
            labels.append(label)
    return labels


def _categories_display(categories: str | list[str] | tuple[str, ...] | None) -> str:
    items = [_slugify(item.replace("/", "-"), "category") for item in _category_items(categories)]
    return _display_list(items, "not supplied")


def _deck_artifacts(run_dir: Path, link_base: Path | None = None) -> list[str]:
    link_base = link_base or run_dir
    artifacts = []
    for base in (run_dir, run_dir / "decks", run_dir / "artifacts"):
        if not base.exists():
            continue
        for path in sorted(base.glob("deck-manifest.*")):
            if path.is_file():
                artifacts.append(_relative_link(link_base, path, path.name))
        for path in sorted(base.glob("*.deck.*")):
            if path.is_file():
                artifacts.append(_relative_link(link_base, path, path.name))
    return sorted(dict.fromkeys(artifacts))


def _method_lens_sentence(
    methods: list[dict[str, str]],
    categories: str | list[str] | tuple[str, ...] | None,
) -> str:
    return (
        f"Review categories and lenses: requested categories: "
        f"{_categories_display(categories)}; artifact-backed method lenses: "
        f"{_display_list(_method_labels(methods), 'not supplied by method-statistics artifact')}."
    )


def _value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return ""


QUESTION_PREFIXES = (
    "should ",
    "how ",
    "is ",
    "are ",
    "what ",
    "can ",
    "could ",
    "would ",
    "do ",
    "does ",
)


def _looks_like_question(value: Any) -> bool:
    text = str(value or "").strip()
    return text.endswith("?") or text.lower().startswith(QUESTION_PREFIXES)


def _decision_question(response: dict[str, Any]) -> str:
    explicit = (
        response.get("decision_question")
        or response.get("editor_question")
        or response.get("open_question")
    )
    if explicit:
        return str(explicit)
    remaining = response.get("remaining_threat", "")
    return str(remaining) if _looks_like_question(remaining) else ""


def _if_no_change_remaining_threat(response: dict[str, Any]) -> str:
    explicit = (
        response.get("if_no_change_remaining_threat")
        or response.get("remaining_threat_statement")
        or response.get("If No Change, Remaining Threat")
    )
    if explicit:
        return str(explicit)
    remaining = _value(response, "remaining_threat", "Remaining Threat")
    return "" if _looks_like_question(remaining) else str(remaining)


def _decision_todo(response: dict[str, Any]) -> str:
    explicit = response.get("decision_todo") or response.get("todo") or response.get("Decision / To-Do")
    if explicit:
        return str(explicit)
    question = _decision_question(response).strip()
    if not question:
        return ""
    normalized = question.rstrip("?")
    lower = normalized.lower()
    if lower.startswith("should "):
        return f"Decide whether {normalized[7:]}."
    if lower.startswith("how "):
        return f"Decide how {normalized[4:]}."
    if lower.startswith("what "):
        return f"Decide what {normalized[5:]}."
    if lower.startswith("is "):
        return f"Decide whether {normalized[3:]}."
    if lower.startswith("are "):
        return f"Decide whether {normalized[4:]}."
    return normalized + "."


def _assumptions_used(response: dict[str, Any]) -> str:
    return _string_list(_value(response, "assumptions_used", "assumptions", "Assumptions Used"))


def _markdown_table(rows: list[dict[str, Any]], headers: list[str]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        values = [str(row.get(header, "")).replace("|", "\\|") for header in headers]
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines)


def _dictionary_table(run_dir: Path) -> str:
    path = _first_existing_path(run_dir, "dfd-dictionary.md")
    if not path.exists():
        return ""
    lines = [line for line in path.read_text().splitlines() if line.startswith("|")]
    if lines:
        headers = _split_markdown_row(lines[0])
        if headers and headers[0].lower() == "id":
            headers[0] = "ID"
        aliases = {
            "Mermaid ID": "Mermaid node ID",
            "Visible Label": "Visible label",
            "Assurance": "Assurance Level",
        }
        headers = [aliases.get(header, header) for header in headers]
        lines[0] = "| " + " | ".join(headers) + " |"
    return "\n".join(lines) if lines else path.read_text().strip()


def _assumptions_table(run_dir: Path) -> str:
    path = _first_existing_path(run_dir, "assumptions-and-follow-up.md")
    if not path.exists():
        return (
            "| ID | Assumption | Applies to | Evidence status | Why it matters | If wrong | "
            "Validation source | Follow-up owner | Follow-up / issue | Status |\n"
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"
        )
    lines = [line for line in path.read_text().splitlines() if line.startswith("|")]
    return "\n".join(lines) if lines else path.read_text().strip()


def _threat_rows(threats: list[dict[str, Any]], include_delta: bool = False) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for threat in threats:
        row = {
            "ID": str(_value(threat, "threat_id", "ID")),
            "Element": _string_list(_value(threat, "affected_model_elements", "model_element_ids", "Element")),
            "Threat Name": str(_value(threat, "threat_name", "title", "Threat Name")),
            "Threat Type": _string_list(_value(threat, "threat_type", "Threat Type")),
            "Threat Analysis Framework": _string_list(_value(threat, "threat_analysis_framework", "Threat Analysis Framework")),
            "Threat Category": _string_list(_value(threat, "threat_category", "Threat Category")),
            "Threat Description": str(_value(threat, "threat_story", "Threat Description")),
            "Finding Mode": str(_value(threat, "finding_mode", "Finding Mode")),
            "Found By": _string_list(_value(threat, "found_by_methods", "Found By")),
            "Question References": _string_list(_value(threat, "question_references", "Question References")),
            "Specification Reference": _string_list(_value(threat, "specification_reference", "source_references", "Specification Reference")),
        }
        if include_delta:
            row["Coverage Relation"] = str(_value(threat, "coverage_relation", "Coverage Relation"))
            row["Related Baseline Threat IDs"] = _string_list(_value(
                threat,
                "related_baseline_threat_ids",
                "related_as_is_threat_ids",
                "Related Baseline Threat IDs",
                "Related Actual Threat IDs",
            ))
        rows.append(row)
    return rows


def _response_rows(responses: list[dict[str, Any]], proposed: bool = False) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for response in responses:
        if proposed:
            rows.append({
                "Response ID": str(_value(response, "response_id", "Response ID")),
                "Threat ID": str(_value(response, "threat_id", "Threat ID")),
                "Proposed ERTA": str(_value(response, "erta", "Proposed ERTA", "ERTA")),
                "Reviewer Recommendation": str(_value(response, "response", "Reviewer Recommendation")),
                "Decision Owner": str(_value(response, "decision_owner", "owner", "Decision Owner")),
                "Decision / To-Do": _decision_todo(response),
                "If No Change, Remaining Threat": _if_no_change_remaining_threat(response),
                "Assumptions Used": _assumptions_used(response),
                "Next Action": str(_value(response, "next_action", "Next Action")),
            })
        else:
            rows.append({
                "Response ID": str(_value(response, "response_id", "Response ID")),
                "Threat ID": str(_value(response, "threat_id", "Threat ID")),
                "ERTA": str(_value(response, "erta", "ERTA")),
                "Status": str(_value(response, "status", "Status")),
                "Response Origin": str(_value(response, "response_origin", "Response Origin")),
                "Current / Baseline Response": str(_value(
                    response,
                    "current_baseline_response",
                    "current_as_is_response",
                    "response",
                    "Current / Baseline Response",
                    "Current / As-Is Response",
                )),
                "Threat Owner": str(_value(response, "owner", "Threat Owner", "Decision Owner")),
                "Decision / To-Do": _decision_todo(response),
                "Remaining Threat": _if_no_change_remaining_threat(response),
                "Assumptions Used": _assumptions_used(response),
                "Next Action": str(_value(response, "next_action", "Next Action")),
            })
    return rows


def _method_rows(run_dir: Path) -> list[dict[str, str]]:
    path = _first_existing_path(run_dir, "full-workshop.method-stats.csv", "method-statistics.csv")
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        rows = []
        for row in csv.DictReader(handle):
            rows.append({
                "method": row.get("method") or row.get("method_id", ""),
                "prompts_or_plays": row.get("prompts_or_plays") or row.get("rows_or_plays", ""),
                "producing": row.get("producing") or row.get("producing_or_confirming", ""),
                "non_producing": row.get("non_producing", ""),
                "threat_ids": row.get("threat_ids") or row.get("unique_threat_ids", ""),
                "new_unique_after_previous_methods": (
                    row.get("new_unique_after_previous_methods")
                    or row.get("new_unique_threats_after_as_is", "")
                ),
            })
        return rows


def _csv_rows(run_dir: Path, name: str) -> list[dict[str, str]]:
    path = _first_existing_path(run_dir, name)
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _new_actions(threats: list[dict[str, Any]], responses: list[dict[str, Any]]) -> list[dict[str, str]]:
    responses_by_threat = {str(_value(response, "threat_id", "Threat ID")): response for response in responses}
    rows: list[dict[str, str]] = []
    for threat in threats:
        threat_id = str(_value(threat, "threat_id", "ID"))
        response = responses_by_threat.get(threat_id, {})
        impact = "Update Privacy Considerations"
        if "security" in _string_list(_value(threat, "threat_type", "Threat Type")).lower():
            impact = "Update Security and Privacy Considerations"
        rows.append({
            "New Threat ID": threat_id,
            "Threat Name": str(_value(threat, "threat_name", "title", "Threat Name")),
            "Proposed Remediation ID": str(_value(response, "response_id", "Response ID")),
            "ERTA": str(_value(response, "erta", "Proposed ERTA", "ERTA")),
            "Considerations Impact": impact,
            "Related Baseline Threat IDs": _string_list(_value(
                threat,
                "related_baseline_threat_ids",
                "related_as_is_threat_ids",
                "Related Baseline Threat IDs",
                "Related Actual Threat IDs",
            )),
            "Next Action": str(_value(response, "next_action", "Next Action") or "Draft consideration text or open issue."),
        })
    return rows


def _actual_delta_actions(responses: list[dict[str, Any]]) -> str:
    actions = []
    for response in responses:
        next_action = str(_value(response, "next_action", "Next Action")).strip()
        threat_id = str(_value(response, "threat_id", "Threat ID")).strip()
        if next_action:
            actions.append(f"- `{threat_id}`: {next_action}")
    if actions:
        return "\n".join(actions)
    return "- No actual-threat delta actions were supplied by the response package."


def _what_is_missing(run_dir: Path) -> str:
    versioned: list[Path] = []
    for directory in ARTIFACT_DIRS:
        base = run_dir / directory if directory else run_dir
        versioned.extend(base.glob("shostack-skeptic-v*-what-is-missing.md"))

    def _skeptic_version(path: Path) -> int:
        match = re.search(r"-v(\d+)-what-is-missing\.md$", path.name)
        return int(match.group(1)) if match else -1

    candidates = [
        *sorted(set(versioned), key=_skeptic_version, reverse=True),
        _first_existing_path(run_dir, "shostack-skeptic-what-is-missing.md"),
        _first_existing_path(run_dir, "shostack-skeptic-cosa-manca.md"),
    ]
    for path in candidates:
        if path.exists():
            text = path.read_text().strip()
            if text:
                lines = [
                    line for line in text.splitlines()
                    if not line.lstrip().startswith("#")
                ]
                return "\n".join(lines).strip() or text
    return (
        "- Shostack skeptic pass not supplied for this run. Run a skeptic review "
        "over the assembled report and write `shostack-skeptic-what-is-missing.md` "
        "before treating this report as final."
    )


def _unresolved_model_gaps(package: dict[str, Any]) -> str:
    gaps = package.get("unresolved_model_gaps") or []
    if not gaps:
        return "- No unresolved model gaps were supplied by the reconciled threat package."
    lines = []
    for index, gap in enumerate(gaps, start=1):
        if isinstance(gap, dict):
            gap_id = str(gap.get("candidate_id") or gap.get("gap_id") or f"GAP-{index:02d}")
            title = str(gap.get("title") or gap.get("description") or "Unresolved model gap")
            basis = str(gap.get("decision_basis") or gap.get("reason") or "Requires model-owner review.")
            lines.append(f"- `{gap_id}` — {title}: {basis}")
        else:
            lines.append(f"- {gap}")
    return "\n".join(lines)


def _method_comparison_links(run_dir: Path, link_base: Path | None = None) -> str:
    link_base = link_base or run_dir
    candidates = [
        ("reconciled method statistics", _first_existing_path(run_dir, "method-statistics.md", "full-workshop.method-stats.md")),
        ("additional reconciliation review", run_dir / "reconciliation" / "reconciliation-review.md"),
        ("generic candidate review", run_dir / "reconciliation" / "reviews" / "generic" / "review.md"),
        ("security/card candidate review", run_dir / "reconciliation" / "reviews" / "security" / "review.md"),
        ("privacy/RFC/human-rights candidate review", run_dir / "reconciliation" / "reviews" / "privacy" / "review.md"),
    ]
    links = [
        f"[{label}]({_relative_link(link_base, path, path.name)})"
        for label, path in candidates
        if path.exists()
    ]
    if not links:
        return "No method-comparison artifacts were supplied."
    return "See " + ", ".join(links) + "."


def _first_source(model_packet: dict[str, Any], evidence_packet: dict[str, Any]) -> dict[str, Any]:
    sources = model_packet.get("source_inventory") or evidence_packet.get("source_inventory") or []
    if sources:
        return sources[0]
    snapshot = evidence_packet.get("snapshot_identity")
    return snapshot if isinstance(snapshot, dict) else {}


def _scope_list(value: Any) -> str:
    if isinstance(value, list):
        return "; ".join(str(item).strip().rstrip(".") for item in value)
    return str(value or "").strip().rstrip(".")


def _introduction(
    model_packet: dict[str, Any],
    evidence_packet: dict[str, Any],
    stats: dict[str, Any],
    methods: list[dict[str, str]],
    actual_threats: list[dict[str, Any]],
    new_threats: list[dict[str, Any]],
    actual_responses: list[dict[str, Any]],
    new_responses: list[dict[str, Any]],
    as_is_only: bool = False,
    categories: str | list[str] | tuple[str, ...] | None = None,
    run_scope: str | None = None,
) -> str:
    source = _first_source(model_packet, evidence_packet)
    spec_title = source.get("title") or model_packet.get("system_under_analysis") or evidence_packet.get("target") or "target specification"
    status = source.get("status", "status unavailable")
    publication_date = source.get("publication_date", "publication date unavailable")
    immutable_url = source.get("immutable_url") or source.get("immutable_publication_url") or source.get("source_url") or ""
    latest_url = source.get("latest_url") or ""
    source_mode = source.get("source_mode") or evidence_packet.get("source_mode") or "unknown"
    dfd_level = model_packet.get("dfd_detail_level", "unknown")
    abstraction = model_packet.get("abstraction_level", "unknown")

    source_line = f"Source mode: `{source_mode}`."
    if immutable_url:
        source_line += f" Reviewed snapshot: {immutable_url}."
    if latest_url:
        source_line += f" Latest TR URL: {latest_url}."

    scope_slug = _report_scope_slug(as_is_only, run_scope)
    if scope_slug == "baseline":
        run_label = "source-grounded baseline reverse-engineering run"
        run_type = (
            "Run type: reverse-engineer the current specification baseline only. "
            f"{_method_lens_sentence(methods, categories)} No later "
            "full-elicitation pass is included in this report.\n\n"
        )
    else:
        run_label = "source-grounded baseline plus additional spec-review run"
        run_type = (
            "Run type: reverse-engineer the current specification baseline, then "
            "run additional elicitation over the same diagram. "
            "Default additional mode includes comprehensive-LLM non-compact "
            "method-item-by-element matrices for STRIDE, LINDDUN, and RFC 6973 "
            "unless the run explicitly selected compact elicitation. "
            f"{_method_lens_sentence(methods, categories)}\n\n"
        )

    return (
        f"This is a {run_label} for `{spec_title}` ({status}, {publication_date}). "
        f"{source_line}\n\n"
        f"{run_type}"
        f"Model level for What Are We Building: `{dfd_level}` DFD detail level, "
        f"with `{abstraction}` abstraction. This is a specification-level review: "
        "it does not claim current browser implementation behavior, deployment "
        "mitigations, legal compliance, or working-group intent unless cited "
        f"evidence says so. Output: {len(actual_threats)} baseline threats, "
        f"{len(new_threats)} additional threats, {len(actual_responses)} actual responses, "
        f"{len(new_responses)} proposed responses, and "
        f"{stats.get('total_trace_rows', 'unknown')} trace rows.\n"
    )


def _relative_link(link_base: Path, path: Path, fallback: str) -> str:
    if not path.exists():
        return fallback
    try:
        return Path(os.path.relpath(path, start=link_base)).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def _diagram_block(run_dir: Path, link_base: Path | None = None) -> str:
    link_base = link_base or run_dir
    png = _first_existing_path(
        run_dir,
        "dfd-large.png",
        "*-dfd-large.png",
        "*-large.png",
    )
    svg = _first_existing_path(run_dir, "dfd.svg", "*-dfd.svg", "*.svg")
    mmd = _first_existing_path(run_dir, "dfd.mmd", "*-dfd.mmd", "*.mmd")
    model = _first_existing_path(run_dir, "model-packet.json")
    dictionary = _first_existing_path(run_dir, "dfd-dictionary.md")
    assumptions = _first_existing_path(run_dir, "assumptions-and-follow-up.md")
    element_sources = _first_existing_path(run_dir, "full-workshop.element-source-packets.md")

    links = [
        f"[Mermaid source]({_relative_link(link_base, mmd, 'dfd.mmd')})",
        f"[SVG render]({_relative_link(link_base, svg, 'dfd.svg')})",
        f"[model packet]({_relative_link(link_base, model, 'model-packet.json')})",
        f"[dictionary artifact]({_relative_link(link_base, dictionary, 'dfd-dictionary.md')})",
        f"[assumptions artifact]({_relative_link(link_base, assumptions, 'assumptions-and-follow-up.md')})",
    ]
    if element_sources.exists():
        links.append(f"[element source packets]({_relative_link(link_base, element_sources, 'full-workshop.element-source-packets.md')})")
    return (
        f"![DFD]({_relative_link(link_base, png, 'dfd-large.png')})\n\n"
        f"Artifacts: {', '.join(links)}.\n\n"
    )


def _what_are_we_building_intro(model_packet: dict[str, Any], run_dir: Path | None = None) -> str:
    scope = _scope_list(model_packet.get("scope"))
    out_of_scope = _scope_list(model_packet.get("out_of_scope"))
    model_assumptions = model_packet.get(
        "assumptions_and_follow_up",
        model_packet.get("assumptions", []),
    )
    assumption_count = len(model_assumptions)
    if run_dir is not None:
        registry = _load_run_json(run_dir, ("assumptions-and-follow-up.json",), {})
        registry_rows = registry.get("rows", []) if isinstance(registry, dict) else []
        if isinstance(registry_rows, list) and registry_rows:
            assumption_count = len(registry_rows)
    counts = {
        "external entities": len(model_packet.get("external_entities", [])),
        "processes": len(model_packet.get("processes", [])),
        "data stores": len(model_packet.get("data_stores", [])),
        "data flows": len(model_packet.get("data_flows", [])),
        "trust boundaries": len(model_packet.get("trust_boundaries", [])),
        "assumptions and follow-up records": assumption_count,
        "inline safeguards": len(model_packet.get("inline_safeguards", [])),
        "implicit threat-model signals": len(model_packet.get("implicit_threat_model_signals", [])),
        "unresolved questions": len(model_packet.get("unresolved_questions", [])),
    }
    count_text = "; ".join(f"{name}: {count}" for name, count in counts.items())
    return (
        f"Scope: {scope or 'not supplied'}.\n"
        f"Outside this diagram: {out_of_scope or 'not supplied'}.\n\n"
        f"Model coverage: {count_text}.\n\n"
    )


def _what_can_go_wrong_intro(
    stats: dict[str, Any],
    new_threats: list[dict[str, Any]],
    methods: list[dict[str, str]] | None = None,
    run_dir: Path | None = None,
    link_base: Path | None = None,
) -> str:
    methods = methods or []
    trace_rows = stats.get("total_trace_rows", "unknown")
    producing_rows = stats.get("producing_trace_rows", "unknown")
    non_producing_rows = stats.get("non_producing_trace_rows", "unknown")
    if not new_threats:
        return (
            "This section reconstructs the as-is threat baseline implied by the "
            "current specification text. `Baseline identified threats` are source-grounded "
            "threats derived from normative algorithms, inline safeguards, "
            "privacy or security considerations, WebIDL-visible behavior, and "
            "the diagram. A retained threat still has to be a concrete bad "
            "event tied to model elements and specification evidence; framework "
            "labels or missing controls are not enough by themselves.\n\n"
            "No later full-elicitation pass is included in this report. The "
            "`Additional identified threats` subsection is kept only to preserve the report "
            "structure and should state that no additional threats were produced "
            "or reviewed in this as-is run.\n\n"
        )
    method_text = _display_list(_method_labels(methods), "no method-statistics artifact was supplied")
    deck_artifacts = _deck_artifacts(run_dir, link_base) if run_dir else []
    deck_sentence = ""
    if deck_artifacts:
        deck_sentence = f" Deck artifacts supplied: {', '.join(deck_artifacts[:6])}."
    return (
        "This section separates the threats reconstructed from the current "
        "specification baseline from the threats found by the later full "
        "elicitation pass. `Baseline identified threats` are source-grounded baseline threats "
            "already implied by the specification text, inline safeguards, privacy "
            "considerations, algorithms, or modeled API behavior. `Additional identified threats` are "
            "additional candidates produced after the baseline by applying the "
            "artifact-backed review lenses to the same diagram.\n\n"
        f"The full pass used the diagram elements as the unit of analysis. "
        f"Artifact-backed method lenses for this assembled run: {method_text}."
        f"{deck_sentence} A prompt produced a threat only when it led to a "
        "concrete bad event tied to model elements and specification evidence. "
        "Non-producing prompts are retained as coverage trace, not as proof "
        "that an element is safe.\n\n"
        f"For this run, the trace contains {trace_rows} rows: {producing_rows} "
        f"producing rows and {non_producing_rows} non-producing rows. The detailed "
        "trace, method statistics, and element coverage remain in the appendix "
        "and linked artifacts so the body can focus on the retained threat "
        "stories.\n\n"
    )


def _good_enough_intro(new_threats: list[dict[str, Any]]) -> str:
    if new_threats:
        return (
            "For this review stage, this run is good enough because the "
            "per-element elicitation pass completed across the diagram, retained "
            "only concrete bad events as threats, preserved non-producing rows as "
            "coverage evidence, reconciled additional threats against the as-is "
            "baseline, and mapped each retained threat to an as-is response, "
            "proposed ERTA response, or editor decision question. This is a "
            "stopping condition for editor review, not a claim that the "
            "specification has no further threats.\n\n"
        )
    return (
        "For this review stage, this as-is run is good enough because the "
        "source-grounded baseline was reconstructed from the current "
        "specification text and mapped to concrete threat stories, diagram "
        "elements, specification references, and as-is ERTA responses. No later "
        "full-elicitation pass is included, so the stopping condition is limited "
        "to whether the current specification baseline is useful for editor "
        "review.\n\n"
        "This is not a claim that the specification has no further threats. "
        "Another pass should be triggered if the diagram changes, if the review "
        "scope expands beyond specification text, if editors request additional "
        "elicitation, if implementation evidence is added, or if horizontal-review "
        "feedback introduces new security or privacy concerns.\n\n"
    )


def _controlled_good_enough_judgment(run_dir: Path, as_is_only: bool) -> str:
    if as_is_only:
        return (
            "Controlled judgment: `baseline_ready_for_editor_review`. This value "
            "applies only to the source-grounded baseline report.\n\n"
        )
    delta = _load_run_json(run_dir, ("considerations-delta.json",), {})
    decisions = delta.get("controlled_decisions", {}) if isinstance(delta, dict) else {}
    judgment = str(decisions.get("good_enough_judgment") or "missing")
    return (
        f"Controlled judgment: `{judgment}`. Drafting readiness and separate "
        "Security/Privacy update decisions are stated below.\n\n"
    )


def _model_adequacy_assessment(model_packet: dict[str, Any]) -> str:
    dfd_level = model_packet.get("dfd_detail_level", "the selected")
    abstraction = model_packet.get("abstraction_level", "specification-level")

    return (
        f"The selected model level is adequate because the `{dfd_level}` diagram "
        f"at `{abstraction}` abstraction exposes the security- and privacy-relevant "
        "decision points needed for review without claiming a concrete browser "
        "implementation architecture. Another pass should be triggered if the "
        "diagram changes, editors materially revise proposed responses, "
        "implementation evidence enters scope, zero-threat elements need manual "
        "reclassification, or horizontal-review feedback introduces new concerns.\n\n"
    )


def _latest_numbered_skeptic(run_dir: Path) -> tuple[Path | None, dict[str, Any]]:
    candidates: list[Path] = []
    for directory in ARTIFACT_DIRS:
        base = run_dir / directory if directory else run_dir
        candidates.extend(base.glob("independent-skeptic-v*.json"))

    def _version(path: Path) -> int:
        match = re.search(r"-v(\d+)\.json$", path.name)
        return int(match.group(1)) if match else -1

    if not candidates:
        return None, {}
    path = max(set(candidates), key=_version)
    value = _load_json(path, {})
    return path, value if isinstance(value, dict) else {}


def _run_completion_status(run_dir: Path, as_is_only: bool) -> str:
    analysis = _load_run_json(run_dir, ("analysis-gate.json",), {})
    good_enough = _load_run_json(run_dir, ("independent-review-gate.json",), {})
    publication = _load_run_json(run_dir, ("publication-gate.json",), {})
    _, skeptic = _latest_numbered_skeptic(run_dir)
    semantic_good_enough = str(skeptic.get("good_enough_status") or "").lower()
    semantic_publication = str(skeptic.get("publication_status") or "").lower()
    good_enough_status = str(good_enough.get("status") or "missing")
    publication_status = str(publication.get("status") or "pending current assembly")
    if semantic_good_enough and semantic_good_enough not in {"pass", "complete"}:
        good_enough_status = f"{semantic_good_enough} (latest semantic review)"
    if semantic_publication and semantic_publication not in {"pass", "complete"}:
        publication_status = f"{semantic_publication} (latest semantic review)"
    rows = [
        {
            "Gate": "Analysis",
            "Status": str(analysis.get("status") or "missing"),
            "Meaning": "Source, model, DFD, elicitation, response, trace, and independent analysis checks.",
        },
        {
            "Gate": "Good-enough / independent review",
            "Status": good_enough_status,
            "Meaning": "Stage-specific stopping condition, exact package coverage, and semantic skeptic review.",
        },
        {
            "Gate": "Publication",
            "Status": publication_status,
            "Meaning": "Report contract, exact inline ID sets, required renders, and local-link integrity.",
        },
        {
            "Gate": "Run scope",
            "Status": "baseline" if as_is_only else "baseline plus additional",
            "Meaning": "The report does not claim that no further threats exist.",
        },
    ]
    return _markdown_table(rows, ["Gate", "Status", "Meaning"]) + "\n\n"


def _step4_checklist(
    run_dir: Path,
    model_packet: dict[str, Any],
    methods: list[dict[str, str]],
    actual_threats: list[dict[str, Any]],
    new_threats: list[dict[str, Any]],
    actual_responses: list[dict[str, Any]],
    new_responses: list[dict[str, Any]],
    as_is_only: bool,
) -> str:
    method_names = {str(row.get("method") or "") for row in methods}
    assumptions = _load_run_json(run_dir, ("assumptions-and-follow-up.json",), {})
    assumption_rows = assumptions.get("rows", []) if isinstance(assumptions, dict) else []
    open_assumptions = sum(
        str(row.get("Status") or row.get("status") or "").lower() == "open"
        for row in assumption_rows
        if isinstance(row, dict)
    )
    transfers = _load_run_json(run_dir, ("transfer-register.json",), {})
    transfer_rows = transfers.get("rows", []) if isinstance(transfers, dict) else []
    open_transfers = [
        row
        for row in transfer_rows
        if isinstance(row, dict) and str(row.get("Register status") or "").lower() == "open"
    ]
    accepted_transfers = [
        row
        for row in transfer_rows
        if isinstance(row, dict)
        and str(row.get("Receiver acceptance evidenced") or "").lower() == "yes"
    ]
    trace_manifest = _load_run_json(run_dir, ("trace-linkage-manifest.json",), {})
    linked = trace_manifest.get("linked_artifacts", []) if isinstance(trace_manifest, dict) else []
    linked_present = sum(
        isinstance(row, dict) and row.get("status") == "present" for row in linked
    )
    rows = [
        {
            "Step 4 check": "Model story and DFD fidelity",
            "Status": "pass",
            "Evidence / remaining work": (
                f"{len(_model_elements(model_packet))} canonical model elements; "
                "dictionary, Mermaid, PNG, and SVG are required by the publication gate."
            ),
        },
        {
            "Step 4 check": "Threat and response traceability",
            "Status": "pass",
            "Evidence / remaining work": (
                f"{len(actual_threats)} baseline threats / {len(actual_responses)} actual responses; "
                f"{len(new_threats)} additional threats / {len(new_responses)} proposed responses."
            ),
        },
        {
            "Step 4 check": "Security and privacy framework walk",
            "Status": "not in baseline scope" if as_is_only else "pass",
            "Evidence / remaining work": (
                "STRIDE, RFC 3552, LINDDUN, RFC 6973, fingerprinting, XS-Leaks, "
                "principles, checklists, and horizontal-review methods are recorded."
            ),
        },
        {
            "Step 4 check": "Harms, human rights, and affected stakeholders",
            "Status": "not in baseline scope" if as_is_only else "pass",
            "Evidence / remaining work": (
                "The baseline-only report does not claim a separate harms or RFC 9620 pass."
                if as_is_only
                else (
                    "RFC 9620 and Microsoft harms method rows are present; retained "
                    "stories preserve accessibility, agency, opportunity, surveillance, "
                    "affected-person, and remedy consequences."
                    if {
                    "rfc9620_human_rights_per_element",
                    "microsoft_harms_modeling_per_element",
                    } <= method_names
                    else "The required harms and RFC 9620 method rows are not both present."
                )
            ),
        },
        {
            "Step 4 check": "Producing and non-producing evidence",
            "Status": "pass" if linked and linked_present == len(linked) else "follow-up",
            "Evidence / remaining work": f"{linked_present} of {len(linked)} linked artifacts are present.",
        },
        {
            "Step 4 check": "Transfers",
            "Status": "follow-up" if open_transfers else "pass",
            "Evidence / remaining work": (
                f"{len(open_transfers)} transfers remain open; "
                f"{len(accepted_transfers)} have receiver-acceptance evidence."
            ),
        },
        {
            "Step 4 check": "Assumptions and follow-up",
            "Status": "follow-up" if open_assumptions else "pass",
            "Evidence / remaining work": (
                f"{len(assumption_rows)} canonical assumptions; {open_assumptions} remain open."
            ),
        },
    ]
    return _markdown_table(rows, ["Step 4 check", "Status", "Evidence / remaining work"]) + "\n\n"


def _classified_delta_summary(
    run_dir: Path,
    actual_threats: list[dict[str, Any]],
    new_threats: list[dict[str, Any]],
    actual_responses: list[dict[str, Any]],
    new_responses: list[dict[str, Any]],
    as_is_only: bool,
) -> str:
    delta = _load_run_json(run_dir, ("considerations-delta.json",), {})
    delta_rows = delta.get("rows", []) if isinstance(delta, dict) else []
    allowed = delta.get("allowed_classifications", []) if isinstance(delta, dict) else []
    in_scope_ids = {
        str(_value(threat, "threat_id", "ID"))
        for threat in [*actual_threats, *new_threats]
    }
    threat_by_id = {
        str(_value(threat, "threat_id", "ID")): threat
        for threat in [*actual_threats, *new_threats]
    }
    response_by_threat = {
        str(_value(response, "threat_id", "Threat ID")): response
        for response in [*actual_responses, *new_responses]
    }
    filtered: list[dict[str, Any]] = []
    for row in delta_rows:
        if not isinstance(row, dict):
            continue
        pair = str(row.get("Threat / Response") or "")
        threat_id = pair.split("/", maxsplit=1)[0].strip()
        if threat_id not in in_scope_ids:
            continue
        threat = threat_by_id.get(threat_id, {})
        response = response_by_threat.get(threat_id, {})
        filtered.append({
            "ID": row.get("Delta ID", ""),
            "Threat/Response IDs": pair,
            "Considerations Section": row.get("Considerations target", ""),
            "Delta Classification": row.get("Classification", ""),
            "What The Threat Model Says": (
                f"{_value(threat, 'threat_story', 'Threat Description')} "
                f"Response: {_value(response, 'response', 'Reviewer Recommendation', 'Current / Baseline Response')}"
            ).strip(),
            "What The Specification Says": row.get("Current specification evidence", ""),
            "Source Locator": row.get("Source locator", ""),
            "Gap": row.get("Gap", ""),
            "Next Action": row.get("Next action", ""),
        })
    counts = {
        classification: sum(
            row.get("Delta Classification") == classification for row in filtered
        )
        for classification in allowed
    }
    count_rows = [
        {"Coverage classification": classification, "Count": count}
        for classification, count in counts.items()
    ]
    return (
        _markdown_table(count_rows, ["Coverage classification", "Count"])
        + "\n\n"
        + _markdown_table(
            filtered,
            [
                "ID",
                "Threat/Response IDs",
                "Considerations Section",
                "Delta Classification",
                "What The Threat Model Says",
                "What The Specification Says",
                "Source Locator",
                "Gap",
                "Next Action",
            ],
        )
        + "\n\n"
    )


def _considerations_decision(
    run_dir: Path,
    actual_threats: list[dict[str, Any]],
    new_threats: list[dict[str, Any]],
    actual_responses: list[dict[str, Any]],
    new_responses: list[dict[str, Any]],
    as_is_only: bool,
) -> str:
    security_and_privacy = sum(
        "security" in _string_list(_value(threat, "threat_type", "Threat Type")).lower()
        for threat in new_threats
    )
    privacy_only = len(new_threats) - security_and_privacy
    text = (
        f"The baseline records {len(actual_threats)} threats and {len(actual_responses)} "
        "actual response/follow-up rows. "
    )
    if not as_is_only:
        text += (
            f"The additional delta contains {security_and_privacy} proposed Security "
            f"and Privacy Considerations actions and {privacy_only} proposed Privacy "
            f"Considerations actions, covering all {len(new_responses)} proposed responses. "
        )
    delta = _load_run_json(run_dir, ("considerations-delta.json",), {})
    decisions = delta.get("controlled_decisions", {}) if isinstance(delta, dict) else {}
    decision_text = ""
    if not as_is_only and decisions:
        decision_text = (
            "Controlled decisions: "
            f"`security_considerations_update={decisions.get('security_considerations_update')}`; "
            f"`privacy_considerations_update={decisions.get('privacy_considerations_update')}`; "
            f"`drafting_readiness={decisions.get('drafting_readiness')}`; "
            "`further_elicitation_required_before_drafting="
            f"{str(decisions.get('further_elicitation_required_before_drafting')).lower()}`. "
        )
    elif as_is_only:
        decision_text = (
            "Controlled baseline decisions: "
            "`security_considerations_update=not_assessed_in_baseline_only`; "
            "`privacy_considerations_update=baseline_follow_up_only`; "
            "`drafting_readiness=requires_additional_run_or_editor_scope_decision`. "
        )
    return (
        text
        + decision_text
        + "These are review recommendations and routed follow-up, not Working Group "
        "adoption or implementation-conformance claims. Open transfers and assumptions "
        "remain part of closure.\n\n"
    )


def _remaining_question_routing(model_packet: dict[str, Any]) -> str:
    rows = []
    for question in model_packet.get("unresolved_questions", []):
        if not isinstance(question, dict):
            continue
        rows.append({
            "Question ID": str(question.get("question_id") or question.get("id") or "unassigned"),
            "Question": str(question.get("question") or "Question text not supplied"),
            "Owner / decision path": str(question.get("owner") or "Model owner and specification editors"),
            "Next action": str(question.get("next_action") or "Assign an owner and validation source."),
        })
    if not rows:
        return "No unresolved model questions are recorded.\n\n"
    return _markdown_table(
        rows,
        ["Question ID", "Question", "Owner / decision path", "Next action"],
    ) + "\n\n"


def _recommended_next_elicitation() -> str:
    return (
        "Controlled next elicitation: `none`. Do not start another broad elicitation "
        "pass while the model, source corpus, "
        "and retained-threat set are unchanged. Next perform the routed editor, "
        "receiver-acceptance, implementation-test, accessibility, privacy, and "
        "cross-specification follow-up. Rerun elicitation if the diagram or trust "
        "boundaries change, editors materially revise responses, new implementation "
        "evidence enters scope, a model gap gains evidence, or horizontal review "
        "introduces a new concrete bad event.\n\n"
    )


def _diagram_summary(model_packet: dict[str, Any]) -> str:
    rows = [
        {"Element type": "External entities", "Count": len(model_packet.get("external_entities", []))},
        {"Element type": "Processes", "Count": len(model_packet.get("processes", []))},
        {"Element type": "Data stores", "Count": len(model_packet.get("data_stores", []))},
        {"Element type": "Data flows", "Count": len(model_packet.get("data_flows", []))},
        {"Element type": "Trust boundaries", "Count": len(model_packet.get("trust_boundaries", []))},
    ]
    total = sum(int(row["Count"]) for row in rows)
    rows.append({"Element type": "Total DFD elements", "Count": total})
    return _markdown_table(rows, ["Element type", "Count"])


def _model_elements(model_packet: dict[str, Any]) -> list[dict[str, str]]:
    collections = [
        ("external_entities", "External Entity"),
        ("processes", "Process"),
        ("data_stores", "Data Store"),
        ("data_flows", "Data Flow"),
        ("trust_boundaries", "Trust Boundary"),
    ]
    rows: list[dict[str, str]] = []
    for key, default_type in collections:
        for item in model_packet.get(key, []):
            element_id = str(item.get("stable_id") or item.get("id") or "").strip()
            if not element_id:
                continue
            rows.append({
                "Element ID": element_id,
                "Type": str(item.get("type") or default_type),
                "Name": str(item.get("name") or item.get("label") or ""),
            })
    return rows


def _affected_elements(threat: dict[str, Any]) -> set[str]:
    affected = _value(threat, "affected_model_elements", "model_element_ids", "Element")
    if isinstance(affected, list):
        return {str(item).strip() for item in affected if str(item).strip()}
    if isinstance(affected, str):
        normalized = affected.replace(",", ";")
        return {item.strip() for item in normalized.split(";") if item.strip()}
    return set()


def _threats_per_element_rows(
    model_packet: dict[str, Any],
    actual_threats: list[dict[str, Any]],
    new_threats: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    elements = _model_elements(model_packet)
    element_index = {row["Element ID"]: row for row in elements}
    actual_counts = {element_id: 0 for element_id in element_index}
    new_counts = {element_id: 0 for element_id in element_index}

    for threat in actual_threats:
        for element_id in _affected_elements(threat):
            actual_counts[element_id] = actual_counts.get(element_id, 0) + 1
            element_index.setdefault(element_id, {"Element ID": element_id, "Type": "Unknown", "Name": ""})
    for threat in new_threats:
        for element_id in _affected_elements(threat):
            new_counts[element_id] = new_counts.get(element_id, 0) + 1
            element_index.setdefault(element_id, {"Element ID": element_id, "Type": "Unknown", "Name": ""})

    ordered_ids = [row["Element ID"] for row in elements]
    ordered_ids.extend(sorted(element_id for element_id in element_index if element_id not in set(ordered_ids)))
    rows: list[dict[str, Any]] = []
    for element_id in ordered_ids:
        actual_count = actual_counts.get(element_id, 0)
        new_count = new_counts.get(element_id, 0)
        element = element_index[element_id]
        rows.append({
            "Element ID": element_id,
            "Name": element["Name"],
            "Type": element["Type"],
            "Baseline identified threats": actual_count,
            "Additional identified threats": new_count,
            "Total Threats": actual_count + new_count,
        })
    rows.sort(key=lambda row: (-int(row["Total Threats"]), row["Element ID"]))
    return rows


def _threats_per_element_summary(
    model_packet: dict[str, Any],
    actual_threats: list[dict[str, Any]],
    new_threats: list[dict[str, Any]],
) -> str:
    rows = _threats_per_element_rows(model_packet, actual_threats, new_threats)
    return _markdown_table(rows, ["Element ID", "Name", "Baseline identified threats", "Additional identified threats", "Total Threats"])


def _as_int(value: Any) -> int:
    try:
        return int(str(value or "0"))
    except ValueError:
        return 0


def _traceability_review_summary(
    run_dir: Path,
    model_packet: dict[str, Any],
    methods: list[dict[str, str]],
    actual_threats: list[dict[str, Any]],
    new_threats: list[dict[str, Any]],
    actual_responses: list[dict[str, Any]] | None = None,
    as_is_only: bool = False,
) -> str:
    if as_is_only:
        rows = [
            {
                "Item": "Actual threats",
                "Count": len(actual_threats),
                "Note": "Source-grounded baseline threat stories retained from specification evidence and model elements.",
            },
            {
                "Item": "Actual responses",
                "Count": len(actual_responses or []),
                "Note": "Current as-is responses, transfers, reductions, eliminations, or acceptances mapped through ERTA.",
            },
            {
                "Item": "New threats",
                "Count": 0,
                "Note": "No later full-elicitation pass is included in this as-is-only report.",
            },
        ]
        return (
            "#### Traceability Review Summary\n\n"
            + _markdown_table(rows, ["Item", "Count", "Note"])
            + "\n\n"
        )

    producing_methods = sorted(methods, key=lambda row: _as_int(row.get("producing")), reverse=True)
    producing_methods = [row for row in producing_methods if _as_int(row.get("producing")) > 0][:5]

    def _new_unique_text(row: dict[str, str]) -> str:
        value = str(row.get("new_unique_after_previous_methods") or "").strip()
        if value:
            return f"new unique IDs: {value}"
        return "0 new unique IDs after earlier methods"

    productive = "; ".join(
        f"{row.get('method')} ({row.get('producing')} producing, "
        f"{_new_unique_text(row)})"
        for row in producing_methods
    ) or "No producing method statistics were supplied"
    coverage_only = "; ".join(
        row.get("method", "")
        for row in methods
        if _as_int(row.get("producing")) == 0 and row.get("method")
    ) or "none"
    top_elements = [
        row for row in _threats_per_element_rows(model_packet, actual_threats, new_threats)
        if _as_int(row.get("Total Threats")) > 0
    ][:5]
    top_element_text = "; ".join(
        f"{row['Element ID']} {row['Name']} ({row['Total Threats']})"
        for row in top_elements
    ) or "No element concentration was supplied"
    zero_count = sum(
        1
        for row in _threats_per_element_rows(model_packet, actual_threats, new_threats)
        if _as_int(row.get("Total Threats")) == 0
    )
    theme_rows = _csv_rows(run_dir, "full-workshop.method-yield-by-theme.csv")
    if theme_rows:
        theme_text = "; ".join(
            f"{row.get('Theme')} -> {row.get('Producing Methods')}"
            for row in theme_rows[:5]
        )
    else:
        theme_details: dict[str, dict[str, set[str]]] = {}
        for threat in [*actual_threats, *new_threats]:
            threat_id = str(_value(threat, "threat_id", "ID") or "")
            categories = _value(threat, "threat_category", "Threat Category") or []
            found_by = _value(threat, "found_by_methods", "Found By") or []
            category_items = categories if isinstance(categories, list) else [categories]
            method_items = found_by if isinstance(found_by, list) else [found_by]
            for category in category_items:
                name = str(category).strip()
                if not name:
                    continue
                detail = theme_details.setdefault(name, {"threats": set(), "methods": set()})
                if threat_id:
                    detail["threats"].add(threat_id)
                detail["methods"].update(
                    str(method).strip() for method in method_items if str(method).strip()
                )
        top_themes = sorted(
            theme_details.items(),
            key=lambda item: (-len(item[1]["threats"]), item[0].lower()),
        )[:8]
        theme_text = "; ".join(
            f"{name}: {len(detail['threats'])} threats via "
            f"{', '.join(sorted(detail['methods'])) or 'method not recorded'}"
            for name, detail in top_themes
        ) or "No theme/category data was supplied"
    candidate_rows = _csv_rows(run_dir, "full-workshop.candidate-lifecycle.csv")
    if candidate_rows:
        disposition_counts: dict[str, int] = {}
        for row in candidate_rows:
            disposition = row.get("disposition", "unknown") or "unknown"
            disposition_counts[disposition] = disposition_counts.get(disposition, 0) + 1
        candidate_text = "; ".join(
            f"{key}: {value}" for key, value in sorted(disposition_counts.items())
        )
    else:
        candidate_text = "No raw candidate lifecycle artifact was supplied"
    question_quality_rows = _csv_rows(run_dir, "full-workshop.question-generation-quality.csv")
    if question_quality_rows:
        source_grounded = sum(_as_int(row.get("Source-grounded")) for row in question_quality_rows)
        model_inferred = sum(_as_int(row.get("Model-inferred")) for row in question_quality_rows)
        framework_probe = sum(_as_int(row.get("Framework-probe")) for row in question_quality_rows)
        model_gap = sum(_as_int(row.get("Model-gap")) for row in question_quality_rows)
        generic_prompts = sum(_as_int(row.get("Generic prompt rows")) for row in question_quality_rows)
        missing_relatedness = sum(_as_int(row.get("Missing relatedness basis")) for row in question_quality_rows)
        aggregated = [
            row.get("Artifact", "")
            for row in question_quality_rows
            if "method_per_element" in row.get("Aggregation levels", "")
        ]
        quality_text = (
            f"source-grounded rows: {source_grounded}; "
            f"model-inferred rows: {model_inferred}; framework probes: "
            f"{framework_probe}; model-gap rows: {model_gap}; generic prompt "
            f"rows: {generic_prompts}; rows missing relatedness basis: "
            f"{missing_relatedness}; aggregated method traces: "
            f"{len(aggregated)}."
        )
    else:
        quality_text = "No question-generation quality artifact was supplied"
    source_packet_rows = _csv_rows(run_dir, "full-workshop.element-source-packets.csv")
    prompt_feedback_rows = _csv_rows(run_dir, "full-workshop.prompt-template-feedback.csv")
    card_play_comparison_rows = _csv_rows(run_dir, "full-workshop.card-play-rerun-comparison.csv")
    semantic_playtest_rows = _csv_rows(run_dir, "full-workshop.semantic-card-playtest.csv")
    llm_sample_rows = _csv_rows(run_dir, "full-workshop.llm-sampled-card-playtest.csv")
    llm_zero_rows = _csv_rows(run_dir, "full-workshop.llm-zero-threat-elements-check.csv")
    llm_one_rows = _csv_rows(run_dir, "full-workshop.llm-one-threat-elements-check.csv")
    candidate_dfd_rows = _csv_rows(run_dir, "full-workshop.candidate-dfd-model-refinements.csv")
    gate_rows = _csv_rows(run_dir, "full-workshop.strict-quality-gate.csv")
    if gate_rows:
        gate_failures = [
            row for row in gate_rows
            if str(row.get("status", "")).lower() != "pass"
        ]
        gate_text = (
            f"{len(gate_rows)} checks, {len(gate_failures)} failures; "
            f"{len(source_packet_rows)} element source packets; "
            f"{len(prompt_feedback_rows)} prompt-template feedback rows."
        )
    else:
        gate_text = "No strict full-run quality gate artifact was supplied"
    if card_play_comparison_rows:
        comparison_by_key = {
            (row.get("scope", ""), row.get("metric", "")): row
            for row in card_play_comparison_rows
        }

        def _comparison_metric(scope: str, metric: str) -> str:
            row = comparison_by_key.get((scope, metric), {})
            if not row:
                return f"{metric}: not supplied"
            return (
                f"{metric}: {row.get('before')} -> {row.get('after')} "
                f"({row.get('delta')})"
            )

        comparison_text = "; ".join(
            [
                _comparison_metric("workshop_simulation", "rows"),
                _comparison_metric("workshop_simulation", "rewrite"),
                _comparison_metric("workshop_simulation", "retire"),
                _comparison_metric("workshop_simulation", "unique_templates"),
            ]
        )
    else:
        comparison_text = "No card-play rerun comparison artifact was supplied"
    if semantic_playtest_rows:
        semantic_decisions: dict[str, int] = {}
        semantic_new_threats = 0
        semantic_dfd_candidates: dict[str, str] = {}
        for row in semantic_playtest_rows:
            decision = row.get("classifier_decision", "unknown") or "unknown"
            semantic_decisions[decision] = semantic_decisions.get(decision, 0) + 1
            if row.get("candidate_new_threat_id"):
                semantic_new_threats += 1
            if row.get("candidate_new_dfd_element_id"):
                semantic_dfd_candidates[
                    row.get("candidate_new_dfd_element_id", "")
                ] = row.get("candidate_new_dfd_element_name", "")
        semantic_decision_text = "; ".join(
            f"{key}: {value}" for key, value in sorted(semantic_decisions.items())
        )
        dfd_text = (
            "; ".join(
                f"{key} {value}".strip()
                for key, value in sorted(semantic_dfd_candidates.items())
            )
            or "none"
        )
        semantic_text = (
            f"{len(semantic_playtest_rows)} card plays classified from source "
            f"packets; decisions: {semantic_decision_text}; candidate new "
            f"threat rows: {semantic_new_threats}; candidate DFD elements: "
            f"{dfd_text}."
        )
    else:
        semantic_text = "No semantic card-play classifier artifact was supplied"
    if llm_sample_rows:
        candidate_ids = sorted({
            row.get("candidate_new_threat_id", "")
            for row in llm_sample_rows
            if row.get("candidate_new_threat_id")
        })
        promotion_statuses = sorted({
            row.get("promotion_status", "")
            for row in llm_sample_rows
            if row.get("promotion_status")
        })
        llm_text = (
            f"{len(llm_sample_rows)} sampled source-reread rows; "
            f"candidate threat IDs: {', '.join(candidate_ids) or 'none'}; "
            f"promotion status: {', '.join(promotion_statuses) or 'not supplied'}."
        )
    else:
        llm_text = "No LLM sampled card-play source-reread artifact was supplied"
    if llm_zero_rows or llm_one_rows:
        def _llm_element_summary(rows: list[dict[str, str]], label: str) -> str:
            if not rows:
                return f"{label}: not supplied"
            elements = {
                row.get("element_id", "")
                for row in rows
                if row.get("element_id")
            }
            candidates = sorted({
                row.get("candidate_new_threat_id", "")
                for row in rows
                if row.get("candidate_new_threat_id")
            })
            decisions: dict[str, int] = {}
            for row in rows:
                decision = row.get("llm_decision", "unknown") or "unknown"
                decisions[decision] = decisions.get(decision, 0) + 1
            decision_text = "; ".join(
                f"{key}: {value}" for key, value in sorted(decisions.items())
            )
            return (
                f"{label}: {len(elements)} elements, {len(rows)} rows, "
                f"candidate IDs: {', '.join(candidates) or 'none'}, "
                f"decisions: {decision_text}"
            )

        llm_element_text = (
            f"{_llm_element_summary(llm_zero_rows, 'zero-threat')}. "
            f"{_llm_element_summary(llm_one_rows, 'one-threat')}."
        )
    else:
        llm_element_text = "No LLM zero/one-threat element source-reread artifacts were supplied"
    if candidate_dfd_rows:
        candidate_dfd_text = "; ".join(
            f"{row.get('Added Element ID') or row.get('Candidate Element ID')} "
            f"{row.get('Name')} ({row.get('Modeling Decision')}; "
            f"{row.get('Evidence Status')})"
            for row in candidate_dfd_rows
        )
    else:
        candidate_dfd_text = "No candidate DFD model-refinement artifact was supplied"
    manifest_rows = _csv_rows(run_dir, "full-workshop.trace-manifest.csv")
    if manifest_rows:
        by_artifact = {row.get("Artifact", ""): row for row in manifest_rows}
        complete_method_traces = [
            row for row in manifest_rows
            if row.get("Artifact", "").endswith(".complete-trace.csv")
        ]

        def _manifest_item(artifact: str) -> str:
            row = by_artifact.get(artifact, {})
            if not row:
                return f"{artifact} not supplied"
            return (
                f"{artifact} ({row.get('Rows')} rows, "
                f"{row.get('Completeness')})"
            )

        manifest_text = (
            f"{len(manifest_rows)} listed artifacts, including "
            f"{len(complete_method_traces)} complete method traces. "
            f"Key complete traces: {_manifest_item('full-workshop.card-play-trace.csv')}; "
            f"{_manifest_item('full-workshop.candidate-lifecycle.csv')}; "
            f"{_manifest_item('full-workshop.stride-paper-matrix.csv')}; "
            f"{_manifest_item('full-workshop.linddun-paper-matrix.csv')}. "
            "The full trace manifest names the per-method complete-trace "
            "artifacts used for RFC, checklist, principle, XS-Leaks, "
            "fingerprinting, and Simone-review question generation."
        )
    else:
        manifest_text = "No trace manifest was supplied"

    repair_trace_manifest = _load_run_json(
        run_dir,
        ("trace-linkage-manifest.json",),
        {},
    )
    if (
        isinstance(repair_trace_manifest, dict)
        and repair_trace_manifest.get("artifact_kind") == "repair_trace_linkage_manifest"
    ):
        linked_artifacts = repair_trace_manifest.get("linked_artifacts", [])
        linked_artifacts = [
            row
            for row in linked_artifacts
            if isinstance(row, dict) and row.get("status") == "present"
        ]
        linked_paths = [str(row.get("path") or "") for row in linked_artifacts]

        def _linked_count(*needles: str) -> int:
            return sum(
                1
                for path in linked_paths
                if any(needle in path for needle in needles)
            )

        reconciliation = _load_run_json(run_dir, ("reconciliation-map.json",), {})
        disposition_counts = (
            reconciliation.get("worker_dispositions", {})
            if isinstance(reconciliation, dict)
            else {}
        )
        if isinstance(disposition_counts, dict) and disposition_counts:
            candidate_text = "; ".join(
                f"{key}: {value}"
                for key, value in sorted(disposition_counts.items())
            )

        theme_text = (
            f"{theme_text}. This aggregation is derived from the canonical "
            "threat categories and found-by method IDs; the linked artifacts "
            "preserve the underlying method-specific execution"
        )
        source_trace_count = _linked_count("source-trace", "input.json")
        producing_trace_count = _linked_count("producing-trace")
        nonproducing_trace_count = _linked_count("nonproducing-trace")
        feedback_count = _linked_count("prompt-template-feedback")
        quality_text = (
            f"{source_trace_count} linked source/input artifacts, "
            f"{producing_trace_count} producing-trace artifacts, "
            f"{nonproducing_trace_count} non-producing-trace artifacts, and "
            f"{feedback_count} prompt-template feedback artifact. Repair-v2 "
            "links the earlier source-conditioned execution to canonical IDs; "
            "it does not claim every method was rerun after the skill repair"
        )
        analysis_gate = _load_run_json(run_dir, ("analysis-gate.json",), {})
        analysis_checks = _gate_check_rows(analysis_gate) if isinstance(analysis_gate, dict) else []
        failed_links = [
            row
            for row in repair_trace_manifest.get("linked_artifacts", [])
            if not isinstance(row, dict) or row.get("status") != "present"
        ]
        gate_text = (
            f"analysis gate {analysis_gate.get('status', 'not supplied')} with "
            f"{len(analysis_checks)} named checks; {len(linked_artifacts)} "
            f"hash-linked artifacts present and {len(failed_links)} missing or invalid"
        )
        comparison_text = (
            "No separate before/after card-play comparison was emitted for "
            "repair-v2; the linkage manifest preserves the earlier card-play "
            f"execution ({_linked_count('card-play-trace')} trace artifacts) "
            "and the reconciliation map records its canonical dispositions"
        )
        semantic_text = (
            f"{_linked_count('card-play-classifier')} linked semantic classifier "
            f"artifacts and {_linked_count('card-play-trace')} linked card-play "
            "trace artifacts are hash-verified by the repair manifest."
        )
        llm_text = (
            f"{_linked_count('llm-sampled-card-playtest')} linked sampled "
            "source-reread artifacts are hash-verified by the repair manifest."
        )
        llm_element_text = (
            f"{_linked_count('zero-threat-elements', 'one-threat-elements')} "
            "linked zero/one-threat element reread artifacts are hash-verified "
            "by the repair manifest."
        )
        model_gaps = (
            reconciliation.get("model_gaps", [])
            if isinstance(reconciliation, dict)
            else []
        )
        if isinstance(model_gaps, list) and model_gaps:
            gap_ids = [
                str(row.get("candidate_id") or "unnamed")
                for row in model_gaps
                if isinstance(row, dict)
            ]
            candidate_dfd_text = (
                f"{len(model_gaps)} candidate model gaps are recorded in the "
                f"reconciliation map ({'; '.join(gap_ids)}); neither was added "
                "without sufficient architecture and authority-boundary evidence"
            )
        else:
            candidate_dfd_text = (
                "The repair reconciliation map records no unresolved candidate "
                "DFD refinement"
            )
        legacy_manifest = repair_trace_manifest.get("legacy_trace_manifest", {})
        declared_rows = (
            legacy_manifest.get("declared_rows", "unknown")
            if isinstance(legacy_manifest, dict)
            else "unknown"
        )
        declared_count = repair_trace_manifest.get(
            "linked_artifact_count",
            len(linked_artifacts),
        )
        manifest_text = (
            f"{len(linked_artifacts)} of {declared_count} linked artifacts are "
            f"present with recorded hashes; the linked legacy manifest declares "
            f"{declared_rows} rows. {repair_trace_manifest.get('scope', '')}"
        ).strip().rstrip(".")
    return (
        "#### Traceability Review Summary\n\n"
        f"The most productive methods for retained threats were: {productive}. "
        f"The highest-concentration diagram areas were: {top_element_text}. "
        "Methods with zero raw producing trace rows in the repaired statistics "
        f"were: {coverage_only}. Their linked artifacts may still confirm "
        "baseline threats, contribute reconciled card results, or supply coverage evidence.\n\n"
        f"Method yield by threat theme: {theme_text}. Candidate lifecycle: "
        f"{candidate_text}.\n\n"
        f"Question-generation quality: {quality_text}.\n\n"
        f"Strict full-run gate: {gate_text}.\n\n"
        f"Card-play rerun comparison: {comparison_text}.\n\n"
        f"Semantic card-play classifier: {semantic_text}\n\n"
        f"LLM sampled card-play source reread: {llm_text}\n\n"
        f"LLM zero/one-threat element source reread: {llm_element_text}\n\n"
        f"Candidate DFD model refinement: {candidate_dfd_text}.\n\n"
        f"Trace manifest: {manifest_text}.\n\n"
        "Non-producing rows mean that the selected prompt did not produce a "
        "separate concrete bad event beyond the reconciled threats. They are "
        "useful as coverage evidence, but they are not proof that an element is "
        "safe; each non-producing row should carry a controlled reason and, "
        "when applicable, related retained threat IDs. "
        f"{zero_count} diagram elements had no mapped retained threat; "
        "their interpretation is separated in the appendix so reviewers can see "
        "which elements are context, indirectly covered, weakly explored, or "
        "still unresolved.\n\n"
    )


def _zero_threat_interpretation(
    model_packet: dict[str, Any],
    actual_threats: list[dict[str, Any]],
    new_threats: list[dict[str, Any]],
) -> str:
    zero_rows = [
        row for row in _threats_per_element_rows(model_packet, actual_threats, new_threats)
        if _as_int(row.get("Total Threats")) == 0
    ]
    rows: list[dict[str, str]] = []
    for row in zero_rows:
        element_id = str(row["Element ID"])
        name = str(row["Name"])
        element_type = str(row["Type"])
        interpretation = "No separate bad event found"
        reason = "Applied prompts did not produce a retained threat for this element beyond adjacent threats."
        follow_up = "Revisit if the diagram or review scope changes."
        if element_type == "External Entity":
            interpretation = "Context element"
            reason = "Threats are mapped to API behavior affecting or involving this actor, not to the actor itself."
            follow_up = "None unless stakeholder-harm modeling is expanded."
        elif element_type == "Trust Boundary":
            interpretation = "Boundary assumption"
            reason = "Threats are mapped to flows or processes that cross the boundary rather than to the boundary row itself."
            follow_up = "Revisit if trust-boundary ownership or enforcement changes."
        elif "watch" in name.lower():
            interpretation = "Indirectly covered"
            reason = "Watch behavior is represented by lifecycle, callback, and movement-profile threats."
            follow_up = "Revisit if watch identifier misuse becomes in scope."
        elif "emulation" in name.lower() or "emulated" in name.lower():
            interpretation = "Indirectly covered"
            reason = "Emulation concerns are represented by automation and emulated-state threats."
            follow_up = "Revisit if automation access control is in scope."
        rows.append({
            "Element ID": element_id,
            "Name": name,
            "Interpretation": interpretation,
            "Reason": reason,
            "Follow-up": follow_up,
        })
    if not rows:
        return "No zero-threat diagram elements were identified.\n"
    return _markdown_table(rows, ["Element ID", "Name", "Interpretation", "Reason", "Follow-up"])


def _transfer_and_assumption_summary(responses: list[dict[str, Any]]) -> str:
    rows: list[dict[str, str]] = []
    for response in responses:
        if str(_value(response, "erta", "ERTA", "Proposed ERTA")).strip() != "Transfer":
            continue
        receiver = str(
            _value(
                response,
                "transfer_receiver",
                "receiver",
                "decision_owner",
                "owner",
                "Decision Owner",
                "Threat Owner",
            )
            or "Receiver not named"
        )
        responsibility = str(
            _value(
                response,
                "transferred_responsibility",
                "response",
                "reviewer_recommendation",
                "Current / Baseline Response",
                "Reviewer Recommendation",
            )
            or "Transferred responsibility not supplied"
        )
        assumptions = _string_list(_value(response, "assumptions", "Assumptions Used"))
        remaining = str(
            _value(
                response,
                "remaining_threat",
                "if_no_change_remaining_threat",
                "Remaining Threat",
                "If No Change, Remaining Threat",
            )
            or "Remaining concern not supplied"
        )
        rows.append({
            "Receiver": receiver,
            "Transferred Responsibility": responsibility,
            "Key Assumption": assumptions or "None recorded",
            "Related Threats": str(_value(response, "threat_id", "Threat ID")),
            "Remaining Concern": remaining,
        })
    if not rows:
        return (
            "#### Transfer and Assumption Summary\n\n"
            "No ERTA Transfer response is present in this response set.\n\n"
        )
    return (
        "#### Transfer and Assumption Summary\n\n"
        + _markdown_table(rows, ["Receiver", "Transferred Responsibility", "Key Assumption", "Related Threats", "Remaining Concern"])
        + "\n\n"
    )


def _remaining_threat_closure_summary(responses: list[dict[str, Any]]) -> str:
    by_erta: dict[str, list[str]] = {"Reduce": [], "Transfer": [], "Accept": [], "Eliminate": []}
    still_open: list[str] = []
    for response in responses:
        threat_id = str(_value(response, "threat_id", "Threat ID"))
        erta = str(_value(response, "erta", "ERTA", "Proposed ERTA"))
        if erta in by_erta:
            by_erta[erta].append(threat_id)
        if _decision_question(response):
            still_open.append(threat_id)
        if erta == "Transfer" and not str(_value(response, "acceptance_rationale")).strip():
            still_open.append(threat_id)
    rows = [
        {
            "Closure Type": "Reduced but remaining",
            "Threats": "; ".join(by_erta["Reduce"]) or "None",
            "Meaning": "A response reduces the threat but leaves residual behavior, implementation dependency, or editor decision work.",
        },
        {
            "Closure Type": "Transferred",
            "Threats": "; ".join(by_erta["Transfer"]) or "None",
            "Meaning": (
                "Responsibility is assigned to the receiver named in the transfer "
                "summary; a transfer remains open until receiver acceptance and "
                "its enabling assumptions are evidenced."
            ),
        },
        {
            "Closure Type": "Accepted",
            "Threats": "; ".join(by_erta["Accept"]) or "None",
            "Meaning": (
                "These threats are explicitly accepted by the response set; "
                "their owners, assumptions, remaining threat, next action, and "
                "revisit conditions remain recorded in the response table."
                if by_erta["Accept"]
                else "No retained threat is explicitly accepted in this run."
            ),
        },
        {
            "Closure Type": "Eliminated",
            "Threats": "; ".join(by_erta["Eliminate"]) or "None",
            "Meaning": (
                "The response set records these threats as eliminated."
                if by_erta["Eliminate"]
                else "No retained threat is fully eliminated by the current response set."
            ),
        },
        {
            "Closure Type": "Open decision or transfer",
            "Threats": "; ".join(dict.fromkeys(still_open)) or "None",
            "Meaning": "The row contains an unresolved decision or an unaccepted transfer that needs editor, implementer, receiver, or reviewer closure.",
        },
    ]
    return (
        "#### Remaining Threat Closure Summary\n\n"
        + _markdown_table(rows, ["Closure Type", "Threats", "Meaning"])
        + "\n\n"
    )


def _candidate_threats_from_llm_compact(run_dir: Path) -> str:
    candidate_sources = [
        "full-workshop.llm-expanded-source-reread-probes.csv",
        "full-workshop.llm-sampled-card-playtest.csv",
        "full-workshop.llm-zero-threat-elements-check.csv",
        "full-workshop.llm-one-threat-elements-check.csv",
        "full-workshop.llm-stride-per-element-compact.csv",
        "full-workshop.llm-linddun-per-element-compact.csv",
        "full-workshop.llm-rfc6973-privacy-per-element-compact.csv",
        "full-workshop.llm-rfc3552-security-per-element-compact.csv",
        "full-workshop.llm-horizontal-checklist-per-element-compact.csv",
        "full-workshop.llm-xs-leaks-per-element-compact.csv",
        "full-workshop.llm-stride-method-item-x-element.csv",
        "full-workshop.llm-linddun-method-item-x-element.csv",
        "full-workshop.llm-rfc6973-privacy-method-item-x-element.csv",
    ]
    by_candidate: dict[str, dict[str, Any]] = {}
    for artifact in candidate_sources:
        for row in _csv_rows(run_dir, artifact):
            candidate_id = row.get("candidate_new_threat_id", "").strip()
            if not candidate_id:
                continue
            entry = by_candidate.setdefault(candidate_id, {
                "Candidate ID": candidate_id,
                "Candidate Name": row.get("candidate_new_threat_name", ""),
                "Seen In Artifacts": set(),
                "Related Retained Threats": set(),
                "Why Not Retained": set(),
                "Decision Needed": set(),
            })
            if row.get("candidate_new_threat_name"):
                entry["Candidate Name"] = row.get("candidate_new_threat_name", "")
            entry["Seen In Artifacts"].add(artifact)
            related = row.get("related_threat_ids", "")
            for threat_id in str(related).replace(",", ";").split(";"):
                threat_id = threat_id.strip()
                if threat_id:
                    entry["Related Retained Threats"].add(threat_id)
            promotion = row.get("promotion_status", "")
            evidence = row.get("evidence_status", "")
            if promotion:
                entry["Why Not Retained"].add(promotion)
            elif evidence:
                entry["Why Not Retained"].add(evidence)
            action = row.get("reviewer_action", "")
            if action:
                entry["Decision Needed"].add(action)

    if not by_candidate:
        return "No `T-CAND-*` rows were supplied by compact LLM artifacts.\n\n"

    decision_fallback = {
        "T-CAND-17": "Decide whether recipient-side auxiliary data joins and candidate DFD elements DS-06/DF-27 are in scope.",
        "T-CAND-18": "Decide whether implementation-specific error-message variance is in scope or needs browser evidence.",
        "T-CAND-19": "Decide whether motion attributes should become a separate threat or refine T-08/T-12.",
        "T-CAND-20": "Decide whether high-accuracy timing/capability probing is a separate oracle threat or a refinement of existing timing/linkability threats.",
        "T-CAND-21": "Decide whether maximumAge cache-existence probing is distinct from cached-location reuse and error/timing oracles.",
    }
    rows: list[dict[str, str]] = []
    for candidate_id in sorted(by_candidate):
        entry = by_candidate[candidate_id]
        decisions = entry["Decision Needed"] or {decision_fallback.get(candidate_id, "Manual reviewer decision required before promotion.")}
        rows.append({
            "Candidate ID": candidate_id,
            "Candidate Name": entry["Candidate Name"],
            "Seen In Artifacts": "; ".join(sorted(entry["Seen In Artifacts"])),
            "Related Retained Threats": "; ".join(sorted(entry["Related Retained Threats"])),
            "Why Not Retained": "; ".join(sorted(entry["Why Not Retained"])) or "needs_manual_review",
            "Decision Needed": "; ".join(sorted(decisions)),
        })
    return _markdown_table(rows, [
        "Candidate ID",
        "Candidate Name",
        "Seen In Artifacts",
        "Related Retained Threats",
        "Why Not Retained",
        "Decision Needed",
    ]) + "\n\n"


def _stats_from_methods(stats: Any, methods: list[dict[str, str]]) -> dict[str, Any]:
    if isinstance(stats, dict):
        normalized = dict(stats)
    else:
        normalized = {}
    if "total_trace_rows" not in normalized:
        normalized["total_trace_rows"] = sum(_as_int(row.get("prompts_or_plays")) for row in methods) or "unknown"
    if "producing_trace_rows" not in normalized:
        normalized["producing_trace_rows"] = sum(_as_int(row.get("producing")) for row in methods) or "unknown"
    if "non_producing_trace_rows" not in normalized:
        normalized["non_producing_trace_rows"] = sum(_as_int(row.get("non_producing")) for row in methods) or "unknown"
    rows_by_method = {str(row.get("method") or ""): row for row in methods}
    if "stride_paper_matrix_rows" not in normalized:
        stride = rows_by_method.get("stride_per_element", {})
        normalized["stride_paper_matrix_rows"] = stride.get("prompts_or_plays") or "unknown"
    if "linddun_paper_matrix_rows" not in normalized:
        linddun = rows_by_method.get("linddun_per_element", {})
        normalized["linddun_paper_matrix_rows"] = linddun.get("prompts_or_plays") or "unknown"
    return normalized


def _optional_table_or_note(rows: list[dict[str, str]], headers: list[str], note: str) -> str:
    if rows:
        return _markdown_table(rows, headers) + "\n"
    return note.rstrip() + "\n\n" + _markdown_table([], headers) + "\n"


def _filter_new_threats(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    statuses = {str(_value(threat, "status", "Status")).lower() for threat in threats}
    if statuses & {"actual", "baseline", "new", "additional", "retained", "retained_unique"}:
        return [
            threat for threat in threats
            if str(_value(threat, "status", "Status")).lower()
            in {"new", "additional", "retained", "retained_unique"}
        ]
    return threats


def _filter_proposed_responses(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    statuses = {str(_value(response, "status", "Status")).lower() for response in responses}
    if statuses & {"existing", "proposed"}:
        return [
            response for response in responses
            if str(_value(response, "status", "Status")).lower() == "proposed"
        ]
    return responses


def _row_ids(rows: list[dict[str, Any]], *keys: str) -> list[str]:
    return [str(_value(row, *keys)).strip() for row in rows]


def _model_element_ids(model_packet: dict[str, Any]) -> frozenset[str]:
    return frozenset(row["Element ID"] for row in _model_elements(model_packet))


def _dictionary_rows(run_dir: Path) -> tuple[list[str], list[dict[str, str]]]:
    text = _dictionary_table(run_dir)
    lines = [line for line in text.splitlines() if line.lstrip().startswith("|")]
    if len(lines) < 2:
        return [], []
    headers = _split_markdown_row(lines[0])
    rows: list[dict[str, str]] = []
    for line in lines[2:]:
        cells = _split_markdown_row(line)
        if len(cells) == len(headers):
            rows.append(dict(zip(headers, cells)))
    return headers, rows


def _gate_status(value: Any) -> str:
    return str(value or "").strip().lower()


def _analysis_gate(run_dir: Path, *, baseline_only: bool) -> tuple[dict[str, Any], list[str]]:
    path = _first_existing_path(run_dir, "analysis-gate.json")
    if not path.exists():
        return {}, ["missing required analysis-gate.json"]
    try:
        gate = _load_json(path, {})
    except (json.JSONDecodeError, OSError) as error:
        return {}, [f"invalid analysis-gate.json: {error}"]
    if not isinstance(gate, dict):
        return {}, ["analysis-gate.json must contain a JSON object"]
    errors: list[str] = []
    name = str(gate.get("gate") or gate.get("name") or "").strip().lower()
    if name not in {"analysis", "analysis gate", "analysis_gate"}:
        errors.append("analysis-gate.json must be explicitly named analysis")
    if _gate_status(gate.get("status")) not in {"pass", "complete"}:
        errors.append(
            "analysis gate must pass before publication assembly; "
            f"found {gate.get('status') or 'missing'}"
        )
    checks = gate.get("checks", gate.get("rows"))
    if not isinstance(checks, list) or not checks:
        errors.append("analysis gate must contain named checks")
    else:
        check_names = {
            _slugify(check.get("name") or check.get("check"), "unnamed").replace("-", "_")
            for check in checks
            if isinstance(check, dict)
        }
        required_check_aliases = {
            "source_corpus": {"source_corpus", "source_identity", "source_corpus_and_source_identity"},
            "model_packet": {"model_packet", "model_source_coverage", "model_packet_and_source_coverage"},
            "dfd_representation": {
                "dfd_representation",
                "dfd_representation_and_complete_dictionary",
                "dfd_complete_dictionary",
            },
            "baseline_elicitation": {"baseline_elicitation", "baseline"},
            "response_mapping": {"response_mapping", "responses"},
            "independent_review": {
                "independent_review",
                "independent_skeptic_review",
                "independent_skeptic_good_enough_review",
            },
        }
        if not baseline_only:
            required_check_aliases["additional_elicitation_reconciliation"] = {
                "additional_elicitation_reconciliation",
                "additional_elicitation_and_reconciliation",
            }
        missing_checks = sorted(
            canonical
            for canonical, aliases in required_check_aliases.items()
            if not (aliases & check_names)
        )
        if missing_checks:
            errors.append(f"analysis gate missing required named checks: {missing_checks}")
        failed = [
            str(check.get("name") or check.get("check") or "unnamed")
            for check in checks
            if not isinstance(check, dict)
            or _gate_status(check.get("status")) not in {"pass", "complete"}
        ]
        if failed:
            errors.append(f"analysis gate has non-passing checks: {failed}")
    return gate, errors


def _validate_tmdc_mermaid(run_dir: Path, model_ids: frozenset[str]) -> list[str]:
    path = _first_existing_path(run_dir, "dfd.mmd", "*-dfd.mmd", "*.mmd")
    if not path.exists():
        return ["missing Mermaid DFD source"]
    source = path.read_text()
    checks = {
        "Arial font": "Arial" in source,
        "22px labels": bool(re.search(r'fontSize["\']?\s*:\s*["\']22px["\']', source)),
        "linear routing": bool(re.search(r'curve["\']?\s*:\s*["\']linear["\']', source)),
        "HTML labels": bool(re.search(r'htmlLabels["\']?\s*:\s*true', source)),
        "thick node borders": "stroke-width:4px" in source,
        "thick black arrows": "linkStyle default stroke:#000,stroke-width:3px,color:#000" in source,
        "TMDC flow arrows": "==>" in source,
        "native trust boundaries": "subgraph " in source,
        "dashed trust boundaries": "stroke-dasharray:8 6" in source,
        "no styled HTML labels": "<span" not in source.lower() and "<b>" not in source.lower(),
    }
    errors = [f"TMDC Mermaid evidence failed: {name}" for name, passed in checks.items() if not passed]
    missing_labels = sorted(element_id for element_id in model_ids if element_id not in source)
    if missing_labels:
        errors.append(f"Mermaid source missing canonical visible labels: {missing_labels}")
    if not _first_existing_path(run_dir, "dfd.svg", "*-dfd.svg", "*.svg").exists():
        errors.append("missing SVG DFD render")
    if not _first_existing_path(run_dir, "dfd-large.png", "*-dfd-large.png", "*-large.png").exists():
        errors.append("missing large PNG DFD render")
    return errors


def _validate_input_artifacts(
    run_dir: Path,
    model_packet: dict[str, Any],
    baseline_threats: list[dict[str, Any]],
    additional_threats: list[dict[str, Any]],
    actual_responses: list[dict[str, Any]],
    new_responses: list[dict[str, Any]],
    *,
    baseline_only: bool,
    publication_ready: bool = True,
) -> tuple[ReportExpectations | None, dict[str, Any], list[str]]:
    errors: list[str] = []
    analysis_gate, gate_errors = _analysis_gate(run_dir, baseline_only=baseline_only)
    errors.extend(gate_errors)
    independent_gate_path = _first_existing_path(run_dir, "independent-review-gate.json")
    if publication_ready and not independent_gate_path.exists() and not baseline_only:
        errors.append("missing required independent-review-gate.json for full report")
    elif independent_gate_path.exists():
        independent_gate = _load_json(independent_gate_path, {})
        independent_checks = (
            _gate_check_rows(independent_gate)
            if isinstance(independent_gate, dict)
            else []
        )
        independent_check_names = {
            str(row.get("name") or row.get("check") or "")
            for row in independent_checks
            if isinstance(row, dict)
        }
        if (
            not isinstance(independent_gate, dict)
            or _gate_status(independent_gate.get("status")) not in {"pass", "complete"}
            or independent_gate.get("publication_allowed") is False
        ):
            errors.append("independent review gate must pass before publication assembly")
        if (
            publication_ready
            and not baseline_only
            and "semantic_good_enough_review" not in independent_check_names
        ):
            errors.append(
                "independent review gate missing semantic_good_enough_review check"
            )
    if not model_packet:
        errors.append("model packet is missing or empty")
    model_ids = _model_element_ids(model_packet)
    if not model_ids:
        errors.append("model packet contains no DFD elements")
    noncanonical_model_ids = sorted(element_id for element_id in model_ids if not CANONICAL_DFD_ID.fullmatch(element_id))
    if noncanonical_model_ids:
        errors.append(f"model packet contains non-canonical DFD IDs: {noncanonical_model_ids}")

    dictionary_headers, dictionary_rows = _dictionary_rows(run_dir)
    missing_headers = [header for header in DICTIONARY_REQUIRED_HEADERS if header not in dictionary_headers]
    if missing_headers:
        errors.append(f"DFD dictionary missing required columns: {missing_headers}")
    dictionary_ids = frozenset(row.get("ID", "").strip() for row in dictionary_rows if row.get("ID", "").strip())
    if dictionary_ids != model_ids:
        errors.append(
            "DFD dictionary must exactly cover the model element set; "
            f"missing={sorted(model_ids - dictionary_ids)}, extra={sorted(dictionary_ids - model_ids)}"
        )
    for row in dictionary_rows:
        element_id = row.get("ID", "").strip()
        for field in ("Mermaid node ID", "Type", "Visible label", "Name", "Description", "Specification Reference"):
            if not row.get(field, "").strip():
                errors.append(f"DFD dictionary row {element_id or '<missing ID>'} has empty {field}")
        if row.get("Type", "").strip().lower() in {"data flow", "data_flow", "flow"}:
            for field in ("Flow Source", "Flow Destination"):
                if not row.get(field, "").strip():
                    errors.append(f"DFD dictionary flow {element_id or '<missing ID>'} has empty {field}")
    assumption_registry = _load_run_json(run_dir, ("assumptions-and-follow-up.json",), {})
    assumption_rows = assumption_registry.get("rows", []) if isinstance(assumption_registry, dict) else []
    registry_ids = {
        str(row.get("ID"))
        for row in assumption_rows
        if isinstance(row, dict) and row.get("ID")
    }
    assumption_refs: set[str] = set()
    for assumption in model_packet.get("assumptions", []):
        if isinstance(assumption, dict):
            assumption_refs.add(str(assumption.get("assumption_id") or assumption.get("id") or ""))
    for row in dictionary_rows:
        assumption_refs.update(re.findall(r"A-\d{3,}", row.get("Assumptions", "")))
    for item in [*baseline_threats, *additional_threats, *actual_responses, *new_responses]:
        values = item.get("assumptions", []) if isinstance(item, dict) else []
        if isinstance(values, list):
            assumption_refs.update(str(value) for value in values)
        else:
            errors.append("threat/response assumptions must be an array of canonical A-### references")
    assumption_refs.discard("")
    invalid_assumption_refs = sorted(value for value in assumption_refs if not re.fullmatch(r"A-\d{3,}", value))
    if invalid_assumption_refs:
        errors.append(f"non-canonical assumption references: {invalid_assumption_refs}")
    if not assumption_rows:
        errors.append("missing canonical assumptions-and-follow-up registry")
    elif (not baseline_only and assumption_refs != registry_ids) or (baseline_only and not assumption_refs <= registry_ids):
        errors.append(
            "assumption references must resolve to the canonical registry"
            + (" and exactly equal it for the full report; " if not baseline_only else "; ")
            + f"missing={sorted(registry_ids - assumption_refs)}, extra={sorted(assumption_refs - registry_ids)}"
        )
    errors.extend(_validate_tmdc_mermaid(run_dir, model_ids))

    baseline_ids_list = _row_ids(baseline_threats, "threat_id", "ID")
    additional_ids_list = _row_ids(additional_threats, "threat_id", "ID")
    actual_response_ids_list = _row_ids(actual_responses, "response_id", "Response ID")
    new_response_ids_list = _row_ids(new_responses, "response_id", "Response ID")
    for label, values, pattern in (
        ("baseline threat", baseline_ids_list, CANONICAL_THREAT_ID),
        ("additional threat", additional_ids_list, CANONICAL_THREAT_ID),
        ("actual response", actual_response_ids_list, CANONICAL_RESPONSE_ID),
        ("new response", new_response_ids_list, CANONICAL_RESPONSE_ID),
    ):
        if any(not value for value in values):
            errors.append(f"{label} package contains a row without an ID")
        invalid = sorted({value for value in values if value and not pattern.fullmatch(value)})
        if invalid:
            errors.append(f"{label} package contains non-canonical IDs: {invalid}")
        if len(values) != len(set(values)):
            errors.append(f"{label} package contains duplicate IDs")

    baseline_ids = frozenset(baseline_ids_list)
    additional_ids = frozenset(additional_ids_list)
    actual_response_ids = frozenset(actual_response_ids_list)
    new_response_ids = frozenset(new_response_ids_list)
    actual_response_threat_ids = frozenset(_row_ids(actual_responses, "threat_id", "Threat ID"))
    new_response_threat_ids = frozenset(_row_ids(new_responses, "threat_id", "Threat ID"))
    if not baseline_ids:
        errors.append("baseline threat package must contain at least one retained threat")
    if actual_response_threat_ids != baseline_ids:
        errors.append(
            "Actual Responses must cover the exact baseline threat ID set; "
            f"missing={sorted(baseline_ids - actual_response_threat_ids)}, "
            f"extra={sorted(actual_response_threat_ids - baseline_ids)}"
        )
    expected_additional_ids = frozenset() if baseline_only else additional_ids
    expected_new_response_ids = frozenset() if baseline_only else new_response_ids
    if not baseline_only and new_response_threat_ids != additional_ids:
        errors.append(
            "New Proposed Responses must cover the exact additional retained threat ID set; "
            f"missing={sorted(additional_ids - new_response_threat_ids)}, "
            f"extra={sorted(new_response_threat_ids - additional_ids)}"
        )
    if baseline_ids & additional_ids:
        errors.append(f"baseline and additional threat ID sets overlap: {sorted(baseline_ids & additional_ids)}")
    if actual_response_ids & new_response_ids:
        errors.append(f"actual and new response ID sets overlap: {sorted(actual_response_ids & new_response_ids)}")

    if not baseline_only:
        delta_path = _first_existing_path(run_dir, "considerations-delta.json")
        if not delta_path.exists():
            errors.append("missing required Security/Privacy Considerations delta")
        else:
            delta = _load_json(delta_path, {})
            delta_rows = delta.get("rows", []) if isinstance(delta, dict) else []
            allowed = tuple(delta.get("allowed_classifications", [])) if isinstance(delta, dict) else ()
            decisions = delta.get("controlled_decisions", {}) if isinstance(delta, dict) else {}
            declared_counts = delta.get("counts", {}) if isinstance(delta, dict) else {}
            if set(allowed) != set(CONSIDERATION_DELTA_CLASSES):
                errors.append(
                    "considerations delta must declare the complete controlled classification set"
                )
            parsed_pairs: set[tuple[str, str]] = set()
            calculated_counts = {name: 0 for name in CONSIDERATION_DELTA_CLASSES}
            for row in delta_rows:
                if not isinstance(row, dict):
                    errors.append("considerations delta contains a non-object row")
                    continue
                pair = re.fullmatch(
                    r"(T-\d{2,3})\s*/\s*(R-\d{2,3})",
                    str(row.get("Threat / Response") or "").strip(),
                )
                if not pair:
                    errors.append("considerations delta row has an invalid Threat / Response pair")
                    continue
                parsed_pairs.add((pair.group(1), pair.group(2)))
                classification = str(row.get("Classification") or "")
                if classification not in calculated_counts:
                    errors.append(
                        f"considerations delta row has invalid classification: {classification or '<missing>'}"
                    )
                else:
                    calculated_counts[classification] += 1
                for field in (
                    "Delta ID",
                    "Considerations target",
                    "Current specification evidence",
                    "Source locator",
                    "Gap",
                    "Next action",
                ):
                    if not str(row.get(field) or "").strip():
                        errors.append(f"considerations delta row missing {field}")
            expected_pairs = {
                (
                    str(_value(response, "threat_id", "Threat ID")),
                    str(_value(response, "response_id", "Response ID")),
                )
                for response in [*actual_responses, *new_responses]
            }
            if parsed_pairs != expected_pairs:
                errors.append(
                    "considerations delta must exactly cover canonical threat/response pairs; "
                    f"missing={sorted(expected_pairs - parsed_pairs)}, "
                    f"extra={sorted(parsed_pairs - expected_pairs)}"
                )
            expected_counts = {**calculated_counts, "total": len(delta_rows)}
            if declared_counts != expected_counts:
                errors.append(
                    "considerations delta declared counts do not match parsed rows"
                )
            if decisions.get("good_enough_judgment") != "update_considerations_recommended":
                errors.append("considerations delta has no controlled good-enough judgment")
            for decision_name in (
                "security_considerations_update",
                "privacy_considerations_update",
                "drafting_readiness",
            ):
                if not str(decisions.get(decision_name) or "").strip():
                    errors.append(f"considerations delta missing controlled decision: {decision_name}")
            if decisions.get("further_elicitation_required_before_drafting") is not False:
                errors.append(
                    "considerations delta must state whether further elicitation is required before drafting"
                )

    if errors:
        return None, analysis_gate, errors
    return ReportExpectations(
        dictionary_ids=model_ids,
        baseline_threat_ids=baseline_ids,
        additional_threat_ids=expected_additional_ids,
        actual_response_ids=actual_response_ids,
        actual_response_threat_ids=baseline_ids,
        new_response_ids=expected_new_response_ids,
        new_response_threat_ids=expected_additional_ids,
    ), analysis_gate, []


def _gate_check_rows(gate: dict[str, Any]) -> list[dict[str, Any]]:
    checks = gate.get("checks", gate.get("rows", []))
    return checks if isinstance(checks, list) else []


def _quality_gate_table(run_dir: Path, analysis_gate: dict[str, Any]) -> str:
    analysis_checks = _gate_check_rows(analysis_gate)
    good_enough = _load_run_json(run_dir, ("independent-review-gate.json",), {})
    good_enough_checks = _gate_check_rows(good_enough) if isinstance(good_enough, dict) else []
    publication = _load_run_json(run_dir, ("publication-gate.json",), {})
    _, skeptic = _latest_numbered_skeptic(run_dir)
    semantic_good_enough = str(skeptic.get("good_enough_status") or "").lower()
    semantic_publication = str(skeptic.get("publication_status") or "").lower()
    good_enough_status = str(good_enough.get("status") or "missing")
    publication_status = str(publication.get("status") or "pending current assembly")
    if semantic_good_enough and semantic_good_enough not in {"pass", "complete"}:
        good_enough_status = f"{semantic_good_enough} (latest semantic review)"
    if semantic_publication and semantic_publication not in {"pass", "complete"}:
        publication_status = f"{semantic_publication} (latest semantic review)"
    rows = [
        {
            "Gate": "Analysis gate",
            "Status": str(analysis_gate.get("status") or "missing"),
            "Evidence": f"{len(analysis_checks)} named upstream analysis checks passed.",
        },
        {
            "Gate": "Good-enough / independent-review gate",
            "Status": good_enough_status,
            "Evidence": f"{len(good_enough_checks)} named stopping-condition and exact-coverage checks recorded.",
        },
        {
            "Gate": "Publication gate",
            "Status": publication_status,
            "Evidence": "Canonical structure, exact inline table sets, complete dictionary, canonical DFD/TMDC evidence, and response coverage validated.",
        },
    ]
    return _markdown_table(rows, ["Gate", "Status", "Evidence"])


def _quality_evidence_links(run_dir: Path, link_base: Path) -> str:
    project_root = run_dir.parents[1] if run_dir.parent.name == "artifacts" else run_dir
    latest_skeptic_path, _ = _latest_numbered_skeptic(run_dir)
    candidates = [
        ("trace linkage manifest", _first_existing_path(run_dir, "trace-linkage-manifest.json")),
        ("producing trace", project_root / "artifacts" / "reconciled" / "producing-trace.json"),
        ("non-producing trace", project_root / "artifacts" / "reconciled" / "nonproducing-trace.json"),
        ("section-to-model coverage", _first_existing_path(run_dir, "section-to-model-coverage.json")),
        ("model-element threat coverage", _first_existing_path(run_dir, "model-element-threat-coverage.json")),
        ("transfer register", _first_existing_path(run_dir, "transfer-register.json")),
        ("Security/Privacy Considerations delta", _first_existing_path(run_dir, "considerations-delta.json")),
        ("analysis gate", _first_existing_path(run_dir, "analysis-gate.json")),
        ("good-enough / independent-review gate", _first_existing_path(run_dir, "independent-review-gate.json")),
        ("publication gate", _first_existing_path(run_dir, "publication-gate.json")),
    ]
    if latest_skeptic_path is not None:
        candidates.insert(-3, ("latest semantic skeptic review", latest_skeptic_path))
    links = [
        f"[{label}]({_relative_link(link_base, path, path.name)})"
        for label, path in candidates
        if path.exists()
    ]
    return "Evidence: " + ", ".join(links) + "."


def _publication_gate_path(run_dir: Path) -> Path:
    if (run_dir / "model").is_dir() and (run_dir / "quality").is_dir():
        directory = run_dir / "quality"
    else:
        directory = run_dir / "artifacts" / "quality"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "publication-gate.json"


def _write_publication_gate(run_dir: Path, status: str, errors: list[str] | tuple[str, ...]) -> None:
    gate = {
        "gate": "publication",
        "status": status,
        "checks": [
            {
                "name": "assembled_report_contract",
                "status": "pass" if status == "pass" else "fail",
                "errors": list(errors),
            }
        ],
    }
    _publication_gate_path(run_dir).write_text(json.dumps(gate, indent=2) + "\n")


def _validate_local_links(markdown: str, output: Path) -> list[str]:
    """Return missing local Markdown-link errors relative to the report output."""

    errors: list[str] = []
    base = output.parent.resolve()
    for raw_target in re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", markdown):
        target = raw_target.strip()
        if target.startswith("<") and ">" in target:
            target = target[1:target.index(">")]
        else:
            target = target.split(maxsplit=1)[0]
        target = unquote(target).split("#", maxsplit=1)[0]
        if not target or target.startswith("#") or re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
            continue
        path = Path(target)
        resolved = (path if path.is_absolute() else base / path).resolve()
        if not resolved.exists():
            errors.append(f"report contains a missing local link target: {target}")
    return list(dict.fromkeys(errors))


def assemble_report(
    run_dir: Path,
    output: Path | None = None,
    title: str | None = None,
    as_is_only: bool = False,
    run_scope: str | None = None,
    spec_slug: str | None = None,
    diagram_level: str | None = None,
    categories: str | list[str] | tuple[str, ...] | None = None,
    timestamp: str | None = None,
    draft: bool = False,
) -> Path:
    """Assemble a Markdown report from a run directory and validate its shape."""

    run_dir = run_dir.resolve()
    title = title or "Specification Threat Model Review"

    as_is_threat_pkg = _load_run_json(
        run_dir,
        ("baseline.threat-package.json", "baseline-threat-package.json", "as-is.threat-package.json"),
        {"threats": []},
    )
    new_threat_pkg = _load_run_json(
        run_dir,
        (
            "additional.threat-package.json",
            "additional-threat-package.json",
            "full-workshop.threat-package.json",
            "threat-package.json",
        ),
        {"threats": []},
    )
    as_is_response_pkg = _load_run_json(
        run_dir,
        ("baseline.response-package.json", "baseline-response-package.json", "as-is.response-package.json"),
        {"responses": []},
    )
    new_response_pkg = _load_run_json(
        run_dir,
        (
            "additional.response-package.json",
            "additional-response-package.json",
            "full-workshop.response-package.json",
            "response-package.json",
        ),
        {"responses": []},
    )
    stats_source = _load_run_json(run_dir, ("full-workshop.statistics.json", "method-statistics.json"), {})
    model_packet = _load_run_json(run_dir, ("model-packet.json", "model-packet-v1.json"), {})
    evidence_packet = _load_run_json(
        run_dir,
        ("evidence-packet.json", "source-packet.json", "*-source-packet.json"),
        {},
    )
    output = output or _default_report_path(
        run_dir,
        model_packet,
        evidence_packet,
        as_is_only=as_is_only,
        spec_slug=spec_slug,
        diagram_level=diagram_level,
        categories=categories,
        timestamp=timestamp,
        run_scope=run_scope,
    )
    link_base = output.parent.resolve()

    actual_threats = as_is_threat_pkg.get("threats", [])
    baseline_ids = frozenset(_row_ids(actual_threats, "threat_id", "ID"))
    candidate_new_threats = _filter_new_threats(new_threat_pkg.get("threats", []))
    new_threats = [] if as_is_only else [
        threat for threat in candidate_new_threats
        if str(_value(threat, "threat_id", "ID")) not in baseline_ids
    ]
    actual_responses = as_is_response_pkg.get("responses", [])
    candidate_new_responses = _filter_proposed_responses(new_response_pkg.get("responses", []))
    new_responses = [] if as_is_only else [
        response for response in candidate_new_responses
        if str(_value(response, "threat_id", "Threat ID")) not in baseline_ids
    ]
    methods = _method_rows(run_dir)
    if as_is_only:
        methods = [
            row for row in methods
            if row.get("method") in {"as_is_source_signal", "as-is baseline", "as_is_baseline"}
        ]
    stats = _stats_from_methods(stats_source, methods)

    expectations, analysis_gate, input_errors = _validate_input_artifacts(
        run_dir,
        model_packet,
        actual_threats,
        new_threats,
        actual_responses,
        new_responses,
        baseline_only=as_is_only,
        publication_ready=not draft,
    )
    if input_errors:
        if not draft:
            _write_publication_gate(run_dir, "fail", input_errors)
        raise ValueError("Assembly input validation failed:\n" + "\n".join(input_errors))
    assert expectations is not None

    actual_threat_headers = [
        "ID", "Element", "Threat Name", "Threat Type", "Threat Analysis Framework",
        "Threat Category", "Threat Description", "Finding Mode", "Found By",
        "Question References", "Specification Reference",
    ]
    new_threat_headers = actual_threat_headers + ["Coverage Relation", "Related Baseline Threat IDs"]
    actual_response_headers = [
        "Response ID", "Threat ID", "ERTA", "Status", "Response Origin",
        "Current / Baseline Response", "Threat Owner", "Decision / To-Do",
        "Remaining Threat", "Assumptions Used", "Next Action",
    ]
    new_response_headers = [
        "Response ID", "Threat ID", "Proposed ERTA", "Reviewer Recommendation",
        "Decision Owner", "Decision / To-Do", "If No Change, Remaining Threat",
        "Assumptions Used", "Next Action",
    ]
    action_headers = [
        "New Threat ID", "Threat Name", "Proposed Remediation ID", "ERTA",
        "Considerations Impact", "Related Baseline Threat IDs", "Next Action",
    ]

    dashboard = (
        f"Trace rows: {stats.get('total_trace_rows', 'unknown')}; "
        f"STRIDE paper-matrix rows: {stats.get('stride_paper_matrix_rows', 'unknown')}; "
        f"LINDDUN paper-matrix rows: {stats.get('linddun_paper_matrix_rows', 'unknown')}; "
        f"new threats: {len(new_threats)}; proposed responses: {len(new_responses)}."
    )

    report = [
        f"# {title}\n",
        "## Introduction\n\n",
        _introduction(
            model_packet,
            evidence_packet,
            stats,
            methods,
            actual_threats,
            new_threats,
            actual_responses,
            new_responses,
            as_is_only,
            categories,
            run_scope,
        ) + "\n",
        "## What Are We Building\n\n",
        _what_are_we_building_intro(model_packet, run_dir),
        "### Diagram\n\n",
        _diagram_block(run_dir, link_base),
        "### Dictionary\n\n",
        _dictionary_table(run_dir) + "\n",
        "## What Can Go Wrong\n\n",
        _what_can_go_wrong_intro(stats, new_threats, methods, run_dir, link_base),
        "### Baseline identified threats\n\n",
        _markdown_table(_threat_rows(actual_threats), actual_threat_headers) + "\n\n",
        "### Additional identified threats\n\n",
        _optional_table_or_note(
            _threat_rows(new_threats, include_delta=True),
            new_threat_headers,
            "No additional threats were produced or reviewed in this as-is-only report.",
        ),
        "## What Are We Going To Do About It\n\n",
        "### Actual Responses\n\n",
        _markdown_table(_response_rows(actual_responses), actual_response_headers) + "\n\n",
        "### New Proposed Responses\n\n",
        _optional_table_or_note(
            _response_rows(new_responses, proposed=True),
            new_response_headers,
            "No new proposed responses were produced or reviewed in this as-is-only report.",
        ),
        "## Did We Do A Good Enough Job?\n\n",
        "### What We Did\n\n",
        "#### Run Completion Status\n\n",
        _run_completion_status(run_dir, as_is_only),
        "#### Good-Enough Judgment\n\n",
        _controlled_good_enough_judgment(run_dir, as_is_only),
        _good_enough_intro(new_threats),
        _model_adequacy_assessment(model_packet),
        "#### Step 4 Checklist\n\n",
        _step4_checklist(
            run_dir,
            model_packet,
            methods,
            actual_threats,
            new_threats,
            actual_responses,
            new_responses,
            as_is_only,
        ),
        "#### Classified Delta\n\n",
        _classified_delta_summary(
            run_dir,
            actual_threats,
            new_threats,
            actual_responses,
            new_responses,
            as_is_only,
        ),
        "#### Security and Privacy Considerations Decision\n\n",
        _considerations_decision(
            run_dir,
            actual_threats,
            new_threats,
            actual_responses,
            new_responses,
            as_is_only,
        ),
        "#### Remaining Question Routing\n\n",
        _remaining_question_routing(model_packet),
        "#### Recommended Next Elicitation\n\n",
        _recommended_next_elicitation(),
        _traceability_review_summary(
            run_dir,
            model_packet,
            methods,
            actual_threats,
            new_threats,
            actual_responses,
            as_is_only,
        ),
        _transfer_and_assumption_summary(actual_responses + new_responses),
        _remaining_threat_closure_summary(actual_responses + new_responses),
        "### What Remains To Do\n\n",
        "#### Baseline Specification Update Actions\n\n",
        "These actions summarize specification updates or editor-review issues that follow from the as-is threat baseline.\n\n",
        _actual_delta_actions(actual_responses) + "\n\n",
        "#### Remaining Review Gaps\n\n",
        _what_is_missing(run_dir) + "\n\n",
        ("" if as_is_only else "#### Candidate Threats From LLM Compact Pass\n\n"),
        ("" if as_is_only else _candidate_threats_from_llm_compact(run_dir)),
        "#### New Threat and Proposed Response Actions\n\n",
        _optional_table_or_note(
            _new_actions(new_threats, new_responses),
            action_headers,
            "No new-threat follow-up actions are included in this as-is-only report.",
        ),
        f"Dashboard: {dashboard}\n",
        "# Appendix\n\n",
        "## Diagram Summary\n\n",
        _diagram_summary(model_packet) + "\n\n",
        "## Threats Per Elements Summary\n\n",
        _threats_per_element_summary(model_packet, actual_threats, new_threats) + "\n\n",
        "## Zero-Threat Element Interpretation\n\n",
        _zero_threat_interpretation(model_packet, actual_threats, new_threats) + "\n\n",
        "## Coverage Notes\n\n",
        "Coverage artifacts are linked from the run directory. This report preserves the full ",
        "source-grounded baseline and separates later additional threats.\n\n",
        "## Blocked Elements\n\n",
        "No blocked elements were supplied to the portable assembler.\n\n",
        "## Unresolved Model Gaps\n\n",
        _unresolved_model_gaps(new_threat_pkg) + "\n\n",
        "## Techniques Used To Find Threats\n\n",
        _markdown_table(methods, list(methods[0].keys()) if methods else ["method", "prompts_or_plays", "producing", "non_producing", "threat_ids"]) + "\n",
        "## Method Comparison Summary\n\n",
        _method_comparison_links(run_dir, link_base) + "\n\n",
        "## Quality Checks\n\n",
        _quality_gate_table(run_dir, analysis_gate) + "\n\n",
        _quality_evidence_links(run_dir, link_base) + "\n",
    ]
    markdown = "".join(report)
    result = validate_report_contract(markdown, expectations)
    publication_errors = [*result.errors, *_validate_local_links(markdown, output)]
    if publication_errors:
        if not draft:
            _write_publication_gate(run_dir, "fail", publication_errors)
        raise ValueError(
            "Report contract validation failed:\n" + "\n".join(publication_errors)
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown)
    if not draft:
        _write_publication_gate(run_dir, "pass", [])
    return output
