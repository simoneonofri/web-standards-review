"""Report-shape contract for portable spec-review threat-model reports."""

from __future__ import annotations

from dataclasses import dataclass
import re


REQUIRED_HEADINGS: tuple[str, ...] = (
    "# ",
    "## Introduction",
    "## What Are We Building",
    "### Diagram",
    "### Dictionary",
    "## What Can Go Wrong",
    "### Baseline identified threats",
    "### Additional identified threats",
    "## What Are We Going To Do About It",
    "### Actual Responses",
    "### New Proposed Responses",
    "## Did We Do A Good Enough Job?",
    "### What We Did",
    "#### Run Completion Status",
    "#### Good-Enough Judgment",
    "#### Step 4 Checklist",
    "#### Classified Delta",
    "#### Security and Privacy Considerations Decision",
    "#### Remaining Question Routing",
    "#### Recommended Next Elicitation",
    "#### Traceability Review Summary",
    "#### Transfer and Assumption Summary",
    "#### Remaining Threat Closure Summary",
    "### What Remains To Do",
    "#### Baseline Specification Update Actions",
    "#### Remaining Review Gaps",
    "#### New Threat and Proposed Response Actions",
    "# Appendix",
    "## Diagram Summary",
    "## Threats Per Elements Summary",
    "## Zero-Threat Element Interpretation",
    "## Coverage Notes",
    "## Blocked Elements",
    "## Unresolved Model Gaps",
    "## Techniques Used To Find Threats",
    "## Method Comparison Summary",
    "## Quality Checks",
)

FORBIDDEN_SNIPPETS: tuple[str, ...] = (
    "This report assembles the portable spec-review threat-model artifacts.",
    "\n### As-Is",
    "\n### As-is identified threats",
    "\n### New\n",
    "\n## Diagram\n",
    "\n## Dictionary\n",
    "\n## Techniques Used To Find Threats\n\n##",
    "\n### Actual Threats",
    "\n### New Threats",
    "| both |",
    "; both",
    "Owner / Receiver",
    "\n### New Responses\n",
    "Shostack skeptic pass not supplied for this run",
    "NR-",
    "R-NEW",
)

GOOD_ENOUGH_REQUIRED_SNIPPETS: tuple[str, ...] = (
    "### What We Did",
    "### What Remains To Do",
    "#### Remaining Review Gaps",
    "Controlled judgment:",
    "Coverage classification",
    "What The Specification Says",
    "security_considerations_update=",
    "privacy_considerations_update=",
)

INTRODUCTION_REQUIRED_SNIPPETS: tuple[str, ...] = (
    "Review categories and lenses:",
    "Model level for What Are We Building:",
)

INTRODUCTION_RUN_TYPE_SNIPPETS: tuple[str, ...] = (
    "source-grounded baseline plus additional spec-review run",
    "source-grounded baseline reverse-engineering run",
)

WHAT_ARE_WE_BUILDING_REQUIRED_SNIPPETS: tuple[str, ...] = (
    "Model coverage:",
    "assumptions-and-follow-up.md",
)

WHAT_ARE_WE_BUILDING_FORBIDDEN_SNIPPETS: tuple[str, ...] = (
    "System under analysis:",
    "Scenario:",
    "DFD detail level:",
    "Abstraction level:",
)

RESPONSE_REQUIRED_SNIPPETS: tuple[str, ...] = (
    "Threat Owner",
    "Decision / To-Do",
    "If No Change, Remaining Threat",
    "Current / Baseline Response",
    "Assumptions Used",
)

DIAGRAM_SUMMARY_REQUIRED_SNIPPETS: tuple[str, ...] = (
    "Total DFD elements",
)

THREATS_PER_ELEMENT_REQUIRED_SNIPPETS: tuple[str, ...] = (
    "Total Threats",
)

QUALITY_CHECKS_REQUIRED_SNIPPETS: tuple[str, ...] = (
    "Analysis gate",
    "Good-enough / independent-review gate",
    "Publication gate",
)

CANONICAL_DFD_ID = re.compile(r"^(EE|PO|DF|DS|TB)-[0-9]{2,}$")
BAD_DFD_ID = re.compile(r"^(EE|PO|DF|DS|TB)[0-9]{2}($|_)")
BAD_THREAT_ID = re.compile(r"(^|[\s|`])T-00($|[\s|`])")
CANONICAL_THREAT_ID = re.compile(r"^T-[0-9]{2,3}$")
CANONICAL_RESPONSE_ID = re.compile(r"^R-[0-9]{2,3}$")

DICTIONARY_REQUIRED_HEADERS: tuple[str, ...] = (
    "ID",
    "Mermaid node ID",
    "Type",
    "Visible label",
    "Name",
    "Description",
    "Source ID",
    "Assurance Level",
    "Specification Reference",
    "Source Locator",
    "Coverage Status",
    "Evidence Status",
    "Assumptions",
    "Boundary Membership",
    "Flow Source",
    "Flow Destination",
)
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


@dataclass(frozen=True)
class ContractResult:
    ok: bool
    errors: tuple[str, ...]


@dataclass(frozen=True)
class ReportExpectations:
    """Exact row sets expected from the authoritative run packages."""

    dictionary_ids: frozenset[str]
    baseline_threat_ids: frozenset[str]
    additional_threat_ids: frozenset[str]
    actual_response_ids: frozenset[str]
    actual_response_threat_ids: frozenset[str]
    new_response_ids: frozenset[str]
    new_response_threat_ids: frozenset[str]


def validate_report_contract(
    markdown: str,
    expectations: ReportExpectations | None = None,
) -> ContractResult:
    """Validate the canonical assembled report structure."""

    errors: list[str] = []
    for heading in REQUIRED_HEADINGS:
        if heading == "# ":
            if not markdown.startswith("# "):
                errors.append("report must start with a top-level title")
            continue
        if f"\n{heading}" not in markdown and not markdown.startswith(heading):
            errors.append(f"missing heading: {heading}")

    appendix_pos = markdown.find("\n# Appendix")
    techniques_pos = markdown.find("\n## Techniques Used To Find Threats")
    if appendix_pos == -1:
        errors.append("missing top-level # Appendix")
    elif techniques_pos == -1:
        errors.append("missing Techniques Used To Find Threats in Appendix")
    elif techniques_pos < appendix_pos:
        errors.append("Techniques Used To Find Threats must be inside # Appendix")

    wawb_pos = markdown.find("\n## What Are We Building")
    diagram_pos = markdown.find("\n### Diagram")
    dictionary_pos = markdown.find("\n### Dictionary")
    wcgw_pos = markdown.find("\n## What Can Go Wrong")
    if -1 not in (wawb_pos, diagram_pos, dictionary_pos, wcgw_pos):
        if not (wawb_pos < diagram_pos < dictionary_pos < wcgw_pos):
            errors.append("Diagram and Dictionary must be inside What Are We Building")

    intro_text = _section_text(markdown, "## Introduction", "## What Are We Building")
    if not any(snippet in intro_text for snippet in INTRODUCTION_RUN_TYPE_SNIPPETS):
        errors.append(
            "Introduction missing required run type: source-grounded baseline plus additional spec-review run "
            "or source-grounded baseline reverse-engineering run"
        )
    for snippet in INTRODUCTION_REQUIRED_SNIPPETS:
        if snippet not in intro_text:
            errors.append(f"Introduction missing required content: {snippet}")

    wawb_text = _section_text(markdown, "## What Are We Building", "## What Can Go Wrong")
    for snippet in WHAT_ARE_WE_BUILDING_REQUIRED_SNIPPETS:
        if snippet not in wawb_text:
            errors.append(f"What Are We Building missing required content: {snippet}")
    for snippet in WHAT_ARE_WE_BUILDING_FORBIDDEN_SNIPPETS:
        if snippet in wawb_text:
            errors.append(f"What Are We Building contains removed content: {snippet}")

    errors.extend(_validate_dictionary_ids(wawb_text))

    response_text = _section_text(markdown, "## What Are We Going To Do About It", "## Did We Do A Good Enough Job?")
    for snippet in RESPONSE_REQUIRED_SNIPPETS:
        if snippet not in response_text:
            errors.append(f"What Are We Going To Do About It missing required content: {snippet}")
    errors.extend(_validate_residual_threat_cells(response_text))

    good_enough_text = _section_text(markdown, "## Did We Do A Good Enough Job?", "# Appendix")
    for snippet in GOOD_ENOUGH_REQUIRED_SNIPPETS:
        if snippet not in good_enough_text:
            errors.append(f"Did We Do A Good Enough Job missing required content: {snippet}")

    diagram_summary_text = _section_text(markdown, "## Diagram Summary", "## Threats Per Elements Summary")
    for snippet in DIAGRAM_SUMMARY_REQUIRED_SNIPPETS:
        if snippet not in diagram_summary_text:
            errors.append(f"Diagram Summary missing required content: {snippet}")

    threats_per_element_text = _section_text(markdown, "## Threats Per Elements Summary", "## Coverage Notes")
    for snippet in THREATS_PER_ELEMENT_REQUIRED_SNIPPETS:
        if snippet not in threats_per_element_text:
            errors.append(f"Threats Per Elements Summary missing required content: {snippet}")

    quality_checks_text = _section_text(markdown, "## Quality Checks", "")
    for snippet in QUALITY_CHECKS_REQUIRED_SNIPPETS:
        if snippet not in quality_checks_text:
            errors.append(f"Quality Checks missing required named gate: {snippet}")

    for snippet in FORBIDDEN_SNIPPETS:
        if snippet in markdown:
            errors.append(f"forbidden snippet present: {snippet.strip()}")
    if BAD_THREAT_ID.search(markdown):
        errors.append("forbidden threat ID present: T-00")

    errors.extend(_validate_required_inline_tables(markdown, expectations))

    return ContractResult(ok=not errors, errors=tuple(errors))


def _split_markdown_row(line: str) -> list[str]:
    """Split a simple Markdown table row without breaking escaped pipes."""

    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|"):
        text = text[:-1]
    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for character in text:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
            current.append(character)
        elif character == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    cells.append("".join(current).strip())
    return cells


def _table_after_heading(markdown: str, heading: str) -> tuple[list[str], list[dict[str, str]]]:
    pattern = re.compile(rf"(?m)^{re.escape(heading)}\s*$")
    match = pattern.search(markdown)
    if not match:
        return [], []
    remainder = markdown[match.end():]
    next_heading = re.search(r"(?m)^#{1,4}\s+", remainder)
    section = remainder[:next_heading.start()] if next_heading else remainder
    lines = section.splitlines()
    for index, line in enumerate(lines):
        if not line.lstrip().startswith("|"):
            continue
        table_lines: list[str] = []
        for candidate in lines[index:]:
            if not candidate.lstrip().startswith("|"):
                break
            table_lines.append(candidate.strip())
        if len(table_lines) < 2:
            return [], []
        headers = _split_markdown_row(table_lines[0])
        rows: list[dict[str, str]] = []
        for row_line in table_lines[2:]:
            cells = _split_markdown_row(row_line)
            if len(cells) != len(headers):
                continue
            rows.append(dict(zip(headers, cells)))
        return headers, rows
    return [], []


def _set_from_rows(rows: list[dict[str, str]], column: str) -> frozenset[str]:
    return frozenset(row.get(column, "").strip() for row in rows if row.get(column, "").strip())


def _compare_exact_set(
    errors: list[str],
    label: str,
    actual: frozenset[str],
    expected: frozenset[str],
) -> None:
    if actual == expected:
        return
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    errors.append(f"{label} ID set mismatch; missing={missing}, extra={extra}")


def _validate_required_inline_tables(
    markdown: str,
    expectations: ReportExpectations | None,
) -> list[str]:
    errors: list[str] = []
    table_specs = (
        ("### Dictionary", "ID"),
        ("### Baseline identified threats", "ID"),
        ("### Additional identified threats", "ID"),
        ("### Actual Responses", "Response ID"),
        ("### New Proposed Responses", "Response ID"),
    )
    tables: dict[str, tuple[list[str], list[dict[str, str]]]] = {}
    for heading, identity_column in table_specs:
        headers, rows = _table_after_heading(markdown, heading)
        tables[heading] = (headers, rows)
        if not headers:
            errors.append(f"{heading} must contain an inline Markdown table")
            continue
        if identity_column not in headers:
            errors.append(f"{heading} table missing identity column: {identity_column}")

    dictionary_headers, dictionary_rows = tables["### Dictionary"]
    if dictionary_headers:
        missing_headers = [header for header in DICTIONARY_REQUIRED_HEADERS if header not in dictionary_headers]
        if missing_headers:
            errors.append(f"Dictionary table missing required columns: {missing_headers}")
        if not dictionary_rows:
            errors.append("Dictionary table must include every DFD element, not only headings")

    baseline_rows = tables["### Baseline identified threats"][1]
    actual_response_rows = tables["### Actual Responses"][1]
    if not baseline_rows:
        errors.append("Baseline identified threats must include concrete inline rows")
    if not actual_response_rows:
        errors.append("Actual Responses must include concrete inline rows")

    for heading in ("### Baseline identified threats", "### Additional identified threats"):
        for threat_id in _set_from_rows(tables[heading][1], "ID"):
            if not CANONICAL_THREAT_ID.fullmatch(threat_id):
                errors.append(f"{heading} contains non-canonical threat ID: {threat_id}")
    for heading in ("### Actual Responses", "### New Proposed Responses"):
        for response_id in _set_from_rows(tables[heading][1], "Response ID"):
            if not CANONICAL_RESPONSE_ID.fullmatch(response_id):
                errors.append(f"{heading} contains non-canonical response ID: {response_id}")

    if expectations is None:
        return errors

    _compare_exact_set(errors, "Dictionary", _set_from_rows(dictionary_rows, "ID"), expectations.dictionary_ids)
    _compare_exact_set(
        errors,
        "Baseline identified threats",
        _set_from_rows(baseline_rows, "ID"),
        expectations.baseline_threat_ids,
    )
    additional_rows = tables["### Additional identified threats"][1]
    _compare_exact_set(
        errors,
        "Additional identified threats",
        _set_from_rows(additional_rows, "ID"),
        expectations.additional_threat_ids,
    )
    _compare_exact_set(
        errors,
        "Actual Responses",
        _set_from_rows(actual_response_rows, "Response ID"),
        expectations.actual_response_ids,
    )
    _compare_exact_set(
        errors,
        "Actual Response threat coverage",
        _set_from_rows(actual_response_rows, "Threat ID"),
        expectations.actual_response_threat_ids,
    )
    new_response_rows = tables["### New Proposed Responses"][1]
    _compare_exact_set(
        errors,
        "New Proposed Responses",
        _set_from_rows(new_response_rows, "Response ID"),
        expectations.new_response_ids,
    )
    _compare_exact_set(
        errors,
        "New Proposed Response threat coverage",
        _set_from_rows(new_response_rows, "Threat ID"),
        expectations.new_response_threat_ids,
    )
    return errors


def _looks_like_question(value: str) -> bool:
    text = value.strip()
    return bool(text) and (text.endswith("?") or text.lower().startswith(QUESTION_PREFIXES))


def _validate_residual_threat_cells(response_text: str) -> list[str]:
    errors: list[str] = []
    rows = [line for line in response_text.splitlines() if line.startswith("|")]
    index = 0
    while index < len(rows):
        headers = _split_markdown_row(rows[index])
        residual_columns = [
            pos for pos, header in enumerate(headers)
            if header in {"Remaining Threat", "If No Change, Remaining Threat"}
        ]
        if residual_columns and index + 1 < len(rows):
            data_index = index + 2
            while data_index < len(rows):
                cells = _split_markdown_row(rows[data_index])
                if len(cells) != len(headers):
                    break
                for column in residual_columns:
                    if column < len(cells) and _looks_like_question(cells[column]):
                        response_id = cells[0] if cells else "unknown"
                        errors.append(
                            f"Residual threat must be declarative, not a question, in response {response_id}"
                        )
                data_index += 1
            index = data_index
        else:
            index += 1
    return errors


def _section_text(markdown: str, start_heading: str, end_heading: str) -> str:
    start = markdown.find(start_heading)
    if start == -1:
        return ""
    if not end_heading:
        return markdown[start:]
    end = markdown.find(end_heading, start + len(start_heading))
    if end == -1:
        return markdown[start:]
    return markdown[start:end]


def _validate_dictionary_ids(wawb_text: str) -> list[str]:
    errors: list[str] = []
    dictionary_start = wawb_text.find("### Dictionary")
    if dictionary_start == -1:
        return errors
    dictionary_text = wawb_text[dictionary_start:]
    rows = [line for line in dictionary_text.splitlines() if line.startswith("|")]
    if len(rows) < 3:
        return errors
    headers = _split_markdown_row(rows[0])
    if not headers or headers[0] != "ID":
        errors.append("Dictionary first column must be ID")
        return errors
    for row in rows[2:]:
        cells = _split_markdown_row(row)
        if not cells:
            continue
        value = cells[0]
        if BAD_DFD_ID.match(value):
            errors.append(f"Dictionary ID must use canonical hyphenated form, not {value}")
        elif value.startswith(("EE", "PO", "DF", "DS", "TB")) and not CANONICAL_DFD_ID.match(value):
            errors.append(f"Dictionary ID is not canonical: {value}")
    return errors
