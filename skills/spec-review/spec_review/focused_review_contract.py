"""Deterministic contract for a focused W3C single-finding reply."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse


ARTIFACT_KIND = "focused_w3c_security_reply_evidence"
REVIEW_MODE = "focused_w3c_reply"
OUTPUT_REGISTER = "single_finding_w3c_issue_comment"
PUBLISH_DECISION = "publish_single_finding"
NO_FINDING_DECISION = "no_new_finding"
ALLOWED_PRIOR_FEEDBACK_RELATIONSHIPS = frozenset(
    {
        "duplicate",
        "refinement",
        "distinct",
        "follow_up_existing",
        "unable_to_verify",
    }
)
ALLOWED_PRIOR_FEEDBACK_DISPOSITIONS = frozenset(
    {
        "retain_distinct",
        "exclude_already_raised",
        "merge",
        "follow_up_existing",
        "unable_to_verify",
    }
)
PRIOR_FEEDBACK_RELATIONSHIP_DISPOSITION = {
    "duplicate": "exclude_already_raised",
    "refinement": "merge",
    "distinct": "retain_distinct",
    "follow_up_existing": "follow_up_existing",
    "unable_to_verify": "unable_to_verify",
}
DISPOSITIONS_REQUIRING_DELTA = frozenset(
    {
        "retain_distinct",
        "merge",
        "follow_up_existing",
    }
)
ALLOWED_REQUESTED_CHANGE_STRENGTHS = frozenset(
    {"informative_documentation", "normative_requirement"}
)

_INLINE_MARKDOWN_RE = re.compile(r"(!?)\[([^\]\n]*)\]\(([^)\n]*)\)")
_REFERENCE_USAGE_RE = re.compile(r"!?\[[^\]\n]*\]\[[^\]\n]*\]")
_REFERENCE_DEFINITION_RE = re.compile(
    r"^\s{0,3}\[[^\]\n]+\]:\s*(?:<([^>\n]+)>|(\S+))",
    re.MULTILINE,
)
_SCHEME_AUTOLINK_RE = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]*:[^<>\s]+)>")
_BARE_URL_RE = re.compile(r"https?://[^\s)>]+")
_WORD_RE = re.compile(r"[A-Za-zÀ-ÖØ-öø-ÿ0-9]+(?:[’'][A-Za-zÀ-ÖØ-öø-ÿ0-9]+)*")
_HEADING_RE = re.compile(
    r"(?:^\s{0,3}#{1,6}\s+|^[^\n]+\n\s*(?:=+|-+)\s*$|<h[1-6]\b)",
    re.IGNORECASE | re.MULTILINE,
)
_TABLE_ROW_RE = re.compile(
    r"(?:^\s*\|.*\|\s*$|<(?:table|tr|td|th)\b)",
    re.IGNORECASE | re.MULTILINE,
)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HTML_COMMENT_TOKEN_RE = re.compile(r"<!--|-->")
_RAW_HTML_TAG_RE = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*(?:\s[^>]*)?\s*/?>")
_FENCED_CODE_RE = re.compile(r"^\s{0,3}(?:```|~~~)", re.MULTILINE)
_INDENTED_CODE_RE = re.compile(r"^(?: {4,}|\t+)\S", re.MULTILINE)
_BLOCKQUOTE_RE = re.compile(r"^\s{0,3}>", re.MULTILINE)
_CODE_SPAN_RE = re.compile(r"(`+)([^`\n]+)\1")
_FULL_REVIEW_SCAFFOLD_RE = re.compile(
    r"(?:^|[\n.!?;])\s*(?:Dear\s+Group\b|(?:Concern|Impact|Recommendation|Affected\s+Sections?|Evidence|References?)\s*:)",
    re.IGNORECASE,
)
_PROCESS_NARRATION_RE = re.compile(
    r"\b(?:I\s+(?:searched|reviewed|checked|examined|compared|audited|deduplicat(?:e|ed|ing))(?:\s+and\s+deduplicat(?:e|ed|ing))?\s+(?:the\s+|all\s+|every\s+)?(?:prior\s+)?(?:tracker|repository|issues?|comments?|sources?|candidates?)|evidence\s+packet|search(?:ed|ing)?\s+the\s+(?:tracker|repository|issues?))\b",
    re.IGNORECASE,
)
_PRIVATE_LOCAL_REFERENCE_RE = re.compile(
    r"(?:\bfile:/+|(?:^|\s)(?:~/|\.\.?/|/(?:private|tmp|Users|var|home|etc)/|[A-Za-z]:\\)\S+)",
    re.IGNORECASE,
)
_FIRST_PERSON_SINGULAR_RE = re.compile(r"\b(?:I|me|my|mine|Me|My|Mine)\b")
_FIRST_PERSON_PLURAL_RE = re.compile(r"\b(?:we|us|our|ours|We|Us|Our|Ours)\b")
_ACTION_VERB_RE = re.compile(
    r"\b(?:add|address|avoid|clarify|cover|delete|describe|document|ensure|explain|fix|identify|include|link|mandate|mention|move|note|recommend|record|remove|replace|require|revise|specify|state|update)\b",
    re.IGNORECASE,
)
_QUESTION_START_RE = re.compile(
    r"^(?:can|could|how|is\s+it\s+possible|it\s+is\s+possible|may|should|when|where|will|would|would\s+it\s+be\s+possible)\b",
    re.IGNORECASE,
)
_REQUEST_START_RE = re.compile(
    r"^(?:please\b|I\s+(?:ask|recommend|request|suggest)\b)",
    re.IGNORECASE,
)
_IMPERATIVE_START_RE = re.compile(
    r"^(?:add|address|avoid|clarify|cover|delete|describe|document|ensure|explain|fix|identify|include|link|mandate|mention|move|note|recommend|record|remove|replace|require|revise|specify|state|update)\b",
    re.IGNORECASE,
)
_NORMATIVE_REQUEST_RE = re.compile(
    r"\b(?:mandate|mandates|mandated|must|require|requires|required|shall)\b",
    re.IGNORECASE,
)
_GROUP_VOICE_RE = re.compile(
    r"\b(?:on\s+behalf\s+of|(?:(?:writing|speaking|posting)\s+for|representing)\s+(?:the\s+)?[^,.;]{0,80}\b(?:group|committee|team|PING|TAG|APA|W3C|reviewers?)\b|(?:as\s+(?:the\s+)?[^,.;]{0,80}\b(?:group|committee|team|PING|TAG|APA)\b[^,.;]{0,30}|I\s+(?:am|'m)\s+(?:the\s+)?[^,.;]{0,80}\b(?:group|committee|team|PING|TAG|APA)\b[^,.;]{0,30})\breviewer|(?:group|committee|team|reviewers?|colleagues|PING|TAG|APA)\s+and\s+I\s+(?:finds?|found|identif(?:y|ies|ied)|recommend(?:s|ed)?))\b",
    re.IGNORECASE,
)
_GENERIC_MARKER_WORDS = {
    "behavior",
    "change",
    "considerations",
    "document",
    "finding",
    "issue",
    "limitation",
    "mechanism",
    "only",
    "prerequisite",
    "request",
    "review",
    "security",
    "that",
    "these",
    "this",
    "those",
    "what",
    "when",
    "where",
    "which",
    "with",
}
_CONSENSUS_RE = re.compile(
    r"\b(?:accepted|resolved|consensus|(?:the\s+)?(?:(?:[a-z][\w-]*\s+){0,4}(?:group|committee|team)|reviewers?)\s+(?:agree(?:s|d)?|conclud(?:e[sd]?|ing)|decid(?:e[sd]?|ing)|finds?|found|identif(?:y|ies|ied)|recommend(?:s|ed)?))\b",
    re.IGNORECASE,
)
_NAMED_GROUP_POSITION_RE = re.compile(
    r"\b(?:PING|TAG|APA)\s+(?:agree(?:s|d)?|conclud(?:e[sd]?|ing)|decid(?:e[sd]?|ing)|finds?|found|identif(?:y|ies|ied)|recommend(?:s|ed)?)\b"
)


@dataclass(frozen=True)
class FocusedReviewValidationResult:
    """The structural result of validating an evidence packet and comment."""

    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    word_count: int
    link_count: int

    @property
    def ok(self) -> bool:
        return not self.errors


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_http_url(value: Any) -> bool:
    if not _is_non_empty_string(value):
        return False
    try:
        parsed = urlparse(value)
        parsed.port
    except ValueError:
        return False
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)


def _url_key(value: str) -> str:
    try:
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return value
    host_display = f"[{host}]" if ":" in host else host
    default_port = (parsed.scheme.lower(), port) in {("http", 80), ("https", 443)}
    port_part = "" if port is None or default_port else f":{port}"
    userinfo = ""
    if "@" in parsed.netloc:
        userinfo = parsed.netloc.rsplit("@", 1)[0] + "@"
    return parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=f"{userinfo}{host_display}{port_part}",
    ).geturl()


def _inline_destination(raw_destination: str) -> str:
    value = raw_destination.strip()
    if value.startswith("<") and ">" in value:
        return value[1 : value.index(">")]
    return value.split(maxsplit=1)[0] if value else ""


def _inline_has_title(raw_destination: str) -> bool:
    value = raw_destination.strip()
    if value.startswith("<") and ">" in value:
        return bool(value[value.index(">") + 1 :].strip())
    return len(value.split(maxsplit=1)) > 1


def _comment_urls(markdown: str) -> list[str]:
    scan_markdown = _CODE_SPAN_RE.sub(
        lambda match: (
            " " * len(match.group(0))
            if re.search(r"https?://", match.group(2), re.IGNORECASE)
            else match.group(0)
        ),
        markdown,
    )
    markdown_matches = list(_INLINE_MARKDOWN_RE.finditer(scan_markdown))
    urls = [
        destination
        for match in markdown_matches
        if not match.group(1)
        and _is_http_url(destination := _inline_destination(match.group(3)))
    ]
    masked = list(scan_markdown)
    for match in markdown_matches:
        for index in range(match.start(), match.end()):
            masked[index] = " "
    for match in _REFERENCE_DEFINITION_RE.finditer(scan_markdown):
        for index in range(match.start(), match.end()):
            masked[index] = " "
    urls.extend(_BARE_URL_RE.findall("".join(masked)))
    return urls


def _invalid_link_destinations(markdown: str) -> list[str]:
    destinations = [
        _inline_destination(match.group(3))
        for match in _INLINE_MARKDOWN_RE.finditer(markdown)
    ]
    destinations.extend(
        match.group(1) or match.group(2) or ""
        for match in _REFERENCE_DEFINITION_RE.finditer(markdown)
    )
    destinations.extend(
        match.group(1) for match in _SCHEME_AUTOLINK_RE.finditer(markdown)
    )
    return [
        destination for destination in destinations if not _is_http_url(destination)
    ]


def _plain_comment(markdown: str) -> str:
    text = _INLINE_MARKDOWN_RE.sub(
        lambda match: "" if match.group(1) else match.group(2), markdown
    )
    text = _BARE_URL_RE.sub(" ", text)
    return text.replace("`", "")


def _word_count(markdown: str) -> int:
    return len(_WORD_RE.findall(_plain_comment(markdown)))


def _sequence(value: Any) -> Sequence[Any] | None:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return None


def _validate_evidence_refs(
    value: Any,
    prefix: str,
    errors: list[str],
    *,
    require_one: bool,
) -> set[str]:
    entries = _sequence(value)
    if entries is None or (require_one and not entries):
        qualifier = "a non-empty list" if require_one else "a list"
        errors.append(f"{prefix} must be {qualifier}")
        return set()

    urls: set[str] = set()
    for index, entry in enumerate(entries):
        item_prefix = f"{prefix}[{index}]"
        if not isinstance(entry, Mapping):
            errors.append(f"{item_prefix} must be an object")
            continue
        if not _is_non_empty_string(entry.get("evidence_id")):
            errors.append(f"{item_prefix}.evidence_id must be non-empty")
        source_url = entry.get("source_url")
        if not _is_http_url(source_url):
            errors.append(f"{item_prefix}.source_url must be an HTTP(S) URL")
        else:
            urls.add(_url_key(str(source_url)))
    return urls


def _validate_prior_feedback(
    value: Any, errors: list[str]
) -> tuple[set[str], set[str], bool]:
    entries = _sequence(value)
    if entries is None:
        errors.append("prior_feedback must be a list")
        return set(), set(), False

    urls: set[str] = set()
    evidence_urls: set[str] = set()
    has_retained_delta = False
    for index, entry in enumerate(entries):
        prefix = f"prior_feedback[{index}]"
        if not isinstance(entry, Mapping):
            errors.append(f"{prefix} must be an object")
            continue
        if entry.get("domain") not in {
            "design",
            "privacy",
            "security",
            "accessibility",
            "internationalization",
        }:
            errors.append(f"{prefix}.domain must be a supported review domain")
        url = entry.get("prior_feedback_url")
        if not _is_http_url(url):
            errors.append(f"{prefix}.prior_feedback_url must be an HTTP(S) URL")
        else:
            urls.add(_url_key(str(url)))
        evidence_urls.update(
            _validate_evidence_refs(
                entry.get("evidence"), f"{prefix}.evidence", errors, require_one=True
            )
        )
        relationship = entry.get("relationship")
        if relationship not in ALLOWED_PRIOR_FEEDBACK_RELATIONSHIPS:
            errors.append(
                f"{prefix}.relationship must be one of: "
                + ", ".join(sorted(ALLOWED_PRIOR_FEEDBACK_RELATIONSHIPS))
            )
        disposition = entry.get("disposition")
        if disposition not in ALLOWED_PRIOR_FEEDBACK_DISPOSITIONS:
            errors.append(
                f"{prefix}.disposition must be one of: "
                + ", ".join(sorted(ALLOWED_PRIOR_FEEDBACK_DISPOSITIONS))
            )
        expected_disposition = (
            PRIOR_FEEDBACK_RELATIONSHIP_DISPOSITION.get(relationship)
            if isinstance(relationship, str)
            else None
        )
        if expected_disposition and disposition != expected_disposition:
            errors.append(
                f"{prefix}.disposition must be {expected_disposition!r} "
                f"for relationship {relationship!r}"
            )
        if not _is_non_empty_string(entry.get("rationale")):
            errors.append(f"{prefix}.rationale must be non-empty")
        if disposition in DISPOSITIONS_REQUIRING_DELTA:
            if not _is_non_empty_string(entry.get("distinct_delta")):
                errors.append(f"{prefix}.distinct_delta is required for {disposition}")
            else:
                has_retained_delta = True
        prior_issue_state = entry.get("prior_issue_state", "unknown")
        if prior_issue_state not in {"open", "closed", "unknown"}:
            errors.append(f"{prefix}.prior_issue_state has an unsupported value")
        conclusion = entry.get("conclusion", "unable_to_verify")
        final_conclusions = {
            "accepted",
            "resolved",
            "completed",
            "no_concerns",
            "rejected",
        }
        if conclusion not in final_conclusions | {"open", "unable_to_verify"}:
            errors.append(f"{prefix}.conclusion has an unsupported value")
        conclusion_urls = _validate_evidence_refs(
            entry.get("conclusion_evidence", []),
            f"{prefix}.conclusion_evidence",
            errors,
            require_one=conclusion in final_conclusions,
        )
        evidence_urls.update(conclusion_urls)
        if (
            prior_issue_state == "closed"
            and conclusion != "unable_to_verify"
            and not conclusion_urls
        ):
            errors.append(
                f"{prefix} closed issue without explicit conclusion evidence must remain unable_to_verify"
            )
    return urls, evidence_urls, has_retained_delta


def _validate_projection_markers(
    value: Any,
    source_fields: Mapping[str, tuple[str, ...]],
    errors: list[str],
) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, Mapping):
        errors.append("finding.public_projection_markers must be an object")
        return {}

    markers: dict[str, tuple[str, ...]] = {}
    for field, source_items in source_fields.items():
        entries = _sequence(value.get(field))
        if not entries or any(
            not _is_non_empty_string(item) or len(str(item).strip()) < 3
            for item in entries
        ):
            errors.append(
                f"finding.public_projection_markers.{field} must contain at least one stable marker"
            )
            continue
        normalized_sources = tuple(item.casefold() for item in source_items)
        normalized_markers: list[str] = []
        for item in entries:
            marker = str(item).strip()
            marker_words = [word.casefold() for word in _WORD_RE.findall(marker)]
            if not any(
                len(word) >= 4 and word not in _GENERIC_MARKER_WORDS
                for word in marker_words
            ):
                errors.append(
                    f"finding.public_projection_markers.{field} marker {marker!r} is too generic"
                )
            if not any(marker.casefold() in source for source in normalized_sources):
                errors.append(
                    f"finding.public_projection_markers.{field} marker {marker!r} is not derived from the corresponding finding field"
                )
            normalized_markers.append(marker)
        marker_keys = tuple(marker.casefold() for marker in normalized_markers)
        if len(marker_keys) != len(set(marker_keys)):
            errors.append(
                f"finding.public_projection_markers.{field} must not repeat markers"
            )
        for source_item in normalized_sources:
            uniquely_derived = [
                marker
                for marker in marker_keys
                if marker in source_item
                and sum(marker in candidate for candidate in normalized_sources) == 1
            ]
            if not uniquely_derived:
                errors.append(
                    f"finding.public_projection_markers.{field} must provide a distinct derived public marker for each material entry"
                )
        markers[field] = tuple(normalized_markers)
    return markers


def _validate_finding(
    value: Any, errors: list[str]
) -> tuple[set[str], set[str], dict[str, tuple[str, ...]], str, str, tuple[str, ...]]:
    if not isinstance(value, Mapping):
        errors.append("finding must be an object for publish_single_finding")
        return set(), set(), {}, "", "", ()

    for field in (
        "distinct_delta",
        "mechanism",
        "consequence",
        "target_section",
        "requested_change",
    ):
        if not _is_non_empty_string(value.get(field)):
            errors.append(f"finding.{field} must be non-empty")

    target_section = (
        str(value.get("target_section")).strip()
        if _is_non_empty_string(value.get("target_section"))
        else ""
    )
    requested_change = (
        str(value.get("requested_change")).strip()
        if _is_non_empty_string(value.get("requested_change"))
        else ""
    )
    requested_change_strength_value = value.get("requested_change_strength")
    if requested_change_strength_value not in ALLOWED_REQUESTED_CHANGE_STRENGTHS:
        allowed = ", ".join(sorted(ALLOWED_REQUESTED_CHANGE_STRENGTHS))
        errors.append(f"finding.requested_change_strength must be one of: {allowed}")
        requested_change_strength = ""
    else:
        requested_change_strength = str(requested_change_strength_value)
        packet_is_normative = bool(_NORMATIVE_REQUEST_RE.search(requested_change))
        if (
            requested_change_strength == "informative_documentation"
            and packet_is_normative
        ):
            errors.append(
                "finding.requested_change uses normative force but requested_change_strength is informative_documentation"
            )
        if (
            requested_change_strength == "normative_requirement"
            and not packet_is_normative
        ):
            errors.append(
                "finding.requested_change_strength is normative_requirement but requested_change does not express normative force"
            )

    requested_change_components = _sequence(value.get("requested_change_components"))
    component_values = tuple(
        str(item).strip()
        for item in requested_change_components or ()
        if _is_non_empty_string(item)
    )
    if not requested_change_components or any(
        not _is_non_empty_string(item) for item in requested_change_components
    ):
        errors.append(
            "finding.requested_change_components must contain every material requested-change object"
        )
    elif any(
        str(item).casefold() not in requested_change.casefold()
        for item in requested_change_components
    ):
        errors.append(
            "each finding.requested_change_components entry must be derived from finding.requested_change"
        )
    if len({item.casefold() for item in component_values}) != len(component_values):
        errors.append("finding.requested_change_components must be unique")
    if any(
        re.search(r"\b(?:and|or)\b|[,;]", item, re.IGNORECASE)
        for item in component_values
    ):
        errors.append(
            "finding.requested_change_components must be atomic; split conjunctions and lists into separate entries"
        )

    prerequisites = _sequence(value.get("prerequisites"))
    if not prerequisites or any(
        not _is_non_empty_string(item) for item in prerequisites
    ):
        errors.append(
            "finding.prerequisites must contain at least one non-empty string"
        )

    uncertainties = _sequence(value.get("uncertainties"))
    if uncertainties is None or any(
        not _is_non_empty_string(item) for item in uncertainties
    ):
        errors.append("finding.uncertainties must be a list of non-empty strings")

    limitations = _sequence(value.get("limitations"))
    if not limitations or any(not _is_non_empty_string(item) for item in limitations):
        errors.append("finding.limitations must contain at least one non-empty string")

    non_claims = _sequence(value.get("non_claims"))
    if non_claims is None or any(not _is_non_empty_string(item) for item in non_claims):
        errors.append("finding.non_claims must be a list of non-empty strings")

    projection_sources: dict[str, tuple[str, ...]] = {
        "distinct_delta": (str(value.get("distinct_delta", "")),),
        "mechanism": (str(value.get("mechanism", "")),),
        "prerequisites": tuple(str(item) for item in prerequisites or ()),
        "consequence": (str(value.get("consequence", "")),),
        "limitations": tuple(str(item) for item in limitations or ()),
        "requested_change": (str(value.get("requested_change", "")),),
        "requested_change_components": component_values,
    }
    if non_claims:
        projection_sources["non_claims"] = tuple(str(item) for item in non_claims)
    if uncertainties:
        projection_sources["uncertainties"] = tuple(str(item) for item in uncertainties)
    projection_markers = _validate_projection_markers(
        value.get("public_projection_markers"), projection_sources, errors
    )

    sources = _sequence(value.get("sources"))
    if not sources:
        errors.append("finding.sources must contain at least one source")
        return (
            set(),
            set(),
            projection_markers,
            target_section,
            requested_change_strength,
            component_values,
        )

    urls: set[str] = set()
    required_urls: set[str] = set()
    required_roles: list[str] = []
    for index, source in enumerate(sources):
        prefix = f"finding.sources[{index}]"
        if not isinstance(source, Mapping):
            errors.append(f"{prefix} must be an object")
            continue
        url = source.get("url")
        if not _is_http_url(url):
            errors.append(f"{prefix}.url must be an HTTP(S) URL")
        else:
            normalized_url = _url_key(str(url))
            if normalized_url in urls:
                errors.append("finding.sources must not repeat the same URL")
            urls.add(normalized_url)
        role = source.get("role")
        if not _is_non_empty_string(role):
            errors.append(f"{prefix}.role must be non-empty")
        public_required = source.get("public_required")
        if not isinstance(public_required, bool):
            errors.append(f"{prefix}.public_required must be true or false")
        elif public_required and _is_http_url(url):
            required_urls.add(_url_key(str(url)))
            if _is_non_empty_string(role):
                required_roles.append(str(role).strip().casefold())
    if not required_urls:
        errors.append(
            "finding.sources must mark at least one source as public_required"
        )
    if len(required_roles) != len(set(required_roles)):
        errors.append(
            "public_required finding sources must have distinct evidence roles"
        )
    return (
        urls,
        required_urls,
        projection_markers,
        target_section,
        requested_change_strength,
        component_values,
    )


def _sentences(text: str) -> list[str]:
    stripped = text.strip()
    if not stripped:
        return []
    return [
        match.strip()
        for match in re.findall(r"[^.!?]+[.!?]?", stripped)
        if match.strip()
    ]


def _final_sentence(text: str) -> str:
    sentences = _sentences(text)
    return sentences[-1] if sentences else ""


def _is_actionable_ask(sentence: str) -> bool:
    if not _ACTION_VERB_RE.search(sentence):
        return False
    if sentence.endswith("?"):
        return bool(_QUESTION_START_RE.search(sentence))
    return bool(
        _REQUEST_START_RE.search(sentence) or _IMPERATIVE_START_RE.search(sentence)
    )


def _has_one_actionable_final_ask(text: str) -> bool:
    sentences = _sentences(text)
    if not sentences or text.count("?") > 1:
        return False
    actionable_indices = [
        index
        for index, sentence in enumerate(sentences)
        if _is_actionable_ask(sentence)
    ]
    if actionable_indices != [len(sentences) - 1]:
        return False
    if text.count("?") == 1 and not sentences[-1].endswith("?"):
        return False
    return True


def _consensus_urls(value: Any, errors: list[str]) -> set[str]:
    entries = _sequence(value)
    if entries is None:
        errors.append("consensus_evidence must be a list")
        return set()
    urls: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping) or not _is_http_url(entry.get("url")):
            errors.append(f"consensus_evidence[{index}].url must be an HTTP(S) URL")
            continue
        urls.add(_url_key(str(entry["url"])))
    return urls


def validate_focused_review(
    evidence: Mapping[str, Any],
    comment_markdown: str,
) -> FocusedReviewValidationResult:
    """Validate the focused-review evidence and its public projection."""

    errors: list[str] = []
    warnings: list[str] = []

    if evidence.get("artifact_kind") != ARTIFACT_KIND:
        errors.append(f"artifact_kind must be {ARTIFACT_KIND!r}")
    if evidence.get("review_mode") != REVIEW_MODE:
        errors.append(f"review_mode must be {REVIEW_MODE!r}")
    if evidence.get("output_register") != OUTPUT_REGISTER:
        errors.append(f"output_register must be {OUTPUT_REGISTER!r}")
    if evidence.get("review_capacity") != "individual":
        errors.append(
            "review_capacity must be 'individual'; route group-authorized findings through the full-review contract"
        )

    target = evidence.get("target")
    if not isinstance(target, Mapping) or not _is_non_empty_string(
        target.get("specification")
    ):
        errors.append("target.specification must be non-empty")
    if not isinstance(target, Mapping) or not _is_http_url(target.get("issue_url")):
        errors.append("target.issue_url must be an HTTP(S) URL")

    search_urls = _validate_evidence_refs(
        evidence.get("search_evidence"),
        "search_evidence",
        errors,
        require_one=True,
    )
    prior_urls, _prior_evidence_urls, has_retained_delta = _validate_prior_feedback(
        evidence.get("prior_feedback"), errors
    )
    consensus_urls = _consensus_urls(evidence.get("consensus_evidence"), errors)
    decision = evidence.get("publication_decision")

    if decision == NO_FINDING_DECISION:
        if has_retained_delta:
            errors.append(
                "no_new_finding cannot retain, merge, or follow up a distinct delta"
            )
        if evidence.get("finding") not in (None, {}):
            errors.append("finding must be absent for no_new_finding")
        if comment_markdown.strip():
            errors.append("comment.md must be empty for no_new_finding")
        return FocusedReviewValidationResult(
            tuple(errors),
            tuple(warnings),
            _word_count(comment_markdown),
            len(_comment_urls(comment_markdown)),
        )

    if decision != PUBLISH_DECISION:
        errors.append(
            "publication_decision must be 'publish_single_finding' or 'no_new_finding'"
        )

    (
        _finding_urls,
        required_finding_urls,
        projection_markers,
        target_section,
        requested_change_strength,
        requested_change_components,
    ) = _validate_finding(evidence.get("finding"), errors)
    if prior_urls and not has_retained_delta:
        errors.append(
            "publish_single_finding with prior feedback requires a distinct, refinement, or follow-up delta; duplicate-only and unable-only packets must use no_new_finding"
        )
    if not prior_urls and not search_urls:
        errors.append(
            "publish_single_finding without a related prior finding requires search_evidence"
        )

    if _HTML_COMMENT_TOKEN_RE.search(comment_markdown):
        errors.append("comment.md must not contain HTML comments")
    visible_comment = _HTML_COMMENT_RE.sub("", comment_markdown)
    if any(match.group(1) for match in _INLINE_MARKDOWN_RE.finditer(visible_comment)):
        errors.append("comment.md must not contain Markdown images")
    if _REFERENCE_USAGE_RE.search(visible_comment) or _REFERENCE_DEFINITION_RE.search(
        visible_comment
    ):
        errors.append(
            "comment.md must not use reference-style Markdown links or images"
        )
    if any(
        _inline_has_title(match.group(3))
        for match in _INLINE_MARKDOWN_RE.finditer(visible_comment)
    ):
        errors.append("comment.md must not use Markdown link titles")
    if _RAW_HTML_TAG_RE.search(visible_comment):
        errors.append("comment.md must not contain raw HTML")
    if _FENCED_CODE_RE.search(visible_comment) or _INDENTED_CODE_RE.search(
        visible_comment
    ):
        errors.append("comment.md must not contain code blocks")
    if _BLOCKQUOTE_RE.search(visible_comment):
        errors.append("comment.md must not contain block quotes")
    if any(
        re.search(r"https?://", match.group(2), re.IGNORECASE)
        for match in _CODE_SPAN_RE.finditer(visible_comment)
    ):
        errors.append("comment.md must not put citation URLs inside code spans")
    if _FULL_REVIEW_SCAFFOLD_RE.search(visible_comment):
        errors.append(
            "comment.md must not contain full-review scaffolding or field labels"
        )
    invalid_link_destinations = _invalid_link_destinations(visible_comment)
    if invalid_link_destinations:
        errors.append(
            "comment.md contains non-HTTP(S) link destinations: "
            + ", ".join(invalid_link_destinations)
        )

    comment_urls = _comment_urls(visible_comment)
    comment_url_keys = [_url_key(url) for url in comment_urls]
    unique_comment_urls = set(comment_url_keys)
    word_count = _word_count(visible_comment)
    plain_comment = _plain_comment(visible_comment)
    if _PROCESS_NARRATION_RE.search(visible_comment) or _PROCESS_NARRATION_RE.search(
        plain_comment
    ):
        errors.append(
            "comment.md must not narrate the private search or review process"
        )
    if _PRIVATE_LOCAL_REFERENCE_RE.search(
        visible_comment
    ) or _PRIVATE_LOCAL_REFERENCE_RE.search(plain_comment):
        errors.append("comment.md must not expose local paths or file URLs")

    if not 50 <= word_count <= 140:
        errors.append(f"comment.md must contain 50-140 words; found {word_count}")
    if _HEADING_RE.search(visible_comment):
        errors.append("comment.md must not contain headings")
    if _TABLE_ROW_RE.search(visible_comment):
        errors.append("comment.md must not contain tables")
    if len(comment_urls) != len(unique_comment_urls):
        errors.append("comment.md must not repeat the same URL")
    if not 2 <= len(unique_comment_urls) <= 4:
        errors.append(
            f"comment.md must contain 2-4 distinct links; found {len(unique_comment_urls)}"
        )
    if not _has_one_actionable_final_ask(plain_comment):
        errors.append("comment.md must contain one actionable question or request")
    final_sentence = _final_sentence(plain_comment)
    if target_section and target_section.casefold() not in final_sentence.casefold():
        errors.append(
            "the final request in comment.md must name finding.target_section"
        )
    for field in ("requested_change", "requested_change_components"):
        for marker in projection_markers.get(field, ()):
            if marker.casefold() not in final_sentence.casefold():
                errors.append(
                    f"the final request in comment.md must preserve the {field} marker {marker!r}"
                )
    for component in requested_change_components:
        if component.casefold() not in final_sentence.casefold():
            errors.append(
                f"the final request in comment.md must preserve the complete requested-change component {component!r}"
            )
    final_request_is_normative = bool(_NORMATIVE_REQUEST_RE.search(final_sentence))
    if (
        requested_change_strength == "informative_documentation"
        and final_request_is_normative
    ):
        errors.append(
            "comment.md upgrades an informative documentation request to normative force"
        )
    if (
        requested_change_strength == "normative_requirement"
        and not final_request_is_normative
    ):
        errors.append(
            "comment.md does not preserve the normative force of finding.requested_change"
        )

    if not _FIRST_PERSON_SINGULAR_RE.search(plain_comment):
        errors.append("an individual review comment must use first-person singular")
    if _FIRST_PERSON_PLURAL_RE.search(plain_comment):
        errors.append(
            "an individual review comment must not claim first-person plural authority"
        )
    if _GROUP_VOICE_RE.search(plain_comment):
        errors.append(
            "an individual review comment must not claim to speak on behalf of a group"
        )

    prior_link_count = sum(url in prior_urls for url in comment_url_keys)
    if prior_urls and prior_link_count != 1:
        errors.append(
            "comment.md must cite exactly one registered prior-feedback URL as its boundary"
        )
    if not prior_urls and prior_link_count:
        errors.append(
            "comment.md cites a prior-feedback boundary not present in the packet"
        )

    registered_urls = prior_urls | required_finding_urls | consensus_urls
    unregistered_urls = [
        original
        for original, canonical in zip(comment_urls, comment_url_keys, strict=True)
        if canonical not in registered_urls
    ]
    if unregistered_urls:
        errors.append(
            "comment.md contains links not registered in the evidence packet: "
            + ", ".join(unregistered_urls)
        )
    missing_required_urls = sorted(required_finding_urls - unique_comment_urls)
    if missing_required_urls:
        errors.append(
            "comment.md omits public_required finding sources: "
            + ", ".join(missing_required_urls)
        )

    if (
        _CONSENSUS_RE.search(plain_comment)
        or _NAMED_GROUP_POSITION_RE.search(plain_comment)
    ) and not consensus_urls.intersection(comment_url_keys):
        errors.append(
            "a consensus or disposition claim requires a cited consensus_evidence URL"
        )

    normalized_comment = plain_comment.casefold()
    for field, markers in projection_markers.items():
        for marker in markers:
            if marker.casefold() not in normalized_comment:
                errors.append(
                    f"comment.md must preserve the {field} marker {marker!r} from the evidence packet"
                )

    return FocusedReviewValidationResult(
        tuple(errors), tuple(warnings), word_count, len(unique_comment_urls)
    )


def validate_focused_review_files(
    evidence_path: Path,
    comment_path: Path,
) -> FocusedReviewValidationResult:
    """Read and validate separate focused-review files."""

    import json

    if evidence_path.resolve() == comment_path.resolve():
        return FocusedReviewValidationResult(
            ("evidence packet and public comment must be separate files",), (), 0, 0
        )
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except OSError as error:
        return FocusedReviewValidationResult(
            (f"cannot read evidence packet: {error}",), (), 0, 0
        )
    except json.JSONDecodeError as error:
        return FocusedReviewValidationResult(
            (f"evidence packet is not valid JSON: {error.msg}",), (), 0, 0
        )
    if not isinstance(evidence, Mapping):
        return FocusedReviewValidationResult(
            ("evidence packet root must be an object",), (), 0, 0
        )
    try:
        comment_markdown = comment_path.read_text(encoding="utf-8")
    except OSError as error:
        return FocusedReviewValidationResult(
            (f"cannot read public comment: {error}",), (), 0, 0
        )
    return validate_focused_review(
        evidence,
        comment_markdown,
    )
