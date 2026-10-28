"""Build a fact-check-aware publication gate for an exact review artifact."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


FACT_CHECK_SCHEMA_VERSION = "fact-check-result/v1"
PUBLICATION_GATE_SCHEMA_VERSION = "review-publication-gate/v1"
PASS_STATUSES = {"pass", "passed", "complete", "completed", "ready"}
BLOCKING_BOUNDARY_SEVERITIES = {"blocker", "high"}
FACT_CHECK_REVIEW_STATUSES = {"draft", "human_reviewed"}
FACT_CHECK_PUBLICATION_STATUSES = {"pass", "needs_revision", "blocked"}
FACT_CHECK_ARTIFACT_TYPES = {
    "markdown",
    "text",
    "html",
    "json",
    "issue_draft",
    "pull_request_draft",
    "review_comment",
    "report",
    "specification_text",
    "other",
}
FACT_CHECK_SOURCE_TYPES = {
    "specification",
    "standard",
    "source_repository",
    "test_result",
    "issue_or_pull_request",
    "minutes",
    "official_documentation",
    "official_organization_page",
    "academic_paper",
    "regulator_or_court",
    "reputable_secondary_source",
    "supplied_source",
    "other",
}
FACT_CHECK_SOURCE_AUTHORITIES = {"primary", "authoritative", "secondary", "supplied", "unclear"}
FACT_CHECK_ACCESS_STATUSES = {"checked", "partial", "unavailable"}
FACT_CHECK_CHECKABILITIES = {"externally_checkable", "analysis_or_judgment", "not_checkable"}
FACT_CHECK_CLAIM_STATUSES = {
    "verified",
    "partially_supported",
    "inference",
    "unsupported",
    "contradicted",
    "not_checkable",
}
FACT_CHECK_IMPORTANCE = {"load_bearing", "material", "minor"}
FACT_CHECK_DISPOSITIONS = {
    "keep",
    "qualify",
    "label_inference",
    "remove",
    "replace",
    "open_question",
    "manual_review",
}
FACT_CHECK_UNRESOLVED_STATUSES = {"partially_supported", "unsupported", "contradicted"}
FACT_CHECK_SOURCE_REQUIRED_STATUSES = {"verified", "partially_supported", "inference", "contradicted"}
FACT_CHECK_INFERENCE_VISIBLE_DISPOSITIONS = {"label_inference", "qualify", "open_question", "manual_review"}
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    status: str
    evidence: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "status": self.status,
            "evidence": list(self.evidence),
            "errors": list(self.errors),
        }


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _string_array(value: Any) -> bool:
    return isinstance(value, list) and all(_non_empty_string(item) for item in value)


def _expected_fact_check_status(claims: list[dict[str, Any]]) -> str:
    if any(
        claim.get("importance") == "load_bearing"
        and claim.get("status") in {"unsupported", "contradicted"}
        for claim in claims
    ):
        return "blocked"
    if any(
        claim.get("status") in FACT_CHECK_UNRESOLVED_STATUSES
        or (
            claim.get("status") == "inference"
            and claim.get("disposition") not in FACT_CHECK_INFERENCE_VISIBLE_DISPOSITIONS
        )
        for claim in claims
    ):
        return "needs_revision"
    return "pass"


def _validate_fact_check_result_v1(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "fact_check_id",
        "artifact",
        "checked_at",
        "review_status",
        "sources",
        "claims",
        "unresolved_claim_ids",
        "limitations",
        "publication_status",
    }
    for key in sorted(required - payload.keys()):
        errors.append(f"fact-check result is missing required field {key!r}")
    if payload.get("schema_version") != FACT_CHECK_SCHEMA_VERSION:
        errors.append(f"fact-check schema_version must be {FACT_CHECK_SCHEMA_VERSION}")
    if not _non_empty_string(payload.get("fact_check_id")):
        errors.append("fact-check fact_check_id must be a non-empty string")
    if not _non_empty_string(payload.get("checked_at")):
        errors.append("fact-check checked_at must be a non-empty date-time string")
    if payload.get("review_status") not in FACT_CHECK_REVIEW_STATUSES:
        errors.append("fact-check review_status is invalid")

    artifact = payload.get("artifact")
    if not isinstance(artifact, dict):
        errors.append("fact-check artifact must be an object")
    else:
        for field in ("artifact_id", "reference"):
            if not _non_empty_string(artifact.get(field)):
                errors.append(f"fact-check artifact.{field} must be a non-empty string")
        if artifact.get("artifact_type") not in FACT_CHECK_ARTIFACT_TYPES:
            errors.append("fact-check artifact.artifact_type is invalid")
        digest = artifact.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            errors.append("fact-check artifact.sha256 must be a lowercase SHA-256 digest")

    sources = payload.get("sources")
    source_ids: set[str] = set()
    if not isinstance(sources, list):
        errors.append("fact-check sources must be an array")
        sources = []
    for index, source in enumerate(sources):
        label = f"fact-check sources[{index}]"
        if not isinstance(source, dict):
            errors.append(f"{label} must be an object")
            continue
        source_id = source.get("source_id")
        if not _non_empty_string(source_id):
            errors.append(f"{label}.source_id must be a non-empty string")
        elif source_id in source_ids:
            errors.append(f"duplicate fact-check source_id: {source_id}")
        else:
            source_ids.add(source_id)
        for field in ("title", "reference", "version_or_date", "retrieved_at"):
            if not _non_empty_string(source.get(field)):
                errors.append(f"{label}.{field} must be a non-empty string")
        if source.get("source_type") not in FACT_CHECK_SOURCE_TYPES:
            errors.append(f"{label}.source_type is invalid")
        if source.get("authority") not in FACT_CHECK_SOURCE_AUTHORITIES:
            errors.append(f"{label}.authority is invalid")
        if source.get("access_status") not in FACT_CHECK_ACCESS_STATUSES:
            errors.append(f"{label}.access_status is invalid")
        content_digest = source.get("content_sha256")
        if content_digest is not None and (
            not isinstance(content_digest, str) or not SHA256_RE.fullmatch(content_digest)
        ):
            errors.append(f"{label}.content_sha256 must be null or a lowercase SHA-256 digest")
        if "limitations" in source and not _string_array(source.get("limitations")):
            errors.append(f"{label}.limitations must be an array of non-empty strings")

    claims = payload.get("claims")
    valid_claims: list[dict[str, Any]] = []
    claim_ids: set[str] = set()
    if not isinstance(claims, list):
        errors.append("fact-check claims must be an array")
        claims = []
    for index, claim in enumerate(claims):
        label = f"fact-check claims[{index}]"
        if not isinstance(claim, dict):
            errors.append(f"{label} must be an object")
            continue
        valid_claims.append(claim)
        claim_id = claim.get("claim_id")
        if not _non_empty_string(claim_id):
            errors.append(f"{label}.claim_id must be a non-empty string")
        elif claim_id in claim_ids:
            errors.append(f"duplicate fact-check claim_id: {claim_id}")
        else:
            claim_ids.add(claim_id)
        for field in ("locator", "claim", "evidence_note"):
            if not _non_empty_string(claim.get(field)):
                errors.append(f"{label}.{field} must be a non-empty string")
        if not isinstance(claim.get("recommended_edit"), str):
            errors.append(f"{label}.recommended_edit must be a string")
        if claim.get("checkability") not in FACT_CHECK_CHECKABILITIES:
            errors.append(f"{label}.checkability is invalid")
        status = claim.get("status")
        if status not in FACT_CHECK_CLAIM_STATUSES:
            errors.append(f"{label}.status is invalid")
        if claim.get("importance") not in FACT_CHECK_IMPORTANCE:
            errors.append(f"{label}.importance is invalid")
        if claim.get("disposition") not in FACT_CHECK_DISPOSITIONS:
            errors.append(f"{label}.disposition is invalid")
        referenced_sources = claim.get("source_ids")
        if not _string_array(referenced_sources):
            errors.append(f"{label}.source_ids must be an array of non-empty source IDs")
            referenced_sources = []
        elif len(referenced_sources) != len(set(referenced_sources)):
            errors.append(f"{label}.source_ids must not contain duplicates")
        unknown_sources = sorted(set(referenced_sources) - source_ids)
        if unknown_sources:
            errors.append(f"{label}.source_ids references unknown sources: {unknown_sources}")
        if status in FACT_CHECK_SOURCE_REQUIRED_STATUSES and not referenced_sources:
            errors.append(f"{label}.source_ids must not be empty for status {status}")
        if status == "unsupported" and claim.get("evidence_note") != "No reliable source found":
            errors.append(
                f"{label}.evidence_note must be exactly 'No reliable source found' for unsupported claims"
            )
        if status == "not_checkable" and claim.get("checkability") != "not_checkable":
            errors.append(f"{label}.checkability must be not_checkable when status is not_checkable")
        if claim.get("checkability") == "not_checkable" and status != "not_checkable":
            errors.append(f"{label}.status must be not_checkable when checkability is not_checkable")

    unresolved = payload.get("unresolved_claim_ids")
    if not _string_array(unresolved):
        errors.append("fact-check unresolved_claim_ids must be an array of non-empty claim IDs")
        unresolved = []
    elif len(unresolved) != len(set(unresolved)):
        errors.append("fact-check unresolved_claim_ids must not contain duplicates")
    unknown_unresolved = sorted(set(unresolved) - claim_ids)
    if unknown_unresolved:
        errors.append(f"fact-check unresolved_claim_ids references unknown claims: {unknown_unresolved}")
    expected_unresolved = {
        claim["claim_id"]
        for claim in valid_claims
        if _non_empty_string(claim.get("claim_id"))
        and claim.get("status") in FACT_CHECK_UNRESOLVED_STATUSES
    }
    if set(unresolved) != expected_unresolved:
        errors.append(
            "fact-check unresolved_claim_ids must exactly match unresolved claim statuses"
        )
    if not _string_array(payload.get("limitations")):
        errors.append("fact-check limitations must be an array of non-empty strings")
    publication_status = payload.get("publication_status")
    if publication_status not in FACT_CHECK_PUBLICATION_STATUSES:
        errors.append("fact-check publication_status is invalid")
    expected_status = _expected_fact_check_status(valid_claims)
    if publication_status in FACT_CHECK_PUBLICATION_STATUSES and publication_status != expected_status:
        errors.append(
            "fact-check publication_status does not match the deterministic factual-readiness gate"
        )
    return errors


def _portable_reference(path: Path) -> str:
    return path.name


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    return payload


def artifact_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _extract_status(payload: dict[str, Any]) -> str | None:
    for key in ("status", "publication_status", "gate_status", "result"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    gate = payload.get("gate")
    if isinstance(gate, dict):
        return _extract_status(gate)
    return None


def check_artifact_identity(
    artifact_path: Path,
    fact_check: dict[str, Any],
) -> CheckResult:
    artifact = fact_check.get("artifact")
    if not isinstance(artifact, dict):
        return CheckResult(
            "artifact_identity",
            "fail",
            errors=("fact-check result does not contain artifact identity",),
        )
    expected = artifact.get("sha256")
    if not _non_empty_string(expected):
        return CheckResult(
            "artifact_identity",
            "fail",
            errors=("fact-check artifact.sha256 is missing",),
        )
    calculated = artifact_sha256(artifact_path)
    if calculated != expected:
        return CheckResult(
            "artifact_identity",
            "fail",
            evidence=(_portable_reference(artifact_path),),
            errors=(
                f"checked artifact digest mismatch: expected {expected}, calculated {calculated}",
            ),
        )
    return CheckResult(
        "artifact_identity",
        "pass",
        evidence=(_portable_reference(artifact_path), f"sha256:{calculated}"),
    )


def check_fact_check_result(
    fact_check_path: Path,
    fact_check: dict[str, Any],
    *,
    require_human_reviewed: bool,
) -> CheckResult:
    errors = _validate_fact_check_result_v1(fact_check)
    if fact_check.get("publication_status") != "pass":
        errors.append(
            "fact-check factual-readiness status must be pass; "
            f"got {fact_check.get('publication_status')!r}"
        )
    unresolved = fact_check.get("unresolved_claim_ids")
    if isinstance(unresolved, list) and unresolved:
        errors.append(
            f"fact-check contains unresolved claims: {sorted(str(item) for item in unresolved)}"
        )
    if require_human_reviewed and fact_check.get("review_status") != "human_reviewed":
        errors.append(
            "final publication gate requires fact-check review_status human_reviewed"
        )
    return CheckResult(
        "fact_check",
        "fail" if errors else "pass",
        evidence=(_portable_reference(fact_check_path),),
        errors=tuple(errors),
    )


def check_upstream_gate(
    check_id: str,
    path: Path | None,
    *,
    required: bool,
) -> CheckResult:
    if path is None:
        if required:
            return CheckResult(
                check_id,
                "fail",
                errors=(f"required {check_id} artifact was not supplied",),
            )
        return CheckResult(check_id, "not_supplied")
    try:
        payload = load_json(path)
    except (OSError, json.JSONDecodeError, ValueError) as error:
            return CheckResult(
                check_id,
                "fail",
                evidence=(_portable_reference(path),),
            errors=(f"could not load {check_id}: {error}",),
        )
    status = _extract_status(payload)
    if status not in PASS_STATUSES:
        return CheckResult(
            check_id,
            "fail",
            evidence=(_portable_reference(path),),
            errors=(f"{check_id} must pass; got {status!r}",),
        )
    return CheckResult(check_id, "pass", evidence=(_portable_reference(path),))


def check_publication_boundary(path: Path | None) -> CheckResult:
    if path is None:
        return CheckResult("publication_boundary", "not_supplied")
    try:
        payload = load_json(path)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        return CheckResult(
            "publication_boundary",
            "fail",
            evidence=(_portable_reference(path),),
            errors=(f"could not load publication-boundary audit: {error}",),
        )
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return CheckResult(
            "publication_boundary",
            "fail",
            evidence=(_portable_reference(path),),
            errors=("publication-boundary audit findings must be an array",),
        )
    blocking = [
        finding
        for finding in findings
        if isinstance(finding, dict)
        and str(finding.get("severity", "")).lower() in BLOCKING_BOUNDARY_SEVERITIES
    ]
    if blocking:
        labels = [
            f"{item.get('rule', 'finding')}:{item.get('path', '')}:{item.get('line', '')}"
            for item in blocking
        ]
        return CheckResult(
            "publication_boundary",
            "fail",
            evidence=(_portable_reference(path),),
            errors=(f"blocking publication-boundary findings remain: {labels}",),
        )
    return CheckResult(
        "publication_boundary",
        "pass",
        evidence=(_portable_reference(path),),
    )


def build_publication_gate(
    *,
    artifact_path: Path,
    fact_check_path: Path,
    analysis_gate_path: Path | None = None,
    independent_review_gate_path: Path | None = None,
    publication_boundary_path: Path | None = None,
    require_analysis_gate: bool = True,
    require_independent_review_gate: bool = True,
    require_human_reviewed_fact_check: bool = False,
) -> dict[str, Any]:
    artifact_path = artifact_path.resolve()
    fact_check_path = fact_check_path.resolve()
    fact_check = load_json(fact_check_path)
    checks = [
        check_artifact_identity(artifact_path, fact_check),
        check_fact_check_result(
            fact_check_path,
            fact_check,
            require_human_reviewed=require_human_reviewed_fact_check,
        ),
        check_upstream_gate(
            "analysis_gate",
            analysis_gate_path.resolve() if analysis_gate_path else None,
            required=require_analysis_gate,
        ),
        check_upstream_gate(
            "independent_review_gate",
            independent_review_gate_path.resolve() if independent_review_gate_path else None,
            required=require_independent_review_gate,
        ),
        check_publication_boundary(
            publication_boundary_path.resolve() if publication_boundary_path else None
        ),
    ]
    status = "fail" if any(check.status == "fail" for check in checks) else "pass"
    return {
        "schema_version": PUBLICATION_GATE_SCHEMA_VERSION,
        "artifact": {
            "reference": _portable_reference(artifact_path),
            "sha256": artifact_sha256(artifact_path),
        },
        "status": status,
        "checks": [check.to_dict() for check in checks],
        "inputs": {
            "fact_check_result": _portable_reference(fact_check_path),
            "analysis_gate": (
                _portable_reference(analysis_gate_path.resolve()) if analysis_gate_path else None
            ),
            "independent_review_gate": (
                _portable_reference(independent_review_gate_path.resolve())
                if independent_review_gate_path
                else None
            ),
            "publication_boundary_audit": (
                _portable_reference(publication_boundary_path.resolve())
                if publication_boundary_path
                else None
            ),
        },
        "human_approval": {
            "required": True,
            "status": "not_recorded",
            "approver": None,
            "approved_at": None,
        },
    }


def write_publication_gate(path: Path, gate: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(gate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
