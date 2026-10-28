#!/usr/bin/env python3
"""Validate fact-check-result/v1 and its deterministic factual-readiness gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "fact-check-result/v1"
VALID_REVIEW_STATUS = {"draft", "human_reviewed"}
VALID_PUBLICATION_STATUS = {"pass", "needs_revision", "blocked"}
VALID_ARTIFACT_TYPES = {
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
VALID_SOURCE_TYPES = {
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
VALID_SOURCE_AUTHORITY = {"primary", "authoritative", "secondary", "supplied", "unclear"}
VALID_ACCESS_STATUS = {"checked", "partial", "unavailable"}
VALID_CHECKABILITY = {"externally_checkable", "analysis_or_judgment", "not_checkable"}
VALID_CLAIM_STATUS = {
    "verified",
    "partially_supported",
    "inference",
    "unsupported",
    "contradicted",
    "not_checkable",
}
VALID_IMPORTANCE = {"load_bearing", "material", "minor"}
VALID_DISPOSITION = {
    "keep",
    "qualify",
    "label_inference",
    "remove",
    "replace",
    "open_question",
    "manual_review",
}
UNRESOLVED_STATUSES = {"partially_supported", "unsupported", "contradicted"}
SOURCE_REQUIRED_STATUSES = {"verified", "partially_supported", "inference", "contradicted"}
INFERENCE_VISIBLE_DISPOSITIONS = {"label_inference", "qualify", "open_question", "manual_review"}
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _string_array(value: Any, *, non_empty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and (bool(value) or not non_empty)
        and all(_non_empty_string(item) for item in value)
    )


def _validate_artifact(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["artifact must be an object"]
    errors: list[str] = []
    for field in ("artifact_id", "reference"):
        if not _non_empty_string(value.get(field)):
            errors.append(f"artifact.{field} must be a non-empty string")
    artifact_type = value.get("artifact_type")
    if artifact_type not in VALID_ARTIFACT_TYPES:
        errors.append(f"artifact.artifact_type must be one of {sorted(VALID_ARTIFACT_TYPES)}")
    digest = value.get("sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        errors.append("artifact.sha256 must be a lowercase 64-character SHA-256 digest")
    return errors


def _validate_sources(value: Any) -> tuple[list[str], set[str]]:
    if not isinstance(value, list):
        return ["sources must be an array"], set()
    errors: list[str] = []
    seen: set[str] = set()
    for index, source in enumerate(value):
        label = f"sources[{index}]"
        if not isinstance(source, dict):
            errors.append(f"{label} must be an object")
            continue
        source_id = source.get("source_id")
        if not _non_empty_string(source_id):
            errors.append(f"{label}.source_id must be a non-empty string")
        elif source_id in seen:
            errors.append(f"duplicate source_id: {source_id}")
        else:
            seen.add(source_id)
        for field in ("title", "reference", "version_or_date", "retrieved_at"):
            if not _non_empty_string(source.get(field)):
                errors.append(f"{label}.{field} must be a non-empty string")
        if source.get("source_type") not in VALID_SOURCE_TYPES:
            errors.append(f"{label}.source_type must be one of {sorted(VALID_SOURCE_TYPES)}")
        if source.get("authority") not in VALID_SOURCE_AUTHORITY:
            errors.append(f"{label}.authority must be one of {sorted(VALID_SOURCE_AUTHORITY)}")
        if source.get("access_status") not in VALID_ACCESS_STATUS:
            errors.append(f"{label}.access_status must be one of {sorted(VALID_ACCESS_STATUS)}")
        content_digest = source.get("content_sha256")
        if content_digest is not None and (
            not isinstance(content_digest, str) or not SHA256_RE.fullmatch(content_digest)
        ):
            errors.append(f"{label}.content_sha256 must be null or a lowercase SHA-256 digest")
        limitations = source.get("limitations")
        if limitations is not None and not _string_array(limitations):
            errors.append(f"{label}.limitations must be an array of non-empty strings")
    return errors, seen


def _validate_claims(value: Any, source_ids: set[str]) -> tuple[list[str], list[dict[str, Any]]]:
    if not isinstance(value, list):
        return ["claims must be an array"], []
    errors: list[str] = []
    seen: set[str] = set()
    valid_claims: list[dict[str, Any]] = []
    for index, claim in enumerate(value):
        label = f"claims[{index}]"
        if not isinstance(claim, dict):
            errors.append(f"{label} must be an object")
            continue
        valid_claims.append(claim)
        claim_id = claim.get("claim_id")
        if not _non_empty_string(claim_id):
            errors.append(f"{label}.claim_id must be a non-empty string")
        elif claim_id in seen:
            errors.append(f"duplicate claim_id: {claim_id}")
        else:
            seen.add(claim_id)
        for field in ("locator", "claim", "evidence_note"):
            if not _non_empty_string(claim.get(field)):
                errors.append(f"{label}.{field} must be a non-empty string")
        if not isinstance(claim.get("recommended_edit"), str):
            errors.append(f"{label}.recommended_edit must be a string")
        if claim.get("checkability") not in VALID_CHECKABILITY:
            errors.append(f"{label}.checkability must be one of {sorted(VALID_CHECKABILITY)}")
        status = claim.get("status")
        if status not in VALID_CLAIM_STATUS:
            errors.append(f"{label}.status must be one of {sorted(VALID_CLAIM_STATUS)}")
        if claim.get("importance") not in VALID_IMPORTANCE:
            errors.append(f"{label}.importance must be one of {sorted(VALID_IMPORTANCE)}")
        disposition = claim.get("disposition")
        if disposition not in VALID_DISPOSITION:
            errors.append(f"{label}.disposition must be one of {sorted(VALID_DISPOSITION)}")
        referenced_sources = claim.get("source_ids")
        if not _string_array(referenced_sources):
            errors.append(f"{label}.source_ids must be an array of non-empty source IDs")
            referenced_sources = []
        if len(referenced_sources) != len(set(referenced_sources)):
            errors.append(f"{label}.source_ids must not contain duplicates")
        unknown_sources = sorted(set(referenced_sources) - source_ids)
        if unknown_sources:
            errors.append(f"{label}.source_ids references unknown sources: {unknown_sources}")
        if status in SOURCE_REQUIRED_STATUSES and not referenced_sources:
            errors.append(f"{label}.source_ids must not be empty for status {status}")
        if status == "unsupported" and claim.get("evidence_note") != "No reliable source found":
            errors.append(
                f"{label}.evidence_note must be exactly 'No reliable source found' for unsupported claims"
            )
        if status == "not_checkable" and claim.get("checkability") != "not_checkable":
            errors.append(f"{label}.checkability must be not_checkable when status is not_checkable")
        if claim.get("checkability") == "not_checkable" and status != "not_checkable":
            errors.append(f"{label}.status must be not_checkable when checkability is not_checkable")
    return errors, valid_claims


def expected_publication_status(claims: list[dict[str, Any]]) -> str:
    for claim in claims:
        if claim.get("importance") == "load_bearing" and claim.get("status") in {
            "unsupported",
            "contradicted",
        }:
            return "blocked"
    for claim in claims:
        status = claim.get("status")
        if status in UNRESOLVED_STATUSES:
            return "needs_revision"
        if status == "inference" and claim.get("disposition") not in INFERENCE_VISIBLE_DISPOSITIONS:
            return "needs_revision"
    return "pass"


def validate_result(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return ["fact-check result must be a JSON object"]
    errors: list[str] = []
    if payload.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    if not _non_empty_string(payload.get("fact_check_id")):
        errors.append("fact_check_id must be a non-empty string")
    if not _non_empty_string(payload.get("checked_at")):
        errors.append("checked_at must be a non-empty date-time string")
    if payload.get("review_status") not in VALID_REVIEW_STATUS:
        errors.append(f"review_status must be one of {sorted(VALID_REVIEW_STATUS)}")
    errors.extend(_validate_artifact(payload.get("artifact")))
    source_errors, source_ids = _validate_sources(payload.get("sources"))
    errors.extend(source_errors)
    claim_errors, claims = _validate_claims(payload.get("claims"), source_ids)
    errors.extend(claim_errors)
    unresolved = payload.get("unresolved_claim_ids")
    if not _string_array(unresolved):
        errors.append("unresolved_claim_ids must be an array of non-empty claim IDs")
        unresolved = []
    if len(unresolved) != len(set(unresolved)):
        errors.append("unresolved_claim_ids must not contain duplicates")
    known_claim_ids = {claim.get("claim_id") for claim in claims if _non_empty_string(claim.get("claim_id"))}
    unknown_unresolved = sorted(set(unresolved) - known_claim_ids)
    if unknown_unresolved:
        errors.append(f"unresolved_claim_ids references unknown claims: {unknown_unresolved}")
    expected_unresolved = {
        claim["claim_id"]
        for claim in claims
        if _non_empty_string(claim.get("claim_id")) and claim.get("status") in UNRESOLVED_STATUSES
    }
    if set(unresolved) != expected_unresolved:
        errors.append(
            "unresolved_claim_ids must exactly match partially_supported, unsupported, and contradicted claims: "
            f"expected {sorted(expected_unresolved)}, got {sorted(set(unresolved))}"
        )
    if not _string_array(payload.get("limitations")):
        errors.append("limitations must be an array of non-empty strings")
    declared_status = payload.get("publication_status")
    if declared_status not in VALID_PUBLICATION_STATUS:
        errors.append(f"publication_status must be one of {sorted(VALID_PUBLICATION_STATUS)}")
    calculated_status = expected_publication_status(claims)
    if declared_status in VALID_PUBLICATION_STATUS and declared_status != calculated_status:
        errors.append(
            f"publication_status must match the deterministic factual-readiness gate: "
            f"expected {calculated_status}, got {declared_status}"
        )
    return errors


def _resolve_artifact(reference: str, artifact_root: Path) -> Path:
    root = artifact_root.expanduser().resolve()
    candidate = Path(reference).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError("artifact.reference resolves outside --artifact-root") from error
    return resolved


def validate_artifact_digest(payload: dict[str, Any], artifact_root: Path) -> list[str]:
    artifact = payload.get("artifact")
    if not isinstance(artifact, dict) or not _non_empty_string(artifact.get("reference")):
        return ["cannot check artifact digest without artifact.reference"]
    try:
        path = _resolve_artifact(artifact["reference"], artifact_root)
    except ValueError as error:
        return [str(error)]
    if not path.is_file():
        return [f"artifact file does not exist: {path}"]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != artifact.get("sha256"):
        return [f"artifact.sha256 mismatch: expected {artifact.get('sha256')}, calculated {digest}"]
    return []


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    parser.add_argument("--check-artifact", action="store_true")
    parser.add_argument("--artifact-root", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        payload = json.loads(args.result.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR: could not load fact-check result: {error}")
        return 1
    errors = validate_result(payload)
    if args.check_artifact:
        if args.artifact_root is None:
            errors.append("--artifact-root is required with --check-artifact")
        elif isinstance(payload, dict):
            errors.extend(validate_artifact_digest(payload, args.artifact_root))
    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        print(f"Validation failed: {len(errors)} error(s)")
        return 1
    print(
        f"Validation passed: {len(payload.get('claims', []))} claim(s), "
        f"publication_status={payload.get('publication_status')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
