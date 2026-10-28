"""Validation contract for bounded local proof-of-concept evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


POC_CLASSES = {"executable", "browser", "documentary", "model"}
VERIFICATION_SCOPES = {
    "specification_mechanism",
    "process_condition",
    "model_consequence",
    "implementation_behavior",
}
VERIFICATION_STATUSES = {"verified", "unable_to_verify", "not_reproduced"}
CASE_NAMES = ("positive", "negative", "mitigated")
CASE_STATUSES = {"pass", "fail", "unable"}


@dataclass(frozen=True)
class PocValidationResult:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.errors


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _string_list(value: Any) -> bool:
    return isinstance(value, list) and all(_non_empty_string(item) for item in value)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_poc_document(document: Any, *, base_dir: Path) -> PocValidationResult:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(document, dict):
        return PocValidationResult(("document must be a JSON object",), ())

    if document.get("artifact_kind") != "bounded_local_poc":
        errors.append("artifact_kind must be bounded_local_poc")
    if document.get("schema_version") != 1:
        errors.append("schema_version must be 1")

    poc_class = document.get("poc_class")
    if poc_class not in POC_CLASSES:
        errors.append(f"poc_class must be one of {sorted(POC_CLASSES)}")
    scope = document.get("verification_scope")
    if scope not in VERIFICATION_SCOPES:
        errors.append(f"verification_scope must be one of {sorted(VERIFICATION_SCOPES)}")
    if poc_class in {"documentary", "model"} and scope == "implementation_behavior":
        errors.append(f"{poc_class} PoCs cannot claim implementation_behavior")

    status = document.get("verification_status")
    if status not in VERIFICATION_STATUSES:
        errors.append(f"verification_status must be one of {sorted(VERIFICATION_STATUSES)}")

    environment = document.get("environment")
    if not isinstance(environment, dict):
        errors.append("environment must be an object")
    else:
        if not _non_empty_string(environment.get("identity")):
            errors.append("environment.identity must be a non-empty string")
        if not _non_empty_string(environment.get("command")):
            errors.append("environment.command must be a non-empty string")
        host = environment.get("host")
        if poc_class in {"executable", "browser"} and host not in {None, "127.0.0.1"}:
            errors.append("executable and browser PoCs may bind only to 127.0.0.1")

    safety = document.get("safety")
    if not isinstance(safety, dict):
        errors.append("safety must be an object")
    else:
        if safety.get("synthetic_inputs") is not True:
            errors.append("safety.synthetic_inputs must be true")
        if safety.get("real_credentials") is not False:
            errors.append("safety.real_credentials must be false")
        if safety.get("external_endpoints") is not False:
            errors.append("safety.external_endpoints must be false")

    cases = document.get("cases")
    case_statuses: list[str] = []
    if not isinstance(cases, dict):
        errors.append("cases must be an object")
    else:
        for name in CASE_NAMES:
            case = cases.get(name)
            if not isinstance(case, dict):
                errors.append(f"cases.{name} must be an object")
                continue
            if not _non_empty_string(case.get("expected")):
                errors.append(f"cases.{name}.expected must be a non-empty string")
            if not _non_empty_string(case.get("observed")):
                errors.append(f"cases.{name}.observed must be a non-empty string")
            case_status = case.get("status")
            if case_status not in CASE_STATUSES:
                errors.append(f"cases.{name}.status must be one of {sorted(CASE_STATUSES)}")
            else:
                case_statuses.append(case_status)
    if status == "verified" and case_statuses != ["pass", "pass", "pass"]:
        errors.append("verified PoCs require positive, negative, and mitigated cases to pass")
    if status == "unable_to_verify" and "unable" not in case_statuses:
        warnings.append("unable_to_verify should normally include an unable case")

    claims = document.get("claims")
    if not isinstance(claims, dict):
        errors.append("claims must be an object")
    else:
        if not _string_list(claims.get("demonstrates")) or not claims.get("demonstrates"):
            errors.append("claims.demonstrates must be a non-empty string list")
        if not _string_list(claims.get("does_not_demonstrate")) or not claims.get("does_not_demonstrate"):
            errors.append("claims.does_not_demonstrate must be a non-empty string list")

    concept = document.get("concept")
    if not isinstance(concept, dict):
        errors.append("concept must be an object")
    else:
        if not _non_empty_string(concept.get("concept_id")):
            errors.append("concept.concept_id must be a non-empty string")
        if not _non_empty_string(concept.get("description")):
            errors.append("concept.description must be a non-empty string")

    artifacts = document.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("artifacts must be a non-empty list")
    else:
        resolved_base = base_dir.resolve()
        for index, artifact in enumerate(artifacts):
            prefix = f"artifacts[{index}]"
            if not isinstance(artifact, dict):
                errors.append(f"{prefix} must be an object")
                continue
            relative = artifact.get("path")
            expected_hash = artifact.get("sha256")
            if not _non_empty_string(relative):
                errors.append(f"{prefix}.path must be a non-empty relative path")
                continue
            path = (resolved_base / relative).resolve()
            try:
                path.relative_to(resolved_base)
            except ValueError:
                errors.append(f"{prefix}.path escapes the PoC directory")
                continue
            if not path.is_file():
                errors.append(f"{prefix}.path does not exist: {relative}")
                continue
            if not isinstance(expected_hash, str) or len(expected_hash) != 64:
                errors.append(f"{prefix}.sha256 must be a 64-character digest")
            elif _sha256(path) != expected_hash.lower():
                errors.append(f"{prefix}.sha256 does not match {relative}")

    return PocValidationResult(tuple(errors), tuple(warnings))


def validate_poc_file(path: Path) -> PocValidationResult:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return PocValidationResult((f"cannot read evidence: {exc}",), ())
    return validate_poc_document(document, base_dir=path.parent)
