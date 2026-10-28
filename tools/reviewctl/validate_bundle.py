#!/usr/bin/env python3
"""Validate and compose the portable threat-modeling-flow bundle."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

BUNDLE_SCHEMA = "threat-modeling-bundle/v1"
FIXTURE_SCHEMA = "threat-modeling-flow-fixture/v1"
CORE_STAGE_IDS = [
    "what-are-we-building",
    "dfd-mermaid",
    "what-can-go-wrong",
    "what-are-we-going-to-do-about-it",
    "did-we-do-a-good-enough-job",
]
HEX40 = re.compile(r"^[0-9a-f]{40}$")


class BundleError(RuntimeError):
    """Raised when the bundle fails closed."""


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BundleError(f"{label}: cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise BundleError(f"{label}: top-level value must be an object")
    return value


def safe_path(root: Path, value: str, field: str, *, must_exist: bool = True) -> Path:
    relative = Path(value)
    if not value or relative.is_absolute() or ".." in relative.parts:
        raise BundleError(f"{field}: must be a safe package-relative path")
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise BundleError(f"{field}: escapes the package root") from error
    if must_exist and not candidate.exists():
        raise BundleError(f"{field}: missing required path {value}")
    return candidate


def require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BundleError(f"{field}: must be a non-empty string")
    return value


def validate_manifest(manifest_path: Path) -> tuple[dict[str, Any], Path, list[str]]:
    manifest = load_json(manifest_path, "bundle")
    if manifest.get("schema_version") != BUNDLE_SCHEMA:
        raise BundleError(
            f"bundle.schema_version: expected {BUNDLE_SCHEMA}, "
            f"found {manifest.get('schema_version')!r}"
        )
    if manifest.get("publication_status") != "publication_review_required":
        raise BundleError(
            "bundle.publication_status: bundle validation is not publication approval"
        )

    package_root = manifest_path.resolve().parents[1]
    require_string(manifest.get("bundle_id"), "bundle.bundle_id")

    stages = manifest.get("ordered_stages")
    if not isinstance(stages, list):
        raise BundleError("bundle.ordered_stages: must be an array")
    stage_ids = [
        stage.get("skill_id") if isinstance(stage, dict) else None for stage in stages
    ]
    if stage_ids != CORE_STAGE_IDS:
        raise BundleError(
            "bundle.ordered_stages: must preserve the canonical five-stage order"
        )

    checks: list[str] = []
    catalog = load_json(package_root / "catalog.yaml", "catalog")
    inventory = {row["id"]: row for row in catalog["skills"]}
    for category in ("entrypoints", "horizontal_layers"):
        for row in manifest.get(category, []):
            identifier = row.get("skill_id")
            if identifier not in inventory or row.get("source_commit") != inventory[identifier]["source"]["commit"]:
                raise BundleError(f"{category}: missing or mismatched skill pin")
            for value in row.get("required_paths", []):
                safe_path(package_root, value, category)
            checks.append(f"{category}:{identifier}:pinned-and-present")
    if catalog.get("catalog_version", 0) >= 3:
        horizontal = package_root / "skills/w3c-horizontal-review/references/extractors.json"
        registry = load_json(horizontal, "extractor registry")
        expected = {row["id"] for row in registry["extractors"]}
        actual = [row["skill_id"] for row in manifest.get("horizontal_layers", [])]
        if set(actual) != expected or len(actual) != len(expected):
            raise BundleError("horizontal layer inventory does not match the registered extractors")
    for index, stage in enumerate(stages):
        assert isinstance(stage, dict)
        label = f"bundle.ordered_stages[{index}]"
        commit = require_string(stage.get("source_commit"), f"{label}.source_commit")
        if not HEX40.fullmatch(commit):
            raise BundleError(f"{label}.source_commit: must be an exact 40-hex pin")
        inputs = stage.get("input_contracts")
        outputs = stage.get("output_contracts")
        if not isinstance(inputs, list) or not all(isinstance(item, str) and item for item in inputs):
            raise BundleError(f"{label}.input_contracts: must be an array of contract IDs")
        if not isinstance(outputs, list) or not all(isinstance(item, str) and item for item in outputs):
            raise BundleError(f"{label}.output_contracts: must be an array of contract IDs")
        paths = stage.get("required_paths")
        if not isinstance(paths, list) or not paths:
            raise BundleError(f"{label}.required_paths: must be a non-empty array")
        for path_index, value in enumerate(paths):
            safe_path(package_root, str(value), f"{label}.required_paths[{path_index}]")
        checks.append(f"stage:{stage['skill_id']}:pinned-and-present")

    handoffs = manifest.get("handoffs")
    if not isinstance(handoffs, list) or len(handoffs) != len(CORE_STAGE_IDS) - 1:
        raise BundleError("bundle.handoffs: must describe every adjacent core handoff")
    for index, row in enumerate(handoffs):
        if not isinstance(row, dict):
            raise BundleError(f"bundle.handoffs[{index}]: must be an object")
        if row.get("from") != CORE_STAGE_IDS[index] or row.get("to") != CORE_STAGE_IDS[index + 1]:
            raise BundleError(f"bundle.handoffs[{index}]: does not match canonical stage order")
        contracts = row.get("contracts")
        if not isinstance(contracts, list) or not contracts:
            raise BundleError(f"bundle.handoffs[{index}].contracts: must be non-empty")

    # A handoff may retain upstream artifacts; it must not invent them or omit
    # the next stage's declared inputs.
    available = set(stages[0]["input_contracts"])
    for index, stage in enumerate(stages):
        missing = set(stage["input_contracts"]) - available
        if missing:
            raise BundleError(f"stage {stage['skill_id']}: unavailable input contracts {sorted(missing)}")
        available.update(stage["output_contracts"])
        if index < len(handoffs):
            carried = set(handoffs[index]["contracts"])
            unknown = carried - available
            if unknown:
                raise BundleError(f"handoff {index}: unavailable artifact contracts {sorted(unknown)}")
            missing = set(stages[index + 1]["input_contracts"]) - carried
            if missing:
                raise BundleError(f"handoff {index}: missing receiver input contracts {sorted(missing)}")

    shared = manifest.get("shared_contract")
    if not isinstance(shared, dict) or shared.get("version") != 1:
        raise BundleError("bundle.shared_contract: contract version 1 is required")
    contract_root = safe_path(
        package_root, require_string(shared.get("root"), "bundle.shared_contract.root"),
        "bundle.shared_contract.root"
    )
    validator = safe_path(
        package_root,
        require_string(shared.get("validator"), "bundle.shared_contract.validator"),
        "bundle.shared_contract.validator",
    )
    try:
        validator.relative_to(contract_root)
    except ValueError as error:
        raise BundleError(
            "bundle.shared_contract.validator: must be inside the canonical contract root"
        ) from error
    checks.append("shared-contract:present")

    providers = manifest.get("providers")
    if not isinstance(providers, list) or not providers:
        raise BundleError("bundle.providers: must be a non-empty array")
    for index, provider in enumerate(providers):
        if not isinstance(provider, dict):
            raise BundleError(f"bundle.providers[{index}]: must be an object")
        require_string(provider.get("interface"), f"bundle.providers[{index}].interface")
        if provider.get("public_default") not in {"offline", "none", "caller-supplied"}:
            raise BundleError(
                f"bundle.providers[{index}].public_default: unsupported public default"
            )
        if provider.get("private_required") is True:
            raise BundleError(
                f"bundle.providers[{index}]: a private provider cannot be required by the public bundle"
            )

    hosts = manifest.get("host_projections")
    if not isinstance(hosts, list) or set(hosts) != {"codex", "claude"}:
        raise BundleError(
            "bundle.host_projections: Codex and Claude must preserve the same portable core"
        )

    artifact_root = manifest.get("artifact_root")
    if not isinstance(artifact_root, dict) or artifact_root.get("caller_supplied") is not True:
        raise BundleError("bundle.artifact_root: a caller-supplied root is required")
    if artifact_root.get("publication_authorized") is not False:
        raise BundleError(
            "bundle.artifact_root.publication_authorized: validation must not authorize publication"
        )

    return manifest, package_root, checks


def _identity(artifact: dict[str, Any], field: str) -> str | None:
    value = artifact.get(field)
    return value if isinstance(value, str) and value else None


def validate_fixture(
    manifest: dict[str, Any],
    package_root: Path,
    fixture_path: Path,
) -> tuple[str, list[str]]:
    fixture = load_json(fixture_path, "fixture")
    if fixture.get("schema_version") != FIXTURE_SCHEMA:
        raise BundleError(
            f"fixture.schema_version: expected {FIXTURE_SCHEMA}, "
            f"found {fixture.get('schema_version')!r}"
        )
    outcome = fixture.get("expected_outcome")
    if outcome not in {"complete", "partial", "blocked"}:
        raise BundleError("fixture.expected_outcome: must be complete, partial, or blocked")
    if fixture.get("publication_authorized") is not False:
        raise BundleError("fixture.publication_authorized: must remain false")

    artifacts = fixture.get("artifacts")
    if not isinstance(artifacts, dict):
        raise BundleError("fixture.artifacts: must be an object")

    loaded: dict[str, dict[str, Any]] = {}
    paths: dict[str, Path] = {}
    for key, value in artifacts.items():
        if not isinstance(value, str):
            raise BundleError(f"fixture.artifacts.{key}: must be a relative path")
        path = safe_path(package_root, value, f"fixture.artifacts.{key}")
        paths[key] = path
        if path.suffix == ".json":
            loaded[key] = load_json(path, f"fixture.artifacts.{key}")

    for field in ("run_id", "target_id"):
        values = {
            value
            for artifact in loaded.values()
            if (value := _identity(artifact, field)) is not None
        }
        if len(values) > 1:
            raise BundleError(f"fixture: shared {field} identity mismatch: {sorted(values)}")

    model_id_values = {
        value
        for key in ("model", "dictionary", "threats", "responses")
        if key in loaded
        if (value := _identity(loaded[key], "model_id")) is not None
    }
    if len(model_id_values) > 1:
        raise BundleError(f"fixture: model_id mismatch: {sorted(model_id_values)}")

    if "threats" in loaded and "responses" in loaded:
        threat_package_id = _identity(loaded["threats"], "threat_package_id")
        response_threat_package_id = _identity(loaded["responses"], "threat_package_id")
        if threat_package_id != response_threat_package_id:
            raise BundleError("fixture: response package references a different threat package")

    provider_requirements = fixture.get("provider_requirements", [])
    if not isinstance(provider_requirements, list):
        raise BundleError("fixture.provider_requirements: must be an array")
    unavailable = [
        row.get("interface")
        for row in provider_requirements
        if isinstance(row, dict) and row.get("available") is False
    ]
    if unavailable:
        if outcome != "blocked":
            raise BundleError(
                f"fixture: unavailable providers require blocked outcome: {unavailable}"
            )
        return "blocked", [f"provider-unavailable:{item}" for item in unavailable]

    shared = manifest["shared_contract"]
    validator = safe_path(
        package_root, str(shared["validator"]), "bundle.shared_contract.validator"
    )
    contract_keys = [key for key in ("model", "dictionary", "threats", "responses", "handoff") if key in paths]
    if outcome in {"complete", "partial"} and not contract_keys:
        raise BundleError("fixture: complete or partial outcomes require contract artifacts")

    command = [sys.executable, str(validator)]
    for key in contract_keys:
        command.extend([f"--{key}", str(paths[key])])
    if outcome == "complete":
        for required in ("model", "dictionary", "threats", "responses"):
            if required not in paths:
                raise BundleError(f"fixture: complete outcome requires {required}")
        command.append("--require-complete-response-coverage")

    result = subprocess.run(command, text=True, capture_output=True, check=False)
    expected_contract_failure = fixture.get("expected_contract_failure") is True
    if expected_contract_failure:
        if outcome != "blocked":
            raise BundleError("fixture.expected_contract_failure requires blocked outcome")
        if result.returncode == 0:
            raise BundleError("fixture: expected the shared contract to fail closed")
        return "blocked", ["shared-contract:failed-as-expected"]

    if result.returncode != 0:
        detail = (result.stdout + result.stderr).strip()
        raise BundleError(f"fixture: shared contract validation failed: {detail}")

    gate = loaded.get("quality_gate")
    if gate is not None:
        gate_outcome = gate.get("outcome")
        expected_gate = {"complete": "pass", "partial": "partial", "blocked": "blocked"}[outcome]
        if gate_outcome != expected_gate:
            raise BundleError(
                f"fixture.quality_gate.outcome: expected {expected_gate}, found {gate_outcome!r}"
            )
        if gate.get("publication_authorized") is not False:
            raise BundleError("fixture.quality_gate: must not authorize publication")

    fact_check = loaded.get("fact_check")
    if outcome == "complete":
        if fact_check is None or fact_check.get("status") != "passed":
            raise BundleError("fixture: complete outcome requires a passed fact-check result")
        if fact_check.get("publication_authorized") is not False:
            raise BundleError("fixture.fact_check: must not authorize publication")

    return outcome, ["shared-contract:pass", f"fixture:{outcome}"]


def validate_bundle(
    manifest_path: Path,
    fixture_path: Path | None = None,
) -> dict[str, Any]:
    manifest, package_root, checks = validate_manifest(manifest_path)
    fixture = fixture_path
    if fixture is None:
        default_fixture = manifest.get("default_fixture")
        if isinstance(default_fixture, str) and default_fixture:
            fixture = safe_path(package_root, default_fixture, "bundle.default_fixture")
    outcome = None
    if fixture is not None:
        outcome, fixture_checks = validate_fixture(manifest, package_root, fixture)
        checks.extend(fixture_checks)
    return {
        "schema_version": "bundle-validation-result/v1",
        "bundle_id": manifest["bundle_id"],
        "status": "pass",
        "fixture_outcome": outcome,
        "publication_authorized": False,
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reviewctl validate-bundle", description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--fixture", type=Path)
    args = parser.parse_args(argv)
    try:
        result = validate_bundle(args.manifest, args.fixture)
    except BundleError as error:
        print(json.dumps({
            "schema_version": "bundle-validation-result/v1",
            "status": "blocked",
            "publication_authorized": False,
            "error": str(error),
        }, indent=2, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
