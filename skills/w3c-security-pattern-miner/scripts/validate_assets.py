#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT
REF = SKILL / "references"
ASSETS = SKILL / "assets"
CATALOG = ROOT / "catalog"
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "tests" / "fixtures"
EVALS = ROOT / "evals"

EVIDENCE_CLASSES = {
    "explicit-normative",
    "explicit-informative",
    "derived-from-normative-behavior",
    "derived-from-algorithm",
    "derived-from-cross-reference",
    "review-observed",
    "resolution-validated",
    "implementation-observed",
    "hypothesis",
}
MATURITIES = {"seed", "candidate", "observed", "recurring", "validated", "deprecated"}
RESULTS = {"pass", "partial", "fail", "unknown", "not-applicable", "not-evaluated"}
SCOPES = {"specification-design", "implementation-conformance", "deployment-operation"}


def load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc


def confidence(value: Any) -> bool:
    return isinstance(value, (int, float)) and 0 <= value <= 1


def validate_observation(obs: dict[str, Any], where: str, categories: set[str], errors: list[str]) -> None:
    required = {"observation_id", "spec_id", "spec_version", "observation_type", "statement", "security_category", "evidence_class", "evidence", "confidence"}
    missing = required - set(obs)
    if missing:
        errors.append(f"{where}: observation missing {sorted(missing)}")
        return
    if obs["security_category"] not in categories:
        errors.append(f"{where}: unknown category {obs['security_category']}")
    if obs["evidence_class"] not in EVIDENCE_CLASSES:
        errors.append(f"{where}: invalid evidence_class {obs['evidence_class']}")
    if not confidence(obs["confidence"]):
        errors.append(f"{where}: confidence out of range")
    if obs["evidence_class"] != "hypothesis" and not obs.get("evidence"):
        errors.append(f"{where}: non-hypothesis observation requires evidence")
    evidence = obs.get("evidence")
    if not isinstance(evidence, list):
        errors.append(f"{where}: evidence must be an array")
        return
    for ev in evidence:
        if not isinstance(ev, dict):
            errors.append(f"{where}: evidence item must be an object")
            continue
        for key in ("source_id", "artifact_id", "locator", "evidence_span", "interpretation"):
            if key not in ev:
                errors.append(f"{where}: evidence missing {key}")


def validate_pattern(pattern: dict[str, Any], where: str, categories: set[str], errors: list[str]) -> None:
    required = {"pattern_id", "conceptual_key", "category", "applicability", "occurrence_ids", "evidence_classes", "provenance", "confidence", "maturity"}
    missing = required - set(pattern)
    if missing:
        errors.append(f"{where}: pattern missing {sorted(missing)}")
        return
    if pattern["category"] not in categories:
        errors.append(f"{where}: unknown pattern category {pattern['category']}")
    if pattern["maturity"] not in MATURITIES:
        errors.append(f"{where}: invalid maturity {pattern['maturity']}")
    if not confidence(pattern["confidence"]):
        errors.append(f"{where}: confidence out of range")
    for cls in pattern.get("evidence_classes", []):
        if cls not in EVIDENCE_CLASSES:
            errors.append(f"{where}: invalid pattern evidence class {cls}")
    prov = pattern.get("provenance", {})
    if pattern["maturity"] == "seed":
        if pattern.get("occurrence_ids") or pattern.get("evidence_classes"):
            errors.append(f"{where}: seed pattern must not contain fabricated occurrences or evidence classes")
        if prov.get("supporting_specifications") != 0 or prov.get("supporting_occurrences") != 0:
            errors.append(f"{where}: seed provenance counts must be zero")
    elif not pattern.get("occurrence_ids") and pattern["maturity"] != "deprecated":
        errors.append(f"{where}: non-seed pattern requires occurrence support")


def validate_check(check: dict[str, Any], where: str, pattern_ids: set[str], categories: set[str], errors: list[str]) -> None:
    required = {"check_id", "pattern_id", "category", "scope", "question", "applicability", "evidence_to_collect", "pass_criteria", "partial_criteria", "fail_criteria", "unknown_criteria", "not_applicable_criteria", "result", "evidence", "maturity"}
    missing = required - set(check)
    if missing:
        errors.append(f"{where}: check missing {sorted(missing)}")
        return
    if check["pattern_id"] not in pattern_ids:
        errors.append(f"{where}: unknown pattern_id {check['pattern_id']}")
    if check["category"] not in categories:
        errors.append(f"{where}: unknown check category {check['category']}")
    if check["scope"] not in SCOPES:
        errors.append(f"{where}: invalid scope {check['scope']}")
    if check["result"] not in RESULTS:
        errors.append(f"{where}: invalid result {check['result']}")
    if check["maturity"] not in MATURITIES:
        errors.append(f"{where}: invalid maturity {check['maturity']}")
    for key in ("evidence_to_collect", "pass_criteria", "partial_criteria", "fail_criteria", "unknown_criteria", "not_applicable_criteria"):
        if not check.get(key):
            errors.append(f"{where}: {key} must be non-empty")
    if check["result"] == "fail" and not check.get("evidence"):
        errors.append(f"{where}: fail requires affirmative evidence")


def validate_result(result: dict[str, Any], where: str, categories: set[str], errors: list[str], pattern_ids: set[str] | None = None) -> None:
    if not isinstance(result, dict):
        errors.append(f"{where}: result must be an object")
        return
    missing = {"mode", "specification", "observations", "security_checks"} - result.keys()
    if missing:
        errors.append(f"{where}: result missing {sorted(missing)}")
    if result.get("mode") != "mine-spec":
        errors.append(f"{where}: missing or invalid mode; expected mine-spec")
    spec = result.get("specification")
    if not isinstance(spec, dict):
        errors.append(f"{where}: specification must be an object")
        spec = {}
    spec_id = spec.get("spec_id")
    version = spec.get("version")
    if not spec_id or not version:
        errors.append(f"{where}: specification requires spec_id and version")

    def objects(key: str) -> list[tuple[int, dict[str, Any]]]:
        values = result.get(key, [])
        if not isinstance(values, list):
            errors.append(f"{where}: {key} must be an array")
            return []
        valid = []
        for index, item in enumerate(values):
            if not isinstance(item, dict):
                errors.append(f"{where}: {key}[{index}] must be an object")
            else:
                valid.append((index, item))
        return valid

    for _, obs in objects("observations"):
        validate_observation(obs, f"{where}:{obs.get('observation_id')}", categories, errors)
        if spec_id and version and (obs.get("spec_id") != spec_id or obs.get("spec_version") != version):
            errors.append(f"{where}: mixed specification or version in {obs.get('observation_id')}")
    derived = objects("derived_pattern_candidates")
    for _, item in derived:
        chain = item.get("derivation_chain")
        if not isinstance(chain, dict) or not chain:
            errors.append(f"{where}: derived candidate missing derivation_chain object")
        else:
            for key in ("premises", "inference_rule", "conclusion", "alternative_interpretation", "missing_evidence", "confidence"):
                if key not in chain:
                    errors.append(f"{where}: derivation_chain missing {key}")
            if "confidence" in chain and not confidence(chain["confidence"]):
                errors.append(f"{where}: derivation confidence out of range")
    for _, item in objects("not_applicable_categories"):
        if not item.get("reason"):
            errors.append(f"{where}: not-applicable category missing reason")
    known_patterns = set(pattern_ids or ())
    for _, item in objects("explicit_patterns") + derived:
        if isinstance(item.get("pattern_id"), str):
            known_patterns.add(item["pattern_id"])
    for index, check in objects("security_checks"):
        validate_check(check, f"{where}:security_checks[{index}]", known_patterns, categories, errors)


def main() -> int:
    errors: list[str] = []
    for path in list(ROOT.rglob("*.json")):
        if ".git" not in path.parts:
            try:
                load(path)
            except ValueError as exc:
                errors.append(str(exc))

    taxonomy = load(REF / "security-taxonomy.json")
    categories = {c["category_id"] for c in taxonomy.get("categories", [])}
    if len(categories) < 36:
        errors.append("security-taxonomy.json: expected at least 36 categories")
    for cat in taxonomy.get("categories", []):
        for key in ("definition", "positive_signals", "exclusion_signals", "common_assets", "common_actors", "common_trust_boundaries", "expected_security_properties", "frequent_threats", "typical_mechanisms", "common_anti_patterns", "evidence_locations_to_inspect", "possible_reusable_checks", "confusion_risks"):
            if not cat.get(key):
                errors.append(f"{cat.get('category_id')}: missing or empty {key}")

    patterns_data = load(CATALOG / "security-patterns.json")
    checks_data = load(CATALOG / "security-checks.json")
    patterns = patterns_data.get("patterns", [])
    checks = checks_data.get("checks", [])
    if len(patterns) < 50:
        errors.append(f"catalog: expected at least 50 seed patterns, found {len(patterns)}")
    if len(checks) < 60:
        errors.append(f"catalog: expected at least 60 seed checks, found {len(checks)}")

    pattern_ids = set()
    conceptual_keys = set()
    for pattern in patterns:
        pid = pattern.get("pattern_id")
        if pid in pattern_ids:
            errors.append(f"duplicate pattern_id {pid}")
        pattern_ids.add(pid)
        key = pattern.get("conceptual_key")
        if key in conceptual_keys:
            errors.append(f"duplicate conceptual_key {key}")
        conceptual_keys.add(key)
        validate_pattern(pattern, f"catalog:{pid}", categories, errors)

    check_ids = set()
    for check in checks:
        cid = check.get("check_id")
        if cid in check_ids:
            errors.append(f"duplicate check_id {cid}")
        check_ids.add(cid)
        validate_check(check, f"catalog:{cid}", pattern_ids, categories, errors)

    occ = load(CATALOG / "occurrences.json").get("occurrences", [])
    for item in occ:
        if len({ev.get("spec_version") for ev in item.get("evidence", []) if ev.get("spec_version")}) > 1:
            errors.append(f"occurrence {item.get('occurrence_id')}: mixed versions")

    asset_objects = [(path, load(path)) for path in sorted(ASSETS.glob("*.json"))]
    asset_pattern_ids = {
        obj["pattern_id"] for _, obj in asset_objects
        if "conceptual_key" in obj and isinstance(obj.get("pattern_id"), str)
    }
    known_patterns = pattern_ids | asset_pattern_ids
    for path, obj in asset_objects:
        if "observation_id" in obj:
            validate_observation(obj, f"asset:{path.name}", categories, errors)
        if "pattern_id" in obj and "conceptual_key" in obj:
            validate_pattern(obj, f"asset:{path.name}", categories, errors)
        if "check_id" in obj:
            validate_check(obj, f"asset:{path.name}", known_patterns, categories, errors)
        if obj.get("mode") == "mine-spec" or "observations" in obj:
            validate_result(obj, f"asset:{path.name}", categories, errors, known_patterns)

    for path in sorted(FIXTURES.glob("*.json")):
        if path.name == "mixed-version-invalid.json":
            continue
        validate_result(load(path), f"fixture:{path.name}", categories, errors, known_patterns)

    for path in sorted(SCHEMAS.glob("*.json")):
        obj = load(path)
        if obj.get("type") != "object":
            errors.append(f"schema {path.name}: root type must be object")

    eval_count = 0
    for line in (EVALS / "prompts.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        eval_count += 1
        obj = json.loads(line)
        for key in ("eval_id", "prompt", "should_trigger", "prohibited_claims", "expected_evidence_behavior"):
            if key not in obj:
                errors.append(f"eval line {eval_count}: missing {key}")
    if eval_count < 16:
        errors.append(f"evals: expected at least 16 prompts, found {eval_count}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Asset validation passed.")
    print(f"categories: {len(categories)}")
    print(f"seed patterns: {len(patterns)}")
    print(f"seed checks: {len(checks)}")
    print(f"eval prompts: {eval_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
