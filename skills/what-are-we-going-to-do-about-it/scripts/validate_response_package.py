"""Validate a response-package v1 JSON file through the shared contract."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


GENERIC_RESPONSE_RE = re.compile(
    r"^\s*(?:improve|enhance|ensure|address)\s+(?:security|privacy|safety)|"
    r"^\s*validate inputs?\s*$|"
    r"^\s*document (?:the )?(?:risk|threat|issue)\s*$|"
    r"^\s*(?:route|add) (?:this )?(?:to|in) (?:the )?(?:security|privacy) considerations\s*$|"
    r"^\s*(?:use|apply|follow) (?:appropriate )?(?:controls|guidance|mitigations|best practices?)\s*$",
    re.IGNORECASE,
)


def _non_empty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _non_empty_string_array(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(_non_empty(item) for item in value)
    )


def _validate_v1_record_shape(response: dict[str, Any], label: str) -> list[str]:
    errors: list[str] = []
    if "model_element" in response:
        errors.append(
            f"{label}: model_element is a legacy singular field; "
            "use affected_model_elements with canonical model IDs"
        )
    if not _non_empty_string_array(response.get("affected_model_elements")):
        errors.append(
            f"{label}: affected_model_elements must be a non-empty array of canonical model IDs"
        )
    for field in ("response_id", "threat_id"):
        if not _non_empty(response.get(field)):
            errors.append(f"{label}: {field} must be a non-empty string")
    next_action = response.get("next_action")
    if not _non_empty(next_action):
        if isinstance(next_action, dict):
            errors.append(
                f"{label}: next_action must be a non-empty string; "
                "structured action objects are not part of response-package v1"
            )
        else:
            errors.append(f"{label}: response needs a testable next_action")
    return errors


def validate_specific_responses(package: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(package, dict):
        return ["response package must be a JSON object"]
    responses = package.get("responses")
    if not isinstance(responses, list):
        return ["responses must be an array"]
    for index, response in enumerate(responses):
        label = f"responses[{index}]"
        if not isinstance(response, dict):
            errors.append(f"{label} must be an object")
            continue

        errors.extend(_validate_v1_record_shape(response, label))

        if response.get("erta") == "Unresolved":
            if not _non_empty(response.get("owner")):
                errors.append(f"{label}: Unresolved needs a decision owner")
            continue

        mechanism = response.get("mechanism_or_text")
        owner = response.get("owner")
        if not _non_empty(mechanism):
            errors.append(f"{label}: response needs a threat-specific mechanism_or_text")
        if not _non_empty(owner):
            errors.append(f"{label}: response needs a responsible owner")
        combined = " ".join(
            str(response.get(field, ""))
            for field in ("response", "mechanism_or_text")
        ).strip()
        if GENERIC_RESPONSE_RE.search(combined) or GENERIC_RESPONSE_RE.fullmatch(str(mechanism or "").strip()):
            errors.append(f"{label}: generic keyword-routing text is not a specific response")
    return errors


def resolve_contract_root() -> Path:
    explicit = os.environ.get("STANDARDS_REVIEW_CONTRACTS_ROOT")
    repository_root = Path(__file__).resolve().parents[1]
    candidates = [Path(explicit)] if explicit else []
    candidates.extend([repository_root, repository_root.parents[1]])
    for candidate in candidates:
        if (candidate / "scripts" / "validate_threat_model_contract.py").is_file():
            return candidate
    raise SystemExit(
        "Cannot find the shared threat-model contract validator. Set "
        "STANDARDS_REVIEW_CONTRACTS_ROOT or install the contract tree in the project package."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("response_package", type=Path)
    parser.add_argument("--threats", type=Path)
    parser.add_argument("--model", type=Path)
    parser.add_argument("--handoff", type=Path)
    parser.add_argument(
        "--allow-subset",
        action="store_true",
        help="Allow a response package that intentionally covers only a supplied threat-package subset",
    )
    args = parser.parse_args()
    try:
        response_package = json.loads(args.response_package.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR: could not load response package: {error}")
        return 1
    local_errors = validate_specific_responses(response_package)
    if local_errors:
        for error in local_errors:
            print(f"ERROR: {error}")
        return 1
    contract_root = resolve_contract_root()
    with tempfile.TemporaryDirectory(prefix="standards-review-response-") as temp_dir:
        threat_path = args.threats
        if threat_path:
            try:
                threat_package = json.loads(threat_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                print(f"ERROR: could not load threat package: {error}")
                return 1
            if isinstance(threat_package, dict):
                threat_package = dict(threat_package)
                threat_package.pop("workshop_simulation", None)
                threat_path = Path(temp_dir) / "threat-package.json"
                threat_path.write_text(json.dumps(threat_package), encoding="utf-8")
        command = [
            sys.executable,
            str(contract_root / "scripts" / "validate_threat_model_contract.py"),
        ]
        if args.model:
            command.extend(["--model", str(args.model)])
        if threat_path:
            command.extend(["--threats", str(threat_path)])
            if not args.allow_subset:
                command.append("--require-complete-response-coverage")
        command.extend(["--responses", str(args.response_package)])
        if args.handoff:
            command.extend(["--handoff", str(args.handoff)])
        return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
