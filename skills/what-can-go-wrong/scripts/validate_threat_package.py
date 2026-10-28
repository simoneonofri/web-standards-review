"""Validate a threat-package v1 JSON file through the shared workbench contract."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REQUIRED_BAD_EVENT_FIELDS = (
    "actor_or_condition",
    "action_or_failure",
    "violated_property_or_interest",
    "consequence",
)
VALID_EVIDENCE_STATUS = {
    "supplied",
    "verified",
    "inferred",
    "assumed",
    "untested",
    "unavailable",
}
VALID_DECK_STATUSES = {"draft", "playtest", "stable", "retired"}
VALID_GENERATION_MODES = {
    "new-deck",
    "deck-refinement",
    "source-to-cards",
    "credential-flow-deck",
    "playtest-repair",
}
VALID_PLAY_MODES = {"competitive", "collaborative", "hybrid"}
VALID_CARD_STATUSES = {"new", "keep", "rewrite", "split", "merge", "retire"}
CARD_STATUSES_REQUIRING_NOTES = {"rewrite", "split", "merge", "retire"}
VALID_SOURCE_KINDS = {
    "primary_source",
    "local_snapshot",
    "extracted_table",
    "user_notes",
    "assumption",
    "existing_deck",
    "review_material",
    "other",
}
VALID_SOURCE_EVIDENCE_STATUSES = {"verified", "inferred", "assumed", "unavailable"}
VALID_WORKSHOP_ANSWER_STATUS = {
    "generated_threat",
    "no_applicable_threat",
    "model_gap",
    "blocked",
    "deferred",
}
VALID_WORKSHOP_RELATIONS = {
    "new_uncovered_threat",
    "new_partially_covered_threat",
    "method_confirmed_existing",
    "method_refined_existing",
    "not_applicable_prompt",
}
QUESTION_METADATA_FIELDS = (
    "prompt_template_id",
    "prompt_family",
    "source_item_id",
    "applicability_rule_id",
    "expected_bad_event_shape",
)
GENERIC_BAD_EVENT_VALUES = {
    "unknown",
    "unspecified",
    "n/a",
    "none",
    "potential issue",
    "security issue",
    "privacy issue",
    "harm may occur",
}


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _non_empty_string_array(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(_non_empty_string(item) for item in value)
    )


def _model_ids(model: Any) -> set[str]:
    if not isinstance(model, dict):
        return set()
    result: set[str] = set()
    for section in (
        "external_entities",
        "processes",
        "data_stores",
        "data_flows",
        "trust_boundaries",
    ):
        rows = model.get(section, [])
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            value = row.get("canonical_id") or row.get("stable_id") or row.get("id")
            if _non_empty_string(value):
                result.add(value)
    return result


def _validate_source_trace(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        return [f"{label} must be a non-empty array"]

    errors: list[str] = []
    for index, row in enumerate(value):
        row_label = f"{label}[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{row_label} must be an object")
            continue
        source_kind = row.get("source_kind")
        if source_kind not in VALID_SOURCE_KINDS:
            errors.append(f"{row_label}.source_kind must be one of {sorted(VALID_SOURCE_KINDS)}")
        if not _non_empty_string(row.get("source_reference")):
            errors.append(f"{row_label}.source_reference must be a non-empty string")
        evidence_status = row.get("evidence_status")
        if evidence_status is not None and evidence_status not in VALID_SOURCE_EVIDENCE_STATUSES:
            errors.append(
                f"{row_label}.evidence_status must be one of "
                f"{sorted(VALID_SOURCE_EVIDENCE_STATUSES)}"
            )
        if source_kind == "assumption" and evidence_status != "assumed":
            errors.append(
                f"{row_label}.evidence_status must be assumed when source_kind is assumption"
            )
    return errors


def _validate_workshop_simulation(
    workshop: Any,
    *,
    known_model_ids: set[str],
    known_threat_ids: set[str],
) -> list[str]:
    if workshop is None:
        return []
    if not isinstance(workshop, dict):
        return ["workshop_simulation must be an object"]

    errors: list[str] = []
    if workshop.get("mode") != "card_workshop":
        errors.append("workshop_simulation.mode must be card_workshop")

    deck = workshop.get("deck")
    if not isinstance(deck, dict):
        return errors + ["workshop_simulation.deck must be an object"]

    for field in ("deck_id", "title", "version"):
        if not _non_empty_string(deck.get(field)):
            errors.append(f"workshop_simulation.deck.{field} must be a non-empty string")

    status = deck.get("status")
    if status not in VALID_DECK_STATUSES:
        errors.append(
            f"workshop_simulation.deck.status must be one of {sorted(VALID_DECK_STATUSES)}"
        )

    generation_mode = deck.get("generation_mode")
    if generation_mode not in VALID_GENERATION_MODES:
        errors.append(
            "workshop_simulation.deck.generation_mode must be one of "
            f"{sorted(VALID_GENERATION_MODES)}; render-only is not deck provenance"
        )

    play_mode = deck.get("play_mode")
    if play_mode not in VALID_PLAY_MODES:
        errors.append(
            f"workshop_simulation.deck.play_mode must be one of {sorted(VALID_PLAY_MODES)}"
        )

    if not _non_empty_string(deck.get("artifact_reference")):
        errors.append("workshop_simulation.deck.artifact_reference must be a non-empty string")
    if deck.get("validation_status") != "passed":
        errors.append("workshop_simulation.deck.validation_status must be passed")

    cards_used = deck.get("cards_used")
    if not isinstance(cards_used, list) or not cards_used:
        errors.append("workshop_simulation.deck.cards_used must be a non-empty array")
        cards_used = []

    cards_by_id: dict[str, dict[str, Any]] = {}
    for index, card in enumerate(cards_used):
        label = f"workshop_simulation.deck.cards_used[{index}]"
        if not isinstance(card, dict):
            errors.append(f"{label} must be an object")
            continue

        card_id = card.get("card_id")
        if not _non_empty_string(card_id):
            errors.append(f"{label}.card_id must be a non-empty string")
            continue
        if card_id in cards_by_id:
            errors.append(f"duplicate workshop card_id: {card_id}")
        cards_by_id[card_id] = card

        for field in ("suit", "title", "prompt"):
            if not _non_empty_string(card.get(field)):
                errors.append(f"{label}.{field} must be a non-empty string")
        rank = card.get("rank")
        if not isinstance(rank, int) or isinstance(rank, bool) or rank < 1:
            errors.append(f"{label}.rank must be a positive integer")
        if not _non_empty_string_array(card.get("applies_to")):
            errors.append(f"{label}.applies_to must be a non-empty array of strings")

        if generation_mode == "source-to-cards" or "source_trace" in card:
            errors.extend(_validate_source_trace(card.get("source_trace"), f"{label}.source_trace"))

        missing_metadata = [
            field for field in QUESTION_METADATA_FIELDS if not _non_empty_string(card.get(field))
        ]
        if missing_metadata:
            errors.append(
                f"{label} is missing canonical question-generation metadata: "
                f"{', '.join(missing_metadata)}"
            )

        card_status = card.get("card_status")
        if card_status is not None and card_status not in VALID_CARD_STATUSES:
            errors.append(f"{label}.card_status must be one of {sorted(VALID_CARD_STATUSES)}")
        change_notes = card.get("change_notes")
        if change_notes is not None and not _non_empty_string_array(change_notes):
            errors.append(f"{label}.change_notes must be a non-empty array of strings")
        if card_status in CARD_STATUSES_REQUIRING_NOTES and not change_notes:
            errors.append(f"{label}.change_notes is required when card_status is {card_status}")

    card_plays = workshop.get("card_plays")
    if not isinstance(card_plays, list) or not card_plays:
        errors.append("workshop_simulation.card_plays must be a non-empty array")
        card_plays = []

    seen_play_ids: set[str] = set()
    seen_card_element_pairs: set[tuple[str, str]] = set()
    deck_id = deck.get("deck_id")

    for index, play in enumerate(card_plays):
        label = f"workshop_simulation.card_plays[{index}]"
        if not isinstance(play, dict):
            errors.append(f"{label} must be an object")
            continue

        card_play_id = play.get("card_play_id")
        if not _non_empty_string(card_play_id):
            errors.append(
                f"{label}.card_play_id must be a non-empty string; play_id is a legacy alias"
            )
        elif card_play_id in seen_play_ids:
            errors.append(f"duplicate workshop card_play_id: {card_play_id}")
        else:
            seen_play_ids.add(card_play_id)

        if play.get("deck_id") != deck_id:
            errors.append(f"{label}.deck_id must match workshop_simulation.deck.deck_id")

        card_id = play.get("card_id")
        card = cards_by_id.get(card_id)
        if card is None:
            errors.append(f"{label}.card_id must reference workshop_simulation.deck.cards_used")

        model_element_id = play.get("model_element_id")
        if not _non_empty_string(model_element_id):
            errors.append(
                f"{label}.model_element_id must be a non-empty string; "
                "target_model_element_ids is a legacy multi-target shape"
            )
        elif known_model_ids and model_element_id not in known_model_ids:
            errors.append(f"{label}.model_element_id references an unknown model element")

        if _non_empty_string(card_id) and _non_empty_string(model_element_id):
            pair = (card_id, model_element_id)
            if pair in seen_card_element_pairs:
                errors.append(
                    f"{label} duplicates the card/model-element pair {card_id}/{model_element_id}"
                )
            else:
                seen_card_element_pairs.add(pair)

        for field in ("model_element_type", "model_element_name", "prompt", "answer"):
            if not _non_empty_string(play.get(field)):
                errors.append(f"{label}.{field} must be a non-empty string")

        if card is not None:
            if play.get("prompt") != card.get("prompt"):
                errors.append(f"{label}.prompt must match the canonical card prompt")
            for field in QUESTION_METADATA_FIELDS:
                if play.get(field) != card.get(field):
                    errors.append(f"{label}.{field} must match the canonical card metadata")
            if play.get("suit") != card.get("suit"):
                errors.append(f"{label}.suit must match the canonical card suit")
            if play.get("rank") != card.get("rank"):
                errors.append(f"{label}.rank must match the canonical card rank")

        answer_status = play.get("answer_status")
        if answer_status not in VALID_WORKSHOP_ANSWER_STATUS:
            errors.append(
                f"{label}.answer_status must be one of {sorted(VALID_WORKSHOP_ANSWER_STATUS)}"
            )

        relation = play.get("candidate_relation")
        if relation not in VALID_WORKSHOP_RELATIONS:
            errors.append(
                f"{label}.candidate_relation must be one of {sorted(VALID_WORKSHOP_RELATIONS)}"
            )

        derived_threat_ids = play.get("derived_threat_ids")
        if not isinstance(derived_threat_ids, list) or not all(
            _non_empty_string(item) for item in derived_threat_ids
        ):
            errors.append(f"{label}.derived_threat_ids must be an array of threat IDs")
            derived_threat_ids = []
        unknown_threat_ids = sorted(set(derived_threat_ids) - known_threat_ids)
        if unknown_threat_ids:
            errors.append(
                f"{label}.derived_threat_ids contains unknown threat IDs: {unknown_threat_ids}"
            )

        non_producing_reason = play.get("non_producing_reason")
        if answer_status in {"no_applicable_threat", "model_gap", "blocked", "deferred"}:
            if not _non_empty_string(non_producing_reason):
                errors.append(f"{label}.non_producing_reason is required for non-producing plays")
            if derived_threat_ids:
                errors.append(f"{label}.derived_threat_ids must be empty for non-producing plays")

        for field in (
            "applicability_basis",
            "review_basis",
            "question_basis",
            "answer_basis_summary",
            "source_reference",
        ):
            if not _non_empty_string(play.get(field)):
                errors.append(f"{label}.{field} must be a non-empty string")

        if not _non_empty_string_array(play.get("question_generation_inputs")):
            errors.append(f"{label}.question_generation_inputs must be a non-empty array of strings")

    return errors


def validate_local(package: Any, model: Any | None = None) -> list[str]:
    """Fail closed on the incident conditions not expressed by schema v1."""

    errors: list[str] = []
    if not isinstance(package, dict):
        return ["threat package must be a JSON object"]
    known_model_ids = _model_ids(model) if model is not None else set()
    threats = package.get("threats")
    if not isinstance(threats, list):
        return ["threats must be an array"]

    seen_ids: set[str] = set()
    for index, threat in enumerate(threats):
        label = f"threats[{index}]"
        if not isinstance(threat, dict):
            errors.append(f"{label} must be an object")
            continue
        threat_id = threat.get("threat_id")
        if not _non_empty_string(threat_id):
            errors.append(f"{label}.threat_id must be a non-empty string")
        elif threat_id in seen_ids:
            errors.append(f"duplicate threat_id: {threat_id}")
        else:
            seen_ids.add(threat_id)

        for field in REQUIRED_BAD_EVENT_FIELDS:
            value = threat.get(field)
            if not _non_empty_string(value):
                errors.append(f"{label}.{field} must be a non-empty concrete bad-event field")
            elif value.strip().lower() in GENERIC_BAD_EVENT_VALUES:
                errors.append(f"{label}.{field} is generic rather than a concrete bad event")

        elements = threat.get("affected_model_elements")
        if not isinstance(elements, list) or not elements or not all(
            _non_empty_string(item) for item in elements
        ):
            errors.append(f"{label}.affected_model_elements must be a non-empty array of model IDs")
        elif known_model_ids:
            unknown = sorted(set(elements) - known_model_ids)
            if unknown:
                errors.append(f"{label}.affected_model_elements contains unknown model IDs: {unknown}")

        evidence_status = threat.get("evidence_status")
        if evidence_status not in VALID_EVIDENCE_STATUS:
            errors.append(f"{label}.evidence_status must be one of {sorted(VALID_EVIDENCE_STATUS)}")
        evidence = threat.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            errors.append(
                f"{label}.evidence must contain a source reference or explicit inference record"
            )

        story = threat.get("threat_story")
        if not _non_empty_string(story):
            errors.append(f"{label}.threat_story must be a non-empty concrete story")
        else:
            story_lower = story.strip().lower()
            component_values = [
                str(threat.get(field, "")).strip().lower()
                for field in REQUIRED_BAD_EVENT_FIELDS
            ]
            if story_lower in GENERIC_BAD_EVENT_VALUES or story_lower in component_values:
                errors.append(f"{label}.threat_story is not a complete concrete bad-event story")

    errors.extend(
        _validate_workshop_simulation(
            package.get("workshop_simulation"),
            known_model_ids=known_model_ids,
            known_threat_ids=seen_ids,
        )
    )
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
    parser.add_argument("threat_package", type=Path)
    parser.add_argument("--model", type=Path)
    parser.add_argument("--candidate-ledger", type=Path, help="Require complete candidate reconciliation")
    parser.add_argument("--elicitation-ledger", type=Path, help="Frozen elicitation input for reconciliation")
    parser.add_argument(
        "--handoff", type=Path, help="Validate the multi-agent producer/consumer handoff"
    )
    args = parser.parse_args()
    if bool(args.candidate_ledger) != bool(args.elicitation_ledger) or (args.candidate_ledger and not args.model):
        parser.error("candidate reconciliation requires --model, --candidate-ledger and --elicitation-ledger together")

    try:
        package = json.loads(args.threat_package.read_text(encoding="utf-8"))
        model = json.loads(args.model.read_text(encoding="utf-8")) if args.model else None
        if args.handoff:
            json.loads(args.handoff.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR: could not load input JSON: {error}")
        return 1

    local_errors = validate_local(package, model)
    if local_errors:
        for error in local_errors:
            print(f"ERROR: {error}")
        return 1

    if args.candidate_ledger:
        from validate_candidate_ledger import OPEN, load, validate

        try:
            ledger, _ = load(args.candidate_ledger)
            frozen, frozen_digest = load(args.elicitation_ledger)
            _model, model_digest = load(args.model)
            _package, package_digest = load(args.threat_package)
            ledger_errors = validate(ledger, model, model_digest=model_digest, threats=package, threats_digest=package_digest, elicitation=frozen, elicitation_digest=frozen_digest)
        except (OSError, ValueError) as error:
            print(f"ERROR: could not load candidate reconciliation: {error}")
            return 1
        if not ledger_errors and (ledger.get("stage") != "reconciliation" or any(row["disposition"] in OPEN for row in ledger["candidates"])):
            ledger_errors.append("candidate reconciliation is not complete")
        if ledger_errors:
            for error in ledger_errors:
                print(f"ERROR: {error}")
            return 1

    contract_root = resolve_contract_root()
    with tempfile.TemporaryDirectory(prefix="standards-review-threat-") as temp_dir:
        shared_package_path = Path(temp_dir) / "threat-package.json"
        shared_package = dict(package)
        shared_package.pop("workshop_simulation", None)
        shared_package_path.write_text(json.dumps(shared_package), encoding="utf-8")
        command = [
            sys.executable,
            str(contract_root / "scripts" / "validate_threat_model_contract.py"),
        ]
        if args.model:
            command.extend(["--model", str(args.model)])
        command.extend(["--threats", str(shared_package_path)])
        if args.handoff:
            command.extend(["--handoff", str(args.handoff)])
        return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
