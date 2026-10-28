#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path


REQUIRED_TOP_LEVEL = [
    "deck_id",
    "title",
    "version",
    "status",
    "description",
    "method_notes",
    "suits",
    "cards",
    "playtest_log",
]

REQUIRED_SUIT = ["id", "name", "description"]
REQUIRED_CARD = ["id", "suit", "rank", "title", "prompt", "look_for", "outputs"]
VALID_STATUSES = {"draft", "playtest", "stable", "retired"}
VALID_PLAY_MODES = {"competitive", "collaborative", "hybrid"}
VALID_GENERATION_MODES = {
    "new-deck",
    "deck-refinement",
    "source-to-cards",
    "credential-flow-deck",
    "playtest-repair",
}
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
QUESTION_METADATA_FIELDS = (
    "prompt_template_id",
    "prompt_family",
    "source_item_id",
    "applicability_rule_id",
    "expected_bad_event_shape",
)
CARD_ID_RE = re.compile(r"^[A-Z0-9]+-[A-Z0-9]+-\d{2}$")
VAGUE_PROMPT_RE = re.compile(
    r"\b(something bad|bad thing|is .*secure|is .*private|privacy protected)\b",
    re.IGNORECASE,
)
SOCIO_TECHNICAL_RE = re.compile(
    r"\b(socio|social|governance|harm|redress|exclusion|mandatory|policy)\b",
    re.IGNORECASE,
)
LINDDUN_RE = re.compile(r"\b(LINDDUN|privacy_threat|hotspot)\b", re.IGNORECASE)


def load_json(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def is_non_empty_string(value):
    return isinstance(value, str) and bool(value.strip())


def require_object(value, label, errors):
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return False
    return True


def require_non_empty_string(value, label, errors):
    if not is_non_empty_string(value):
        errors.append(f"{label} must be a non-empty string")
        return False
    return True


def require_string_array(value, label, errors, *, non_empty=True):
    if not isinstance(value, list):
        errors.append(f"{label} must be an array")
        return False
    if non_empty and not value:
        errors.append(f"{label} must be a non-empty array")
        return False
    for index, item in enumerate(value):
        if not is_non_empty_string(item):
            errors.append(f"{label}[{index}] must be a non-empty string")
    return True


def validate_source_trace(value, label, errors):
    if not isinstance(value, list) or not value:
        errors.append(f"{label} must be a non-empty array")
        return

    for index, source in enumerate(value):
        source_label = f"{label}[{index}]"
        if not require_object(source, source_label, errors):
            continue

        require_non_empty_string(source.get("source_kind"), f"{source_label}.source_kind", errors)
        require_non_empty_string(
            source.get("source_reference"),
            f"{source_label}.source_reference",
            errors,
        )

        source_kind = source.get("source_kind")
        if not isinstance(source_kind, str) or source_kind not in VALID_SOURCE_KINDS:
            errors.append(
                f"{source_label}.source_kind must be one of {sorted(VALID_SOURCE_KINDS)}"
            )

        evidence_status = source.get("evidence_status")
        if "evidence_status" in source and (not isinstance(evidence_status, str) or evidence_status not in VALID_SOURCE_EVIDENCE_STATUSES):
            errors.append(
                f"{source_label}.evidence_status must be one of "
                f"{sorted(VALID_SOURCE_EVIDENCE_STATUSES)}"
            )
        if source_kind == "assumption" and evidence_status != "assumed":
            errors.append(
                f"{source_label}.evidence_status must be assumed when source_kind is assumption"
            )

        for key in (
            "source_item_id",
            "source_locator",
            "derivation_notes",
            "license",
            "attribution",
        ):
            if key in source:
                require_non_empty_string(source.get(key), f"{source_label}.{key}", errors)


def validate(deck):
    errors = []
    warnings = []

    if not require_object(deck, "deck", errors):
        return errors, warnings

    for key in REQUIRED_TOP_LEVEL:
        if key not in deck:
            errors.append(f"missing top-level field: {key}")

    for key in ("deck_id", "title", "version", "description"):
        if key in deck:
            require_non_empty_string(deck.get(key), key, errors)

    status = deck.get("status")
    if not isinstance(status, str) or status not in VALID_STATUSES:
        errors.append(f"status must be one of {sorted(VALID_STATUSES)}")

    generation_mode = deck.get("generation_mode")
    if "generation_mode" in deck and (not isinstance(generation_mode, str) or generation_mode not in VALID_GENERATION_MODES):
        errors.append(
            f"generation_mode must be one of {sorted(VALID_GENERATION_MODES)}; "
            "render-only is an operation and must not replace deck provenance"
        )

    play_mode = deck.get("play_mode")
    if "play_mode" in deck and (not isinstance(play_mode, str) or play_mode not in VALID_PLAY_MODES):
        errors.append(f"play_mode must be one of {sorted(VALID_PLAY_MODES)}")

    if "method_notes" in deck:
        require_string_array(deck.get("method_notes"), "method_notes", errors, non_empty=False)
    if "playtest_log" in deck:
        require_string_array(deck.get("playtest_log"), "playtest_log", errors, non_empty=False)

    suits = deck.get("suits", [])
    cards = deck.get("cards", [])
    if not isinstance(suits, list) or not suits:
        errors.append("suits must be a non-empty array")
        suits = []
    if not isinstance(cards, list) or not cards:
        errors.append("cards must be a non-empty array")
        cards = []
    if suits and not 4 <= len(suits) <= 7:
        warnings.append("deck should normally have 4-7 suits")

    suit_ids = set()
    for index, suit in enumerate(suits):
        if not require_object(suit, f"suits[{index}]", errors):
            continue
        for key in REQUIRED_SUIT:
            if key not in suit:
                errors.append(f"suits[{index}] missing field: {key}")
            else:
                require_non_empty_string(suit.get(key), f"suits[{index}].{key}", errors)
        suit_id = suit.get("id")
        if is_non_empty_string(suit_id):
            if suit_id in suit_ids:
                errors.append(f"duplicate suit id: {suit_id}")
            suit_ids.add(suit_id)

    card_ids = set()
    by_suit = {suit_id: 0 for suit_id in suit_ids}
    for index, card in enumerate(cards):
        if not require_object(card, f"cards[{index}]", errors):
            continue
        label = card.get("id", f"cards[{index}]")
        for key in REQUIRED_CARD:
            if key not in card:
                errors.append(f"{label} missing field: {key}")

        card_id = card.get("id")
        if "id" in card:
            require_non_empty_string(card_id, f"{label} id", errors)
        if is_non_empty_string(card_id):
            if card_id in card_ids:
                errors.append(f"duplicate card id: {card_id}")
            card_ids.add(card_id)
            if not CARD_ID_RE.match(card_id):
                warnings.append(f"{card_id} does not match recommended ID pattern DECK-SUIT-00")

        for key in ("suit", "title"):
            if key in card:
                require_non_empty_string(card.get(key), f"{label} {key}", errors)

        suit = card.get("suit")
        if is_non_empty_string(suit) and suit not in suit_ids:
            errors.append(f"{label} references unknown suit: {suit}")
        elif is_non_empty_string(suit):
            by_suit[suit] = by_suit.get(suit, 0) + 1

        rank = card.get("rank")
        if not isinstance(rank, int) or isinstance(rank, bool) or rank < 1:
            errors.append(f"{label} rank must be a positive integer")

        prompt = card.get("prompt")
        if isinstance(prompt, str):
            if not prompt.strip():
                errors.append(f"{label} prompt must be a non-empty string")
            if not prompt.endswith("?"):
                errors.append(f"{label} prompt must be a question ending with '?'")
            if len(prompt) > 180:
                warnings.append(f"{label} prompt is long; consider shortening it")
            if VAGUE_PROMPT_RE.search(prompt):
                warnings.append(f"{label} prompt may be too vague for threat elicitation")
        else:
            errors.append(f"{label} prompt must be a string")

        if "look_for" in card:
            require_string_array(card.get("look_for"), f"{label} look_for", errors)
        if "outputs" in card:
            require_string_array(card.get("outputs"), f"{label} outputs", errors)

        if "applies_to" not in card:
            warnings.append(f"{label} should include applies_to to tie the card to model elements")
        else:
            require_string_array(card.get("applies_to"), f"{label} applies_to", errors)

        for key in (
            "anti_patterns",
            "framework_prompts",
            "hotspots",
            "elicitation_questions",
            "consequences",
        ):
            if key in card:
                require_string_array(card.get(key), f"{label} {key}", errors)

        for key in ("example", "privacy_threat", "threat_source"):
            if key in card:
                require_non_empty_string(card.get(key), f"{label} {key}", errors)

        if "source_trace" in card:
            validate_source_trace(card.get("source_trace"), f"{label} source_trace", errors)
        elif generation_mode == "source-to-cards":
            errors.append(f"{label} must include source_trace in a source-to-cards deck")

        card_status = card.get("card_status")
        if "card_status" in card and (not isinstance(card_status, str) or card_status not in VALID_CARD_STATUSES):
            errors.append(f"{label} card_status must be one of {sorted(VALID_CARD_STATUSES)}")

        if "change_notes" in card:
            require_string_array(card.get("change_notes"), f"{label} change_notes", errors)
        if isinstance(card_status, str) and card_status in CARD_STATUSES_REQUIRING_NOTES and not card.get("change_notes"):
            errors.append(f"{label} change_notes is required when card_status is {card_status}")

        present_metadata = [key for key in QUESTION_METADATA_FIELDS if key in card]
        if present_metadata:
            missing_metadata = [key for key in QUESTION_METADATA_FIELDS if key not in card]
            if missing_metadata:
                errors.append(
                    f"{label} has partial question-generation metadata; missing "
                    f"{', '.join(missing_metadata)}"
                )
            for key in present_metadata:
                require_non_empty_string(card.get(key), f"{label} {key}", errors)

        combined_text = " ".join(
            str(value)
            for key in ("title", "prompt", "outputs", "framework_prompts")
            for value in (
                card.get(key) if isinstance(card.get(key), list) else [card.get(key, "")]
            )
        )
        if SOCIO_TECHNICAL_RE.search(combined_text) and "anti_patterns" not in card:
            warnings.append(f"{label} socio-technical or governance card should include anti_patterns")

        linddun_text = " ".join(
            str(value)
            for key in ("title", "prompt", "privacy_threat", "framework_prompts")
            for value in (
                card.get(key) if isinstance(card.get(key), list) else [card.get(key, "")]
            )
        )
        if LINDDUN_RE.search(linddun_text):
            if "hotspots" not in card and "applies_to" not in card:
                warnings.append(
                    f"{label} LINDDUN-style card should preserve hotspots or applies_to surfaces"
                )
            if "elicitation_questions" not in card:
                warnings.append(f"{label} LINDDUN-style card should include elicitation_questions")

    for suit_id, count in sorted(by_suit.items()):
        if count == 0:
            warnings.append(f"suit has no cards: {suit_id}")

    return errors, warnings


def main(argv):
    if len(argv) != 2:
        print("usage: validate_deck.py <deck.json>", file=sys.stderr)
        return 2
    try:
        deck = load_json(argv[1])
    except Exception as error:
        print(f"ERROR: could not load JSON: {error}", file=sys.stderr)
        return 1

    errors, warnings = validate(deck)
    for warning in warnings:
        print(f"WARNING: {warning}")
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)

    if errors:
        print(f"Validation failed: {len(errors)} error(s), {len(warnings)} warning(s)")
        return 1

    print(
        f"Validation passed: {len(deck.get('cards', []))} cards, "
        f"{len(deck.get('suits', []))} suits, {len(warnings)} warning(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
