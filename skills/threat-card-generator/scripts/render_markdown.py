#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def load(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def append_list(lines, heading, values):
    if values:
        lines.extend(["", heading])
        lines.extend(f"- {item}" for item in values)


def source_trace_markdown(source):
    source_kind = source.get("source_kind", "source")
    source_reference = source.get("source_reference", "")
    details = []
    if source.get("source_item_id"):
        details.append(f"item `{source['source_item_id']}`")
    if source.get("source_locator"):
        details.append(f"locator `{source['source_locator']}`")
    if source.get("evidence_status"):
        details.append(f"evidence `{source['evidence_status']}`")
    if source.get("license"):
        details.append(f"license `{source['license']}`")
    suffix = f" ({'; '.join(details)})" if details else ""
    line = f"- **{source_kind}:** {source_reference}{suffix}"
    if source.get("derivation_notes"):
        line += f" — {source['derivation_notes']}"
    if source.get("attribution"):
        line += f" Attribution: {source['attribution']}"
    return line


def card_markdown(card):
    lines = [
        f"### {card['id']} - {card['title']}",
        "",
        f"Suit: `{card['suit']}`  ",
        f"Rank: `{card['rank']}`",
    ]
    if card.get("card_status"):
        lines.append(f"Card status: `{card['card_status']}`")

    lines.extend(["", f"**Prompt:** {card['prompt']}", "", "**Look for:**"])
    lines.extend(f"- {item}" for item in card.get("look_for", []))
    append_list(lines, "**Expected outputs:**", card.get("outputs", []))
    append_list(lines, "**Applies to:**", card.get("applies_to", []))

    if card.get("prompt_template_id"):
        lines.extend(
            [
                "",
                "**Question-generation metadata:**",
                f"- Prompt template: `{card['prompt_template_id']}`",
                f"- Prompt family: `{card['prompt_family']}`",
                f"- Source item: `{card['source_item_id']}`",
                f"- Applicability rule: `{card['applicability_rule_id']}`",
                f"- Expected bad event shape: {card['expected_bad_event_shape']}",
            ]
        )

    if card.get("source_trace"):
        lines.extend(["", "**Source trace:**"])
        lines.extend(source_trace_markdown(source) for source in card["source_trace"])

    append_list(lines, "**Change notes:**", card.get("change_notes", []))

    if card.get("privacy_threat"):
        lines.extend(["", f"**Privacy threat:** {card['privacy_threat']}"])
    append_list(lines, "**Hotspots:**", card.get("hotspots", []))
    if card.get("threat_source"):
        lines.extend(["", f"**Threat source:** {card['threat_source']}"])
    append_list(lines, "**Elicitation questions:**", card.get("elicitation_questions", []))
    append_list(lines, "**Consequences:**", card.get("consequences", []))
    append_list(lines, "**Framework prompts:**", card.get("framework_prompts", []))
    if card.get("example"):
        lines.extend(["", f"**Example:** {card['example']}"])
    append_list(lines, "**Avoid:**", card.get("anti_patterns", []))
    return "\n".join(lines)


def render(deck):
    suits = {suit["id"]: suit for suit in deck.get("suits", [])}
    suit_order = {suit["id"]: index for index, suit in enumerate(deck.get("suits", []))}
    cards = sorted(
        deck.get("cards", []),
        key=lambda card: (
            suit_order.get(card.get("suit"), len(suit_order)),
            card.get("rank", 0),
            card.get("id", ""),
        ),
    )
    lines = [
        f"# {deck['title']}",
        "",
        deck.get("description", ""),
        "",
        f"Version: `{deck.get('version', '')}`  ",
        f"Status: `{deck.get('status', '')}`",
    ]
    if deck.get("generation_mode"):
        lines.append(f"Generation mode: `{deck['generation_mode']}`")
    if deck.get("play_mode"):
        lines.append(f"Play mode: `{deck['play_mode']}`")
    if deck.get("license"):
        lines.append(f"License: `{deck['license']}`")
    if deck.get("attribution"):
        lines.append(f"Attribution: {deck['attribution']}")

    lines.extend(["", "## Suits", ""])
    for suit in deck.get("suits", []):
        lines.append(f"- **{suit['id']} - {suit['name']}**: {suit['description']}")
    lines.extend(["", "## Cards", ""])
    current_suit = None
    for card in cards:
        if card.get("suit") != current_suit:
            current_suit = card.get("suit")
            suit_name = suits.get(current_suit, {}).get("name", current_suit)
            lines.extend(["", f"## {current_suit} - {suit_name}", ""])
        lines.extend([card_markdown(card), ""])
    return "\n".join(lines).rstrip() + "\n"


def main(argv):
    if len(argv) != 3:
        print("usage: render_markdown.py <deck.json> <output.md>", file=sys.stderr)
        return 2
    deck = load(argv[1])
    output = Path(argv[2])
    output.write_text(render(deck), encoding="utf-8")
    print(f"Rendered {len(deck.get('cards', []))} cards to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
