"""Offline structural validator for threat-model-contract v1 packages."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

CONTRACT_VERSION = 1
REQUIRED_MODEL_FIELDS = {
    "contract_version",
    "model_id",
    "system_under_analysis",
    "scenario",
    "dfd_detail_level",
    "abstraction_level",
    "scope",
    "out_of_scope",
    "source_inventory",
    "external_entities",
    "processes",
    "data_stores",
    "data_flows",
    "trust_boundaries",
    "assumptions",
    "inline_safeguards",
    "implicit_threat_model_signals",
    "review_signals",
    "unresolved_questions",
    "validation_notes",
}
CANONICAL_MODEL_ID = re.compile(r"^(EE|PO|DS|DF|TB)-\d{2,}$")
CANONICAL_THREAT_ID = re.compile(r"^T-\d{2,}$")
CANONICAL_RESPONSE_ID = re.compile(r"^R-\d{2,}$")
CANONICAL_ASSUMPTION_ID = re.compile(r"^A-\d{3,}$")
COLLECTION_PREFIX = {
    "external_entities": "EE",
    "processes": "PO",
    "data_stores": "DS",
    "data_flows": "DF",
    "trust_boundaries": "TB",
}
REQUIRED_DICTIONARY_FIELDS = {
    "canonical_id",
    "mermaid_node_id",
    "type",
    "visible_label",
    "name",
    "description",
    "source_id",
    "assurance_level",
    "specification_reference",
    "source_locator",
    "coverage_status",
    "evidence_status",
    "assumptions",
    "boundary_membership",
    "flow_source",
    "flow_destination",
}
HANDOFF_ID_AUTHORITY = {
    "model_packet": "model",
    "dfd_bundle": "model",
    "candidate_ledger": "none",
    "elicitation_trace": "none",
    "threat_package": "threat_reconciliation",
    "response_package": "response_reconciliation",
    "quality_gate": "none",
    "assembled_report": "assembler",
}
REQUIRED_THREAT_FIELDS = {
    "threat_id",
    "affected_model_elements",
    "actor_or_condition",
    "action_or_failure",
    "violated_property_or_interest",
    "consequence",
    "threat_story",
    "evidence_status",
    "evidence",
    "assumptions",
    "lens",
    "harm",
    "response_hint",
    "responsibility_or_transfer_hint",
    "remaining_question",
}
REQUIRED_RESPONSE_FIELDS = {
    "response_id",
    "threat_id",
    "affected_model_elements",
    "erta",
    "response",
    "mechanism_or_text",
    "owner",
    "evidence_status",
    "evidence",
    "assumptions",
    "transfer_receiver",
    "acceptance_rationale",
    "revisit_trigger",
    "remaining_threat",
    "next_action",
    "status",
}
EVIDENCE_STATUS = {"supplied", "verified", "inferred", "assumed", "untested", "unavailable"}
TRACE_ANSWER_STATUS = {"generated_threat", "no_applicable_threat", "model_gap", "blocked", "deferred"}
CHECK_RELEVANCE = {"relevant", "not_relevant", "unclear"}
CHECK_PRESENCE = {"present", "partial", "absent", "unknown", "not_applicable", "not_checked"}
CHECK_SOURCE_KIND = {"spec-present", "spec-absent", "review-guidance", "corpus-pattern"}
PRINCIPLE_ASSESSMENT = {"supported", "partially_supported", "not_supported", "conflicts", "unknown", "not_applicable", "not_checked"}
METHOD_IDS = {
    "as_is_threat_model",
    "stride_per_element",
    "linddun_per_element",
    "rfc3552_security_per_element",
    "rfc6973_privacy_per_element",
    "rfc9620_human_rights_per_element",
    "browser_fingerprinting_prompt_lens",
    "xs_leaks_oracle_checklist",
    "microsoft_harms_modeling_per_element",
    "workshop_simulation",
    "stride_workshop_simulation",
    "linddun_workshop_simulation",
    "checklist_assessment",
    "principles_assessment",
    "design_principles_assessment",
    "privacy_principles_assessment",
    "independent_additional_elicitation",
}
COVERAGE_RELATIONS = {
    "new_uncovered_threat",
    "new_partially_covered_threat",
    "already_explicitly_documented",
    "already_implicitly_signaled",
    "silently_responded",
    "method_confirmed_existing",
    "method_refined_existing",
    "not_applicable_prompt",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def require_fields(obj: dict[str, Any], fields: set[str], where: str, errors: list[str]) -> None:
    for field in sorted(fields - obj.keys()):
        errors.append(f"{where}: missing required field {field}")


def check_version(obj: dict[str, Any], where: str, errors: list[str]) -> None:
    if obj.get("contract_version") != CONTRACT_VERSION:
        errors.append(f"{where}: contract_version must be {CONTRACT_VERSION}")


def is_nonempty(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return value is not None


def validate_assumption_refs(value: Any, where: str, errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append(f"{where}: must be an array of canonical A-### references")
        return
    for index, assumption_id in enumerate(value):
        if not isinstance(assumption_id, str) or not CANONICAL_ASSUMPTION_ID.fullmatch(assumption_id):
            errors.append(f"{where}[{index}]: {assumption_id!r} must be a canonical A-### reference")


def legacy_assumption_references(value: Any, where: str = "") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            findings.extend(legacy_assumption_references(item, f"{where}.{key}" if where else str(key)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(legacy_assumption_references(item, f"{where}[{index}]"))
    elif isinstance(value, str) and re.search(r"\b(?:AS-\d+|A-NEW-[A-Z]+-\d+)\b", value):
        findings.append(f"{where}: retired assumption reference in {value!r}")
    return findings


def validate_model(packet: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    require_fields(packet, REQUIRED_MODEL_FIELDS, "model", errors)
    check_version(packet, "model", errors)
    seen_ids: set[str] = set()
    validation_text = " ".join(str(note) for note in packet.get("validation_notes", []))
    assumptions = packet.get("assumptions")
    seen_assumption_ids: set[str] = set()
    if not isinstance(assumptions, list):
        errors.append("model.assumptions: must be an array")
    else:
        for index, assumption in enumerate(assumptions):
            where = f"model.assumptions[{index}]"
            if not isinstance(assumption, dict):
                errors.append(f"{where}: must be an object with a canonical ID and statement")
                continue
            assumption_id = assumption.get("assumption_id") or assumption.get("id")
            statement = assumption.get("statement") or assumption.get("text")
            if not isinstance(assumption_id, str) or not CANONICAL_ASSUMPTION_ID.fullmatch(assumption_id):
                errors.append(f"{where}: assumption ID {assumption_id!r} must use A-###")
            elif assumption_id in seen_assumption_ids:
                errors.append(f"{where}: duplicate assumption ID {assumption_id}")
            else:
                seen_assumption_ids.add(assumption_id)
            if not is_nonempty(statement):
                errors.append(f"{where}: assumption statement must be non-empty")
    for collection in ["external_entities", "processes", "data_stores", "data_flows", "trust_boundaries"]:
        for index, element in enumerate(packet.get(collection, [])):
            where = f"{collection}[{index}]"
            if not isinstance(element, dict):
                errors.append(f"{where}: must be an object")
                continue
            element_id = element.get("stable_id") or element.get("candidate_id")
            if not element_id:
                errors.append(f"{where}: missing stable_id or candidate_id")
            elif element_id in seen_ids:
                errors.append(f"{where}: duplicate element id {element_id}")
            else:
                seen_ids.add(element_id)
            expected_prefix = COLLECTION_PREFIX[collection]
            if element_id and not CANONICAL_MODEL_ID.fullmatch(str(element_id)):
                errors.append(f"{where}: non-canonical model ID {element_id!r}")
            elif element_id and not str(element_id).startswith(expected_prefix + "-"):
                errors.append(f"{where}: ID {element_id!r} does not match {collection}")
            for field in ["type", "name", "description", "evidence_status", "source_reference", "confidence", "notes"]:
                if field not in element:
                    errors.append(f"{where}: missing {field}")
            if element.get("evidence_status") not in EVIDENCE_STATUS:
                errors.append(f"{where}: invalid evidence_status {element.get('evidence_status')!r}")
            source = str(element.get("source_reference", "")).strip()
            if not source:
                errors.append(f"{where}: source_reference is empty")
            if source == "TBD" and "TBD" not in validation_text:
                errors.append(f"{where}: TBD source_reference must be reported in validation_notes")
            if collection == "trust_boundaries":
                basis = element.get("boundary_basis") or []
                if not element.get("justification"):
                    errors.append(f"{where}: trust boundary missing justification")
                if not basis:
                    errors.append(f"{where}: trust boundary missing boundary_basis")
            if collection == "data_flows":
                source_id = element.get("source") or element.get("flow_source")
                destination_id = element.get("destination") or element.get("target") or element.get("flow_destination")
                if not source_id:
                    errors.append(f"{where}: data flow missing source")
                if not destination_id:
                    errors.append(f"{where}: data flow missing destination")
                for endpoint_name, endpoint_id in (("source", source_id), ("destination", destination_id)):
                    if endpoint_id and not CANONICAL_MODEL_ID.fullmatch(str(endpoint_id)):
                        errors.append(f"{where}: {endpoint_name} has non-canonical ID {endpoint_id!r}")
    return errors


def validate_threats(package: dict[str, Any], model: dict[str, Any] | None = None) -> list[str]:
    errors: list[str] = []
    require_fields(package, {
        "contract_version", "threat_package_id", "model_id", "source_contract_version", "threats",
        "coverage_notes", "blocked_elements", "unresolved_model_gaps", "skeptic_result",
    }, "threat_package", errors)
    check_version(package, "threat_package", errors)
    errors.extend(legacy_assumption_references(package, "threat_package"))
    if package.get("source_contract_version") != CONTRACT_VERSION:
        errors.append("threat_package: source_contract_version mismatch")
    if model and package.get("model_id") != model.get("model_id"):
        errors.append("threat_package: model_id does not match model packet")
    model_ids = collect_model_ids(model) if model else None
    seen: set[str] = set()
    stories: set[str] = set()
    for index, threat in enumerate(package.get("threats", [])):
        where = f"threats[{index}]"
        require_fields(threat, REQUIRED_THREAT_FIELDS, where, errors)
        threat_id = threat.get("threat_id")
        if threat_id and not CANONICAL_THREAT_ID.fullmatch(str(threat_id)):
            errors.append(f"{where}: non-canonical threat_id {threat_id!r}")
        if threat_id in seen:
            errors.append(f"{where}: duplicate threat_id {threat_id}")
        seen.add(threat_id)
        story = " ".join(
            " ".join(str(threat.get(part, "")).lower().split())
            for part in ["actor_or_condition", "action_or_failure", "consequence"]
        )
        if story in stories:
            errors.append(f"{where}: likely duplicate threat story")
        stories.add(story)
        if threat.get("evidence_status") not in EVIDENCE_STATUS:
            errors.append(f"{where}: invalid evidence_status {threat.get('evidence_status')!r}")
        affected = threat.get("affected_model_elements") or []
        if not affected:
            errors.append(f"{where}: affected_model_elements is empty")
        if model_ids is not None:
            for element_id in affected:
                if element_id not in model_ids:
                    errors.append(f"{where}: unknown affected_model_element {element_id}")
        if len(str(threat.get("threat_story", "")).split()) < 8:
            errors.append(f"{where}: threat_story is too short to be concrete")
        for field in [
            "actor_or_condition",
            "action_or_failure",
            "violated_property_or_interest",
            "consequence",
            "threat_story",
            "evidence",
        ]:
            if not is_nonempty(threat.get(field)):
                errors.append(f"{where}: concrete-threat gate requires non-empty {field}")
        methods = threat.get("found_by_methods", [])
        if methods and not isinstance(methods, list):
            errors.append(f"{where}.found_by_methods: must be an array")
        for method in methods if isinstance(methods, list) else []:
            if method not in METHOD_IDS:
                errors.append(f"{where}: invalid found_by_methods entry {method!r}")
        provenance = threat.get("method_provenance", [])
        if provenance and not isinstance(provenance, list):
            errors.append(f"{where}.method_provenance: must be an array")
        for prov_index, item in enumerate(provenance if isinstance(provenance, list) else []):
            pwhere = f"{where}.method_provenance[{prov_index}]"
            if not isinstance(item, dict):
                errors.append(f"{pwhere}: must be an object")
                continue
            method = item.get("method")
            if method not in METHOD_IDS:
                errors.append(f"{pwhere}: invalid method {method!r}")
        relation = threat.get("coverage_relation")
        if relation is not None and relation not in COVERAGE_RELATIONS:
            errors.append(f"{where}: invalid coverage_relation {relation!r}")
        validate_assumption_refs(threat.get("assumptions"), f"{where}.assumptions", errors)
    if not package.get("threats") and not (package.get("blocked_elements") or package.get("unresolved_model_gaps")):
        errors.append("threat_package: empty threats require blocked_elements or unresolved_model_gaps")
    validate_elicitation_trace(package, model_ids, seen, errors)
    validate_checklist_assessment(package, model_ids, seen, errors)
    validate_workshop_simulation(package, model_ids, seen, errors)
    validate_principles_assessment(package, model_ids, seen, errors)
    validate_principles_assessment(
        package,
        model_ids,
        seen,
        errors,
        field_name="design_principles_assessment",
        expected_mode="design_principles_assessment",
    )
    validate_principles_assessment(
        package,
        model_ids,
        seen,
        errors,
        field_name="privacy_principles_assessment",
        expected_mode="privacy_principles_assessment",
    )
    validate_method_comparison(package, seen, errors)
    validate_independent_elicitation_pass(package, model_ids, seen, errors)
    return errors

def validate_elicitation_trace(
    package: dict[str, Any],
    model_ids: set[str] | None,
    threat_ids: set[str],
    errors: list[str],
) -> None:
    trace = package.get("elicitation_trace")
    if trace is None:
        return
    if not isinstance(trace, list):
        errors.append("threat_package.elicitation_trace: must be an array")
        return
    for trace_index, item in enumerate(trace):
        where = f"elicitation_trace[{trace_index}]"
        if not isinstance(item, dict):
            errors.append(f"{where}: must be an object")
            continue
        require_fields(
            item,
            {"trace_id", "model_element_id", "model_element_type", "model_element_name", "evidence_status", "selected_lenses", "questions"},
            where,
            errors,
        )
        if item.get("evidence_status") not in EVIDENCE_STATUS:
            errors.append(f"{where}: invalid evidence_status {item.get('evidence_status')!r}")
        element_id = item.get("model_element_id")
        if model_ids is not None and element_id not in model_ids:
            errors.append(f"{where}: unknown model_element_id {element_id}")
        questions = item.get("questions")
        if not isinstance(questions, list):
            errors.append(f"{where}.questions: must be an array")
            continue
        for question_index, question in enumerate(questions):
            qwhere = f"{where}.questions[{question_index}]"
            if not isinstance(question, dict):
                errors.append(f"{qwhere}: must be an object")
                continue
            require_fields(
                question,
                {"question_id", "lens", "question", "answer", "answer_status", "derived_threat_ids"},
                qwhere,
                errors,
            )
            status = question.get("answer_status")
            if status not in TRACE_ANSWER_STATUS:
                errors.append(f"{qwhere}: invalid answer_status {status!r}")
            derived = question.get("derived_threat_ids")
            if not isinstance(derived, list):
                errors.append(f"{qwhere}.derived_threat_ids: must be an array")
                continue
            if status == "generated_threat" and not derived:
                errors.append(f"{qwhere}: generated_threat needs derived_threat_ids")
            for threat_id in derived:
                if threat_id not in threat_ids:
                    errors.append(f"{qwhere}: unknown derived threat_id {threat_id}")

def validate_checklist_assessment(
    package: dict[str, Any],
    model_ids: set[str] | None,
    threat_ids: set[str],
    errors: list[str],
) -> None:
    assessment = package.get("checklist_assessment")
    if assessment is None:
        return
    if not isinstance(assessment, dict):
        errors.append("threat_package.checklist_assessment: must be an object")
        return
    require_fields(
        assessment,
        {"mode", "checklist_source", "checklist_items", "element_checks"},
        "checklist_assessment",
        errors,
    )
    if assessment.get("mode") != "checklist_assessment":
        errors.append("checklist_assessment: mode must be checklist_assessment")
    source = assessment.get("checklist_source")
    if isinstance(source, dict):
        require_fields(source, {"source_id", "source_reference", "selected_families"}, "checklist_assessment.checklist_source", errors)
    else:
        errors.append("checklist_assessment.checklist_source: must be an object")
    item_ids: set[str] = set()
    items = assessment.get("checklist_items")
    if not isinstance(items, list):
        errors.append("checklist_assessment.checklist_items: must be an array")
    else:
        for index, item in enumerate(items):
            where = f"checklist_assessment.checklist_items[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{where}: must be an object")
                continue
            require_fields(item, {"checklist_item_id", "family", "prompt", "applies_to", "source_kind"}, where, errors)
            item_id = item.get("checklist_item_id")
            if item_id in item_ids:
                errors.append(f"{where}: duplicate checklist_item_id {item_id}")
            elif item_id:
                item_ids.add(item_id)
            if item.get("source_kind") not in CHECK_SOURCE_KIND:
                errors.append(f"{where}: invalid source_kind {item.get('source_kind')!r}")
    checks = assessment.get("element_checks")
    if not isinstance(checks, list):
        errors.append("checklist_assessment.element_checks: must be an array")
        return
    for index, check in enumerate(checks):
        where = f"checklist_assessment.element_checks[{index}]"
        if not isinstance(check, dict):
            errors.append(f"{where}: must be an object")
            continue
        require_fields(
            check,
            {
                "check_id",
                "model_element_id",
                "model_element_type",
                "checklist_item_id",
                "relevance",
                "presence",
                "evidence_status",
                "evidence",
                "answer",
                "answer_status",
                "derived_threat_ids",
            },
            where,
            errors,
        )
        element_id = check.get("model_element_id")
        if model_ids is not None and element_id not in model_ids:
            errors.append(f"{where}: unknown model_element_id {element_id}")
        item_id = check.get("checklist_item_id")
        if item_ids and item_id not in item_ids:
            errors.append(f"{where}: unknown checklist_item_id {item_id}")
        if check.get("relevance") not in CHECK_RELEVANCE:
            errors.append(f"{where}: invalid relevance {check.get('relevance')!r}")
        if check.get("presence") not in CHECK_PRESENCE:
            errors.append(f"{where}: invalid presence {check.get('presence')!r}")
        if check.get("evidence_status") not in EVIDENCE_STATUS:
            errors.append(f"{where}: invalid evidence_status {check.get('evidence_status')!r}")
        status = check.get("answer_status")
        if status not in TRACE_ANSWER_STATUS:
            errors.append(f"{where}: invalid answer_status {status!r}")
        derived = check.get("derived_threat_ids")
        if not isinstance(derived, list):
            errors.append(f"{where}.derived_threat_ids: must be an array")
            continue
        if status == "generated_threat" and not derived:
            errors.append(f"{where}: generated_threat needs derived_threat_ids")
        for threat_id in derived:
            if threat_id not in threat_ids:
                errors.append(f"{where}: unknown derived threat_id {threat_id}")

def validate_workshop_simulation(
    package: dict[str, Any],
    model_ids: set[str] | None,
    threat_ids: set[str],
    errors: list[str],
) -> None:
    workshop = package.get("workshop_simulation")
    if workshop is None:
        return
    if not isinstance(workshop, dict):
        errors.append("threat_package.workshop_simulation: must be an object")
        return
    require_fields(workshop, {"mode", "deck", "facilitation", "card_plays"}, "workshop_simulation", errors)
    if workshop.get("mode") != "card_workshop":
        errors.append("workshop_simulation: mode must be card_workshop")
    deck = workshop.get("deck")
    if isinstance(deck, dict):
        require_fields(deck, {"deck_id", "title", "generation_mode", "play_mode", "suits", "cards_used"}, "workshop_simulation.deck", errors)
    else:
        errors.append("workshop_simulation.deck: must be an object")
    facilitation = workshop.get("facilitation")
    if isinstance(facilitation, dict):
        require_fields(facilitation, {"coverage_strategy", "element_order"}, "workshop_simulation.facilitation", errors)
        if model_ids is not None:
            for element_id in facilitation.get("element_order", []):
                if element_id not in model_ids:
                    errors.append(f"workshop_simulation.facilitation: unknown element_order id {element_id}")
    else:
        errors.append("workshop_simulation.facilitation: must be an object")
    card_plays = workshop.get("card_plays")
    if not isinstance(card_plays, list):
        errors.append("workshop_simulation.card_plays: must be an array")
        return
    for index, play in enumerate(card_plays):
        where = f"workshop_simulation.card_plays[{index}]"
        if not isinstance(play, dict):
            errors.append(f"{where}: must be an object")
            continue
        require_fields(
            play,
            {"play_id", "card_id", "card_title", "suit", "prompt", "target_model_element_ids", "answer", "answer_status", "derived_threat_ids"},
            where,
            errors,
        )
        status = play.get("answer_status")
        if status not in TRACE_ANSWER_STATUS:
            errors.append(f"{where}: invalid answer_status {status!r}")
        targets = play.get("target_model_element_ids")
        if not isinstance(targets, list) or not targets:
            errors.append(f"{where}.target_model_element_ids: must be a non-empty array")
        elif model_ids is not None:
            for element_id in targets:
                if element_id not in model_ids:
                    errors.append(f"{where}: unknown target_model_element_id {element_id}")
        derived = play.get("derived_threat_ids")
        if not isinstance(derived, list):
            errors.append(f"{where}.derived_threat_ids: must be an array")
            continue
        if status == "generated_threat" and not derived:
            errors.append(f"{where}: generated_threat needs derived_threat_ids")
        for threat_id in derived:
            if threat_id not in threat_ids:
                errors.append(f"{where}: unknown derived threat_id {threat_id}")

def validate_principles_assessment(
    package: dict[str, Any],
    model_ids: set[str] | None,
    threat_ids: set[str],
    errors: list[str],
    field_name: str = "principles_assessment",
    expected_mode: str = "principles_assessment",
) -> None:
    assessment = package.get(field_name)
    if assessment is None:
        return
    if not isinstance(assessment, dict):
        errors.append(f"threat_package.{field_name}: must be an object")
        return
    require_fields(
        assessment,
        {"mode", "principle_sources", "principles", "principle_checks"},
        field_name,
        errors,
    )
    if assessment.get("mode") != expected_mode:
        errors.append(f"{field_name}: mode must be {expected_mode}")
    source_ids: set[str] = set()
    sources = assessment.get("principle_sources")
    if not isinstance(sources, list):
        errors.append(f"{field_name}.principle_sources: must be an array")
    else:
        for index, source in enumerate(sources):
            where = f"{field_name}.principle_sources[{index}]"
            if not isinstance(source, dict):
                errors.append(f"{where}: must be an object")
                continue
            require_fields(source, {"source_id", "title", "url"}, where, errors)
            source_id = source.get("source_id")
            if source_id in source_ids:
                errors.append(f"{where}: duplicate source_id {source_id}")
            elif source_id:
                source_ids.add(source_id)
    principle_ids: set[str] = set()
    principles = assessment.get("principles")
    if not isinstance(principles, list):
        errors.append(f"{field_name}.principles: must be an array")
    else:
        for index, principle in enumerate(principles):
            where = f"{field_name}.principles[{index}]"
            if not isinstance(principle, dict):
                errors.append(f"{where}: must be an object")
                continue
            require_fields(principle, {"principle_id", "source_id", "title", "prompt", "applies_to"}, where, errors)
            principle_id = principle.get("principle_id")
            if principle_id in principle_ids:
                errors.append(f"{where}: duplicate principle_id {principle_id}")
            elif principle_id:
                principle_ids.add(principle_id)
            if source_ids and principle.get("source_id") not in source_ids:
                errors.append(f"{where}: unknown source_id {principle.get('source_id')}")
    checks = assessment.get("principle_checks")
    if not isinstance(checks, list):
        errors.append(f"{field_name}.principle_checks: must be an array")
        return
    for index, check in enumerate(checks):
        where = f"{field_name}.principle_checks[{index}]"
        if not isinstance(check, dict):
            errors.append(f"{where}: must be an object")
            continue
        require_fields(
            check,
            {
                "check_id",
                "model_element_id",
                "model_element_type",
                "principle_id",
                "relevance",
                "assessment",
                "evidence_status",
                "evidence",
                "answer",
                "answer_status",
                "derived_threat_ids",
            },
            where,
            errors,
        )
        element_id = check.get("model_element_id")
        if model_ids is not None and element_id not in model_ids:
            errors.append(f"{where}: unknown model_element_id {element_id}")
        if principle_ids and check.get("principle_id") not in principle_ids:
            errors.append(f"{where}: unknown principle_id {check.get('principle_id')}")
        if check.get("relevance") not in CHECK_RELEVANCE:
            errors.append(f"{where}: invalid relevance {check.get('relevance')!r}")
        if check.get("assessment") not in PRINCIPLE_ASSESSMENT:
            errors.append(f"{where}: invalid assessment {check.get('assessment')!r}")
        if check.get("evidence_status") not in EVIDENCE_STATUS:
            errors.append(f"{where}: invalid evidence_status {check.get('evidence_status')!r}")
        status = check.get("answer_status")
        if status not in TRACE_ANSWER_STATUS:
            errors.append(f"{where}: invalid answer_status {status!r}")
        derived = check.get("derived_threat_ids")
        if not isinstance(derived, list):
            errors.append(f"{where}.derived_threat_ids: must be an array")
            continue
        if status == "generated_threat" and not derived:
            errors.append(f"{where}: generated_threat needs derived_threat_ids")
        for threat_id in derived:
            if threat_id not in threat_ids:
                errors.append(f"{where}: unknown derived threat_id {threat_id}")

def validate_method_comparison(
    package: dict[str, Any],
    threat_ids: set[str],
    errors: list[str],
) -> None:
    comparison = package.get("method_comparison")
    if comparison is None:
        return
    if not isinstance(comparison, dict):
        errors.append("threat_package.method_comparison: must be an object")
        return
    require_fields(
        comparison,
        {"mode", "methods_run", "total_unique_threats", "method_results"},
        "method_comparison",
        errors,
    )
    if comparison.get("mode") != "multi_method":
        errors.append("method_comparison: mode must be multi_method")
    methods_run = comparison.get("methods_run")
    if not isinstance(methods_run, list):
        errors.append("method_comparison.methods_run: must be an array")
    else:
        for method in methods_run:
            if method not in METHOD_IDS:
                errors.append(f"method_comparison: invalid methods_run entry {method!r}")
    results = comparison.get("method_results")
    if not isinstance(results, list):
        errors.append("method_comparison.method_results: must be an array")
        return
    for index, result in enumerate(results):
        where = f"method_comparison.method_results[{index}]"
        if not isinstance(result, dict):
            errors.append(f"{where}: must be an object")
            continue
        require_fields(result, {"method", "threats_found", "unique_threat_ids", "overlapping_threat_ids"}, where, errors)
        if result.get("method") not in METHOD_IDS:
            errors.append(f"{where}: invalid method {result.get('method')!r}")
        for field in ["unique_threat_ids", "overlapping_threat_ids"]:
            ids = result.get(field)
            if not isinstance(ids, list):
                errors.append(f"{where}.{field}: must be an array")
                continue
            for threat_id in ids:
                if threat_id not in threat_ids:
                    errors.append(f"{where}: unknown {field} threat_id {threat_id}")
    overlaps = comparison.get("overlaps", [])
    if overlaps and not isinstance(overlaps, list):
        errors.append("method_comparison.overlaps: must be an array")
        return
    for index, overlap in enumerate(overlaps if isinstance(overlaps, list) else []):
        where = f"method_comparison.overlaps[{index}]"
        if not isinstance(overlap, dict):
            errors.append(f"{where}: must be an object")
            continue
        for threat_id in overlap.get("threat_ids", []):
            if threat_id not in threat_ids:
                errors.append(f"{where}: unknown overlap threat_id {threat_id}")


def validate_independent_elicitation_pass(
    package: dict[str, Any],
    model_ids: set[str] | None,
    threat_ids: set[str],
    errors: list[str],
) -> None:
    pass_obj = package.get("independent_elicitation_pass")
    if pass_obj is None:
        return
    if not isinstance(pass_obj, dict):
        errors.append("threat_package.independent_elicitation_pass: must be an object")
        return
    require_fields(
        pass_obj,
        {"mode", "baseline_threat_package_id", "methods_run", "candidate_checks", "reconciliation_summary"},
        "independent_elicitation_pass",
        errors,
    )
    if pass_obj.get("mode") != "independent_additional_elicitation":
        errors.append("independent_elicitation_pass: mode must be independent_additional_elicitation")
    methods_run = pass_obj.get("methods_run")
    if not isinstance(methods_run, list):
        errors.append("independent_elicitation_pass.methods_run: must be an array")
    else:
        for method in methods_run:
            if method not in METHOD_IDS:
                errors.append(f"independent_elicitation_pass: invalid methods_run entry {method!r}")
    candidates = pass_obj.get("candidate_checks")
    if not isinstance(candidates, list):
        errors.append("independent_elicitation_pass.candidate_checks: must be an array")
        return
    candidate_ids: set[str] = set()
    for index, candidate in enumerate(candidates):
        where = f"independent_elicitation_pass.candidate_checks[{index}]"
        if not isinstance(candidate, dict):
            errors.append(f"{where}: must be an object")
            continue
        require_fields(
            candidate,
            {
                "candidate_id",
                "target_model_element_ids",
                "methods",
                "candidate_story",
                "relation",
                "derived_threat_ids",
                "evidence_status",
                "evidence",
                "answer_status",
            },
            where,
            errors,
        )
        candidate_id = candidate.get("candidate_id")
        if candidate_id in candidate_ids:
            errors.append(f"{where}: duplicate candidate_id {candidate_id}")
        elif candidate_id:
            candidate_ids.add(candidate_id)
        targets = candidate.get("target_model_element_ids")
        if not isinstance(targets, list):
            errors.append(f"{where}.target_model_element_ids: must be an array")
        elif model_ids is not None:
            for element_id in targets:
                if element_id not in model_ids:
                    errors.append(f"{where}: unknown target_model_element_id {element_id}")
        methods = candidate.get("methods")
        if not isinstance(methods, list):
            errors.append(f"{where}.methods: must be an array")
        else:
            for method in methods:
                if method not in METHOD_IDS:
                    errors.append(f"{where}: invalid method {method!r}")
        if candidate.get("relation") not in COVERAGE_RELATIONS:
            errors.append(f"{where}: invalid relation {candidate.get('relation')!r}")
        if candidate.get("evidence_status") not in EVIDENCE_STATUS:
            errors.append(f"{where}: invalid evidence_status {candidate.get('evidence_status')!r}")
        status = candidate.get("answer_status")
        if status not in TRACE_ANSWER_STATUS:
            errors.append(f"{where}: invalid answer_status {status!r}")
        derived = candidate.get("derived_threat_ids")
        if not isinstance(derived, list):
            errors.append(f"{where}.derived_threat_ids: must be an array")
            continue
        if status == "generated_threat" and not derived:
            errors.append(f"{where}: generated_threat needs derived_threat_ids")
        for threat_id in derived:
            if threat_id not in threat_ids:
                errors.append(f"{where}: unknown derived threat_id {threat_id}")
        if status != "generated_threat" and derived:
            errors.append(f"{where}: non-producing answer_status must not derive threat IDs")
    summary = pass_obj.get("reconciliation_summary")
    if isinstance(summary, dict):
        for field in ["new_threat_ids", "confirmed_existing_threat_ids", "refined_existing_threat_ids"]:
            ids = summary.get(field, [])
            if ids and not isinstance(ids, list):
                errors.append(f"independent_elicitation_pass.reconciliation_summary.{field}: must be an array")
                continue
            for threat_id in ids if isinstance(ids, list) else []:
                if threat_id not in threat_ids:
                    errors.append(f"independent_elicitation_pass.reconciliation_summary: unknown {field} threat_id {threat_id}")
    else:
        errors.append("independent_elicitation_pass.reconciliation_summary: must be an object")


def validate_responses(
    package: dict[str, Any],
    threats: dict[str, Any] | None = None,
    require_complete_coverage: bool = False,
) -> list[str]:
    errors: list[str] = []
    require_fields(package, {
        "contract_version", "response_package_id", "model_id", "threat_package_id", "source_contract_version",
        "responses", "unresolved_threats", "cross_cutting_assumptions", "skeptic_result", "next_actions",
    }, "response_package", errors)
    errors.extend(legacy_assumption_references(package, "response_package"))
    check_version(package, "response_package", errors)
    if package.get("source_contract_version") != CONTRACT_VERSION:
        errors.append("response_package: source_contract_version mismatch")
    if threats and package.get("threat_package_id") != threats.get("threat_package_id"):
        errors.append("response_package: threat_package_id does not match threat package")
    threat_ids = {t.get("threat_id") for t in threats.get("threats", [])} if threats else None
    seen_response_ids: set[str] = set()
    covered_threat_ids: set[str] = set()
    for index, response in enumerate(package.get("responses", [])):
        where = f"responses[{index}]"
        require_fields(response, REQUIRED_RESPONSE_FIELDS, where, errors)
        affected = response.get("affected_model_elements")
        if not isinstance(affected, list) or not affected:
            errors.append(f"{where}: affected_model_elements must be a non-empty array")
        if not isinstance(response.get("next_action"), str) or not response["next_action"].strip():
            errors.append(f"{where}: next_action must be a non-empty string")
        response_id = response.get("response_id")
        if response_id and not CANONICAL_RESPONSE_ID.fullmatch(str(response_id)):
            errors.append(f"{where}: non-canonical response_id {response_id!r}")
        if response_id in seen_response_ids:
            errors.append(f"{where}: duplicate response_id {response_id}")
        elif response_id:
            seen_response_ids.add(response_id)
        if threat_ids is not None and response.get("threat_id") not in threat_ids:
            errors.append(f"{where}: unknown threat_id {response.get('threat_id')}")
        if response.get("threat_id"):
            covered_threat_ids.add(response["threat_id"])
        text = " ".join(str(response.get(part, "")) for part in ["response", "mechanism_or_text"]).lower()
        if "best practice" in text or "best practices" in text:
            errors.append(f"{where}: vague best-practice response")
        if "out of scope" in text:
            errors.append(f"{where}: out of scope is not an ERTA response")
        erta = response.get("erta")
        if erta == "Eliminate" and not response.get("mechanism_or_text"):
            errors.append(f"{where}: Eliminate needs mechanism_or_text")
        if erta == "Reduce" and not response.get("remaining_threat"):
            errors.append(f"{where}: Reduce needs remaining_threat")
        if erta == "Transfer":
            if not response.get("transfer_receiver"):
                errors.append(f"{where}: Transfer needs transfer_receiver")
            if not response.get("assumptions"):
                errors.append(f"{where}: Transfer needs explicit assumptions")
        if erta == "Accept":
            if not response.get("acceptance_rationale"):
                errors.append(f"{where}: Accept needs acceptance_rationale")
            if not response.get("owner"):
                errors.append(f"{where}: Accept needs owner")
            if not response.get("revisit_trigger"):
                errors.append(f"{where}: Accept needs revisit_trigger")
        if erta == "Unresolved" and response.get("status") not in {"blocked", "needs-threat-clarification"}:
            errors.append(f"{where}: Unresolved requires blocked or needs-threat-clarification status")
        if response.get("status") == "needs-threat-clarification" and response.get("mechanism_or_text"):
            errors.append(f"{where}: unclear threat should not gain a concrete mechanism")
        validate_assumption_refs(response.get("assumptions"), f"{where}.assumptions", errors)
    cross_cutting = package.get("cross_cutting_assumptions")
    if not isinstance(cross_cutting, list):
        errors.append("response_package.cross_cutting_assumptions: must be an array")
    else:
        for index, assumption in enumerate(cross_cutting):
            where = f"response_package.cross_cutting_assumptions[{index}]"
            if not isinstance(assumption, dict):
                errors.append(f"{where}: must be an object")
                continue
            assumption_id = assumption.get("assumption_id") or assumption.get("id")
            if not isinstance(assumption_id, str) or not CANONICAL_ASSUMPTION_ID.fullmatch(assumption_id):
                errors.append(f"{where}: assumption ID {assumption_id!r} must use A-###")
            if not is_nonempty(assumption.get("statement") or assumption.get("text")):
                errors.append(f"{where}: assumption statement must be non-empty")
            applies_to = assumption.get("applies_to", [])
            if not isinstance(applies_to, list):
                errors.append(f"{where}.applies_to: must be an array")
            else:
                for response_id in applies_to:
                    if response_id not in seen_response_ids:
                        errors.append(f"{where}: unknown applies_to response ID {response_id!r}")
    if require_complete_coverage and threat_ids is not None:
        missing = sorted(threat_ids - covered_threat_ids)
        if missing:
            errors.append(f"response_package: missing response rows for threat IDs {missing}")
    return errors


def validate_dfd_dictionary(dictionary: dict[str, Any], model: dict[str, Any] | None = None) -> list[str]:
    errors: list[str] = []
    require_fields(dictionary, {"contract_version", "model_id", "rows"}, "dfd_dictionary", errors)
    check_version(dictionary, "dfd_dictionary", errors)
    if model and dictionary.get("model_id") != model.get("model_id"):
        errors.append("dfd_dictionary: model_id does not match model packet")
    model_ids = collect_model_ids(model) if model else None
    rows = dictionary.get("rows")
    if not isinstance(rows, list):
        errors.append("dfd_dictionary.rows: must be an array")
        return errors
    row_ids: set[str] = set()
    for index, row in enumerate(rows):
        where = f"dfd_dictionary.rows[{index}]"
        if not isinstance(row, dict):
            errors.append(f"{where}: must be an object")
            continue
        require_fields(row, REQUIRED_DICTIONARY_FIELDS, where, errors)
        canonical_id = row.get("canonical_id")
        if canonical_id and not CANONICAL_MODEL_ID.fullmatch(str(canonical_id)):
            errors.append(f"{where}: non-canonical canonical_id {canonical_id!r}")
        if canonical_id in row_ids:
            errors.append(f"{where}: duplicate canonical_id {canonical_id}")
        elif canonical_id:
            row_ids.add(canonical_id)
        renderer_id = str(row.get("mermaid_node_id", ""))
        if not re.fullmatch(r"(EE|PO|DS|DF|TB)\d+_[A-Za-z0-9_]+", renderer_id):
            errors.append(f"{where}: invalid Mermaid renderer ID {renderer_id!r}")
        for field in ["visible_label", "name", "description", "source_id", "specification_reference"]:
            if not is_nonempty(row.get(field)):
                errors.append(f"{where}: {field} must be non-empty")
        validate_assumption_refs(row.get("assumptions"), f"{where}.assumptions", errors)
        if str(canonical_id).startswith("DF-"):
            for field in ["flow_source", "flow_destination"]:
                value = row.get(field)
                if not value:
                    errors.append(f"{where}: data-flow row requires {field}")
                elif not CANONICAL_MODEL_ID.fullmatch(str(value)):
                    errors.append(f"{where}: {field} has non-canonical ID {value!r}")
    if model_ids is not None:
        missing = sorted(model_ids - row_ids)
        extra = sorted(row_ids - model_ids)
        if missing:
            errors.append(f"dfd_dictionary: missing model IDs {missing}")
        if extra:
            errors.append(f"dfd_dictionary: unknown dictionary IDs {extra}")
    return errors


def validate_handoff(handoff: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {
        "contract_version", "handoff_id", "run_id", "producer_agent",
        "producer_role", "consumer_role", "artifact_kind", "artifact_path",
        "input_artifacts", "exclusive_write_scope", "source_corpus_manifest",
        "id_authority", "status", "validation", "provenance", "blocking_issues",
    }
    require_fields(handoff, required, "handoff", errors)
    check_version(handoff, "handoff", errors)
    artifact_kind = handoff.get("artifact_kind")
    expected_authority = HANDOFF_ID_AUTHORITY.get(artifact_kind)
    if expected_authority is None:
        errors.append(f"handoff: invalid artifact_kind {artifact_kind!r}")
    elif handoff.get("id_authority") != expected_authority:
        errors.append(
            f"handoff: {artifact_kind} requires id_authority {expected_authority!r}, "
            f"got {handoff.get('id_authority')!r}"
        )
    validation = handoff.get("validation")
    if not isinstance(validation, dict):
        errors.append("handoff.validation: must be an object")
    else:
        require_fields(validation, {"result", "checks", "evidence_paths"}, "handoff.validation", errors)
        if handoff.get("status") == "ready":
            if validation.get("result") != "pass":
                errors.append("handoff: ready status requires validation.result pass")
            if not validation.get("evidence_paths"):
                errors.append("handoff: ready status requires validation evidence_paths")
    if not handoff.get("exclusive_write_scope"):
        errors.append("handoff: exclusive_write_scope must be non-empty")
    return errors


def collect_model_ids(model: dict[str, Any] | None) -> set[str]:
    if not model:
        return set()
    ids: set[str] = set()
    for collection in ["external_entities", "processes", "data_stores", "data_flows", "trust_boundaries"]:
        for element in model.get(collection, []):
            element_id = element.get("stable_id") or element.get("candidate_id")
            if element_id:
                ids.add(element_id)
    return ids


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model")
    parser.add_argument("--threats")
    parser.add_argument("--responses")
    parser.add_argument("--dictionary")
    parser.add_argument("--handoff")
    parser.add_argument("--require-complete-response-coverage", action="store_true")
    args = parser.parse_args()
    errors: list[str] = []
    model = load_json(Path(args.model)) if args.model else None
    threats = load_json(Path(args.threats)) if args.threats else None
    responses = load_json(Path(args.responses)) if args.responses else None
    dictionary = load_json(Path(args.dictionary)) if args.dictionary else None
    handoff = load_json(Path(args.handoff)) if args.handoff else None
    if model:
        errors.extend(validate_model(model))
    if threats:
        errors.extend(validate_threats(threats, model))
    if responses:
        errors.extend(validate_responses(responses, threats, args.require_complete_response_coverage))
    if dictionary:
        errors.extend(validate_dfd_dictionary(dictionary, model))
    if handoff:
        errors.extend(validate_handoff(handoff))
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("threat-model-contract validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
