#!/usr/bin/env python3
"""Required Miner Knowledge + Threat Knowledge reconciliation for Web specifications.

prepare: read a pinned model, complete exact source packet, portable miner cache
and the bundled Threat Knowledge method registry; produce a versioned, immutable
selection plan and a pending disposition template for THREE phases.
verify: fail closed unless every selected record has evidence, model attachment
and a justified final disposition. This tool does NOT auto-claim applicability.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from query_miner_cache import inspect as inspect_cache
from query_threat_knowledge_cache import load as load_threat_knowledge_cache

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "specification-threat-knowledge/v1"
PHASES = ("explicit", "implicit", "additional")
PROVIDERS = ("miner_knowledge", "threat_knowledge")
DOMAINS = (
    "security",
    "privacy",
    "design",
    "accessibility",
    "internationalization",
    "harms",
    "human-rights",
)
ALIASES = {
    "tag": "design",
    "a11y": "accessibility",
    "i18n": "internationalization",
    "human_rights": "human-rights",
}
STATUS = {
    "explicit": {
        "documented_threat",
        "documented_control",
        "not_documented",
        "not_applicable",
        "unable_to_verify",
    },
    "implicit": {
        "observed_control",
        "partially_observed_control",
        "control_absent",
        "not_applicable",
        "unable_to_verify",
    },
    "additional": {
        "new_threat",
        "confirms_existing",
        "refines_existing",
        "not_applicable",
        "unable_to_verify",
    },
}
REQUIRES_SOURCE = {
    "documented_threat",
    "documented_control",
    "observed_control",
    "partially_observed_control",
    "control_absent",
    "new_threat",
    "confirms_existing",
    "refines_existing",
}
REQUIRES_THREAT = {
    "documented_threat",
    "new_threat",
    "confirms_existing",
    "refines_existing",
}
REQUIRES_BAD_EVENT = {
    "observed_control",
    "partially_observed_control",
    "control_absent",
}
STOPWORDS = frozenset(
    {
        "with",
        "will",
        "what",
        "which",
        "when",
        "where",
        "from",
        "that",
        "this",
        "shall",
        "should",
        "could",
        "would",
        "about",
        "there",
        "their",
        "have",
        "been",
        "using",
        "used",
        "your",
        "into",
        "more",
        "does",
        "only",
        "then",
        "were",
        "also",
        "than",
        "them",
        "user",
        "users",
        "data",
        "document",
        "specification",
        "source",
        "model",
        "review",
        "considerations",
    }
)


def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode()


def read_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"{path.name}: expected a JSON object")
    return data


def evidence_inspector():
    path = ROOT / "tools/reviewctl/evidence.py"
    spec = importlib.util.spec_from_file_location("portable_evidence_inspector", path)
    if spec is None or spec.loader is None:
        raise ValueError("missing portable source evidence inspector")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect_packet


def validated_source(path: Path) -> tuple[dict, dict]:
    primary, coverage = evidence_inspector()(path.read_bytes())
    if coverage.get("primary_coverage") != "complete":
        raise ValueError("primary specification packet is incomplete")
    snapshot = coverage.get("snapshot_url", "")
    if not snapshot.startswith("https://"):
        raise ValueError("immutable HTTPS target URL is required")
    if len(primary["sections"]) != coverage["sections"]:
        raise ValueError("source packet section count changed")
    for section in primary["sections"]:
        url = section.get("source_url", "")
        if not isinstance(url, str) or not url.startswith(snapshot.rstrip("/") + "/#"):
            raise ValueError("source section belongs to another snapshot")
    return primary, coverage


def model_elements(model: dict) -> tuple[dict[str, dict], list[str]]:
    elements = {}
    for collection in (
        "external_entities",
        "processes",
        "data_stores",
        "data_flows",
        "trust_boundaries",
    ):
        for record in model.get(collection, []):
            if not isinstance(record, dict):
                raise TypeError("model contains an invalid element")
            identifier = record.get("stable_id") or record.get("candidate_id")
            if not isinstance(identifier, str) or not re.fullmatch(
                r"(EE|PO|DS|DF|TB)-\d{2,}", identifier
            ):
                raise ValueError("model contains a non-canonical element identifier")
            if identifier in elements:
                raise ValueError("duplicate model element identifier")
            elements[identifier] = {"collection": collection, **record}
    if not elements:
        raise ValueError("model contains no pointable DFD elements")
    if not all(
        isinstance(model.get(k), str) and model[k]
        for k in ("run_id", "model_id", "target_id")
    ):
        raise ValueError("model is missing its exact identity")
    assumptions = [
        x.get("id", x.get("assumption_id")) for x in model.get("assumptions", [])
    ]
    return elements, assumptions


def validate_target_model(model: dict, coverage: dict) -> dict[str, dict]:
    elements, _ = model_elements(model)
    snapshot = coverage["snapshot_url"].rstrip("/")
    references = [
        str(entry.get("source_reference", ""))
        for entry in model.get("source_inventory", [])
        if isinstance(entry, dict)
    ]
    if not references or not any(value.rstrip("/") == snapshot for value in references):
        raise ValueError(
            "model.source_inventory is not pinned to the exact source packet snapshot"
        )
    return elements


def domains_from(text: str) -> list[str]:
    domains = [
        ALIASES.get(x.strip().lower(), x.strip().lower()) for x in text.split(",")
    ]
    if (
        not domains
        or any(x not in DOMAINS for x in domains)
        or len(set(domains)) != len(domains)
    ):
        raise ValueError(
            "unknown or duplicate review domains (sustainability is not integrated)"
        )
    return domains


def tokens(value: object) -> set[str]:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    return {
        x
        for x in re.findall(r"[a-z][a-z0-9_-]{3,}", str(value).lower())
        if x not in STOPWORDS
    }


def source_and_method_registry() -> tuple[dict, dict, bytes, bytes]:
    sources_path = ROOT / "skills/threat-knowledge/references/public-sources.json"
    methods_path = ROOT / "prompt-packs/operational-method-prompts-v1.json"
    sources_data, methods_data = sources_path.read_bytes(), methods_path.read_bytes()
    source_registry, prompts = json.loads(sources_data), json.loads(methods_data)
    if source_registry.get("schema_version") != "threat-prompt-source-registry/v1":
        raise ValueError("unsupported Threat Knowledge source registry")
    if prompts.get("schema_version") != "web-standards-review-method-prompts/v1":
        raise ValueError("unsupported operational method question registry")
    sources = {r["id"]: r for r in source_registry["sources"]}
    if len(sources) != len(source_registry["sources"]):
        raise ValueError("duplicate Threat Knowledge source identities")
    for entry in prompts["questions"]:
        if entry["source_id"] not in sources or not all(
            isinstance(entry.get("phase_questions", {}).get(phase), str)
            and entry["phase_questions"][phase].strip()
            for phase in PHASES
        ):
            raise ValueError("operational questions have missing provenance or phases")
    return sources, prompts, sources_data, methods_data


def selected_threat_methods(domains: list[str], questions: list[dict]) -> list[dict]:
    domain_set = set(domains)
    selection = [row for row in questions if row["domain"] in domain_set]
    # Design is a review discipline, not a separate normative threat method.
    # Likewise i18n/a11y have no bundled specialized source catalog yet.
    routing = {
        "design": {"stride", "rfc3552"},
        "accessibility": {"linddun", "harms"},
        "internationalization": {"linddun", "rfc6973"},
    }
    extra = (
        set().union(*(routing[d] for d in domain_set if d in routing))
        if domain_set & routing.keys()
        else set()
    )
    selection += [
        row for row in questions if row["source_id"] in extra and row not in selection
    ]
    return sorted(selection, key=lambda row: (row["domain"], row["source_id"]))


def selected_threat_cache_methods(
    cache_path: Path, domains: list[str], model: dict, per_source: int
) -> list[dict]:
    """Use the existing Threat Knowledge corpus cache, not a second method table."""
    entries, _manifest = load_threat_knowledge_cache(cache_path)
    source_to_method = {
        "stride": "stride_per_element",
        "rfc3552": "rfc3552_security_per_element",
        "linddun": "linddun_per_element",
        "rfc6973": "rfc6973_privacy_per_element",
        "rfc9620": "rfc9620_human_rights_per_element",
        "harms": "microsoft_harms_modeling_per_element",
        "stakeholders": "microsoft_harms_modeling_per_element",
        "w3c-privacy-security": "independent_additional_elicitation",
    }
    expansion = {
        "design": {"security", "combined"},
        "accessibility": {"privacy", "harms", "human-rights"},
        "internationalization": {"privacy", "human-rights"},
    }
    allowed_domains = set(domains)
    for domain in domains:
        allowed_domains.update(expansion.get(domain, set()))
    if {"security", "privacy"} & set(domains):
        allowed_domains.add("combined")
    candidates = [
        r
        for r in entries
        if r["domain"] in allowed_domains and r["source_id"] in source_to_method
    ]
    relevant = profile_terms(model)
    by_source = defaultdict(list)
    for entry in candidates:
        by_source[entry["source_id"]].append(entry)
    methods = []
    for source_id, rows in sorted(by_source.items()):
        ordered = sorted(
            rows,
            key=lambda row: (
                -(
                    3 * len(tokens(row["category"]) & relevant)
                    + len(tokens(row["question"]) & relevant)
                ),
                row["id"],
            ),
        )
        for entry in ordered[:per_source]:
            question = entry["question"]
            methods.append(
                {
                    "source_id": entry["id"],
                    "method_id": source_to_method[source_id],
                    "domain": entry["domain"],
                    "applies_to": [
                        "external_entities",
                        "processes",
                        "data_stores",
                        "data_flows",
                        "trust_boundaries",
                    ],
                    "source_mode": "portable_threat_knowledge_cache",
                    "source_url": entry["source_url"],
                    "authority": entry["authority"],
                    "phase_questions": {
                        "explicit": "Is this Threat Knowledge concern directly described in the specification's explicit considerations? "
                        + question,
                        "implicit": "Do existing or omitted normative safeguards imply this Threat Knowledge bad event? "
                        + question,
                        "additional": "Independently apply this Threat Knowledge question to the model and source evidence: "
                        + question,
                    },
                }
            )
    if not methods:
        raise ValueError("Threat Knowledge cache contains no applicable method prompts")
    return methods


def profile_terms(model: dict) -> set[str]:
    summary = [
        model.get("system_under_analysis"),
        model.get("scenario"),
        model.get("scope", []),
        model.get("assets_and_properties", []),
        model.get("inline_safeguards", []),
    ]
    for key in ("processes", "data_flows", "trust_boundaries", "external_entities"):
        summary.extend(
            [
                row.get("name", "") + " " + row.get("description", "")
                for row in model.get(key, [])
            ]
        )
    return tokens(summary)


def choose_miner_rows(
    records: list[dict], domains: list[str], model: dict, per_source: int
) -> tuple[list[dict], list[dict]]:
    available = [
        row
        for row in records
        if row.get("domain") in domains and row.get("skill") != "method-reference-index"
    ]
    by_source: dict[str, list[dict]] = defaultdict(list)
    for row in available:
        by_source[row["skill"]].append(row)
    relevant = profile_terms(model)
    selected = []
    exclusions = []
    for source, rows in sorted(by_source.items()):
        ranking = sorted(
            rows,
            key=lambda row: (
                -(
                    3 * len(tokens(row["title"]) & relevant)
                    + 2 * len(tokens(row["applicability"]) & relevant)
                    + len(tokens(row["question"]) & relevant)
                ),
                row["id"],
            ),
        )
        chosen = ranking[:per_source]
        if not chosen:
            continue
        selected.extend(chosen)
        exclusions.append(
            {
                "source": source,
                "inventory": len(rows),
                "selected": len(chosen),
                "unselected": len(rows) - len(chosen),
                "reason": "bounded by per-source selection; unselected not assessed as non-applicable",
            }
        )
    return selected, exclusions


def matching_sections(
    section_rows: list[dict], question: str, limit: int = 3
) -> list[str]:
    query_terms = tokens(question)
    ranked = []
    for section in section_rows:
        title_tokens = tokens(section.get("heading", ""))
        body_tokens = tokens(section.get("text", "")[:4000])
        score = 3 * len(title_tokens & query_terms) + len(body_tokens & query_terms)
        if score > 0:
            ranked.append((-score, section["source_url"]))
    return [url for _, url in sorted(ranked)[:limit]]


def matching_model_ids(
    elements: dict[str, dict], question: str, families: list[str] | None, limit: int = 4
) -> list[str]:
    ts = tokens(question)
    relevant = []
    for identifier, element in elements.items():
        if families and element["collection"] not in families:
            continue
        score = 3 * len(ts & tokens(element.get("name", "")))
        score += len(ts & tokens(element.get("description", "")))
        relevant.append((-score, identifier))
    ranking = sorted(relevant)
    return [identifier for score, identifier in ranking if score < 0][:limit]


def prepare(
    model_path: Path,
    packet_path: Path,
    cache_path: Path,
    domains_text: str,
    per_source: int,
    output: Path,
    mode: str = "full",
    threat_cache_path: Path | None = None,
) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError("preflight output already exists; use a new run directory")
    if not 1 <= per_source <= 30:
        raise ValueError("per-source limit must be between 1 and 30")
    domains = domains_from(domains_text)
    model = read_json(model_path)
    primary, coverage = validated_source(packet_path)
    elements = validate_target_model(model, coverage)
    records, cache_manifest = inspect_cache(cache_path)
    sources, prompts, source_bytes, prompt_bytes = source_and_method_registry()
    miners, exclusions = choose_miner_rows(records, domains, model, per_source)
    methods = (
        selected_threat_cache_methods(threat_cache_path, domains, model, per_source)
        if threat_cache_path
        else selected_threat_methods(domains, prompts["questions"])
    )
    if not miners:
        raise ValueError("Miner Knowledge returned no selected catalog questions")
    if not methods:
        raise ValueError("Threat Knowledge returned no selected method questions")
    considerations = [
        section
        for section in primary["sections"]
        if "consideration" in section.get("heading", "").lower()
        and (
            "security" in section.get("heading", "").lower()
            or "privacy" in section.get("heading", "").lower()
            or "rights" in section.get("heading", "").lower()
        )
    ]
    phases = PHASES if mode == "full" else PHASES[:2]
    rows = []
    for phase in phases:
        sections = considerations if phase == "explicit" else primary["sections"]
        for selected in miners:
            question = {
                "explicit": "In Security/Privacy Considerations, is the risk addressed by this catalog entry explicitly described? "
                + selected["question"],
                "implicit": "In normative behavior, is the protective control observed, absent, or incomplete, and what risk does it imply? "
                + selected["question"],
                "additional": "Apply this mined pattern as an independent candidate; is there a concrete uncovered bad event at this model boundary? "
                + selected["question"],
            }[phase]
            item_id = selected["id"]
            rows.append(
                {
                    "id": "K-"
                    + sha((phase + "|miner_knowledge|" + item_id).encode())[:16],
                    "phase": phase,
                    "provider": "miner_knowledge",
                    "source_item_id": item_id,
                    "source_mode": "portable_cache",
                    "catalog_skill": selected["skill"],
                    "record_kind": selected["kind"],
                    "domain": selected["domain"],
                    "question": question,
                    "authority": selected["authority"],
                    "source_reference": selected["source_url"],
                    "section_suggestions": matching_sections(
                        sections, selected["title"] + " " + selected["question"]
                    ),
                    "model_suggestions": matching_model_ids(
                        elements, selected["title"] + " " + selected["question"], None
                    ),
                }
            )
        for selected in methods:
            sid = selected["source_id"]
            question = selected["phase_questions"][phase]
            rows.append(
                {
                    "id": "K-"
                    + sha((phase + "|threat_knowledge|" + sid).encode())[:16],
                    "phase": phase,
                    "provider": "threat_knowledge",
                    "source_item_id": sid,
                    "method_id": selected["method_id"],
                    "source_mode": selected.get(
                        "source_mode", "bundled_operational_questions"
                    ),
                    "record_kind": "method_prompt",
                    "domain": selected["domain"],
                    "question": question,
                    "authority": selected.get(
                        "authority",
                        sources.get(sid, {}).get("authority", "source_link"),
                    ),
                    "source_reference": selected.get(
                        "source_url", sources.get(sid, {}).get("url", "")
                    ),
                    "section_suggestions": matching_sections(sections, question),
                    "model_suggestions": matching_model_ids(
                        elements, question, selected["applies_to"]
                    ),
                }
            )
    row_ids = [row["id"] for row in rows]
    if len(row_ids) != len(set(row_ids)):
        raise ValueError("repeated selected knowledge item identity")
    coverage_by_phase = {
        phase: {
            provider: sum(
                row["phase"] == phase and row["provider"] == provider for row in rows
            )
            for provider in PROVIDERS
        }
        for phase in phases
    }
    if any(
        coverage_by_phase[phase][provider] == 0
        for phase in phases
        for provider in PROVIDERS
    ):
        raise ValueError(
            "both knowledge providers are mandatory in each requested phase"
        )
    model_blob, packet_blob, cache_blob = (
        model_path.read_bytes(),
        packet_path.read_bytes(),
        cache_path.read_bytes(),
    )
    plan = {
        "schema_version": SCHEMA,
        "state": "selected_requires_application",
        "created_at": datetime.now(UTC).isoformat(),
        "mode": mode,
        "phases": phases,
        "domains": domains,
        "per_source": per_source,
        "run_id": model["run_id"],
        "model_id": model["model_id"],
        "target_id": model["target_id"],
        "immutable_snapshot_url": coverage["snapshot_url"],
        "specification_version_id": coverage["specification_version_id"],
        "source_packet_sha256": sha(packet_blob),
        "model_sha256": sha(model_blob),
        "cache_sha256": sha(cache_blob),
        "threat_cache_sha256": sha(threat_cache_path.read_bytes())
        if threat_cache_path
        else None,
        "threat_cache_mode": "portable_corpus"
        if threat_cache_path
        else "source_registry_fallback",
        "cache_manifest_schema": cache_manifest["schema_version"],
        "threat_source_registry_sha256": sha(source_bytes),
        "operational_method_prompts_sha256": sha(prompt_bytes),
        "primary_sections": coverage["sections"],
        "explicit_considerations_sections": [
            row["source_url"] for row in considerations
        ],
        "provider_phase_coverage": coverage_by_phase,
        "source_selection_exclusions": exclusions,
        "method_sources_selected": sorted({row["source_id"] for row in methods}),
        "limitations": [
            "Selection and section/model suggestions are only discovery aids.",
            "A real review must decide every selected item and cite exact source sections.",
            "Threat Knowledge operational questions are author-created prompts, not complete third-party method texts.",
            "The additional phase is independent of baseline dispositions until subsequent reconciliation.",
            "No W3C or implementation finding, harm, control, or vulnerability is established by this plan.",
        ],
        "rows": rows,
    }
    plan_blob = json_bytes(plan)
    template = {
        "schema_version": SCHEMA,
        "state": "pending_dispositions",
        "selection_sha256": sha(plan_blob),
        "run_id": plan["run_id"],
        "model_sha256": plan["model_sha256"],
        "source_packet_sha256": plan["source_packet_sha256"],
        "rows": [
            {
                "id": row["id"],
                "phase": row["phase"],
                "provider": row["provider"],
                "source_item_id": row["source_item_id"],
                "disposition": "pending",
                "element_ids": [],
                "section_urls": [],
                "threat_ids": [],
                "bad_event": "",
                "rationale": "",
            }
            for row in rows
        ],
    }
    output.mkdir(parents=True)
    (output / "knowledge-selection.json").write_bytes(plan_blob)
    (output / "knowledge-dispositions.template.json").write_bytes(json_bytes(template))
    return {
        "status": "requires_dispositions",
        "selection": str(output / "knowledge-selection.json"),
        "template": str(output / "knowledge-dispositions.template.json"),
        "total": len(rows),
        "phase_coverage": coverage_by_phase,
        "unselected_miner_catalog_records": sum(x["unselected"] for x in exclusions),
    }


def validate_dispositions(
    plan_path: Path,
    ledger_path: Path,
    model_path: Path,
    packet_path: Path,
    cache_path: Path,
    threats_path: Path,
    baseline_path: Path | None = None,
    threat_cache_path: Path | None = None,
) -> dict:
    plan_blob = plan_path.read_bytes()
    plan = read_json(plan_path)
    ledger = read_json(ledger_path)
    if plan.get("schema_version") != SCHEMA or ledger.get("schema_version") != SCHEMA:
        raise ValueError("unsupported knowledge plan or disposition schema")
    if plan.get("state") != "selected_requires_application":
        raise ValueError("invalid knowledge plan state")
    if ledger.get("selection_sha256") != sha(plan_blob):
        raise ValueError("dispositions do not reference these exact selected questions")
    model = read_json(model_path)
    primary, coverage = validated_source(packet_path)
    elements = validate_target_model(model, coverage)
    known_sections = {x["source_url"] for x in primary["sections"]}
    threats = read_json(threats_path)
    retained = {row["threat_id"]: row for row in threats.get("threats", [])}
    if len(retained) != len(threats.get("threats", [])):
        raise ValueError("duplicate canonical threat ID")
    baseline = read_json(baseline_path) if baseline_path else None
    baseline_ids = (
        {x["threat_id"] for x in baseline.get("threats", [])} if baseline else set()
    )
    if plan.get("mode") == "full" and baseline is None:
        raise ValueError(
            "full review requires separately frozen baseline threat package"
        )
    _registry, method_registry, source_blob, prompt_blob = source_and_method_registry()
    catalog_records, _cache_manifest = inspect_cache(cache_path)
    expected_phases = (
        PHASES
        if plan.get("mode") == "full"
        else PHASES[:2]
        if plan.get("mode") == "baseline"
        else None
    )
    if expected_phases is None or plan.get("phases") != list(expected_phases):
        raise ValueError("knowledge plan cannot omit a mandatory review phase")
    expected_domains = domains_from(",".join(plan.get("domains", [])))
    expected_miners, _excluded = choose_miner_rows(
        catalog_records, expected_domains, model, plan.get("per_source", 0)
    )
    if (plan.get("threat_cache_sha256") is None) != (threat_cache_path is None):
        raise ValueError(
            "Threat Knowledge cache presence differs from the frozen selection"
        )
    if threat_cache_path and plan["threat_cache_sha256"] != sha(
        threat_cache_path.read_bytes()
    ):
        raise ValueError(
            "Threat Knowledge cache digest differs from the frozen selection"
        )
    expected_methods = (
        selected_threat_cache_methods(
            threat_cache_path, expected_domains, model, plan.get("per_source", 0)
        )
        if threat_cache_path
        else selected_threat_methods(expected_domains, method_registry["questions"])
    )
    expected_identity = {}
    for phase in expected_phases:
        for record in expected_miners:
            key = "K-" + sha((phase + "|miner_knowledge|" + record["id"]).encode())[:16]
            expected_identity[key] = ("miner_knowledge", phase, record["id"])
        for record in expected_methods:
            key = (
                "K-"
                + sha((phase + "|threat_knowledge|" + record["source_id"]).encode())[
                    :16
                ]
            )
            expected_identity[key] = ("threat_knowledge", phase, record["source_id"])
    actual_selected = {
        row.get("id"): (
            row.get("provider"),
            row.get("phase"),
            row.get("source_item_id"),
        )
        for row in plan.get("rows", [])
        if isinstance(row, dict)
    }
    if actual_selected != expected_identity or len(plan.get("rows", [])) != len(
        expected_identity
    ):
        raise ValueError(
            "knowledge plan does not match the complete deterministic provider selection"
        )
    actual = {
        "model_sha256": sha(model_path.read_bytes()),
        "source_packet_sha256": sha(packet_path.read_bytes()),
        "cache_sha256": sha(cache_path.read_bytes()),
        "threat_source_registry_sha256": sha(source_blob),
        "operational_method_prompts_sha256": sha(prompt_blob),
    }
    bad_hashes = [key for key, digest in actual.items() if plan.get(key) != digest]
    if bad_hashes:
        raise ValueError(
            "knowledge inputs changed after selection: " + ", ".join(bad_hashes)
        )
    if (
        plan.get("immutable_snapshot_url") != coverage["snapshot_url"]
        or plan.get("specification_version_id") != coverage["specification_version_id"]
        or plan.get("run_id") != model["run_id"]
        or plan.get("model_id") != model["model_id"]
        or plan.get("target_id") != model["target_id"]
        or ledger.get("run_id") != model["run_id"]
        or ledger.get("model_sha256") != actual["model_sha256"]
        or ledger.get("source_packet_sha256") != actual["source_packet_sha256"]
        or threats.get("model_id") != model["model_id"]
        or threats.get("run_id") != model["run_id"]
        or baseline
        and baseline.get("model_id") != model["model_id"]
    ):
        raise ValueError("source/model/threat identity mismatch")
    rows = plan.get("rows")
    submitted = ledger.get("rows")
    if not isinstance(rows, list) or not isinstance(submitted, list):
        raise TypeError("knowledge plan and dispositions must both contain rows")
    plan_ids = [x.get("id") for x in rows if isinstance(x, dict)]
    ledger_ids = [x.get("id") for x in submitted if isinstance(x, dict)]
    if (
        len(plan_ids) != len(rows)
        or len(ledger_ids) != len(submitted)
        or len(set(plan_ids)) != len(plan_ids)
        or len(set(ledger_ids)) != len(ledger_ids)
        or set(plan_ids) != set(ledger_ids)
    ):
        raise ValueError("missing, additional or duplicated knowledge dispositions")
    by_id = {x["id"]: x for x in rows}
    checks = []
    errors = []
    still_open = []
    count = Counter()
    for item in submitted:
        source = by_id[item["id"]]
        idx = item["id"]
        phase, provider = source["phase"], source["provider"]
        if any(
            item.get(key) != source[key]
            for key in ("phase", "provider", "source_item_id")
        ):
            errors.append(f"{idx}: immutable source/provider/phase attribution changed")
            continue
        disposition = item.get("disposition")
        if disposition == "pending":
            still_open.append(idx)
            continue
        if disposition not in STATUS[phase]:
            errors.append(f"{idx}: invalid phase-specific disposition")
            continue
        rationale = item.get("rationale")
        if not isinstance(rationale, str) or len(rationale.strip()) < 15:
            errors.append(f"{idx}: a specific review rationale is mandatory")
        elids = item.get("element_ids")
        urls = item.get("section_urls")
        tids = item.get("threat_ids")
        if not isinstance(elids, list) or any(x not in elements for x in elids):
            errors.append(f"{idx}: model element IDs must resolve exactly")
            elids = []
        if not isinstance(urls, list) or any(x not in known_sections for x in urls):
            errors.append(
                f"{idx}: source anchors must resolve to the pinned source packet"
            )
            urls = []
        if not isinstance(tids, list) or any(x not in retained for x in tids):
            errors.append(f"{idx}: threat IDs must resolve to the final threat package")
            tids = []
        if (
            len(elids) != len(set(elids))
            or len(urls) != len(set(urls))
            or len(tids) != len(set(tids))
        ):
            errors.append(f"{idx}: repeated IDs or source anchors")
        if disposition in REQUIRES_SOURCE and not urls:
            errors.append(
                f"{idx}: affirmative/absent control or threat requires target source evidence"
            )
        if disposition in REQUIRES_THREAT and not tids:
            errors.append(
                f"{idx}: producing threat disposition requires retained threat ID"
            )
        if disposition in REQUIRES_BAD_EVENT and (
            not isinstance(item.get("bad_event"), str)
            or len(item["bad_event"].split()) < 8
        ):
            errors.append(
                f"{idx}: observed/missing control needs a concrete implied bad event"
            )
        if disposition != "not_documented" and not elids:
            errors.append(
                f"{idx}: every applied or excluded prompt must identify model elements"
            )
        if disposition == "not_applicable" and not urls:
            errors.append(
                f"{idx}: non-applicability requires a section-level source rationale"
            )
        if disposition in {"documented_threat", "documented_control"} and not set(
            urls
        ).issubset(set(plan.get("explicit_considerations_sections", []))):
            errors.append(
                f"{idx}: explicitly documented items must cite considerations sections"
            )
        for tid in tids:
            target_ids = set(retained[tid].get("affected_model_elements", []))
            if not target_ids.intersection(elids):
                errors.append(
                    f"{idx}: {tid} does not attach to one of the claimed model elements"
                )
        if disposition == "new_threat" and (
            baseline is None or any(tid in baseline_ids for tid in tids)
        ):
            errors.append(f"{idx}: new threat must be absent from the frozen baseline")
        if disposition in {"confirms_existing", "refines_existing"} and any(
            tid not in baseline_ids for tid in tids
        ):
            errors.append(f"{idx}: confirming/refining requires a baseline threat")
        if disposition == "documented_threat" and any(
            tid not in baseline_ids for tid in tids
        ):
            errors.append(f"{idx}: explicit documentary threat must be in the baseline")
        if disposition == "unable_to_verify":
            still_open.append(idx)
        count[(phase, provider, disposition)] += 1
        checks.append(
            {
                "id": idx,
                "phase": phase,
                "provider": provider,
                "disposition": disposition,
                "model_elements": len(elids),
                "source_anchors": len(urls),
                "linked_threats": len(tids),
            }
        )
    phases = plan.get("phases", [])
    for phase in phases:
        for provider in PROVIDERS:
            if not any(
                row["phase"] == phase and row["provider"] == provider for row in rows
            ):
                errors.append(
                    f"{phase}: missing mandatory {provider} invocation selection"
                )
            if not any(
                x["phase"] == phase and x["provider"] == provider for x in checks
            ):
                still_open.append(f"{phase}:{provider}:no_adjudicated_rows")
    state = "blocked" if errors else "partial" if still_open else "pass"
    return {
        "schema_version": "specification-threat-knowledge-reconciliation/v1",
        "status": state,
        "execution_kind": "miner_and_threat_knowledge_target_application",
        "source_snapshot": coverage["snapshot_url"],
        "source_version_id": coverage["specification_version_id"],
        "run_id": model["run_id"],
        "model_id": model["model_id"],
        "plan_sha256": sha(plan_blob),
        "ledger_sha256": sha(ledger_path.read_bytes()),
        "model_sha256": actual["model_sha256"],
        "source_packet_sha256": actual["source_packet_sha256"],
        "cache_sha256": actual["cache_sha256"],
        "method_registry_sha256": actual["threat_source_registry_sha256"],
        "phase_provider_counts": {
            phase: {
                provider: sum(
                    x["phase"] == phase and x["provider"] == provider for x in checks
                )
                for provider in PROVIDERS
            }
            for phase in phases
        },
        "selected": len(rows),
        "adjudicated": len(checks),
        "unresolved_ids": sorted(set(still_open)),
        "errors": errors,
        "disposition_counts": {
            "|".join(keys): value for keys, value in sorted(count.items())
        },
        "checklist_and_prompt_dispositions": checks,
        "publication_authorized": False,
        "limitations": [
            "This is a traceable evidence review, not an automatic W3C finding or a browser implementation test.",
            "Third-party method sources are referenced, not redistributed as full text.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--model", type=Path, required=True)
    prep.add_argument("--source-packet", type=Path, required=True)
    prep.add_argument("--cache", type=Path, required=True)
    prep.add_argument(
        "--threat-cache", type=Path, help="Optional full Threat Knowledge corpus ZIP"
    )
    prep.add_argument("--domains", default="security,privacy")
    prep.add_argument("--per-source", type=int, default=6)
    prep.add_argument("--mode", choices=("full", "baseline"), default="full")
    prep.add_argument("--output-dir", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--selection", type=Path, required=True)
    verify.add_argument("--dispositions", type=Path, required=True)
    verify.add_argument("--model", type=Path, required=True)
    verify.add_argument("--source-packet", type=Path, required=True)
    verify.add_argument("--cache", type=Path, required=True)
    verify.add_argument(
        "--threat-cache", type=Path, help="Pinned Threat Knowledge corpus ZIP"
    )
    verify.add_argument("--threats", type=Path, required=True)
    verify.add_argument("--baseline-threats", type=Path)
    verify.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare(
                args.model,
                args.source_packet,
                args.cache,
                args.domains,
                args.per_source,
                args.output_dir,
                args.mode,
                args.threat_cache,
            )
            print(json.dumps(result, indent=2))
            return 0
        result = validate_dispositions(
            args.selection,
            args.dispositions,
            args.model,
            args.source_packet,
            args.cache,
            args.threats,
            args.baseline_threats,
            args.threat_cache,
        )
        if args.output.is_symlink():
            raise ValueError("symlink result destination forbidden")
        if args.output.exists():
            raise ValueError("knowledge receipt already exists; no silent overwrite")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(json_bytes(result))
        print(
            json.dumps(
                {
                    "status": result["status"],
                    "selected": result["selected"],
                    "adjudicated": result["adjudicated"],
                    "unresolved": len(result["unresolved_ids"]),
                    "errors": result["errors"][:8],
                    "output": str(args.output),
                }
            )
        )
        return 0 if result["status"] == "pass" else 2
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
