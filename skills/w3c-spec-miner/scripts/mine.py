from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SECURITY_SECTION = re.compile(r"security(?: and privacy)? considerations?", re.I)
EXCLUDED_SECTION = re.compile(r"^(?:(?:normative|informative) references|references|bibliography|(?:issues )?index|terms defined by|acknowledg|status of this document)", re.I)
NEGATED_CONTROL = re.compile(r"(?:chose|chooses|chosen) not to|does not impose|do not impose|not impose such|without requiring|is not required|should perhaps|possibly (?:be )?gated", re.I)
NORMATIVE_STRENGTHS = (("must", re.compile(r"\bMUST(?: NOT)?\b")), ("should", re.compile(r"\bSHOULD(?: NOT)?\b")), ("may", re.compile(r"\bMAY\b")))
ASSET_SIGNALS = {
    "credentials and authorization state": re.compile(r"credential|authorization|authentication|permission", re.I),
    "identifiers and identity claims": re.compile(r"identifier|identity|issuer|subject|account", re.I),
    "user or personal data": re.compile(r"personal data|user data|location|contact|biometric|payment", re.I),
    "persistent state and caches": re.compile(r"storage|persistent|database|cache", re.I),
    "cryptographic keys and proofs": re.compile(r"cryptographic|private key|public key|signature|proof", re.I),
    "network resources and responses": re.compile(r"network|request|response|fetch|resource|url", re.I),
}
ENTRY_SIGNALS = {
    "Web API calls": re.compile(r"interface\s+[A-Z]|dictionary\s+[A-Z]|navigator\.", re.I),
    "network retrieval": re.compile(r"fetch|dereferenc|http request|remote server", re.I),
    "events and callbacks": re.compile(r"event handler|dispatch.*event|callback", re.I),
    "parsers and serialized input": re.compile(r"parse|parser|serialization|json|xml", re.I),
    "embedded or delegated contexts": re.compile(r"iframe|embedded|nested frame|delegate", re.I),
}
BOUNDARY_SIGNALS = {
    "origin or site boundary": re.compile(r"cross[- ]origin|same[- ]origin|origin boundary", re.I),
    "user-agent to site boundary": re.compile(r"user agent|browser", re.I),
    "network boundary": re.compile(r"network|remote server|http|tls", re.I),
    "external service or issuer boundary": re.compile(r"third party|external|issuer|relying party|operator", re.I),
    "persistent-state boundary": re.compile(r"storage|persistent|cache", re.I),
}


@dataclass(frozen=True)
class MiningResult:
    model: dict[str, Any]
    observations: tuple[dict[str, Any], ...]
    gaps: tuple[dict[str, Any], ...]


def load_patterns(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def _strength(text: str) -> str:
    for name, pattern in NORMATIVE_STRENGTHS:
        if pattern.search(text):
            return name
    return "prose"


def _snippet(text: str, match: re.Match[str], width: int = 360) -> str:
    start = max(0, match.start() - width // 2)
    end = min(len(text), match.end() + width // 2)
    value = re.sub(r"\s+", " ", text[start:end]).strip()
    return value[:width]


def _section_is_security(section: dict[str, Any]) -> bool:
    kind = str(section.get("section_type") or "")
    heading = str(section.get("heading") or "")
    return kind == "security_considerations" or bool(SECURITY_SECTION.search(heading))


def _section_is_mineable(section: dict[str, Any]) -> bool:
    heading = str(section.get("heading") or "").strip()
    section_type = str(section.get("section_type") or "")
    return section_type not in {"references", "bibliography", "index"} and not bool(EXCLUDED_SECTION.search(heading))


def _signal_list(text: str, signals: dict[str, re.Pattern[str]]) -> list[str]:
    return [name for name, pattern in signals.items() if pattern.search(text)]


def mine_specification(specification: dict[str, Any], packet: dict[str, Any], patterns: list[dict[str, Any]]) -> MiningResult:
    sections = packet.get("sections") or []
    observations: list[dict[str, Any]] = []
    mineable_sections = [section for section in sections if _section_is_mineable(section)]
    combined = "\n".join(str(section.get("raw_text") or section.get("text") or "") for section in mineable_sections)
    security_present = any(_section_is_security(section) for section in sections)
    observed_ids: set[str] = set()
    security_ids: set[str] = set()

    for pattern in patterns:
        compiled = [re.compile(value, re.I) for value in pattern["regex"]]
        pattern_hits: list[dict[str, Any]] = []
        for section in mineable_sections:
            text = str(section.get("raw_text") or section.get("text") or "")
            search_text = re.sub(r"\s+", " ", text)
            match = next((result for candidate in compiled if (result := candidate.search(search_text)) is not None), None)
            if match is None:
                continue
            in_security = _section_is_security(section)
            context = _snippet(search_text, match)
            if NEGATED_CONTROL.search(context):
                continue
            strength = _strength(context)
            default_signals = [term for term in ("by default", "default", "initial value", "must") if term in context.lower()]
            exception_signals = [term for term in ("except", "unless", "may", "optional", "implementation-defined") if term in context.lower()]
            pattern_hits.append(
                {
                    "schema_version": 1,
                    "specification_id": specification["internal_id"],
                    "shortname": specification["shortname"],
                    "title": specification["title"],
                    "publication_status": specification.get("publication_status"),
                    "snapshot_url": specification.get("current_published_url"),
                    "pattern_id": pattern["pattern_id"],
                    "pattern_title": pattern["title"],
                    "category": pattern["category"],
                    "normative_strength": strength,
                    "in_security_considerations": in_security,
                    "source_url": section.get("source_url") or specification.get("current_published_url"),
                    "section_heading": section.get("heading"),
                    "section_anchor": section.get("anchor") or section.get("fragment"),
                    "section_content_hash": section.get("content_hash"),
                    "excerpt": context,
                    "evidence_ids": section.get("evidence_ids") or [],
                    "secure_default_signals": default_signals,
                    "exception_signals": exception_signals,
                    "interpretation": "protection_observed",
                }
            )
        if pattern_hits:
            observed_ids.add(pattern["pattern_id"])
            if any(hit["in_security_considerations"] for hit in pattern_hits):
                security_ids.add(pattern["pattern_id"])
            pattern_hits.sort(key=lambda item: (not item["in_security_considerations"], {"must": 0, "should": 1, "may": 2, "prose": 3}[item["normative_strength"]], str(item["source_url"])))
            observations.extend(pattern_hits[:3])

    pattern_map = {pattern["pattern_id"]: pattern for pattern in patterns}
    threats = []
    for pattern_id in sorted(observed_ids):
        for threat in pattern_map[pattern_id]["threats"]:
            threats.append({"threat": threat, "derivation": "derived_from_observed_control", "pattern_id": pattern_id})
    model = {
        "schema_version": 1,
        "model_kind": "as_is_corpus_derived",
        "specification_id": specification["internal_id"],
        "shortname": specification["shortname"],
        "title": specification["title"],
        "publication_status": specification.get("publication_status"),
        "snapshot_url": specification.get("current_published_url"),
        "packet_snapshot_identity": packet.get("snapshot_identity"),
        "assets": _signal_list(combined, ASSET_SIGNALS),
        "entry_points": _signal_list(combined, ENTRY_SIGNALS),
        "trust_boundaries": _signal_list(combined, BOUNDARY_SIGNALS),
        "threats": threats,
        "observed_protections": sorted(observed_ids),
        "security_considerations_present": security_present,
        "security_considerations_protections": sorted(security_ids),
        "limits": ["Machine-derived routing model; confirm every element against target evidence.", "Observed controls do not prove adequacy, implementation, or general applicability."],
    }

    first_by_pattern: dict[str, dict[str, Any]] = {}
    for observation in observations:
        first_by_pattern.setdefault(observation["pattern_id"], observation)
    gaps = []
    for pattern_id in sorted(observed_ids - security_ids):
        pattern = pattern_map[pattern_id]
        evidence = first_by_pattern[pattern_id]
        gaps.append(
            {
                "schema_version": 1,
                "disposition": "editorial_non_blocking",
                "specification_id": specification["internal_id"],
                "shortname": specification["shortname"],
                "title": specification["title"],
                "publication_status": specification.get("publication_status"),
                "snapshot_url": specification.get("current_published_url"),
                "security_considerations_present": security_present,
                "pattern_id": pattern_id,
                "pattern_title": pattern["title"],
                "outside_section_evidence": {key: evidence[key] for key in ("source_url", "section_heading", "section_anchor", "section_content_hash", "excerpt", "evidence_ids", "normative_strength")},
                "question": f"The specification uses {pattern['title']} outside Security Considerations. Could that section summarize the protection, its secure default, failure behavior, and any bounded exceptions?",
                "limits": "This is a discoverability and coverage comparison, not an independent technical finding.",
            }
        )
    return MiningResult(model=model, observations=tuple(observations), gaps=tuple(gaps))


def aggregate_catalog(patterns: list[dict[str, Any]], observations: list[dict[str, Any]], corpus: dict[str, Any]) -> dict[str, Any]:
    by_pattern: dict[str, list[dict[str, Any]]] = {pattern["pattern_id"]: [] for pattern in patterns}
    for observation in observations:
        by_pattern[observation["pattern_id"]].append(observation)
    catalog = []
    for pattern in patterns:
        hits = by_pattern[pattern["pattern_id"]]
        strengths = Counter(hit["normative_strength"] for hit in hits)
        examples = sorted(hits, key=lambda item: ({"must": 0, "should": 1, "may": 2, "prose": 3}[item["normative_strength"]], item["shortname"], str(item["source_url"])))[:8]
        catalog.append(
            {
                **{key: pattern[key] for key in ("pattern_id", "title", "category", "threats", "secure_default", "exception_questions", "review_question")},
                "specification_count": len({hit["specification_id"] for hit in hits}),
                "observation_count": len(hits),
                "normative_strength_counts": dict(sorted(strengths.items())),
                "examples": [{key: item[key] for key in ("shortname", "title", "source_url", "section_heading", "section_content_hash", "normative_strength", "excerpt")} for item in examples],
            }
        )
    catalog.sort(key=lambda item: (-item["specification_count"], item["pattern_id"]))
    return {"schema_version": 1, "corpus": corpus, "interpretation": "Corpus frequency is descriptive and never establishes normative applicability.", "patterns": catalog}


def sha256_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def render_catalog_markdown(catalog: dict[str, Any], coverage: dict[str, Any]) -> str:
    lines = [
        "# W3C protection-pattern catalog",
        "",
        f"> Corpus snapshot: {coverage['inventory_count']} W3C Technical Reports (`REC`, `CR`, `CRD`, `WD`); {coverage['successful_packets']} complete packets analyzed; {coverage['failed_packets']} failures; generated {coverage['retrieved_at']}.",
        "",
        "Frequency is descriptive. A pattern is not a W3C requirement and does not apply to a review target until target-specific evidence and threat analysis establish it.",
        "",
        "| Pattern | Specifications | Observations | Secure default | Review question |",
        "| --- | ---: | ---: | --- | --- |",
    ]
    for pattern in catalog["patterns"]:
        lines.append(f"| `{pattern['pattern_id']}` — {pattern['title']} | {pattern['specification_count']} | {pattern['observation_count']} | {pattern['secure_default']} | {pattern['review_question']} |")
    lines.extend(
        [
            "",
            "## Coverage interpretation",
            "",
            f"The miner produced {coverage['observation_count']} bounded observations across {coverage['specifications_with_observed_protections']} specifications. It found {coverage['editorial_gap_count']} cases where a protection appears outside Security Considerations but not inside it; every such case is classified `editorial_non_blocking` until an independent technical threat path establishes otherwise.",
            "",
            "Traceable examples, section hashes, excerpts, defaults, exceptions, and normative strength are in `protection-catalog.json` and `protection-observations.jsonl`. Per-specification as-is models are in `threat-models.jsonl`.",
            "",
        ]
    )
    return "\n".join(lines)
