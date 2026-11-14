"""Validate PR #37/#36 threat → ERTA → remediation → residual traceability.

The W3C Threat Modeling Guide PRs are open proposals, not merged W3C policy.
This contract makes their practical writing method testable without adding
an extra human approval stage to the writing workflow.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

SCHEMA = "considerations-editorial-packet/v2"
STRATEGIES = {"Eliminate", "Reduce", "Transfer", "Accept"}
STATES = {"specified", "proposed", "delegated", "unselected", "removed"}
KINDS = {"create", "amend", "rewrite", "propose"}


def text(value: object, key: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing or empty: {key}")
    return value.strip()


def refs(value: object, key: str) -> list[str]:
    if not isinstance(value, list):
        raise TypeError(f"{key}: expected URL array")
    if len(value) != len(set(value)):
        raise ValueError(f"{key}: duplicate references")
    for url in value:
        if not isinstance(url, str) or not url.startswith("https://"):
            raise ValueError(f"{key}: invalid HTTPS reference")
        if not urlsplit(url).hostname:
            raise ValueError(f"{key}: missing URL hostname")
    return value


def normalized(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().casefold()


def verify_normative_evidence(
    remediation: dict, source_urls: list[str], source: dict
) -> list[dict]:
    """Match each normative excerpt to an exact pinned source section.

    A label alone does not establish a normative mechanism. An explicitly
    non-normative section is never a sufficient basis. Source metadata can
    under-report algorithm normativity, hence recognize explicit algorithm
    structure independently of the boolean classifier.
    """
    evidence = remediation.get("normative_evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError(
            "specified remediation needs normative_evidence from source clauses"
        )
    indexed = {
        row.get("source_url"): row
        for row in source.get("sections", [])
        if isinstance(row, dict)
    }
    validated = []
    for i, entry in enumerate(evidence):
        if not isinstance(entry, dict):
            raise TypeError("normative_evidence records must be objects")
        url = text(entry.get("source_url"), f"normative_evidence[{i}].source_url")
        if url not in source_urls or url not in indexed:
            raise ValueError("normative evidence source is not a cited pinned section")
        section = indexed[url]
        raw = normalized(str(section.get("raw_text") or section.get("text") or ""))
        quote = text(entry.get("quote"), f"normative_evidence[{i}].quote")
        normalized_quote = normalized(quote)
        if len(normalized_quote) < 30 or normalized_quote not in raw:
            raise ValueError(
                "normative excerpt not found verbatim in the pinned source section"
            )
        heading = normalized(str(section.get("heading", "")))
        explicitly_non_normative = (
            "this section is non-normative" in raw[:300]
            or "this section is informative" in raw[:300]
            or (
                ("privacy" in heading or "security" in heading)
                and "consideration" in heading
                and section.get("normative") is False
            )
        )
        if explicitly_non_normative:
            raise ValueError(
                "normative evidence cites an informative/non-normative section"
            )
        # The curated corpus can mark an algorithm False when it contains no
        # standalone RFC2119 keyword. We accept its literal algorithm steps,
        # never arbitrary explanatory prose, as the applicable procedure.
        algorithmic = (
            "to " in raw[:200]
            and "let " in raw
            and "if " in raw
            and any(
                token in raw
                for token in (
                    "this algorithm",
                    "terminate",
                    "queue a task",
                    "call back",
                )
            )
        )
        metadata_normative = section.get("normative") is True
        requirement_language = any(
            phrase in raw for phrase in ("must ", "shall ", " is required to ")
        )
        if not (metadata_normative or algorithmic or requirement_language):
            raise ValueError("source section does not establish a normative procedure")
        validated.append(
            {
                "source_url": url,
                "quote": quote,
                "evidence_basis": (
                    "pinned_normative_section"
                    if metadata_normative
                    else "pinned_algorithm"
                    if algorithmic
                    else "pinned_requirement_language"
                ),
                "source_section_heading": section.get("heading"),
            }
        )
    if not any(item["source_url"] in source_urls for item in validated):
        raise ValueError(
            "no normative evidence relates to the selected remediation references"
        )
    return validated


def validate(packet: dict, threats: dict, responses: dict, source: dict) -> dict:
    if packet.get("schema_version") != SCHEMA:
        raise ValueError("PR37-aligned writing requires " + SCHEMA)
    snapshot = source.get("snapshot_identity", {}).get("immutable_url")
    if not isinstance(snapshot, str) or not snapshot.startswith("https://"):
        raise ValueError("source snapshot must be versioned HTTPS")
    if packet.get("source_snapshot") != snapshot:
        raise ValueError("editorial target differs from source snapshot")
    source_urls = {row.get("source_url") for row in source.get("sections", [])}
    originals = {t["threat_id"]: t for t in threats.get("threats", [])}
    response_rows = {r["threat_id"]: r for r in responses.get("responses", [])}
    if not originals or len(originals) != len(threats.get("threats", [])):
        raise ValueError("invalid or duplicate threat identifiers")
    if set(originals) != set(response_rows):
        raise ValueError("final threat package and response package must agree")
    editorial = packet.get("editing", {})
    if editorial.get("mode") not in KINDS:
        raise ValueError("editing.mode must be create, amend, rewrite or propose")
    traces = packet.get("threat_responses")
    if not isinstance(traces, list):
        raise TypeError("threat_responses must be an array")
    by_id = {}
    checked = []
    for row in traces:
        if not isinstance(row, dict):
            raise TypeError("threat response entry must be an object")
        tid = text(row.get("threat_id"), "threat_id")
        if tid not in originals or tid in by_id:
            raise ValueError("unknown or duplicate threat in remediation trace: " + tid)
        by_id[tid] = row
        response = response_rows[tid]
        rid = response["response_id"]
        if row.get("response_id") != rid:
            raise ValueError("remediation response ID differs from ERTA package")
        strategies = row.get("strategies")
        if not isinstance(strategies, list):
            raise TypeError("ERTA strategies must be an array")
        if len(set(strategies)) != len(strategies) or not set(strategies) <= STRATEGIES:
            raise ValueError("invalid ERTA combination")
        prior = response.get("erta")
        if prior in STRATEGIES and prior not in strategies:
            raise ValueError("selected ERTA response strategy was lost")
        if prior == "Unresolved" and strategies:
            raise ValueError(
                "unresolved upstream ERTA response cannot become a specified "
                "strategy without updating the response package first"
            )
        if len(strategies) > 1:
            text(row.get("combination_rationale"), "combined ERTA rationale")
        remed = row.get("remediation")
        if not isinstance(remed, dict):
            raise TypeError("remediation record is mandatory")
        state = remed.get("state")
        if state not in STATES:
            raise ValueError("invalid remediation state")
        if not strategies and state != "unselected":
            raise ValueError(
                "a threat with no selected ERTA response must be marked unselected"
            )
        if strategies and state == "unselected":
            raise ValueError(
                "unselected remediation cannot claim a selected ERTA strategy"
            )
        text(remed.get("description"), "remediation description")
        source_refs = refs(
            remed.get("specification_refs", []), "remediation.specification_refs"
        )
        third_party_refs = refs(
            remed.get("external_refs", []), "remediation.external_refs"
        )
        issue_refs = refs(row.get("issue_refs", []), "issue_refs")
        if any(url not in source_urls for url in source_refs):
            raise ValueError(
                "remediation source locator not in the pinned specification"
            )
        verified_normative_evidence = []
        if state == "specified":
            if not source_refs:
                raise ValueError(
                    "external-only specified remediation requires an independently "
                    "pinned external source packet; mark delegated or proposed until verified"
                )
            if not source_refs and not third_party_refs:
                raise ValueError(
                    "specified remediation needs a normative or external source reference"
                )
            strength = remed.get("source_strength")
            if strength != "normative":
                raise ValueError(
                    "specified remediation requires an explicit normative source "
                    "classification; informative or unverified references cannot "
                    "establish normative enforcement"
                )
            text(remed.get("normative_basis"), "normative remediation basis")
            verified_normative_evidence = verify_normative_evidence(
                remed, source_refs, source
            )
            source_by_url = {
                item.get("source_url"): item
                for item in source.get("sections", [])
                if isinstance(item, dict)
            }
            unambiguously_informative = [
                source_by_url[url]
                for url in source_refs
                if url in source_by_url
                and "considerations for recipients"
                in str(source_by_url[url].get("heading", "")).lower()
            ]
            if (
                source_refs
                and len(unambiguously_informative) == len(source_refs)
                and not third_party_refs
            ):
                raise ValueError(
                    "only informative recipient guidance cited as normative remediation"
                )
            if not source_refs and all(
                "github.com" in url or "docs.google.com" in url
                for url in third_party_refs
            ):
                raise ValueError(
                    "a PR or discussion cannot itself prove normative remediation"
                )
        if state == "proposed" and not (source_refs or third_party_refs or issue_refs):
            text(
                row.get("open_decision_note"),
                "proposed remediation without an existing source or issue",
            )
        if state == "unselected" and not (
            source_refs or third_party_refs or issue_refs
        ):
            text(
                row.get("open_decision_note"),
                "unselected response with no available issue/PR",
            )
        if (
            state == "unselected"
            and prior not in {"Unresolved", None}
            and str(response.get("status", "")).lower()
            not in {"proposed", "unresolved"}
        ):
            raise ValueError("unselected response contradicts adopted upstream ERTA")
        if "Reduce" in strategies:
            text(remed.get("enforcing_actor"), "enforcing actor for Reduce")
            text(remed.get("failure_behavior"), "failure behavior for Reduce")
        if "Transfer" in strategies:
            text(remed.get("receiving_actor"), "Transfer receiving actor")
            text(remed.get("delegated_duty"), "Transfer delegated duty")
            text(row.get("transfer_assumption"), "Transfer assumption")
        if "Eliminate" in strategies:
            text(remed.get("removed_feature_or_condition"), "eliminated condition")
        if "Accept" in strategies:
            text(row.get("acceptance_rationale"), "threat acceptance rationale")
            conditions = row.get("review_conditions")
            if (
                not isinstance(conditions, list)
                or not conditions
                or not all(
                    isinstance(value, str) and value.strip() for value in conditions
                )
            ):
                raise ValueError("accepted threat needs meaningful review conditions")
            if not any(
                isinstance(item, dict) and item.get("accepted") is True
                for item in row.get("remaining_threats", [])
            ):
                text(
                    row.get("acceptance_scope"),
                    "scope of accepted threat when other remaining threats are unaccepted",
                )
        if state == "delegated" and "Transfer" not in strategies:
            raise ValueError("delegated remediation must include Transfer")
        assumptions = row.get("assumptions", [])
        if not isinstance(assumptions, list) or any(
            not isinstance(x, str) for x in assumptions
        ):
            raise TypeError("assumptions must be an array of text")
        remaining = row.get("remaining_threats")
        if not isinstance(remaining, list):
            raise TypeError("remaining threats must be an array")
        if not remaining and not (
            "Eliminate" in strategies
            and state == "removed"
            and isinstance(row.get("no_remaining_threats_rationale"), str)
            and row["no_remaining_threats_rationale"].strip()
        ):
            raise ValueError(
                "remaining threats must be explicit or an elimination rationale supplied"
            )
        for item in remaining:
            if not isinstance(item, dict):
                raise TypeError("remaining threat must be an object")
            text(item.get("description"), "remaining threat description")
            if item.get("accepted") not in {True, False, None}:
                raise ValueError(
                    "remaining threat acceptance must be true, false or null"
                )
            if item.get("accepted") is True:
                text(item.get("rationale"), "remaining threat acceptance rationale")
                cond = item.get("review_conditions")
                if not isinstance(cond, list) or not cond:
                    raise ValueError(
                        "accepted remaining threat needs review conditions"
                    )
        checked.append(
            {
                "threat_id": tid,
                "response_id": rid,
                "strategies": strategies,
                "remediation_state": state,
                "remediation_description": remed.get("description"),
                "source_strength": remed.get("source_strength", "unverified"),
                "normative_basis": remed.get("normative_basis"),
                "verified_normative_evidence": verified_normative_evidence,
                "enforcement": remed.get("enforcing_actor"),
                "delegated_duty": remed.get("delegated_duty"),
                "transfer_assumption": row.get("transfer_assumption"),
                "assumptions": assumptions,
                "acceptance_rationale": row.get("acceptance_rationale"),
                "acceptance_scope": row.get("acceptance_scope"),
                "review_conditions": row.get("review_conditions", []),
                "open_decision_note": row.get("open_decision_note"),
                "receiving_actor": remed.get("receiving_actor"),
                "specification_refs": source_refs,
                "external_refs": third_party_refs,
                "issue_refs": issue_refs,
                "source_link_count": len(source_refs)
                + len(third_party_refs)
                + len(issue_refs),
                "remaining_threats": remaining,
            }
        )
    if set(by_id) != set(originals):
        raise ValueError(
            "missing PR37 remediation dispositions: "
            + ", ".join(sorted(set(originals) - set(by_id)))
        )
    exclusions = packet.get("out_of_scope", [])
    if not isinstance(exclusions, list):
        raise TypeError("out_of_scope must be an array")
    for i, entry in enumerate(exclusions):
        if not isinstance(entry, dict):
            raise TypeError("out_of_scope entry must be an object")
        text(entry.get("threat"), f"out_of_scope[{i}].threat")
        text(entry.get("rationale"), f"out_of_scope[{i}].rationale")
        for url in refs(
            entry.get("specification_refs", []), f"out_of_scope[{i}].specification_refs"
        ):
            if url not in source_urls:
                raise ValueError("out-of-scope reference is not in target snapshot")
    return {
        "schema_version": "considerations-remediation-trace/v1",
        "source_snapshot": snapshot,
        "threats": len(checked),
        "out_of_scope_count": len(exclusions),
        "records": checked,
        "publication_approved": False,
        "guidance": [
            "https://github.com/w3c/threat-modeling-guide/pull/37",
            "https://github.com/w3c/threat-modeling-guide/pull/36",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--editorial-packet", type=Path, required=True)
    parser.add_argument("--threats", type=Path, required=True)
    parser.add_argument("--responses", type=Path, required=True)
    parser.add_argument("--source-packet", type=Path, required=True)
    args = parser.parse_args()
    data = [
        json.loads(p.read_text())
        for p in (
            args.editorial_packet,
            args.threats,
            args.responses,
            args.source_packet,
        )
    ]
    result = validate(*data)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
