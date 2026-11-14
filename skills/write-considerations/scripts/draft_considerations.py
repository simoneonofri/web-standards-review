"""Scaffold self-contained Security and Privacy Considerations from reviewed artifacts.

Produces conservative, explicitly draft prose. No normative claim is made
without separately verified source text and an editorial approval decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

SCHEMA = "considerations-evidence-ledger/v1"
PRIVACY_TERMS = {
    "privacy",
    "confidentiality",
    "disclosure",
    "consent",
    "retention",
    "location",
    "identity",
    "tracking",
    "identifiability",
    "linkability",
    "surveillance",
    "personal",
    "data minimization",
    "purpose",
    "association",
    "autonomy",
}
SECURITY_TERMS = {
    "security",
    "authorization",
    "authentication",
    "integrity",
    "availability",
    "confidentiality",
    "attack",
    "origin",
    "spoof",
    "tamper",
    "permission",
    "policy",
    "network",
    "replay",
    "secure",
    "cryptograph",
}
CANONICAL_ID = re.compile(r"^(T|R)-\d{2,}$")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load(path: Path) -> dict:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise TypeError(f"{path.name}: expected object")
    return obj


def classify(threat: dict) -> tuple[str, ...]:
    text = " ".join(
        str(threat.get(k, ""))
        for k in (
            "violated_property_or_interest",
            "consequence",
            "harm",
            "actor_or_condition",
            "action_or_failure",
        )
    ).lower()
    privacy = any(word in text for word in PRIVACY_TERMS)
    security = any(word in text for word in SECURITY_TERMS)
    return (
        ("security", "privacy")
        if privacy and security
        else (("privacy",) if privacy else ("security",))
    )


def safe_line(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def validate_identity(
    model: dict, threats: dict, responses: dict, source: dict
) -> tuple[str, list[dict]]:
    mid = model.get("model_id")
    if (
        not isinstance(mid, str)
        or not mid
        or threats.get("model_id") != mid
        or responses.get("model_id") != mid
    ):
        raise ValueError("model/threat/response identity mismatch")
    if responses.get("threat_package_id") != threats.get("threat_package_id"):
        raise ValueError("response package references another threat model")
    coverage = source.get("coverage", {})
    if coverage.get("primary_coverage") != "complete":
        raise ValueError("source corpus must have complete primary coverage")
    snapshot = coverage.get("snapshot_url")
    if not isinstance(snapshot, str) or not snapshot.startswith("https://"):
        raise ValueError("missing pinned HTTPS specification URL")
    inventory = model.get("source_inventory", [])
    if not any(
        isinstance(row, dict)
        and str(row.get("source_reference", "")).rstrip("/") == snapshot.rstrip("/")
        for row in inventory
    ):
        raise ValueError("model source identity does not match source manifest")
    ts = threats.get("threats")
    rs = responses.get("responses")
    if not isinstance(ts, list) or not isinstance(rs, list) or not ts:
        raise ValueError("cannot draft from empty threats or response package")
    by_t = {}
    for t in ts:
        tid = t.get("threat_id")
        if not isinstance(tid, str) or not CANONICAL_ID.fullmatch(tid) or tid in by_t:
            raise ValueError("invalid or repeated threat ID")
        by_t[tid] = t
    by_r = {}
    for r in rs:
        tid = r.get("threat_id")
        if tid not in by_t or tid in by_r:
            raise ValueError("response references unknown or duplicate threat ID")
        if not isinstance(r.get("response_id"), str) or not CANONICAL_ID.fullmatch(
            r["response_id"]
        ):
            raise ValueError("response ID must be canonical")
        if r.get("erta") not in {
            "Eliminate",
            "Reduce",
            "Transfer",
            "Accept",
            "Unresolved",
        }:
            raise ValueError("unsupported ERTA response")
        if not isinstance(r.get("next_action"), str) or not r["next_action"].strip():
            raise ValueError("response must have testable next action")
        by_r[tid] = r
    if set(by_t) != set(by_r):
        raise ValueError("all retained threats require a distinct response")
    return snapshot, [(by_t[tid], by_r[tid]) for tid in sorted(by_t)]


def source_locator(t: dict, snapshot: str) -> str:
    for e in t.get("evidence", []):
        if isinstance(e, dict):
            source = e.get("source_reference")
            if isinstance(source, str) and source.startswith(
                snapshot.rstrip("/") + "/#"
            ):
                return source
    return ""


def draft_text(
    model: dict,
    pairs: list[tuple[dict, dict]],
    snapshot: str,
    quality: dict | None = None,
) -> tuple[str, list[dict]]:
    quality_status = (quality or {}).get("status", "unknown")
    gate = (
        "partial"
        if quality_status not in {"pass", "complete"}
        else "editorial_review_required"
    )
    lines = [
        "# Draft Security and Privacy Considerations",
        "",
        "> Working draft — not normative text, tested implementation behavior,",
        "> an accepted risk decision or W3C group consensus.",
        "> Quality gate: "
        + safe_line(quality_status)
        + "; publication state: "
        + gate
        + ".",
        "",
        "Source snapshot: " + snapshot,
        "",
        "## Security Considerations",
        "",
        "### Attack model, scope and assumptions",
        "",
        "This section outlines potential misuse and failure conditions identified in the",
        "source-pinned threat analysis. The recorded responses are proposals or",
        "documented mechanisms only to the extent independently supported by",
        "the specification. Their mention does not prove browser or relying-party",
        "conformance.",
        "",
    ]
    assumptions = model.get("assumptions", [])
    if assumptions:
        lines.extend(["Key assumptions underlying this assessment:", ""])
        lines.extend(
            "- " + safe_line(x.get("text") or x.get("statement")).rstrip(".") + "."
            for x in assumptions[:5]
            if isinstance(x, dict)
        )
        lines.append("")
    entries = []

    def paragraph(threat: dict, response: dict, section: str) -> list[str]:
        tid = threat["threat_id"]
        rid = response["response_id"]
        source = source_locator(threat, snapshot)
        actor = safe_line(threat.get("actor_or_condition"))
        failure = safe_line(threat.get("action_or_failure"))
        consequence = safe_line(threat.get("consequence"))
        mechanism = safe_line(
            response.get("mechanism_or_text") or response.get("response")
        )
        owner = (
            safe_line(response.get("owner")) or "responsible actor not yet identified"
        )
        remaining = (
            safe_line(response.get("remaining_threat"))
            or "the residual exposure requires further assessment"
        )
        next_action = safe_line(response["next_action"])
        state = safe_line(response.get("status") or "proposed").lower()
        response_line = (
            "The response package records a " + response["erta"] + " approach"
            " (status: "
            + state
            + "): "
            + mechanism
            + " The enforcing normative requirement, if any, must be checked"
            " separately against the exact specification section."
        )
        out = [
            "<!-- threat:" + tid + " response:" + rid + " -->",
            "### "
            + ("Privacy" if section == "privacy" else "Security")
            + " risk "
            + tid
            + ": "
            + safe_line(
                threat.get("violated_property_or_interest", "relevant property")
            ),
            "",
            "A potential scenario is that "
            + actor
            + " "
            + failure.rstrip(".")
            + ". The resulting harm could be: "
            + consequence.rstrip(".")
            + ".",
            response_line,
            "The responsible actor identified for this response is "
            + owner
            + ". Its actual enforcement must be confirmed against the specified requirements and implementation.",
            "Remaining threat: " + remaining.rstrip(".") + ".",
            "Next verification: " + next_action.rstrip(".") + ".",
        ]
        if source:
            out.append(
                "Specification mechanism or issue context: ["
                + source
                + "]("
                + source
                + ")."
            )
        else:
            out.append(
                "No exact target-specific source anchor is recorded for this scenario; verify before adoption."
            )
        out.append("")
        entries.append(
            {
                "threat_id": tid,
                "response_id": rid,
                "section": section,
                "erta": response["erta"],
                "response_status": state,
                "source_url": source,
                "source_status": "target_reference_not_normative_status_verified",
                "owner": owner,
                "mechanism": mechanism,
                "residual_threat": remaining,
                "next_action": next_action,
                "prose_marker": "threat:" + tid + " response:" + rid,
                "normative_enforcement_verified": False,
                "publication_status": "draft_requires_editorial_and_source_review",
            }
        )
        return out

    for t, r in pairs:
        if "security" in classify(t):
            lines += paragraph(t, r, "security")
    if not any(e["section"] == "security" for e in entries):
        lines += [
            "The model contains no independently established security threats in scope;",
            "this is a coverage limitation, not evidence that no threats exist.",
            "",
        ]
    lines += [
        "### Security remaining threats and scope limits",
        "",
        "The above responses do not automatically address malicious actors inside",
        "already trusted contexts, omitted implementation checks, dependency",
        "compromise, or other conditions outside the documented mechanisms.",
        "Do not treat an ERTA transfer as elimination of the underlying risk.",
        "",
        "## Privacy Considerations",
        "",
        "### Data subjects, recipients and processing assumptions",
        "",
        "Review which people and bystanders may be affected by collection,",
        "retention, linkability, transmission or secondary use of information.",
        "Where the specification gives advice to recipients rather than normative",
        "browser steps, the responsibility remains with the recipient.",
        "",
    ]
    for t, r in pairs:
        if "privacy" in classify(t):
            lines += paragraph(t, r, "privacy")
    if not any(e["section"] == "privacy" for e in entries):
        lines += [
            "No independently verified privacy analysis is available for this",
            "scope; this is an explicit gap and not a privacy-safety claim.",
            "",
        ]
    lines += [
        "### Privacy remaining threats and delegated responsibilities",
        "",
        "Confirm the actual data categories, purpose, permission lifetimes,",
        "retention, deletion, sharing, profiling and user choices for this",
        "specific deployment. These may be outside the API's enforcement.",
        "Implementers and recipients should not assume that a browser-level",
        "permission enforces recipient-side privacy decisions.",
        "",
        "### Open issues and publication status",
        "",
        "The threats, ERTA decisions, normative/informative source distinctions",
        "and remaining threats need editorial verification. This draft must not",
        "be published or merged without the responsible specification",
        "editors' and reviewers' approval.",
        "",
    ]
    return "\n".join(lines), entries


def write(
    output: Path,
    model_path: Path,
    threats_path: Path,
    responses_path: Path,
    source_path: Path,
    quality_path: Path | None = None,
) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError(
            "output directory exists; refusing to overwrite an existing draft"
        )
    model, threats, responses, source = map(
        load, (model_path, threats_path, responses_path, source_path)
    )
    snapshot, pairs = validate_identity(model, threats, responses, source)
    quality = load(quality_path) if quality_path else None
    markdown, entries = draft_text(model, pairs, snapshot, quality)
    output.mkdir(parents=True)
    (output / "considerations.md").write_text(markdown, encoding="utf-8")
    ledger = {
        "schema_version": SCHEMA,
        "model_id": model["model_id"],
        "threat_package_id": threats["threat_package_id"],
        "response_package_id": responses["response_package_id"],
        "source_snapshot": snapshot,
        "source_manifest_sha256": digest(source_path.read_bytes()),
        "model_sha256": digest(model_path.read_bytes()),
        "threats_sha256": digest(threats_path.read_bytes()),
        "responses_sha256": digest(responses_path.read_bytes()),
        "draft_sha256": digest(markdown.encode()),
        "created_at": datetime.now(UTC).isoformat(),
        "quality_gate_status": (quality or {}).get("status", "unknown"),
        "publication_authorized": False,
        "entries": entries,
        "missing_normative_verifications": len(entries),
        "limitations": [
            "Generated draft cannot prove existing normative enforcement.",
            "Source references to source-backed threats are not automatically normative mitigation requirements.",
            "Owner proposals and transferred duties require explicit verification and acceptance.",
        ],
    }
    (output / "considerations-ledger.json").write_text(
        json.dumps(ledger, indent=2, ensure_ascii=False) + "\n"
    )
    (output / "publication-status.json").write_text(
        json.dumps(
            {
                "status": "blocked_requires_editorial_source_review",
                "publication_authorized": False,
                "quality_gate_status": ledger["quality_gate_status"],
                "required": [
                    "normative-source verification",
                    "accurate enforcement ownership",
                    "editorial approval",
                    "residual-risk review",
                ],
            },
            indent=2,
        )
        + "\n"
    )
    return {
        "status": "draft_created_not_publication_ready",
        "sections": ["Security Considerations", "Privacy Considerations"],
        "threats": len(pairs),
        "evidence_ledger_rows": len(entries),
        "output": str(output),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("model", "threats", "responses", "source-manifest"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--quality-gate", type=Path)
    p.add_argument("--output-dir", type=Path, required=True)
    args = p.parse_args()
    try:
        result = write(
            args.output_dir,
            args.model,
            args.threats,
            args.responses,
            args.source_manifest,
            args.quality_gate,
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "blocked", "error": str(error)}))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
