#!/usr/bin/env python3
"""Fail-closed rights inventory for the restricted private beta."""
import argparse
import collections
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def inspect(root: Path) -> dict:
    catalog = json.loads((root / "catalog.yaml").read_text(encoding="utf-8"))
    blockers = []
    skills = []
    if catalog.get("publication_review_required") is not True:
        blockers.append("Catalog publication-review marker absent or changed.")
    if catalog.get("status") != "private-beta":
        blockers.append("Unexpected catalog status; private-beta gate needs review.")
    if not any((root / x).is_file() for x in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING")):
        blockers.append("No selected top-level distribution license.")
    for skill in catalog["skills"]:
        path = root / skill["path"] / ".review" / "rights.json"
        if not path.is_file():
            blockers.append(f"{skill['id']}: missing rights inventory.")
            continue
        rights = json.loads(path.read_text(encoding="utf-8"))
        included = [x for x in rights.get("files", {}).values()
                    if x.get("include_decision") == "include"]
        by_status = dict(sorted(collections.Counter(
            x.get("rights_status", "unclassified") for x in included
        ).items()))
        skills.append({"id": skill["id"], "included_files": len(included),
                       "rights_statuses": by_status, "pending": rights.get("pending", [])})
        if not included:
            blockers.append(f"{skill['id']}: no included file inventory.")
        if skill.get("review_state") != "publication_review_required":
            blockers.append(f"{skill['id']}: unexpected publication state.")
    if not (root / "docs" / "PUBLICATION_APPROVAL.json").is_file():
        blockers.append("No explicit human-signed, commit-scoped publication approval record.")
    blockers.append("Private beta must not be published; fresh-history release requires separate approval.")
    return {"status": "blocked", "publication_authorized": False,
            "review_scope": "private-beta", "catalog_version": catalog.get("catalog_version"),
            "skill_count": len(skills), "skills": skills,
            "provider_manual_review": "providers/w3c-knowledge",
            "blockers": blockers}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-blocked", action="store_true")
    args = parser.parse_args()
    report = inspect(ROOT)
    print(json.dumps(report, indent=2))
    return 0 if args.expect_blocked and report["status"] == "blocked" else 2


if __name__ == "__main__":
    raise SystemExit(main())
