#!/usr/bin/env python3
"""Check release rights and the maintainer's exact-content approval record."""
import argparse
import collections
import json
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def content_digest(root: Path) -> str:
    """Bind package files; omit generated root reports and the approval record."""
    rows = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in {".git", "__pycache__", ".pytest_cache", ".ruff_cache"} for part in relative.parts):
            continue
        if relative.parts[0] == ".review" or relative.as_posix() == "docs/PUBLICATION_APPROVAL.json":
            continue
        if path.is_symlink():
            raise ValueError("Release approval cannot cover symlinks")
        if path.is_file():
            rows.append([relative.as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()])
    return "sha256:" + hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def inspect(root: Path) -> dict:
    catalog = json.loads((root / "catalog.yaml").read_text(encoding="utf-8"))
    blockers = []
    skills = []
    if catalog.get("publication_review_required") is not True:
        blockers.append("Catalog publication-review marker absent or changed.")
    if catalog.get("status") not in {"private-beta", "public-beta"}:
        blockers.append("Unexpected catalog release status.")
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
    approval_path = root / "docs" / "PUBLICATION_APPROVAL.json"
    if not approval_path.is_file():
        blockers.append("No explicit maintainer publication approval record for the fresh-history release.")
    else:
        try:
            approval = json.loads(approval_path.read_text(encoding="utf-8"))
            if not isinstance(approval, dict) or approval.get("schema_version") != "maintainer-release-approval/v1":
                raise ValueError("Invalid release approval format")
            if (approval.get("approved") is not True or approval.get("approver") != "simoneonofri"
                    or approval.get("repository") != "https://github.com/simoneonofri/web-standards-review"
                    or approval.get("scope") != "public-beta" or not approval.get("approved_on")):
                blockers.append("Release approval identity, decision or scope is missing.")
            if approval.get("content_digest") != content_digest(root):
                blockers.append("Release content differs from the maintainer-approved snapshot.")
        except (ValueError, OSError) as error:
            blockers.append(str(error))
    if catalog.get("status") == "private-beta":
        blockers.append("Private beta must not be published; fresh-history release requires separate approval.")
    return {"status": "blocked" if blockers else "approved", "publication_authorized": not blockers,
            "review_scope": catalog.get("status"), "catalog_version": catalog.get("catalog_version"),
            "skill_count": len(skills), "skills": skills,
            "provider_manual_review": "providers/w3c-knowledge",
            "blockers": blockers}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-blocked", action="store_true")
    args = parser.parse_args()
    report = inspect(ROOT)
    print(json.dumps(report, indent=2))
    if args.expect_blocked:
        return 0 if report["status"] == "blocked" else 2
    return 0 if report["publication_authorized"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
