from __future__ import annotations

import difflib

from w3c_knowledge.models import SpecificationVersion


def diff_versions(
    from_version: SpecificationVersion | None, to_version: SpecificationVersion | None
) -> tuple[list[str], list[dict[str, str]]]:
    if not from_version or not to_version:
        return [], []
    document_changes = list(
        difflib.unified_diff(
            from_version.raw_text.splitlines(),
            to_version.raw_text.splitlines(),
            fromfile=from_version.version,
            tofile=to_version.version,
            lineterm="",
        )
    )[:500]
    old_by_anchor = {section.anchor: section for section in from_version.sections}
    new_by_anchor = {section.anchor: section for section in to_version.sections}
    changes: list[dict[str, str]] = []
    for anchor, section in new_by_anchor.items():
        previous = old_by_anchor.get(anchor)
        if previous is None:
            changes.append({"change_type": "added_section", "anchor": anchor, "heading": section.heading})
        elif previous.content_hash != section.content_hash:
            changes.append(
                {
                    "change_type": "normative_change" if section.normative else "informative_change",
                    "anchor": anchor,
                    "heading": section.heading,
                }
            )
    for anchor, section in old_by_anchor.items():
        if anchor not in new_by_anchor:
            changes.append({"change_type": "removed_section", "anchor": anchor, "heading": section.heading})
    return document_changes, changes
