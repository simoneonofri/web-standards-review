# P0 — Redistribution and publication rights review

**Status: BLOCKED.** This is an independently maintained, restricted private beta. It is not an official W3C deliverable. Passing `reviewctl audit-marketplace`, `validate-bundle`, or a clean local export establishes only artifact integrity, **not** publication authorization, copyright ownership, or license compliance.

## Evidence reviewed

- 19 catalogued skills and their per-file `skills/*/.review/rights.json` inventories.
- Source-pinned projection manifests under `manifests/`, plus the W3C Knowledge provider's reviewed file inventory.
- Maintainer-authored text and scripts are marked `maintainer-owned`; this is an inventory classification, not an independently verified rights grant.
- Synthetic test fixtures are marked `synthetic-approved`. Source decks, full third-party texts, paid material, personal overlays, private discussion and internal W3C material remain excluded.
- Selected license for maintainer-owned content: W3C Software and Document License (2023), in the root LICENSE.md file. Provider dependencies, container images, optional model and any third-party content retain their own applicable terms.

## Decisions required before public redistribution

1. Determine distribution scope: named team members, restricted pilot, or public release. Each has different permission needs.
2. Verify copyright/redistribution authority for the included maintainer-authored skills, scripts, catalogs and examples, including any contribution made under institutional duties.
3. Re-check third-party provenance, licensing, attribution, adaptations, and quotations; link-only use must not become automatic full-text redistribution.
4. Review separately the W3C Knowledge provider, image, Python dependencies, and the optional non-vendored embedding model.
5. Select a distribution license and record **human** approval, exact candidate commit, decision date, approver, approved scope and supporting evidence.
6. Publish only from a separately reviewed fresh-history repository. Do not flip the visibility of this private beta or auto-push an export.

A clean rights inventory or empty `pending` array is not a human approval. Retain `publication_review_required` until an authorized release process replaces it.

## Automated private-beta gate

`python3 scripts/check_publication_rights.py` reports the exact current blockers and fails closed. CI checks `--expect-blocked`: even if technical package tests pass, this private beta must remain non-publishable.

The full source repositories may include local paths, Google source-document links and active review inventories. Collaborators should receive only the specifically allowlisted and reviewed portable projection, not a wholesale clone of authoring source trees.
