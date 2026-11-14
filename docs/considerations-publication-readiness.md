# Publishing the Considerations writer and Web Standards Review

This is a release-preparation checklist, **not** publication authorization.
The candidate lives in a private, isolated local checkout; the main working
tree and remote repository must remain unchanged until a separate publication
instruction and distribution review.

## What is ready for an initial release candidate

- `write-considerations` is installed as skill 20,
  supported on Codex and Claude, documented and projected from reviewed
  maintainer-owned resources.
- It runs with the existing model, threat and ERTA response contracts;
  it can produce combined prose and a minimal patch in the same run.
- FedCM and TPAC 2026 editorial examples are cited via URLs and paraphrased,
  rather than bundling copied third-party source text.
- Tests exercise exact-source anchors, ID consistency, bundled entrypoints,
  source-aware editorial QA, create/amend modes and Geolocation.
- The full Threat Knowledge corpus is not copied into the writer.
  The independent cache exporter builds a *separately reviewable* ZIP.

## Actual release decisions still needed

1. Choose and add an explicit root distribution license (including code,
   documentation, and appropriately licensed examples).
2. Audit third-party rights and provenance for derived Threat Knowledge,
   downloaded source material, catalog prompt entries and documentation.
   Do not silently redistribute originals with unknown licensing.
3. Decide whether to release the **writer skill alone first** (simpler rights
   surface) or the complete 20-skill marketplace and cache artifacts.
4. Authorize the exact commit and public Git history strategy. Current
   private-beta history is not implicitly an appropriate public export.
5. Only then publish a clean artifact and test installation from the
   actual public tag/release.

These are distribution/licensing and repository operations, not additional
gates for the skill's generation of specification prose.

## Release artifacts

Generate the native marketplace from an audited commit with
`reviewctl export-native-marketplace`. Include a pinned manifest of
the exact source commit and SHA-256 checksums. Produce a separate
standalone writer ZIP if only that skill is being released. Do not
require external W3C Knowledge or private Shostack corpora to use the
writer.

No GitHub push, release tag, external review comment or W3C specification
edit should be performed merely because the authoring skill completes
a draft.


The `write-considerations` skill is maintained privately at https://github.com/simoneonofri/write-considerations. Any later public redistribution remains a separate user-controlled action.
