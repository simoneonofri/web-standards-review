# Project status

Web Standards Review contains 19 portable skills: the original eight skills, horizontal-review orchestration, nine extraction, prompt-routing or implementation layers, and a thread-facing issue/PR review entrypoint. An optional W3C Knowledge service provides local CPU embeddings, exact vector ranking and hybrid retrieval over ingested sections and artifacts. Personal libraries, writing profiles, database contents, model weights and review archives are excluded.

This project is independently maintained by Simone Onofri. It is informed by Web standards and W3C work, but it is not an official W3C deliverable. Generated outputs do not represent W3C, Working Group, Interest Group, TAG, or horizontal-review conclusions unless adopted through the applicable process. Technical validation is not publication approval, and generated outputs require human review.

## Completed private-beta surface

- `catalog.yaml` version 4 lists the 19 skills, optional service, and versioned bundle, with contract directions, source pins, provenance, supported hosts, and publication-review state.
- `w3c-issue-pr-review` handles thread triage, PR review, focused replies and resolution checks. Its optional specialist routes preserve evidence and coverage limits; it has no required personal profile or service and adds no modeling stage.
- `reviewctl catalog/install/status/update/uninstall` provides Codex and Claude discovery through separate commit snapshots, reversible symlinks, and a lock that detects full-package drift.
- Installer preflight refuses non-symlinks and unrelated links; clean-room environment overrides avoid touching real user homes in tests.
- `reviewctl export-marketplace` produces only a fresh local positive-allowlist tree, excludes private-beta-only paths, records exact file and artifact digests, and cannot create or write a remote.
- The existing `project/audit/compose/diff/pull/promote` bridge preserves explicit conflicts between public cores and private overlays.
- Semantic anchors cover every skill; composition preserves YAML frontmatter and prevents adjacent insertions from modifying protected contracts or leaking private text through promotion.
- `prepare-private` builds a complete private workspace and carries overlays into a fresh updated package. `export-native-marketplace` produces both native plugin layouts with dependencies inside the cached plugin root.
- The evidence client checks snapshot identity and complete primary section coverage, attaching full sections from the selected version when the source packet omits inventory entries.
- The shared contract package, complete/partial/blocked fixtures, component tests, bundle validation, catalog audit, installer drift/refusal checks, and clean-room export/import round trip are covered by the local test suites and CLI gates. No CI workflow is included in this snapshot.
- `main` is the current beta branch. Clone, installation, and contribution instructions are in `README.md`.
