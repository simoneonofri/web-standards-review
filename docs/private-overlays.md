# Private customization and reimport

Keep a clean shared checkout for contributions and a separate private workspace for personal configuration. Prepare the first private workspace from an audited, clean commit:

```sh
./tools/reviewctl/reviewctl prepare-private --output /path/to/private-review-v1
```

The new workspace contains `public/` (the pinned portable package), `package/` (the full composed installation), `overlays/`, one `<skill>.installation.json` descriptor per skill, and locks. All scripts and shared contracts remain in their expected package locations. Treat this entire workspace as private; it is never a contribution or a publication candidate.

Edit `overlays/<skill>.json` and keep the `extends` pin. Supported operations are `insert_before`, `insert_after`, `replace`, `append`, `remove_public_optional_section`, `register_private_provider`, and `set_private_default`. Use stable `section_id` anchors and keep any referenced overlay files under `overlays/`. Personal provider registrations also require the descriptor's corresponding `provider_interfaces` declaration. Protected contract sections cannot be replaced or changed through adjacent insertion.

After an intentional overlay edit, compose and verify it:

```sh
./tools/reviewctl/reviewctl compose /path/to/private-review-v1/fact-check.installation.json
./tools/reviewctl/reviewctl diff /path/to/private-review-v1/fact-check.installation.json
```

For host use, point the chosen skill link at the corresponding `package/skills/<skill>` directory. Review existing host destinations first and replace only a link you own; never overwrite an existing personal skill directory. Do not link to a lone generated `SKILL.md`, because its supporting files are part of the installation. The standard marketplace installer manages portable snapshots; private workspace links are separate and are not changed by its `update` command.

## Receive colleague improvements

Review the colleague's exact commit and tests in the shared repository, then check out the accepted clean commit. Prepare a new candidate from the previous private workspace:

```sh
./tools/reviewctl/reviewctl prepare-private --previous /path/to/private-review-v1 --output /path/to/private-review-v2
```

This checks the previous public snapshot, generated skills, and supporting resources, refreshes the entire package, reapplies private overlays, and records the new pins. Overlapping public/private sections, changed shared contracts, changed skill inventory, or manually edited generated resources stop the operation. The old workspace remains intact and a failed preparation leaves no new output directory. After reviewing the candidate, repoint owned host links to its `package/skills/` directories. Retain the old workspace for rollback.

For an additive inventory transition, add `--allow-new-skills` to that command after reviewing the new inventory. Catalog v3 introduced 18 skills; v4 adds `w3c-issue-pr-review` as the nineteenth. Migration from v2 or v3 to v4 preserves existing overlays and gives each new skill an empty overlay. Removed, renamed or reordered existing skills still stop migration, and a collision with an unregistered private overlay blocks the operation. The result lists `added_skills`. Runtime model/data volumes stay outside both packages and do not participate in the source update.

`pull` remains useful for a text-only descriptor migration, but it does not refresh a complete resource tree. Use `prepare-private --previous` for routine full-package updates. Do not run concurrent mutations of one workspace; file composition restores prior bytes on caught write failures but is not a multi-file crash transaction.

## Contribute a portable improvement

Prefer editing the shared core directly in a branch. For an improvement prototyped in a private composition, retain the generated baseline and create a separate candidate file. Declare `promotion_candidate` and `promotion_report` in the installation descriptor, along with a `promotion_claims` entry for each changed section with a `public_source` or `assumption` basis, then run `promote`. The tool writes `public.patch` beside the report. Inspect both artifacts before using them in a pull request.

Promotion excludes sections owned by private overlays, including sections that received adjacent or unanchored insertions. It rejects changed preambles, added or deleted anchors, protected-section edits, and boundary findings. It produces a local candidate, not automatic publication approval. Review the whole exact patch for personal content; pattern scanning cannot establish that arbitrary prose is safe to share. Bring the accepted portable commit back through the same complete-package update path.
