# Native Codex and Claude Code plugins

The canonical repository is where colleagues edit the skills and submit pull requests. To use native plugin discovery, export an audited clean commit into a new directory outside the checkout:

```sh
./tools/reviewctl/reviewctl export-native-marketplace --output /path/to/review-marketplace
```

The export contains `.agents/plugins/marketplace.json` for Codex, `.claude-plugin/marketplace.json` for Claude Code, and one plugin at `plugins/web-standards-review/`. Its 19 skills, contracts, scripts, and optional evidence service are all inside that plugin. The package has no Git history, personal overlays, model weights, database, or credentials. `distribution.json` records the source commit and exact exported files.

Version `0.4.0+<commit>` adds `w3c-issue-pr-review` for standards issues, PRs, comments, and resolution checks. It returns to the thread after any relevant specialist analysis; see the [integration guide](../skills/w3c-issue-pr-review/references/marketplace-integration.md). Choose `spec-review` or `w3c-horizontal-review` directly when the task starts with a specification or a complete horizontal review.

Register the resulting local marketplace with the selected host, then install `web-standards-review`. For Codex CLI:

```sh
codex plugin marketplace add /path/to/review-marketplace
codex plugin add web-standards-review@web-standards-review
```

For Claude Code, run these commands inside its session:

```text
/plugin marketplace add /path/to/review-marketplace
/plugin install web-standards-review@web-standards-review
```

Open a new host session after installation. Plugin skill names may include the plugin namespace. Choose either native plugins or the repository's symlink installer for a host, to avoid duplicate discovery. Do not modify a host's plugin cache as the source for a contribution.

For an update, review and accept the new portable commit, export it to a fresh directory, and select that new marketplace in the host before reinstalling. The plugin version includes the source commit. Keep the old export for rollback. Exporting is local-only; it does not create a remote marketplace, publish a package, or register anything in a user's host configuration.

Manifest formats follow the [Codex plugin documentation](https://developers.openai.com/plugins/build/plugins) and [Claude Code marketplace documentation](https://code.claude.com/docs/en/plugin-marketplaces). Public beta source is available under the root LICENSE.md; generated packages and subsequent changes retain their publication-review requirements.
