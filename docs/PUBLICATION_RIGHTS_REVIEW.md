# Redistribution and publication rights review

**Status: maintainer-approved public beta.** The exact content approval is recorded in [PUBLICATION_APPROVAL.json](PUBLICATION_APPROVAL.json). This is an independently maintained project, not an official W3C deliverable.

## Distribution scope

- Maintainer-owned skills, code, catalogs and documentation: [W3C Software and Document License (2023)](../LICENSE.md), SPDX W3C-20150513.
- Third-party notices, provider dependencies, container images and the optional embedding model retain their applicable upstream terms.
- Personal profiles, libraries, databases, model weights, source decks, paid material, private discussions and internal W3C material remain excluded.
- Synthetic fixtures and source-pinned per-file rights inventories remain in the package.

## Approval and subsequent changes

The maintainer explicitly authorized publication of the fresh repository. The approval record binds the exact package content and identifies the previously verified source commit; it is a record of the maintainer instruction, not a digital signature. Technical validation does not itself grant publication authority or settle third-party rights.

Run `python3 scripts/check_publication_rights.py` to verify the current approval and content. Missing approval, altered content or private-beta status blocks publication. Generated root export reports and the approval record itself are excluded from its content digest; all other package files are included. Existing per-skill publication_review_required markers continue to apply to subsequent revisions and derived artifacts.

The previous private repository was retained separately. This repository starts from an audited export and does not inherit its old branches, issues or pull requests.
