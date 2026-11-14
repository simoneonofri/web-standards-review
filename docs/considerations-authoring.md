# Security and Privacy Considerations writer — integrated workflow

The writer is an optional authoring extension of the same Web Standards Review
monorepo, supported in the native Codex and Claude marketplace.

## Where it runs

`What Are We Building` → model/DFD → `What Can Go Wrong` (explicit,
implicit and additional threat analysis with Miner Knowledge and Threat
Knowledge) → ERTA responses → **write-considerations**.

When the deliverable includes actual Considerations text, `spec-review`,
`w3c-horizontal-review` and `w3c-issue-pr-review` invoke this skill, which
does the writing in the current run. They do not pass the task back to the
user or stop at an individual threat-record scaffold.

## How the skill writes

The authoring model reads the exact source version, current Security and
Privacy sections, source-backed threat and response evidence and the
specific normative algorithms. It writes topical, coherent paragraphs,
following the user's *Security by Design* TPAC 2026 examples and the
FedCM Editor's Draft organizational pattern.

For every relevant topic, record the concrete bad event, ERTA response,
who enforces it, where that behavior is specified, and what remains.
Distinguish browser checks, relying-party or recipient responsibilities,
informative recommendations and proposed changes. A generic HTTPS
requirement alone is never a complete threat/mitigation discussion.

The authoring model creates `considerations-editorial-packet/v1` as an
intermediate artifact and immediately calls
`scripts/compose_considerations.py`. The composer produces:

- `considerations.md`: final reader-facing proposed prose;
- `minimal-edit.md`: preferred targeted amendments when rewriting a
  specification with sound existing sections;
- `editorial-evidence.json`: exact model/threat/response/source mappings;
- `editorial-qa.json`: integrity and editorial checks (no word quotas or
  arbitrary approval requirement).

A create-mode run does not invent a minimal-edit patch.

The old `draft_considerations.py` remains for compatibility and as a
machine-traceable scaffold. It is not the normal final authoring path.

## Example and source comparison

- FedCM Editor's Draft (security assumptions, threats/mitigations; privacy
  principals, network requests and tracking):
  https://w3c-fedid.github.io/FedCM/
- Security by Design: From Threat Modeling to Security Considerations,
  W3C TPAC 2026:
  https://docs.google.com/presentation/d/1k-e0ZA3m03IaOBBb3ZnQcI3wrmFo-i1zRiQYi9qVYBo/edit
- Geolocation CRD, 5 November 2026:
  https://www.w3.org/TR/2026/CRD-geolocation-20261105/

The Geolocation test preserves the useful existing privacy treatment and
proposes a more explanatory Security Considerations section. Its private
run directory contains the original combined rewrite, preferred minimal
change, editorial packet, and a complete source/threat/response ledger.

## Practical checks

The program validates exact source-packet section URLs, consistent
model/threat/response IDs, topic-level threat/ERTA coverage, meaningful
enforcement and residual notes, and obvious audit-log prose. The goal is
technically useful writing, not an arbitrary number of headings or words.

Reviewing a spec is ordinary W3C editorial practice. No extra authoring
approval workflow is imposed by the skill. Posting to remote repositories
is a separate action and uses the user's instructions and normal access
controls; publishing the marketplace/package itself additionally requires
the correct distribution rights.


## D2D and PR triggers (job proposal)

Did We Do A Good Enough Job? compares the exact target's Security and
Privacy Considerations with the source-linked model, threats, ERTA decisions
and residual risks. When a concrete gap exists, it recommends the
`write-considerations` job; the current quality-gate
status remains separate, and proposing the job is not a new blocking gate.

For a security/privacy PR, the reviewer checks not only direct edits to the
Considerations sections but also changes to authorization, origin, permission
or data processing algorithms that may require updating the explanatory
text. The same helper supports `--kind pr --changed-area <area>` on the
pinned source and model. Unrelated editorial PRs do not trigger the writer.

The helper produces `considerations-authoring-proposal/v1` with the writer
skill ID, source/model/response digests, specific security/privacy actions,
and a statement about preserving existing useful text. If the user asked
to write the sections, the writer executes; otherwise the reviewer proposes
the focused change, without creating a GitHub comment or remote PR.

The writer is maintained privately at
https://github.com/simoneonofri/write-considerations
and mirrored at `skills/write-considerations`. The
pinned commit and content hashes live in
`manifests/standalone-writer-source.json`. To check both local copies:
`python3 scripts/check_writer_mirror.py --standalone-checkout <path>`.


## PR #37 / #36 remediation links

The current standalone contract is `considerations-editorial-packet/v2`. For every retained threat it traces one or more ERTA strategies, source-linked remediation in an algorithm, external specification or issue/PR, the enforcing or receiving actor, assumptions, remaining threats (minacce residue), acceptance rationale/revisit conditions, and justified out-of-scope threats. The writer exports `considerations-remediation-trace.json`. PR #37 and #36 are still open guide proposals; their examples guide writing, not target-specific normative behavior.
