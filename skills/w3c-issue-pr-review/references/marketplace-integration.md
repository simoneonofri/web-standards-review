# Integration with Web Standards Review

Use `w3c-issue-pr-review` as the thread-facing entrypoint. It owns the issue or PR context, requested outcome, linked discussion, recommendation, response draft, and resolution check. Specialist skills own their analysis. Return their results to the thread rather than creating a second competing disposition.

## Choose the smallest relevant route

| Incoming task | Route | Return to the thread with |
| --- | --- | --- |
| Editorial PR, terminology question, or short status | Review directly; use `fact-check` if a material claim needs verification | Exact change, supported judgment, and next action |
| One specification security/privacy concern | `spec-review` in its focused reply mode | Evidence, bounded consequence, caveats, and proposed specification action |
| Charter/recharter thread | `strategy-charter-miner` for relevant precedents, then `w3c-horizontal-review` for the requested current-target analysis | Current-candidate evidence, relevant per-domain status, and questions that remain open |
| Implementation or test offered as proof | `w3c-spec-code`; reconcile through `spec-review` or `w3c-horizontal-review` when a specification finding is proposed | Pinned mapping, observed implementation behavior, and the separate specification conclusion |
| Threat/privacy prompts for an accepted target model | `threat-knowledge`; supply the selected model elements, assumptions and question | Model-attached prompt candidates and source limits; verify any resulting claim against target evidence before drafting the thread response |
| Full specification security/privacy review requested through an issue | `w3c-horizontal-review` for the full workflow; `spec-review` for its finding contracts | Review coverage, atomic findings, unresolved evidence gaps, and the thread-specific disposition |
| Request to close an existing review | Use this skill's resolution checks; reuse a specialist only for unresolved technical evidence | Required outcomes versus landed changes and a bounded closure recommendation |

These are task routes, not mandatory sequential stages. Do not invoke every row for each issue. A full review coordinator may use the five-stage modeling flow and its miners; the thread entrypoint does not run the same flow again. A standalone installation can perform focused review from supplied evidence without the optional skills, while explicitly limiting any broader assurance claim.

## Handoff contents

Pass a compact note or reuse an existing packet containing:

- The thread URL or supplied artifact identifier, exact requested question, and output type.
- Specification/charter snapshot and relevant anchors; for a PR, the compared base and head commits; for implementation claims, the repository and pinned revision.
- Checked evidence and material links, with source visibility, locators, versions, and unavailable sources.
- Facts, proposed claims, counterevidence, uncertainty, and acceptance conditions already established in the thread.
- Requested analysis scope, existing packet locations, and the destination to which the result must return.

Keep this handoff in the user's chosen private artifact location. It is an orchestration note, not a new machine-validated contract. Do not mark a downstream contract complete merely because this note exists; apply that skill's actual validation requirements.

On return, check that the specialist used the same target and answered the requested question. Preserve its evidence references and limits. If the target changed, inspect the relevant delta before reusing conclusions. Distinguish unavailable, partial, and verified work. Resolve disagreement using primary evidence or report the remaining uncertainty.

## Publication and customization

Draft only the part of the result needed by the recipient. A full analytical packet stays separate from a public issue or comment. Apply optional author style after the facts and recommendation are stable; style must not change evidence, normative force, uncertainty, or ownership.

The shared entrypoint has no required personal writing or knowledge provider. Private customization belongs in the host's user configuration or a private overlay. An analysis result, proposed response, or completed validator does not itself authorize a remote write.
