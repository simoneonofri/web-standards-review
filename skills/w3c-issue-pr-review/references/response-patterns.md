# Response patterns

Choose the structure that fits the requested artifact and repository conventions. These patterns are formatting aids, not evidence or mandatory dispositions.

## Focused thread reply

State the specific observed change or concern, its consequence, and the requested action. Keep the evidence chain visible without reproducing the complete review packet. One actionable point may need only a paragraph. Separate independent actions into flat bullets when that helps the recipient respond.

If the evidence supports acceptance with suggestions, distinguish those suggestions from acceptance conditions. Do not insert “no blockers” or “resolved” as template language. If the conclusion remains uncertain, state the missing evidence or ask a bounded question.

## Downstream security/privacy issue

Use a descriptive title and one independently actionable concern per issue, unless the repository requires a grouped review. If the user selects a prior issue as a template, inspect its exact structure and preserve the semantic role of each field.

When useful, use these fields:

- **Description:** the observed mechanism or omission, exact supporting sections, affected boundary, and limits of the evidence.
- **Impact:** the supported consequence and its preconditions. Mark inferred or implementation-dependent consequences as conditional.
- **Suggestions:** a specification-facing resolution path, including a clarification question when it is needed.
- **Affected Sections:** exact links to the relevant text or algorithms.

A question can be part of the suggested resolution without replacing the description of the concern. Keep implementation evidence distinct from specification evidence. An absent defense is not by itself proof of an exploitable path; account for applicable safeguards and counterevidence.

Keep a review-request disposition separate from a downstream issue. A tracker reply may link to the detailed issue, but do not imply that filing it completes the review or resolves the concern.

## Exploratory reply

State what was checked and which rationale remains missing. Put the strongest concrete case first. If a commit, test, and disclosure form a material evidence chain, link each and explain its role briefly. Distinguish what the implementation demonstrates from what the specification requires.

Ask an open question when the purpose is to understand the group's reasoning. Preserve a concrete correction request when a particular artifact still needs to change. Do not convert the question into an unsupported approval, rejection, or institutional position.

## Replacement wording

Identify the exact text or section being replaced and the intended replacement boundary. Check whether deleting a claim removes a requirement, exception, caveat, or source that must remain. Preserve defined terms, normative force, and cross-references. Do not claim the edit has been applied when supplying only proposed wording.

## Closure recommendation

After the resolution checks in `SKILL.md`, state which required outcome is satisfied and cite the landed source. Mention a residual difference only when it matters. An unimplemented optional example need not block closure if the required semantics are present. Conversely, a merged PR does not resolve a request if the required behavior is still missing.

Use first-person reviewer judgment only when appropriate for the intended author; do not impersonate a group. Keep recommending closure, authorizing closure, and performing closure distinct.
