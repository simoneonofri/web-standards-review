---
name: write-considerations
description: Write or rewrite specification-ready Security Considerations and Privacy Considerations using the pinned specification, What Can Go Wrong, ERTA responses, Threat Knowledge and Miner Knowledge. Produce thematic prose, minimal edits when appropriate, and a traceability ledger.
---

# Write Security and Privacy Considerations

<!-- section:purpose -->

## Purpose

**Write the sections.** Do not merely generate a checklist or a per-threat
scaffold and hand the writing back to the user. Use the skill's authoring
capabilities to write concise, coherent, technically grounded specification
prose in one workflow. A normal editorial review is expected in standards
development and is **not** a separate prerequisite to drafting.

Read these references as needed:
- `references/writing-method.md`: Threat → ERTA → enforcement → residual.
- `references/security-by-design-examples.md`: user's Security by Design,
  TPAC 2026, with secure-context and WebAuthn examples.
- `references/fedcm-editorial-pattern.md`: actual FedCM Editor's Draft
  Security and Privacy Considerations structure.
- `references/shostack-four-questions.md`: source/model/response/coverage logic.
- `references/w3c-guide-pr37-pr36.md`: **the PR #37 writing contract** and PR #36 ERTA examples.

## Inputs and routing

Work from the pinned specification's actual Security and Privacy Considerations,
the accepted model/DFD dictionary, reconciled threats, the ERTA response package,
and their evidence ledger. Reuse Miner Knowledge and Threat Knowledge findings
**already produced by What Can Go Wrong**, without rerunning all miners or
requiring a wholly completed threat model to draft an informative section.
Mark unresolved technical claims as open in the sidecar ledger, not as generic
prose disclaimers repeated in every paragraph.

If upstream artifacts are missing, use the currently available spec text and
source references to produce a focused, scoped draft. Do not invent a complete
threat model or label a source mechanism normative unless the actual source
supports it.

<!-- section:authoring -->

## Authoring behavior — default

1. **Read the target**: freeze the spec version and inspect its existing
   Security and Privacy Considerations and relevant algorithms. For a rewrite,
   determine which passages should be kept, strengthened, added or removed.
2. **Recover the model**: actors, attacker capabilities, trust boundaries,
   sensitive information, potential harms and scope assumptions.
3. **Connect threat and response**: for each important threat, distinguish
   existing mitigations, partially applied or absent safeguards, ERTA proposals
   and accepted/delegated responsibilities. Identify the actual enforcing
   browser, relying party, recipient, implementation or deployment layer.
4. **Write by mechanism, not by ID**: group related threats and protections
   into natural headings. Explain the bad event, source-backed safeguard,
   enforcement actor and remaining threat in **continuous paragraphs**.
   Threat and response IDs belong in the ledger, not public subsection titles.
5. **Write privacy separately**: introduce relevant principals and what
   information each learns; explain collection/permission, correlation,
   minimization, sharing/retention and receiver responsibilities as applicable.
   Preserve useful text already present in the specification.
6. **Finish the text in this same run**: revise repetitive or mechanical
   wording yourself. Check exact references and normative/informative language.
   Provide a consolidated rewrite and a preferred minimal-edit proposal when
   changing an existing specification.
7. **Report precisely**: show the resulting prose and technical changes.
   Evidence gaps stay identifiable; do not claim an unverified implementation,
   normative requirement or Working Group consensus.

### PR #37: link every minaccia residua to a concrete remediation

For new work, use the W3C Threat Modeling Guide's proposed
[Security Considerations guidance](https://github.com/w3c/threat-modeling-guide/pull/37)
and [ERTA response flow](https://github.com/w3c/threat-modeling-guide/pull/36).
Both PRs are currently proposals, but are the explicit authoring method for
this skill. Read `references/w3c-guide-pr37-pr36.md`.

For **each in-scope threat**, write or preserve an auditable chain:
**threat → ERTA response (possibly combined) → remediation location and
status → enforcing actor / transfer recipient → assumptions →
remaining threat (minaccia residua)**. For an accepted remaining threat,
state the rationale and conditions for reviewing that acceptance. A
transferred responsibility must name its recipient and what that party
is expected to do. If no response is selected, state that and link the
open issue/PR if available. Excluded threats require an explicit scope
reason, rather than disappearing from the review.

For a remediation labelled `specified`, record its explicit source strength,
normative basis **and an exact excerpt from the pinned specification's
actual requirement or algorithm**, using `normative_evidence[]`.
An invented quote or informative guidance cannot establish a normative
remediation. Do not infer that a specified requirement is implemented.
 Informative guidance or a proposed change cannot be
represented as an already specified requirement; any newly selected response
must first be reconciled in the upstream ERTA response package.

Remediation can be a source-normative algorithm, an external normative
requirement, a non-normative statement delegating a duty, or a **proposed**
change with a linked issue/PR. Do not collapse those into a claim that
the protection already exists or has been implemented. The threat model
may be linked externally and summarized in readable Considerations text.
Follow the PRs' Digital Credentials, WebAuthn and OpenID4VP examples as
methodological tests, not as normative rules for other APIs.

**Terminology:** Always say remaining threat / residual threat in English,
*minaccia residua* in Italian. Do **not** substitute residual risk /
*rischio residuo*: risk and impact are separate concepts.

### Writing pattern

`Threat or bad event → ERTA response → specification mechanism / actor who
enforces it → remaining threat or dependency`.

A specified `[SecureContext]` restriction does not make an authorized HTTPS
site trustworthy; a relying-party origin check is not automatically enforced
by the user agent; recipient advice in a non-normative section is not a browser
MUST. Only source-supported statements belong in the specification prose.

## Local orchestration

The model performing this skill **authors the prose**. The bundled composer
assembles the actual sections, preserves topic-to-threat-to-response links and
runs source checks. It is part of the authoring run, not a new approval step.

Create a `considerations-editorial-packet/v2` object using the schema in
`references/editorial-packet-contract.md`. It contains thematic Security and
Privacy topics, their fully written paragraphs, IDs, exact source locators,
enforcement actors and remaining threats. Then execute:

```sh
python3 skills/write-considerations/scripts/compose_considerations.py \
  --editorial-packet /run/editorial-packet.json \
  --model /run/model.json \
  --threats /run/threats.json \
  --responses /run/responses.json \
  --source-manifest /run/source-corpus/manifest.json \
  --source-packet /run/source-corpus/complete-primary-v1.json \
  --output-dir /run/considerations
```

When this skill is installed **standalone**, run
`python3 scripts/compose_considerations.py` from its own directory with the
same input flags. It uses Python standard library modules only; no private
repository, model API, external W3C Knowledge service or copied Threat
Knowledge corpus is needed for the writer itself.

Outputs:
- `considerations.md`: directly readable combined sections;
- `minimal-edit.md`: preferred amendments to existing sections;
- `editorial-evidence.json`: threat/response/source/owner/remaining-threat mapping;
- `editorial-qa.json`: technical/style checks and relevant follow-ups.
- `considerations-remediation-trace.json`: source-linked PR #37
  threat/ERTA/remediation/remaining-threat mapping (v2).

The composer validates that every cited source anchor belongs to the pinned
snapshot, that no retained threat disappears, and that each selected
threat has ERTA, remediation links and remaining-threat dispositions.
The author, not the user,
performs the prose revision within this run. `check_editorial_rewrite.py`
is available for rechecking text after edits. Its checks enforce evidence
integrity and reject obvious machine-ledger writing, **not arbitrary word
counts or a separate human sign-off**.

The older `draft_considerations.py` remains for backward compatibility as
a structured evidence scaffold. **It is not the normal final output**; do
not respond with that scaffold alone when asked to write Considerations.

## Output and integration contract

`what-are-we-building` provides the model; `what-can-go-wrong` performs
explicit/implicit/additional threat analysis with Miner/Threat Knowledge;
`what-are-we-going-to-do-about-it` provides ERTA; this skill turns those
results into text. `spec-review`, `w3c-horizontal-review` and issue/PR
review can invoke this skill whenever writing/updating considerations is
part of their deliverable.

Authoring and remote publication are separate actions: save the draft and
evidence locally. Do not push to a GitHub or W3C repository without an
explicit instruction to do so. When asked to publish the **plugin/package**
itself, use the repository's actual license, provenance and redistribution
checks; do not confuse those legal distribution checks with an editorial
review of generated prose.
