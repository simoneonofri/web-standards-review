# Considerations editorial packet — current v2

The authoring agent creates this packet **during the current task** by reading
the target specification, its model, the reconciled threats and ERTA responses.
It is not a form for the user to fill in. Its job is to preserve source-linked
evidence behind **finished Security and Privacy Considerations prose**.

## Packet identity and structure

`schema_version`: `considerations-editorial-packet/v2`.

The packet contains exact `model_id`, `threat_package_id`,
`response_package_id`, `source_snapshot` and:

- `sections.security` and `sections.privacy`: each has a finished
  `introduction`, ordered thematic `topics[]` and optional `closing`.
- Each topic has natural `heading`, fully authored `paragraphs[]`,
  source `source_urls[]`, affected `threat_ids[]`, matching `response_ids[]`,
  an `enforcement` actor/layer and a concrete `residual` description.
  The legacy `residual` field is a compatibility alias for **remaining
  threat (minaccia residua)**, never an assertion about a calculated risk.
- `editing`: `mode` is `create`, `amend`, `rewrite` or `propose`.
  Include `privacy_strategy` and `privacy_additions[]` with target source
  `section_url`, `heading` and `text` for targeted amendments.
- `threat_responses[]`: **exactly one record for every retained threat**.
- `out_of_scope[]`: each excluded threat and its documented rationale.

## PR #37 / #36 threat-response-remediation record

Each `threat_responses[]` entry has:

```json
{
  "threat_id": "T-01",
  "response_id": "R-01",
  "strategies": ["Reduce"],
  "remediation": {
    "state": "specified",
    "description": "Browser rejects geolocation access from insecure documents",
    "specification_refs": [
      "https://www.w3.org/TR/2026/CRD-geolocation-20261105/#request-a-position"
    ],
    "external_refs": [],
    "enforcing_actor": "User agent",
    "failure_behavior": "Return PERMISSION_DENIED without acquiring a position"
  },
  "assumptions": ["The user agent follows the request algorithm"],
  "remaining_threats": [
    {
      "description": "A malicious site already authorized to obtain coordinates can misuse them",
      "accepted": false
    }
  ],
  "issue_refs": []
}
```

This is a **schema illustration**, not a verified current finding or an
assertion that the entire sample response has been formally adopted.

The `remediation.state` distinguishes:

- `specified`: behavior actually stated by a target normative requirement
  or linked external specification (identify the exact requirement and layer);
- `proposed`: a desired change not yet incorporated into the specification;
- `delegated`: responsibility transferred to a named actor/component;
- `removed`: eliminated feature/condition;
- `unselected`: no response currently selected; retain issue/PR links.

`strategies` supports **combined** ERTA (e.g. `["Transfer","Reduce"]`)
with `combination_rationale`. For Transfer include
`remediation.receiving_actor`, `delegated_duty` and
`transfer_assumption`; for Reduce include `enforcing_actor` and
`failure_behavior`. For Eliminate identify
`removed_feature_or_condition`. For Accept include
`acceptance_rationale` and `review_conditions`.

If no response has been selected, use an empty `strategies` array and
`remediation.state="unselected"`; record the decision gap and link the
issue/PR if available.

`remaining_threats[]` lists each original or **remaining threat** after
the response and whether that threat is accepted. Acceptance requires its
own `rationale` and `review_conditions`, never silent closure.
For every `out_of_scope[]` threat record the reason for excluding it.

Use `scripts/validate_remediation_links.py` to verify references and
dispositions. `scripts/compose_considerations.py` performs this validation
while composing and also exports `considerations-remediation-trace.json`.
It links remediation back to exact specification sections, external
requirements, issue/PR records and the owner without making public prose
look like a machine-generated ledger.

## Guide status and examples

Source: [W3C Threat Modeling Guide PR #37](https://github.com/w3c/threat-modeling-guide/pull/37)
(open on 13 November 2026), complemented by
[PR #36 on ERTA](https://github.com/w3c/threat-modeling-guide/pull/36).
Read `references/w3c-guide-pr37-pr36.md` for Digital Credentials,
WebAuthn and OpenID4VP examples. These are working proposals, not merged
W3C requirements. Validate the **target specification's** normative
references separately.

The v1 editorial packet remains supported for existing consumers. New
authoring should produce v2, including the additional remediation trace.

## Normative evidence and response-state semantics (adversarial hardening)

When a remediation is marked `specified`, its record **must** explicitly set
`remediation.source_strength="normative"` and supply a meaningful
`remediation.normative_basis` explaining which requirement/algorithm establishes
the control. A URL to informative recipient advice, a discussion or a PR alone
does not prove a normative requirement. The validator checks source identity,
obviously informative recipient-only references and structural completeness;
it does not certify implementation conformance or replace reading the actual
specification.

An upstream selected ERTA strategy may **not** silently disappear from the
editorial packet. If the response package has `erta:"Unresolved"`, update that
package and its provenance before describing a newly selected strategy. The
`Accept` strategy requires acceptance rationale and meaningful review
conditions. If other remaining threats are still unaccepted, provide
`acceptance_scope` to distinguish what has and has not been accepted.

A threat with no selected response may carry
`remediation.state="unselected"`, an empty `strategies` array and an
`open_decision_note` when no issue/PR has been created yet. PR #37 requires
issue links **where available**, not fabricated links.

A fully eliminated enabling condition may have no remaining threats only
when `Eliminate`, `state="removed"`, and a concrete
`no_remaining_threats_rationale` are recorded. Otherwise explicitly
describe the original or remaining threat (*minaccia residua*).

The composition command supports `create`, `amend`, `rewrite`, and
`propose` modes; output is written transactionally so an unsuccessful
editorial QA does not leave incomplete deliverables. The resulting
Considerations include readable descriptions of remediation status,
responsibilities, assumptions and remaining threats in thematic paragraphs;
a sidecar ledger continues to retain the full ID mapping.


## Verified normative evidence (required for v2 specified remediation)

A `remediation.state="specified"` record is not established by a
self-asserted `source_strength="normative"` string or a bare section URL.
For each specified remediation, provide:

```json
"source_strength": "normative",
"normative_basis": "Why the quoted algorithm or requirement supplies this control",
"normative_evidence": [{
  "source_url": "https://www.w3.org/TR/2026/CRD-geolocation-20261105/#request-a-position",
  "quote": "If document is not allowed to use the ... Call back with error ... PERMISSION_DENIED"
}]
```

The example `quote` above is abbreviated **for documentation only**;
real packets MUST contain a contiguous, exact excerpt from the pinned
source-corpus section. The validator normalizes whitespace and verifies
that the actual excerpt occurs in that section. It rejects explicit
informative/non-normative Considerations as proof of a normative mechanism.
For algorithms whose automatic `normative` metadata is imperfect, it
checks for actual procedural steps in the section instead of trusting a
self-assigned boolean.

A reference that points **only** to an external specification is not
verified by the target source packet. Classify that proposed/delegated
response accurately until the external requirement is independently
available in a pinned source packet. Do not invent external normative
evidence to obtain a passing result.

This check establishes **documentary evidence and provenance**, not
browser implementation conformance or a semantic theorem that the
remediation eliminates its associated threat. Editors must still
accurately interpret the source when authoring the narrative.
