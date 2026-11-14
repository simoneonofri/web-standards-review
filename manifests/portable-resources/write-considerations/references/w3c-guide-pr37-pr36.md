# W3C Threat Modeling Guide PRs #37 and #36 — considerations method

Primary proposed sources:
- [PR #37 — How to Write the Security Considerations Section](https://github.com/w3c/threat-modeling-guide/pull/37) (open; reviewed at head `cf3a8b8`, 8 November 2026)
- [PR #36 — Consider Responses, ERTA decision flow](https://github.com/w3c/threat-modeling-guide/pull/36) (open; head `3031557`, 8 November 2026)

These are **proposed guide changes**, not already merged W3C requirements. They are the explicitly chosen authoring reference for this private skill.

## Threat → response → remediation → minaccia residua

For EACH in-scope threat in the selected threat model:

1. Identify and explain the threat and its affected people, properties and scope.
2. Identify the response and the ERTA strategy or **combined strategies**: Eliminate, Reduce, Transfer, Accept. Cite the source model/response.
3. Link to the **remediation actually implemented or proposed**, ideally the exact normative algorithm/requirement, a related specification or a tracked issue/PR. Do not call a proposed change an already implemented requirement.
4. Identify the actual **enforcing actor**, with the failure behavior for Reduce. For Transfer, identify the **receiving actor**, the delegated duty and the assumption that the receiving actor applies it. A Transfer can combine with Reduce.
5. Identify **remaining threats (minacce residue)** and any original threat that remains. If an original or remaining threat has been accepted, document the explicit rationale and conditions for reconsidering that decision.
6. If no response has been selected, state so and link the relevant issue or PR where available. Explain the unresolved state without fabricating a mitigation.
7. Record **out-of-scope threats**, each with the reason for excluding it, independently of the selected threat package.

Security and Privacy Considerations are the **external security/privacy notes**, not a threat table dumped into the spec. They should summarize the important findings for implementers, adopters, web authors and affected users. A detailed threat model may remain in a separate linked document or be included when appropriately sized. The Working Group determines the section format.

## Examples carried by the guide proposals

- **Reduce — Digital Credentials:** a network attacker could tamper with a page loaded in a non-secure context; an API exposure restriction using `[SecureContext]` reduces that threat at the browser layer. A malicious *secure* origin is not covered by that restriction. See [Digital Credential interface](https://www.w3.org/TR/2026/WD-digital-credentials-20261020/#x7-7-the-digitalcredential-interface).
- **Transfer + Reduce — WebAuthn:** a Relying Party is required to validate the origin received in client data. The RP is the enforcing actor; omitting the check leaves an origin-confusion threat. See [WebAuthn origin validation](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-validating-origin).
- **Reduce — user activation:** [Digital Credentials — prepare credential requests](https://w3c-fedid.github.io/digital-credentials/#prepare-credential-requests) rejects requests without transient activation, enforced by the browser.
- **Transfer — unlinkable presentations:** [Digital Credentials — unlinkable presentations](https://w3c-fedid.github.io/digital-credentials/#unlinkable-presentations) delegates protection to protocols and credential format actors; describe the named recipient and the assumption.
- **Reduce + Transfer — encrypted wallet response:** [OpenID4VP `dc_api.jwt`](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-A.2) requires an encrypted JWT in that mode. Describe precisely which wallet/protocol participant enforces encryption.

Use the concrete **target specification** for normative claims. The guide's examples illuminate methodology, but do not import Digital Credentials or WebAuthn requirements into Geolocation.

## Authoring outputs

`considerations-editorial-packet/v2` adds `threat_responses[]` to the existing thematic section prose. Each entry provides the exact ERTA combination, source-backed remediation state and references, receiving/enforcing actor, assumptions, remaining threats, acceptance rationale/conditions and any open issue links. It also adds `out_of_scope[]`.

`validate_remediation_links.py` checks that mapping. `compose_considerations.py` validates it and exports a `considerations-remediation-trace.json` alongside the readable sections, minimal-edit changes and editorial evidence ledger. The older v1 editorial packet remains readable for compatibility; use v2 for new PR37-aligned writing.

**Terminology:** Write **minaccia residua** (remaining or residual threat), never `rischio residuo` as a synonym. Risk/impact may be analyzed separately; this guide's specified output is the *remaining threat* and the reasons for any explicit acceptance decision.
