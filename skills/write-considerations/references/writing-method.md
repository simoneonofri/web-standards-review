# Writing method

The threat model documents reasoning; a specification's Security and Privacy Considerations communicate the consequences to people who were not present.

Primary references:
- W3C Security and Privacy Questionnaire §2.16: https://www.w3.org/TR/security-privacy-questionnaire/#considerations
- RFC 3552 §5: https://www.rfc-editor.org/rfc/rfc3552.html#section-5
- RFC 6973: https://www.rfc-editor.org/rfc/rfc6973.html

For each meaningful group of threats identify: (1) a concrete bad event and actor or condition; (2) ERTA response; (3) exactly what source rule, algorithm or guidance implements it; (4) responsible browser, relying party, application, deployment, or user; (5) what remains; (6) assumptions or open issues. If the source is not normative, do not write an existing requirement. If the response is proposed, use proposal language.

Security section: attack model and boundaries; concrete threats and existing/proposed protections; actual enforcers; remaining and unaddressed threats; assumptions and external dependencies.

Privacy section: people, attributes, origin/recipient/observer, purpose, permission lifetime, minimization, disclosure, retention/deletion, sharing and linkability, when supported by evidence. Distinguish user-agent enforcement from informative advice to recipients.

Use concise explanatory prose. Keep threat IDs, normative anchors, evidence confidence and outstanding decisions in the sidecar ledger, not in every public sentence.

Never infer that Secure Context alone protects against a malicious HTTPS origin, or that an implementation owner is an actual enforcer without verification.

Publication state remains draft until source, technical and editorial review is complete; a passing validator checks traceability only.


## Editing existing text

Read references/fedcm-editorial-pattern.md and the exact current sections. Preserve non-redundant useful prose. Group threats by source-proven mechanisms rather than generated threat IDs, and propose a minimum-change patch separately from a consolidated comparison draft. Do not call a generated scaffold PR-ready without editorial/source review.
