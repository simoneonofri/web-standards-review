# Security by Design: TPAC 2026 examples

Source: https://docs.google.com/presentation/d/1k-e0ZA3m03IaOBBb3ZnQcI3wrmFo-i1zRiQYi9qVYBo/edit

Slide 23 introduces as-is before to-be ERTA. Slide 24 emphasizes explicit rationale, transferred responsibility and remaining threats. Slide 25 links the analysis to Security Considerations. Slide 26 explains their purpose as external security notes, pointing to RFC 3552 §5 and the W3C Security and Privacy Questionnaire §2.16. Slides 27 and 28 give reduction and transfer examples. Slide 32 says an independent threat model supports rather than replaces the specification sections.

## Example 1 — Reduce: secure-context exposure

A network attacker could change an insecure document before it calls a powerful Web API, affecting the integrity of the page and its API invocation. Where the specific API normatively restricts interface exposure to secure contexts, the browser applies this restriction when exposing that interface, reducing this form of attack. The restriction does not eliminate abuse by a malicious site already using a secure context; authorization and user agency must be analyzed separately.

Illustrative source shown on slide 27: https://www.w3.org/TR/2026/WD-digital-credentials-20261020/#x7-7-the-digitalcredential-interface

The editor MUST recheck the exact normative IDL for the target snapshot. The text here is a newly written summary of the author's pedagogical example, not a blanket claim about all APIs.

## Example 2 — Transfer: WebAuthn relying-party origin validation

An authentication response from an unexpected origin could be accepted if the relying party omits origin checks. WebAuthn assigns the relying party the duty to validate origin data and reject unexpected values during authentication and registration. The enforcing layer is the relying-party implementation; this responsibility is not satisfied merely by the browser returning a response. If the relying party omits or misconfigures this step, the origin-confusion threat persists.

Illustrative source shown on slide 28: https://www.w3.org/TR/webauthn-3/#sctn-validating-origin

## Example 3 — Privacy: geolocation recipients

Precise location can disclose movements of the device user and enable inferences when aggregated. The browser's permission-mediated disclosure is distinct from the data recipient's subsequent retention and sharing. Geolocation recommends that recipients limit collection to the purpose, disclose use, handle deletion and obtain appropriate sharing permission. These recipient provisions are informative advice, not normative browser enforcement; downstream tracking remains a residual threat.

Illustrative source: https://www.w3.org/TR/2026/CRD-geolocation-20261105/#privacy_for_recipients

All three examples follow Threat -> Response -> Enforcement and owner -> Remaining threat, preserving normative/informative distinctions.
