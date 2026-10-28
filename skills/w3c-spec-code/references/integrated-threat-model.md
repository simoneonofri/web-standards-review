
# Integrated specification-to-code threat model

The integrated threat model reconciles the specification, implementation, tests, and any optional scanner evidence. It is the primary review artifact; individual high-, medium-, detailed-, or ad-hoc code analyses are evidence views rather than independent conclusions.

Write the final artifact as `threat-model-<feature>-integrated.md` and include:

1. **Review target and revisions** — specification URL, anchors and revision; implementation repository and revision; feature-scope manifest and lock hashes.
2. **Scope and limitations** — entry points, included feature paths, justified supporting and engine dependencies, exclusions, unavailable code, and coverage budgets.
3. **Actors, assets, data flows, and trust boundaries** — include users and parties affected by the feature, not only implementation components.
4. **Specification control inventory** — normative force, protected property, required behaviour, secure default, exceptions, failure behaviour, and expected tests.
5. **Implementation control inventory** — code and test anchors, actual failure behaviour, implementation-specific defence in depth, platform dependencies, and compensating controls.
6. **Bidirectional mapping** — for every specification control, state whether it is implemented, partial, divergent, absent, test-only, non-public, not applicable, or unable to verify; for every relevant implementation control, state whether it is required by the specification, implementation-specific defence in depth, a compensating control, a platform dependency, a candidate missing specification requirement, non-security behaviour, or unable to verify.
7. **Discrepancies and ownership** — distinguish specification defects, implementation defects, divergence, ambiguity, test gaps, research hypotheses, non-issues, and unresolved evidence. Do not transfer a risk without naming the recipient, assumption, documentation point, and residual risk.
8. **Threats, privacy risks, harms, and mitigations** — connect each scenario to actors, preconditions, broken or missing controls, impact, response, and residual risk. Use STRIDE, LINDDUN, RFC 3552, RFC 6973, or other methods only where they improve coverage.
9. **Optional Codex Security evidence** — record whether it was not requested, unavailable, partial, failed, or completed; map accepted findings to controls and code anchors; preserve rejected findings and counterevidence where relevant.
10. **Sufficiency for the current specification stage** — state what is known, what remains unverified, the risk of being wrong, the minimum decision supported by the evidence, and the next issue, PR, test, or review needed.

Do not infer Working Group intent, normative requirements, or implementation reachability from scanner output alone. Keep evidence, inference, assumption, editorial preference, and process decision distinguishable.
