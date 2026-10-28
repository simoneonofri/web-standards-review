# Evidence and Provenance

Evidence classes are exactly: `explicit-normative`, `explicit-informative`, `derived-from-normative-behavior`, `derived-from-algorithm`, `derived-from-cross-reference`, `review-observed`, `resolution-validated`, `implementation-observed`, and `hypothesis`.

Preserve source ID, artifact ID, locator, exact span, interpretation, and normative strength. Do not represent reviewer comments as consensus. Do not call a mitigation validated without resolution or specification-change evidence. Keep inherited dependency behavior separate from current-spec evidence.

Confidence above 0.9 requires direct evidence. Derived items without dependency text should stay below 0.75. Hypotheses should stay below 0.6 and must not enter the accepted catalog.