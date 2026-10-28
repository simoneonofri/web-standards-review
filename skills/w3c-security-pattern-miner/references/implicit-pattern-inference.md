# Implicit Pattern Inference

Derived patterns require a derivation chain. Each chain must include necessary premises, optional signals, prohibited shortcuts, alternative explanations, output classification, and maximum confidence without direct evidence.

## Rule Families

- Authority crossing: inspect principal identification, authorization, confused-deputy protection,
  delegation, lifetime, revocation, and ambient authority.
- Native capability exposure: inspect user activation, active-document state, secure context,
  trusted UI, permission lifetime, background invocation, and native-boundary validation.
- Persistent state: inspect keying, origin/site scope, expiry, revocation, clearing, rollback,
  cache consistency, quota, and exhaustion.
- Network exchange: inspect endpoint authentication, integrity, confidentiality assumptions,
  redirects, downgrade, replay, freshness, cross-origin leakage, and active/passive attackers.
- Parsing and serialization: inspect ambiguity, parser differentials, canonicalization, unknown or
  duplicate fields, recursion, size limits, injection, and signature coverage.
- Identity and credentials: inspect authentication versus authorization, origin binding, account
  enumeration, credential substitution, replay, recovery, revocation, lifecycle, trusted UI, and phishing.
- Error behavior: inspect information oracles, timing differences, cross-origin observability,
  existence leakage, and retry amplification.
- Lifecycle: inspect stale authority, cleanup, cancellation, races, reentrancy, restoration, and duplicate execution.
- Negotiation and extensibility: inspect downgrade, unsupported values, fail-open behavior, unknown
  critical extensions, canonical interpretation, and algorithm confusion.

## Prohibited Shortcuts

Do not treat missing Security Considerations as proof of insecurity; missing validation text as proof validation never occurs; every persistent identifier as a vulnerability; every cross-origin feature as a same-origin-policy bypass; cryptography as proof of confidentiality; user consent as authorization; authentication as authorization; HTTPS as sufficient against all attackers; reviewer comments as consensus; informative examples as requirements; referenced protocols as secure without their assumptions; incompatible attacker capabilities as valid; severity as implicit; or hypotheses as accepted catalog checks.