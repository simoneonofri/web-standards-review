# Mining and interpretation method

## Corpus boundary

The refresh uses the complete source packets currently stored by W3C Knowledge for specifications whose publication status is `REC`, `CR`, `CRD`, or `WD`. This is the locally available W3C Technical Report corpus, not every historical publication, editor's draft, WHATWG Living Standard, IETF document, or un-ingested W3C report. The catalog records the inventory hash, successful and failed packet counts, retrieval time, and each source locator so coverage can be audited.

## As-is model

For each specification, the miner extracts assets, entry points, trust-boundary signals, threats addressed by observed protections, protection patterns, and explicit Security Considerations coverage. Every derived threat is labeled `derived_from_observed_control`; the miner does not infer undocumented implementation architecture or claim that an attack is feasible.

## Protection evidence

A protection observation requires a matching source section, stable source URL, content hash, bounded excerpt, and detected normative strength. `MUST`, `SHOULD`, `MAY`, and prose are recorded separately from the bounded match context rather than the whole section. Reference, bibliography, index, status, and acknowledgement sections are excluded, as are localized statements that explicitly reject or decline to impose the matched control. An observed pattern establishes that the source specification uses or discusses a mechanism; it does not establish adequacy, implementation support, or general applicability.

## Secure defaults and exceptions

Pattern definitions contain candidate secure-default language and common exception questions. The refresh records default and exception signals found in the source text but does not manufacture an exception from silence. Reviewers must inspect the source and the target before using either in a finding.

## Security Considerations coverage gaps

The miner compares protections observed anywhere in a specification with protections mentioned in sections classified or headed as Security Considerations. A protection present outside that section but absent inside it is emitted as `editorial_non_blocking`. This means the specification appears to implement or discuss the protection without making it discoverable in its Security Considerations; it does not mean the protection is missing from the specification.

## Review constraints

- Frequency is descriptive, not normative.
- Similarity routes review effort; it is not a target finding.
- Absence from the catalog can reflect vocabulary mismatch, incomplete ingestion, or a genuinely absent mechanism.
- A source protection can be inappropriate for the target's threat model.
- Technical severity and blocking status require an independent target-specific threat path.
