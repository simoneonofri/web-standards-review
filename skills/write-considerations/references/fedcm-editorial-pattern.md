# FedCM editorial pattern — comparative example

Editorial reference: [Federated Credential Management API Editor’s Draft, 21 October 2026](https://w3c-fedid.github.io/FedCM/), especially §§6–7. This is a style comparator, NOT a normative input for other specifications.

## Observed organization

FedCM's Security Considerations lead with system-level **security assumptions** (trusted user agent, secure network, headers, IdP/RP integrity, token responsibilities). They then organize **threat and mitigation** explanations by recognizable mechanisms and attacker strategies: script injection, unauthorized fetching, sensitive data, browser UI impersonation, IdP impersonation, deceptive UI and clickjacking.

The Privacy Considerations begin with **principals** (user agent, RP, IdP, tracker) and what each party may know, then analyze **network requests** and attack scenarios such as timing and correlation. Normative browser behavior, deployment assumptions and implementer recommendations are not interchangeable.

## What to emulate, and what not to copy

- Name the actors, trust boundaries, assumptions and important protected assets in a short introduction.
- Use substantive topical headings instead of one heading per machine-generated threat ID.
- For each topic, explain **bad event → existing protection or proposed response → who enforces it → what remains**.
- Put evidence/threat/response IDs in an accompanying ledger; reserve public prose for readers unfamiliar with threat modeling.
- Distinguish browser algorithms from advice to relying parties, websites and recipients.
- Preserve meaningful existing Considerations prose: when updating an existing section, prefer a targeted amendment to wholesale rewriting if the earlier language already addresses important obligations.
- Separate security from privacy; cross-reference where necessary, but do not replace either section with a one-line pointer.

Do not transplant FedCM's token, CSP or IdP rules into other APIs merely because FedCM uses them. They must be independently supported in the target specification.

## Application to Geolocation

The 5 November 2026 Geolocation specification's Security Considerations contain only a short statement that no security considerations are identified. Its normative algorithms nevertheless provide policy, secure-context, permission, watch lifecycle and cache-related protections. The Privacy Considerations already cover consent, permission lifetimes, recipient data use, retention, sharing and user agency.

The preferred review strategy is to propose a substantive **Security** replacement while limiting **Privacy** changes to targeted additions on principals/data flow, location history/linkability and remaining threats in recipient-side processing. This respects the existing text and avoids unnecessary rewriting.

The source-led editorial test of this comparison is saved privately on Tleilax under the Geolocation full-model validation run; it is not a W3C Working Group proposal.
