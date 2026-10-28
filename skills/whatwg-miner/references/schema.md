# Catalog schema and classification

## Finding fields

| Field | Meaning |
| --- | --- |
| `id` | Stable lowercase identifier: `<standard>-<control>` |
| `standard_id` | ID from `catalog/inventory.json` |
| `standard` | Official index title |
| `control` | Concise name of the reusable security mechanism |
| `category` | One category from the controlled list below |
| `section` | Human-readable section or concept name |
| `url` | Official anchored Living Standard URL |
| `evidence` | Short quotation or semantic summary |
| `evidence_kind` | `semantic_summary` or `short_quote` |
| `normative_status` | `normative`, `informative`, or `mixed` |
| `evidence_class` | Classification from the controlled list below |
| `applicability` | Preconditions, actors, resources, and contexts |
| `secure_default` | Default state and whether it denies, isolates, constrains, or requires opt-in |
| `failure_behavior` | Exception, rejection, network error, ignore, filtering, or other failure result |
| `exceptions` | Explicit bypasses, legacy cases, or user-agent discretion |
| `dependencies` | Other standards or mechanisms required by the control |
| `limitations` | What the evidence does not establish |
| `confidence` | `high`, `medium`, or `candidate` |
| `verified_on` | Date of the official-source snapshot used for validation |

## Security categories

- `authority-and-permission`: permission state, policy delegation, capabilities, or authority checks.
- `origin-and-isolation`: origin, site, agent-cluster, partition, sandbox, or cross-origin isolation boundaries.
- `network-and-request-policy`: CORS, request/header restrictions, credentials, transport, port, mixed-content, or redirect controls.
- `content-and-type-safety`: MIME, encoding, script/content typing, injection-resistant sinks, or content interpretation controls.
- `user-intent-and-visibility`: transient activation, prompts, visible indicators, or user-controlled exit.
- `storage-and-state`: cookie visibility, partitioned storage, persistence, quota, or state clearing boundaries.
- `resource-and-abuse-control`: decompression bounds, backpressure, quotas, or denial-of-service mitigations when explicitly security-relevant.
- `input-validation-and-failure`: validation that fails closed at a security boundary.
- `interface-exposure`: Web IDL exposure gates such as secure context or cross-origin isolation.

## Evidence classes

- `security_control`: explicit reusable mechanism that changes authority, exposure, isolation, integrity, interpretation, or security-relevant failure.
- `security_rationale`: informative explanation of a threat or mitigation.
- `privacy_only`: privacy property without a security-control consequence; excluded from the security catalog.
- `generic_algorithm`: general parsing, queuing, conversion, or exception behavior without an established security boundary; excluded.
- `testing_only`: internal test automation surface; excluded from production-control recommendations.

## Confidence

- `high`: explicit normative algorithm, definition, requirement, or reusable extended attribute at the cited anchor.
- `medium`: control is explicit but the exact default, exception, or cross-spec consequence requires following dependencies.
- `candidate`: keyword-mined material that has not passed manual semantic review; never include it in `security-features.json`.

## Coverage states

- `cataloged`: at least one curated reusable control is recorded.
- `assessed-no-reusable-control`: reviewed but only generic, privacy-only, compatibility, or testing material was found.
- `partial`: large or cross-cutting standard assessed with known residual sections or dependency chains still to inspect.

The catalogs are review aids, not exhaustive conformance statements. A zero count means no reusable security control was curated under this taxonomy, not that the standard has no security implications.
