# Method

## Evidence order

Use immutable W3C publication text first. Use current official W3C or WHATWG text when no immutable publication exists or when a living standard owns the definition. Use an official editor draft only when the charter names incubation text. A Source Packet v1 record strengthens traceability to a local snapshot but does not change normative force.

## Evidence classes

`explicit-normative` records behavior stated in normative text or a normative algorithm. `explicit-informative` records authoring guidance or explanation explicitly present in a source. `derived-cross-spec-synthesis` is a review recommendation assembled from multiple explicit mechanisms. `charter-scope` establishes only whether a deliverable is in scope.

## Review results

Use `pass` when the specification explicitly integrates the applicable mechanism. Use `partial` when only some required surfaces or states are covered. Use `fail` only when an applicable explicit requirement is contradicted or omitted with enough evidence to make that conclusion. Use `unknown` when evidence is incomplete. Use `not-applicable` with the applicability reason. Use `not-evaluated` when the control was selected but not assessed.

## Defaults and exceptions

A secure default record distinguishes an explicit platform default from a synthesized authoring recommendation. An exception record captures the condition, resulting behavior, and security consequence. Treat exceptions as first-class review objects: verify that the triggering condition is narrow, observable where appropriate, and paired with a defined fallback or failure mode.

## Limitations

The initial catalog covers every named normative deliverable in the 2026 charter, but it is a targeted mechanism inventory rather than exhaustive clause-level mining. It does not prove implementation support, interoperability, or security. Charter tentative and other deliverables are inventory-only unless a control cites them directly. The Permissions Policy editor text still calls out incomplete Worker and Worklet coverage. The W3C Referrer Policy snapshot is old and should not be used to infer the current Fetch default without checking the living Fetch Standard.
