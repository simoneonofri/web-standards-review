# Bounded support for authors

The seven extraction miners support specification or charter authors during design, drafting and revision, before or during review. Start from a concrete question and an exact draft. Select only the relevant layer: WebAppSec mechanisms, WHATWG integration, W3C protection comparisons, single-spec security patterns, historical review questions, vulnerability intelligence or Strategy charter precedents.

Return a compact decision table:

| Target section or decision | Source and applicability | Proposed author action | Verification or test | Evidence status |
| --- | --- | --- | --- | --- |
| Synthetic draft: sending a request before user confirmation | Supplied draft section 2 states that the request can be sent before confirmation; applicability is limited to that flow | Clarify whether transmission is intended to wait for confirmation; choose and specify the intended ordering | Compare the algorithm's transmit and confirmation steps, then test the permitted orderings | open_question |

Use `evidence_supported`, `open_question`, `already_covered`, `not_applicable` or `unable_to_verify` to label an author action. Keep the miner's existing review dispositions separate. A historical prompt, catalog match or implementation vulnerability does not establish that the current draft has a defect or is required to adopt a mechanism.

An author-support question does not automatically invoke a complete horizontal review, full threat model, scanner, corpus refresh, document edit or publication. Keep the draft intact unless editing is requested. Route a supported review candidate through the existing finding gate. Return missing evidence explicitly instead of filling it from model memory.
