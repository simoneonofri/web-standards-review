---
name: threat-knowledge
description: Select security, privacy, harms and stakeholder prompt repertoires for model-attached threat elicitation, without requiring a personal library.
---

# Threat prompt knowledge

<!-- section:scope -->
Read `references/concept-boundaries.md` when threats, harms, weaknesses, controls and risk are being mixed. This skill chooses prompt sources; it does not perform the modeling workflow or establish that a category applies. No books, personal corpora, bibliography account or spreadsheet export is bundled.

<!-- section:workflow -->
Start with the task model and affected people. Read `references/public-sources.json` to choose a small relevant repertoire and `references/source-authority.md` to label its role. Retrieve the requested source through the caller's evidence provider or a verified public source. Record edition, date, locator/hash and availability; an unavailable source remains unavailable rather than being reconstructed as a quotation from model memory.

Use STRIDE for security bad-event prompts, LINDDUN for privacy, RFC 3552/6973/9620 for protocol security/privacy/human-rights questions, and XS-Leaks or fingerprinting material for cross-origin observability and linkability. Choose harms and stakeholder material when effects extend beyond the software operator. These are routing choices, not completeness claims or normative requirements on the target.

For each selected prompt, identify the actor or condition, model element or assumption, violated property or interest and consequence. Return a threat-modeling queue item to `what-can-go-wrong`. Keep this independent elicitation separate from checklist pass/fail and baseline threat dispositions until reconciliation. Do not convert a framework category into a failed control check.

<!-- section:evidence-contract protected -->
Preserve original source authority and every provenance path through deduplication. A prompt, synthesis, example or similarity score cannot prove applicability. Let `what-are-we-going-to-do-about-it` choose task-specific responses and `w3c-horizontal-review` decide whether evidence supports a finding. Share only reviewed generic improvements; keep caller source material in the caller's artifact store.
