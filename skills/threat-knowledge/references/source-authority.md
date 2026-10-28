# Source Authority

Use these labels when recording why a source is being used. The label limits what can be claimed from the source.

## Authority Levels

- `primary`: the original standard, specification, official publication, repository, paper, or project material that supports a factual claim.
- `authoritative_guidance`: guidance from the owning organization, standards body, maintainers, or a recognized expert source. Use it for interpretation, not as a substitute for the underlying primary text when exact claims matter.
- `local_snapshot`: a local copy or extraction of source material. Use it for routing, prompts, and offline review. Check the primary source before publication-facing claims.
- `extracted_table`: a table extracted from a source or local spreadsheet. Use it as prompt vocabulary only unless the primary source is checked.
- `internal_normalization`: local synthesis that reorganizes concepts, fields, or routes across sources. Use it to choose a lens, not as evidence.
- `inferred_relationship`: a local mapping between concepts or surfaces. Treat it as a hypothesis to test against the model.
- `example`: an illustrative pattern from a source or local deck. Do not generalize it without task evidence.
- `task_assumption`: a premise supplied by the user or inferred for the current task. Record it explicitly and do not publish it as fact.

## Recording Rules

Record the authority level in `references/public-sources.json` for reusable sources. For task-specific work, record assumptions and inferred relationships in the task notes, deck `source_trace`, or review table.

When a claim will be published, standards-facing, or externally verifiable, prefer `primary` sources. `authoritative_guidance` can support interpretation. `local_snapshot`, `extracted_table`, `internal_normalization`, `inferred_relationship`, `example`, and `task_assumption` require either a primary-source check or clear wording that limits the claim.

Prompt sources do not prove applicability. A STRIDE, LINDDUN, harms, governance, or identity category only suggests a question to ask against the model.
