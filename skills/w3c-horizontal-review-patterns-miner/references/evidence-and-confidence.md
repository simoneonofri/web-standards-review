# Evidence and Confidence

## Evidence classes

- `normative`: derived from W3C principles, questionnaires, or requirements.
- `empirical`: observed in an actual review artifact.
- `validated`: linked to a resolution or specification change.
- `seed`: initialized from this skill taxonomy and not yet backed by normalized
  historical evidence.

Do not fabricate source URLs, issue IDs, consensus, or resolutions. Seed patterns remain `seed` until normalized evidence supports an upgrade.

## Confidence guidance

- `0.90-1.00`: exact evidence span plus matching source relationship and no
  material ambiguity.
- `0.70-0.89`: direct evidence span with some missing context.
- `0.40-0.69`: plausible interpretation from incomplete artifacts; mark
  `possible`.
- `0.00-0.39`: insufficient support; produce a question or `unknown`.

## Epistemic rules

- A checklist item is not evidence that a specification has a defect.
- Absence of a finding is not evidence that reviewers considered and rejected it.
- Absence of text is not automatically a confirmed vulnerability.
- Do not infer severity merely from labels unless label semantics are defined.
- Do not present a reviewer comment as W3C consensus.
- Record specification version and review date when available.
- Keep unresolved uncertainty visible.

## Bias checks

- Denominator bias: do not generalize from the visible subset of reviews.
- Version bias: link findings to the specification version reviewed.
- Consensus bias: distinguish individual comments from group decisions.
- Checklist bias: do not convert unanswered checklist items into defects.
- Duplicated-review bias: deduplicate repeated comments before counting trends.
- Survivorship bias: unresolved and abandoned findings still matter.
