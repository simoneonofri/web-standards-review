# Focused W3C Security Reply

Use this route for one narrow security finding in an existing W3C issue, pull request, or horizontal-review thread. Keep the complete review record private and project only the minimum public comment needed to move the discussion forward.

This focused route is for an individual reviewer. Use the full-review route for a group-authorized finding unless a separate authorization-evidence contract is available; never switch to `we` from an unsupported packet declaration.

## Required artifacts

Create a private `evidence-packet.json` and a separate public `comment.md`. Do not put private notes, unused sources, uncertainty analysis, or local PoC details in `comment.md`. Keep the detailed uncertainty analysis private, while preserving every material qualification in the public comment.

The evidence packet must use this shape:

```json
{
  "artifact_kind": "focused_w3c_security_reply_evidence",
  "review_mode": "focused_w3c_reply",
  "output_register": "single_finding_w3c_issue_comment",
  "review_capacity": "individual",
  "publication_decision": "publish_single_finding",
  "target": {
    "specification": "Specification name and version",
    "issue_url": "https://github.com/..."
  },
  "search_evidence": [
    {
      "evidence_id": "prior-review-search-1",
      "source_url": "https://github.com/..."
    }
  ],
  "prior_feedback": [
    {
      "domain": "privacy",
      "prior_feedback_url": "https://github.com/...",
      "evidence": [
        {
          "evidence_id": "prior-finding-1",
          "source_url": "https://github.com/..."
        }
      ],
      "relationship": "distinct",
      "disposition": "retain_distinct",
      "rationale": "Why this is related but not the same finding.",
      "distinct_delta": "The exact additional behavior, prerequisite, or consequence introduced by this finding.",
      "prior_issue_state": "closed",
      "conclusion": "unable_to_verify",
      "conclusion_evidence": []
    }
  ],
  "finding": {
    "distinct_delta": "The additional behavior introduced beyond prior feedback.",
    "mechanism": "How the additional behavior produces a bounded security consequence.",
    "prerequisites": ["The conditions required for exploitability."],
    "consequence": "The bounded security consequence.",
    "limitations": ["The applicability boundary supported by the evidence."],
    "non_claims": ["What the evidence does not demonstrate."],
    "target_section": "Security Considerations",
    "requested_change": "The requested documentation change.",
    "requested_change_strength": "informative_documentation",
    "requested_change_components": ["documentation change"],
    "sources": [
      {
        "url": "https://example.org/primary-source",
        "role": "Evidence for the established primitive or baseline.",
        "public_required": true
      },
      {
        "url": "https://example.org/complementary-source",
        "role": "Evidence for the new composition or amplification.",
        "public_required": true
      }
    ],
    "uncertainties": [],
    "public_projection_markers": {
      "distinct_delta": ["additional behavior"],
      "mechanism": ["security consequence"],
      "prerequisites": ["conditions required"],
      "consequence": ["bounded security consequence"],
      "limitations": ["applicability boundary"],
      "non_claims": ["does not demonstrate"],
      "requested_change": ["documentation change"],
      "requested_change_components": ["documentation change"]
    }
  },
  "consensus_evidence": []
}
```

Record both the evidence relationship and the resulting publication disposition for every related prior finding:

| Relationship | Disposition | Meaning |
| --- | --- | --- |
| `duplicate` | `exclude_already_raised` | Do not repeat the prior finding. |
| `refinement` | `merge` | Retain only the supported additional delta within the existing finding. |
| `distinct` | `retain_distinct` | Retain a separate finding because it has a concrete delta. |
| `follow_up_existing` | `follow_up_existing` | Add evidence or a narrower question to the existing thread. |
| `unable_to_verify` | `unable_to_verify` | Do not claim novelty or disposition until the relationship is verified. |

For `retain_distinct`, `merge`, and `follow_up_existing`, write a non-empty `distinct_delta`. For `exclude_already_raised`, explain the exclusion in `rationale`. A closed issue is not evidence that a finding was accepted or resolved; record such a status only when an authoritative comment or change supports it.

Always preserve `search_evidence`, including when no related prior finding is found. An empty `prior_feedback` list is valid when that bounded negative search is recorded; do not invent a prior-finding URL. Search-evidence URLs remain private unless the same URL is independently registered as the prior-feedback boundary, required finding evidence, or consensus evidence. Mark only the finding-evidence links that the public comment needs as `public_required: true`; keep corroborating sources false and private. A finding source marked `public_required: false` is not permitted in `comment.md`, and duplicate source URLs are invalid even when their role labels differ. Required public sources must have distinct evidence roles. Set `requested_change_strength` to `informative_documentation` or `normative_requirement`; the requested-change wording and final ask must preserve that force. List every material requested-change object separately in `requested_change_components`; entries must be atomic, derived from `requested_change`, and reproduced in full in the final ask. Use `public_projection_markers` for short, stable technical terms or phrases drawn verbatim from the corresponding finding field that must survive in `comment.md`; every material prerequisite, limitation, non-claim, and uncertainty needs a marker that distinguishes that entry from the others in the same field. The validator rejects generic, shared-only, duplicate, or unrelated markers. These markers are integrity checks between the packet and its projection, not a final-text template.

When `finding.uncertainties` is non-empty, add an `uncertainties` entry to `public_projection_markers` with a distinct derived marker for each material uncertainty. The empty-uncertainty example above does not need that entry.

## Public projection

Write `comment.md` as ordinary issue prose, not as a review report. It must:

- contain 50–140 words;
- contain no heading or table;
- use first-person singular when the reviewer is acting individually;
- cite one prior finding as the boundary when `prior_feedback` is non-empty; do not invent that boundary when the recorded search found none;
- state one distinct finding and its applicability boundary;
- give only the short technical support needed to understand the delta;
- end with one actionable question or request aimed at the relevant considerations section;
- contain 2–4 necessary links, all registered in the evidence packet;
- avoid claiming Working Group, reviewer, or community consensus without cited evidence.
- contain no HTML, HTML comments, images, code blocks, block quotes, reference-style Markdown links, Markdown link titles, or non-HTTP(S) link destinations.

A useful movement is: optional acknowledgment; prior-finding boundary; distinct technical delta and prerequisites; complementary evidence; one requested change. Do not copy a fixed phrase or preserve this sequence when a shorter natural construction is clearer.

Keep source roles complementary. For example, one source can establish an existing primitive while another demonstrates how the reviewed feature composes with or amplifies it. Retain additional corroborating sources in the private packet rather than adding them all to the comment.

Run the deterministic gate before presenting the comment:

```bash
python scripts/validate_focused_review.py --evidence /path/to/evidence-packet.json --comment /path/to/comment.md
```

Treat a passing gate as heuristic structural validation, not proof that the finding is correct. Fact-check the evidence and status claims separately.
