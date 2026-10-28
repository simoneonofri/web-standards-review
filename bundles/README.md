# Bundles

`threat-modeling-flow-v1.json` describes the reviewed private-beta bundle. Catalog version 4 installs all 19 skills; the bundle keeps the canonical five-stage modeling flow and adds three entrypoints for different starting tasks.

| Entrypoint | Responsibility |
| --- | --- |
| `w3c-issue-pr-review` | Issue/PR context, linked evidence, recommendation, response draft, and resolution check |
| `spec-review` | Focused specification finding or complete threat-modeling flow |
| `w3c-horizontal-review` | Specification/charter orchestration, domain coverage, and reconciliation |

An issue or PR can enter a specialist workflow when the requested review needs it. Pass the exact target, question, checked sources, coverage limits, and acceptance conditions; return the result to the thread entrypoint for the response. See the [integration guide](../skills/w3c-issue-pr-review/references/marketplace-integration.md). A handoff note is not a validated model or finding contract, and a thread review does not run every modeling stage by default.

The five stages remain `what-are-we-building` → `dfd-mermaid` → `what-can-go-wrong` → `what-are-we-going-to-do-about-it` → `did-we-do-a-good-enough-job`. Contracts remain in this repository tree so producer and consumer changes can be tested together.

Validate the bundle with `./tools/reviewctl/reviewctl validate-bundle bundles/threat-modeling-flow-v1.json` from the repository root. Install it with `./tools/reviewctl/reviewctl install --bundle threat-modeling-flow-v1 --host codex` (or `claude` or `all`). Installation and export operate on an audited clean commit; editing files alone does not update an installed snapshot.

The bundle remains a private-beta artifact requiring publication review. Neither validation nor a generated recommendation represents group adoption or authorizes remote publication.
