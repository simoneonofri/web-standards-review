# Mandatory Miner Knowledge + Threat Knowledge in specification threat modeling

This is part of Web Standards Review's existing monorepo, not a new skill, repo
or online database. It applies whenever What Can Go Wrong reviews a versioned
Web specification. For generic diagram-only modeling with no spec snapshot,
the original modeling workflow remains available without a false W3C claim.

## Responsibilities

What Are We Building produces the model, DFD, dictionary and exact source
identity. It does not decide whether a control mitigates a threat.

Miner Knowledge provides bounded, source-linked control and pattern candidates
from catalog snapshots. Threat Knowledge provides independent protocol security,
privacy, human-rights and harms methods. The registry of authoritative source
links is at skills/threat-knowledge/references/public-sources.json; original
method questions are at prompt-packs/operational-method-prompts-v1.json.

What Can Go Wrong MUST apply both providers in three distinct phases:

1. EXPLICIT — Identify actual bad events and protections documented in Security
   and Privacy Considerations and other explicit threat discussions.
2. IMPLICIT — Inspect normative algorithms, protection mechanisms, inherited
   platform controls, defaults and exceptions. For observed controls, partial
   or missing controls, reconstruct the implied bad events and affected
   model elements. A documented control is not proof of correct implementation.
3. ADDITIONAL — After freezing the baseline, use both Miner Knowledge patterns
   and Threat Knowledge frameworks to generate and disposition additional
   candidate bad events, independently of the baseline. Reconcile afterward.

Baseline-only work requires explicit and implicit but does not claim that
additional methods were run.

## Prepare a reproducible selection

From the installed marketplace/plugin root:

    python3 scripts/reconcile_specification_knowledge.py prepare \
      --model /outside/repo/run/model.json \
      --source-packet /outside/repo/run/source-packet.json \
      --cache /outside/repo/cache-VERSION.zip \
      --domains security,privacy,harms,human-rights \
      --mode full \
      --output-dir /outside/repo/run/knowledge

The source packet must be complete, versioned, and match the accepted
model source identity. The resulting knowledge-selection.json records
source/catalog/method hashes, selected IDs, both providers per phase and
bounded catalog exclusions. The dispositions template is not a review result.

For every selected item, inspect exact source clauses, name the affected
canonical DFD element, write a phase-specific disposition and an honest
rationale. Affirmative source observations require exact section URLs.
Observed/partial/absent controls require a concrete implied bad event.
Producing threats require linked canonical threat IDs. Non-applicability
also requires a model element and source anchor. Missing evidence is
unable_to_verify, not a finding or a default non-applicable.

## Reconcile and validate

    python3 scripts/reconcile_specification_knowledge.py verify \
      --selection /outside/repo/run/knowledge/knowledge-selection.json \
      --dispositions /outside/repo/run/knowledge/knowledge-dispositions.json \
      --model /outside/repo/run/model.json \
      --source-packet /outside/repo/run/source-packet.json \
      --cache /outside/repo/cache-VERSION.zip \
      --baseline-threats /outside/repo/run/baseline-threats.json \
      --threats /outside/repo/run/threats.json \
      --output /outside/repo/run/knowledge/reconciliation-receipt.json

The verifier reconstructs the selected provider/phase roster, rechecks
immutable source and catalog hashes, and rejects dropped/altered/pending
candidates. It returns nonzero for partial or blocked reviews. A valid
receipt proves selected items were adjudicated, NOT that all threats were
discovered or that browser controls work.

For real spec models, the bundled What Can Go Wrong threat-package validator
now automatically requires the exact knowledge selection, dispositions,
source packet and cache (plus frozen baseline for a full pass).
The independent good-enough gate requires a passing knowledge receipt and
both providers' dispositions in each requested phase. It must receive
the model and receipt, not merely a manually supplied pass label.

The separate charter review uses Strategy Charter Miner and relevant
historical charter questions, not this technical specification elicitation.

## Scope and publication truth

The portable cache is a list of questions, not an execution of live miners.
Operational method prompts link to RFC 3552, RFC 6973, RFC 9620, STRIDE,
LINDDUN and other named methods; no paid or third-party source text is bundled.
The historical source registry and method-specific questions need normal
source and licensing verification. Accessibility/i18n/human-rights domain
coverage requires specialist review to claim completeness. Sustainability
remains a separate future work item. Keep all review artifacts outside the
monorepo. Public release is still blocked by the rights/licensing gate.


## Optional full Threat Knowledge source cache

When a pinned Threat Knowledge corpus ZIP is available, supply --threat-cache
to both prepare and verify (and --knowledge-threat-cache to the What Can Go
Wrong validator). The same SHA-256 is pinned into the knowledge selection.
This reuses the curated original Threat Knowledge tables instead of the
minimal bundled operational prompts; do not duplicate the corpus. The cache
is generated with scripts/export_threat_knowledge_cache.py and queried with
scripts/query_threat_knowledge_cache.py. See cache/threat-knowledge/README.md.
If that artifact is absent, label source registry fallback coverage limited.
