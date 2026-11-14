# Offline miner cache inside Web Standards Review

This is part of the existing Web Standards Review monorepo. It does not create
another repository, another skill, or a second marketplace.

## Three layers

1. Optional source providers: W3C Knowledge, official specifications, issue
   trackers and independently maintained miner source checkouts. These are not
   included in the portable marketplace.
2. Checked-in portable skills and their reviewed catalogs: the marketplace's
   skills/ directory is the only source for the offline export.
3. Lightweight portable snapshots: a versioned ZIP archive containing
   records.jsonl, records.json, records.csv, index.html, index.md,
   curation-template.csv, and manifest.json.

Users without W3C Knowledge can search the archive by domain and keyword.
They still need an exact target specification snapshot or source packet to
substantiate a target-specific conclusion. The index contains questions and
patterns, not proven defects or adopted W3C consensus.

## Build an offline cache

From the root of the monorepo, run:

    python3 scripts/export_miner_cache.py --output /outside/repo/web-review-cache.zip

This reads only the five explicitly allowed source catalogs listed in the
exporter under skills/. It has no network, Docker, database or other repository
dependency. The output must remain outside the checkout and is private staging
until redistribution rights are reviewed.

To use the index in a terminal:

    python3 scripts/query_miner_cache.py /outside/repo/web-review-cache.zip --domain privacy --search fingerprint

Extract and open index.html for a human-readable local searchable catalog.
CSV is useful for inspection; JSONL or JSON is useful for agents and scripts.
The manifest contains source and payload SHA-256 digests plus catalog version
and per-miner coverage. Consumers should pin an immutable release asset hash.

## Issue, review, threat-model handoff

For an exact W3C Knowledge source-packet v1 JSON previously exported and
frozen to an immutable specification version:

    python3 scripts/review_miner_gate.py --cache /outside/repo/web-review-cache.zip --source-packet /path/to/frozen-source-packet.json --kind review --scope combined --domains security,privacy,design,accessibility,internationalization,harms,human-rights --output-dir /outside/repo/review-run/miner-preflight

Supported kinds: issue, review, threat-model.
Supported scopes: editorial, charter, security, privacy, design,
accessibility, internationalization, harms, human-rights, combined.

An ordinary editorial issue may use kind issue / scope editorial / reason,
and skips technical catalog lookups. Charter/recharter scope requires a reason
and separately delegates to strategy-charter-miner. A cached question index
cannot replace that specialist. Sustainability is intentionally deferred.

The gate checks cache hashes and the supplied source packet identity, rejects
mixed-version sections and incomplete normative coverage, and produces:
- miner-gate.json: scope, selected domains, exact target ID/version and ledger
- checks.json: unevaluated candidate checks with source provenance
- threat-queue.json: unconsumed prompts awaiting attachment to a model

The CLI returns a nonzero exit code for partial, blocked, and
needs_specialist results, while retaining the receipt for inspection. Only
preflight_ready and a justified editorial not_applicable return success.

A cache hit is recorded as cache_hit, NOT miner_invoked. Missing specialist
sources are explicitly unavailable or partial. An offline cache preflight
never certifies that the complete six-miner orchestration, what-can-go-wrong
elicitation, DFD modeling, reviewer dispositions, or implementation testing
were performed. The portable gate can be used before starting those stages.

## Collaboration and weekly refresh

Human changes are proposed through pull requests to this SAME repository's
cache/curation/overrides.csv. Each override is keyed by a stable question ID,
and can change only question wording, applicability, curation status and
reviewer note. Generated JSONL/CSV files should not be edited by hand.
Approved overrides remain layered above freshly mined catalogs.

Every week, a maintainer may refresh source miners on Tleilax, promote reviewed
catalog updates into the skills/ tree through their normal publication
projections, run tests and the rights review, then generate a ZIP. A future
approved GitHub release of Web Standards Review can attach this ZIP as an
additional DATA asset. The skills and the cache will share one versioned
marketplace, while the exact cache digest documents its data freshness.

The cache is NOT a replacement for W3C Knowledge, and an automated public
release must never run solely because nightly mining completed.

## Coverage limitations and backlog

Available portable source catalogs: W3C WebAppSec, WHATWG, W3C Spec pattern
definitions, horizontal-review pattern definitions, security-pattern checks.

Some specialist miners, including Strategy and query-specific vulnerability
intelligence, are not bundled as generic reusable catalog exports. Initial
accessibility, i18n, harms and human-rights records are reference-only and
MUST NOT be treated as complete specialist checks. The full specialist
miner routing remains separate and may require W3C Knowledge or primary
source retrieval.

Sustainability / Web Sustainability Guidelines / Insights are FUTURE WORK.
No sustainability miner, standards taxonomy or source-rights review is
claimed to exist in this portable cache.

## Published cache boundary

The public repository distributes the **reviewed, original question-pattern
index** in `cache/miner-knowledge-v1.zip`; the W3C Software and Document
License 2023 applies to the code and author-maintained prompt catalog.
The index does not include W3C Knowledge's database, private overlays,
credentials or entire source specifications. Metadata, manifest and
SHA-256 values are checked by `reviewctl audit-marketplace`.

The independently curated third-party Threat Knowledge source corpus is
**not** redistributed. Only newly authored category-level routing prompts
are included in `cache/threat-knowledge-v1.zip`; source texts, verbatim
third-party questions, case narratives and private spreadsheet URLs are
excluded. See [Threat Knowledge](threat-knowledge/README.md).

The source/versioned specification packet is a separate input. A cache hit
never means a specialist miner was executed or a target threat verified.

## Mandatory application inside What Can Go Wrong

A cache contains discovery questions, not an executed threat model.
For a specification, What Can Go Wrong MUST apply **both** Miner Knowledge
and Threat Knowledge to explicit, implicit, and additional phases, then
reconcile every selected question against actual source sections and model
elements. The reference protocol and fail-closed gate are documented in
[mandatory knowledge application](../docs/mandatory-specification-knowledge.md).
This is separate from the earlier offline review_miner_gate preflight.


## Portable Threat Knowledge cache

The Threat Knowledge source corpus may be exported separately into a small, source-pinned question-cache ZIP, queryable offline by any skill or external tool. See [Threat Knowledge cache](threat-knowledge/README.md). The public ZIP contains original routing questions only; the curated source corpus remains separate.
