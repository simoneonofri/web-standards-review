# Architecture

`w3c-security-pattern-miner` consumes normalized W3C material and produces security mining results for one specification version at a time.

`w3c-knowledge` owns retrieval, parsing, normalization, links, source metadata, and evidence spans. `w3c-horizontal-review-patterns-miner` owns specification family and horizontal-review pattern selection. This skill owns security-surface modeling, explicit and derived security observations, reusable security patterns, security checks, catalog merge policy, and provenance.

The local `w3c-knowledge` repository is available at `simoneonofri/w3c-knowledge`. Its documented consumer contract is the versioned `/api/v1/` API, especially `GET /api/v1/specifications/{id}/source-packet`, which returns `source_packet_contract_version: 1`. A local `w3c-horizontal-review-patterns-miner` repository is also available at `simoneonofri/w3c-horizontal-review-patterns-miner`, so this skill reuses compatible family and facet identifiers without importing it or requiring it at runtime.

No live network calls, GitHub ingestion, W3C crawling, vector search, or replacement knowledge store belongs in this repository.