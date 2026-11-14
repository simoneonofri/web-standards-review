# Threat Knowledge — portable question cache

The authoritative curated corpus remains the separate local threat-knowledge source checkout. This folder describes an **optional portable data asset** distributed through the SAME Web Standards Review monorepo and its releases. No new repository or database is necessary.

## Included public artifact

`cache/threat-knowledge-v1.zip` contains 169 **original category-level
routing prompts**, with their public method and RFC links, JSON/JSONL,
CSV and offline HTML browser. The original source questions, third-party
full texts and private curated corpus are not distributed. The public
artifact is built separately from the private curated source cache using
`scripts/build_public_threat_cache.py`; its SHA-256 manifest is verified
by the marketplace audit.

Consume the packaged cache without Docker or W3C Knowledge:

    python3 scripts/query_threat_knowledge_cache.py cache/threat-knowledge-v1.zip --source stride --limit 6

To apply it to a pinned spec/model along with Miner Knowledge, run
`scripts/knowledge_cache_fallback.py` from the marketplace root.

## Refresh and export

From Web Standards Review root:

    python3 scripts/export_threat_knowledge_cache.py \
      --threat-knowledge-root /trusted/local/threat-knowledge \
      --output /private/staging/threat-knowledge-VERSION.zip

The exporter extracts bounded question/index entries from selected source tables: STRIDE, RFC 3552/6973/9620, LINDDUN, Microsoft Harms, W3C privacy/security questions, Access Now stakeholder/harms, Corti et al. and cognitive threats. It DOES NOT package raw PDFs, private stories, original spreadsheet files or full framework text. The source hash, rows and rights status are recorded for every source tab. The user may approve editorial corrections through an overrides CSV.

An independent consumer can use:

    python3 scripts/query_threat_knowledge_cache.py \
      /private/staging/threat-knowledge-VERSION.zip \
      --source rfc9620 --search privacy

Extract the ZIP to read JSONL, JSON, CSV or the offline HTML search index. The query tool requires only the Python standard library.

## Integration with What Can Go Wrong

The full optional cache can feed the REQUIRED three-pass knowledge selection:

    python3 scripts/reconcile_specification_knowledge.py prepare \
      --model /run/model.json --source-packet /run/source.json \
      --cache /release/miner-cache.zip \
      --threat-cache /release/threat-knowledge-cache.zip \
      --mode full --domains security,privacy,harms,human-rights \
      --output-dir /run/knowledge

When supplied, the adapter uses source-linked questions from the existing Threat Knowledge corpus, not a second hand-authored substitute catalog. Its exact SHA-256 is pinned to the knowledge selection. The verify step and What Can Go Wrong's threat-package validator must receive the SAME --threat-cache path.

Without the full cache, the minimal bundled original method prompts are a source-routing fallback, not evidence of comprehensive Threat Knowledge question coverage.

## Weekly update and rights

Prefer a weekly, manually approved refresh on Tleilax: refresh the source tables, inspect deltas, apply approved editorial overrides, compute hashes, test query compatibility, and upload the resulting ZIP to a **Web Standards Review release** only after the rights gate passes. Include an immutable content digest in each review.

The original, source-derived private cache remains restricted pending
its own source-rights review. This restriction does not apply to the
separately authored public routing-only cache distributed here.
Sustainability prompts are deferred.
