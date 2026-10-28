# Local W3C Knowledge

This reviewed source snapshot runs a separate local evidence service for the private beta. It includes ingestion and API code, public source configuration, migrations, and provenance hashes. Each collaborator starts with an empty database. No maintainer database, credentials, downloaded corpus, private review, or source Git history is included.

From this directory, with Python 3 and Docker Compose installed:

```sh
python3 setup_local.py --output /path/to/private/knowledge.env
docker compose --env-file /path/to/private/knowledge.env up --build -d
docker compose --env-file /path/to/private/knowledge.env run --rm api w3c-knowledge sync-tr --statuses REC,CR,CRD,WD --shortname geolocation
```

Choose an existing private directory outside the source checkout, installation snapshot, or composed package for `knowledge.env`. The API binds to the loopback interface on port 18080 by default. The database has no published host port. `setup_local.py` writes a new random local database password with owner-only permissions and refuses to overwrite existing settings. Without `--output` it uses an ignored `.env` beside the script; use the explicit external path above so runtime settings do not cause package-audit or update drift. The Compose project and volume are separate from other W3C Knowledge installations. Do not reuse a personal service's volume or import a database dump as part of this setup.

Use `docker compose --env-file /path/to/private/knowledge.env down` to stop the service while retaining its local data. Refresh only the sources needed for the current review. Public fetches may be rate-limited; an unavailable source remains unavailable rather than evidence of no issue.

The API preserves source text, snapshot identifiers, section coverage, locators, content hashes, and retrieval timestamps. Its threat-model source packet uses contract version 2 to distinguish the documentary baseline from independent elicitation. Consumers use the API or exported source packets; they do not access the database directly.

## Local embeddings and vector search

Download the fixed local model once, then index the sources actually ingested:

```sh
docker compose --env-file /path/to/private/knowledge.env exec api w3c-knowledge download-embedding-model
docker compose --env-file /path/to/private/knowledge.env exec api w3c-knowledge reindex
docker compose --env-file /path/to/private/knowledge.env exec api w3c-knowledge index-status
docker compose --env-file /path/to/private/knowledge.env exec api w3c-knowledge retrieve "Come viene richiesto il consenso per la geolocalizzazione?" --specification geolocation
```

The model is [multilingual E5 small](https://huggingface.co/intfloat/multilingual-e5-small/tree/614241f622f53c4eeff9890bdc4f31cfecc418b3), revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`, with the model card's MIT license. The two downloaded files total about 487 MB and are verified against fixed SHA-256 digests. ONNX Runtime uses the CPU, with two inference threads by default and no GPU or API key requirement. Set `KNOWLEDGE_EMBEDDING_THREADS` to 1–8 in the Compose environment if needed. Allow approximately 2 GB of available memory for the service and indexing as an initial deployment allowance; actual use depends on document sizes and the runtime. Test capacity on the colleague's machine before indexing a large corpus.

Weights live in the separate `knowledge-models` Docker volume. The runtime uses only these verified local files; indexing and searching do not download weights, send source text or queries to an embedding API, or use Hub account credentials. The explicit download contacts Hugging Face. Public source ingestion and an explicitly requested miner refresh still contact their respective sources. A missing or invalid model fails with an actionable error; it is never reported as a successful semantic search.

The index covers nonempty specification sections and normalized artifacts, including review findings represented as artifacts. Other raw database tables are outside its declared coverage. Text is split into overlapping token windows with exact source character offsets. Each chunk records a source and chunk SHA-256, source ID, fixed model/chunker fingerprint and 384-dimensional embedding. PostgreSQL ranks with exact cosine distance; hybrid mode combines lexical and vector ranks. It currently favors reproducibility over approximate nearest-neighbor indexing. Top-k retrieval is a candidate selection step, not exhaustive source review.

Use `--mode vector`, `--mode hybrid` (default), or `--mode lexical` with `retrieve`. An exact `--version-id` restricts retrieval to that specification version's sections. Without it, results can include multiple locally stored versions and retain their individual identities. The HTTP endpoints are `/api/v1/retrieval/search?q=...&mode=hybrid`, with optional `specification`, `version_id`, `kind`, `domain`, `limit`, and `/api/v1/retrieval/status`. A domain filter selects artifacts; specification sections have no assigned review domain. The existing `/api/v1/search` and `/precedents` retain their original lexical artifact behavior and work without generating embeddings.

Every new retrieval response states eligible, indexed, and stale/missing document counts. `complete` refers only to the selected local index scope, not completeness of the W3C corpus or a review. Unchanged documents are reused by `reindex`; modified or deleted sources are excluded from retrieval before the next index run. Reindex after ingestion or normalization. A failed run rolls back its index changes; the previous valid index remains available. Use `reindex --rebuild` for a complete refresh. No automatic background task is installed.

For a native Python environment, use Python 3.12 or later, install this provider with `pip install '.[vectors]'`, configure an external database and `W3C_KNOWLEDGE_EMBEDDING_MODEL_DIR`, and run `alembic upgrade head` before indexing. PostgreSQL must have the pgvector extension available. The Docker route installs these dependencies and runs migrations. Unit tests use a fake encoder and SQLite; `tests/smoke_local_vectors.py` separately verifies real E5 retrieval on an empty disposable PostgreSQL database and must never be run against a populated working database.

Search scores describe retrieval relevance, not confidence in a security finding. This local service has no application authentication boundary for a shared deployment; keep the provided loopback binding.

This snapshot is part of the restricted private beta. Source provenance is in `.review/provenance.json`; public redistribution and its license remain subject to the package's publication review.
