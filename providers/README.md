# Public provider interfaces

Portable skills depend on typed interfaces such as `ReviewEvidenceProvider`, `ReviewCheckProvider`, `PromptSeedProvider`, `MethodKnowledgeProvider`, `ImplementationEvidenceProvider`, `FactSourceProvider`, and `ArtifactStore`. The optional [local W3C Knowledge service](w3c-knowledge/README.md) supplies source evidence without requiring access to a maintainer's service or database.

An unavailable required provider produces an explicit blocked or unable-to-verify state. It must not fall back to model memory or silently reduce behavior.

Capture a selected specification using the service's base URL in `W3C_KNOWLEDGE_URL`:

```sh
python3 tools/reviewctl/evidence.py --knowledge-url "$W3C_KNOWLEDGE_URL" --spec geolocation --output /path/to/run/source-corpus
```

Alternatively use `--packet /path/to/source-packet.json`, with `--full-sections /path/to/sections.json` when the packet omits inventoried sections. Add `--expected-snapshot <exact-URL>` when the user supplied a dated snapshot. A mismatch blocks capture. The helper preserves the raw responses, exact section text hashes, provider hashes, and coverage in a `source-corpus-manifest/v1`. The modeling stage uses these records to build its `source-corpus/v1` input; the two objects are not schema aliases.

The convenience threat-model endpoint has default limits. The client uses the primary source endpoint and, when needed, obtains full sections for the exact version. Complete primary coverage does not establish complete coverage of referenced specifications, RFCs, implementation repositories, or browser behavior. Those remain explicit follow-up work.
