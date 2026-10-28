"""Versioned local retrieval. Similarity ranks candidates; it does not validate claims."""
from __future__ import annotations

import hashlib
import math
import re
from functools import lru_cache
from datetime import UTC

from sqlalchemy import case, delete, func, literal, select, text, union_all
from sqlalchemy.orm import Session

from w3c_knowledge.config import get_settings
from w3c_knowledge.models import Artifact, SourceEvidence, Specification, SpecificationSection, SpecificationVersion
from w3c_knowledge.search.embeddings import DIMENSIONS, FINGERPRINT, LocalEncoder
from w3c_knowledge.search.vector_store import VectorChunk as Chunk, VectorDocument as Document


def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def same_time(a, b):
    # SQLite drops the timezone annotation from UTC timestamps on readback.
    def utc(value):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    return utc(a) == utc(b)


@lru_cache(maxsize=1)
def local_encoder() -> LocalEncoder:
    settings = get_settings()
    return LocalEncoder(settings.embedding_model_dir, settings.embedding_threads)


class VectorService:
    def __init__(self, session: Session, encoder=None):
        self.session = session
        self._encoder = encoder
        self.fingerprint = encoder.fingerprint if encoder is not None else FINGERPRINT

    @property
    def encoder(self):
        return self._encoder if self._encoder is not None else local_encoder()

    def sources(self, kind=None, specification=None, version_id=None, domain=None):
        """Shared source selection for coverage and results; version IDs are exact."""
        rows = []
        if kind in (None, "artifact") and version_id is None:
            body = func.coalesce(Artifact.raw_text, Artifact.normalized_text, Artifact.title)
            stmt = select(
                (literal("artifact:") + Artifact.internal_id).label("id"),
                Artifact.internal_id.label("source_id"), literal("artifact").label("kind"),
                body.label("body"), Artifact.updated_at.label("updated_at"),
            ).where(func.length(func.trim(body)) > 0)
            if specification:
                stmt = stmt.where(Artifact.provenance["shortname"].as_string() == specification)
            if domain:
                stmt = stmt.where(Artifact.primary_domain == domain)
            rows.append(stmt)
        if kind in (None, "section") and domain is None:
            stmt = select(
                (literal("section:") + SpecificationSection.internal_id).label("id"),
                SpecificationSection.internal_id.label("source_id"), literal("section").label("kind"),
                SpecificationSection.raw_text.label("body"), SpecificationSection.updated_at.label("updated_at"),
            ).join(SpecificationVersion).join(Specification).where(func.length(func.trim(SpecificationSection.raw_text)) > 0)
            if specification:
                stmt = stmt.where(Specification.shortname == specification)
            if version_id:
                stmt = stmt.where(SpecificationVersion.internal_id == version_id)
            rows.append(stmt)
        if not rows:
            # Preserve the column shape for deliberately disjoint filters.
            return self.sources(kind="artifact").select().where(literal(False)).subquery()
        return union_all(*rows).subquery()

    def fresh(self, **filters):
        source = self.sources(**filters)
        return select(Document.id).join(source, source.c.id == Document.id).where(
            Document.fingerprint == self.fingerprint,
            Document.source_updated_at == source.c.updated_at,
            Document.source_text == source.c.body,
            Document.chunk_count > 0,
        )

    def status(self, **filters) -> dict:
        total = self.session.scalar(select(func.count()).select_from(self.sources(**filters))) or 0
        fresh = self.session.scalar(select(func.count()).select_from(self.fresh(**filters).subquery())) or 0
        return {
            "status": "empty" if total == 0 else "complete" if fresh == total else "partial",
            "eligible_documents": total, "indexed_documents": fresh,
            "unindexed_or_stale_documents": total - fresh,
            "fingerprint": self.fingerprint,
            "scope": "nonempty specification sections and artifacts; other raw tables are not indexed",
            "filters": filters,
        }

    def reindex(self, *, rebuild=False) -> dict:
        # Load/verify the model before taking the writer lock or touching index data.
        encoder = self.encoder
        pg = self.session.bind.dialect.name == "postgresql"
        try:
            if pg:
                locked = bool(self.session.scalar(text("SELECT pg_try_advisory_xact_lock(727384610)")))
                if not locked:
                    raise RuntimeError("Another vector indexer is running")
            changed = unchanged = chunks = 0
            # Stream source text; retain only one document's embeddings at a time.
            for source in self.session.execute(select(self.sources()).order_by("id").execution_options(yield_per=32)).mappings():
                old = self.session.get(Document, source["id"])
                if not rebuild and old and old.fingerprint == self.fingerprint and old.source_text == source["body"] and old.source_updated_at == source["updated_at"]:
                    unchanged += 1
                    continue
                spans = encoder.chunks(source["body"])
                values = []
                for first in range(0, len(spans), 8):
                    batch = spans[first:first + 8]
                    vectors = encoder.encode([source["body"][a:b] for a, b in batch])
                    if len(vectors) != len(batch) or any(len(v) != DIMENSIONS or not all(math.isfinite(x) for x in v) or abs(sum(x*x for x in v) - 1) > 0.01 for v in vectors):
                        raise ValueError("Encoder returned invalid, non-normalized or incomplete vectors")
                    values.extend(vectors)
                if not spans:
                    raise ValueError("Nonempty source produced no embedding chunks")
                # Atomic per document; an error rolls back this entire reindex transaction.
                self.session.execute(delete(Chunk).where(Chunk.document_id == source["id"]))
                self.session.execute(delete(Document).where(Document.id == source["id"]))
                self.session.add(Document(id=source["id"], kind=source["kind"], source_id=source["source_id"], source_updated_at=source["updated_at"], source_text=source["body"], source_sha256=sha(source["body"]), fingerprint=self.fingerprint, chunk_count=len(spans)))
                self.session.flush()
                for number, ((start, end), vector) in enumerate(zip(spans, values, strict=True)):
                    body = source["body"][start:end]
                    self.session.add(Chunk(id=f"{source['id']}:{number}", document_id=source["id"], start=start, end=end, text=body, sha256=sha(body), embedding=vector))
                self.session.flush()
                changed += 1
                chunks += len(spans)
            eligible = select(self.sources().c.id)
            removed = select(Document.id).where(Document.id.not_in(eligible))
            self.session.execute(delete(Chunk).where(Chunk.document_id.in_(removed)))
            self.session.execute(delete(Document).where(Document.id.in_(removed)))
            self.session.commit()
            return {"changed_documents": changed, "unchanged_documents": unchanged, "written_chunks": chunks, "coverage": self.status()}
        except BaseException:
            self.session.rollback()
            raise

    def search(self, q: str, *, mode="hybrid", limit=10, **filters) -> dict:
        if mode not in {"lexical", "vector", "hybrid"} or not q.strip() or len(q) > 4000 or not 1 <= limit <= 100:
            raise ValueError("Use a nonempty query (maximum 4000 characters), a supported mode and limit 1..100")
        coverage = self.status(**filters)
        base = select(Chunk).where(Chunk.document_id.in_(self.fresh(**filters)))
        ranks, cosine, lexical = {}, {}, {}
        candidates = {}
        if mode in {"vector", "hybrid"}:
            vector = self.encoder.encode([q], query=True)[0]
            if self.session.bind.dialect.name == "postgresql":
                distance = Chunk.embedding.cosine_distance(vector)
                ranked = [(c, float(d)) for c, d in self.session.execute(base.add_columns(distance).order_by(distance, Chunk.id).limit(200))]
            else:
                ranked = sorted(((c, 1.0 - sum(a*b for a, b in zip(c.embedding, vector, strict=True))) for c in self.session.scalars(base)), key=lambda pair: (pair[1], pair[0].id))[:200]
            for rank, (chunk, distance) in enumerate(ranked, 1):
                candidates[chunk.id] = chunk
                cosine[chunk.id] = 1.0 - distance
                ranks[chunk.id] = 1.0 / (60 + rank)
        if mode in {"lexical", "hybrid"}:
            terms = list(dict.fromkeys(re.findall(r"\w+", q.lower())))[:24]
            if terms:
                score = sum(case((func.lower(Chunk.text).contains(term, autoescape=True), 1), else_=0) for term in terms)
                for rank, (chunk, hits) in enumerate(self.session.execute(base.add_columns(score).where(score > 0).order_by(score.desc(), Chunk.id).limit(200)), 1):
                    candidates[chunk.id] = chunk
                    lexical[chunk.id] = int(hits)
                    ranks[chunk.id] = ranks.get(chunk.id, 0) + 1.0 / (60 + rank)
        chosen = sorted(candidates, key=lambda key: (-ranks[key], key))[:limit]
        results = []
        for key in chosen:
            chunk = candidates[key]
            document = self.session.get(Document, chunk.document_id)
            if document.kind == "section":
                source = self.session.get(SpecificationSection, document.source_id)
                if source is None or source.raw_text != document.source_text or not same_time(source.updated_at, document.source_updated_at):
                    continue
                version = self.session.get(SpecificationVersion, source.specification_version_id)
                info = {"title": source.heading, "source_url": source.source_url, "anchor": source.anchor, "specification_version_id": version.internal_id, "version_or_commit": version.source_commit or version.version, "evidence_ids": source.evidence_ids}
            else:
                source = self.session.get(Artifact, document.source_id)
                if source is None or (source.raw_text if source.raw_text is not None else source.normalized_text if source.normalized_text is not None else source.title) != document.source_text or not same_time(source.updated_at, document.source_updated_at):
                    continue
                info = {"title": source.title, "source_url": source.source_url, "artifact_type": source.artifact_type, "version_or_commit": source.commit_sha or source.version, "evidence_ids": list(self.session.scalars(select(SourceEvidence.internal_id).where(SourceEvidence.artifact_id == source.internal_id)))}
            results.append({**info, "kind": document.kind, "source_id": document.source_id, "source_sha256": document.source_sha256, "chunk_id": chunk.id, "start": chunk.start, "end": chunk.end, "text": chunk.text, "sha256": chunk.sha256, "retrieval_score": ranks[key], "cosine_similarity": cosine.get(key), "lexical_term_hits": lexical.get(key)})
        return {"mode": mode, "ranking": "reciprocal-rank-fusion-k60" if mode == "hybrid" else mode, "coverage": coverage, "results": results}
