from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from w3c_knowledge.graph import GraphService
from w3c_knowledge.models import Artifact, SourceEvidence
from w3c_knowledge.schemas import SearchResult


class SearchService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def search(
        self,
        q: str,
        domain: str | None = None,
        artifact_type: str | None = None,
        specification: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[SearchResult]:
        stmt = select(Artifact)
        if q:
            pattern = f"%{q.lower()}%"
            stmt = stmt.where(or_(Artifact.normalized_text.ilike(pattern), Artifact.title.ilike(pattern)))
        if domain:
            stmt = stmt.where(Artifact.primary_domain == domain)
        if artifact_type:
            stmt = stmt.where(Artifact.artifact_type == artifact_type)
        if specification:
            stmt = stmt.where(Artifact.provenance["shortname"].as_string() == specification)
        artifacts = self.session.scalars(stmt.offset(offset).limit(limit)).all()
        graph = GraphService(self.session)
        results: list[SearchResult] = []
        for artifact in artifacts:
            evidence_ids = [
                row.internal_id
                for row in self.session.scalars(
                    select(SourceEvidence).where(SourceEvidence.artifact_id == artifact.internal_id)
                )
            ]
            relationship_links = graph.links_for_artifact(artifact, limit=5)
            links = [row["predicate"] for row in relationship_links]
            text = artifact.raw_text or artifact.title
            snippet = text[:240].replace("\n", " ")
            score = 1.0 if q.lower() in text.lower() else 0.5
            results.append(
                SearchResult(
                    title=artifact.title,
                    snippet=snippet,
                    artifact_type=artifact.artifact_type,
                    primary_domain=artifact.primary_domain,
                    applicable_domains=artifact.applicable_domains,
                    source_url=artifact.source_url,
                    canonical_url=artifact.canonical_url,
                    date=artifact.retrieved_at,
                    specification_version_or_commit=artifact.version or artifact.commit_sha,
                    primary_relationships=links,
                    relationship_links=relationship_links,
                    retrieval_score=score,
                    analysis_confidence=artifact.confidence,
                    evidence_ids=evidence_ids,
                )
            )
        return results
