from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from w3c_knowledge.models import Artifact, SourceEvidence
from w3c_knowledge.schemas import (
    ProcessQuestionContext,
    ProcessQuestionContextItem,
    TransitionRequestContextItem,
)

PROCESS_ARTIFACT_TYPES = ("process_document",)
GUIDEBOOK_ARTIFACT_TYPES = ("operational_guidance",)
TRANSITION_ARTIFACT_TYPES = ("transition_request",)
TRANSITION_TERMS = (
    "transition",
    "transitions",
    "candidate recommendation",
    "cr",
    "proposed recommendation",
    "pr",
    "recommendation",
    "wide review",
)


class ProcessQuestionContextService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def context(self, q: str, limit: int = 10) -> ProcessQuestionContext:
        query = q.strip()
        process_artifacts = self._search_artifacts(PROCESS_ARTIFACT_TYPES, query, limit)
        guidebook_artifacts = self._search_artifacts(GUIDEBOOK_ARTIFACT_TYPES, query, limit)
        transition_artifacts = self._search_transition_artifacts(
            query,
            process_artifacts + guidebook_artifacts,
            limit,
        )
        return ProcessQuestionContext(
            query=query,
            process_requirements=[
                self._process_or_guidebook_item(artifact, "process")
                for artifact in process_artifacts
            ],
            guidebook_guidance=[
                self._process_or_guidebook_item(artifact, "guidebook")
                for artifact in guidebook_artifacts
            ],
            transition_requests=[
                self._transition_item(artifact) for artifact in transition_artifacts
            ],
            notes=[
                "Process results are W3C Process material; Guidebook results are operational guidance.",
                "Transition requests are GitHub issue artifacts correlated by query terms and explicit transition vocabulary.",
            ],
        )

    def _search_transition_artifacts(
        self,
        query: str,
        context_artifacts: list[Artifact],
        limit: int,
    ) -> list[Artifact]:
        artifacts = self._search_artifacts(TRANSITION_ARTIFACT_TYPES, query, limit)
        if artifacts or not self._is_transition_related(query, context_artifacts):
            return artifacts
        return self._search_artifacts(TRANSITION_ARTIFACT_TYPES, "transition", limit)

    def _search_artifacts(
        self,
        artifact_types: tuple[str, ...],
        query: str,
        limit: int,
    ) -> list[Artifact]:
        stmt = select(Artifact).where(Artifact.artifact_type.in_(artifact_types))
        if query:
            pattern = f"%{query.lower()}%"
            stmt = stmt.where(
                or_(Artifact.normalized_text.ilike(pattern), Artifact.title.ilike(pattern))
            )
        return self.session.scalars(stmt.limit(limit)).all()

    def _is_transition_related(self, query: str, artifacts: list[Artifact]) -> bool:
        haystacks = [query.lower()]
        haystacks.extend(
            f"{artifact.title} {artifact.raw_text or ''}".lower() for artifact in artifacts
        )
        return any(term in haystack for haystack in haystacks for term in TRANSITION_TERMS)

    def _process_or_guidebook_item(
        self,
        artifact: Artifact,
        source_kind: str,
    ) -> ProcessQuestionContextItem:
        return ProcessQuestionContextItem(
            title=artifact.title,
            snippet=self._snippet(artifact),
            source_kind=source_kind,
            artifact_type=artifact.artifact_type,
            source_url=artifact.source_url,
            canonical_url=artifact.canonical_url,
            date=artifact.retrieved_at,
            specification_version_or_commit=artifact.version or artifact.commit_sha,
            evidence_ids=self._evidence_ids(artifact),
        )

    def _transition_item(self, artifact: Artifact) -> TransitionRequestContextItem:
        return TransitionRequestContextItem(
            title=artifact.title,
            snippet=self._snippet(artifact),
            source_url=artifact.source_url,
            state=artifact.metadata_.get("state"),
            labels=artifact.metadata_.get("labels") or [],
            issue_number=artifact.provenance.get("number"),
            evidence_ids=self._evidence_ids(artifact),
        )

    def _snippet(self, artifact: Artifact) -> str:
        text = artifact.raw_text or artifact.title
        return text[:360].replace("\n", " ")

    def _evidence_ids(self, artifact: Artifact) -> list[str]:
        return [
            row.internal_id
            for row in self.session.scalars(
                select(SourceEvidence).where(SourceEvidence.artifact_id == artifact.internal_id)
            )
        ]
