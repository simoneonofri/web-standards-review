from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from w3c_knowledge.models import (
    Artifact,
    ArtifactLink,
    Commit,
    Issue,
    PullRequest,
    Repository,
    Resolution,
    Review,
    ReviewFinding,
)


@dataclass(frozen=True)
class EntitySummary:
    title: str | None
    url: str | None
    external_id: str | None


class GraphService:
    TRACE_STAGE_ORDER = [
        "review_request",
        "horizontal_review",
        "review_comment",
        "review_finding",
        "specification_issue",
        "working_group_response",
        "pull_request",
        "commit",
        "changed_section",
        "resolution",
    ]
    TRACE_PREDICATE_ORDER = [
        "HAS_FINDING",
        "RAISED_IN",
        "TRACKED_BY",
        "DISCUSSED_IN",
        "RESPONDS_TO",
        "RESOLVED_BY",
        "IMPLEMENTED_BY",
        "CHANGES",
    ]

    def __init__(self, session: Session) -> None:
        self.session = session

    def links_for_entity(self, entity_type: str, entity_id: str, limit: int = 100) -> list[dict]:
        links = self.session.scalars(
            select(ArtifactLink)
            .where(
                ((ArtifactLink.subject_type == entity_type) & (ArtifactLink.subject_id == entity_id))
                | ((ArtifactLink.object_type == entity_type) & (ArtifactLink.object_id == entity_id))
            )
            .limit(limit)
        ).all()
        return [self.hydrate_link(link) for link in links]

    def links_for_artifact(self, artifact: Artifact, limit: int = 5) -> list[dict]:
        entity_refs = [("artifact", artifact.internal_id)]
        if artifact.source_type == "github_issue" and artifact.external_id:
            issue = self._issue_from_external_id(artifact.external_id)
            if issue is not None:
                entity_refs.append(("issue", issue.internal_id))
        links: list[ArtifactLink] = []
        for entity_type, entity_id in entity_refs:
            links.extend(
                self.session.scalars(
                    select(ArtifactLink)
                    .where(ArtifactLink.subject_type == entity_type, ArtifactLink.subject_id == entity_id)
                    .limit(limit)
                ).all()
            )
        return [self.hydrate_link(link) for link in links[:limit]]

    def hydrate_link(self, link: ArtifactLink) -> dict:
        subject = self._summarize_entity(link.subject_type, link.subject_id)
        target = self._summarize_entity(link.object_type, link.object_id)
        return {
            "subject_type": link.subject_type,
            "subject_id": link.subject_id,
            "predicate": link.predicate,
            "object_type": link.object_type,
            "object_id": link.object_id,
            "confidence": link.confidence,
            "extraction_method": link.extraction_method,
            "supporting_evidence": link.supporting_evidence,
            "is_explicit": link.is_explicit,
            "subject_title": subject.title,
            "subject_url": subject.url,
            "subject_external_id": subject.external_id,
            "object_title": target.title,
            "object_url": target.url,
            "object_external_id": target.external_id,
        }

    def trace_resolution(self, entity_type: str, entity_id: str, max_depth: int = 8) -> dict:
        raw_links = self._links_touching_entity(entity_type, entity_id)
        if not self._entity_exists(entity_type, entity_id) and not raw_links:
            return {
                "start_entity_type": entity_type,
                "start_entity_id": entity_id,
                "status": "not_found",
                "steps": [
                    {
                        "stage": self._stage_for_entity(entity_type),
                        "status": "missing",
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "title": None,
                        "url": None,
                        "external_id": None,
                    }
                ],
                "links": [],
                "missing_stages": self.TRACE_STAGE_ORDER,
                "notes": ["Start entity was not found and no graph links reference it."],
            }

        visited = {(entity_type, entity_id)}
        queue: list[tuple[str, str, int]] = [(entity_type, entity_id, 0)]
        ordered_entities: list[tuple[str, str]] = [(entity_type, entity_id)]
        ordered_links: list[ArtifactLink] = []

        while queue:
            current_type, current_id, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            candidates = self._links_touching_entity(current_type, current_id)
            for link in sorted(candidates, key=self._trace_link_sort_key):
                neighbor = self._neighbor_for_link(link, current_type, current_id)
                if neighbor is None:
                    continue
                if link not in ordered_links:
                    ordered_links.append(link)
                if neighbor not in visited and not neighbor[0].startswith("github_"):
                    visited.add(neighbor)
                    ordered_entities.append(neighbor)
                    queue.append((neighbor[0], neighbor[1], depth + 1))

        steps = sorted(
            [self._trace_step(entity_type, entity_id) for entity_type, entity_id in ordered_entities],
            key=lambda step: self._stage_sort_key(step["stage"]),
        )
        present_stages = {step["stage"] for step in steps}
        missing_stages = [stage for stage in self.TRACE_STAGE_ORDER if stage not in present_stages]
        steps.extend(
            {
                "stage": stage,
                "status": "missing",
                "entity_type": None,
                "entity_id": None,
                "title": None,
                "url": None,
                "external_id": None,
            }
            for stage in missing_stages
        )
        status = "complete" if "resolution" in present_stages and "commit" in present_stages else "partial"
        notes = []
        if missing_stages:
            notes.append("Missing stages were not verified from explicit graph links.")
        if any(not link.is_explicit for link in ordered_links):
            notes.append("One or more links are inferred; inspect each link before treating the trace as authoritative.")
        return {
            "start_entity_type": entity_type,
            "start_entity_id": entity_id,
            "status": status,
            "steps": steps,
            "links": [self.hydrate_link(link) for link in ordered_links],
            "missing_stages": missing_stages,
            "notes": notes,
        }

    def _summarize_entity(self, entity_type: str, entity_id: str) -> EntitySummary:
        if entity_type == "issue":
            issue = self.session.get(Issue, entity_id)
            if issue is None:
                return EntitySummary(None, None, entity_id)
            repository = self.session.get(Repository, issue.repository_id)
            external_id = f"{repository.canonical_full_name}#{issue.number}" if repository else str(issue.number)
            return EntitySummary(issue.title, issue.source_url, external_id)
        if entity_type == "pull_request":
            pr = self.session.get(PullRequest, entity_id)
            if pr is None:
                return EntitySummary(None, None, entity_id)
            repository = self.session.get(Repository, pr.repository_id)
            external_id = f"{repository.canonical_full_name}#{pr.number}" if repository else str(pr.number)
            return EntitySummary(pr.title, pr.source_url, external_id)
        if entity_type == "commit":
            commit = self.session.get(Commit, entity_id)
            if commit is None:
                return EntitySummary(None, None, entity_id)
            repository = self.session.get(Repository, commit.repository_id)
            repo = repository.canonical_full_name if repository else None
            url = f"https://github.com/{repo}/commit/{commit.sha}" if repo else None
            return EntitySummary(commit.message, url, f"{repo}@{commit.sha}" if repo else commit.sha)
        if entity_type == "artifact":
            artifact = self.session.get(Artifact, entity_id)
            if artifact is None:
                return EntitySummary(None, None, entity_id)
            return EntitySummary(artifact.title, artifact.source_url, artifact.external_id)
        if entity_type == "review":
            review = self.session.get(Review, entity_id)
            if review is None:
                return EntitySummary(None, None, entity_id)
            title = f"{review.review_domain} review"
            return EntitySummary(title, None, review.internal_id)
        if entity_type == "review_finding":
            finding = self.session.get(ReviewFinding, entity_id)
            if finding is None:
                return EntitySummary(None, None, entity_id)
            return EntitySummary(finding.summary, None, finding.internal_id)
        if entity_type == "resolution":
            resolution = self.session.get(Resolution, entity_id)
            if resolution is None:
                return EntitySummary(None, None, entity_id)
            return EntitySummary(resolution.outcome, resolution.source_url, resolution.internal_id)
        return EntitySummary(None, None, entity_id)

    def _issue_from_external_id(self, external_id: str) -> Issue | None:
        if "#" not in external_id:
            return None
        repository_ref, number_ref = external_id.rsplit("#", maxsplit=1)
        owner_repo = repository_ref.split("/")
        if len(owner_repo) != 2 or not number_ref.isdigit():
            return None
        repository = self.session.scalar(
            select(Repository).where(Repository.owner == owner_repo[0], Repository.name == owner_repo[1])
        )
        if repository is None:
            return None
        return self.session.scalar(
            select(Issue).where(Issue.repository_id == repository.internal_id, Issue.number == int(number_ref))
        )

    def _links_touching_entity(self, entity_type: str, entity_id: str) -> list[ArtifactLink]:
        return list(
            self.session.scalars(
                select(ArtifactLink).where(
                    ((ArtifactLink.subject_type == entity_type) & (ArtifactLink.subject_id == entity_id))
                    | ((ArtifactLink.object_type == entity_type) & (ArtifactLink.object_id == entity_id))
                )
            ).all()
        )

    def _trace_link_sort_key(self, link: ArtifactLink) -> tuple[int, int, int, str]:
        predicate_rank = (
            self.TRACE_PREDICATE_ORDER.index(link.predicate)
            if link.predicate in self.TRACE_PREDICATE_ORDER
            else len(self.TRACE_PREDICATE_ORDER)
        )
        external_penalty = 1 if link.object_type.startswith("github_") else 0
        inferred_penalty = 0 if link.is_explicit else 1
        return predicate_rank, external_penalty, inferred_penalty, link.created_at.isoformat()

    def _neighbor_for_link(
        self,
        link: ArtifactLink,
        entity_type: str,
        entity_id: str,
    ) -> tuple[str, str] | None:
        if link.subject_type == entity_type and link.subject_id == entity_id:
            return link.object_type, link.object_id
        if link.object_type == entity_type and link.object_id == entity_id:
            return link.subject_type, link.subject_id
        return None

    def _trace_step(self, entity_type: str, entity_id: str) -> dict:
        summary = self._summarize_entity(entity_type, entity_id)
        return {
            "stage": self._stage_for_entity(entity_type),
            "status": "present",
            "entity_type": entity_type,
            "entity_id": entity_id,
            "title": summary.title,
            "url": summary.url,
            "external_id": summary.external_id,
        }

    def _stage_for_entity(self, entity_type: str) -> str:
        return {
            "review_request": "review_request",
            "review": "horizontal_review",
            "review_comment": "review_comment",
            "review_finding": "review_finding",
            "issue": "specification_issue",
            "pull_request": "pull_request",
            "commit": "commit",
            "specification_section": "changed_section",
            "resolution": "resolution",
        }.get(entity_type, entity_type)

    def _stage_sort_key(self, stage: str) -> tuple[int, str]:
        if stage in self.TRACE_STAGE_ORDER:
            return self.TRACE_STAGE_ORDER.index(stage), stage
        return len(self.TRACE_STAGE_ORDER), stage

    def _entity_exists(self, entity_type: str, entity_id: str) -> bool:
        model_by_type = {
            "artifact": Artifact,
            "issue": Issue,
            "pull_request": PullRequest,
            "commit": Commit,
            "review": Review,
            "review_finding": ReviewFinding,
            "resolution": Resolution,
        }
        model = model_by_type.get(entity_type)
        if model is None:
            return bool(self._summarize_entity(entity_type, entity_id).title)
        return self.session.get(model, entity_id) is not None
