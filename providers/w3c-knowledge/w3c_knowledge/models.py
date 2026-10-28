from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from w3c_knowledge.db import Base


def new_id() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(UTC)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now, onupdate=now, nullable=False
    )


class Artifact(Base, TimestampMixin):
    __tablename__ = "artifacts"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    external_id: Mapped[str | None] = mapped_column(String(512), index=True)
    source_type: Mapped[str] = mapped_column(String(64), index=True)
    artifact_type: Mapped[str] = mapped_column(String(64), index=True)
    primary_domain: Mapped[str] = mapped_column(String(64), index=True)
    applicable_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    source_url: Mapped[str | None] = mapped_column(Text)
    canonical_url: Mapped[str | None] = mapped_column(Text, index=True)
    title: Mapped[str] = mapped_column(Text)
    raw_text: Mapped[str | None] = mapped_column(Text)
    normalized_text: Mapped[str | None] = mapped_column(Text)
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)
    retrieved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    content_hash: Mapped[str | None] = mapped_column(String(128), index=True)
    version: Mapped[str | None] = mapped_column(String(128))
    commit_sha: Mapped[str | None] = mapped_column(String(64), index=True)
    provenance: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[float | None] = mapped_column(Float)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    evidence: Mapped[list[SourceEvidence]] = relationship(
        back_populates="artifact", cascade="all, delete-orphan"
    )


class Source(Base, TimestampMixin):
    __tablename__ = "sources"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), index=True)
    url: Mapped[str] = mapped_column(Text)
    canonical_url: Mapped[str | None] = mapped_column(Text)
    organization: Mapped[str | None] = mapped_column(String(128))
    repository: Mapped[str | None] = mapped_column(String(256))
    branch: Mapped[str | None] = mapped_column(String(128))
    document_path: Mapped[str | None] = mapped_column(Text)
    primary_domain: Mapped[str] = mapped_column(String(64), index=True)
    applicable_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    artifact_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    source_priority: Mapped[int] = mapped_column(Integer, default=100)
    sync_strategy: Mapped[str] = mapped_column(String(64), default="incremental")
    parser: Mapped[str | None] = mapped_column(String(128))
    default_labels: Mapped[list[str]] = mapped_column(JSON, default=list)
    allow_redirects: Mapped[bool] = mapped_column(Boolean, default=True)
    historical_versions: Mapped[list[str]] = mapped_column(JSON, default=list)
    authentication_profile: Mapped[str | None] = mapped_column(String(128))
    raw_config: Mapped[dict] = mapped_column(JSON, default=dict)


class Repository(Base, TimestampMixin):
    __tablename__ = "repositories"
    __table_args__ = (UniqueConstraint("owner", "name", name="uq_repository_owner_name"),)

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    owner: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(String(256), index=True)
    original_full_name: Mapped[str | None] = mapped_column(String(512))
    canonical_full_name: Mapped[str] = mapped_column(String(512), index=True)
    html_url: Mapped[str] = mapped_column(Text)
    api_url: Mapped[str | None] = mapped_column(Text)
    default_branch: Mapped[str | None] = mapped_column(String(128))
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)


class WorkingGroup(Base, TimestampMixin):
    __tablename__ = "working_groups"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    external_id: Mapped[str | None] = mapped_column(String(256), index=True)
    name: Mapped[str] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class Specification(Base, TimestampMixin):
    __tablename__ = "specifications"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    shortname: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    title: Mapped[str] = mapped_column(Text)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    responsible_working_group_id: Mapped[str | None] = mapped_column(ForeignKey("working_groups.internal_id"))
    publication_status: Mapped[str | None] = mapped_column(String(128))
    current_published_url: Mapped[str | None] = mapped_column(Text)
    editors_draft_url: Mapped[str | None] = mapped_column(Text)
    source_repository_id: Mapped[str | None] = mapped_column(ForeignKey("repositories.internal_id"))
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    versions: Mapped[list[SpecificationVersion]] = relationship(
        back_populates="specification", cascade="all, delete-orphan"
    )


class SpecificationVersion(Base, TimestampMixin):
    __tablename__ = "specification_versions"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    specification_id: Mapped[str] = mapped_column(ForeignKey("specifications.internal_id"), index=True)
    version: Mapped[str] = mapped_column(String(128), index=True)
    publication_status: Mapped[str | None] = mapped_column(String(128))
    publication_date: Mapped[str | None] = mapped_column(String(64))
    source_url: Mapped[str] = mapped_column(Text)
    canonical_url: Mapped[str | None] = mapped_column(Text)
    source_commit: Mapped[str | None] = mapped_column(String(64))
    content_hash: Mapped[str] = mapped_column(String(128), index=True)
    raw_text: Mapped[str] = mapped_column(Text)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    specification: Mapped[Specification] = relationship(back_populates="versions")
    sections: Mapped[list[SpecificationSection]] = relationship(
        back_populates="specification_version", cascade="all, delete-orphan"
    )


class SpecificationSection(Base, TimestampMixin):
    __tablename__ = "specification_sections"
    __table_args__ = (
        UniqueConstraint("specification_version_id", "anchor", name="uq_section_version_anchor"),
    )

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    specification_version_id: Mapped[str] = mapped_column(
        ForeignKey("specification_versions.internal_id"), index=True
    )
    heading: Mapped[str] = mapped_column(Text)
    anchor: Mapped[str] = mapped_column(String(512), index=True)
    parent_section_id: Mapped[str | None] = mapped_column(ForeignKey("specification_sections.internal_id"))
    heading_level: Mapped[int | None] = mapped_column(Integer)
    display_number: Mapped[str | None] = mapped_column(String(128))
    source_url: Mapped[str | None] = mapped_column(Text)
    raw_text: Mapped[str] = mapped_column(Text)
    normalized_text: Mapped[str] = mapped_column(Text)
    raw_html: Mapped[str | None] = mapped_column(Text)
    section_type: Mapped[str | None] = mapped_column(String(64), index=True)
    order: Mapped[int] = mapped_column(Integer, default=0)
    content_hash: Mapped[str] = mapped_column(String(128), index=True)
    normative: Mapped[bool | None] = mapped_column(Boolean)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    specification_version: Mapped[SpecificationVersion] = relationship(back_populates="sections")


class SpecificationReference(Base, TimestampMixin):
    __tablename__ = "specification_references"
    __table_args__ = (
        UniqueConstraint(
            "specification_version_id",
            "reference_type",
            "label",
            name="uq_spec_reference_version_type_label",
        ),
    )

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    specification_version_id: Mapped[str] = mapped_column(
        ForeignKey("specification_versions.internal_id"), index=True
    )
    reference_type: Mapped[str] = mapped_column(String(32), index=True)
    label: Mapped[str] = mapped_column(String(256), index=True)
    title: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    section_fragment: Mapped[str | None] = mapped_column(String(512))
    source_url: Mapped[str | None] = mapped_column(Text)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class SpecificationIdlBlock(Base, TimestampMixin):
    __tablename__ = "specification_idl_blocks"
    __table_args__ = (
        UniqueConstraint("specification_version_id", "order", name="uq_spec_idl_version_order"),
    )

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    specification_version_id: Mapped[str] = mapped_column(
        ForeignKey("specification_versions.internal_id"), index=True
    )
    section_id: Mapped[str | None] = mapped_column(ForeignKey("specification_sections.internal_id"))
    order: Mapped[int] = mapped_column(Integer)
    fragment: Mapped[str | None] = mapped_column(String(512))
    idl_text: Mapped[str] = mapped_column(Text)
    source_url: Mapped[str | None] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(128), index=True)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class SpecificationConsiderationStatus(Base, TimestampMixin):
    __tablename__ = "specification_consideration_statuses"
    __table_args__ = (
        UniqueConstraint(
            "specification_version_id",
            "consideration_type",
            name="uq_spec_consideration_version_type",
        ),
    )

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    specification_version_id: Mapped[str] = mapped_column(
        ForeignKey("specification_versions.internal_id"), index=True
    )
    consideration_type: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    section_id: Mapped[str | None] = mapped_column(ForeignKey("specification_sections.internal_id"))
    source_url: Mapped[str | None] = mapped_column(Text)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class GuidanceDocument(Base, TimestampMixin):
    __tablename__ = "guidance_documents"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(Text)
    primary_domain: Mapped[str] = mapped_column(String(64), index=True)
    artifact_type: Mapped[str] = mapped_column(String(64), index=True)
    canonical_url: Mapped[str] = mapped_column(Text)
    raw_text: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class GuidanceSection(Base, TimestampMixin):
    __tablename__ = "guidance_sections"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    guidance_document_id: Mapped[str] = mapped_column(ForeignKey("guidance_documents.internal_id"))
    heading: Mapped[str] = mapped_column(Text)
    anchor: Mapped[str | None] = mapped_column(String(512))
    raw_text: Mapped[str] = mapped_column(Text)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class ProcessDocument(Base, TimestampMixin):
    __tablename__ = "process_documents"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(Text)
    edition: Mapped[str | None] = mapped_column(String(128))
    effective_date: Mapped[str | None] = mapped_column(String(64), index=True)
    canonical_url: Mapped[str] = mapped_column(Text)
    retrieved_url: Mapped[str] = mapped_column(Text)
    publication_date: Mapped[str | None] = mapped_column(String(64))
    content_hash: Mapped[str] = mapped_column(String(128))
    retrieval_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    applicable_from: Mapped[str | None] = mapped_column(String(64))
    applicable_to: Mapped[str | None] = mapped_column(String(64))
    supersedes_id: Mapped[str | None] = mapped_column(ForeignKey("process_documents.internal_id"))
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class ReviewRequest(Base, TimestampMixin):
    __tablename__ = "review_requests"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    domain: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(Text)
    source_url: Mapped[str] = mapped_column(Text)
    state: Mapped[str | None] = mapped_column(String(64), index=True)
    requested_snapshot_url: Mapped[str | None] = mapped_column(Text)
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)


class Review(Base, TimestampMixin):
    __tablename__ = "reviews"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    review_request_id: Mapped[str | None] = mapped_column(ForeignKey("review_requests.internal_id"))
    review_domain: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(64), index=True)
    reviewer_group: Mapped[str | None] = mapped_column(String(256))
    target_specification_id: Mapped[str | None] = mapped_column(ForeignKey("specifications.internal_id"))
    reviewed_snapshot_version_id: Mapped[str | None] = mapped_column(ForeignKey("specification_versions.internal_id"))
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class ReviewFinding(Base, TimestampMixin):
    __tablename__ = "review_findings"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    review_id: Mapped[str | None] = mapped_column(ForeignKey("reviews.internal_id"), index=True)
    review_domain: Mapped[str] = mapped_column(String(64), index=True)
    finding_category: Mapped[str | None] = mapped_column(String(128), index=True)
    summary: Mapped[str] = mapped_column(Text)
    original_text: Mapped[str] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(64))
    severity_source: Mapped[str | None] = mapped_column(String(64))
    reviewer: Mapped[str | None] = mapped_column(String(256))
    reviewer_group: Mapped[str | None] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(64), index=True)
    finding_date: Mapped[str | None] = mapped_column(String(64))
    affected_component: Mapped[str | None] = mapped_column(Text)
    affected_section: Mapped[str | None] = mapped_column(Text)
    risk: Mapped[str | None] = mapped_column(Text)
    proposed_mitigation: Mapped[str | None] = mapped_column(Text)
    accepted_mitigation: Mapped[str | None] = mapped_column(Text)
    related_principles: Mapped[list[str]] = mapped_column(JSON, default=list)
    related_guidance: Mapped[list[str]] = mapped_column(JSON, default=list)
    related_issues: Mapped[list[str]] = mapped_column(JSON, default=list)
    related_pull_requests: Mapped[list[str]] = mapped_column(JSON, default=list)
    related_commits: Mapped[list[str]] = mapped_column(JSON, default=list)
    final_outcome: Mapped[str | None] = mapped_column(Text)
    analysis_confidence: Mapped[float | None] = mapped_column(Float)
    analysis_method: Mapped[str | None] = mapped_column(String(128))
    analysis_version: Mapped[str | None] = mapped_column(String(64))


class ReviewComment(Base, TimestampMixin):
    __tablename__ = "review_comments"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    review_id: Mapped[str | None] = mapped_column(ForeignKey("reviews.internal_id"))
    author: Mapped[str | None] = mapped_column(String(256))
    body: Mapped[str] = mapped_column(Text)
    source_url: Mapped[str] = mapped_column(Text)
    created_source_at: Mapped[str | None] = mapped_column(String(64))
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)


class Issue(Base, TimestampMixin):
    __tablename__ = "issues"
    __table_args__ = (UniqueConstraint("repository_id", "number", name="uq_issue_repository_number"),)

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.internal_id"), index=True)
    external_id: Mapped[str | None] = mapped_column(String(256), index=True)
    number: Mapped[int] = mapped_column(Integer, index=True)
    title: Mapped[str] = mapped_column(Text)
    body: Mapped[str | None] = mapped_column(Text)
    author: Mapped[str | None] = mapped_column(String(256))
    state: Mapped[str] = mapped_column(String(64), index=True)
    state_reason: Mapped[str | None] = mapped_column(String(64))
    labels: Mapped[list[str]] = mapped_column(JSON, default=list)
    milestone: Mapped[str | None] = mapped_column(String(256))
    assignees: Mapped[list[str]] = mapped_column(JSON, default=list)
    source_url: Mapped[str] = mapped_column(Text)
    created_source_at: Mapped[str | None] = mapped_column(String(64))
    updated_source_at: Mapped[str | None] = mapped_column(String(64))
    closed_source_at: Mapped[str | None] = mapped_column(String(64))
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)


class PullRequest(Base, TimestampMixin):
    __tablename__ = "pull_requests"
    __table_args__ = (UniqueConstraint("repository_id", "number", name="uq_pr_repository_number"),)

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.internal_id"), index=True)
    number: Mapped[int] = mapped_column(Integer, index=True)
    title: Mapped[str] = mapped_column(Text)
    body: Mapped[str | None] = mapped_column(Text)
    author: Mapped[str | None] = mapped_column(String(256))
    state: Mapped[str] = mapped_column(String(64), index=True)
    merged: Mapped[bool] = mapped_column(Boolean, default=False)
    source_url: Mapped[str] = mapped_column(Text)
    changed_files: Mapped[list[dict]] = mapped_column(JSON, default=list)
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)


class PullRequestReview(Base, TimestampMixin):
    __tablename__ = "pull_request_reviews"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    pull_request_id: Mapped[str] = mapped_column(ForeignKey("pull_requests.internal_id"), index=True)
    reviewer: Mapped[str | None] = mapped_column(String(256))
    state: Mapped[str | None] = mapped_column(String(64))
    body: Mapped[str | None] = mapped_column(Text)
    submitted_at: Mapped[str | None] = mapped_column(String(64))
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)


class Commit(Base, TimestampMixin):
    __tablename__ = "commits"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.internal_id"), index=True)
    sha: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    message: Mapped[str | None] = mapped_column(Text)
    author: Mapped[str | None] = mapped_column(String(256))
    committed_at: Mapped[str | None] = mapped_column(String(64))
    changed_files: Mapped[list[dict]] = mapped_column(JSON, default=list)
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)


class Resolution(Base, TimestampMixin):
    __tablename__ = "resolutions"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("review_findings.internal_id"), index=True)
    outcome: Mapped[str] = mapped_column(Text)
    source_url: Mapped[str | None] = mapped_column(Text)
    implemented_change_id: Mapped[str | None] = mapped_column(String(36))
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(64), default="recorded")


class Principle(Base, TimestampMixin):
    __tablename__ = "principles"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(Text)
    primary_domain: Mapped[str] = mapped_column(String(64), index=True)
    source_url: Mapped[str] = mapped_column(Text)
    raw_text: Mapped[str] = mapped_column(Text)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)


class Topic(Base, TimestampMixin):
    __tablename__ = "topics"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(256), unique=True)
    domain: Mapped[str] = mapped_column(String(64), index=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class ArtifactLink(Base, TimestampMixin):
    __tablename__ = "artifact_links"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    subject_type: Mapped[str] = mapped_column(String(64), index=True)
    subject_id: Mapped[str] = mapped_column(String(36), index=True)
    predicate: Mapped[str] = mapped_column(String(64), index=True)
    object_type: Mapped[str] = mapped_column(String(64), index=True)
    object_id: Mapped[str] = mapped_column(String(512), index=True)
    source: Mapped[str] = mapped_column(Text)
    discovery_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    extraction_method: Mapped[str] = mapped_column(String(128), default="explicit")
    supporting_evidence: Mapped[list[str]] = mapped_column(JSON, default=list)
    is_explicit: Mapped[bool] = mapped_column(Boolean, default=True)


class SourceEvidence(Base, TimestampMixin):
    __tablename__ = "source_evidence"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    artifact_id: Mapped[str | None] = mapped_column(ForeignKey("artifacts.internal_id"), index=True)
    source_url: Mapped[str] = mapped_column(Text)
    canonical_url: Mapped[str | None] = mapped_column(Text)
    source_artifact_id: Mapped[str | None] = mapped_column(String(512))
    fragment: Mapped[str | None] = mapped_column(String(512))
    original_text: Mapped[str] = mapped_column(Text)
    source_position: Mapped[str | None] = mapped_column(String(256))
    retrieval_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    content_hash: Mapped[str | None] = mapped_column(String(128))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    specification_version: Mapped[str | None] = mapped_column(String(128))
    original_author: Mapped[str | None] = mapped_column(String(256))
    original_timestamp: Mapped[str | None] = mapped_column(String(64))

    artifact: Mapped[Artifact | None] = relationship(back_populates="evidence")


class IngestionRun(Base, TimestampMixin):
    __tablename__ = "ingestion_runs"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str | None] = mapped_column(ForeignKey("sources.internal_id"))
    status: Mapped[str] = mapped_column(String(64), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    summary: Mapped[dict] = mapped_column(JSON, default=dict)


class SyncCursor(Base, TimestampMixin):
    __tablename__ = "sync_cursors"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.internal_id"), unique=True)
    cursor_type: Mapped[str] = mapped_column(String(64), default="updated_since")
    cursor_value: Mapped[str | None] = mapped_column(Text)
    etag: Mapped[str | None] = mapped_column(String(256))
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class AnalysisResult(Base, TimestampMixin):
    __tablename__ = "analysis_results"

    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    artifact_type: Mapped[str] = mapped_column(String(64), index=True)
    artifact_id: Mapped[str] = mapped_column(String(36), index=True)
    analyzer: Mapped[str] = mapped_column(String(128))
    analyzer_version: Mapped[str] = mapped_column(String(64))
    method: Mapped[str] = mapped_column(String(128))
    confidence: Mapped[float] = mapped_column(Float)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    manually_verified: Mapped[bool] = mapped_column(Boolean, default=False)
