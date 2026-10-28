from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Domain = Literal[
    "design",
    "privacy",
    "security",
    "accessibility",
    "internationalization",
    "ethics",
    "cross_cutting",
]


class EvidenceRef(BaseModel):
    evidence_id: str
    source_url: str
    source_title: str | None = None
    source_type: str | None = None
    date: str | None = None
    confidence: float | None = None
    explicit: bool = True


class Page(BaseModel):
    items: list[Any]
    limit: int
    offset: int
    total: int


class SourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    internal_id: str
    name: str
    source_type: str
    url: str
    canonical_url: str | None
    primary_domain: str
    applicable_domains: list[str]
    artifact_types: list[str]
    enabled: bool


class RepositoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    internal_id: str
    canonical_full_name: str
    original_full_name: str | None
    html_url: str
    archived: bool


class WorkingGroupOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    internal_id: str
    name: str
    url: str | None


class SpecificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    internal_id: str
    shortname: str
    title: str
    aliases: list[str]
    publication_status: str | None
    current_published_url: str | None
    editors_draft_url: str | None


class SpecificationVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    internal_id: str
    specification_id: str
    version: str
    publication_status: str | None
    publication_date: str | None
    source_url: str
    canonical_url: str | None
    source_commit: str | None
    content_hash: str


class SpecificationDetailOut(SpecificationOut):
    latest_version: SpecificationVersionOut | None = None
    consideration_presence: dict[str, str] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)


class SpecificationSectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    internal_id: str
    specification_version_id: str
    heading: str
    anchor: str
    parent_section_id: str | None = None
    heading_level: int | None = None
    display_number: str | None = None
    source_url: str | None = None
    raw_text: str
    section_type: str | None
    content_hash: str
    normative: bool | None
    evidence_ids: list[str] = Field(default_factory=list)


class SpecificationReferenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    internal_id: str
    specification_version_id: str
    reference_type: str
    label: str
    title: str | None
    url: str | None
    section_fragment: str | None
    source_url: str | None
    evidence_ids: list[str] = Field(default_factory=list)


class SpecificationIdlBlockOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    internal_id: str
    specification_version_id: str
    section_id: str | None
    order: int
    fragment: str | None
    idl_text: str
    source_url: str | None
    content_hash: str
    evidence_ids: list[str] = Field(default_factory=list)


class SpecificationConsiderationStatusOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    consideration_type: str
    status: str
    section_id: str | None
    source_url: str | None
    evidence_ids: list[str] = Field(default_factory=list)


class SyncTRRequest(BaseModel):
    statuses: list[str] = Field(default_factory=lambda: ["REC", "CR", "CRD", "WD"])
    latest_only: bool = True
    shortnames: list[str] = Field(default_factory=list)
    limit: int | None = Field(default=None, ge=1, le=10000)
    concurrency: int = Field(default=4, ge=1, le=16)
    force: bool = False
    dry_run: bool = False
    skip_existing: bool = False


class SyncWHATWGHTMLRequest(BaseModel):
    url: str = "https://html.spec.whatwg.org/"
    force: bool = False
    dry_run: bool = False
    skip_existing: bool = False


class SyncWHATWGSpecsRequest(BaseModel):
    shortnames: list[str] = Field(default_factory=list)
    limit: int | None = Field(default=None, ge=1, le=10000)
    force: bool = False
    dry_run: bool = False
    skip_existing: bool = False


class SyncRFCsRequest(BaseModel):
    scope: Literal["referenced", "selected", "all"] = "referenced"
    rfcs: list[str] = Field(default_factory=list)
    mirror_dir: str | None = None
    limit: int | None = Field(default=None, ge=1, le=100000)
    concurrency: int = Field(default=4, ge=1, le=16)
    skip_existing: bool = False
    force: bool = False
    dry_run: bool = False


class SpecSourceSection(BaseModel):
    section_id: str
    order: int
    parent_section_id: str | None
    heading_level: int | None
    display_number: str | None
    heading: str
    fragment: str
    source_url: str | None
    section_type: str | None = None
    normative: bool | None = None
    text: str
    content_hash: str
    evidence_ids: list[str]


class SpecSnapshotIdentity(BaseModel):
    requested_shortname: str
    normalized_status: str | None
    raw_status: str | None
    publication_date: str | None
    latest_url: str | None
    immutable_url: str | None
    canonical_url: str | None
    content_hash: str


class SpecSourcePacket(BaseModel):
    source_packet_contract_version: int = 1
    specification_id: str
    specification_version_id: str
    source_type: Literal["w3c_tr", "whatwg_html", "whatwg_spec", "rfc_editor", "other"]
    shortname: str
    title: str
    status: str | None
    raw_status: str | None
    publication_date: str | None
    latest_tr_url: str | None
    immutable_publication_url: str | None
    editors_draft_url: str | None
    source_repository_url: str | None
    section_inventory: list[dict[str, Any]]
    export_metadata: dict[str, Any] = Field(default_factory=dict)
    sections: list[SpecSourceSection]
    consideration_presence: dict[str, str]
    considerations: list[SpecificationConsiderationStatusOut] = Field(default_factory=list)
    snapshot_identity: SpecSnapshotIdentity
    webidl_blocks: list[SpecificationIdlBlockOut]
    normative_references: list[SpecificationReferenceOut]
    informative_references: list[SpecificationReferenceOut]
    unknown_references: list[SpecificationReferenceOut]
    source_evidence_ids: list[str]
    retrieval_timestamp: str | None
    content_hashes: dict[str, str]


class ThreatModelUsageGuidance(BaseModel):
    as_is_model_role: Literal["documentary_baseline"]
    as_is_model_instructions: list[str]
    full_model_role: Literal["independent_security_privacy_harms_elicitation"]
    full_model_instructions: list[str]
    separation_requirements: list[str]
    reconciliation_instructions: list[str]


class WhatAreWeBuildingSourcePacket(BaseModel):
    what_are_we_building_source_packet_version: int = 1
    threat_model_contract_version: int = 2
    purpose: Literal["evidence_capture_for_what_are_we_building"]
    non_goals: list[str]
    threat_model_usage: ThreatModelUsageGuidance
    primary_specification: SpecSourcePacket
    cited_rfc_inventory: list[dict[str, Any]]
    cited_rfc_packets: list[dict[str, Any]]
    unavailable_or_omitted_rfc_references: list[dict[str, Any]]
    export_metadata: dict[str, Any]
    handoff_notes: list[str]


class ReviewOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    internal_id: str
    review_domain: str
    status: str
    reviewer_group: str | None
    target_specification_id: str | None
    reviewed_snapshot_version_id: str | None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    internal_id: str
    review_id: str | None
    review_domain: str
    finding_category: str | None
    summary: str
    original_text: str
    severity: str | None
    severity_source: str | None
    status: str
    affected_section: str | None
    final_outcome: str | None
    analysis_confidence: float | None
    analysis_method: str | None
    evidence: list[EvidenceRef] = Field(default_factory=list)


class ReviewCommentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    internal_id: str
    review_id: str | None
    author: str | None
    body: str
    source_url: str
    created_source_at: str | None


class GraphLinkOut(BaseModel):
    subject_type: str
    subject_id: str
    predicate: str
    object_type: str
    object_id: str
    confidence: float
    extraction_method: str
    supporting_evidence: list[str]
    is_explicit: bool
    subject_title: str | None = None
    subject_url: str | None = None
    subject_external_id: str | None = None
    object_title: str | None = None
    object_url: str | None = None
    object_external_id: str | None = None


class SearchResult(BaseModel):
    title: str
    snippet: str
    artifact_type: str
    primary_domain: str
    applicable_domains: list[str]
    source_url: str | None
    canonical_url: str | None
    date: datetime | None
    specification_version_or_commit: str | None
    primary_relationships: list[str]
    relationship_links: list[GraphLinkOut] = Field(default_factory=list)
    retrieval_score: float
    analysis_confidence: float | None
    evidence_ids: list[str]


class ProcessQuestionContextItem(BaseModel):
    title: str
    snippet: str
    source_kind: Literal["process", "guidebook"]
    artifact_type: str
    source_url: str | None
    canonical_url: str | None
    date: datetime | None
    specification_version_or_commit: str | None
    evidence_ids: list[str] = Field(default_factory=list)


class TransitionRequestContextItem(BaseModel):
    title: str
    snippet: str
    source_url: str | None
    state: str | None = None
    labels: list[str] = Field(default_factory=list)
    issue_number: int | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class ProcessQuestionContext(BaseModel):
    query: str
    process_requirements: list[ProcessQuestionContextItem]
    guidebook_guidance: list[ProcessQuestionContextItem]
    transition_requests: list[TransitionRequestContextItem]
    notes: list[str]


class TraceStep(BaseModel):
    stage: str
    status: Literal["present", "missing"]
    entity_type: str | None = None
    entity_id: str | None = None
    title: str | None = None
    url: str | None = None
    external_id: str | None = None


class ResolutionTraceResponse(BaseModel):
    start_entity_type: str
    start_entity_id: str
    status: Literal["complete", "partial", "not_found"]
    steps: list[TraceStep]
    links: list[GraphLinkOut]
    missing_stages: list[str]
    notes: list[str]


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    internal_id: str
    source_url: str
    canonical_url: str | None
    source_artifact_id: str | None
    fragment: str | None
    original_text: str
    retrieval_date: datetime
    content_hash: str | None
    commit_sha: str | None
    specification_version: str | None
    original_author: str | None
    original_timestamp: str | None


class IngestionResponse(BaseModel):
    run_id: str
    status: str
    summary: dict[str, Any]


class SyncRepositoryRequest(BaseModel):
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    limit: int = Field(default=25, ge=0, le=10000)
    incremental: bool = True


class SyncDomainRequest(BaseModel):
    domain: Domain
    limit_per_repository: int = Field(default=25, ge=0, le=10000)
    incremental: bool = True


class MaterializeReferencesRequest(BaseModel):
    limit: int = Field(default=50, ge=0, le=10000)


class NormalizeFindingsRequest(BaseModel):
    limit: int | None = Field(default=None, ge=1, le=10000)


class DiffResponse(BaseModel):
    specification_id: str
    from_version: str | None
    to_version: str | None
    document_changes: list[str]
    section_changes: list[dict[str, Any]]
    evidence_ids: list[str]
