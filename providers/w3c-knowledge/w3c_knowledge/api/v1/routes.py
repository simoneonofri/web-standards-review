from __future__ import annotations

from pathlib import Path
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from w3c_knowledge.adapters.github import GitHubRESTAdapter
from w3c_knowledge.adapters.rfc_editor import RFCEditorAdapter
from w3c_knowledge.adapters.w3c import W3CAPIAdapter
from w3c_knowledge.config import get_settings
from w3c_knowledge.db import get_session
from w3c_knowledge.graph import GraphService
from w3c_knowledge.ingestion.service import IngestionService
from w3c_knowledge.ingestion.source_config import load_sources
from w3c_knowledge.models import (
    Artifact,
    GuidanceDocument,
    IngestionRun,
    ProcessDocument,
    Repository,
    Review,
    ReviewComment,
    ReviewFinding,
    Source,
    SourceEvidence,
    Specification,
    SpecificationConsiderationStatus,
    SpecificationIdlBlock,
    SpecificationReference,
    SpecificationSection,
    SpecificationVersion,
    WorkingGroup,
)
from w3c_knowledge.parsing.diff import diff_versions
from w3c_knowledge.process_context import ProcessQuestionContextService
from w3c_knowledge.schemas import (
    DiffResponse,
    EvidenceOut,
    FindingOut,
    GraphLinkOut,
    IngestionResponse,
    MaterializeReferencesRequest,
    NormalizeFindingsRequest,
    ProcessQuestionContext,
    RepositoryOut,
    ResolutionTraceResponse,
    ReviewCommentOut,
    ReviewOut,
    SearchResult,
    SourceOut,
    SpecificationConsiderationStatusOut,
    SpecificationDetailOut,
    SpecificationIdlBlockOut,
    SpecificationOut,
    SpecificationReferenceOut,
    SpecificationSectionOut,
    SpecificationVersionOut,
    SpecSourcePacket,
    SyncDomainRequest,
    SyncRepositoryRequest,
    SyncRFCsRequest,
    SyncTRRequest,
    SyncWHATWGHTMLRequest,
    SyncWHATWGSpecsRequest,
    WhatAreWeBuildingSourcePacket,
    WorkingGroupOut,
)
from w3c_knowledge.search.service import SearchService
from w3c_knowledge.security import make_http_client

router = APIRouter(prefix="/api/v1")


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "api_version": get_settings().api_version}


def paginate(session: Session, model, limit: int, offset: int):
    total = session.scalar(select(func.count()).select_from(model)) or 0
    return session.scalars(select(model).offset(offset).limit(limit)).all(), total


def _get_specification_by_id_or_shortname(
    session: Session, identifier: str
) -> Specification | None:
    return session.get(Specification, identifier) or session.scalar(
        select(Specification).where(Specification.shortname == identifier)
    )


def _latest_version(session: Session, specification_id: str) -> SpecificationVersion | None:
    return session.scalar(
        select(SpecificationVersion)
        .where(SpecificationVersion.specification_id == specification_id)
        .order_by(
            SpecificationVersion.publication_date.desc().nullslast(),
            SpecificationVersion.updated_at.desc(),
        )
    )


def _latest_version_for_identifier(
    session: Session, identifier: str
) -> SpecificationVersion | None:
    spec = _get_specification_by_id_or_shortname(session, identifier)
    return _latest_version(session, spec.internal_id) if spec else None


@router.get("/sources", response_model=list[SourceOut])
def list_sources(session: Session = Depends(get_session), limit: int = 100, offset: int = 0):
    items, _ = paginate(session, Source, limit, offset)
    return items


@router.get("/repositories", response_model=list[RepositoryOut])
def list_repositories(session: Session = Depends(get_session), limit: int = 100, offset: int = 0):
    items, _ = paginate(session, Repository, limit, offset)
    return items


@router.get("/working-groups", response_model=list[WorkingGroupOut])
def list_working_groups(session: Session = Depends(get_session), limit: int = 100, offset: int = 0):
    items, _ = paginate(session, WorkingGroup, limit, offset)
    return items


@router.get("/specifications", response_model=list[SpecificationOut])
def list_specifications(
    session: Session = Depends(get_session),
    limit: int = 100,
    offset: int = 0,
    status: str | None = None,
    shortname: str | None = None,
):
    stmt = select(Specification)
    if status:
        stmt = stmt.where(Specification.publication_status == status)
    if shortname:
        stmt = stmt.where(Specification.shortname == shortname)
    return session.scalars(stmt.offset(offset).limit(limit)).all()


@router.get("/specifications/{id}", response_model=SpecificationDetailOut)
def get_specification(id: str, session: Session = Depends(get_session)):
    item = _get_specification_by_id_or_shortname(session, id)
    if item is None:
        raise HTTPException(status_code=404, detail="Specification not found")
    latest = _latest_version(session, item.internal_id)
    considerations: dict[str, str] = {}
    evidence_ids: list[str] = []
    if latest is not None:
        considerations = {
            row.consideration_type: row.status
            for row in session.scalars(
                select(SpecificationConsiderationStatus).where(
                    SpecificationConsiderationStatus.specification_version_id == latest.internal_id
                )
            )
        }
        artifact = session.scalar(
            select(SourceEvidence).where(SourceEvidence.specification_version == latest.version)
        )
        if artifact is not None:
            evidence_ids.append(artifact.internal_id)
    return SpecificationDetailOut(
        internal_id=item.internal_id,
        shortname=item.shortname,
        title=item.title,
        aliases=item.aliases,
        publication_status=item.publication_status,
        current_published_url=item.current_published_url,
        editors_draft_url=item.editors_draft_url,
        latest_version=latest,
        consideration_presence=considerations,
        evidence_ids=evidence_ids,
    )


@router.get("/specifications/{id}/versions", response_model=list[SpecificationVersionOut])
def get_specification_versions(id: str, session: Session = Depends(get_session)):
    spec = _get_specification_by_id_or_shortname(session, id)
    if spec is None:
        raise HTTPException(status_code=404, detail="Specification not found")
    return session.scalars(
        select(SpecificationVersion).where(
            SpecificationVersion.specification_id == spec.internal_id
        )
    ).all()


@router.get("/specifications/{id}/sections", response_model=list[SpecificationSectionOut])
def get_specification_sections(id: str, session: Session = Depends(get_session)):
    spec = _get_specification_by_id_or_shortname(session, id)
    if spec is None:
        raise HTTPException(status_code=404, detail="Specification not found")
    versions = session.scalars(
        select(SpecificationVersion).where(
            SpecificationVersion.specification_id == spec.internal_id
        )
    ).all()
    version_ids = [version.internal_id for version in versions]
    if not version_ids:
        return []
    return session.scalars(
        select(SpecificationSection).where(
            SpecificationSection.specification_version_id.in_(version_ids)
        )
    ).all()


@router.get("/specifications/{id}/latest", response_model=SpecificationVersionOut)
def get_specification_latest(id: str, session: Session = Depends(get_session)):
    spec = _get_specification_by_id_or_shortname(session, id)
    if spec is None:
        raise HTTPException(status_code=404, detail="Specification not found")
    latest = _latest_version(session, spec.internal_id)
    if latest is None:
        raise HTTPException(status_code=404, detail="Specification version not found")
    return latest


@router.get(
    "/specifications/{id}/considerations", response_model=list[SpecificationConsiderationStatusOut]
)
def get_specification_considerations(id: str, session: Session = Depends(get_session)):
    latest = _latest_version_for_identifier(session, id)
    if latest is None:
        raise HTTPException(status_code=404, detail="Specification version not found")
    return session.scalars(
        select(SpecificationConsiderationStatus).where(
            SpecificationConsiderationStatus.specification_version_id == latest.internal_id
        )
    ).all()


@router.get("/specifications/{id}/webidl", response_model=list[SpecificationIdlBlockOut])
def get_specification_webidl(id: str, session: Session = Depends(get_session)):
    latest = _latest_version_for_identifier(session, id)
    if latest is None:
        raise HTTPException(status_code=404, detail="Specification version not found")
    return session.scalars(
        select(SpecificationIdlBlock)
        .where(SpecificationIdlBlock.specification_version_id == latest.internal_id)
        .order_by(SpecificationIdlBlock.order.asc())
    ).all()


@router.get("/specifications/{id}/references", response_model=list[SpecificationReferenceOut])
def get_specification_references(
    id: str,
    reference_type: str | None = None,
    label: str | None = None,
    q: str | None = None,
    url: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
):
    latest = _latest_version_for_identifier(session, id)
    if latest is None:
        raise HTTPException(status_code=404, detail="Specification version not found")
    stmt = select(SpecificationReference).where(
        SpecificationReference.specification_version_id == latest.internal_id
    )
    if reference_type:
        stmt = stmt.where(SpecificationReference.reference_type == reference_type)
    if label:
        stmt = stmt.where(SpecificationReference.label == label)
    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(
            SpecificationReference.label.ilike(pattern)
            | SpecificationReference.title.ilike(pattern)
        )
    if url:
        stmt = stmt.where(SpecificationReference.url.ilike(f"%{url}%"))
    return session.scalars(
        stmt.order_by(SpecificationReference.label.asc()).offset(offset).limit(limit)
    ).all()


@router.get("/specifications/{id}/source-packet", response_model=SpecSourcePacket)
def export_specification_source_packet(
    id: str,
    section_limit: int | None = Query(default=None, ge=1, le=10000),
    section_offset: int = Query(default=0, ge=0),
    include_evidence_ids: bool = True,
    session: Session = Depends(get_session),
):
    spec = _get_specification_by_id_or_shortname(session, id)
    if spec is None:
        raise HTTPException(status_code=404, detail="Specification not found")
    try:
        return IngestionService(session).export_spec_source_packet(
            spec.shortname,
            section_limit=section_limit,
            section_offset=section_offset,
            include_evidence_ids=include_evidence_ids,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404, detail="Specification source packet not found"
        ) from exc


@router.get(
    "/specifications/{id}/what-are-we-building-source-packet",
    response_model=WhatAreWeBuildingSourcePacket,
)
def export_what_are_we_building_source_packet(
    id: str,
    primary_section_limit: int | None = Query(default=200, ge=1, le=10000),
    primary_section_offset: int = Query(default=0, ge=0),
    rfc_limit: int = Query(default=20, ge=0, le=200),
    rfc_section_limit: int = Query(default=20, ge=0, le=1000),
    include_evidence_ids: bool = True,
    include_rfc_section_inventory: bool = False,
    session: Session = Depends(get_session),
):
    spec = _get_specification_by_id_or_shortname(session, id)
    if spec is None:
        raise HTTPException(status_code=404, detail="Specification not found")
    try:
        return IngestionService(session).export_what_are_we_building_source_packet(
            spec.shortname,
            primary_section_limit=primary_section_limit,
            primary_section_offset=primary_section_offset,
            rfc_limit=rfc_limit,
            rfc_section_limit=rfc_section_limit,
            include_evidence_ids=include_evidence_ids,
            include_rfc_section_inventory=include_rfc_section_inventory,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404, detail="Specification source packet not found"
        ) from exc


@router.get("/reviews", response_model=list[ReviewOut])
def list_reviews(session: Session = Depends(get_session), domain: str | None = None):
    stmt = select(Review)
    if domain:
        stmt = stmt.where(Review.review_domain == domain)
    return session.scalars(stmt).all()


@router.get("/reviews/{id}", response_model=ReviewOut)
def get_review(id: str, session: Session = Depends(get_session)):
    item = session.get(Review, id)
    if item is None:
        raise HTTPException(status_code=404, detail="Review not found")
    return item


@router.get("/reviews/{id}/comments", response_model=list[ReviewCommentOut])
def get_review_comments(
    id: str,
    session: Session = Depends(get_session),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    review = session.get(Review, id)
    if review is None:
        raise HTTPException(status_code=404, detail="Review not found")
    return session.scalars(
        select(ReviewComment)
        .where(ReviewComment.review_id == id)
        .order_by(ReviewComment.created_source_at.asc().nullslast(), ReviewComment.created_at.asc())
        .offset(offset)
        .limit(limit)
    ).all()


@router.get("/findings", response_model=list[FindingOut])
def list_findings(session: Session = Depends(get_session), domain: str | None = None):
    stmt = select(ReviewFinding)
    if domain:
        stmt = stmt.where(ReviewFinding.review_domain == domain)
    return session.scalars(stmt).all()


@router.get("/findings/{id}", response_model=FindingOut)
def get_finding(id: str, session: Session = Depends(get_session)):
    item = session.get(ReviewFinding, id)
    if item is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return item


@router.get("/guidance")
def list_guidance(session: Session = Depends(get_session), domain: str | None = None):
    stmt = select(GuidanceDocument)
    if domain:
        stmt = stmt.where(GuidanceDocument.primary_domain == domain)
    return session.scalars(stmt).all()


@router.get("/process")
def list_process_documents(session: Session = Depends(get_session)):
    return session.scalars(select(ProcessDocument)).all()


@router.get("/process/question-context", response_model=ProcessQuestionContext)
def process_question_context(
    q: str = "",
    limit: int = Query(default=10, ge=1, le=50),
    session: Session = Depends(get_session),
):
    return ProcessQuestionContextService(session).context(q, limit=limit)


@router.get("/search", response_model=list[SearchResult])
def search(
    q: str = "",
    domain: str | None = None,
    artifact_type: str | None = None,
    specification: str | None = None,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
):
    return SearchService(session).search(
        q,
        domain=domain,
        artifact_type=artifact_type,
        specification=specification,
        limit=limit,
        offset=offset,
    )


@router.get("/precedents", response_model=list[SearchResult])
def precedents(q: str, domain: str | None = None, session: Session = Depends(get_session)):
    return SearchService(session).search(q, domain=domain, artifact_type="review_finding", limit=20)


def _vector_service(session):
    try:
        from w3c_knowledge.search.vectors import VectorService
        return VectorService(session)
    except ImportError as exc:
        raise HTTPException(503, "Install W3C Knowledge with [vectors] and run migrations") from exc


@router.get("/retrieval/status")
def retrieval_status(session: Session = Depends(get_session)):
    return _vector_service(session).status()


@router.get("/retrieval/search")
def retrieval_search(
    q: str = Query(min_length=1, max_length=4000),
    mode: Literal["lexical", "vector", "hybrid"] = "hybrid",
    kind: Literal["section", "artifact"] | None = None,
    specification: str | None = None,
    version_id: str | None = None,
    domain: str | None = None,
    limit: int = Query(default=10, ge=1, le=100),
    session: Session = Depends(get_session),
):
    from w3c_knowledge.search.embeddings import EmbeddingUnavailable
    try:
        return _vector_service(session).search(q, mode=mode, limit=limit, kind=kind, specification=specification, version_id=version_id, domain=domain)
    except EmbeddingUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/graph/{entity_type}/{entity_id}", response_model=list[GraphLinkOut])
def graph(entity_type: str, entity_id: str, session: Session = Depends(get_session)):
    return GraphService(session).links_for_entity(entity_type, entity_id)


@router.get("/trace/resolution/{entity_type}/{entity_id}", response_model=ResolutionTraceResponse)
def trace_resolution(
    entity_type: str,
    entity_id: str,
    max_depth: int = Query(default=8, ge=1, le=20),
    session: Session = Depends(get_session),
):
    return GraphService(session).trace_resolution(entity_type, entity_id, max_depth=max_depth)


@router.get("/diff/specifications/{specification_id}", response_model=DiffResponse)
def diff_specification(
    specification_id: str,
    from_version: str | None = None,
    to_version: str | None = None,
    session: Session = Depends(get_session),
):
    versions = session.scalars(
        select(SpecificationVersion).where(
            SpecificationVersion.specification_id == specification_id
        )
    ).all()
    if len(versions) < 2 and not (from_version and to_version):
        return DiffResponse(
            specification_id=specification_id,
            from_version=None,
            to_version=versions[0].version if versions else None,
            document_changes=[],
            section_changes=[],
            evidence_ids=[],
        )
    old = next((version for version in versions if version.version == from_version), versions[0])
    new = next((version for version in versions if version.version == to_version), versions[-1])
    document_changes, section_changes = diff_versions(old, new)
    return DiffResponse(
        specification_id=specification_id,
        from_version=old.version,
        to_version=new.version,
        document_changes=document_changes,
        section_changes=section_changes,
        evidence_ids=[],
    )


@router.get("/evidence/{evidence_id}", response_model=EvidenceOut)
def get_evidence(evidence_id: str, session: Session = Depends(get_session)):
    item = session.get(SourceEvidence, evidence_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return item


@router.post("/ingestion/bootstrap", response_model=IngestionResponse)
def bootstrap(session: Session = Depends(get_session)):
    path = Path("config/sources.yaml")
    run = IngestionService(session).bootstrap_sources(path)
    return IngestionResponse(run_id=run.internal_id, status=run.status, summary=run.summary)


@router.post("/ingestion/sync", response_model=IngestionResponse)
def sync(session: Session = Depends(get_session)):
    run = IngestionService(session).sync()
    return IngestionResponse(run_id=run.internal_id, status=run.status, summary=run.summary)


@router.post("/ingestion/sync-repository", response_model=IngestionResponse)
def sync_repository(request: SyncRepositoryRequest, session: Session = Depends(get_session)):
    owner, name = request.repository.split("/", maxsplit=1)
    matching_source = next(
        (
            source
            for source in load_sources(Path("config/sources.yaml"))
            if source.organization == owner and source.repository == name
        ),
        None,
    )
    settings = get_settings()
    try:
        with make_http_client(settings, settings.github_token) as client:
            adapter = GitHubRESTAdapter(client, settings.github_token)
            run = IngestionService(session).sync_github_repository(
                adapter,
                owner,
                name,
                limit=request.limit or None,
                source_config=matching_source,
                incremental=request.incremental,
            )
    except httpx.HTTPStatusError as exc:
        status_code = 429 if exc.response.status_code == 403 else exc.response.status_code
        raise HTTPException(
            status_code=status_code,
            detail={
                "message": "GitHub request failed during repository sync",
                "github_status_code": exc.response.status_code,
                "url": str(exc.request.url),
            },
        ) from exc
    return IngestionResponse(run_id=run.internal_id, status=run.status, summary=run.summary)


@router.post("/ingestion/sync-domain", response_model=IngestionResponse)
def sync_domain(request: SyncDomainRequest, session: Session = Depends(get_session)):
    settings = get_settings()
    try:
        with make_http_client(settings, settings.github_token) as client:
            adapter = GitHubRESTAdapter(client, settings.github_token)
            run = IngestionService(session).sync_github_domain(
                adapter,
                request.domain,
                load_sources(Path("config/sources.yaml")),
                limit_per_repository=request.limit_per_repository or None,
                incremental=request.incremental,
            )
    except httpx.HTTPStatusError as exc:
        status_code = 429 if exc.response.status_code == 403 else exc.response.status_code
        raise HTTPException(
            status_code=status_code,
            detail={
                "message": "GitHub request failed during domain sync",
                "github_status_code": exc.response.status_code,
                "url": str(exc.request.url),
            },
        ) from exc
    return IngestionResponse(run_id=run.internal_id, status=run.status, summary=run.summary)


@router.post("/ingestion/sync-tr", response_model=IngestionResponse)
def sync_tr(request: SyncTRRequest, session: Session = Depends(get_session)):
    settings = get_settings()
    with make_http_client(settings) as client:
        adapter = W3CAPIAdapter(
            client,
            max_response_bytes=settings.max_response_bytes,
            retry_attempts=settings.w3c_retry_attempts,
            backoff_seconds=settings.w3c_retry_backoff_seconds,
            request_delay_seconds=settings.w3c_request_delay_seconds,
        )
        run = IngestionService(session).sync_w3c_tr(
            adapter,
            request.statuses,
            shortnames=request.shortnames or None,
            limit=request.limit,
            latest_only=request.latest_only,
            force=request.force,
            dry_run=request.dry_run,
            concurrency=request.concurrency,
            skip_existing=request.skip_existing,
        )
    return IngestionResponse(run_id=run.internal_id, status=run.status, summary=run.summary)


@router.post("/ingestion/sync-whatwg-html", response_model=IngestionResponse)
def sync_whatwg_html(request: SyncWHATWGHTMLRequest, session: Session = Depends(get_session)):
    settings = get_settings()
    with make_http_client(settings) as client:
        adapter = W3CAPIAdapter(
            client,
            max_response_bytes=settings.max_response_bytes,
            retry_attempts=settings.w3c_retry_attempts,
            backoff_seconds=settings.w3c_retry_backoff_seconds,
            request_delay_seconds=settings.w3c_request_delay_seconds,
        )
        run = IngestionService(session).sync_whatwg_html(
            adapter,
            url=request.url,
            force=request.force,
            dry_run=request.dry_run,
            skip_existing=request.skip_existing,
        )
    return IngestionResponse(run_id=run.internal_id, status=run.status, summary=run.summary)


@router.post("/ingestion/sync-whatwg-specs", response_model=IngestionResponse)
def sync_whatwg_specs(request: SyncWHATWGSpecsRequest, session: Session = Depends(get_session)):
    settings = get_settings()
    with make_http_client(settings) as client:
        adapter = W3CAPIAdapter(
            client,
            max_response_bytes=settings.max_response_bytes,
            retry_attempts=settings.w3c_retry_attempts,
            backoff_seconds=settings.w3c_retry_backoff_seconds,
            request_delay_seconds=settings.w3c_request_delay_seconds,
        )
        run = IngestionService(session).sync_whatwg_specs(
            adapter,
            shortnames=request.shortnames or None,
            limit=request.limit,
            force=request.force,
            dry_run=request.dry_run,
            skip_existing=request.skip_existing,
        )
    return IngestionResponse(run_id=run.internal_id, status=run.status, summary=run.summary)


@router.post("/ingestion/sync-rfcs", response_model=IngestionResponse)
def sync_rfcs(request: SyncRFCsRequest, session: Session = Depends(get_session)):
    settings = get_settings()
    mirror_dir: Path | None = None
    if request.scope == "all":
        if not request.mirror_dir:
            raise HTTPException(status_code=400, detail="scope=all requires mirror_dir")
        root = Path(settings.rfc_mirror_root).resolve()
        candidate = Path(request.mirror_dir).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"mirror_dir must be under configured RFC mirror root: {root}",
            ) from exc
        if not candidate.is_dir():
            raise HTTPException(status_code=400, detail="mirror_dir is not a directory")
        mirror_dir = candidate
    elif request.mirror_dir:
        raise HTTPException(status_code=400, detail="mirror_dir is only accepted with scope=all")
    with make_http_client(settings) as client:
        adapter = RFCEditorAdapter(client, max_response_bytes=settings.max_response_bytes)
        run = IngestionService(session).sync_rfcs(
            adapter,
            scope=request.scope,
            numbers=request.rfcs,
            mirror_dir=mirror_dir,
            limit=request.limit,
            concurrency=request.concurrency,
            force=request.force,
            dry_run=request.dry_run,
            skip_existing=request.skip_existing,
        )
    return IngestionResponse(run_id=run.internal_id, status=run.status, summary=run.summary)


@router.get("/ingestion/tr-status")
def tr_bootstrap_status(session: Session = Depends(get_session)):
    artifact_counts: dict[str, int] = {
        source_type: count
        for source_type, count in session.execute(
            select(Artifact.source_type, func.count())
            .where(Artifact.artifact_type == "specification_snapshot")
            .group_by(Artifact.source_type)
        )
    }
    status_counts: dict[str, int] = {
        status or "unknown": count
        for status, count in session.execute(
            select(SpecificationVersion.publication_status, func.count()).group_by(
                SpecificationVersion.publication_status
            )
        )
    }
    last_runs = [
        {
            "run_id": run.internal_id,
            "status": run.status,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "operation": (run.summary or {}).get("operation"),
            "summary": run.summary,
        }
        for run in session.scalars(
            select(IngestionRun).order_by(IngestionRun.started_at.desc()).limit(10)
        ).all()
        if (run.summary or {}).get("operation") in {"sync_w3c_tr", "sync_whatwg_html"}
    ]
    return {
        "specifications": session.scalar(select(func.count()).select_from(Specification)) or 0,
        "versions": session.scalar(select(func.count()).select_from(SpecificationVersion)) or 0,
        "sections": session.scalar(select(func.count()).select_from(SpecificationSection)) or 0,
        "webidl_blocks": session.scalar(select(func.count()).select_from(SpecificationIdlBlock))
        or 0,
        "references": session.scalar(select(func.count()).select_from(SpecificationReference)) or 0,
        "snapshots_by_source_type": artifact_counts,
        "versions_by_status": status_counts,
        "last_runs": last_runs,
    }


@router.get("/ingestion/rfc-status")
def rfc_status(session: Session = Depends(get_session)):
    rfc_versions = session.scalars(
        select(SpecificationVersion)
        .join(Specification, SpecificationVersion.specification_id == Specification.internal_id)
        .where(Specification.shortname.like("rfc%"))
    ).all()
    version_ids = [version.internal_id for version in rfc_versions]
    format_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    metadata_only = 0
    with_content = 0
    for version in rfc_versions:
        metadata = version.metadata_ or {}
        content_format = metadata.get("content_format") or "unknown"
        format_counts[content_format] = format_counts.get(content_format, 0) + 1
        status = metadata.get("status") or version.publication_status or "unknown"
        status_counts[status] = status_counts.get(status, 0) + 1
        if content_format == "metadata-only":
            metadata_only += 1
        else:
            with_content += 1
    sections = 0
    references = 0
    if version_ids:
        sections = (
            session.scalar(
                select(func.count())
                .select_from(SpecificationSection)
                .where(SpecificationSection.specification_version_id.in_(version_ids))
            )
            or 0
        )
        references = (
            session.scalar(
                select(func.count())
                .select_from(SpecificationReference)
                .where(SpecificationReference.specification_version_id.in_(version_ids))
            )
            or 0
        )
    last_runs = [
        {
            "run_id": run.internal_id,
            "status": run.status,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "summary": run.summary,
        }
        for run in session.scalars(
            select(IngestionRun).order_by(IngestionRun.started_at.desc()).limit(10)
        ).all()
        if (run.summary or {}).get("operation") == "sync_rfcs"
    ]
    return {
        "rfcs": len(rfc_versions),
        "with_content": with_content,
        "metadata_only": metadata_only,
        "sections": sections,
        "references": references,
        "by_status": status_counts,
        "by_format": format_counts,
        "last_runs": last_runs,
    }


@router.post("/ingestion/reindex", response_model=IngestionResponse)
def reindex(session: Session = Depends(get_session)):
    return IngestionResponse(run_id="manual", status="completed", summary={"reindexed": True})


@router.post("/analysis/reanalyze", response_model=IngestionResponse)
def reanalyze(session: Session = Depends(get_session)):
    run = IngestionService(session).normalize_stored_github_timelines()
    return IngestionResponse(run_id=run.internal_id, status=run.status, summary=run.summary)


@router.post("/analysis/materialize-references", response_model=IngestionResponse)
def materialize_references(
    request: MaterializeReferencesRequest, session: Session = Depends(get_session)
):
    settings = get_settings()
    with make_http_client(settings, settings.github_token) as client:
        adapter = GitHubRESTAdapter(client, settings.github_token)
        run = IngestionService(session).materialize_external_github_refs(
            adapter, limit=request.limit or None
        )
    return IngestionResponse(run_id=run.internal_id, status=run.status, summary=run.summary)


@router.post("/analysis/normalize-findings", response_model=IngestionResponse)
def normalize_findings(request: NormalizeFindingsRequest, session: Session = Depends(get_session)):
    run = IngestionService(session).normalize_review_findings(limit=request.limit)
    return IngestionResponse(run_id=run.internal_id, status=run.status, summary=run.summary)
