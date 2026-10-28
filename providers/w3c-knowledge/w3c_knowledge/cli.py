from __future__ import annotations

import json
from pathlib import Path

import typer
from sqlalchemy import select

from w3c_knowledge.adapters.github import GitHubRESTAdapter
from w3c_knowledge.adapters.ietf_datatracker import IETFDatatrackerAdapter
from w3c_knowledge.adapters.rfc_editor import RFCEditorAdapter
from w3c_knowledge.adapters.w3c import W3CAPIAdapter
from w3c_knowledge.config import get_settings
from w3c_knowledge.db import Base, SessionLocal, engine
from w3c_knowledge.ingestion.service import IngestionService
from w3c_knowledge.ingestion.source_config import load_sources
from w3c_knowledge.models import Specification, SpecificationVersion
from w3c_knowledge.parsing.diff import diff_versions
from w3c_knowledge.search.service import SearchService
from w3c_knowledge.security import make_http_client

app = typer.Typer(no_args_is_help=True)


@app.command()
def bootstrap(sources: Path = Path("config/sources.yaml")) -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        run = IngestionService(session).bootstrap_sources(sources)
        typer.echo(json.dumps(run.summary))


@app.command()
def sync() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        run = IngestionService(session).sync()
        typer.echo(json.dumps(run.summary))


@app.command("sync-repository")
def sync_repository(
    repository: str,
    limit: int = typer.Option(25, min=0, max=10000),
    incremental: bool = typer.Option(True, "--incremental/--no-incremental"),
    skip_existing: bool = typer.Option(False, "--skip-existing/--no-skip-existing"),
    sources: Path = Path("config/sources.yaml"),
) -> None:
    Base.metadata.create_all(bind=engine)
    owner, name = repository.split("/", maxsplit=1)
    matching_source = next(
        (
            source
            for source in load_sources(sources)
            if source.organization == owner and source.repository == name
        ),
        None,
    )
    settings = get_settings()
    with make_http_client(settings, settings.github_token) as client:
        adapter = GitHubRESTAdapter(client, settings.github_token)
        with SessionLocal() as session:
            run = IngestionService(session).sync_github_repository(
                adapter,
                owner,
                name,
                limit=limit or None,
                source_config=matching_source,
                incremental=incremental,
                skip_existing=skip_existing,
            )
    typer.echo(json.dumps(run.summary))


@app.command("sync-domain")
def sync_domain(
    domain: str,
    limit_per_repository: int = typer.Option(25, min=0, max=10000),
    incremental: bool = typer.Option(True, "--incremental/--no-incremental"),
    sources: Path = Path("config/sources.yaml"),
) -> None:
    Base.metadata.create_all(bind=engine)
    settings = get_settings()
    with make_http_client(settings, settings.github_token) as client:
        adapter = GitHubRESTAdapter(client, settings.github_token)
        with SessionLocal() as session:
            run = IngestionService(session).sync_github_domain(
                adapter,
                domain,
                load_sources(sources),
                limit_per_repository=limit_per_repository or None,
                incremental=incremental,
            )
    typer.echo(json.dumps(run.summary))


@app.command("sync-repository-documents")
def sync_repository_documents(
    repository: str,
    checkout_path: Path,
    limit: int = typer.Option(0, min=0, max=10000),
    commit_sha: str | None = typer.Option(None, "--commit-sha"),
    sources: Path = Path("config/sources.yaml"),
) -> None:
    Base.metadata.create_all(bind=engine)
    owner, name = repository.split("/", maxsplit=1)
    matching_source = next(
        (
            source
            for source in load_sources(sources)
            if source.organization == owner and source.repository == name
        ),
        None,
    )
    if matching_source is None:
        raise typer.BadParameter("Repository is not configured in sources.yaml")
    with SessionLocal() as session:
        run = IngestionService(session).sync_repository_documents(
            checkout_path,
            matching_source,
            commit_sha=commit_sha,
            limit=limit or None,
        )
    typer.echo(json.dumps(run.summary))


@app.command("backfill-repository-issue-artifacts")
def backfill_repository_issue_artifacts(
    repository: str,
    sources: Path = Path("config/sources.yaml"),
) -> None:
    Base.metadata.create_all(bind=engine)
    owner, name = repository.split("/", maxsplit=1)
    matching_source = next(
        (
            source
            for source in load_sources(sources)
            if source.organization == owner and source.repository == name
        ),
        None,
    )
    if matching_source is None:
        raise typer.BadParameter("Repository is not configured in sources.yaml")
    with SessionLocal() as session:
        run = IngestionService(session).backfill_repository_issue_artifacts(
            owner, name, matching_source
        )
    typer.echo(json.dumps(run.summary))


@app.command("ingest-document")
def ingest_document(
    path: Path, title: str = "Imported document", domain: str = "cross_cutting"
) -> None:
    Base.metadata.create_all(bind=engine)
    text = path.read_text(encoding="utf-8")
    with SessionLocal() as session:
        service = IngestionService(session)
        service.ingest_specification_html(title.lower().replace(" ", "-"), text, path.as_uri())
        typer.echo(json.dumps({"ingested": str(path), "domain": domain}))


@app.command("ingest-specification")
def ingest_specification(path: Path, shortname: str, version: str = "current") -> None:
    Base.metadata.create_all(bind=engine)
    html = path.read_text(encoding="utf-8")
    with SessionLocal() as session:
        service = IngestionService(session)
        spec_version = service.ingest_specification_html(shortname, html, path.as_uri(), version)
        typer.echo(json.dumps({"specification_version": spec_version.internal_id}))


@app.command()
def reindex(rebuild: bool = False) -> None:
    """Index new/changed sections and artifacts with the verified local model."""
    from w3c_knowledge.search.vectors import VectorService
    with SessionLocal() as session:
        typer.echo(json.dumps(VectorService(session).reindex(rebuild=rebuild)))


@app.command("download-embedding-model")
def download_embedding_model() -> None:
    """Explicitly download and verify the pinned public model (approximately 487 MB)."""
    from w3c_knowledge.search.embeddings import download_model
    typer.echo(json.dumps(download_model(get_settings().embedding_model_dir)))


@app.command("index-status")
def index_status() -> None:
    from w3c_knowledge.search.vectors import VectorService
    with SessionLocal() as session:
        typer.echo(json.dumps(VectorService(session).status()))


@app.command("retrieve")
def retrieve(q: str, mode: str = "hybrid", limit: int = 10, specification: str | None = None, version_id: str | None = None) -> None:
    """Search indexed chunks; return provenance and explicit index coverage."""
    from w3c_knowledge.search.vectors import VectorService
    with SessionLocal() as session:
        typer.echo(json.dumps(VectorService(session).search(q, mode=mode, limit=limit, specification=specification, version_id=version_id), ensure_ascii=False))


@app.command("normalize-timeline")
def normalize_timeline(limit: int | None = typer.Option(None, min=1)) -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        run = IngestionService(session).normalize_stored_github_timelines(limit=limit)
        typer.echo(json.dumps(run.summary))


@app.command("materialize-refs")
def materialize_refs(limit: int = typer.Option(50, min=0, max=10000)) -> None:
    Base.metadata.create_all(bind=engine)
    settings = get_settings()
    with make_http_client(settings, settings.github_token) as client:
        adapter = GitHubRESTAdapter(client, settings.github_token)
        with SessionLocal() as session:
            run = IngestionService(session).materialize_external_github_refs(
                adapter, limit=limit or None
            )
    typer.echo(json.dumps(run.summary))


@app.command("normalize-findings")
def normalize_findings(limit: int | None = typer.Option(None, min=1, max=10000)) -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        run = IngestionService(session).normalize_review_findings(limit=limit)
    typer.echo(json.dumps(run.summary))


@app.command("sync-tr")
def sync_tr(
    statuses: str = typer.Option("REC,CR,CRD,WD", help="Comma-separated W3C publication statuses."),
    latest_only: bool = typer.Option(True, "--latest-only/--all-versions"),
    shortname: list[str] | None = typer.Option(None, "--shortname"),
    limit: int | None = typer.Option(None, min=1, max=10000),
    concurrency: int = typer.Option(4, min=1, max=16),
    checkpoint_interval: int = typer.Option(25, "--checkpoint-interval", min=1, max=1000),
    progress: bool = typer.Option(True, "--progress/--no-progress"),
    skip_existing: bool = typer.Option(False, "--skip-existing/--no-skip-existing"),
    force: bool = typer.Option(False, "--force/--no-force"),
    dry_run: bool = typer.Option(False, "--dry-run/--no-dry-run"),
) -> None:
    Base.metadata.create_all(bind=engine)
    settings = get_settings()
    parsed_statuses = [item.strip() for item in statuses.split(",") if item.strip()]
    with make_http_client(settings) as client:
        adapter = W3CAPIAdapter(
            client,
            max_response_bytes=settings.max_response_bytes,
            retry_attempts=settings.w3c_retry_attempts,
            backoff_seconds=settings.w3c_retry_backoff_seconds,
            request_delay_seconds=settings.w3c_request_delay_seconds,
        )
        with SessionLocal() as session:

            def progress_callback(event: dict[str, object]) -> None:
                typer.echo(f"sync-tr progress {json.dumps(event, sort_keys=True)}", err=True)

            run = IngestionService(session).sync_w3c_tr(
                adapter,
                parsed_statuses,
                shortnames=shortname,
                limit=limit,
                latest_only=latest_only,
                concurrency=concurrency,
                force=force,
                dry_run=dry_run,
                checkpoint_interval=checkpoint_interval,
                skip_existing=skip_existing,
                progress_callback=progress_callback if progress else None,
            )
    typer.echo(json.dumps(run.summary, indent=2))


@app.command("sync-whatwg-html")
def sync_whatwg_html(
    url: str = typer.Option("https://html.spec.whatwg.org/"),
    skip_existing: bool = typer.Option(False, "--skip-existing/--no-skip-existing"),
    force: bool = typer.Option(False, "--force/--no-force"),
    dry_run: bool = typer.Option(False, "--dry-run/--no-dry-run"),
) -> None:
    Base.metadata.create_all(bind=engine)
    settings = get_settings()
    with make_http_client(settings) as client:
        adapter = W3CAPIAdapter(
            client,
            max_response_bytes=settings.max_response_bytes,
            retry_attempts=settings.w3c_retry_attempts,
            backoff_seconds=settings.w3c_retry_backoff_seconds,
            request_delay_seconds=settings.w3c_request_delay_seconds,
        )
        with SessionLocal() as session:
            run = IngestionService(session).sync_whatwg_html(
                adapter,
                url=url,
                skip_existing=skip_existing,
                force=force,
                dry_run=dry_run,
            )
    typer.echo(json.dumps(run.summary, indent=2))


@app.command("sync-whatwg-specs")
def sync_whatwg_specs(
    shortname: list[str] | None = typer.Option(None, "--shortname"),
    limit: int | None = typer.Option(None, min=1, max=10000),
    skip_existing: bool = typer.Option(False, "--skip-existing/--no-skip-existing"),
    force: bool = typer.Option(False, "--force/--no-force"),
    dry_run: bool = typer.Option(False, "--dry-run/--no-dry-run"),
    progress: bool = typer.Option(True, "--progress/--no-progress"),
) -> None:
    Base.metadata.create_all(bind=engine)
    settings = get_settings()
    with make_http_client(settings) as client:
        adapter = W3CAPIAdapter(client, max_response_bytes=settings.max_response_bytes)
        with SessionLocal() as session:

            def progress_callback(event: dict[str, object]) -> None:
                typer.echo(
                    f"sync-whatwg-specs progress {json.dumps(event, sort_keys=True)}", err=True
                )

            run = IngestionService(session).sync_whatwg_specs(
                adapter,
                shortnames=shortname,
                limit=limit,
                skip_existing=skip_existing,
                force=force,
                dry_run=dry_run,
                progress_callback=progress_callback if progress else None,
            )
    typer.echo(json.dumps(run.summary, indent=2))


@app.command("sync-rfcs")
def sync_rfcs(
    scope: str = typer.Option(
        "referenced", help="RFC discovery scope: referenced, selected, or all."
    ),
    rfc: list[str] | None = typer.Option(None, "--rfc"),
    mirror_dir: Path | None = typer.Option(None, "--mirror-dir"),
    limit: int | None = typer.Option(None, min=1, max=100000),
    concurrency: int = typer.Option(4, min=1, max=16),
    checkpoint_interval: int = typer.Option(25, "--checkpoint-interval", min=1, max=1000),
    progress: bool = typer.Option(True, "--progress/--no-progress"),
    skip_existing: bool = typer.Option(False, "--skip-existing/--no-skip-existing"),
    force: bool = typer.Option(False, "--force/--no-force"),
    dry_run: bool = typer.Option(False, "--dry-run/--no-dry-run"),
) -> None:
    Base.metadata.create_all(bind=engine)
    settings = get_settings()
    with make_http_client(settings) as client:
        adapter = RFCEditorAdapter(client, max_response_bytes=settings.max_response_bytes)
        with SessionLocal() as session:

            def progress_callback(event: dict[str, object]) -> None:
                typer.echo(f"sync-rfcs progress {json.dumps(event, sort_keys=True)}", err=True)

            run = IngestionService(session).sync_rfcs(
                adapter,
                scope=scope,
                numbers=rfc,
                mirror_dir=mirror_dir,
                limit=limit,
                concurrency=concurrency,
                checkpoint_interval=checkpoint_interval,
                progress_callback=progress_callback if progress else None,
                skip_existing=skip_existing,
                force=force,
                dry_run=dry_run,
            )
    typer.echo(json.dumps(run.summary, indent=2))


@app.command("sync-ietf-secdir-reviews")
def sync_ietf_secdir_reviews(
    limit: int | None = typer.Option(None, min=1, max=100000),
    page_size: int = typer.Option(100, "--page-size", min=1, max=500),
    checkpoint_interval: int = typer.Option(100, "--checkpoint-interval", min=1, max=1000),
    progress: bool = typer.Option(True, "--progress/--no-progress"),
    download_review_pages: bool = typer.Option(
        True, "--download-review-pages/--no-download-review-pages"
    ),
    download_reviewed_documents: bool = typer.Option(
        True, "--download-reviewed-documents/--no-download-reviewed-documents"
    ),
    skip_existing: bool = typer.Option(False, "--skip-existing/--no-skip-existing"),
    force: bool = typer.Option(False, "--force/--no-force"),
    dry_run: bool = typer.Option(False, "--dry-run/--no-dry-run"),
) -> None:
    Base.metadata.create_all(bind=engine)
    settings = get_settings()
    with make_http_client(settings) as client:
        adapter = IETFDatatrackerAdapter(
            client,
            max_response_bytes=settings.max_response_bytes,
            retry_attempts=settings.w3c_retry_attempts,
            backoff_seconds=settings.w3c_retry_backoff_seconds,
        )
        with SessionLocal() as session:

            def progress_callback(event: dict[str, object]) -> None:
                typer.echo(
                    f"sync-ietf-secdir-reviews progress {json.dumps(event, sort_keys=True)}",
                    err=True,
                )

            run = IngestionService(session).sync_ietf_secdir_reviews(
                adapter,
                limit=limit,
                page_size=page_size,
                checkpoint_interval=checkpoint_interval,
                download_review_pages=download_review_pages,
                download_reviewed_documents=download_reviewed_documents,
                skip_existing=skip_existing,
                force=force,
                dry_run=dry_run,
                progress_callback=progress_callback if progress else None,
            )
    typer.echo(json.dumps(run.summary, indent=2))


@app.command("export-spec-source")
def export_spec_source(
    shortname: str,
    format: str = typer.Option("json"),
    section_limit: int | None = typer.Option(None, "--section-limit", min=1, max=10000),
    section_offset: int = typer.Option(0, "--section-offset", min=0),
    include_evidence_ids: bool = typer.Option(
        True, "--include-evidence-ids/--no-include-evidence-ids"
    ),
) -> None:
    if format != "json":
        raise typer.BadParameter("Only json is supported")
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        try:
            packet = IngestionService(session).export_spec_source_packet(
                shortname,
                section_limit=section_limit,
                section_offset=section_offset,
                include_evidence_ids=include_evidence_ids,
            )
        except KeyError as exc:
            raise typer.BadParameter("Unknown specification") from exc
        typer.echo(json.dumps(packet, indent=2, default=str))


@app.command("export-what-are-we-building-source")
def export_what_are_we_building_source(
    shortname: str,
    format: str = typer.Option("json"),
    primary_section_limit: int | None = typer.Option(
        200, "--primary-section-limit", min=1, max=10000
    ),
    primary_section_offset: int = typer.Option(0, "--primary-section-offset", min=0),
    rfc_limit: int = typer.Option(20, "--rfc-limit", min=0, max=200),
    rfc_section_limit: int = typer.Option(20, "--rfc-section-limit", min=0, max=1000),
    include_evidence_ids: bool = typer.Option(
        True, "--include-evidence-ids/--no-include-evidence-ids"
    ),
    include_rfc_section_inventory: bool = typer.Option(
        False,
        "--include-rfc-section-inventory/--no-include-rfc-section-inventory",
    ),
) -> None:
    if format != "json":
        raise typer.BadParameter("Only json is supported")
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        try:
            packet = IngestionService(session).export_what_are_we_building_source_packet(
                shortname,
                primary_section_limit=primary_section_limit,
                primary_section_offset=primary_section_offset,
                rfc_limit=rfc_limit,
                rfc_section_limit=rfc_section_limit,
                include_evidence_ids=include_evidence_ids,
                include_rfc_section_inventory=include_rfc_section_inventory,
            )
        except KeyError as exc:
            raise typer.BadParameter("Unknown specification") from exc
        typer.echo(json.dumps(packet, indent=2, default=str))


@app.command()
def search(q: str, domain: str | None = None) -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        results = SearchService(session).search(q, domain=domain)
        typer.echo(json.dumps([result.model_dump(mode="json") for result in results], indent=2))


@app.command()
def trace(entity_type: str, entity_id: str) -> None:
    typer.echo(
        json.dumps(
            {"entity_type": entity_type, "entity_id": entity_id, "status": "use /api/v1/graph"}
        )
    )


@app.command("diff-spec")
def diff_spec(shortname: str) -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        spec = session.scalar(select(Specification).where(Specification.shortname == shortname))
        if not spec:
            raise typer.BadParameter("Unknown specification")
        versions = session.scalars(
            select(SpecificationVersion).where(
                SpecificationVersion.specification_id == spec.internal_id
            )
        ).all()
        document, sections = diff_versions(
            versions[0] if versions else None, versions[-1] if versions else None
        )
        typer.echo(
            json.dumps({"document_changes": document, "section_changes": sections}, indent=2)
        )


@app.command()
def evaluate() -> None:
    typer.echo(json.dumps({"status": "evaluation fixtures available", "path": "evaluation/"}))
