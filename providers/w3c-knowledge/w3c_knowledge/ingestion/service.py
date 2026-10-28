from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from w3c_knowledge.adapters.github import parse_issue_payload
from w3c_knowledge.adapters.ietf_datatracker import (
    DownloadedIETFDocument,
    IETFDatatrackerAdapter,
    IETFDatatrackerError,
    ParsedIETFReviewPage,
    display_result,
    document_name_from_resource,
    normalize_result,
    normalize_review_type,
    normalize_state,
)
from w3c_knowledge.adapters.rfc_editor import (
    DownloadedRFCDocument,
    DownloadedRFCMetadata,
    RFCEditorAdapter,
    RFCEditorError,
    RFCMetadata,
)
from w3c_knowledge.adapters.w3c import (
    W3CAPIAdapter,
    W3CDownloadError,
    W3CLatestVersion,
    W3CSpecificationMetadata,
)
from w3c_knowledge.ingestion.source_config import SourceConfig, load_sources, source_to_model_kwargs
from w3c_knowledge.models import (
    Artifact,
    ArtifactLink,
    Commit,
    GuidanceDocument,
    GuidanceSection,
    IngestionRun,
    Issue,
    ProcessDocument,
    PullRequest,
    PullRequestReview,
    Repository,
    Resolution,
    Review,
    ReviewComment,
    ReviewFinding,
    ReviewRequest,
    Source,
    SourceEvidence,
    Specification,
    SpecificationConsiderationStatus,
    SpecificationIdlBlock,
    SpecificationReference,
    SpecificationSection,
    SpecificationVersion,
    SyncCursor,
)
from w3c_knowledge.parsing.rfc import parse_rfc_document
from w3c_knowledge.parsing.specification import (
    ParsedSpecification,
    content_hash,
    parse_specification_html,
)
from w3c_knowledge.parsing.urls import extract_github_issue_refs, normalize_url

WHATWG_STANDARD_SPECS: tuple[dict[str, str], ...] = (
    {
        "shortname": "compat",
        "title": "Compatibility Standard",
        "url": "https://compat.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/compat",
    },
    {
        "shortname": "compression",
        "title": "Compression Standard",
        "url": "https://compression.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/compression",
    },
    {
        "shortname": "console",
        "title": "Console Standard",
        "url": "https://console.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/console",
    },
    {
        "shortname": "cookiestore",
        "title": "Cookie Store API",
        "url": "https://cookiestore.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/cookie-store",
    },
    {
        "shortname": "dom",
        "title": "DOM Standard",
        "url": "https://dom.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/dom",
    },
    {
        "shortname": "encoding",
        "title": "Encoding Standard",
        "url": "https://encoding.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/encoding",
    },
    {
        "shortname": "fetch",
        "title": "Fetch Standard",
        "url": "https://fetch.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/fetch",
    },
    {
        "shortname": "fs",
        "title": "File System Standard",
        "url": "https://fs.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/fs",
    },
    {
        "shortname": "fullscreen",
        "title": "Fullscreen API Standard",
        "url": "https://fullscreen.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/fullscreen",
    },
    {
        "shortname": "html",
        "title": "HTML Standard",
        "url": "https://html.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/html",
    },
    {
        "shortname": "infra",
        "title": "Infra Standard",
        "url": "https://infra.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/infra",
    },
    {
        "shortname": "mimesniff",
        "title": "MIME Sniffing Standard",
        "url": "https://mimesniff.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/mimesniff",
    },
    {
        "shortname": "notifications",
        "title": "Notifications API Standard",
        "url": "https://notifications.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/notifications",
    },
    {
        "shortname": "quirks",
        "title": "Quirks Mode Standard",
        "url": "https://quirks.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/quirks",
    },
    {
        "shortname": "storage",
        "title": "Storage Standard",
        "url": "https://storage.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/storage",
    },
    {
        "shortname": "streams",
        "title": "Streams Standard",
        "url": "https://streams.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/streams",
    },
    {
        "shortname": "testutils",
        "title": "Test Utils Standard",
        "url": "https://testutils.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/testutils",
    },
    {
        "shortname": "url",
        "title": "URL Standard",
        "url": "https://url.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/url",
    },
    {
        "shortname": "urlpattern",
        "title": "URL Pattern Standard",
        "url": "https://urlpattern.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/urlpattern",
    },
    {
        "shortname": "webidl",
        "title": "Web IDL Standard",
        "url": "https://webidl.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/webidl",
    },
    {
        "shortname": "websockets",
        "title": "WebSockets Standard",
        "url": "https://websockets.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/websockets",
    },
    {
        "shortname": "xhr",
        "title": "XMLHttpRequest Standard",
        "url": "https://xhr.spec.whatwg.org/",
        "repository": "https://github.com/whatwg/xhr",
    },
)

DOCUMENT_SUFFIXES = {".bs", ".html", ".htm", ".md", ".txt"}
GUIDE_EXCLUDED_PATH_PARTS = {"_data", "_includes", ".git"}
GUIDE_EXCLUDED_FILENAMES = {"README.md", "CODE_OF_CONDUCT.md", "CONTRIBUTING.md"}
PROCESS_SNAPSHOT_RE = re.compile(r"^snapshots/(\d{4})-(\d{2})-(\d{2})\.html$")


class IngestionService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def sync_w3c_tr(
        self,
        adapter: W3CAPIAdapter,
        statuses: list[str],
        *,
        shortnames: list[str] | None = None,
        limit: int | None = None,
        latest_only: bool = True,
        force: bool = False,
        dry_run: bool = False,
        concurrency: int = 4,
        checkpoint_interval: int = 25,
        skip_existing: bool = False,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> IngestionRun:
        run = IngestionRun(status="running", summary={"operation": "sync_w3c_tr"})
        self.session.add(run)
        self.session.flush()
        summary: dict[str, Any] = {
            "operation": "sync_w3c_tr",
            "statuses": statuses,
            "latest_only": latest_only,
            "concurrency": concurrency,
            "skip_existing": skip_existing,
            "discovered": 0,
            "deduplicated": 0,
            "selected": 0,
            "downloaded": 0,
            "parsed": 0,
            "unchanged": 0,
            "not_modified": 0,
            "unchanged_by_hash": 0,
            "skipped_existing": 0,
            "skipped_status_mismatch": 0,
            "failed": 0,
            "errors": {},
            "documents": [],
            "processed": 0,
            "checkpoints": 0,
        }
        discovered: list[dict[str, Any]] = []
        if shortnames:
            for shortname in shortnames:
                discovered.append(
                    {
                        "shortname": shortname,
                        "source_status": None,
                        "raw_status": None,
                        "api_url": f"https://api.w3.org/specifications/{shortname}",
                        "raw_payload": {},
                    }
                )
        else:
            for status in statuses:
                try:
                    items = adapter.iter_specifications_by_status(status)
                except Exception as exc:
                    state = f"discovery_{status.lower()}_error"
                    summary["failed"] += 1
                    summary["errors"][state] = summary["errors"].get(state, 0) + 1
                    summary["documents"].append(
                        {
                            "status": status,
                            "state": state,
                            "error": str(exc),
                        }
                    )
                    continue
                summary["discovered"] += len(items)
                for discovered_item in items:
                    discovered.append(
                        {
                            "shortname": discovered_item.shortname,
                            "source_status": discovered_item.source_status,
                            "raw_status": discovered_item.raw_status,
                            "api_url": discovered_item.api_url,
                            "raw_payload": discovered_item.raw_payload,
                        }
                    )
        if shortnames:
            summary["discovered"] = len(discovered)
        selected_by_shortname: dict[str, dict[str, Any]] = {}
        for selected_item in discovered:
            selected_by_shortname.setdefault(str(selected_item["shortname"]), selected_item)
        summary["deduplicated"] = len(discovered) - len(selected_by_shortname)
        selected = list(selected_by_shortname.values())
        if limit is not None:
            selected = selected[:limit]
        summary["selected"] = len(selected)
        checkpoint_interval = max(1, checkpoint_interval)
        for index, selected_item in enumerate(selected, start=1):
            result = self._sync_one_w3c_tr(
                adapter,
                selected_item,
                statuses,
                force=force,
                dry_run=dry_run,
                skip_existing=skip_existing,
            )
            summary["documents"].append(result)
            summary["processed"] = index
            state = result["state"]
            if state in {"downloaded", "parsed"}:
                summary["downloaded"] += 1
            if state == "parsed":
                summary["parsed"] += 1
            elif state == "unchanged":
                summary["unchanged"] += 1
                reason = result.get("unchanged_reason")
                if reason == "not_modified":
                    summary["not_modified"] += 1
                elif reason == "content_hash":
                    summary["unchanged_by_hash"] += 1
                elif reason == "skip_existing":
                    summary["skipped_existing"] += 1
            elif state == "status_mismatch":
                summary["skipped_status_mismatch"] += 1
            elif state not in {"dry_run"}:
                summary["failed"] += 1
                summary["errors"][state] = summary["errors"].get(state, 0) + 1
            if index % checkpoint_interval == 0 or index == len(selected):
                summary["checkpoints"] += 1
                run.summary = summary
                flag_modified(run, "summary")
                self.session.commit()
                if progress_callback is not None:
                    progress_callback(
                        {
                            "operation": "sync_w3c_tr",
                            "processed": index,
                            "selected": len(selected),
                            "parsed": summary["parsed"],
                            "unchanged": summary["unchanged"],
                            "not_modified": summary["not_modified"],
                            "unchanged_by_hash": summary["unchanged_by_hash"],
                            "skipped_existing": summary["skipped_existing"],
                            "skipped_status_mismatch": summary["skipped_status_mismatch"],
                            "failed": summary["failed"],
                            "last_shortname": result.get("shortname"),
                            "last_state": state,
                        }
                    )
        run.status = "completed"
        run.finished_at = datetime.now(UTC)
        run.summary = summary
        flag_modified(run, "summary")
        self.session.commit()
        return run

    def _sync_one_w3c_tr(
        self,
        adapter: W3CAPIAdapter,
        item: dict[str, Any],
        allowed_statuses: list[str],
        *,
        force: bool,
        dry_run: bool,
        skip_existing: bool,
    ) -> dict[str, Any]:
        shortname = str(item["shortname"])
        try:
            spec_meta = adapter.get_specification(shortname)
            latest = adapter.get_latest_version(shortname, spec_meta.raw_payload)
            normalized_status = self._normalize_tr_status(latest.raw_status, latest.raw_payload)
            if normalized_status not in set(allowed_statuses):
                artifact = self._upsert_tr_api_artifact(
                    shortname, spec_meta, latest, item, state="status_mismatch"
                )
                self._upsert_source_evidence(
                    artifact.internal_id,
                    latest.api_url
                    or spec_meta.url
                    or f"https://api.w3.org/specifications/{shortname}/versions/latest",
                    latest.api_url or spec_meta.url or "",
                    f"w3c-api:{shortname}:latest",
                    str(latest.raw_payload),
                    content_hash(str(latest.raw_payload)),
                    None,
                    latest.publication_date,
                    fragment=None,
                    specification_version=latest.version,
                )
                return {
                    "shortname": shortname,
                    "state": "status_mismatch",
                    "raw_status": latest.raw_status,
                    "normalized_status": normalized_status,
                }
            if not latest.tr_url:
                return {"shortname": shortname, "state": "http_error", "error": "missing_tr_url"}
            existing = self._existing_spec_version(shortname, latest.version)
            if dry_run:
                return {
                    "shortname": shortname,
                    "state": "dry_run",
                    "raw_status": latest.raw_status,
                    "normalized_status": normalized_status,
                    "tr_url": latest.tr_url,
                }
            if existing is not None and skip_existing and not force:
                return {
                    "shortname": shortname,
                    "state": "unchanged",
                    "unchanged_reason": "skip_existing",
                    "tr_url": latest.tr_url,
                    "specification_version_id": existing.internal_id,
                }
            doc = adapter.download_tr_document(
                latest.tr_url,
                etag=None if force or existing is None else existing.metadata_.get("etag"),
                last_modified=None
                if force or existing is None
                else existing.metadata_.get("last_modified"),
            )
            if doc is None:
                return {
                    "shortname": shortname,
                    "state": "unchanged",
                    "unchanged_reason": "not_modified",
                    "tr_url": latest.tr_url,
                }
            doc_hash = content_hash(doc.text)
            if existing is not None and existing.content_hash == doc_hash and not force:
                existing.metadata_ = {
                    **(existing.metadata_ or {}),
                    "etag": doc.etag,
                    "last_modified": doc.last_modified,
                    "last_retrieved_url": doc.final_url,
                }
                return {
                    "shortname": shortname,
                    "state": "unchanged",
                    "unchanged_reason": "content_hash",
                    "tr_url": latest.tr_url,
                }
            parsed = parse_specification_html(doc.text, doc.final_url)
            spec_version = self._persist_tr_publication(
                shortname,
                spec_meta,
                latest,
                parsed,
                doc.text,
                doc.final_url,
                normalized_status,
                doc.etag,
                doc.last_modified,
                item,
            )
            return {
                "shortname": shortname,
                "state": "parsed",
                "specification_version_id": spec_version.internal_id,
                "raw_status": latest.raw_status,
                "normalized_status": normalized_status,
                "tr_url": latest.tr_url,
                "sections": len(parsed.sections),
                "webidl_blocks": len(parsed.webidl_blocks),
                "references": len(parsed.references),
            }
        except W3CDownloadError as exc:
            return {"shortname": shortname, "state": exc.status, "error": str(exc), "url": exc.url}
        except httpx.HTTPStatusError as exc:
            return {
                "shortname": shortname,
                "state": "http_error",
                "error": str(exc),
                "status_code": exc.response.status_code,
                "url": str(exc.request.url),
            }
        except Exception as exc:
            return {"shortname": shortname, "state": "parse_error", "error": exc.__class__.__name__}

    def sync_whatwg_html(
        self,
        adapter: W3CAPIAdapter,
        *,
        url: str = "https://html.spec.whatwg.org/",
        force: bool = False,
        dry_run: bool = False,
        skip_existing: bool = False,
    ) -> IngestionRun:
        run = IngestionRun(status="running", summary={"operation": "sync_whatwg_html"})
        self.session.add(run)
        self.session.flush()
        summary: dict[str, Any] = {
            "operation": "sync_whatwg_html",
            "shortname": "html",
            "url": url,
            "downloaded": 0,
            "parsed": 0,
            "unchanged": 0,
            "not_modified": 0,
            "unchanged_by_hash": 0,
            "skipped_existing": 0,
            "failed": 0,
            "errors": {},
            "documents": [],
        }
        try:
            existing = self._existing_spec_version("html", "living-standard")
            result: dict[str, Any]
            if dry_run:
                result = {"shortname": "html", "state": "dry_run", "url": url}
            elif existing is not None and skip_existing and not force:
                result = {
                    "shortname": "html",
                    "state": "unchanged",
                    "unchanged_reason": "skip_existing",
                    "url": url,
                    "specification_version_id": existing.internal_id,
                }
            else:
                doc = adapter.download_whatwg_html(
                    url,
                    etag=None if force or existing is None else existing.metadata_.get("etag"),
                    last_modified=None
                    if force or existing is None
                    else existing.metadata_.get("last_modified"),
                )
                if doc is None:
                    result = {
                        "shortname": "html",
                        "state": "unchanged",
                        "unchanged_reason": "not_modified",
                        "url": url,
                    }
                else:
                    doc_hash = content_hash(doc.text)
                    if existing is not None and existing.content_hash == doc_hash and not force:
                        existing.metadata_ = {
                            **(existing.metadata_ or {}),
                            "etag": doc.etag,
                            "last_modified": doc.last_modified,
                            "last_retrieved_url": doc.final_url,
                        }
                        result = {
                            "shortname": "html",
                            "state": "unchanged",
                            "unchanged_reason": "content_hash",
                            "url": url,
                            "final_url": doc.final_url,
                        }
                    else:
                        parsed = parse_specification_html(doc.text, doc.final_url)
                        parsed.metadata["source_repository_url"] = "https://github.com/whatwg/html"
                        parsed.metadata["editors_draft_url"] = doc.final_url
                        latest = W3CLatestVersion(
                            shortname="html",
                            title=parsed.title or "HTML Standard",
                            raw_status="Living Standard",
                            publication_date=None,
                            version="living-standard",
                            tr_url=doc.final_url,
                            latest_tr_url=url,
                            api_url=None,
                            raw_payload={
                                "source": "whatwg",
                                "url": url,
                                "final_url": doc.final_url,
                            },
                        )
                        spec_meta = W3CSpecificationMetadata(
                            shortname="html",
                            title=parsed.title or "HTML Standard",
                            status="Living Standard",
                            url=url,
                            editors_draft=doc.final_url,
                            raw_payload={
                                "source": "whatwg",
                                "url": url,
                                "final_url": doc.final_url,
                            },
                        )
                        spec_version = self._persist_tr_publication(
                            "html",
                            spec_meta,
                            latest,
                            parsed,
                            doc.text,
                            doc.final_url,
                            "LS",
                            doc.etag,
                            doc.last_modified,
                            {"raw_payload": {"source": "whatwg", "url": url}},
                            source_prefix="whatwg",
                            document_source_type="whatwg_html",
                            persist_api_evidence=False,
                        )
                        result = {
                            "shortname": "html",
                            "state": "parsed",
                            "specification_version_id": spec_version.internal_id,
                            "raw_status": "Living Standard",
                            "normalized_status": "LS",
                            "url": url,
                            "final_url": doc.final_url,
                            "sections": len(parsed.sections),
                            "webidl_blocks": len(parsed.webidl_blocks),
                            "references": len(parsed.references),
                        }
            summary["documents"].append(result)
            state = result["state"]
            if state == "parsed":
                summary["downloaded"] = 1
                summary["parsed"] = 1
            elif state == "unchanged":
                summary["unchanged"] = 1
                reason = result.get("unchanged_reason")
                if reason == "not_modified":
                    summary["not_modified"] = 1
                elif reason == "content_hash":
                    summary["unchanged_by_hash"] = 1
                elif reason == "skip_existing":
                    summary["skipped_existing"] = 1
            elif state != "dry_run":
                summary["failed"] = 1
                summary["errors"][state] = 1
        except W3CDownloadError as exc:
            summary["failed"] = 1
            summary["errors"][exc.status] = 1
            summary["documents"].append(
                {"shortname": "html", "state": exc.status, "error": str(exc), "url": exc.url}
            )
        except Exception as exc:
            summary["failed"] = 1
            summary["errors"]["parse_error"] = 1
            summary["documents"].append(
                {"shortname": "html", "state": "parse_error", "error": exc.__class__.__name__}
            )
        run.status = "completed"
        run.finished_at = datetime.now(UTC)
        run.summary = summary
        self.session.commit()
        return run

    def sync_whatwg_specs(
        self,
        adapter: W3CAPIAdapter,
        *,
        shortnames: Sequence[str] | None = None,
        limit: int | None = None,
        force: bool = False,
        dry_run: bool = False,
        skip_existing: bool = False,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> IngestionRun:
        requested = set(shortnames or [])
        selected = [
            spec
            for spec in WHATWG_STANDARD_SPECS
            if not requested or spec["shortname"] in requested
        ]
        if limit is not None:
            selected = selected[:limit]
        missing = sorted(requested - {spec["shortname"] for spec in WHATWG_STANDARD_SPECS})

        run = IngestionRun(status="running", summary={"operation": "sync_whatwg_specs"})
        self.session.add(run)
        self.session.flush()
        summary: dict[str, Any] = {
            "operation": "sync_whatwg_specs",
            "selected": len(selected),
            "requested": sorted(requested),
            "missing_shortnames": missing,
            "downloaded": 0,
            "parsed": 0,
            "unchanged": 0,
            "not_modified": 0,
            "unchanged_by_hash": 0,
            "skipped_existing": 0,
            "failed": 0,
            "errors": {},
            "documents": [],
            "processed": 0,
        }
        for missing_shortname in missing:
            summary["failed"] += 1
            summary["errors"]["unknown_shortname"] = (
                summary["errors"].get("unknown_shortname", 0) + 1
            )
            summary["documents"].append(
                {"shortname": missing_shortname, "state": "unknown_shortname"}
            )

        for spec_def in selected:
            result = self._sync_one_whatwg_spec(
                adapter,
                spec_def,
                force=force,
                dry_run=dry_run,
                skip_existing=skip_existing,
            )
            summary["documents"].append(result)
            state = result["state"]
            if state == "parsed":
                summary["downloaded"] += 1
                summary["parsed"] += 1
            elif state == "unchanged":
                summary["unchanged"] += 1
                reason = result.get("unchanged_reason")
                if reason == "not_modified":
                    summary["not_modified"] += 1
                elif reason == "content_hash":
                    summary["unchanged_by_hash"] += 1
                elif reason == "skip_existing":
                    summary["skipped_existing"] += 1
            elif state != "dry_run":
                summary["failed"] += 1
                summary["errors"][state] = summary["errors"].get(state, 0) + 1

            summary["processed"] += 1
            run.summary = summary
            self.session.commit()
            if progress_callback is not None:
                progress_callback(
                    {
                        "operation": "sync_whatwg_specs",
                        "processed": summary["processed"],
                        "selected": summary["selected"],
                        "parsed": summary["parsed"],
                        "unchanged": summary["unchanged"],
                        "failed": summary["failed"],
                        "last_shortname": result.get("shortname"),
                        "last_state": state,
                    }
                )

        run.status = "completed"
        run.finished_at = datetime.now(UTC)
        run.summary = summary
        self.session.commit()
        return run

    def _sync_one_whatwg_spec(
        self,
        adapter: W3CAPIAdapter,
        spec_def: dict[str, str],
        *,
        force: bool,
        dry_run: bool,
        skip_existing: bool,
    ) -> dict[str, Any]:
        shortname = spec_def["shortname"]
        url = spec_def["url"]
        version = "living-standard"
        try:
            existing = self._existing_spec_version(shortname, version)
            if dry_run:
                return {
                    "shortname": shortname,
                    "state": "dry_run",
                    "url": url,
                    "title": spec_def["title"],
                }
            if existing is not None and skip_existing and not force:
                return {
                    "shortname": shortname,
                    "state": "unchanged",
                    "unchanged_reason": "skip_existing",
                    "url": url,
                    "specification_version_id": existing.internal_id,
                }

            doc = adapter.download_whatwg_spec(
                url,
                etag=None if force or existing is None else existing.metadata_.get("etag"),
                last_modified=None
                if force or existing is None
                else existing.metadata_.get("last_modified"),
            )
            if doc is None:
                return {
                    "shortname": shortname,
                    "state": "unchanged",
                    "unchanged_reason": "not_modified",
                    "url": url,
                }

            doc_hash = content_hash(doc.text)
            if existing is not None and existing.content_hash == doc_hash and not force:
                existing.metadata_ = {
                    **(existing.metadata_ or {}),
                    "etag": doc.etag,
                    "last_modified": doc.last_modified,
                    "last_retrieved_url": doc.final_url,
                }
                return {
                    "shortname": shortname,
                    "state": "unchanged",
                    "unchanged_reason": "content_hash",
                    "url": url,
                    "final_url": doc.final_url,
                }

            parsed = parse_specification_html(doc.text, doc.final_url)
            parsed.metadata["source_repository_url"] = spec_def["repository"]
            parsed.metadata["editors_draft_url"] = doc.final_url
            parsed.metadata["whatwg_standard_url"] = url
            latest = W3CLatestVersion(
                shortname=shortname,
                title=parsed.title or spec_def["title"],
                raw_status="Living Standard",
                publication_date=None,
                version=version,
                tr_url=doc.final_url,
                latest_tr_url=url,
                api_url=None,
                raw_payload={"source": "whatwg", "url": url, "final_url": doc.final_url},
            )
            spec_meta = W3CSpecificationMetadata(
                shortname=shortname,
                title=parsed.title or spec_def["title"],
                status="Living Standard",
                url=url,
                editors_draft=doc.final_url,
                raw_payload={"source": "whatwg", "url": url, "final_url": doc.final_url},
            )
            document_source_type = "whatwg_html" if shortname == "html" else "whatwg_spec"
            spec_version = self._persist_tr_publication(
                shortname,
                spec_meta,
                latest,
                parsed,
                doc.text,
                doc.final_url,
                "LS",
                doc.etag,
                doc.last_modified,
                {"raw_payload": {"source": "whatwg", "url": url}},
                source_prefix="whatwg",
                document_source_type=document_source_type,
                persist_api_evidence=False,
            )
            return {
                "shortname": shortname,
                "state": "parsed",
                "specification_version_id": spec_version.internal_id,
                "raw_status": "Living Standard",
                "normalized_status": "LS",
                "url": url,
                "final_url": doc.final_url,
                "sections": len(parsed.sections),
                "webidl_blocks": len(parsed.webidl_blocks),
                "references": len(parsed.references),
            }
        except W3CDownloadError as exc:
            return {"shortname": shortname, "state": exc.status, "error": str(exc), "url": exc.url}
        except Exception as exc:
            return {
                "shortname": shortname,
                "state": "parse_error",
                "error": exc.__class__.__name__,
                "url": url,
            }

    def sync_rfcs(
        self,
        adapter: RFCEditorAdapter,
        *,
        scope: str = "referenced",
        numbers: Sequence[str | int] | None = None,
        mirror_dir: str | Path | None = None,
        limit: int | None = None,
        concurrency: int = 4,
        checkpoint_interval: int = 25,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
        skip_existing: bool = False,
        force: bool = False,
        dry_run: bool = False,
    ) -> IngestionRun:
        run = IngestionRun(status="running", summary={"operation": "sync_rfcs"})
        self.session.add(run)
        self.session.flush()
        summary: dict[str, Any] = {
            "operation": "sync_rfcs",
            "scope": scope,
            "concurrency": concurrency,
            "skip_existing": skip_existing,
            "discovered": 0,
            "deduplicated": 0,
            "selected": 0,
            "downloaded_metadata": 0,
            "downloaded_content": 0,
            "parsed": 0,
            "metadata_only": 0,
            "unchanged": 0,
            "not_modified": 0,
            "unchanged_by_hash": 0,
            "metadata_updated": 0,
            "skipped_existing": 0,
            "failed": 0,
            "errors": {},
            "processed": 0,
            "checkpoints": 0,
            "documents": [],
        }
        mirror_metadata: dict[int, DownloadedRFCMetadata] = {}
        if scope == "selected":
            discovered_numbers = [self.normalize_rfc_number(item) for item in numbers or []]
        elif scope == "referenced":
            discovered_numbers = self.discover_referenced_rfc_numbers()
        elif scope == "all":
            if mirror_dir is None:
                raise ValueError("scope=all requires mirror_dir")
            mirror_items = adapter.iter_mirror_metadata(Path(mirror_dir))
            mirror_metadata = {item.metadata.number: item for item in mirror_items}
            discovered_numbers = sorted(mirror_metadata)
        else:
            raise ValueError(f"Unsupported RFC sync scope: {scope}")
        summary["discovered"] = len(discovered_numbers)
        selected_numbers = sorted({number for number in discovered_numbers if number is not None})
        summary["deduplicated"] = len(discovered_numbers) - len(selected_numbers)
        if limit is not None:
            selected_numbers = selected_numbers[:limit]
        summary["selected"] = len(selected_numbers)
        reference_link_numbers = set(
            self.discover_referenced_rfc_numbers(include_rfc_sources=False)
        )
        checkpoint_interval = max(1, checkpoint_interval)
        for index, number in enumerate(selected_numbers, start=1):
            result = self._sync_one_rfc(
                adapter,
                number,
                mirror_metadata=mirror_metadata,
                mirror_dir=Path(mirror_dir) if mirror_dir is not None else None,
                force=force,
                dry_run=dry_run,
                skip_existing=skip_existing,
                reference_link_numbers=reference_link_numbers,
            )
            summary["documents"].append(result)
            summary["processed"] = index
            state = result["state"]
            if result.get("metadata_downloaded"):
                summary["downloaded_metadata"] += 1
            if result.get("content_downloaded"):
                summary["downloaded_content"] += 1
            if state == "parsed":
                summary["parsed"] += 1
            elif state == "metadata_only":
                summary["metadata_only"] += 1
            elif state == "unchanged":
                summary["unchanged"] += 1
                reason = result.get("unchanged_reason")
                if reason == "not_modified":
                    summary["not_modified"] += 1
                elif reason == "content_hash":
                    summary["unchanged_by_hash"] += 1
                elif reason == "skip_existing":
                    summary["skipped_existing"] += 1
            elif state == "metadata_updated":
                summary["metadata_updated"] += 1
            elif state != "dry_run":
                summary["failed"] += 1
                summary["errors"][state] = summary["errors"].get(state, 0) + 1
            if index % checkpoint_interval == 0 or index == len(selected_numbers):
                summary["checkpoints"] += 1
                run.summary = summary
                self.session.commit()
                if progress_callback is not None:
                    progress_callback(
                        {
                            "operation": "sync_rfcs",
                            "processed": index,
                            "selected": len(selected_numbers),
                            "parsed": summary["parsed"],
                            "metadata_only": summary["metadata_only"],
                            "unchanged": summary["unchanged"],
                            "metadata_updated": summary["metadata_updated"],
                            "failed": summary["failed"],
                            "last_rfc": result.get("rfc"),
                            "last_state": state,
                        }
                    )
        run.status = "completed"
        run.finished_at = datetime.now(UTC)
        run.summary = summary
        self.session.commit()
        return run

    def sync_ietf_secdir_reviews(
        self,
        adapter: IETFDatatrackerAdapter,
        *,
        limit: int | None = None,
        page_size: int = 100,
        checkpoint_interval: int = 100,
        download_review_pages: bool = True,
        download_reviewed_documents: bool = True,
        skip_existing: bool = False,
        force: bool = False,
        dry_run: bool = False,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> IngestionRun:
        run = IngestionRun(status="running", summary={"operation": "sync_ietf_secdir_reviews"})
        self.session.add(run)
        self.session.flush()
        summary: dict[str, Any] = {
            "operation": "sync_ietf_secdir_reviews",
            "team": "secdir",
            "limit": limit,
            "download_review_pages": download_review_pages,
            "download_reviewed_documents": download_reviewed_documents,
            "discovered": 0,
            "selected": 0,
            "processed": 0,
            "review_requests": 0,
            "reviews": 0,
            "review_pages_downloaded": 0,
            "review_comments": 0,
            "reviewed_documents_downloaded": 0,
            "linked_reviewed_versions": 0,
            "unchanged": 0,
            "skipped_existing": 0,
            "failed": 0,
            "errors": {},
            "results": {},
            "checkpoints": 0,
            "items": [],
        }
        try:
            assignments = adapter.iter_review_assignments(
                team="secdir", limit=limit, page_size=page_size
            )
        except Exception as exc:
            summary["failed"] += 1
            summary["errors"]["discovery_error"] = str(exc)
            run.status = "failed"
            run.finished_at = datetime.now(UTC)
            run.summary = summary
            self.session.commit()
            return run
        summary["discovered"] = len(assignments)
        summary["selected"] = len(assignments)
        checkpoint_interval = max(1, checkpoint_interval)
        for index, assignment in enumerate(assignments, start=1):
            result = self._sync_one_ietf_secdir_review(
                adapter,
                assignment,
                download_review_page=download_review_pages,
                download_reviewed_document=download_reviewed_documents,
                skip_existing=skip_existing,
                force=force,
                dry_run=dry_run,
            )
            summary["items"].append(result)
            summary["processed"] = index
            state = result["state"]
            normalized_result = result.get("result") or "none"
            summary["results"][normalized_result] = summary["results"].get(normalized_result, 0) + 1
            if state == "synced":
                summary["review_requests"] += int(bool(result.get("review_request_id")))
                summary["reviews"] += int(bool(result.get("review_id")))
                summary["review_pages_downloaded"] += int(bool(result.get("review_page_downloaded")))
                summary["review_comments"] += int(bool(result.get("review_comment_id")))
                summary["reviewed_documents_downloaded"] += int(
                    bool(result.get("reviewed_document_downloaded"))
                )
                summary["linked_reviewed_versions"] += int(
                    bool(result.get("reviewed_snapshot_version_id"))
                )
            elif state == "unchanged":
                summary["unchanged"] += 1
                if result.get("unchanged_reason") == "skip_existing":
                    summary["skipped_existing"] += 1
            elif state != "dry_run":
                summary["failed"] += 1
                summary["errors"][state] = summary["errors"].get(state, 0) + 1
            if index % checkpoint_interval == 0 or index == len(assignments):
                summary["checkpoints"] += 1
                run.summary = summary
                flag_modified(run, "summary")
                self.session.commit()
                if progress_callback is not None:
                    progress_callback(
                        {
                            "operation": "sync_ietf_secdir_reviews",
                            "processed": index,
                            "selected": len(assignments),
                            "reviews": summary["reviews"],
                            "review_comments": summary["review_comments"],
                            "reviewed_documents_downloaded": summary[
                                "reviewed_documents_downloaded"
                            ],
                            "failed": summary["failed"],
                            "last_assignment": result.get("assignment_id"),
                            "last_state": state,
                        }
                    )
        run.status = "completed"
        run.finished_at = datetime.now(UTC)
        run.summary = summary
        flag_modified(run, "summary")
        self.session.commit()
        return run

    def _sync_one_ietf_secdir_review(
        self,
        adapter: IETFDatatrackerAdapter,
        assignment: dict[str, Any],
        *,
        download_review_page: bool,
        download_reviewed_document: bool,
        skip_existing: bool,
        force: bool,
        dry_run: bool,
    ) -> dict[str, Any]:
        assignment_id = int(assignment["id"])
        result_value = normalize_result(assignment.get("result"))
        state = normalize_state(assignment.get("state"))
        if dry_run:
            return {
                "assignment_id": assignment_id,
                "state": "dry_run",
                "assignment_state": state,
                "result": result_value,
            }
        try:
            request_payload = adapter.get_review_request(str(assignment["review_request"]))
            draft_name = document_name_from_resource(request_payload.get("doc"))
            if draft_name is None:
                raise IETFDatatrackerError(
                    "parse_error", "Review request is missing document name", str(assignment)
                )
            existing_review = self._find_ietf_review_by_assignment_id(assignment_id)
            if existing_review is not None and skip_existing and not force:
                return {
                    "assignment_id": assignment_id,
                    "state": "unchanged",
                    "unchanged_reason": "skip_existing",
                    "assignment_state": state,
                    "result": result_value,
                    "review_id": existing_review.internal_id,
                }
            reviewed_rev = str(assignment.get("reviewed_rev") or "").strip()
            review_name = document_name_from_resource(assignment.get("review"))
            review_doc_payload: dict[str, Any] | None = None
            review_page_doc: DownloadedIETFDocument | None = None
            review_page: ParsedIETFReviewPage | None = None
            if review_name:
                review_doc_payload = adapter.get_document(review_name)
                if download_review_page:
                    review_page_doc = adapter.download_review_page(review_name)
                    review_page = adapter.parse_review_page(review_page_doc.text)
                    result_value = normalize_result(assignment.get("result"), review_page.result)
                    reviewed_rev = reviewed_rev or (review_page.reviewed_rev or "")
            requested_rev = str(request_payload.get("requested_rev") or "").strip()
            selected_rev = reviewed_rev or requested_rev
            spec_version: SpecificationVersion | None = None
            reviewed_document_downloaded = False
            if selected_rev and download_reviewed_document:
                draft_doc = adapter.download_draft_snapshot(draft_name, selected_rev)
                spec_version = self._persist_ietf_draft_snapshot(
                    draft_name,
                    selected_rev,
                    draft_doc,
                    adapter.get_document(draft_name),
                )
                reviewed_document_downloaded = True
            elif selected_rev:
                spec_version = self._existing_spec_version(draft_name, selected_rev)
            review_request = self._upsert_ietf_review_request(
                request_payload,
                draft_name,
                selected_rev or None,
            )
            review_artifact = self._upsert_ietf_review_artifact(
                assignment,
                request_payload,
                review_doc_payload,
                review_page_doc,
                review_page,
                result_value,
                draft_name,
                selected_rev or None,
            )
            review_evidence = self._upsert_source_evidence(
                review_artifact.internal_id,
                review_artifact.source_url or "",
                review_artifact.canonical_url or review_artifact.source_url or "",
                f"ietf-secdir-review:{assignment_id}:review",
                review_page.body if review_page else review_artifact.raw_text or "",
                content_hash(review_page.body if review_page else review_artifact.raw_text or ""),
                review_page.reviewer if review_page else None,
                assignment.get("completed_on") or (review_doc_payload or {}).get("time"),
                fragment=None,
                specification_version=selected_rev or None,
            )
            review = self._upsert_ietf_review(
                review_request,
                assignment,
                request_payload,
                review_doc_payload,
                review_page,
                result_value,
                state,
                spec_version,
                review_artifact,
                review_evidence.internal_id,
            )
            comment = None
            if review_page and review_page.body:
                comment = self._upsert_ietf_review_comment(
                    review,
                    assignment,
                    review_page,
                    review_artifact.source_url or "",
                )
                self._upsert_artifact_link(
                    subject_type="review",
                    subject_id=review.internal_id,
                    predicate="HAS_COMMENT",
                    object_type="review_comment",
                    object_id=comment.internal_id,
                    source=comment.source_url,
                    confidence=1.0,
                    extraction_method="ietf-datatracker-review-page",
                    supporting_evidence=[review_evidence.internal_id],
                    is_explicit=True,
                )
            if spec_version is not None:
                self._upsert_artifact_link(
                    subject_type="review",
                    subject_id=review.internal_id,
                    predicate="REVIEWS",
                    object_type="specification_version",
                    object_id=spec_version.internal_id,
                    source=review_artifact.source_url or spec_version.source_url,
                    confidence=1.0,
                    extraction_method="ietf-datatracker-reviewed-revision",
                    supporting_evidence=[review_evidence.internal_id],
                    is_explicit=True,
                )
            self.session.flush()
            return {
                "assignment_id": assignment_id,
                "state": "synced",
                "assignment_state": state,
                "result": result_value,
                "review_request_id": review_request.internal_id,
                "review_id": review.internal_id,
                "review_comment_id": comment.internal_id if comment else None,
                "review_page_downloaded": review_page_doc is not None,
                "reviewed_document_downloaded": reviewed_document_downloaded,
                "draft": draft_name,
                "reviewed_revision": selected_rev or None,
                "reviewed_snapshot_version_id": spec_version.internal_id
                if spec_version is not None
                else None,
            }
        except IETFDatatrackerError as exc:
            return {
                "assignment_id": assignment_id,
                "state": exc.status,
                "assignment_state": state,
                "result": result_value,
                "error": str(exc),
                "url": exc.url,
            }
        except Exception as exc:
            return {
                "assignment_id": assignment_id,
                "state": "parse_error",
                "assignment_state": state,
                "result": result_value,
                "error": exc.__class__.__name__,
            }

    def _persist_ietf_draft_snapshot(
        self,
        shortname: str,
        revision: str,
        document: DownloadedIETFDocument,
        document_payload: dict[str, Any],
    ) -> SpecificationVersion:
        revision = self._normalize_ietf_draft_revision(revision)
        parsed: ParsedSpecification | None = None
        title = str(document_payload.get("title") or shortname)
        raw_text = document.text
        if document.content_format == "html":
            parsed = parse_specification_html(document.text, document.final_url)
            title = parsed.title or title
            raw_text = parsed.text
        spec = self.session.scalar(
            select(Specification).where(Specification.shortname == shortname)
        )
        if spec is None:
            spec = Specification(
                shortname=shortname,
                title=title,
                aliases=[],
                publication_status="Internet-Draft",
                current_published_url=f"https://datatracker.ietf.org/doc/{shortname}/",
                editors_draft_url=None,
                metadata_={},
            )
            self.session.add(spec)
            self.session.flush()
        spec.title = title or spec.title
        spec.publication_status = "Internet-Draft"
        spec.current_published_url = f"https://datatracker.ietf.org/doc/{shortname}/"
        spec.metadata_ = {
            **(spec.metadata_ or {}),
            "source_family": "ietf_datatracker",
            "datatracker_document_id": document_payload.get("id"),
            "current_revision": document_payload.get("rev"),
            "group": document_payload.get("group"),
            "stream": document_payload.get("stream"),
        }
        spec_version = self._existing_spec_version(shortname, revision)
        metadata = {
            "source_family": "ietf_draft",
            "document_name": shortname,
            "revision": revision,
            "datatracker_document": document_payload,
            "retrieved_at": datetime.now(UTC).isoformat(),
            "final_url": document.final_url,
            "etag": document.etag,
            "last_modified": document.last_modified,
            "content_format": document.content_format,
            "content_type": document.content_type,
            "html_content_hash": document.content_hash if document.content_format == "html" else None,
            **(parsed.metadata if parsed else {}),
        }
        if spec_version is None:
            spec_version = SpecificationVersion(
                specification_id=spec.internal_id,
                version=revision,
                publication_status="Internet-Draft",
                publication_date=(document_payload.get("time") or "")[:10] or None,
                source_url=document.final_url,
                canonical_url=document.url,
                source_commit=None,
                content_hash=document.content_hash,
                raw_text=raw_text,
                metadata_=metadata,
            )
            self.session.add(spec_version)
            self.session.flush()
        else:
            spec_version.publication_status = "Internet-Draft"
            spec_version.publication_date = (document_payload.get("time") or "")[:10] or None
            spec_version.source_url = document.final_url
            spec_version.canonical_url = document.url
            spec_version.content_hash = document.content_hash
            spec_version.raw_text = raw_text
            spec_version.metadata_ = metadata
        artifact = self._upsert_ietf_draft_artifact(spec, spec_version, document, title, raw_text)
        evidence = self._upsert_source_evidence(
            artifact.internal_id,
            document.final_url,
            document.url,
            f"ietf-draft:{shortname}:{revision}:{document.content_format}",
            document.text,
            document.content_hash,
            None,
            spec_version.publication_date,
            fragment=None,
            specification_version=revision,
        )
        if parsed is not None:
            self._persist_tr_sections(
                spec,
                spec_version,
                parsed,
                artifact,
                document.final_url,
                evidence.internal_id,
                source_prefix="ietf-draft",
                section_source_type="ietf_draft",
            )
            self._persist_tr_references(spec_version, parsed, document.final_url, evidence.internal_id)
            self._persist_tr_consideration_statuses(spec_version, parsed, evidence.internal_id)
        self.session.flush()
        return spec_version

    def _upsert_ietf_draft_artifact(
        self,
        spec: Specification,
        spec_version: SpecificationVersion,
        document: DownloadedIETFDocument,
        title: str,
        raw_text: str,
    ) -> Artifact:
        external_id = f"ietf-draft:{spec.shortname}:{spec_version.version}"
        artifact = self.session.scalar(select(Artifact).where(Artifact.external_id == external_id))
        kwargs = {
            "external_id": external_id,
            "source_type": "ietf_draft",
            "artifact_type": "specification_snapshot",
            "primary_domain": "security",
            "applicable_domains": ["security"],
            "source_url": document.final_url,
            "canonical_url": document.url,
            "title": title,
            "raw_text": raw_text,
            "normalized_text": raw_text.lower(),
            "raw_payload": {"source_format": document.content_format},
            "retrieved_at": datetime.now(UTC),
            "content_hash": document.content_hash,
            "version": spec_version.version,
            "commit_sha": None,
            "provenance": {
                "shortname": spec.shortname,
                "specification_version_id": spec_version.internal_id,
                "source_family": "ietf_draft",
            },
            "confidence": 1.0,
            "metadata_": {
                "publication_status": "Internet-Draft",
                "content_type": document.content_type,
                "etag": document.etag,
                "last_modified": document.last_modified,
            },
        }
        if artifact is None:
            artifact = Artifact(**kwargs)
            self.session.add(artifact)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(artifact, key, value)
        return artifact

    def _upsert_ietf_review_request(
        self,
        request_payload: dict[str, Any],
        draft_name: str,
        revision: str | None,
    ) -> ReviewRequest:
        request_id = int(request_payload["id"])
        source_url = f"https://datatracker.ietf.org/doc/{draft_name}/reviewrequest/{request_id}/"
        review_request = self.session.scalar(
            select(ReviewRequest).where(ReviewRequest.source_url == source_url)
        )
        review_type = normalize_review_type(request_payload.get("type"))
        requested_snapshot_url = (
            f"https://www.ietf.org/archive/id/{draft_name}-{revision}.html" if revision else None
        )
        kwargs = {
            "domain": "security",
            "title": f"IETF SECDIR {review_type or 'unknown'} review request for {draft_name}",
            "source_url": source_url,
            "state": normalize_state(request_payload.get("state")),
            "requested_snapshot_url": requested_snapshot_url,
            "raw_payload": {
                "datatracker_review_request": request_payload,
                "draft_name": draft_name,
                "reviewed_revision": revision,
            },
        }
        if review_request is None:
            review_request = ReviewRequest(**kwargs)
            self.session.add(review_request)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(review_request, key, value)
        return review_request

    def _upsert_ietf_review_artifact(
        self,
        assignment: dict[str, Any],
        request_payload: dict[str, Any],
        review_doc_payload: dict[str, Any] | None,
        review_page_doc: DownloadedIETFDocument | None,
        review_page: ParsedIETFReviewPage | None,
        result_value: str,
        draft_name: str,
        revision: str | None,
    ) -> Artifact:
        assignment_id = int(assignment["id"])
        review_name = document_name_from_resource(assignment.get("review"))
        source_url = (
            f"https://datatracker.ietf.org/doc/{review_name}/"
            if review_name
            else f"https://datatracker.ietf.org/doc/{draft_name}/reviewrequest/{request_payload['id']}/"
        )
        body = review_page.body if review_page else ""
        title = (
            (review_page.title if review_page else None)
            or (review_doc_payload or {}).get("title")
            or f"SECDIR review assignment {assignment_id}"
        )
        raw_payload = {
            "assignment": assignment,
            "review_request": request_payload,
            "review_document": review_doc_payload or {},
        }
        kwargs = {
            "external_id": f"ietf-secdir-review-assignment:{assignment_id}",
            "source_type": "ietf_datatracker",
            "artifact_type": "security_review",
            "primary_domain": "security",
            "applicable_domains": ["security"],
            "source_url": source_url,
            "canonical_url": source_url,
            "title": str(title),
            "raw_text": body or str(title),
            "normalized_text": (body or str(title)).lower(),
            "raw_payload": raw_payload,
            "retrieved_at": datetime.now(UTC),
            "content_hash": content_hash(
                review_page_doc.text if review_page_doc is not None else body or str(raw_payload)
            ),
            "version": (review_doc_payload or {}).get("rev"),
            "commit_sha": None,
            "provenance": {
                "team": "secdir",
                "assignment_id": assignment_id,
                "request_id": request_payload.get("id"),
                "review_document": review_name,
                "draft_name": draft_name,
                "reviewed_revision": revision,
            },
            "confidence": 1.0,
            "metadata_": {
                "assignment_state": normalize_state(assignment.get("state")),
                "result": result_value,
                "result_display": display_result(result_value),
                "assigned_on": assignment.get("assigned_on"),
                "completed_on": assignment.get("completed_on"),
                "mailarch_url": assignment.get("mailarch_url")
                or (review_page.posted_url if review_page else None)
                or (review_doc_payload or {}).get("external_url"),
            },
        }
        artifact = self.session.scalar(
            select(Artifact).where(Artifact.external_id == kwargs["external_id"])
        )
        if artifact is None:
            artifact = Artifact(**kwargs)
            self.session.add(artifact)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(artifact, key, value)
        return artifact

    def _upsert_ietf_review(
        self,
        review_request: ReviewRequest,
        assignment: dict[str, Any],
        request_payload: dict[str, Any],
        review_doc_payload: dict[str, Any] | None,
        review_page: ParsedIETFReviewPage | None,
        result_value: str,
        state: str,
        spec_version: SpecificationVersion | None,
        artifact: Artifact,
        evidence_id: str,
    ) -> Review:
        assignment_id = int(assignment["id"])
        review = self._find_ietf_review_by_assignment_id(assignment_id)
        metadata = {
            "source_family": "ietf_datatracker",
            "source_artifact_id": artifact.internal_id,
            "source_url": artifact.source_url,
            "team": "secdir",
            "datatracker_assignment_id": assignment_id,
            "datatracker_review_request_id": request_payload.get("id"),
            "datatracker_review_document_id": (review_doc_payload or {}).get("id"),
            "result": result_value,
            "result_display": display_result(result_value),
            "assignment_state": state,
            "review_type": normalize_review_type(request_payload.get("type")),
            "requested_revision": request_payload.get("requested_rev"),
            "reviewed_revision": assignment.get("reviewed_rev") or (review_page.reviewed_rev if review_page else None),
            "reviewer_resource": assignment.get("reviewer"),
            "reviewer": review_page.reviewer if review_page else None,
            "assigned_on": assignment.get("assigned_on"),
            "completed_on": assignment.get("completed_on"),
            "mailarch_url": assignment.get("mailarch_url")
            or (review_page.posted_url if review_page else None)
            or (review_doc_payload or {}).get("external_url"),
            "evidence_ids": [evidence_id],
        }
        kwargs = {
            "review_request_id": review_request.internal_id,
            "review_domain": "security",
            "status": state,
            "reviewer_group": "IETF Security Area Directorate",
            "target_specification_id": spec_version.specification_id if spec_version else None,
            "reviewed_snapshot_version_id": spec_version.internal_id if spec_version else None,
            "metadata_": metadata,
        }
        if review is None:
            review = Review(**kwargs)
            self.session.add(review)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(review, key, value)
        self._upsert_artifact_link(
            subject_type="review_request",
            subject_id=review_request.internal_id,
            predicate="HAS_REVIEW",
            object_type="review",
            object_id=review.internal_id,
            source=artifact.source_url or review_request.source_url,
            confidence=1.0,
            extraction_method="ietf-datatracker-assignment",
            supporting_evidence=[evidence_id],
            is_explicit=True,
        )
        return review

    def _upsert_ietf_review_comment(
        self,
        review: Review,
        assignment: dict[str, Any],
        review_page: ParsedIETFReviewPage,
        source_url: str,
    ) -> ReviewComment:
        comment = self.session.scalar(
            select(ReviewComment).where(
                ReviewComment.review_id == review.internal_id,
                ReviewComment.source_url == source_url,
            )
        )
        kwargs = {
            "review_id": review.internal_id,
            "author": review_page.reviewer,
            "body": review_page.body,
            "source_url": source_url,
            "created_source_at": assignment.get("completed_on") or review_page.completed_date,
            "raw_payload": {
                "datatracker_assignment_id": assignment.get("id"),
                "review_name": review_page.review_name,
                "posted_url": review_page.posted_url,
                "result": review_page.result,
            },
        }
        if comment is None:
            comment = ReviewComment(**kwargs)
            self.session.add(comment)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(comment, key, value)
        return comment

    def _find_ietf_review_by_assignment_id(self, assignment_id: int) -> Review | None:
        reviews = self.session.scalars(
            select(Review).where(Review.review_domain == "security")
        ).all()
        for review in reviews:
            metadata = review.metadata_ or {}
            if metadata.get("datatracker_assignment_id") == assignment_id:
                return review
        return None

    def _normalize_ietf_draft_revision(self, revision: str) -> str:
        value = revision.strip()
        return value.zfill(2) if value.isdigit() else value

    def _sync_one_rfc(
        self,
        adapter: RFCEditorAdapter,
        number: int,
        *,
        mirror_metadata: dict[int, DownloadedRFCMetadata],
        mirror_dir: Path | None,
        force: bool,
        dry_run: bool,
        skip_existing: bool,
        reference_link_numbers: set[int],
    ) -> dict[str, Any]:
        shortname = f"rfc{number}"
        version = f"RFC{number}"
        existing = self._existing_spec_version(shortname, version)
        if existing is None:
            spec = self.session.scalar(
                select(Specification).where(Specification.shortname == shortname)
            )
            if spec is not None:
                existing = self.session.scalar(
                    select(SpecificationVersion)
                    .where(SpecificationVersion.specification_id == spec.internal_id)
                    .order_by(SpecificationVersion.updated_at.desc())
                )
        try:
            if dry_run:
                return {"rfc": number, "shortname": shortname, "state": "dry_run"}
            if existing is not None and skip_existing and not force:
                return {
                    "rfc": number,
                    "shortname": shortname,
                    "state": "unchanged",
                    "unchanged_reason": "skip_existing",
                    "specification_version_id": existing.internal_id,
                }
            if number in mirror_metadata:
                metadata_doc: DownloadedRFCMetadata | None = mirror_metadata[number]
                metadata_not_modified = False
            else:
                metadata_doc = adapter.get_metadata(
                    number,
                    etag=None
                    if force or existing is None
                    else existing.metadata_.get("metadata_etag"),
                    last_modified=None
                    if force or existing is None
                    else existing.metadata_.get("metadata_last_modified"),
                )
                metadata_not_modified = metadata_doc is None
            if metadata_doc is None and existing is not None:
                return {
                    "rfc": number,
                    "shortname": shortname,
                    "state": "unchanged",
                    "unchanged_reason": "not_modified",
                }
            if metadata_doc is None:
                return {"rfc": number, "shortname": shortname, "state": "not_found"}
            metadata = metadata_doc.metadata
            if mirror_dir is not None:
                content_doc: DownloadedRFCDocument | None = adapter.load_mirror_content(
                    mirror_dir, metadata
                )
            else:
                content_doc = adapter.download_content(
                    metadata,
                    etag=None
                    if force or existing is None
                    else existing.metadata_.get("content_etag"),
                    last_modified=None
                    if force or existing is None
                    else existing.metadata_.get("content_last_modified"),
                )
            if content_doc is None and existing is not None:
                spec_version = self._persist_rfc_metadata_only(metadata_doc, existing)
                state = "metadata_updated" if not metadata_not_modified else "unchanged"
                self._materialize_rfc_links(metadata, spec_version, metadata_doc.content_hash)
                if number in reference_link_numbers:
                    self._materialize_rfc_reference_links(number)
                return {
                    "rfc": number,
                    "shortname": shortname,
                    "state": state,
                    "metadata_downloaded": True,
                    "unchanged_reason": "not_modified" if state == "unchanged" else None,
                }
            if content_doc is None:
                return {"rfc": number, "shortname": shortname, "state": "not_found"}
            if content_doc.content_format == "metadata-only":
                spec_version = self._persist_rfc_publication(metadata_doc, content_doc, None)
                self._materialize_rfc_links(metadata, spec_version, metadata_doc.content_hash)
                if number in reference_link_numbers:
                    self._materialize_rfc_reference_links(number)
                return {
                    "rfc": number,
                    "shortname": shortname,
                    "state": "metadata_only",
                    "metadata_downloaded": True,
                    "content_downloaded": False,
                    "specification_version_id": spec_version.internal_id,
                }
            if (
                existing is not None
                and existing.content_hash == content_doc.content_hash
                and not force
            ):
                metadata_changed = (
                    existing.metadata_.get("metadata_json_hash") != metadata_doc.content_hash
                )
                spec_version = self._persist_rfc_metadata_only(
                    metadata_doc, existing, content_doc=content_doc
                )
                self._materialize_rfc_links(metadata, spec_version, metadata_doc.content_hash)
                if number in reference_link_numbers:
                    self._materialize_rfc_reference_links(number)
                return {
                    "rfc": number,
                    "shortname": shortname,
                    "state": "metadata_updated" if metadata_changed else "unchanged",
                    "unchanged_reason": None if metadata_changed else "content_hash",
                    "metadata_downloaded": True,
                    "content_downloaded": True,
                }
            parsed = parse_rfc_document(
                metadata, content_doc.text, content_doc.content_format, content_doc.final_url
            )
            spec_version = self._persist_rfc_publication(metadata_doc, content_doc, parsed)
            self._materialize_rfc_links(metadata, spec_version, metadata_doc.content_hash)
            if number in reference_link_numbers:
                self._materialize_rfc_reference_links(number)
            return {
                "rfc": number,
                "shortname": shortname,
                "state": "parsed",
                "metadata_downloaded": True,
                "content_downloaded": True,
                "specification_version_id": spec_version.internal_id,
                "content_format": content_doc.content_format,
                "sections": len(parsed.sections),
                "references": len(parsed.references),
            }
        except RFCEditorError as exc:
            return {
                "rfc": number,
                "shortname": shortname,
                "state": exc.status,
                "error": str(exc),
                "url": exc.url,
            }
        except Exception as exc:
            self.session.rollback()
            return {
                "rfc": number,
                "shortname": shortname,
                "state": "parse_error",
                "error": exc.__class__.__name__,
            }

    def bootstrap_sources(self, sources_path: str | Path) -> IngestionRun:
        run = IngestionRun(status="running", summary={})
        self.session.add(run)
        count = 0
        for source_config in load_sources(sources_path):
            existing = self.session.scalar(select(Source).where(Source.name == source_config.name))
            if existing:
                for key, value in source_to_model_kwargs(source_config).items():
                    setattr(existing, key, value)
            else:
                self.session.add(Source(**source_to_model_kwargs(source_config)))
            count += 1
        run.status = "completed"
        run.finished_at = datetime.now(UTC)
        run.summary = {"sources": count}
        self.session.commit()
        return run

    def sync_repository_documents(
        self,
        checkout_path: str | Path,
        source_config: SourceConfig,
        *,
        commit_sha: str | None = None,
        limit: int | None = None,
    ) -> IngestionRun:
        root = Path(checkout_path)
        if not root.exists() or not root.is_dir():
            raise ValueError(f"Repository checkout does not exist: {root}")
        run = IngestionRun(
            status="running",
            summary={
                "operation": "sync_repository_documents",
                "repository": f"{source_config.organization}/{source_config.repository}",
            },
        )
        self.session.add(run)
        self.session.flush()
        imported = 0
        skipped = 0
        document_paths = self._repository_document_paths(root, source_config)
        if limit is not None:
            document_paths = document_paths[:limit]
        try:
            repository = self.upsert_repository(
                source_config.organization or "unknown",
                source_config.repository or root.name,
                payload={
                    "full_name": f"{source_config.organization}/{source_config.repository}",
                    "html_url": source_config.url,
                    "default_branch": source_config.branch,
                },
            )
            for path in document_paths:
                relative_path = path.relative_to(root).as_posix()
                text = path.read_text(encoding="utf-8", errors="replace")
                if not text.strip():
                    skipped += 1
                    continue
                if source_config.parser == "process_document":
                    self._ingest_process_repository_document(
                        repository, source_config, relative_path, text, commit_sha
                    )
                else:
                    self._ingest_guidance_repository_document(
                        repository, source_config, relative_path, text, commit_sha
                    )
                imported += 1
        except Exception as exc:
            run.status = "failed"
            run.finished_at = datetime.now(UTC)
            run.summary = {
                "operation": "sync_repository_documents",
                "repository": f"{source_config.organization}/{source_config.repository}",
                "imported": imported,
                "skipped": skipped,
                "error": exc.__class__.__name__,
            }
            self.session.commit()
            raise
        run.status = "completed"
        run.finished_at = datetime.now(UTC)
        run.summary = {
            "operation": "sync_repository_documents",
            "repository": f"{source_config.organization}/{source_config.repository}",
            "imported": imported,
            "skipped": skipped,
            "selected": len(document_paths),
            "commit_sha": commit_sha,
            "parser": source_config.parser,
        }
        self.session.commit()
        return run

    def _repository_document_paths(self, root: Path, source_config: SourceConfig) -> list[Path]:
        paths: list[Path] = []
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in DOCUMENT_SUFFIXES:
                continue
            relative = path.relative_to(root)
            relative_name = relative.as_posix()
            relative_parts = set(relative.parts)
            if ".git" in relative_parts:
                continue
            if source_config.parser == "process_document":
                if relative_name == "index.bs" or PROCESS_SNAPSHOT_RE.match(relative_name):
                    paths.append(path)
                continue
            if relative_parts & GUIDE_EXCLUDED_PATH_PARTS:
                continue
            if path.name in GUIDE_EXCLUDED_FILENAMES:
                continue
            paths.append(path)
        return sorted(paths, key=lambda item: item.relative_to(root).as_posix())

    def _ingest_guidance_repository_document(
        self,
        repository: Repository,
        source_config: SourceConfig,
        relative_path: str,
        text: str,
        commit_sha: str | None,
    ) -> GuidanceDocument:
        title, body, sections = self._parse_document_title_and_sections(relative_path, text)
        source_url = self._github_blob_url(repository, relative_path, commit_sha)
        canonical_url = self._published_guide_url(relative_path)
        doc = self.session.scalar(
            select(GuidanceDocument).where(GuidanceDocument.canonical_url == canonical_url)
        )
        artifact_type = (
            source_config.artifact_types[0]
            if source_config.artifact_types
            else "operational_guidance"
        )
        metadata = {
            "repository": repository.canonical_full_name,
            "path": relative_path,
            "source_url": source_url,
            "commit_sha": commit_sha,
            "parser": source_config.parser,
        }
        kwargs = {
            "title": title,
            "primary_domain": source_config.primary_domain,
            "artifact_type": artifact_type,
            "canonical_url": canonical_url,
            "raw_text": body,
            "metadata_": metadata,
        }
        if doc is None:
            doc = GuidanceDocument(**kwargs)
            self.session.add(doc)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(doc, key, value)
        self._replace_guidance_sections(doc, sections)
        artifact = self._upsert_repository_document_artifact(
            repository,
            source_config,
            relative_path,
            title,
            body,
            source_url,
            canonical_url,
            artifact_type,
            commit_sha,
            extra_metadata={"guidance_document_id": doc.internal_id},
        )
        self._upsert_source_evidence(
            artifact.internal_id,
            source_url,
            canonical_url,
            f"{repository.canonical_full_name}:{relative_path}",
            body,
            content_hash(text),
            None,
            None,
            fragment=None,
            specification_version=commit_sha,
        )
        return doc

    def _ingest_process_repository_document(
        self,
        repository: Repository,
        source_config: SourceConfig,
        relative_path: str,
        text: str,
        commit_sha: str | None,
    ) -> ProcessDocument:
        title, body, _sections = self._parse_document_title_and_sections(relative_path, text)
        source_url = self._github_blob_url(repository, relative_path, commit_sha)
        canonical_url = self._published_process_url(relative_path)
        effective_date = self._process_effective_date(relative_path)
        edition = effective_date or "editors-draft"
        doc_hash = content_hash(text)
        doc = self.session.scalar(
            select(ProcessDocument).where(ProcessDocument.canonical_url == canonical_url)
        )
        metadata = {
            "repository": repository.canonical_full_name,
            "path": relative_path,
            "source_url": source_url,
            "commit_sha": commit_sha,
            "parser": source_config.parser,
            "source_role": "primary_process_source"
            if relative_path == "index.bs"
            else "historical_process_snapshot",
        }
        kwargs = {
            "title": title,
            "edition": edition,
            "effective_date": effective_date,
            "canonical_url": canonical_url,
            "retrieved_url": source_url,
            "publication_date": effective_date,
            "content_hash": doc_hash,
            "retrieval_date": datetime.now(UTC),
            "applicable_from": effective_date,
            "applicable_to": None,
            "metadata_": metadata,
        }
        if doc is None:
            doc = ProcessDocument(**kwargs)
            self.session.add(doc)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(doc, key, value)
        artifact_type = (
            source_config.artifact_types[0] if source_config.artifact_types else "process_document"
        )
        artifact = self._upsert_repository_document_artifact(
            repository,
            source_config,
            relative_path,
            title,
            body,
            source_url,
            canonical_url,
            artifact_type,
            commit_sha,
            extra_metadata={"process_document_id": doc.internal_id, "effective_date": effective_date},
        )
        self._upsert_source_evidence(
            artifact.internal_id,
            source_url,
            canonical_url,
            f"{repository.canonical_full_name}:{relative_path}",
            body,
            doc_hash,
            None,
            effective_date,
            fragment=None,
            specification_version=commit_sha,
        )
        return doc

    def upsert_repository(
        self, owner: str, name: str, payload: dict[str, Any] | None = None
    ) -> Repository:
        canonical = f"{owner}/{name}"
        repository = self.session.scalar(
            select(Repository).where(Repository.owner == owner, Repository.name == name)
        )
        if repository is None:
            repository = Repository(
                owner=owner,
                name=name,
                original_full_name=(payload or {}).get("full_name"),
                canonical_full_name=canonical,
                html_url=(payload or {}).get("html_url") or f"https://github.com/{canonical}",
                api_url=(payload or {}).get("url"),
                default_branch=(payload or {}).get("default_branch"),
                archived=bool((payload or {}).get("archived", False)),
                raw_payload=payload or {},
            )
            self.session.add(repository)
            self.session.flush()
        return repository

    def ingest_github_issue_payload(
        self,
        owner: str,
        repository_name: str,
        issue_payload: dict[str, Any],
        comments: list[dict[str, Any]] | None = None,
        timeline: list[dict[str, Any]] | None = None,
        primary_domain: str = "cross_cutting",
        artifact_type: str = "tracker_issue",
        applicable_domains: list[str] | None = None,
    ) -> Issue:
        parsed = parse_issue_payload(owner, repository_name, issue_payload)
        repository = self.upsert_repository(owner, repository_name)
        issue = self.session.scalar(
            select(Issue).where(
                Issue.repository_id == repository.internal_id, Issue.number == parsed.number
            )
        )
        issue_kwargs = {
            "repository_id": repository.internal_id,
            "external_id": str(issue_payload.get("id")),
            "number": parsed.number,
            "title": parsed.title,
            "body": parsed.body,
            "author": parsed.author,
            "state": parsed.state,
            "state_reason": parsed.state_reason,
            "labels": parsed.labels,
            "milestone": parsed.milestone,
            "assignees": parsed.assignees,
            "source_url": parsed.source_url,
            "created_source_at": parsed.created_at,
            "updated_source_at": parsed.updated_at,
            "closed_source_at": parsed.closed_at,
            "raw_payload": {
                "issue": parsed.raw_payload,
                "comments": comments or [],
                "timeline": timeline or [],
            },
        }
        if issue is None:
            issue = Issue(**issue_kwargs)
            self.session.add(issue)
            self.session.flush()
        else:
            for key, value in issue_kwargs.items():
                setattr(issue, key, value)
        artifact = self._upsert_artifact_for_issue(
            issue,
            repository,
            primary_domain=primary_domain,
            artifact_type=artifact_type,
            applicable_domains=applicable_domains or [],
        )
        self._upsert_evidence(
            artifact.internal_id,
            issue.source_url,
            issue.source_url,
            f"{repository.canonical_full_name}#{issue.number}",
            issue.body or issue.title,
            issue.content_hash if hasattr(issue, "content_hash") else None,
            issue.author,
            issue.created_source_at,
        )
        for comment_payload in comments or []:
            self._upsert_review_comment_for_issue(issue, artifact, repository, comment_payload)
        for index, timeline_payload in enumerate(timeline or []):
            evidence = self._upsert_timeline_evidence(
                issue, artifact, repository, timeline_payload, index
            )
            self._upsert_timeline_relationships(issue, timeline_payload, evidence.internal_id)
        for ref in extract_github_issue_refs(issue.body or ""):
            if ref["number"]:
                object_id = (
                    f"{ref['owner']}/{ref['repository']}#{ref['number']}"
                    if ref["owner"] and ref["repository"]
                    else str(ref["number"])
                )
                self._upsert_artifact_link(
                    subject_type="issue",
                    subject_id=issue.internal_id,
                    predicate="REFERENCES",
                    object_type="github_issue_ref",
                    object_id=object_id,
                    source=issue.source_url,
                    confidence=0.8,
                    extraction_method="markdown-reference",
                    supporting_evidence=[],
                    is_explicit=True,
                )
        self.session.commit()
        return issue

    def sync_github_repository(
        self,
        adapter,
        owner: str,
        repository_name: str,
        limit: int | None,
        source_config: SourceConfig | None = None,
        incremental: bool = True,
        skip_existing: bool = False,
    ) -> IngestionRun:
        run = IngestionRun(status="running", summary={"repository": f"{owner}/{repository_name}"})
        self.session.add(run)
        self.session.flush()
        imported = 0
        skipped_existing = 0
        comment_count = 0
        timeline_event_count = 0
        cursor = self._get_sync_cursor(source_config) if source_config else None
        since = cursor.cursor_value if incremental and cursor and cursor.cursor_value else None
        hit_limit = False
        started_at = run.started_at or datetime.now(UTC)
        try:
            repository = self.upsert_repository(owner, repository_name)
            for payload in adapter.iter_issues(owner, repository_name, since=since):
                if "pull_request" in payload:
                    continue
                issue_number = int(payload["number"])
                if skip_existing and self.session.scalar(
                    select(Issue).where(
                        Issue.repository_id == repository.internal_id,
                        Issue.number == issue_number,
                    )
                ):
                    skipped_existing += 1
                    continue
                comments = adapter.list_issue_comments(owner, repository_name, issue_number)
                timeline = adapter.list_issue_timeline(owner, repository_name, issue_number)
                self.ingest_github_issue_payload(
                    owner,
                    repository_name,
                    payload,
                    comments=comments,
                    timeline=timeline,
                    primary_domain=source_config.primary_domain
                    if source_config
                    else "cross_cutting",
                    artifact_type=(
                        source_config.artifact_types[0]
                        if source_config and source_config.artifact_types
                        else "tracker_issue"
                    ),
                    applicable_domains=source_config.applicable_domains if source_config else [],
                )
                imported += 1
                comment_count += len(comments)
                timeline_event_count += len(timeline)
                if limit is not None and imported >= limit:
                    hit_limit = True
                    break
        except Exception as exc:
            run.status = "failed"
            run.finished_at = datetime.now(UTC)
            run.summary = {
                "repository": f"{owner}/{repository_name}",
                "imported": imported,
                "skipped_existing": skipped_existing,
                "comments": comment_count,
                "timeline_events": timeline_event_count,
                "error": exc.__class__.__name__,
                "since": since,
            }
            self.session.commit()
            raise
        else:
            cursor_advanced = False
            if cursor is not None and not hit_limit:
                cursor.cursor_value = started_at.isoformat()
                cursor.metadata_ = {
                    **(cursor.metadata_ or {}),
                    "repository": f"{owner}/{repository_name}",
                    "last_status": "completed",
                    "last_imported": imported,
                    "last_sync_finished_at": datetime.now(UTC).isoformat(),
                    "last_rate_limit": getattr(adapter, "rate_limit", {}),
                }
                cursor_advanced = True
            run.status = "completed"
            run.finished_at = datetime.now(UTC)
            run.summary = {
                "repository": f"{owner}/{repository_name}",
                "imported": imported,
                "skipped_existing": skipped_existing,
                "comments": comment_count,
                "timeline_events": timeline_event_count,
                "primary_domain": source_config.primary_domain
                if source_config
                else "cross_cutting",
                "since": since,
                "cursor_advanced": cursor_advanced,
                "hit_limit": hit_limit,
                "includes_closed": True,
            }
            self.session.commit()
            return run

    def sync_github_domain(
        self,
        adapter,
        domain: str,
        sources: list[SourceConfig],
        limit_per_repository: int | None,
        incremental: bool = True,
    ) -> IngestionRun:
        run = IngestionRun(status="running", summary={"domain": domain})
        self.session.add(run)
        self.session.flush()
        repository_summaries: list[dict[str, Any]] = []
        try:
            for source_config in sources:
                if not (
                    source_config.enabled
                    and source_config.source_type == "github_repository"
                    and source_config.parser == "github_issue"
                    and source_config.organization
                    and source_config.repository
                    and (
                        source_config.primary_domain == domain
                        or domain in source_config.applicable_domains
                    )
                ):
                    continue
                repository_run = self.sync_github_repository(
                    adapter,
                    source_config.organization,
                    source_config.repository,
                    limit=limit_per_repository,
                    source_config=source_config,
                    incremental=incremental,
                )
                repository_summaries.append(repository_run.summary)
        except Exception as exc:
            run.status = "failed"
            run.finished_at = datetime.now(UTC)
            run.summary = {
                "domain": domain,
                "repositories": repository_summaries,
                "error": exc.__class__.__name__,
            }
            self.session.commit()
            raise
        else:
            run.status = "completed"
            run.finished_at = datetime.now(UTC)
            run.summary = {
                "domain": domain,
                "repositories": repository_summaries,
                "repository_count": len(repository_summaries),
                "imported": sum(item.get("imported", 0) for item in repository_summaries),
                "comments": sum(item.get("comments", 0) for item in repository_summaries),
                "timeline_events": sum(
                    item.get("timeline_events", 0) for item in repository_summaries
                ),
                "includes_closed": True,
            }
            self.session.commit()
            return run

    def backfill_repository_issue_artifacts(
        self,
        owner: str,
        repository_name: str,
        source_config: SourceConfig,
    ) -> IngestionRun:
        run = IngestionRun(
            status="running",
            summary={
                "operation": "backfill_repository_issue_artifacts",
                "repository": f"{owner}/{repository_name}",
            },
        )
        self.session.add(run)
        self.session.flush()
        repository = self.session.scalar(
            select(Repository).where(Repository.owner == owner, Repository.name == repository_name)
        )
        updated = 0
        if repository is not None:
            artifact_type = (
                source_config.artifact_types[0]
                if source_config.artifact_types
                else "tracker_issue"
            )
            for issue in self.session.scalars(
                select(Issue).where(Issue.repository_id == repository.internal_id)
            ):
                artifact = self._upsert_artifact_for_issue(
                    issue,
                    repository,
                    primary_domain=source_config.primary_domain,
                    artifact_type=artifact_type,
                    applicable_domains=source_config.applicable_domains,
                )
                self._upsert_evidence(
                    artifact.internal_id,
                    issue.source_url,
                    issue.source_url,
                    f"{repository.canonical_full_name}#{issue.number}",
                    issue.body or issue.title,
                    None,
                    issue.author,
                    issue.created_source_at,
                )
                updated += 1
        run.status = "completed"
        run.finished_at = datetime.now(UTC)
        run.summary = {
            "operation": "backfill_repository_issue_artifacts",
            "repository": f"{owner}/{repository_name}",
            "updated": updated,
            "artifact_type": source_config.artifact_types[0]
            if source_config.artifact_types
            else "tracker_issue",
        }
        self.session.commit()
        return run

    def normalize_stored_github_timelines(self, limit: int | None = None) -> IngestionRun:
        run = IngestionRun(
            status="running", summary={"operation": "normalize_stored_github_timelines"}
        )
        self.session.add(run)
        self.session.flush()
        processed_issues = 0
        processed_events = 0
        stmt = select(Issue).order_by(Issue.updated_at.desc())
        if limit is not None:
            stmt = stmt.limit(limit)
        for issue in self.session.scalars(stmt):
            timeline = (issue.raw_payload or {}).get("timeline") or []
            if not timeline:
                continue
            repository = self.session.get(Repository, issue.repository_id)
            if repository is None:
                continue
            artifact = self.session.scalar(
                select(Artifact).where(
                    Artifact.external_id == f"{repository.canonical_full_name}#{issue.number}"
                )
            )
            if artifact is None:
                continue
            processed_issues += 1
            for index, payload in enumerate(timeline):
                if not isinstance(payload, dict):
                    continue
                evidence = self._upsert_timeline_evidence(
                    issue, artifact, repository, payload, index
                )
                self._upsert_timeline_relationships(issue, payload, evidence.internal_id)
                processed_events += 1
        run.status = "completed"
        run.finished_at = datetime.now(UTC)
        run.summary = {
            "operation": "normalize_stored_github_timelines",
            "issues": processed_issues,
            "timeline_events": processed_events,
        }
        self.session.commit()
        return run

    def materialize_external_github_refs(self, adapter, limit: int | None = 50) -> IngestionRun:
        run = IngestionRun(
            status="running", summary={"operation": "materialize_external_github_refs"}
        )
        self.session.add(run)
        self.session.flush()
        refs = self.session.scalars(
            select(ArtifactLink)
            .where(
                ArtifactLink.object_type.in_(
                    ["github_issue_ref", "github_pull_request_ref", "github_commit_ref"]
                )
            )
            .order_by(ArtifactLink.created_at.asc())
        ).all()
        if limit is not None:
            refs = refs[:limit]
        summary: dict[str, Any] = {
            "operation": "materialize_external_github_refs",
            "processed": 0,
            "skipped": 0,
            "issues": 0,
            "pull_requests": 0,
            "pull_request_reviews": 0,
            "commits": 0,
            "errors": 0,
            "error_refs": [],
        }
        for link in refs:
            try:
                if link.object_type == "github_issue_ref":
                    materialized = self._materialize_issue_ref(adapter, link)
                elif link.object_type == "github_pull_request_ref":
                    materialized = self._materialize_pull_request_ref(adapter, link)
                else:
                    materialized = self._materialize_commit_ref(adapter, link)
            except Exception as exc:
                summary["errors"] += 1
                if len(summary["error_refs"]) < 10:
                    summary["error_refs"].append(
                        {
                            "object_type": link.object_type,
                            "object_id": link.object_id,
                            "error": exc.__class__.__name__,
                        }
                    )
                continue
            if not materialized:
                summary["skipped"] += 1
                continue
            summary["processed"] += 1
            for key, value in materialized.items():
                summary[key] += value
        summary["rate_limit"] = getattr(adapter, "rate_limit", {})
        run.status = "completed"
        run.finished_at = datetime.now(UTC)
        run.summary = summary
        self.session.commit()
        return run

    def normalize_review_findings(self, limit: int | None = None) -> IngestionRun:
        run = IngestionRun(status="running", summary={"operation": "normalize_review_findings"})
        self.session.add(run)
        self.session.flush()
        processed = 0
        findings = 0
        reviews = 0
        mirrored_links = 0
        comment_links = 0
        stmt = select(Issue).order_by(Issue.updated_at.desc())
        if limit is not None:
            stmt = stmt.limit(limit)
        for issue in self.session.scalars(stmt):
            repository = self.session.get(Repository, issue.repository_id)
            if repository is None:
                continue
            artifact = self.session.scalar(
                select(Artifact).where(
                    Artifact.external_id == f"{repository.canonical_full_name}#{issue.number}"
                )
            )
            if artifact is None or artifact.artifact_type not in {
                "review_request",
                "tracker_issue",
                "horizontal_review",
                "review_finding",
            }:
                continue
            processed += 1
            review_request = self._upsert_review_request_for_issue(issue, repository, artifact)
            review, review_created = self._upsert_review_for_request(review_request, artifact)
            if review_created:
                reviews += 1
            finding, finding_created = self._upsert_review_finding_for_issue(
                issue, repository, artifact, review
            )
            if finding_created:
                findings += 1
            comment_links += self._link_review_comments_for_issue(issue, review)
            self._upsert_artifact_link(
                subject_type="review",
                subject_id=review.internal_id,
                predicate="HAS_FINDING",
                object_type="review_finding",
                object_id=finding.internal_id,
                source=issue.source_url,
                confidence=0.9,
                extraction_method="rule-based-review-finding-normalizer",
                supporting_evidence=[],
                is_explicit=True,
            )
            self._upsert_artifact_link(
                subject_type="review_finding",
                subject_id=finding.internal_id,
                predicate="RAISED_IN",
                object_type="issue",
                object_id=issue.internal_id,
                source=issue.source_url,
                confidence=0.95,
                extraction_method="rule-based-review-finding-normalizer",
                supporting_evidence=[],
                is_explicit=True,
            )
            mirrored_links += self._mirror_issue_resolution_links_to_finding(issue, finding)
        run.status = "completed"
        run.finished_at = datetime.now(UTC)
        run.summary = {
            "operation": "normalize_review_findings",
            "processed_issues": processed,
            "reviews": reviews,
            "findings": findings,
            "mirrored_links": mirrored_links,
            "comment_links": comment_links,
        }
        self.session.commit()
        return run

    def _link_review_comments_for_issue(self, issue: Issue, review: Review) -> int:
        linked = 0
        comments = self.session.scalars(
            select(ReviewComment).where(
                ReviewComment.review_id.is_(None),
                ReviewComment.source_url.like(f"{issue.source_url}#%"),
            )
        )
        for comment in comments:
            comment.review_id = review.internal_id
            linked += 1
        return linked

    @staticmethod
    def normalize_rfc_number(value: str | int) -> int:
        if isinstance(value, int):
            return value
        match = re.search(r"RFC\s*-?(\d+)|^rfc-?(\d+)$|^(\d+)$", value.strip(), re.I)
        if not match:
            raise ValueError(f"Invalid RFC identifier: {value}")
        return int(next(group for group in match.groups() if group))

    @staticmethod
    def rfc_numbers_from_reference(reference: SpecificationReference) -> list[int]:
        values = [
            reference.label or "",
            reference.title or "",
            reference.url or "",
            str(reference.metadata_ or {}),
        ]
        numbers: set[int] = set()
        for value in values:
            for match in re.finditer(
                r"(?:\bRFC\s*-?(\d{3,5})\b|\bRFC(\d{3,5})\b|/rfc/rfc(\d{3,5})(?:[./#?]|$)|rfc(\d{3,5})\.(?:html|txt|xml|pdf|json)\b)",
                value,
                re.I,
            ):
                numbers.add(int(next(group for group in match.groups() if group)))
        return sorted(numbers)

    def discover_referenced_rfc_numbers(self, *, include_rfc_sources: bool = False) -> list[int]:
        numbers: set[int] = set()
        rows = self.session.execute(
            select(SpecificationReference, Specification)
            .join(
                SpecificationVersion,
                SpecificationVersion.internal_id == SpecificationReference.specification_version_id,
            )
            .join(Specification, Specification.internal_id == SpecificationVersion.specification_id)
        )
        for reference, spec in rows:
            if not include_rfc_sources and (
                spec.shortname.lower().startswith("rfc")
                or (spec.metadata_ or {}).get("source_family") == "rfc_editor"
            ):
                continue
            numbers.update(self.rfc_numbers_from_reference(reference))
        return sorted(numbers)

    def _persist_rfc_publication(
        self,
        metadata_doc: DownloadedRFCMetadata,
        content_doc: DownloadedRFCDocument,
        parsed: ParsedSpecification | None,
    ) -> SpecificationVersion:
        metadata = metadata_doc.metadata
        shortname = f"rfc{metadata.number}"
        version = metadata.doc_id
        canonical_url = f"https://www.rfc-editor.org/rfc/rfc{metadata.number}"
        status = metadata.status or metadata.pub_status
        title = parsed.title if parsed is not None else metadata.title
        body_text = (
            parsed.text
            if parsed is not None
            else "\n\n".join(item for item in [metadata.title, metadata.abstract or ""] if item)
        )
        spec = self.session.scalar(
            select(Specification).where(Specification.shortname == shortname)
        )
        aliases = self._rfc_aliases(metadata)
        if spec is None:
            spec = Specification(
                shortname=shortname,
                title=title,
                aliases=aliases,
                publication_status=status,
                current_published_url=canonical_url,
                editors_draft_url=None,
                metadata_={},
            )
            self.session.add(spec)
            self.session.flush()
        spec.title = title
        spec.aliases = aliases
        spec.publication_status = status
        spec.current_published_url = canonical_url
        spec.metadata_ = self._rfc_metadata_dict(metadata)
        spec_version = self._existing_spec_version(shortname, version)
        version_metadata = {
            **self._rfc_metadata_dict(metadata),
            "raw_status": metadata.status,
            "normalized_status": metadata.status,
            "latest_tr_url": canonical_url,
            "immutable_tr_url": canonical_url,
            "final_url": content_doc.final_url,
            "retrieved_at": datetime.now(UTC).isoformat(),
            "source_family": "rfc_editor",
            "content_format": content_doc.content_format,
            "content_url": content_doc.url,
            "content_final_url": content_doc.final_url,
            "content_etag": content_doc.etag,
            "content_last_modified": content_doc.last_modified,
            "metadata_url": metadata_doc.url,
            "metadata_final_url": metadata_doc.final_url,
            "metadata_etag": metadata_doc.etag,
            "metadata_last_modified": metadata_doc.last_modified,
            "metadata_json_hash": metadata_doc.content_hash,
            "content_hash": content_doc.content_hash,
            "source_urls": {"metadata": metadata_doc.final_url, "content": content_doc.final_url},
        }
        if spec_version is None:
            spec_version = SpecificationVersion(
                specification_id=spec.internal_id,
                version=version,
                publication_status=metadata.pub_status or metadata.status,
                publication_date=metadata.pub_date,
                source_url=content_doc.final_url,
                canonical_url=canonical_url,
                source_commit=None,
                content_hash=content_doc.content_hash
                if parsed is not None
                else metadata_doc.content_hash,
                raw_text=body_text,
                metadata_=version_metadata,
            )
            self.session.add(spec_version)
            self.session.flush()
        else:
            spec_version.publication_status = metadata.pub_status or metadata.status
            spec_version.publication_date = metadata.pub_date
            spec_version.source_url = content_doc.final_url
            spec_version.canonical_url = canonical_url
            spec_version.content_hash = (
                content_doc.content_hash if parsed is not None else metadata_doc.content_hash
            )
            spec_version.raw_text = body_text
            spec_version.metadata_ = version_metadata
        artifact = self._upsert_rfc_artifact(
            spec, spec_version, metadata_doc, content_doc, title, body_text
        )
        metadata_evidence = self._upsert_source_evidence(
            artifact.internal_id,
            metadata_doc.final_url,
            metadata_doc.final_url,
            f"rfc-editor:{shortname}:{version}:metadata",
            metadata_doc.text,
            metadata_doc.content_hash,
            None,
            metadata.pub_date,
            fragment=None,
            specification_version=version,
        )
        if parsed is not None:
            content_evidence = self._upsert_source_evidence(
                artifact.internal_id,
                content_doc.final_url,
                canonical_url,
                f"rfc-editor:{shortname}:{version}:content:{content_doc.content_format}",
                content_doc.text,
                content_doc.content_hash,
                None,
                metadata.pub_date,
                fragment=None,
                specification_version=version,
            )
            self._persist_tr_sections(
                spec,
                spec_version,
                parsed,
                artifact,
                content_doc.final_url,
                content_evidence.internal_id,
                source_prefix="rfc-editor",
                section_source_type="rfc_editor",
            )
            self._persist_tr_references(
                spec_version, parsed, content_doc.final_url, metadata_evidence.internal_id
            )
            self._persist_tr_consideration_statuses(
                spec_version, parsed, content_evidence.internal_id
            )
        else:
            for consideration_type in [
                "security",
                "privacy",
                "accessibility",
                "internationalization",
            ]:
                existing = self.session.scalar(
                    select(SpecificationConsiderationStatus).where(
                        SpecificationConsiderationStatus.specification_version_id
                        == spec_version.internal_id,
                        SpecificationConsiderationStatus.consideration_type == consideration_type,
                    )
                )
                kwargs: dict[str, Any] = {
                    "specification_version_id": spec_version.internal_id,
                    "consideration_type": consideration_type,
                    "status": "unable_to_parse",
                    "section_id": None,
                    "source_url": metadata_doc.final_url,
                    "evidence_ids": [metadata_evidence.internal_id],
                    "metadata_": {"reason": "metadata_only"},
                }
                if existing is None:
                    self.session.add(SpecificationConsiderationStatus(**kwargs))
                else:
                    for key, value in kwargs.items():
                        setattr(existing, key, value)
        self.session.flush()
        return spec_version

    def _persist_rfc_metadata_only(
        self,
        metadata_doc: DownloadedRFCMetadata,
        existing: SpecificationVersion,
        *,
        content_doc: DownloadedRFCDocument | None = None,
    ) -> SpecificationVersion:
        metadata = metadata_doc.metadata
        spec = self.session.get(Specification, existing.specification_id)
        if spec is not None:
            spec.title = metadata.title
            spec.aliases = self._rfc_aliases(metadata)
            spec.publication_status = metadata.status or metadata.pub_status
            spec.metadata_ = self._rfc_metadata_dict(metadata)
        existing.publication_status = metadata.pub_status or metadata.status
        existing.publication_date = metadata.pub_date
        existing.metadata_ = {
            **(existing.metadata_ or {}),
            **self._rfc_metadata_dict(metadata),
            "metadata_url": metadata_doc.url,
            "metadata_final_url": metadata_doc.final_url,
            "metadata_etag": metadata_doc.etag,
            "metadata_last_modified": metadata_doc.last_modified,
            "metadata_json_hash": metadata_doc.content_hash,
            "retrieved_at": datetime.now(UTC).isoformat(),
        }
        if content_doc is not None:
            existing.metadata_ = {
                **existing.metadata_,
                "content_etag": content_doc.etag,
                "content_last_modified": content_doc.last_modified,
                "content_final_url": content_doc.final_url,
            }
        artifact = self.session.scalar(
            select(Artifact).where(
                Artifact.external_id == f"rfc-editor:rfc{metadata.number}:{metadata.doc_id}"
            )
        )
        if artifact is None and spec is not None:
            content_placeholder = content_doc or DownloadedRFCDocument(
                number=metadata.number,
                url=existing.source_url,
                final_url=existing.source_url,
                text=existing.raw_text,
                content_format=existing.metadata_.get("content_format", "unknown"),
                content_type="text/plain",
                etag=None,
                last_modified=None,
                status="downloaded",
                content_hash=existing.content_hash,
            )
            artifact = self._upsert_rfc_artifact(
                spec, existing, metadata_doc, content_placeholder, metadata.title, existing.raw_text
            )
        if artifact is not None:
            self._upsert_source_evidence(
                artifact.internal_id,
                metadata_doc.final_url,
                metadata_doc.final_url,
                f"rfc-editor:rfc{metadata.number}:{metadata.doc_id}:metadata",
                metadata_doc.text,
                metadata_doc.content_hash,
                None,
                metadata.pub_date,
                fragment=None,
                specification_version=metadata.doc_id,
            )
        self.session.flush()
        return existing

    def _upsert_rfc_artifact(
        self,
        spec: Specification,
        spec_version: SpecificationVersion,
        metadata_doc: DownloadedRFCMetadata,
        content_doc: DownloadedRFCDocument,
        title: str,
        text: str,
    ) -> Artifact:
        metadata = metadata_doc.metadata
        external_id = f"rfc-editor:{spec.shortname}:{spec_version.version}"
        artifact = self.session.scalar(select(Artifact).where(Artifact.external_id == external_id))
        kwargs = {
            "external_id": external_id,
            "source_type": "rfc_editor",
            "artifact_type": "specification_snapshot",
            "primary_domain": "cross_cutting",
            "applicable_domains": ["cross_cutting"],
            "source_url": content_doc.final_url,
            "canonical_url": f"https://www.rfc-editor.org/rfc/rfc{metadata.number}",
            "title": title,
            "raw_text": text,
            "normalized_text": text.lower(),
            "raw_payload": {"metadata": metadata.raw_payload},
            "retrieved_at": datetime.now(UTC),
            "content_hash": content_doc.content_hash
            if content_doc.content_format != "metadata-only"
            else metadata_doc.content_hash,
            "version": spec_version.version,
            "commit_sha": None,
            "provenance": {
                "shortname": spec.shortname,
                "specification_version_id": spec_version.internal_id,
                "source_family": "rfc_editor",
            },
            "confidence": 1.0,
            "metadata_": {
                **self._rfc_metadata_dict(metadata),
                "content_format": content_doc.content_format,
                "metadata_json_hash": metadata_doc.content_hash,
                "content_hash": content_doc.content_hash,
            },
        }
        if artifact is None:
            artifact = Artifact(**kwargs)
            self.session.add(artifact)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(artifact, key, value)
        return artifact

    def _materialize_rfc_links(
        self,
        metadata: RFCMetadata,
        spec_version: SpecificationVersion,
        metadata_hash: str,
    ) -> None:
        spec = self.session.get(Specification, spec_version.specification_id)
        if spec is None:
            return
        evidence = self.session.scalar(
            select(SourceEvidence).where(
                SourceEvidence.source_artifact_id
                == f"rfc-editor:rfc{metadata.number}:{metadata.doc_id}:metadata"
            )
        )
        evidence_ids = [evidence.internal_id] if evidence is not None else [metadata_hash]
        for predicate, targets in [
            ("OBSOLETES", metadata.obsoletes),
            ("OBSOLETED_BY", metadata.obsoleted_by),
            ("UPDATES", metadata.updates),
            ("UPDATED_BY", metadata.updated_by),
        ]:
            for target_number in targets:
                target_spec = self.session.scalar(
                    select(Specification).where(Specification.shortname == f"rfc{target_number}")
                )
                self._upsert_artifact_link(
                    "specification",
                    spec.internal_id,
                    predicate,
                    "specification" if target_spec else "rfc_ref",
                    target_spec.internal_id if target_spec else f"rfc{target_number}",
                    f"https://www.rfc-editor.org/rfc/rfc{metadata.number}.json",
                    1.0,
                    "rfc_editor_metadata",
                    evidence_ids,
                    True,
                )
        for see_also in metadata.see_also:
            see_also_number: int | None = None
            match = re.search(r"RFC\s*-?(\d+)", see_also, re.I)
            if match:
                see_also_number = int(match.group(1))
            target_spec = (
                self.session.scalar(
                    select(Specification).where(Specification.shortname == f"rfc{see_also_number}")
                )
                if see_also_number
                else None
            )
            self._upsert_artifact_link(
                "specification",
                spec.internal_id,
                "SEE_ALSO",
                "specification" if target_spec else "external_identifier",
                target_spec.internal_id if target_spec else see_also,
                f"https://www.rfc-editor.org/rfc/rfc{metadata.number}.json",
                1.0,
                "rfc_editor_metadata",
                evidence_ids,
                True,
            )

    def _materialize_rfc_reference_links(self, number: int) -> None:
        rfc_spec = self.session.scalar(
            select(Specification).where(Specification.shortname == f"rfc{number}")
        )
        if rfc_spec is None:
            return
        rows = self.session.execute(
            select(SpecificationReference, Specification)
            .join(
                SpecificationVersion,
                SpecificationVersion.internal_id == SpecificationReference.specification_version_id,
            )
            .join(Specification, Specification.internal_id == SpecificationVersion.specification_id)
        )
        for reference, spec in rows:
            if (
                spec.shortname.lower().startswith("rfc")
                or (spec.metadata_ or {}).get("source_family") == "rfc_editor"
            ):
                continue
            if number not in self.rfc_numbers_from_reference(reference):
                continue
            self._upsert_artifact_link(
                "specification_version",
                reference.specification_version_id,
                "REFERENCES",
                "specification",
                rfc_spec.internal_id,
                reference.source_url or reference.url or "",
                1.0,
                "rfc_reference_resolver",
                reference.evidence_ids or [],
                True,
            )

    def _rfc_aliases(self, metadata: RFCMetadata) -> list[str]:
        aliases = [f"RFC {metadata.number}", f"RFC{metadata.number}"]
        aliases.extend(
            item for item in metadata.see_also if re.match(r"^(STD|BCP|FYI)\s*-?\d+$", item, re.I)
        )
        return sorted(set(aliases))

    def _rfc_metadata_dict(self, metadata: RFCMetadata) -> dict[str, Any]:
        return {
            "doc_id": metadata.doc_id,
            "title": metadata.title,
            "authors": metadata.authors,
            "abstract": metadata.abstract,
            "pub_date": metadata.pub_date,
            "pub_status": metadata.pub_status,
            "status": metadata.status,
            "stream": metadata.stream,
            "source": metadata.source,
            "formats": metadata.formats,
            "page_count": metadata.page_count,
            "keywords": metadata.keywords,
            "obsoletes": metadata.obsoletes,
            "obsoleted_by": metadata.obsoleted_by,
            "updates": metadata.updates,
            "updated_by": metadata.updated_by,
            "see_also": metadata.see_also,
            "doi": metadata.doi,
            "errata_url": metadata.errata_url,
        }

    def _normalize_tr_status(self, raw_status: str | None, payload: dict[str, Any]) -> str | None:
        if raw_status in {"REC", "CR", "CRD", "WD"}:
            return raw_status
        if raw_status == "Recommendation":
            return "REC"
        if raw_status in {"CRS", "Candidate Recommendation Snapshot"}:
            payload_text = str(payload).lower()
            if (
                "candidate recommendation snapshot" in payload_text
                or raw_status == "Candidate Recommendation Snapshot"
            ):
                return "CR"
        if raw_status == "Candidate Recommendation Draft":
            return "CRD"
        if raw_status == "Working Draft":
            return "WD"
        return raw_status

    def _existing_spec_version(self, shortname: str, version: str) -> SpecificationVersion | None:
        spec = self.session.scalar(
            select(Specification).where(Specification.shortname == shortname)
        )
        if spec is None:
            return None
        return self.session.scalar(
            select(SpecificationVersion).where(
                SpecificationVersion.specification_id == spec.internal_id,
                SpecificationVersion.version == version,
            )
        )

    def _upsert_tr_api_artifact(
        self,
        shortname: str,
        spec_meta: W3CSpecificationMetadata,
        latest: W3CLatestVersion,
        discovery_item: dict[str, Any],
        *,
        state: str,
    ) -> Artifact:
        external_id = f"w3c-tr:{shortname}:api"
        artifact = self.session.scalar(select(Artifact).where(Artifact.external_id == external_id))
        raw_payload = {
            "discovery": discovery_item.get("raw_payload") or {},
            "specification": spec_meta.raw_payload,
            "latest": latest.raw_payload,
        }
        kwargs = {
            "external_id": external_id,
            "source_type": "w3c_api",
            "artifact_type": "specification",
            "primary_domain": "cross_cutting",
            "applicable_domains": ["cross_cutting"],
            "source_url": latest.api_url or spec_meta.url,
            "canonical_url": latest.api_url or spec_meta.url,
            "title": spec_meta.title,
            "raw_text": spec_meta.title,
            "normalized_text": spec_meta.title.lower(),
            "raw_payload": raw_payload,
            "retrieved_at": datetime.now(UTC),
            "content_hash": content_hash(str(raw_payload)),
            "version": latest.version,
            "commit_sha": None,
            "provenance": {"shortname": shortname, "state": state},
            "confidence": 1.0,
            "metadata_": {
                "raw_status": latest.raw_status,
                "publication_date": latest.publication_date,
                "state": state,
            },
        }
        if artifact is None:
            artifact = Artifact(**kwargs)
            self.session.add(artifact)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(artifact, key, value)
        return artifact

    def _persist_tr_publication(
        self,
        shortname: str,
        spec_meta: W3CSpecificationMetadata,
        latest: W3CLatestVersion,
        parsed: ParsedSpecification,
        html: str,
        final_url: str,
        normalized_status: str,
        etag: str | None,
        last_modified: str | None,
        discovery_item: dict[str, Any],
        *,
        source_prefix: str = "w3c-tr",
        document_source_type: str = "w3c_tr",
        persist_api_evidence: bool = True,
    ) -> SpecificationVersion:
        spec = self.session.scalar(
            select(Specification).where(Specification.shortname == shortname)
        )
        if spec is None:
            spec = Specification(
                shortname=shortname,
                title=parsed.title or latest.title or spec_meta.title,
                aliases=[],
                publication_status=normalized_status,
                current_published_url=latest.latest_tr_url or latest.tr_url,
                editors_draft_url=parsed.metadata.get("editors_draft_url")
                or spec_meta.editors_draft,
                metadata_={},
            )
            self.session.add(spec)
            self.session.flush()
        spec.title = parsed.title or latest.title or spec.title
        spec.publication_status = normalized_status
        spec.current_published_url = latest.latest_tr_url or latest.tr_url
        spec.editors_draft_url = parsed.metadata.get("editors_draft_url") or spec_meta.editors_draft
        spec.metadata_ = {
            **(spec.metadata_ or {}),
            "latest_publication_url": latest.tr_url,
            "source_repository_url": parsed.metadata.get("source_repository_url"),
        }
        version_hash = content_hash(html)
        spec_version = self._existing_spec_version(shortname, latest.version)
        metadata = {
            "raw_status": latest.raw_status,
            "normalized_status": normalized_status,
            "latest_tr_url": latest.latest_tr_url,
            "immutable_tr_url": latest.tr_url,
            "final_url": final_url,
            "etag": etag,
            "last_modified": last_modified,
            "retrieved_at": datetime.now(UTC).isoformat(),
            "html_content_hash": version_hash,
            "source_family": document_source_type,
            "api_payload": {
                "discovery": discovery_item.get("raw_payload") or {},
                "latest": latest.raw_payload,
            },
            **parsed.metadata,
        }
        if spec_version is None:
            spec_version = SpecificationVersion(
                specification_id=spec.internal_id,
                version=latest.version,
                publication_status=normalized_status,
                publication_date=latest.publication_date,
                source_url=final_url,
                canonical_url=latest.tr_url,
                source_commit=None,
                content_hash=version_hash,
                raw_text=parsed.text,
                metadata_=metadata,
            )
            self.session.add(spec_version)
            self.session.flush()
        else:
            spec_version.publication_status = normalized_status
            spec_version.publication_date = latest.publication_date
            spec_version.source_url = final_url
            spec_version.canonical_url = latest.tr_url
            spec_version.content_hash = version_hash
            spec_version.raw_text = parsed.text
            spec_version.metadata_ = metadata
        artifact = self._upsert_tr_document_artifact(
            spec,
            spec_version,
            parsed,
            html,
            final_url,
            latest,
            normalized_status,
            source_prefix=source_prefix,
            document_source_type=document_source_type,
        )
        reference_evidence_id: str
        if persist_api_evidence:
            api_evidence = self._upsert_source_evidence(
                artifact.internal_id,
                latest.api_url
                or spec_meta.url
                or f"https://api.w3.org/specifications/{shortname}/versions/latest",
                latest.api_url or spec_meta.url or "",
                f"w3c-api:{shortname}:latest",
                str(latest.raw_payload),
                content_hash(str(latest.raw_payload)),
                None,
                latest.publication_date,
                fragment=None,
                specification_version=latest.version,
            )
            reference_evidence_id = api_evidence.internal_id
        else:
            reference_evidence_id = ""
        html_evidence = self._upsert_source_evidence(
            artifact.internal_id,
            final_url,
            latest.tr_url or final_url,
            f"{source_prefix}:{shortname}:{latest.version}:html",
            html,
            version_hash,
            None,
            latest.publication_date,
            fragment=None,
            specification_version=latest.version,
        )
        if not reference_evidence_id:
            reference_evidence_id = html_evidence.internal_id
        self._persist_tr_sections(
            spec,
            spec_version,
            parsed,
            artifact,
            final_url,
            html_evidence.internal_id,
            source_prefix=source_prefix,
            section_source_type=document_source_type,
        )
        self._persist_tr_idl_blocks(spec_version, parsed, final_url, html_evidence.internal_id)
        self._persist_tr_references(spec_version, parsed, final_url, reference_evidence_id)
        self._persist_tr_consideration_statuses(spec_version, parsed, html_evidence.internal_id)
        self.session.flush()
        return spec_version

    def _upsert_tr_document_artifact(
        self,
        spec: Specification,
        spec_version: SpecificationVersion,
        parsed: ParsedSpecification,
        html: str,
        final_url: str,
        latest: W3CLatestVersion,
        normalized_status: str,
        *,
        source_prefix: str = "w3c-tr",
        document_source_type: str = "w3c_tr",
    ) -> Artifact:
        external_id = f"{source_prefix}:{spec.shortname}:{spec_version.version}"
        artifact = self.session.scalar(select(Artifact).where(Artifact.external_id == external_id))
        kwargs = {
            "external_id": external_id,
            "source_type": document_source_type,
            "artifact_type": "specification_snapshot",
            "primary_domain": "cross_cutting",
            "applicable_domains": ["cross_cutting"],
            "source_url": final_url,
            "canonical_url": latest.tr_url or final_url,
            "title": parsed.title,
            "raw_text": parsed.text,
            "normalized_text": parsed.text.lower(),
            "raw_payload": {"html": html},
            "retrieved_at": datetime.now(UTC),
            "content_hash": content_hash(html),
            "version": spec_version.version,
            "commit_sha": None,
            "provenance": {
                "shortname": spec.shortname,
                "specification_version_id": spec_version.internal_id,
                "source_family": document_source_type,
            },
            "confidence": 1.0,
            "metadata_": {
                "raw_status": latest.raw_status,
                "normalized_status": normalized_status,
                "publication_date": latest.publication_date,
                "latest_tr_url": latest.latest_tr_url,
            },
        }
        if artifact is None:
            artifact = Artifact(**kwargs)
            self.session.add(artifact)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(artifact, key, value)
        return artifact

    def _persist_tr_sections(
        self,
        spec: Specification,
        spec_version: SpecificationVersion,
        parsed: ParsedSpecification,
        document_artifact: Artifact,
        final_url: str,
        html_evidence_id: str,
        *,
        source_prefix: str = "w3c-tr",
        section_source_type: str = "w3c_tr",
    ) -> None:
        section_by_anchor: dict[str, SpecificationSection] = {}
        for section in parsed.sections:
            source_url = f"{final_url}#{section.anchor}" if section.anchor else final_url
            evidence = self._upsert_source_evidence(
                document_artifact.internal_id,
                source_url,
                source_url,
                f"{source_prefix}:{spec.shortname}:{spec_version.version}:section:{section.anchor}",
                section.text,
                section.content_hash,
                None,
                spec_version.publication_date,
                fragment=section.anchor,
                specification_version=spec_version.version,
            )
            existing = self.session.scalar(
                select(SpecificationSection).where(
                    SpecificationSection.specification_version_id == spec_version.internal_id,
                    SpecificationSection.anchor == section.anchor,
                )
            )
            parent = section_by_anchor.get(section.parent_anchor or "")
            parent_id = parent.internal_id if parent else None
            kwargs: dict[str, Any] = {
                "specification_version_id": spec_version.internal_id,
                "heading": section.heading,
                "anchor": section.anchor,
                "parent_section_id": parent_id,
                "heading_level": section.heading_level,
                "display_number": section.display_number,
                "source_url": source_url,
                "raw_text": section.text,
                "normalized_text": section.text.lower(),
                "raw_html": section.raw_html,
                "section_type": section.section_type,
                "order": section.order,
                "content_hash": section.content_hash,
                "normative": section.normative,
                "evidence_ids": [html_evidence_id, evidence.internal_id],
                "metadata_": {},
            }
            if existing is None:
                existing = SpecificationSection(**kwargs)
                self.session.add(existing)
                self.session.flush()
            else:
                for key, value in kwargs.items():
                    setattr(existing, key, value)
            section_by_anchor[section.anchor] = existing
            self._upsert_section_artifact(
                spec,
                spec_version,
                existing,
                evidence.internal_id,
                source_prefix=source_prefix,
                section_source_type=section_source_type,
            )

    def _upsert_section_artifact(
        self,
        spec: Specification,
        spec_version: SpecificationVersion,
        section: SpecificationSection,
        evidence_id: str,
        *,
        source_prefix: str = "w3c-tr",
        section_source_type: str = "w3c_tr",
    ) -> None:
        external_id = (
            f"{source_prefix}:{spec.shortname}:{spec_version.version}:section:{section.anchor}"
        )
        artifact = self.session.scalar(select(Artifact).where(Artifact.external_id == external_id))
        kwargs = {
            "external_id": external_id,
            "source_type": section_source_type,
            "artifact_type": "specification_section",
            "primary_domain": "cross_cutting",
            "applicable_domains": ["cross_cutting"],
            "source_url": section.source_url,
            "canonical_url": section.source_url,
            "title": f"{spec.shortname}: {section.heading}",
            "raw_text": section.raw_text,
            "normalized_text": section.normalized_text,
            "raw_payload": {},
            "retrieved_at": datetime.now(UTC),
            "content_hash": section.content_hash,
            "version": spec_version.version,
            "commit_sha": None,
            "provenance": {
                "shortname": spec.shortname,
                "specification_version_id": spec_version.internal_id,
                "section_id": section.internal_id,
                "evidence_ids": [evidence_id],
            },
            "confidence": 1.0,
            "metadata_": {"section_type": section.section_type, "normative": section.normative},
        }
        if artifact is None:
            artifact = Artifact(**kwargs)
            self.session.add(artifact)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(artifact, key, value)

    def _persist_tr_idl_blocks(
        self,
        spec_version: SpecificationVersion,
        parsed: ParsedSpecification,
        final_url: str,
        evidence_id: str,
    ) -> None:
        sections = self.session.scalars(
            select(SpecificationSection).where(
                SpecificationSection.specification_version_id == spec_version.internal_id
            )
        ).all()
        by_anchor = {section.anchor: section for section in sections}
        for block in parsed.webidl_blocks:
            existing = self.session.scalar(
                select(SpecificationIdlBlock).where(
                    SpecificationIdlBlock.specification_version_id == spec_version.internal_id,
                    SpecificationIdlBlock.order == block.order,
                )
            )
            block_section = by_anchor.get(block.section_anchor or "")
            section_id = block_section.internal_id if block_section else None
            kwargs: dict[str, Any] = {
                "specification_version_id": spec_version.internal_id,
                "section_id": section_id,
                "order": block.order,
                "fragment": block.fragment,
                "idl_text": block.text,
                "source_url": block.source_url or final_url,
                "content_hash": block.content_hash,
                "evidence_ids": [evidence_id],
                "metadata_": {},
            }
            if existing is None:
                self.session.add(SpecificationIdlBlock(**kwargs))
            else:
                for key, value in kwargs.items():
                    setattr(existing, key, value)

    def _persist_tr_references(
        self,
        spec_version: SpecificationVersion,
        parsed: ParsedSpecification,
        final_url: str,
        evidence_id: str,
    ) -> None:
        for reference in parsed.references:
            existing = self.session.scalar(
                select(SpecificationReference).where(
                    SpecificationReference.specification_version_id == spec_version.internal_id,
                    SpecificationReference.reference_type == reference.reference_type,
                    SpecificationReference.label == reference.label,
                )
            )
            kwargs: dict[str, Any] = {
                "specification_version_id": spec_version.internal_id,
                "reference_type": reference.reference_type,
                "label": reference.label,
                "title": reference.title,
                "url": reference.url,
                "section_fragment": reference.section_fragment,
                "source_url": f"{final_url}#{reference.section_fragment}"
                if reference.section_fragment
                else final_url,
                "evidence_ids": [evidence_id],
                "metadata_": {},
            }
            if existing is None:
                self.session.add(SpecificationReference(**kwargs))
            else:
                for key, value in kwargs.items():
                    setattr(existing, key, value)

    def _persist_tr_consideration_statuses(
        self,
        spec_version: SpecificationVersion,
        parsed: ParsedSpecification,
        evidence_id: str,
    ) -> None:
        sections = self.session.scalars(
            select(SpecificationSection).where(
                SpecificationSection.specification_version_id == spec_version.internal_id
            )
        ).all()
        by_anchor = {section.anchor: section for section in sections}
        for consideration in parsed.consideration_statuses:
            existing = self.session.scalar(
                select(SpecificationConsiderationStatus).where(
                    SpecificationConsiderationStatus.specification_version_id
                    == spec_version.internal_id,
                    SpecificationConsiderationStatus.consideration_type
                    == consideration.consideration_type,
                )
            )
            section = by_anchor.get(consideration.section_anchor or "")
            kwargs: dict[str, Any] = {
                "specification_version_id": spec_version.internal_id,
                "consideration_type": consideration.consideration_type,
                "status": consideration.status,
                "section_id": section.internal_id if section else None,
                "source_url": section.source_url if section else spec_version.source_url,
                "evidence_ids": [evidence_id],
                "metadata_": {},
            }
            if existing is None:
                self.session.add(SpecificationConsiderationStatus(**kwargs))
            else:
                for key, value in kwargs.items():
                    setattr(existing, key, value)

    def export_spec_source_packet(
        self,
        shortname: str,
        *,
        section_limit: int | None = None,
        section_offset: int = 0,
        include_evidence_ids: bool = True,
        include_section_inventory: bool = True,
    ) -> dict[str, Any]:
        spec = self.session.scalar(
            select(Specification).where(Specification.shortname == shortname)
        )
        if spec is None:
            raise KeyError(shortname)
        version = self.session.scalar(
            select(SpecificationVersion)
            .where(SpecificationVersion.specification_id == spec.internal_id)
            .order_by(
                SpecificationVersion.publication_date.desc().nullslast(),
                SpecificationVersion.updated_at.desc(),
            )
        )
        if version is None:
            raise KeyError(shortname)
        sections = self.session.scalars(
            select(SpecificationSection)
            .where(SpecificationSection.specification_version_id == version.internal_id)
            .order_by(SpecificationSection.order.asc())
        ).all()
        considerations = self.session.scalars(
            select(SpecificationConsiderationStatus).where(
                SpecificationConsiderationStatus.specification_version_id == version.internal_id
            )
        ).all()
        idl_blocks = self.session.scalars(
            select(SpecificationIdlBlock)
            .where(SpecificationIdlBlock.specification_version_id == version.internal_id)
            .order_by(SpecificationIdlBlock.order.asc())
        ).all()
        references = self.session.scalars(
            select(SpecificationReference).where(
                SpecificationReference.specification_version_id == version.internal_id
            )
        ).all()
        source_sections_all = [
            section for section in sections if self._include_in_source_packet(section)
        ]
        section_offset = max(section_offset, 0)
        source_sections = source_sections_all[section_offset:]
        if section_limit is not None:
            source_sections = source_sections[:section_limit]
        metadata = version.metadata_ or {}
        artifact = None
        for source_prefix in ("w3c-tr", "whatwg", "rfc-editor"):
            artifact = self.session.scalar(
                select(Artifact).where(
                    Artifact.external_id == f"{source_prefix}:{shortname}:{version.version}"
                )
            )
            if artifact is not None:
                break
        source_type = (
            artifact.source_type if artifact is not None else metadata.get("source_family")
        ) or "other"
        if source_type not in {"w3c_tr", "whatwg_html", "whatwg_spec", "rfc_editor"}:
            source_type = "other"
        evidence_ids = []
        if artifact is not None and include_evidence_ids:
            evidence_ids = [
                row.internal_id
                for row in self.session.scalars(
                    select(SourceEvidence).where(SourceEvidence.artifact_id == artifact.internal_id)
                )
            ]
        latest_url = metadata.get("latest_tr_url") or spec.current_published_url
        immutable_url = metadata.get("immutable_tr_url") or version.canonical_url
        canonical_url = version.canonical_url or immutable_url or latest_url
        return {
            "source_packet_contract_version": 1,
            "specification_id": spec.internal_id,
            "specification_version_id": version.internal_id,
            "source_type": source_type,
            "shortname": spec.shortname,
            "title": spec.title,
            "status": version.publication_status,
            "raw_status": metadata.get("raw_status"),
            "publication_date": version.publication_date,
            "latest_tr_url": latest_url,
            "immutable_publication_url": immutable_url,
            "editors_draft_url": spec.editors_draft_url,
            "source_repository_url": metadata.get("source_repository_url")
            or spec.metadata_.get("source_repository_url"),
            "section_inventory": [
                {
                    "section_id": section.internal_id,
                    "order": section.order,
                    "heading": section.heading,
                    "fragment": section.anchor,
                    "source_url": section.source_url,
                    "section_type": section.section_type,
                    "normative": section.normative,
                }
                for section in sections
            ]
            if include_section_inventory
            else [],
            "export_metadata": {
                "section_offset": section_offset,
                "section_limit": section_limit,
                "sections_total": len(source_sections_all),
                "sections_returned": len(source_sections),
                "include_evidence_ids": include_evidence_ids,
                "include_section_inventory": include_section_inventory,
            },
            "sections": [
                {
                    "section_id": section.internal_id,
                    "order": section.order,
                    "parent_section_id": section.parent_section_id,
                    "heading_level": section.heading_level,
                    "display_number": section.display_number,
                    "heading": section.heading,
                    "fragment": section.anchor,
                    "source_url": section.source_url,
                    "section_type": section.section_type,
                    "normative": section.normative,
                    "text": section.raw_text,
                    "content_hash": section.content_hash,
                    "evidence_ids": (section.evidence_ids or []) if include_evidence_ids else [],
                }
                for section in source_sections
            ],
            "consideration_presence": {
                consideration.consideration_type: consideration.status
                for consideration in considerations
            },
            "considerations": [
                {
                    "consideration_type": consideration.consideration_type,
                    "status": consideration.status,
                    "section_id": consideration.section_id,
                    "source_url": consideration.source_url,
                    "evidence_ids": (consideration.evidence_ids or [])
                    if include_evidence_ids
                    else [],
                }
                for consideration in considerations
            ],
            "snapshot_identity": {
                "requested_shortname": spec.shortname,
                "normalized_status": metadata.get("normalized_status")
                or version.publication_status,
                "raw_status": metadata.get("raw_status"),
                "publication_date": version.publication_date,
                "latest_url": latest_url,
                "immutable_url": immutable_url,
                "canonical_url": canonical_url,
                "content_hash": metadata.get("html_content_hash") or version.content_hash,
            },
            "webidl_blocks": [
                {
                    "internal_id": block.internal_id,
                    "specification_version_id": block.specification_version_id,
                    "section_id": block.section_id,
                    "order": block.order,
                    "fragment": block.fragment,
                    "idl_text": block.idl_text,
                    "source_url": block.source_url,
                    "content_hash": block.content_hash,
                    "evidence_ids": (block.evidence_ids or []) if include_evidence_ids else [],
                }
                for block in idl_blocks
            ],
            "normative_references": [
                self._reference_export(reference, include_evidence_ids=include_evidence_ids)
                for reference in references
                if reference.reference_type == "normative"
            ],
            "informative_references": [
                self._reference_export(reference, include_evidence_ids=include_evidence_ids)
                for reference in references
                if reference.reference_type == "informative"
            ],
            "unknown_references": [
                self._reference_export(reference, include_evidence_ids=include_evidence_ids)
                for reference in references
                if reference.reference_type == "unknown"
            ],
            "source_evidence_ids": evidence_ids,
            "retrieval_timestamp": metadata.get("retrieved_at"),
            "content_hashes": {
                "html": metadata.get("html_content_hash") or version.content_hash,
                "document": metadata.get("content_hash")
                or metadata.get("html_content_hash")
                or version.content_hash,
                "metadata_json": metadata.get("metadata_json_hash", ""),
                "text": content_hash(version.raw_text),
            },
        }

    def export_what_are_we_building_source_packet(
        self,
        shortname: str,
        *,
        primary_section_limit: int | None = 200,
        primary_section_offset: int = 0,
        rfc_limit: int = 20,
        rfc_section_limit: int = 20,
        include_evidence_ids: bool = True,
        include_rfc_section_inventory: bool = False,
    ) -> dict[str, Any]:
        primary_packet = self.export_spec_source_packet(
            shortname,
            section_limit=primary_section_limit,
            section_offset=primary_section_offset,
            include_evidence_ids=include_evidence_ids,
        )
        references = (
            primary_packet["normative_references"]
            + primary_packet["informative_references"]
            + primary_packet["unknown_references"]
        )
        cited: dict[int, dict[str, Any]] = {}
        for reference in references:
            reference_model = SpecificationReference(
                specification_version_id=reference["specification_version_id"],
                reference_type=reference["reference_type"],
                label=reference["label"],
                title=reference.get("title"),
                url=reference.get("url"),
                section_fragment=reference.get("section_fragment"),
                source_url=reference.get("source_url"),
                evidence_ids=reference.get("evidence_ids", []),
                metadata_={},
            )
            for number in self.rfc_numbers_from_reference(reference_model):
                item = cited.setdefault(
                    number,
                    {
                        "rfc": number,
                        "shortname": f"rfc{number}",
                        "available": False,
                        "reference_types": set(),
                        "references": [],
                    },
                )
                item["reference_types"].add(reference["reference_type"])
                item["references"].append(reference)
        cited_numbers = sorted(cited)[: max(rfc_limit, 0)]
        cited_rfc_packets: list[dict[str, Any]] = []
        unavailable_or_omitted: list[dict[str, Any]] = []
        for number in cited_numbers:
            short = f"rfc{number}"
            spec = self.session.scalar(
                select(Specification).where(Specification.shortname == short)
            )
            cited[number]["reference_types"] = sorted(cited[number]["reference_types"])
            if spec is None:
                unavailable_or_omitted.append({**cited[number], "reason": "not_imported"})
                continue
            cited[number]["available"] = True
            cited_rfc_packets.append(
                {
                    "rfc": number,
                    "reference_types": cited[number]["reference_types"],
                    "cited_by": cited[number]["references"],
                    "source_packet": self.export_spec_source_packet(
                        short,
                        section_limit=rfc_section_limit,
                        section_offset=0,
                        include_evidence_ids=include_evidence_ids,
                        include_section_inventory=include_rfc_section_inventory,
                    ),
                }
            )
        for number in sorted(cited)[max(rfc_limit, 0) :]:
            cited[number]["reference_types"] = sorted(cited[number]["reference_types"])
            unavailable_or_omitted.append(
                {**cited[number], "available": False, "reason": "not_included_by_limit"}
            )
        return {
            "what_are_we_building_source_packet_version": 1,
            "threat_model_contract_version": 2,
            "purpose": "evidence_capture_for_what_are_we_building",
            "non_goals": [
                "no_threat_modeling",
                "no_stride",
                "no_erta",
                "no_security_control_inference",
                "no_review_conclusions",
            ],
            "threat_model_usage": {
                "as_is_model_role": "documentary_baseline",
                "as_is_model_instructions": [
                    "Derive the as-is model from the exact specification snapshot and its normative or explanatory text.",
                    "Inventory actors, assets, components, flows, trust boundaries, assumptions, implemented protections, documented threats, privacy properties, residual exposure, and affected stakeholders that the specification already describes or implies.",
                    "Use the as-is model to identify documentary updates: protections or handled threats implemented in the specification but absent or incomplete in Security Considerations, Privacy Considerations, threat-model, or related explanatory sections.",
                    "Treat documentary omissions as editorial and non-blocking unless an independently elicited threat path establishes a technical gap.",
                ],
                "full_model_role": "independent_security_privacy_harms_elicitation",
                "full_model_instructions": [
                    "Perform a new security, privacy, and harms elicitation from the target model, applicable prompt repertoires, affected people, policies, deployment assumptions, and trust boundaries.",
                    "Attach each applicable prompt to concrete target model elements and express it as an actor-or-condition, action-or-failure, affected element, violated property or interest, and consequence.",
                    "Complete elicitation before reading as-is threat conclusions or checklist pass/fail dispositions.",
                    "Do not treat a framework category, checklist item, or mined pattern as evidence that a threat or weakness exists.",
                ],
                "separation_requirements": [
                    "The full model must not copy, paraphrase, reclassify, or use the as-is threat list as its candidate set.",
                    "The as-is model and full-model elicitation must be persisted as separate artifacts with separate provenance and completion states.",
                    "A pending or incomplete full-model queue must produce no zero-new-finding conclusion.",
                ],
                "reconciliation_instructions": [
                    "Compare the independently completed full model with the as-is model only after elicitation.",
                    "Classify each full-model story as new candidate, handled as-is, duplicate as-is, not applicable, or unable to verify.",
                    "Apply the target-evidence, affected-property-or-stakeholder, bounded-impact, ownership, and proof-of-concept finding gate after reconciliation.",
                ],
            },
            "primary_specification": primary_packet,
            "cited_rfc_inventory": [
                {
                    "rfc": number,
                    "shortname": f"rfc{number}",
                    "available": cited[number]["available"],
                    "reference_types": sorted(cited[number]["reference_types"]),
                    "reference_count": len(cited[number]["references"]),
                }
                for number in sorted(cited)
            ],
            "cited_rfc_packets": cited_rfc_packets,
            "unavailable_or_omitted_rfc_references": unavailable_or_omitted,
            "export_metadata": {
                "primary_section_limit": primary_section_limit,
                "primary_section_offset": primary_section_offset,
                "rfc_limit": rfc_limit,
                "rfc_section_limit": rfc_section_limit,
                "include_evidence_ids": include_evidence_ids,
                "include_rfc_section_inventory": include_rfc_section_inventory,
                "cited_rfc_total": len(cited),
                "cited_rfc_included": len(cited_rfc_packets),
            },
            "handoff_notes": [
                "This packet is source evidence for what-are-we-building.",
                "Use sections, references, source URLs, evidence IDs, and content hashes as auditable locators.",
                "Inline safeguards and normative checks must be extracted by the downstream model workflow from cited source text; this packet does not classify them as controls.",
                "Security or Privacy Considerations presence is evidence only, not proof of review completion or baseline completeness.",
                "The as-is model informs documentary updates; the full model is a separate independent elicitation used to discover additional security, privacy, and harms candidates before reconciliation.",
            ],
        }

    def _reference_export(
        self, reference: SpecificationReference, *, include_evidence_ids: bool = True
    ) -> dict[str, Any]:
        return {
            "internal_id": reference.internal_id,
            "specification_version_id": reference.specification_version_id,
            "reference_type": reference.reference_type,
            "label": reference.label,
            "title": reference.title,
            "url": reference.url,
            "section_fragment": reference.section_fragment,
            "source_url": reference.source_url,
            "evidence_ids": (reference.evidence_ids or []) if include_evidence_ids else [],
        }

    def _include_in_source_packet(self, section: SpecificationSection) -> bool:
        normalized_heading = re.sub(r"\s+", " ", section.heading.lower()).strip()
        normalized_anchor = (section.anchor or "").lower()
        excluded_headings = {
            "index",
            "idl index",
            "references",
            "normative references",
            "informative references",
            "acknowledgements",
            "acknowledgments",
            "changes",
            "change log",
        }
        if normalized_heading in excluded_headings:
            return False
        return not normalized_anchor.startswith(
            ("index", "references", "normative-references", "informative-references")
        )

    def ingest_specification_html(
        self,
        shortname: str,
        html: str,
        source_url: str,
        version: str = "current",
        publication_status: str | None = None,
        publication_date: str | None = None,
        source_commit: str | None = None,
    ) -> SpecificationVersion:
        parsed = parse_specification_html(html, source_url)
        spec = self.session.scalar(
            select(Specification).where(Specification.shortname == shortname)
        )
        if spec is None:
            spec = Specification(
                shortname=shortname,
                title=parsed.title,
                aliases=[],
                publication_status=publication_status,
                current_published_url=source_url,
                editors_draft_url=None,
                metadata_={},
            )
            self.session.add(spec)
            self.session.flush()
        text_hash = content_hash(parsed.text)
        spec_version = self.session.scalar(
            select(SpecificationVersion).where(
                SpecificationVersion.specification_id == spec.internal_id,
                SpecificationVersion.version == version,
            )
        )
        if spec_version is None:
            spec_version = SpecificationVersion(
                specification_id=spec.internal_id,
                version=version,
                publication_status=publication_status,
                publication_date=publication_date,
                source_url=source_url,
                canonical_url=normalize_url(source_url, keep_fragment=False),
                source_commit=source_commit,
                content_hash=text_hash,
                raw_text=parsed.text,
                metadata_={
                    "webidl_blocks": [block.text for block in parsed.webidl_blocks],
                    "normative_references": parsed.normative_references,
                    "informative_references": parsed.informative_references,
                },
            )
            self.session.add(spec_version)
            self.session.flush()
        else:
            spec_version.content_hash = text_hash
            spec_version.raw_text = parsed.text
        for section in parsed.sections:
            existing = self.session.scalar(
                select(SpecificationSection).where(
                    SpecificationSection.specification_version_id == spec_version.internal_id,
                    SpecificationSection.anchor == section.anchor,
                )
            )
            kwargs: dict[str, Any] = {
                "specification_version_id": spec_version.internal_id,
                "heading": section.heading,
                "anchor": section.anchor,
                "parent_section_id": None,
                "heading_level": section.heading_level,
                "display_number": section.display_number,
                "source_url": f"{source_url}#{section.anchor}",
                "raw_text": section.text,
                "normalized_text": section.text.lower(),
                "raw_html": section.raw_html,
                "section_type": section.section_type,
                "order": section.order,
                "content_hash": section.content_hash,
                "normative": section.normative,
                "evidence_ids": [],
                "metadata_": {},
            }
            if existing is None:
                self.session.add(SpecificationSection(**kwargs))
            else:
                for key, value in kwargs.items():
                    setattr(existing, key, value)
        self.session.commit()
        return spec_version

    def create_trace_fixture(self) -> dict[str, str]:
        repository = self.upsert_repository("w3c", "example-spec")
        spec_version = self.ingest_specification_html(
            "example-spec",
            Path("tests/fixtures/specification.html").read_text(encoding="utf-8")
            if Path("tests/fixtures/specification.html").exists()
            else "<html><title>Example Spec</title><h2 id='privacy'>Privacy Considerations</h2><p>Data minimization.</p></html>",
            "https://www.w3.org/TR/example-spec/",
            "2026-01-01",
        )
        review_request = ReviewRequest(
            domain="privacy",
            title="Privacy review for Example Spec",
            source_url="https://github.com/w3cping/privacy-request/issues/1",
            state="closed",
            requested_snapshot_url=spec_version.source_url,
            raw_payload={},
        )
        review = Review(
            review_domain="privacy",
            status="completed",
            reviewer_group="PING",
            target_specification_id=spec_version.specification_id,
            reviewed_snapshot_version_id=spec_version.internal_id,
        )
        finding = ReviewFinding(
            review_domain="privacy",
            finding_category="data_minimization",
            summary="Clarify retention limits.",
            original_text="Please clarify retention limits.",
            severity=None,
            severity_source=None,
            status="resolved",
            reviewer="reviewer",
            reviewer_group="PING",
            final_outcome="Addressed by PR and commit.",
            analysis_confidence=1.0,
            analysis_method="fixture",
            analysis_version="0.1",
        )
        pr = Commit(
            repository_id=repository.internal_id,
            sha="abc123",
            message="Clarify privacy considerations",
            author="editor",
            committed_at="2026-01-02T00:00:00Z",
            changed_files=[{"filename": "index.html", "sections": ["privacy"]}],
            raw_payload={},
        )
        self.session.add_all([review_request, review, finding, pr])
        self.session.flush()
        resolution = Resolution(
            finding_id=finding.internal_id,
            outcome="Privacy retention language added.",
            source_url="https://github.com/w3c/example-spec/pull/2",
            implemented_change_id=pr.internal_id,
            evidence_ids=[],
        )
        self.session.add(resolution)
        self.session.flush()
        self.session.add_all(
            [
                ArtifactLink(
                    subject_type="review",
                    subject_id=review.internal_id,
                    predicate="HAS_FINDING",
                    object_type="review_finding",
                    object_id=finding.internal_id,
                    source=review_request.source_url,
                    confidence=1.0,
                    extraction_method="fixture",
                    supporting_evidence=[],
                    is_explicit=True,
                ),
                ArtifactLink(
                    subject_type="review_finding",
                    subject_id=finding.internal_id,
                    predicate="RESOLVED_BY",
                    object_type="resolution",
                    object_id=resolution.internal_id,
                    source=resolution.source_url or "",
                    confidence=1.0,
                    extraction_method="fixture",
                    supporting_evidence=[],
                    is_explicit=True,
                ),
                ArtifactLink(
                    subject_type="resolution",
                    subject_id=resolution.internal_id,
                    predicate="IMPLEMENTED_BY",
                    object_type="commit",
                    object_id=pr.internal_id,
                    source=resolution.source_url or "",
                    confidence=1.0,
                    extraction_method="fixture",
                    supporting_evidence=[],
                    is_explicit=True,
                ),
            ]
        )
        self.session.commit()
        return {
            "review": review.internal_id,
            "finding": finding.internal_id,
            "resolution": resolution.internal_id,
        }

    def _upsert_artifact_for_issue(
        self,
        issue: Issue,
        repository: Repository,
        primary_domain: str,
        artifact_type: str,
        applicable_domains: list[str],
    ) -> Artifact:
        external_id = f"{repository.canonical_full_name}#{issue.number}"
        artifact = self.session.scalar(select(Artifact).where(Artifact.external_id == external_id))
        kwargs = {
            "external_id": external_id,
            "source_type": "github_issue",
            "artifact_type": artifact_type,
            "primary_domain": primary_domain,
            "applicable_domains": applicable_domains,
            "source_url": issue.source_url,
            "canonical_url": issue.source_url,
            "title": issue.title,
            "raw_text": issue.body,
            "normalized_text": (issue.body or issue.title).lower(),
            "raw_payload": issue.raw_payload,
            "retrieved_at": datetime.now(UTC),
            "content_hash": content_hash(issue.body or issue.title),
            "version": None,
            "commit_sha": None,
            "provenance": {"repository": repository.canonical_full_name, "number": issue.number},
            "confidence": 1.0,
            "metadata_": {"state": issue.state, "labels": issue.labels},
        }
        if artifact is None:
            artifact = Artifact(**kwargs)
            self.session.add(artifact)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(artifact, key, value)
        return artifact

    def _upsert_repository_document_artifact(
        self,
        repository: Repository,
        source_config: SourceConfig,
        relative_path: str,
        title: str,
        text: str,
        source_url: str,
        canonical_url: str,
        artifact_type: str,
        commit_sha: str | None,
        *,
        extra_metadata: dict[str, Any],
    ) -> Artifact:
        external_id = f"{repository.canonical_full_name}:{relative_path}"
        artifact = self.session.scalar(select(Artifact).where(Artifact.external_id == external_id))
        kwargs = {
            "external_id": external_id,
            "source_type": "github_repository_document",
            "artifact_type": artifact_type,
            "primary_domain": source_config.primary_domain,
            "applicable_domains": source_config.applicable_domains,
            "source_url": source_url,
            "canonical_url": canonical_url,
            "title": title,
            "raw_text": text,
            "normalized_text": text.lower(),
            "raw_payload": {"repository": repository.canonical_full_name, "path": relative_path},
            "retrieved_at": datetime.now(UTC),
            "content_hash": content_hash(text),
            "version": commit_sha,
            "commit_sha": commit_sha,
            "provenance": {"repository": repository.canonical_full_name, "path": relative_path},
            "confidence": 1.0,
            "metadata_": {
                "parser": source_config.parser,
                "source_name": source_config.name,
                **extra_metadata,
            },
        }
        if artifact is None:
            artifact = Artifact(**kwargs)
            self.session.add(artifact)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(artifact, key, value)
        return artifact

    def _replace_guidance_sections(
        self, document: GuidanceDocument, sections: list[dict[str, str | None]]
    ) -> None:
        existing = self.session.scalars(
            select(GuidanceSection).where(
                GuidanceSection.guidance_document_id == document.internal_id
            )
        ).all()
        for section in existing:
            self.session.delete(section)
        self.session.flush()
        if not sections:
            sections = [{"heading": document.title, "anchor": None, "raw_text": document.raw_text or ""}]
        for section in sections:
            self.session.add(
                GuidanceSection(
                    guidance_document_id=document.internal_id,
                    heading=section["heading"] or document.title,
                    anchor=section["anchor"],
                    raw_text=section["raw_text"] or "",
                    metadata_={},
                )
            )

    def _parse_document_title_and_sections(
        self, relative_path: str, text: str
    ) -> tuple[str, str, list[dict[str, str | None]]]:
        if relative_path.endswith((".html", ".htm")):
            return self._parse_html_title_and_sections(relative_path, text)
        title, body = self._strip_front_matter(relative_path, text)
        sections = self._parse_markdown_sections(body)
        if sections:
            title = title or sections[0]["heading"] or self._title_from_path(relative_path)
        if not title:
            match = re.search(r"^Title:\s*(.+)$", body, re.M)
            title = match.group(1).strip() if match else self._title_from_path(relative_path)
        return title, body, sections

    def _parse_html_title_and_sections(
        self, relative_path: str, text: str
    ) -> tuple[str, str, list[dict[str, str | None]]]:
        soup = BeautifulSoup(text, "html.parser")
        title_node = soup.find("h1") or soup.find("title")
        title = title_node.get_text(" ", strip=True) if title_node else self._title_from_path(relative_path)
        body = soup.get_text("\n", strip=True)
        sections: list[dict[str, str | None]] = []
        headings = soup.find_all(re.compile("^h[1-6]$"))
        for heading in headings:
            heading_text = heading.get_text(" ", strip=True)
            if not heading_text:
                continue
            anchor = heading.get("id")
            parts = [heading_text]
            for sibling in heading.find_next_siblings():
                if sibling.name and re.match(r"^h[1-6]$", sibling.name):
                    break
                sibling_text = sibling.get_text(" ", strip=True) if hasattr(sibling, "get_text") else ""
                if sibling_text:
                    parts.append(sibling_text)
            sections.append(
                {
                    "heading": heading_text,
                    "anchor": str(anchor) if anchor else None,
                    "raw_text": "\n\n".join(parts),
                }
            )
        return title, body, sections

    def _strip_front_matter(self, relative_path: str, text: str) -> tuple[str | None, str]:
        if not text.startswith("---\n"):
            return None, text
        end = text.find("\n---\n", 4)
        if end == -1:
            return None, text
        front_matter = text[4:end]
        title = None
        for line in front_matter.splitlines():
            if line.lower().startswith("title:"):
                title = line.split(":", maxsplit=1)[1].strip().strip('"').strip("'")
                break
        body = text[end + 5 :]
        return title or self._title_from_path(relative_path), body

    def _parse_markdown_sections(self, text: str) -> list[dict[str, str | None]]:
        sections: list[dict[str, str | None]] = []
        current: dict[str, str | None] | None = None
        current_lines: list[str] = []
        lines = text.splitlines()
        for index, line in enumerate(lines):
            match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
            if not match:
                if current is not None:
                    current_lines.append(line)
                continue
            if current is not None:
                current["raw_text"] = "\n".join(current_lines).strip()
                sections.append(current)
            heading = re.sub(r"\s*\{#[-A-Za-z0-9_:.]+\}\s*$", "", match.group(2)).strip()
            anchor = self._markdown_anchor_for_heading(heading)
            next_line = lines[index + 1].strip() if index + 1 < len(lines) else ""
            explicit_next = re.match(r"^\{:#([^}]+)\}$", next_line)
            if explicit_next:
                anchor = explicit_next.group(1)
            explicit_inline = re.search(r"\{#([-A-Za-z0-9_:.]+)\}\s*$", match.group(2))
            if explicit_inline:
                anchor = explicit_inline.group(1)
            current = {"heading": heading, "anchor": anchor, "raw_text": None}
            current_lines = [heading]
        if current is not None:
            current["raw_text"] = "\n".join(current_lines).strip()
            sections.append(current)
        return sections

    def _github_blob_url(
        self, repository: Repository, relative_path: str, commit_sha: str | None
    ) -> str:
        ref = commit_sha or "main"
        return f"https://github.com/{repository.canonical_full_name}/blob/{ref}/{relative_path}"

    def _published_guide_url(self, relative_path: str) -> str:
        path = relative_path
        if path == "index.md":
            return "https://www.w3.org/guide/"
        if path.endswith("/index.md"):
            return f"https://www.w3.org/guide/{path.removesuffix('/index.md')}/"
        if path.endswith(".md"):
            path = f"{path[:-3]}.html"
        return f"https://www.w3.org/guide/{path}"

    def _published_process_url(self, relative_path: str) -> str:
        if relative_path == "index.bs":
            return "https://www.w3.org/policies/process/drafts/"
        match = PROCESS_SNAPSHOT_RE.match(relative_path)
        if not match:
            return f"https://github.com/w3c/process/blob/main/{relative_path}"
        year, month, day = match.groups()
        return f"https://www.w3.org/policies/process/{year}{month}{day}/"

    def _process_effective_date(self, relative_path: str) -> str | None:
        match = PROCESS_SNAPSHOT_RE.match(relative_path)
        if not match:
            return None
        year, month, day = match.groups()
        return f"{year}-{month}-{day}"

    def _title_from_path(self, relative_path: str) -> str:
        stem = Path(relative_path).stem
        if stem == "index":
            stem = Path(relative_path).parent.name or "index"
        return stem.replace("-", " ").replace("_", " ").title()

    def _markdown_anchor_for_heading(self, heading: str) -> str:
        anchor = re.sub(r"[^a-z0-9 -]", "", heading.lower())
        return re.sub(r"\s+", "-", anchor).strip("-")

    def _upsert_review_request_for_issue(
        self,
        issue: Issue,
        repository: Repository,
        artifact: Artifact,
    ) -> ReviewRequest:
        review_request = self.session.scalar(
            select(ReviewRequest).where(ReviewRequest.source_url == issue.source_url)
        )
        kwargs = {
            "domain": artifact.primary_domain,
            "title": issue.title,
            "source_url": issue.source_url,
            "state": issue.state,
            "requested_snapshot_url": self._first_w3c_or_spec_url(issue.body),
            "raw_payload": issue.raw_payload,
        }
        if review_request is None:
            review_request = ReviewRequest(**kwargs)
            self.session.add(review_request)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(review_request, key, value)
        return review_request

    def _upsert_review_for_request(
        self,
        review_request: ReviewRequest,
        artifact: Artifact,
    ) -> tuple[Review, bool]:
        review = self.session.scalar(
            select(Review).where(Review.review_request_id == review_request.internal_id)
        )
        status = self._review_status_from_issue_state(review_request.state)
        kwargs = {
            "review_request_id": review_request.internal_id,
            "review_domain": artifact.primary_domain,
            "status": status,
            "reviewer_group": self._reviewer_group_for_domain(artifact.primary_domain),
            "target_specification_id": None,
            "reviewed_snapshot_version_id": None,
            "metadata_": {
                "source_artifact_id": artifact.internal_id,
                "source_url": review_request.source_url,
                "completion_not_inferred": True,
            },
        }
        created = False
        if review is None:
            review = Review(**kwargs)
            self.session.add(review)
            self.session.flush()
            created = True
        else:
            for key, value in kwargs.items():
                setattr(review, key, value)
        return review, created

    def _upsert_review_finding_for_issue(
        self,
        issue: Issue,
        repository: Repository,
        artifact: Artifact,
        review: Review,
    ) -> tuple[ReviewFinding, bool]:
        source_key = f"{repository.canonical_full_name}#{issue.number}"
        finding = self.session.scalar(
            select(ReviewFinding).where(
                ReviewFinding.review_id == review.internal_id,
                ReviewFinding.analysis_method == "rule-based-review-finding-normalizer",
                ReviewFinding.analysis_version == source_key,
            )
        )
        text = self._finding_text_from_issue(issue)
        kwargs = {
            "review_id": review.internal_id,
            "review_domain": artifact.primary_domain,
            "finding_category": self._finding_category_from_issue(issue),
            "summary": issue.title,
            "original_text": text,
            "severity": None,
            "severity_source": None,
            "reviewer": issue.author,
            "reviewer_group": self._reviewer_group_for_domain(artifact.primary_domain),
            "status": self._finding_status_from_issue_state(issue.state),
            "finding_date": issue.created_source_at,
            "affected_component": None,
            "affected_section": None,
            "risk": None,
            "proposed_mitigation": None,
            "accepted_mitigation": None,
            "related_principles": [],
            "related_guidance": [],
            "related_issues": [source_key],
            "related_pull_requests": [],
            "related_commits": [],
            "final_outcome": None,
            "analysis_confidence": 0.72,
            "analysis_method": "rule-based-review-finding-normalizer",
            "analysis_version": source_key,
        }
        created = False
        if finding is None:
            finding = ReviewFinding(**kwargs)
            self.session.add(finding)
            self.session.flush()
            created = True
        else:
            for key, value in kwargs.items():
                setattr(finding, key, value)
        return finding, created

    def _mirror_issue_resolution_links_to_finding(
        self, issue: Issue, finding: ReviewFinding
    ) -> int:
        mirrored = 0
        issue_links = self.session.scalars(
            select(ArtifactLink).where(
                ArtifactLink.subject_type == "issue",
                ArtifactLink.subject_id == issue.internal_id,
                ArtifactLink.predicate.in_(
                    ["DISCUSSED_IN", "TRACKED_BY", "RESOLVED_BY", "IMPLEMENTED_BY", "CHANGES"]
                ),
            )
        ).all()
        for link in issue_links:
            if link.object_type.startswith("github_"):
                continue
            predicate = "TRACKED_BY" if link.predicate == "DISCUSSED_IN" else link.predicate
            existing = self.session.scalar(
                select(ArtifactLink).where(
                    ArtifactLink.subject_type == "review_finding",
                    ArtifactLink.subject_id == finding.internal_id,
                    ArtifactLink.predicate == predicate,
                    ArtifactLink.object_type == link.object_type,
                    ArtifactLink.object_id == link.object_id,
                )
            )
            self._upsert_artifact_link(
                subject_type="review_finding",
                subject_id=finding.internal_id,
                predicate=predicate,
                object_type=link.object_type,
                object_id=link.object_id,
                source=link.source,
                confidence=min(link.confidence, 0.9),
                extraction_method="rule-based-review-finding-normalizer",
                supporting_evidence=link.supporting_evidence,
                is_explicit=link.is_explicit,
            )
            if existing is None:
                mirrored += 1
        return mirrored

    def _finding_text_from_issue(self, issue: Issue) -> str:
        body = (issue.body or "").strip()
        comments = (issue.raw_payload or {}).get("comments") or []
        comment_texts = [
            str(comment.get("body", "")).strip()
            for comment in comments
            if isinstance(comment, dict) and str(comment.get("body", "")).strip()
        ]
        combined = "\n\n".join([part for part in [body, *comment_texts[:3]] if part])
        return combined or issue.title

    def _finding_category_from_issue(self, issue: Issue) -> str | None:
        labels = {label.lower() for label in issue.labels}
        for candidate in (
            "privacy",
            "security",
            "accessibility",
            "internationalization",
            "i18n",
            "design",
            "tracking",
            "question",
            "needs-resolution",
        ):
            if candidate in labels:
                return (
                    "internationalization" if candidate == "i18n" else candidate.replace("-", "_")
                )
        return None

    def _review_status_from_issue_state(self, state: str | None) -> str:
        if state == "closed":
            return "feedback_provided"
        if state == "open":
            return "requested"
        return "unable_to_verify"

    def _finding_status_from_issue_state(self, state: str | None) -> str:
        if state == "closed":
            return "closed_unverified"
        if state == "open":
            return "open"
        return "unknown"

    def _reviewer_group_for_domain(self, domain: str) -> str | None:
        return {
            "design": "TAG",
            "privacy": "PING",
            "security": "Security Interest Group",
            "accessibility": "APA",
            "internationalization": "Internationalization Working Group",
        }.get(domain)

    def _first_w3c_or_spec_url(self, text: str | None) -> str | None:
        if not text:
            return None
        for token in text.replace(")", " ").replace("]", " ").split():
            candidate = token.strip("<>,.")
            if candidate.startswith(
                ("https://www.w3.org/TR/", "https://w3c.github.io/", "https://github.com/")
            ):
                return candidate
        return None

    def _upsert_review_comment_for_issue(
        self,
        issue: Issue,
        artifact: Artifact,
        repository: Repository,
        payload: dict[str, Any],
    ) -> ReviewComment:
        source_url = (
            payload.get("html_url") or f"{issue.source_url}#issuecomment-{payload.get('id')}"
        )
        comment = self.session.scalar(
            select(ReviewComment).where(ReviewComment.source_url == source_url)
        )
        kwargs = {
            "review_id": None,
            "author": (payload.get("user") or {}).get("login"),
            "body": payload.get("body") or "",
            "source_url": source_url,
            "created_source_at": payload.get("created_at"),
            "raw_payload": payload,
        }
        if comment is None:
            comment = ReviewComment(**kwargs)
            self.session.add(comment)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(comment, key, value)
        self._upsert_evidence(
            artifact.internal_id,
            source_url,
            source_url,
            f"{repository.canonical_full_name}#{issue.number}:comment:{payload.get('id')}",
            comment.body,
            None,
            comment.author,
            comment.created_source_at,
        )
        return comment

    def _upsert_timeline_evidence(
        self,
        issue: Issue,
        artifact: Artifact,
        repository: Repository,
        payload: dict[str, Any],
        index: int,
    ) -> SourceEvidence:
        event_id = payload.get("id") or f"{payload.get('event', 'event')}:{index}"
        event_url = payload.get("html_url") or payload.get("url") or issue.source_url
        event = payload.get("event") or payload.get("__typename") or "timeline_event"
        actor = (payload.get("actor") or {}).get("login")
        created_at = payload.get("created_at")
        return self._upsert_evidence(
            artifact.internal_id,
            event_url,
            event_url,
            f"{repository.canonical_full_name}#{issue.number}:timeline:{event_id}",
            f"GitHub timeline event: {event}",
            None,
            actor,
            created_at,
        )

    def _upsert_timeline_relationships(
        self,
        issue: Issue,
        payload: dict[str, Any],
        evidence_id: str,
    ) -> None:
        event = payload.get("event")
        event_url = payload.get("html_url") or payload.get("url") or issue.source_url
        if event in {"cross-referenced", "mentioned"}:
            ref = self._timeline_source_ref(payload)
            if ref is not None:
                self._upsert_artifact_link(
                    subject_type="issue",
                    subject_id=issue.internal_id,
                    predicate="DISCUSSED_IN",
                    object_type=ref["object_type"],
                    object_id=ref["object_id"],
                    source=event_url,
                    confidence=0.9,
                    extraction_method=f"github-timeline:{event}",
                    supporting_evidence=[evidence_id],
                    is_explicit=True,
                )
        if event == "referenced" and payload.get("commit_id"):
            self._upsert_artifact_link(
                subject_type="issue",
                subject_id=issue.internal_id,
                predicate="REFERENCES",
                object_type="github_commit_ref",
                object_id=self._commit_object_id(payload),
                source=event_url,
                confidence=0.85,
                extraction_method="github-timeline:referenced",
                supporting_evidence=[evidence_id],
                is_explicit=True,
            )
        if event == "closed" and payload.get("commit_id"):
            self._upsert_artifact_link(
                subject_type="issue",
                subject_id=issue.internal_id,
                predicate="RESOLVED_BY",
                object_type="github_commit_ref",
                object_id=self._commit_object_id(payload),
                source=event_url,
                confidence=0.8,
                extraction_method="github-timeline:closed",
                supporting_evidence=[evidence_id],
                is_explicit=True,
            )
        if event == "marked_as_duplicate":
            ref = self._duplicate_ref(payload)
            if ref is not None:
                self._upsert_artifact_link(
                    subject_type="issue",
                    subject_id=issue.internal_id,
                    predicate="DUPLICATES",
                    object_type=ref["object_type"],
                    object_id=ref["object_id"],
                    source=event_url,
                    confidence=0.95,
                    extraction_method="github-timeline:marked_as_duplicate",
                    supporting_evidence=[evidence_id],
                    is_explicit=True,
                )

    def _materialize_issue_ref(self, adapter, link: ArtifactLink) -> dict[str, int] | None:
        parsed = self._parse_github_number_ref(link.object_id)
        if parsed is None:
            return None
        owner, repository_name, number = parsed
        existing_issue = self._find_issue(owner, repository_name, number)
        if existing_issue is not None and self._has_materialized_link(
            link, "issue", existing_issue.internal_id
        ):
            return None
        payload = adapter.get_issue(owner, repository_name, number)
        if "pull_request" in payload:
            return self._materialize_pull_request_ref(adapter, link)
        issue = self.ingest_github_issue_payload(
            owner,
            repository_name,
            payload,
            comments=[],
            timeline=[],
            primary_domain="cross_cutting",
            artifact_type="specification_issue",
            applicable_domains=[],
        )
        self._upsert_materialized_link(link, "issue", issue.internal_id)
        return {"issues": 1, "pull_requests": 0, "pull_request_reviews": 0, "commits": 0}

    def _materialize_pull_request_ref(self, adapter, link: ArtifactLink) -> dict[str, int] | None:
        parsed = self._parse_github_number_ref(link.object_id)
        if parsed is None:
            return None
        owner, repository_name, number = parsed
        existing_pr = self._find_pull_request(owner, repository_name, number)
        if existing_pr is not None and self._has_materialized_link(
            link, "pull_request", existing_pr.internal_id
        ):
            return None
        payload = adapter.get_pull_request(owner, repository_name, number)
        files = adapter.list_pull_request_files(owner, repository_name, number)
        reviews = adapter.list_pull_request_reviews(owner, repository_name, number)
        commits = adapter.list_pull_request_commits(owner, repository_name, number)
        pr = self._upsert_pull_request_payload(owner, repository_name, payload, files)
        review_count = 0
        for review_payload in reviews:
            self._upsert_pull_request_review_payload(pr, review_payload)
            review_count += 1
        commit_count = 0
        for commit_payload in commits:
            self._upsert_commit_payload(owner, repository_name, commit_payload)
            commit_count += 1
        self._upsert_materialized_link(link, "pull_request", pr.internal_id)
        return {
            "issues": 0,
            "pull_requests": 1,
            "pull_request_reviews": review_count,
            "commits": commit_count,
        }

    def _materialize_commit_ref(self, adapter, link: ArtifactLink) -> dict[str, int] | None:
        parsed = self._parse_github_commit_ref(link.object_id)
        if parsed is None:
            return None
        owner, repository_name, sha = parsed
        existing_commit = self.session.scalar(select(Commit).where(Commit.sha == sha))
        if existing_commit is not None and self._has_materialized_link(
            link, "commit", existing_commit.internal_id
        ):
            return None
        payload = adapter.get_commit(owner, repository_name, sha)
        commit = self._upsert_commit_payload(owner, repository_name, payload)
        self._upsert_materialized_link(link, "commit", commit.internal_id)
        return {"issues": 0, "pull_requests": 0, "pull_request_reviews": 0, "commits": 1}

    def _upsert_materialized_link(
        self, source_link: ArtifactLink, object_type: str, object_id: str
    ) -> ArtifactLink:
        return self._upsert_artifact_link(
            subject_type=source_link.subject_type,
            subject_id=source_link.subject_id,
            predicate=source_link.predicate,
            object_type=object_type,
            object_id=object_id,
            source=source_link.source,
            confidence=min(source_link.confidence, 0.95),
            extraction_method="materialized-github-ref",
            supporting_evidence=source_link.supporting_evidence,
            is_explicit=source_link.is_explicit,
        )

    def _has_materialized_link(
        self, source_link: ArtifactLink, object_type: str, object_id: str
    ) -> bool:
        return (
            self.session.scalar(
                select(ArtifactLink).where(
                    ArtifactLink.subject_type == source_link.subject_type,
                    ArtifactLink.subject_id == source_link.subject_id,
                    ArtifactLink.predicate == source_link.predicate,
                    ArtifactLink.object_type == object_type,
                    ArtifactLink.object_id == object_id,
                    ArtifactLink.extraction_method == "materialized-github-ref",
                )
            )
            is not None
        )

    def _find_issue(self, owner: str, repository_name: str, number: int) -> Issue | None:
        repository = self.session.scalar(
            select(Repository).where(Repository.owner == owner, Repository.name == repository_name)
        )
        if repository is None:
            return None
        return self.session.scalar(
            select(Issue).where(
                Issue.repository_id == repository.internal_id, Issue.number == number
            )
        )

    def _find_pull_request(
        self, owner: str, repository_name: str, number: int
    ) -> PullRequest | None:
        repository = self.session.scalar(
            select(Repository).where(Repository.owner == owner, Repository.name == repository_name)
        )
        if repository is None:
            return None
        return self.session.scalar(
            select(PullRequest).where(
                PullRequest.repository_id == repository.internal_id, PullRequest.number == number
            )
        )

    def _upsert_pull_request_payload(
        self,
        owner: str,
        repository_name: str,
        payload: dict[str, Any],
        changed_files: list[dict[str, Any]],
    ) -> PullRequest:
        repository = self.upsert_repository(owner, repository_name)
        number = int(payload["number"])
        pr = self.session.scalar(
            select(PullRequest).where(
                PullRequest.repository_id == repository.internal_id, PullRequest.number == number
            )
        )
        kwargs = {
            "repository_id": repository.internal_id,
            "number": number,
            "title": payload.get("title") or "",
            "body": payload.get("body"),
            "author": (payload.get("user") or {}).get("login"),
            "state": payload.get("state") or "unknown",
            "merged": bool(payload.get("merged")),
            "source_url": payload.get("html_url")
            or f"https://github.com/{owner}/{repository_name}/pull/{number}",
            "changed_files": changed_files,
            "raw_payload": payload,
        }
        if pr is None:
            pr = PullRequest(**kwargs)
            self.session.add(pr)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(pr, key, value)
        return pr

    def _upsert_pull_request_review_payload(
        self,
        pull_request: PullRequest,
        payload: dict[str, Any],
    ) -> PullRequestReview:
        review_id = payload.get("id")
        existing_reviews = self.session.scalars(
            select(PullRequestReview).where(
                PullRequestReview.pull_request_id == pull_request.internal_id
            )
        ).all()
        review = next(
            (
                item
                for item in existing_reviews
                if isinstance(item.raw_payload, dict) and item.raw_payload.get("id") == review_id
            ),
            None,
        )
        kwargs = {
            "pull_request_id": pull_request.internal_id,
            "reviewer": (payload.get("user") or {}).get("login"),
            "state": payload.get("state"),
            "body": payload.get("body"),
            "submitted_at": payload.get("submitted_at"),
            "raw_payload": payload,
        }
        if review is None:
            review = PullRequestReview(**kwargs)
            self.session.add(review)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(review, key, value)
        return review

    def _upsert_commit_payload(
        self, owner: str, repository_name: str, payload: dict[str, Any]
    ) -> Commit:
        repository = self.upsert_repository(owner, repository_name)
        sha = payload.get("sha")
        if not sha:
            raise ValueError("Commit payload is missing sha")
        commit_payload = payload.get("commit") or {}
        author_payload = commit_payload.get("author") or {}
        committer_payload = commit_payload.get("committer") or {}
        author = (payload.get("author") or {}).get("login") or author_payload.get("name")
        committed_at = committer_payload.get("date") or author_payload.get("date")
        commit = self.session.scalar(select(Commit).where(Commit.sha == sha))
        kwargs = {
            "repository_id": repository.internal_id,
            "sha": sha,
            "message": commit_payload.get("message"),
            "author": author,
            "committed_at": committed_at,
            "changed_files": payload.get("files") or [],
            "raw_payload": payload,
        }
        if commit is None:
            commit = Commit(**kwargs)
            self.session.add(commit)
            self.session.flush()
        else:
            for key, value in kwargs.items():
                setattr(commit, key, value)
        return commit

    def _parse_github_number_ref(self, value: str) -> tuple[str, str, int] | None:
        if "#" not in value:
            return None
        repository_ref, number_ref = value.rsplit("#", maxsplit=1)
        parts = repository_ref.split("/")
        if len(parts) != 2 or not number_ref.isdigit():
            return None
        return parts[0], parts[1], int(number_ref)

    def _parse_github_commit_ref(self, value: str) -> tuple[str, str, str] | None:
        if "@" not in value:
            return None
        repository_ref, sha = value.rsplit("@", maxsplit=1)
        parts = repository_ref.split("/")
        if len(parts) != 2 or not sha:
            return None
        return parts[0], parts[1], sha

    def _timeline_source_ref(self, payload: dict[str, Any]) -> dict[str, str] | None:
        source = payload.get("source") or {}
        source_payload = source.get("issue") or source.get("pull_request")
        if not isinstance(source_payload, dict):
            return None
        return self._github_ref_from_payload(source_payload)

    def _duplicate_ref(self, payload: dict[str, Any]) -> dict[str, str] | None:
        for key in ("duplicate_of", "duplicate_issue", "canonical"):
            value = payload.get(key)
            if isinstance(value, dict):
                ref = self._github_ref_from_payload(value)
                if ref is not None:
                    return ref
        return None

    def _github_ref_from_payload(self, payload: dict[str, Any]) -> dict[str, str] | None:
        html_url = payload.get("html_url")
        if not isinstance(html_url, str):
            return None
        return self._github_ref_from_url(html_url)

    def _github_ref_from_url(self, url: str) -> dict[str, str] | None:
        parsed = urlparse(url)
        if parsed.netloc.lower() != "github.com":
            return None
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) < 4 or parts[2] not in {"issues", "pull"}:
            return None
        owner, repository, kind, number = parts[:4]
        object_type = "github_pull_request_ref" if kind == "pull" else "github_issue_ref"
        return {"object_type": object_type, "object_id": f"{owner}/{repository}#{number}"}

    def _commit_object_id(self, payload: dict[str, Any]) -> str:
        commit_id = str(payload.get("commit_id"))
        commit_url = payload.get("commit_url")
        if isinstance(commit_url, str):
            parsed = urlparse(commit_url)
            parts = [part for part in parsed.path.split("/") if part]
            if len(parts) >= 5 and parts[0] == "repos" and parts[3] == "commits":
                return f"{parts[1]}/{parts[2]}@{commit_id}"
        return commit_id

    def _upsert_artifact_link(
        self,
        subject_type: str,
        subject_id: str,
        predicate: str,
        object_type: str,
        object_id: str,
        source: str,
        confidence: float,
        extraction_method: str,
        supporting_evidence: list[str],
        is_explicit: bool,
    ) -> ArtifactLink:
        existing = self.session.scalar(
            select(ArtifactLink).where(
                ArtifactLink.subject_type == subject_type,
                ArtifactLink.subject_id == subject_id,
                ArtifactLink.predicate == predicate,
                ArtifactLink.object_type == object_type,
                ArtifactLink.object_id == object_id,
                ArtifactLink.source == source,
            )
        )
        if existing is not None:
            return existing
        link = ArtifactLink(
            subject_type=subject_type,
            subject_id=subject_id,
            predicate=predicate,
            object_type=object_type,
            object_id=object_id,
            source=source,
            confidence=confidence,
            extraction_method=extraction_method,
            supporting_evidence=supporting_evidence,
            is_explicit=is_explicit,
        )
        self.session.add(link)
        return link

    def _get_sync_cursor(self, source_config: SourceConfig) -> SyncCursor | None:
        source = self.session.scalar(select(Source).where(Source.name == source_config.name))
        if source is None:
            return None
        cursor = self.session.scalar(
            select(SyncCursor).where(SyncCursor.source_id == source.internal_id)
        )
        if cursor is None:
            cursor = SyncCursor(
                source_id=source.internal_id,
                cursor_type="github_updated_since",
                cursor_value=None,
                metadata_={
                    "repository": f"{source_config.organization}/{source_config.repository}"
                },
            )
            self.session.add(cursor)
            self.session.flush()
        return cursor

    def _upsert_evidence(
        self,
        artifact_id: str,
        source_url: str,
        canonical_url: str,
        source_artifact_id: str,
        text: str,
        hash_value: str | None,
        author: str | None,
        timestamp: str | None,
    ) -> SourceEvidence:
        evidence = self.session.scalar(
            select(SourceEvidence).where(
                SourceEvidence.artifact_id == artifact_id,
                SourceEvidence.source_artifact_id == source_artifact_id,
            )
        )
        if evidence is None:
            evidence = SourceEvidence(
                artifact_id=artifact_id,
                source_url=source_url,
                canonical_url=canonical_url,
                source_artifact_id=source_artifact_id,
                fragment=None,
                original_text=text,
                source_position=None,
                content_hash=hash_value or content_hash(text),
                original_author=author,
                original_timestamp=timestamp,
            )
            self.session.add(evidence)
            self.session.flush()
        return evidence

    def _upsert_source_evidence(
        self,
        artifact_id: str | None,
        source_url: str,
        canonical_url: str,
        source_artifact_id: str,
        text: str,
        hash_value: str | None,
        author: str | None,
        timestamp: str | None,
        *,
        fragment: str | None,
        specification_version: str | None,
    ) -> SourceEvidence:
        evidence = self.session.scalar(
            select(SourceEvidence).where(
                SourceEvidence.artifact_id == artifact_id,
                SourceEvidence.source_artifact_id == source_artifact_id,
            )
        )
        if evidence is None:
            evidence = SourceEvidence(
                artifact_id=artifact_id,
                source_url=source_url,
                canonical_url=canonical_url,
                source_artifact_id=source_artifact_id,
                fragment=fragment,
                original_text=text,
                source_position=None,
                content_hash=hash_value or content_hash(text),
                commit_sha=None,
                specification_version=specification_version,
                original_author=author,
                original_timestamp=timestamp,
            )
            self.session.add(evidence)
            self.session.flush()
        else:
            evidence.source_url = source_url
            evidence.canonical_url = canonical_url
            evidence.fragment = fragment
            evidence.original_text = text
            evidence.content_hash = hash_value or content_hash(text)
            evidence.specification_version = specification_version
            evidence.original_author = author
            evidence.original_timestamp = timestamp
        return evidence

    def sync(self) -> IngestionRun:
        run = IngestionRun(status="completed", finished_at=datetime.now(UTC), summary={"synced": 0})
        self.session.add(run)
        for source in self.session.scalars(select(Source).where(Source.enabled.is_(True))):
            cursor = self.session.scalar(
                select(SyncCursor).where(SyncCursor.source_id == source.internal_id)
            )
            if cursor is None:
                self.session.add(
                    SyncCursor(
                        source_id=source.internal_id, cursor_value=datetime.now(UTC).isoformat()
                    )
                )
        self.session.commit()
        return run
