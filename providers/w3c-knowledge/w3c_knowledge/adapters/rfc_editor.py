from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

ALLOWED_RFC_EDITOR_HOSTS = {"www.rfc-editor.org", "rfc-editor.org"}
RFC_CONTENT_TYPES = {
    "application/json": "json",
    "application/xml": "xml",
    "text/xml": "xml",
    "text/html": "html",
    "application/xhtml+xml": "html",
    "text/plain": "txt",
}


class RFCEditorError(RuntimeError):
    def __init__(self, status: str, message: str, url: str) -> None:
        super().__init__(message)
        self.status = status
        self.url = url


@dataclass(frozen=True)
class RFCMetadata:
    number: int
    doc_id: str
    title: str
    authors: list[str]
    abstract: str | None
    pub_date: str | None
    pub_status: str | None
    status: str | None
    stream: str | None
    source: str | None
    formats: list[str]
    page_count: int | None
    keywords: list[str]
    obsoletes: list[int]
    obsoleted_by: list[int]
    updates: list[int]
    updated_by: list[int]
    see_also: list[str]
    doi: str | None
    errata_url: str | None
    raw_payload: dict[str, Any]


@dataclass(frozen=True)
class DownloadedRFCMetadata:
    metadata: RFCMetadata
    url: str
    final_url: str
    text: str
    etag: str | None
    last_modified: str | None
    content_hash: str


@dataclass(frozen=True)
class DownloadedRFCDocument:
    number: int
    url: str
    final_url: str
    text: str
    content_format: str
    content_type: str
    etag: str | None
    last_modified: str | None
    status: str
    content_hash: str


@dataclass(frozen=True)
class RFCFormatChoice:
    content_format: str
    url: str | None
    status: str
    reason: str | None = None


class RFCEditorAdapter:
    def __init__(
        self,
        client: httpx.Client,
        *,
        max_response_bytes: int = 5_242_880,
        retry_attempts: int = 3,
        backoff_seconds: float = 0.5,
    ) -> None:
        self.client = client
        self.max_response_bytes = max_response_bytes
        self.retry_attempts = retry_attempts
        self.backoff_seconds = backoff_seconds

    def get_metadata(
        self,
        number: int,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> DownloadedRFCMetadata | None:
        url = f"https://www.rfc-editor.org/rfc/rfc{number}.json"
        response = self._download(url, {"application/json"}, etag=etag, last_modified=last_modified)
        if response is None:
            return None
        text, final_url, response_etag, response_last_modified, _ = response
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RFCEditorError("parse_error", "RFC metadata JSON could not be parsed", url) from exc
        return DownloadedRFCMetadata(
            metadata=parse_rfc_metadata(payload, number=number),
            url=url,
            final_url=final_url,
            text=text,
            etag=response_etag,
            last_modified=response_last_modified,
            content_hash=_hash(text),
        )

    def choose_content_format(self, metadata: RFCMetadata) -> RFCFormatChoice:
        available = {item.lower().lstrip(".") for item in metadata.formats}
        declared = available or {"xml", "html", "txt"}
        for content_format, suffixes in [
            ("xml", {"xml"}),
            ("html", {"html", "xhtml"}),
            ("txt", {"txt", "text", "ascii"}),
        ]:
            if declared.intersection(suffixes):
                return RFCFormatChoice(
                    content_format=content_format,
                    url=f"https://www.rfc-editor.org/rfc/rfc{metadata.number}.{content_format}",
                    status="selected",
                )
        return RFCFormatChoice("metadata-only", None, "metadata_only", "No supported RFC text format")

    def download_content(
        self,
        metadata: RFCMetadata,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> DownloadedRFCDocument | None:
        choice = self.choose_content_format(metadata)
        if choice.url is None:
            return DownloadedRFCDocument(
                number=metadata.number,
                url=f"https://www.rfc-editor.org/rfc/rfc{metadata.number}.json",
                final_url=f"https://www.rfc-editor.org/rfc/rfc{metadata.number}.json",
                text="",
                content_format="metadata-only",
                content_type="application/json",
                etag=None,
                last_modified=None,
                status="metadata_only",
                content_hash=_hash(""),
            )
        accepted = {
            "xml": {"application/xml", "text/xml"},
            "html": {"text/html", "application/xhtml+xml"},
            "txt": {"text/plain"},
        }[choice.content_format]
        response = self._download(choice.url, accepted, etag=etag, last_modified=last_modified)
        if response is None:
            return None
        text, final_url, response_etag, response_last_modified, content_type = response
        return DownloadedRFCDocument(
            number=metadata.number,
            url=choice.url,
            final_url=final_url,
            text=text,
            content_format=choice.content_format,
            content_type=content_type,
            etag=response_etag,
            last_modified=response_last_modified,
            status="downloaded",
            content_hash=_hash(text),
        )

    def iter_mirror_metadata(self, mirror_dir: Path) -> list[DownloadedRFCMetadata]:
        if not mirror_dir.exists() or not mirror_dir.is_dir():
            raise RFCEditorError("not_found", "RFC mirror directory does not exist", str(mirror_dir))
        results: list[DownloadedRFCMetadata] = []
        for path in sorted(mirror_dir.rglob("rfc*.json")):
            match = re.search(r"rfc(\d+)\.json$", path.name, re.I)
            if not match:
                continue
            text = path.read_text(encoding="utf-8")
            payload = json.loads(text)
            number = int(match.group(1))
            results.append(
                DownloadedRFCMetadata(
                    metadata=parse_rfc_metadata(payload, number=number),
                    url=path.as_uri(),
                    final_url=path.as_uri(),
                    text=text,
                    etag=None,
                    last_modified=None,
                    content_hash=_hash(text),
                )
            )
        return results

    def load_mirror_content(self, mirror_dir: Path, metadata: RFCMetadata) -> DownloadedRFCDocument:
        for content_format, suffixes in [
            ("xml", ["xml"]),
            ("html", ["html", "xhtml"]),
            ("txt", ["txt"]),
        ]:
            for suffix in suffixes:
                matches = sorted(mirror_dir.rglob(f"rfc{metadata.number}.{suffix}"))
                if matches:
                    path = matches[0]
                    text = _sanitize_text(path.read_text(encoding="utf-8", errors="replace"))
                    content_type = {
                        "xml": "application/xml",
                        "html": "text/html",
                        "txt": "text/plain",
                    }[content_format]
                    return DownloadedRFCDocument(
                        number=metadata.number,
                        url=path.as_uri(),
                        final_url=path.as_uri(),
                        text=text,
                        content_format=content_format,
                        content_type=content_type,
                        etag=None,
                        last_modified=None,
                        status="downloaded",
                        content_hash=_hash(text),
                    )
        return DownloadedRFCDocument(
            number=metadata.number,
            url=f"file://{mirror_dir}",
            final_url=f"file://{mirror_dir}",
            text="",
            content_format="metadata-only",
            content_type="application/json",
            etag=None,
            last_modified=None,
            status="metadata_only",
            content_hash=_hash(""),
        )

    def _download(
        self,
        url: str,
        accepted_content_types: set[str],
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> tuple[str, str, str | None, str | None, str] | None:
        self._validate_rfc_url(url)
        headers: dict[str, str] = {}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
        current_url = url
        for redirect_count in range(5):
            response = self._request("GET", current_url, headers=headers)
            if response.status_code == 304:
                return None
            if response.status_code == 404:
                raise RFCEditorError("not_found", "RFC resource not found", current_url)
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    raise RFCEditorError("http_error", "Redirect without Location header", current_url)
                current_url = str(httpx.URL(current_url).join(location))
                self._validate_rfc_url(current_url)
                continue
            if redirect_count >= 4:
                raise RFCEditorError("http_error", "Too many redirects", current_url)
            response.raise_for_status()
            if len(response.content) > self.max_response_bytes:
                raise RFCEditorError("too_large", "Response exceeded configured size limit", current_url)
            content_type = response.headers.get("content-type", "").split(";", maxsplit=1)[0].strip().lower()
            if content_type not in accepted_content_types:
                raise RFCEditorError("unsupported_content_type", content_type or "missing content type", current_url)
            return (
                _sanitize_text(response.text),
                str(response.url),
                response.headers.get("etag"),
                response.headers.get("last-modified"),
                content_type,
            )
        raise RFCEditorError("http_error", "Too many redirects", current_url)

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        last_response: httpx.Response | None = None
        for attempt in range(self.retry_attempts):
            response = self.client.request(method, url, **kwargs)
            last_response = response
            if response.status_code == 429 or response.status_code in {500, 502, 503, 504}:
                self._sleep_retry(response, attempt)
                continue
            return response
        if last_response is None:
            raise RFCEditorError("http_error", "No response", url)
        return last_response

    def _sleep_retry(self, response: httpx.Response, attempt: int) -> None:
        retry_after = response.headers.get("retry-after")
        if retry_after and retry_after.isdigit():
            delay = min(float(retry_after), 10.0)
        else:
            delay = min(self.backoff_seconds * (2**attempt), 10.0)
        time.sleep(delay)

    def _validate_rfc_url(self, url: str) -> None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or host not in ALLOWED_RFC_EDITOR_HOSTS:
            raise RFCEditorError("http_error", "RFC Editor URL host is not allowlisted", url)
        if not parsed.path.startswith("/rfc/"):
            raise RFCEditorError("http_error", "RFC Editor URL path is not under /rfc/", url)


def parse_rfc_metadata(payload: dict[str, Any], *, number: int | None = None) -> RFCMetadata:
    doc_id = str(_first(payload, "doc_id", "docid", "id") or f"RFC{number or 0}").upper()
    parsed_number = number or _number_from_doc_id(doc_id)
    if parsed_number is None:
        raise RFCEditorError("parse_error", "RFC number missing from metadata", doc_id)
    return RFCMetadata(
        number=parsed_number,
        doc_id=doc_id,
        title=str(_first(payload, "title", "name") or doc_id),
        authors=_string_list(_first(payload, "authors", "authors_list", "author")),
        abstract=_maybe_join(_first(payload, "abstract")),
        pub_date=_date_value(_first(payload, "pub_date", "publication_date", "date")),
        pub_status=_string_or_name(_first(payload, "pub_status", "publication_status")),
        status=_string_or_name(_first(payload, "status", "current_status")),
        stream=_string_or_name(_first(payload, "stream")),
        source=_string_or_name(_first(payload, "source")),
        formats=_formats(payload),
        page_count=_int_or_none(_first(payload, "page_count", "pages")),
        keywords=_string_list(_first(payload, "keywords", "keyword")),
        obsoletes=_rfc_number_list(_first(payload, "obsoletes")),
        obsoleted_by=_rfc_number_list(_first(payload, "obsoleted_by", "obsoleted-by")),
        updates=_rfc_number_list(_first(payload, "updates")),
        updated_by=_rfc_number_list(_first(payload, "updated_by", "updated-by")),
        see_also=_string_list(_first(payload, "see_also", "see-also", "also")),
        doi=_string_or_name(_first(payload, "doi")),
        errata_url=str(_first(payload, "errata_url", "errata") or f"https://www.rfc-editor.org/errata/rfc{parsed_number}"),
        raw_payload=payload,
    )


def _first(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def _number_from_doc_id(value: str) -> int | None:
    match = re.search(r"RFC\s*-?(\d+)", value, re.I)
    return int(match.group(1)) if match else None


def _string_or_name(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, dict):
        for key in ("name", "slug", "id", "value"):
            if value.get(key):
                return str(value[key])
        return None
    return str(value)


def _maybe_join(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return "\n".join(str(item) for item in value)
    if isinstance(value, dict):
        return _string_or_name(value)
    return str(value)


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for item in [_string_or_name(value)] if item]
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            if isinstance(item, dict):
                name = _string_or_name(item)
                if name:
                    result.append(name)
            elif item is not None:
                result.append(str(item))
        return result
    return [str(value)]


def _rfc_number_list(value: Any) -> list[int]:
    numbers: list[int] = []
    for item in _string_list(value):
        match = re.search(r"RFC\s*-?(\d+)|^(\d+)$", item, re.I)
        if match:
            numbers.append(int(match.group(1) or match.group(2)))
    return sorted(set(numbers))


def _formats(payload: dict[str, Any]) -> list[str]:
    raw = _first(payload, "formats", "format", "available_formats")
    values = _string_list(raw)
    if not values:
        for key in ("xml", "html", "txt", "ascii", "pdf"):
            if payload.get(key):
                values.append(key)
    return sorted({value.lower().lstrip(".") for value in values})


def _date_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, dict):
        for key in ("date", "value", "iso"):
            if value.get(key):
                return str(value[key])
        return None
    return str(value)


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _hash(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sanitize_text(text: str) -> str:
    # PostgreSQL text columns cannot store NUL bytes. Use a visible replacement
    # so legacy RFC control bytes do not silently disappear from evidence text.
    return text.replace("\x00", "\uFFFD")
