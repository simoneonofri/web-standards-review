from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from w3c_knowledge.parsing.specification import content_hash

DATATRACKER_BASE_URL = "https://datatracker.ietf.org"
IETF_ARCHIVE_BASE_URL = "https://www.ietf.org/archive/id"
ALLOWED_DATATRACKER_HOSTS = {"datatracker.ietf.org", "www.ietf.org"}


class IETFDatatrackerError(RuntimeError):
    def __init__(self, status: str, message: str, url: str) -> None:
        super().__init__(message)
        self.status = status
        self.url = url


@dataclass(frozen=True)
class DownloadedIETFDocument:
    url: str
    final_url: str
    text: str
    content_format: str
    content_type: str
    etag: str | None
    last_modified: str | None
    content_hash: str


@dataclass(frozen=True)
class ParsedIETFReviewPage:
    title: str
    review_name: str
    body: str
    reviewer: str | None
    posted_url: str | None
    reviewed_rev: str | None
    result: str | None
    completed_date: str | None


class IETFDatatrackerAdapter:
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

    def iter_review_assignments(
        self,
        *,
        team: str = "secdir",
        limit: int | None = None,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        page_size = max(1, min(page_size, 500))
        path = (
            "/api/v1/review/reviewassignment/"
            f"?review_request__team__acronym={team}&limit={page_size}&offset=0"
        )
        items: list[dict[str, Any]] = []
        while path:
            payload = self.get_json(path)
            page_items = payload.get("objects") or []
            if not isinstance(page_items, list):
                raise IETFDatatrackerError("parse_error", "Datatracker page is missing objects", path)
            for item in page_items:
                if isinstance(item, dict):
                    items.append(item)
                    if limit is not None and len(items) >= limit:
                        return items
            next_path = (payload.get("meta") or {}).get("next")
            path = str(next_path) if next_path else ""
        return items

    def get_json(self, path_or_url: str) -> dict[str, Any]:
        url = self._absolute_url(path_or_url)
        response = self._request("GET", url, headers={"accept": "application/json"})
        if response.status_code == 404:
            raise IETFDatatrackerError("not_found", "Datatracker resource not found", url)
        response.raise_for_status()
        if len(response.content) > self.max_response_bytes:
            raise IETFDatatrackerError("too_large", "Response exceeded configured size limit", url)
        payload = response.json()
        if not isinstance(payload, dict):
            raise IETFDatatrackerError("parse_error", "Datatracker JSON response is not an object", url)
        return payload

    def get_review_request(self, resource_uri: str) -> dict[str, Any]:
        return self.get_json(resource_uri)

    def get_document(self, resource_uri_or_name: str) -> dict[str, Any]:
        if resource_uri_or_name.startswith("/api/") or resource_uri_or_name.startswith("http"):
            return self.get_json(resource_uri_or_name)
        return self.get_json(f"/api/v1/doc/document/{resource_uri_or_name}/")

    def get_name(self, resource_uri: str | None) -> dict[str, Any] | None:
        if not resource_uri:
            return None
        try:
            return self.get_json(resource_uri)
        except IETFDatatrackerError:
            return None

    def download_review_page(self, review_name: str) -> DownloadedIETFDocument:
        return self._download(f"{DATATRACKER_BASE_URL}/doc/{review_name}/", {"text/html"})

    def download_draft_snapshot(
        self,
        draft_name: str,
        revision: str,
        *,
        prefer_html: bool = True,
    ) -> DownloadedIETFDocument:
        suffixes = ["html", "txt"] if prefer_html else ["txt", "html"]
        for suffix in suffixes:
            url = f"{IETF_ARCHIVE_BASE_URL}/{draft_name}-{revision}.{suffix}"
            try:
                return self._download(
                    url,
                    {
                        "text/html",
                        "application/xhtml+xml",
                    }
                    if suffix == "html"
                    else {"text/plain"},
                )
            except IETFDatatrackerError as exc:
                if exc.status != "not_found" or suffix == suffixes[-1]:
                    raise
        raise IETFDatatrackerError("not_found", "Draft snapshot not found", draft_name)

    def parse_review_page(self, html: str) -> ParsedIETFReviewPage:
        soup = BeautifulSoup(html, "html.parser")
        title = soup.find("h1").get_text(" ", strip=True) if soup.find("h1") else ""
        review_name = ""
        small = soup.find("small")
        if small:
            review_name = small.get_text(" ", strip=True)
        body_node = soup.find("pre", class_="pasted") or soup.find("pre")
        body = body_node.get_text("\n", strip=False).strip() if body_node else ""
        meta = self._review_meta_from_table(soup)
        return ParsedIETFReviewPage(
            title=title,
            review_name=review_name,
            body=body,
            reviewer=meta.get("reviewer"),
            posted_url=meta.get("posted_at"),
            reviewed_rev=meta.get("reviewed_revision"),
            result=meta.get("result"),
            completed_date=meta.get("completed"),
        )

    def _download(
        self,
        url: str,
        accepted_content_types: set[str],
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> DownloadedIETFDocument:
        self._validate_url(url)
        headers: dict[str, str] = {}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
        current_url = url
        for redirect_count in range(5):
            response = self._request("GET", current_url, headers=headers)
            if response.status_code == 404:
                raise IETFDatatrackerError("not_found", "IETF resource not found", current_url)
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    raise IETFDatatrackerError(
                        "http_error", "Redirect without Location header", current_url
                    )
                current_url = str(httpx.URL(current_url).join(location))
                self._validate_url(current_url)
                continue
            if redirect_count >= 4:
                raise IETFDatatrackerError("http_error", "Too many redirects", current_url)
            response.raise_for_status()
            if len(response.content) > self.max_response_bytes:
                raise IETFDatatrackerError(
                    "too_large", "Response exceeded configured size limit", current_url
                )
            content_type = (
                response.headers.get("content-type", "").split(";", maxsplit=1)[0].strip().lower()
            )
            if content_type not in accepted_content_types:
                raise IETFDatatrackerError(
                    "unsupported_content_type", content_type or "missing content type", current_url
                )
            text = _sanitize_text(response.text)
            return DownloadedIETFDocument(
                url=url,
                final_url=str(response.url),
                text=text,
                content_format=_content_format(content_type),
                content_type=content_type,
                etag=response.headers.get("etag"),
                last_modified=response.headers.get("last-modified"),
                content_hash=content_hash(text),
            )
        raise IETFDatatrackerError("http_error", "Too many redirects", current_url)

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        last_response: httpx.Response | None = None
        last_error: httpx.TransportError | None = None
        for attempt in range(self.retry_attempts):
            try:
                response = self.client.request(method, url, **kwargs)
            except httpx.TransportError as exc:
                last_error = exc
                self._sleep_retry(None, attempt)
                continue
            last_response = response
            if response.status_code == 429 or response.status_code in {500, 502, 503, 504}:
                self._sleep_retry(response, attempt)
                continue
            return response
        if last_error is not None:
            raise IETFDatatrackerError("network_error", str(last_error), url) from last_error
        if last_response is None:
            raise IETFDatatrackerError("http_error", "No response", url)
        return last_response

    def _sleep_retry(self, response: httpx.Response | None, attempt: int) -> None:
        retry_after = response.headers.get("retry-after") if response is not None else None
        delay = min(float(retry_after), 10.0) if retry_after and retry_after.isdigit() else min(
            self.backoff_seconds * (2**attempt), 10.0
        )
        time.sleep(delay)

    def _absolute_url(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            url = path_or_url
        else:
            url = str(httpx.URL(DATATRACKER_BASE_URL).join(path_or_url))
        self._validate_url(url)
        return url

    def _validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or host not in ALLOWED_DATATRACKER_HOSTS:
            raise IETFDatatrackerError("http_error", "IETF URL host is not allowlisted", url)

    def _review_meta_from_table(self, soup: BeautifulSoup) -> dict[str, str]:
        result: dict[str, str] = {}
        for row in soup.select("tbody.meta tr"):
            cells = row.find_all(["th", "td"])
            if len(cells) < 2:
                continue
            label = cells[-2].get_text(" ", strip=True).lower().replace(" ", "_")
            value_cell = cells[-1]
            text = value_cell.get_text(" ", strip=True)
            if not label or not text:
                continue
            if label == "posted_at":
                link = value_cell.find("a", href=True)
                result[label] = str(link["href"]) if link else text
            elif label == "reviewed_revision":
                match = re.search(r"\b(\d{2})\b", text)
                result[label] = match.group(1) if match else text
            elif label == "reviewer":
                result[label] = text
            elif label in {"result", "completed"}:
                result[label] = text
        return result


def document_name_from_resource(resource_uri: str | None) -> str | None:
    if not resource_uri:
        return None
    match = re.search(r"/doc/document/([^/]+)/", resource_uri)
    return match.group(1) if match else None


def resource_id(resource_uri: str | None) -> int | None:
    if not resource_uri:
        return None
    match = re.search(r"/(\d+)/?$", resource_uri)
    return int(match.group(1)) if match else None


def slug_from_resource(resource_uri: str | None) -> str | None:
    if not resource_uri:
        return None
    parts = [part for part in resource_uri.split("/") if part]
    return parts[-1] if parts else None


def normalize_result(result_resource: str | None, page_result: str | None = None) -> str:
    slug = slug_from_resource(result_resource)
    if slug:
        return _normalize_result_value(slug)
    if page_result:
        normalized = re.sub(r"\s+", "_", page_result.strip().lower())
        return _normalize_result_value(normalized) if normalized else "none"
    return "none"


def display_result(result: str) -> str:
    return {
        "none": "None",
        "ready": "Ready",
        "has_nits": "Has Nits",
        "has_issues": "Has Issues",
    }.get(result, result.replace("_", " ").title())


def _normalize_result_value(value: str) -> str:
    normalized = value.replace("-", "_").strip().lower()
    aliases = {
        "issues": "has_issues",
        "has_issues": "has_issues",
        "has_issues_": "has_issues",
        "has_nits": "has_nits",
        "nits": "has_nits",
    }
    return aliases.get(normalized, normalized or "none")


def normalize_state(state_resource: str | None) -> str:
    return (slug_from_resource(state_resource) or "unknown").replace("-", "_")


def normalize_review_type(type_resource: str | None) -> str | None:
    slug = slug_from_resource(type_resource)
    return slug.replace("-", "_") if slug else None


def _content_format(content_type: str) -> str:
    if content_type in {"text/html", "application/xhtml+xml"}:
        return "html"
    if content_type == "text/plain":
        return "txt"
    return "unknown"


def _sanitize_text(text: str) -> str:
    return text.replace("\x00", "\ufffd")
