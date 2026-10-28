from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse

import httpx

ALLOWED_W3C_HOSTS = {"api.w3.org", "www.w3.org", "w3.org"}
ALLOWED_WHATWG_HOSTS = {
    "compat.spec.whatwg.org",
    "compression.spec.whatwg.org",
    "console.spec.whatwg.org",
    "cookiestore.spec.whatwg.org",
    "dom.spec.whatwg.org",
    "encoding.spec.whatwg.org",
    "fetch.spec.whatwg.org",
    "fs.spec.whatwg.org",
    "fullscreen.spec.whatwg.org",
    "html.spec.whatwg.org",
    "infra.spec.whatwg.org",
    "mimesniff.spec.whatwg.org",
    "notifications.spec.whatwg.org",
    "quirks.spec.whatwg.org",
    "storage.spec.whatwg.org",
    "streams.spec.whatwg.org",
    "testutils.spec.whatwg.org",
    "url.spec.whatwg.org",
    "urlpattern.spec.whatwg.org",
    "webidl.spec.whatwg.org",
    "websockets.spec.whatwg.org",
    "xhr.spec.whatwg.org",
}
HTML_CONTENT_TYPES = {"text/html", "application/xhtml+xml"}
W3C_STATUS_QUERY_NAMES = {
    "CR": "Candidate Recommendation Snapshot",
    "CRD": "Candidate Recommendation Draft",
    "CRS": "Candidate Recommendation Snapshot",
    "PER": "Proposed Edited Recommendation",
    "PR": "Proposed Recommendation",
    "REC": "Recommendation",
    "WD": "Working Draft",
}


class W3CDownloadError(RuntimeError):
    def __init__(self, status: str, message: str, url: str) -> None:
        super().__init__(message)
        self.status = status
        self.url = url


@dataclass(frozen=True)
class W3CSpecificationMetadata:
    shortname: str
    title: str
    status: str | None
    url: str | None
    editors_draft: str | None
    raw_payload: dict[str, Any]


@dataclass(frozen=True)
class W3CDiscoveryItem:
    shortname: str
    title: str
    raw_status: str | None
    source_status: str
    api_url: str | None
    raw_payload: dict[str, Any]


@dataclass(frozen=True)
class W3CLatestVersion:
    shortname: str
    title: str
    raw_status: str | None
    publication_date: str | None
    version: str
    tr_url: str | None
    latest_tr_url: str | None
    api_url: str | None
    raw_payload: dict[str, Any]


@dataclass(frozen=True)
class DownloadedDocument:
    url: str
    final_url: str
    text: str
    content_type: str
    etag: str | None
    last_modified: str | None
    status: str


class W3CAPIAdapter:
    def __init__(
        self,
        client: httpx.Client,
        *,
        max_response_bytes: int = 5_242_880,
        retry_attempts: int = 3,
        backoff_seconds: float = 0.5,
        request_delay_seconds: float = 0.0,
    ) -> None:
        self.client = client
        self.max_response_bytes = max_response_bytes
        self.retry_attempts = retry_attempts
        self.backoff_seconds = backoff_seconds
        self.request_delay_seconds = request_delay_seconds

    def iter_specifications_by_status(
        self, status: str, items: int = 1000
    ) -> list[W3CDiscoveryItem]:
        api_status = self._api_status_name(status)
        encoded_status = quote(api_status, safe="")
        discovered: list[W3CDiscoveryItem] = []
        page = 1
        next_url: str | None = f"https://api.w3.org/specifications-by-status/{encoded_status}"
        while next_url:
            response = self._request_json(
                next_url, params={"embed": "1", "items": items, "page": page}
            )
            payload = response.json()
            for item in self._extract_specification_items(payload):
                shortname = self._shortname(item)
                if not shortname:
                    continue
                discovered.append(
                    W3CDiscoveryItem(
                        shortname=shortname,
                        title=str(item.get("title") or item.get("name") or shortname),
                        raw_status=self._status(item),
                        source_status=api_status,
                        api_url=self._link(item, "self"),
                        raw_payload=item,
                    )
                )
            next_url = self._link(payload, "next")
            if not next_url:
                pages = payload.get("pages")
                try:
                    total_pages = int(pages)
                except (TypeError, ValueError):
                    total_pages = page
                page += 1
                next_url = (
                    f"https://api.w3.org/specifications-by-status/{encoded_status}"
                    if page <= total_pages
                    else None
                )
            else:
                page += 1
        return discovered

    def _api_status_name(self, status: str) -> str:
        return W3C_STATUS_QUERY_NAMES.get(status, status)

    def get_specification(self, shortname: str) -> W3CSpecificationMetadata:
        response = self._request_json(f"https://api.w3.org/specifications/{shortname}")
        payload = response.json()
        return W3CSpecificationMetadata(
            shortname=payload.get("shortname") or payload.get("name") or shortname,
            title=payload.get("title") or shortname,
            status=self._status(payload),
            url=self._link(payload, "self"),
            editors_draft=payload.get("edDraft") or payload.get("editorsDraft"),
            raw_payload=payload,
        )

    def get_latest_version(
        self, shortname: str, spec_payload: dict[str, Any] | None = None
    ) -> W3CLatestVersion:
        latest_url = self._link(spec_payload or {}, "latest-version") or self._link(
            spec_payload or {}, "latest"
        )
        latest_url = latest_url or f"https://api.w3.org/specifications/{shortname}/versions/latest"
        response = self._request_json(latest_url)
        payload = response.json()
        tr_url = self._document_url(payload)
        return W3CLatestVersion(
            shortname=payload.get("shortname") or payload.get("name") or shortname,
            title=payload.get("title") or shortname,
            raw_status=self._status(payload),
            publication_date=payload.get("date")
            or payload.get("publicationDate")
            or payload.get("publication_date"),
            version=str(payload.get("version") or payload.get("date") or "latest"),
            tr_url=tr_url,
            latest_tr_url=f"https://www.w3.org/TR/{shortname}/",
            api_url=self._link(payload, "self") or latest_url,
            raw_payload=payload,
        )

    def download_tr_document(
        self,
        url: str,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> DownloadedDocument | None:
        return self.download_html_document(
            url,
            etag=etag,
            last_modified=last_modified,
            allowed_hosts=ALLOWED_W3C_HOSTS,
            allowed_path_prefixes=("/TR/",),
            url_label="TR",
        )

    def download_html_document(
        self,
        url: str,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
        allowed_hosts: set[str],
        allowed_path_prefixes: tuple[str, ...],
        url_label: str,
    ) -> DownloadedDocument | None:
        self._validate_html_url(url, allowed_hosts, allowed_path_prefixes, url_label)
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
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    raise W3CDownloadError(
                        "http_error", "Redirect without Location header", current_url
                    )
                current_url = str(httpx.URL(current_url).join(location))
                self._validate_html_url(
                    current_url, allowed_hosts, allowed_path_prefixes, url_label
                )
                continue
            if redirect_count >= 4:
                raise W3CDownloadError("http_error", "Too many redirects", current_url)
            response.raise_for_status()
            content_type = (
                response.headers.get("content-type", "").split(";", maxsplit=1)[0].strip().lower()
            )
            if content_type not in HTML_CONTENT_TYPES:
                raise W3CDownloadError(
                    "unsupported_content_type", content_type or "missing content type", current_url
                )
            if len(response.content) > self.max_response_bytes:
                raise W3CDownloadError(
                    "too_large", "Response exceeded configured size limit", current_url
                )
            text = response.text
            if not text:
                raise W3CDownloadError("parse_error", "Empty document", current_url)
            return DownloadedDocument(
                url=url,
                final_url=str(response.url),
                text=text,
                content_type=content_type,
                etag=response.headers.get("etag"),
                last_modified=response.headers.get("last-modified"),
                status="downloaded",
            )
        raise W3CDownloadError("http_error", "Too many redirects", current_url)

    def download_whatwg_html(
        self,
        url: str = "https://html.spec.whatwg.org/",
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> DownloadedDocument | None:
        return self.download_html_document(
            url,
            etag=etag,
            last_modified=last_modified,
            allowed_hosts=ALLOWED_WHATWG_HOSTS,
            allowed_path_prefixes=("/",),
            url_label="WHATWG HTML",
        )

    def download_whatwg_spec(
        self,
        url: str,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> DownloadedDocument | None:
        return self.download_html_document(
            url,
            etag=etag,
            last_modified=last_modified,
            allowed_hosts=ALLOWED_WHATWG_HOSTS,
            allowed_path_prefixes=("/",),
            url_label="WHATWG",
        )

    def _request_json(self, url: str, params: dict[str, Any] | None = None) -> httpx.Response:
        self._validate_api_url(url)
        response = self._request("GET", url, params=params)
        response.raise_for_status()
        return response

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        last_response: httpx.Response | None = None
        for attempt in range(self.retry_attempts):
            if self.request_delay_seconds > 0:
                time.sleep(self.request_delay_seconds)
            response = self.client.request(method, url, **kwargs)
            last_response = response
            if response.status_code == 429:
                self._sleep_retry(response, attempt)
                continue
            if response.status_code in {500, 502, 503, 504}:
                self._sleep_retry(response, attempt)
                continue
            return response
        if last_response is None:
            raise W3CDownloadError("http_error", "No response", url)
        return last_response

    def _sleep_retry(self, response: httpx.Response, attempt: int) -> None:
        retry_after = response.headers.get("retry-after")
        if retry_after and retry_after.isdigit():
            delay = min(float(retry_after), 10.0)
        else:
            delay = min(self.backoff_seconds * (2**attempt), 10.0)
        time.sleep(delay)

    def _validate_api_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname != "api.w3.org":
            raise W3CDownloadError("http_error", "W3C API URL is not allowlisted", url)

    def _validate_tr_url(self, url: str) -> None:
        self._validate_html_url(url, ALLOWED_W3C_HOSTS, ("/TR/",), "TR")

    def _validate_html_url(
        self,
        url: str,
        allowed_hosts: set[str],
        allowed_path_prefixes: tuple[str, ...],
        url_label: str,
    ) -> None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or host not in allowed_hosts:
            raise W3CDownloadError("http_error", f"{url_label} URL host is not allowlisted", url)
        if not any(parsed.path.startswith(prefix) for prefix in allowed_path_prefixes):
            raise W3CDownloadError(
                "http_error", f"Document URL is not under an allowed {url_label} path", url
            )

    def _extract_specification_items(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        embedded = payload.get("_embedded") or {}
        for key in ["specifications", "specification"]:
            value = embedded.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        value = payload.get("specifications")
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        return []

    def _document_url(self, payload: dict[str, Any]) -> str | None:
        for rel in ["version-history", "latest-version", "self", "alternate"]:
            href = self._link(payload, rel)
            if href and "/TR/" in href:
                return href
        for key in ["uri", "url", "href"]:
            value = payload.get(key)
            if isinstance(value, str) and "/TR/" in value:
                return value
        links = payload.get("_links") or {}
        for value in links.values():
            if isinstance(value, dict):
                href = value.get("href")
                if isinstance(href, str) and "/TR/" in href:
                    return href
        return None

    def _link(self, payload: dict[str, Any], rel: str) -> str | None:
        links = payload.get("_links") or {}
        value = links.get(rel)
        if isinstance(value, dict):
            href = value.get("href")
            return str(href) if href else None
        if isinstance(value, list) and value and isinstance(value[0], dict):
            href = value[0].get("href")
            return str(href) if href else None
        return None

    def _shortname(self, payload: dict[str, Any]) -> str | None:
        value = payload.get("shortname") or payload.get("name")
        if value:
            return str(value)
        href = self._link(payload, "self")
        if href:
            return href.rstrip("/").split("/")[-1]
        return None

    def _status(self, payload: dict[str, Any]) -> str | None:
        value = payload.get("status")
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            return str(value.get("name") or value.get("shortname") or value.get("id") or "") or None
        return None
