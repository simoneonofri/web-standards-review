from __future__ import annotations

from urllib.parse import urlparse

import httpx

from w3c_knowledge.config import Settings


class UnsafeURL(ValueError):
    pass


def validate_ingestion_url(url: str, settings: Settings) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"}:
        raise UnsafeURL("Only HTTP(S) ingestion URLs are allowed")
    hostname = (parsed.hostname or "").lower()
    if hostname not in settings.allowed_domain_set and not any(
        hostname.endswith("." + domain) for domain in settings.allowed_domain_set
    ):
        raise UnsafeURL(f"Domain is not allowlisted: {hostname}")
    return url


def make_http_client(settings: Settings, token: str | None = None) -> httpx.Client:
    headers = {"User-Agent": "w3c-knowledge/0.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(
        timeout=httpx.Timeout(settings.http_timeout),
        follow_redirects=False,
        headers=headers,
        limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
    )
