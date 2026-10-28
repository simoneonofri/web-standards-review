from __future__ import annotations

import re
from urllib.parse import ParseResult, urljoin, urlparse, urlunparse

GITHUB_REF_RE = re.compile(
    r"(?:(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+))?#(?P<number>\d+)"
)


def normalize_url(url: str, base_url: str | None = None, keep_fragment: bool = True) -> str:
    joined = urljoin(base_url, url) if base_url else url
    parsed = urlparse(joined)
    path = re.sub(r"/+", "/", parsed.path)
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    fragment = parsed.fragment if keep_fragment else ""
    normalized = ParseResult(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        path=path,
        params="",
        query=parsed.query,
        fragment=fragment,
    )
    return urlunparse(normalized)


def extract_github_issue_refs(text: str) -> list[dict[str, str | int | None]]:
    refs: list[dict[str, str | int | None]] = []
    for match in GITHUB_REF_RE.finditer(text or ""):
        refs.append(
            {
                "owner": match.group("owner"),
                "repository": match.group("repo"),
                "number": int(match.group("number")),
                "raw": match.group(0),
            }
        )
    return refs
