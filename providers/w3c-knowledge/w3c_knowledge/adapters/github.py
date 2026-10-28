from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class ParsedGitHubIssue:
    repository_owner: str
    repository_name: str
    number: int
    title: str
    body: str | None
    author: str | None
    state: str
    state_reason: str | None
    labels: list[str]
    milestone: str | None
    assignees: list[str]
    source_url: str
    created_at: str | None
    updated_at: str | None
    closed_at: str | None
    raw_payload: dict[str, Any]


def parse_issue_payload(owner: str, repository: str, payload: dict[str, Any]) -> ParsedGitHubIssue:
    return ParsedGitHubIssue(
        repository_owner=owner,
        repository_name=repository,
        number=int(payload["number"]),
        title=payload.get("title") or "",
        body=payload.get("body"),
        author=(payload.get("user") or {}).get("login"),
        state=payload.get("state") or "unknown",
        state_reason=payload.get("state_reason"),
        labels=[label["name"] if isinstance(label, dict) else str(label) for label in payload.get("labels", [])],
        milestone=(payload.get("milestone") or {}).get("title"),
        assignees=[user.get("login") for user in payload.get("assignees", []) if user.get("login")],
        source_url=payload.get("html_url") or "",
        created_at=payload.get("created_at"),
        updated_at=payload.get("updated_at"),
        closed_at=payload.get("closed_at"),
        raw_payload=payload,
    )


class GitHubRESTAdapter:
    def __init__(
        self,
        client: httpx.Client,
        token: str | None = None,
        *,
        max_retries: int = 3,
        max_rate_limit_sleep_seconds: int = 3600,
        retry_backoff_seconds: float = 1.0,
    ) -> None:
        self.client = client
        self.token = token
        self.rate_limit: dict[str, str | None] = {}
        self.max_retries = max_retries
        self.max_rate_limit_sleep_seconds = max_rate_limit_sleep_seconds
        self.retry_backoff_seconds = retry_backoff_seconds

    def iter_issues(self, owner: str, repository: str, since: str | None = None) -> Iterator[dict[str, Any]]:
        page = 1
        while True:
            params: dict[str, str | int] = {"state": "all", "per_page": 100, "page": page}
            if since:
                params["since"] = since
            response = self._get(f"https://api.github.com/repos/{owner}/{repository}/issues", params=params)
            self._record_rate_limit(response)
            response.raise_for_status()
            payload = response.json()
            if not payload:
                break
            yield from payload
            page += 1

    def list_issue_comments(self, owner: str, repository: str, issue_number: int) -> list[dict[str, Any]]:
        return self._list_paginated(
            f"https://api.github.com/repos/{owner}/{repository}/issues/{issue_number}/comments"
        )

    def list_issue_timeline(self, owner: str, repository: str, issue_number: int) -> list[dict[str, Any]]:
        return self._list_paginated(
            f"https://api.github.com/repos/{owner}/{repository}/issues/{issue_number}/timeline"
        )

    def get_issue(self, owner: str, repository: str, issue_number: int) -> dict[str, Any]:
        return self._get_json(f"https://api.github.com/repos/{owner}/{repository}/issues/{issue_number}")

    def get_pull_request(self, owner: str, repository: str, pull_number: int) -> dict[str, Any]:
        return self._get_json(f"https://api.github.com/repos/{owner}/{repository}/pulls/{pull_number}")

    def list_pull_request_files(self, owner: str, repository: str, pull_number: int) -> list[dict[str, Any]]:
        return self._list_paginated(f"https://api.github.com/repos/{owner}/{repository}/pulls/{pull_number}/files")

    def list_pull_request_reviews(self, owner: str, repository: str, pull_number: int) -> list[dict[str, Any]]:
        return self._list_paginated(f"https://api.github.com/repos/{owner}/{repository}/pulls/{pull_number}/reviews")

    def list_pull_request_commits(self, owner: str, repository: str, pull_number: int) -> list[dict[str, Any]]:
        return self._list_paginated(f"https://api.github.com/repos/{owner}/{repository}/pulls/{pull_number}/commits")

    def get_commit(self, owner: str, repository: str, sha: str) -> dict[str, Any]:
        return self._get_json(f"https://api.github.com/repos/{owner}/{repository}/commits/{sha}")

    def _get_json(self, url: str) -> dict[str, Any]:
        response = self._get(url)
        self._record_rate_limit(response)
        response.raise_for_status()
        return response.json()

    def _list_paginated(self, url: str) -> list[dict[str, Any]]:
        page = 1
        items: list[dict[str, Any]] = []
        while True:
            response = self._get(url, params={"per_page": 100, "page": page})
            self._record_rate_limit(response)
            response.raise_for_status()
            payload = response.json()
            if not payload:
                return items
            items.extend(payload)
            page += 1

    def _record_rate_limit(self, response: httpx.Response) -> None:
        self.rate_limit = {
            "limit": response.headers.get("x-ratelimit-limit"),
            "remaining": response.headers.get("x-ratelimit-remaining"),
            "reset": response.headers.get("x-ratelimit-reset"),
            "resource": response.headers.get("x-ratelimit-resource"),
            "used": response.headers.get("x-ratelimit-used"),
        }

    def _get(self, url: str, *, params: dict[str, str | int] | None = None) -> httpx.Response:
        attempt = 0
        while True:
            try:
                response = self.client.get(url, params=params)
                self._record_rate_limit(response)
                if self._should_wait_for_rate_limit(response):
                    attempt += 1
                    if attempt > self.max_retries:
                        return response
                    time.sleep(self._rate_limit_delay(response))
                    continue
                if response.status_code in {401, 502, 503, 504}:
                    raise httpx.HTTPStatusError("transient GitHub response", request=response.request, response=response)
                return response
            except (httpx.TransportError, httpx.HTTPStatusError):
                attempt += 1
                if attempt > self.max_retries:
                    raise
                time.sleep(self.retry_backoff_seconds * attempt)

    def _should_wait_for_rate_limit(self, response: httpx.Response) -> bool:
        if response.status_code != 403:
            return False
        if response.headers.get("x-ratelimit-remaining") != "0":
            return False
        return self._rate_limit_delay(response) <= self.max_rate_limit_sleep_seconds

    def _rate_limit_delay(self, response: httpx.Response) -> float:
        reset = response.headers.get("x-ratelimit-reset")
        if not reset:
            return self.retry_backoff_seconds
        try:
            return max(float(reset) - time.time() + 1.0, self.retry_backoff_seconds)
        except ValueError:
            return self.retry_backoff_seconds


class GitHubGraphQLAdapter:
    def __init__(self, client: httpx.Client) -> None:
        self.client = client

    def query_cross_references(self, owner: str, repository: str, issue_number: int) -> dict[str, Any]:
        query = """
        query($owner: String!, $name: String!, $number: Int!) {
          repository(owner: $owner, name: $name) {
            issue(number: $number) {
              timelineItems(first: 50, itemTypes: [CROSS_REFERENCED_EVENT]) {
                nodes { __typename ... on CrossReferencedEvent { source { __typename } } }
              }
            }
          }
        }
        """
        response = self.client.post(
            "https://api.github.com/graphql",
            json={"query": query, "variables": {"owner": owner, "name": repository, "number": issue_number}},
        )
        response.raise_for_status()
        return response.json()
