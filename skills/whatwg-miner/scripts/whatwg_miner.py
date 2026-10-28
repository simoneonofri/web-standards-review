#!/usr/bin/env python3
"""Stdlib helpers for WHATWG inventory, snapshots, mining, and catalogs."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable

INDEX_URL = "https://spec.whatwg.org/"
USER_AGENT = "whatwg-miner/1.0 (+local standards review)"
BLOCK_TAGS = {"p", "li", "dd", "dt"}
HEADING_TAGS = {"h2", "h3", "h4", "h5", "h6"}
SKIP_TAGS = {"script", "style", "svg", "nav", "header", "footer"}

CATEGORY_PATTERNS: dict[str, tuple[str, ...]] = {
    "authority-and-permission": (
        r"\bpermission(?:s| state)?\b", r"\ballowlist\b", r"\bden(?:y|ied|ies)\b",
        r"\bauthori[sz](?:e|ed|ation)\b", r"\bcapabilit(?:y|ies)\b",
    ),
    "origin-and-isolation": (
        r"\bsame[- ]origin\b", r"\bcross[- ]origin\b", r"\borigin[- ]keyed\b",
        r"\bopaque origin\b", r"\bsandbox(?:ed|ing)?\b", r"\bpartition(?:ed|ing)?\b",
        r"\bcross-origin isolated\b", r"\bagent cluster\b",
    ),
    "network-and-request-policy": (
        r"\bcors\b", r"\bcredentials mode\b", r"\bforbidden (?:request|response)[- ]header\b",
        r"\bmixed content\b", r"\bnetwork error\b", r"\bunsafe request\b",
        r"\bwebsocket secure\b", r"\bblocked port\b", r"\breferrer policy\b",
    ),
    "content-and-type-safety": (
        r"\bmime type\b", r"\bnosniff\b", r"\bcontent-type\b", r"\bencoding\b",
        r"\btrusted type\b", r"\bintegrity metadata\b", r"\bscript[- ]like\b",
    ),
    "user-intent-and-visibility": (
        r"\btransient activation\b", r"\buser activation\b", r"\buser gesture\b",
        r"\bpermission prompt\b", r"\bexit fullscreen\b", r"\buser intent\b",
    ),
    "storage-and-state": (
        r"\bhttponly\b", r"\bsame[- ]site\b", r"\bstorage key\b", r"\bstorage shed\b",
        r"\bquota\b", r"\bpersist(?:ed|ence|ent)?\b", r"\bcookie\b",
    ),
    "resource-and-abuse-control": (
        r"\bbackpressure\b", r"\bdecompression bomb\b", r"\bdenial of service\b",
        r"\bresource exhaustion\b", r"\bsize limit\b", r"\brate limit\b",
    ),
    "input-validation-and-failure": (
        r"\bvalidation error\b", r"\bsyntaxerror\b", r"\bsecurityerror\b",
        r"\bnotallowederror\b", r"\bthrow(?:s|ing)?\b", r"\breject(?:ed|ion)?\b",
    ),
    "interface-exposure": (
        r"\bsecurecontext\b", r"\bcrossoriginisolated\b", r"\bexposed\b",
    ),
}

SECURITY_MARKERS = (
    r"\bsecurity\b", r"\battack(?:er|s)?\b", r"\bthreat\b", r"\bprotect(?:s|ed|ion)?\b",
    r"\bunsafe\b", r"\btrusted\b", r"\bcredential(?:s|ed)?\b", r"\bauthority\b",
    r"\bprivilege(?:d|s)?\b", r"\bleak(?:age|s)?\b", r"\bspoof(?:ing|ed)?\b",
)
PRIVACY_MARKERS = (r"\bprivacy\b", r"\bfingerprint(?:ing|able)?\b", r"\btracking\b")


def normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


def slug_from_url(url: str) -> str:
    host = urllib.parse.urlparse(url).hostname or ""
    if host.endswith(".spec.whatwg.org"):
        return host.split(".", 1)[0]
    raise ValueError(f"not a WHATWG specification URL: {url}")


def atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(data)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def dump_json(path: Path, value: object) -> None:
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_bytes(url: str, retries: int = 3, timeout: int = 60) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except Exception as error:  # pragma: no cover - exercised only on network failure
            last_error = error
            if attempt + 1 < retries:
                time.sleep(2**attempt)
    assert last_error is not None
    raise last_error


class StandardsIndexParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_dl = False
        self.in_dt = False
        self.in_dd = False
        self.current_url: str | None = None
        self.in_title_link = False
        self.current_title: list[str] = []
        self.current_description: list[str] = []
        self.records: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "dl":
            self.in_dl = True
        elif self.in_dl and tag == "dt":
            self.in_dt = True
            self.current_url = None
            self.current_title = []
            self.current_description = []
        elif self.in_dl and tag == "dd":
            self.in_dd = True
        elif self.in_dt and tag == "a" and self.current_url is None:
            href = attributes.get("href")
            if href and href.startswith("https://") and ".spec.whatwg.org" in href:
                self.current_url = href
                self.in_title_link = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self.in_title_link:
            self.in_title_link = False
        elif tag == "dt":
            self.in_dt = False
        elif tag == "dd":
            self.in_dd = False
            if self.current_url:
                title = normalize_space("".join(self.current_title))
                description = normalize_space("".join(self.current_description))
                self.records.append({
                    "id": slug_from_url(self.current_url),
                    "title": title,
                    "url": self.current_url,
                    "description": description,
                })
            self.current_url = None
        elif tag == "dl":
            self.in_dl = False

    def handle_data(self, data: str) -> None:
        if self.in_dt and self.current_url and self.in_title_link:
            self.current_title.append(data)
        elif self.in_dd and self.current_url:
            self.current_description.append(data)


def parse_index(data: bytes, source_url: str = INDEX_URL) -> dict[str, object]:
    parser = StandardsIndexParser()
    parser.feed(data.decode("utf-8"))
    records = sorted(parser.records, key=lambda record: record["id"])
    if not records:
        raise ValueError("no WHATWG standards found in official index")
    if len({record["id"] for record in records}) != len(records):
        raise ValueError("duplicate standard IDs in official index")
    return {
        "schema_version": "1.0",
        "source_url": source_url,
        "source_sha256": sha256_bytes(data),
        "standard_count": len(records),
        "standards": records,
    }


def snapshot_url(standard: dict[str, str]) -> str:
    # The root HTML URL is the complete single-page standard; the official index
    # links HTML's multipage presentation.
    if standard["id"] == "html":
        return "https://html.spec.whatwg.org/"
    return standard["url"]


@dataclass(frozen=True)
class EvidenceBlock:
    heading: str
    anchor: str
    text: str


class SpecDocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.skip_depth = 0
        self.heading_tag: str | None = None
        self.heading_id = ""
        self.heading_text: list[str] = []
        self.current_heading = "Document"
        self.current_heading_id = ""
        self.block_tag: str | None = None
        self.block_id = ""
        self.block_text: list[str] = []
        self.blocks: list[EvidenceBlock] = []

    def _flush_block(self) -> None:
        if self.block_tag is None:
            return
        text = normalize_space("".join(self.block_text))
        if len(text) >= 30:
            self.blocks.append(EvidenceBlock(
                heading=self.current_heading,
                anchor=self.block_id or self.current_heading_id,
                text=text,
            ))
        self.block_tag = None
        self.block_id = ""
        self.block_text = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag in SKIP_TAGS:
            self.skip_depth += 1
            return
        if self.skip_depth:
            return
        if tag in HEADING_TAGS:
            self._flush_block()
            self.heading_tag = tag
            self.heading_id = attributes.get("id") or ""
            self.heading_text = []
        elif tag in BLOCK_TAGS:
            # WHATWG source uses HTML's optional end tags extensively. A new
            # block start therefore closes any still-open previous block.
            self._flush_block()
            self.block_tag = tag
            self.block_id = attributes.get("id") or ""
            self.block_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag in SKIP_TAGS and self.skip_depth:
            self.skip_depth -= 1
            return
        if self.skip_depth:
            return
        if tag == self.heading_tag:
            heading = normalize_space("".join(self.heading_text))
            if heading:
                self.current_heading = heading
                self.current_heading_id = self.heading_id
            self.heading_tag = None
        elif tag == self.block_tag:
            self._flush_block()

    def handle_data(self, data: str) -> None:
        if self.skip_depth:
            return
        if self.heading_tag:
            self.heading_text.append(data)
        if self.block_tag:
            self.block_text.append(data)


def parse_spec(data: bytes) -> list[EvidenceBlock]:
    parser = SpecDocumentParser()
    parser.feed(data.decode("utf-8", errors="replace"))
    parser._flush_block()
    return parser.blocks


def matched_categories(text: str) -> list[str]:
    lowered = text.casefold()
    return sorted(
        category
        for category, patterns in CATEGORY_PATTERNS.items()
        if any(re.search(pattern, lowered) for pattern in patterns)
    )


def candidate_score(text: str, categories: Iterable[str]) -> int:
    lowered = text.casefold()
    category_count = len(tuple(categories))
    security = sum(bool(re.search(pattern, lowered)) for pattern in SECURITY_MARKERS)
    privacy = sum(bool(re.search(pattern, lowered)) for pattern in PRIVACY_MARKERS)
    normative = int(bool(re.search(r"\b(must|must not|shall|required|requires|throw|reject|return a network error)\b", lowered)))
    return category_count * 2 + security * 2 + normative - (privacy if security == 0 else 0)


def evidence_class(text: str, heading: str) -> str:
    lowered = f"{heading} {text}".casefold()
    has_security = any(re.search(pattern, lowered) for pattern in SECURITY_MARKERS)
    has_privacy = any(re.search(pattern, lowered) for pattern in PRIVACY_MARKERS)
    if "test utils" in lowered or "test automation" in lowered:
        return "testing_only"
    if has_privacy and not has_security:
        return "privacy_only"
    if has_security:
        if "security consideration" in lowered or "security and privacy" in lowered:
            return "security_rationale"
        return "security_control"
    return "generic_algorithm"


def excerpt(text: str, limit: int = 280) -> str:
    if len(text) <= limit:
        return text
    shortened = text[: limit + 1].rsplit(" ", 1)[0]
    return shortened.rstrip(" ,;:") + "…"


def mine_candidates(standard: dict[str, str], data: bytes, source_sha256: str) -> list[dict[str, object]]:
    base = snapshot_url(standard)
    records: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for block in parse_spec(data):
        categories = matched_categories(f"{block.heading} {block.text}")
        if not categories:
            continue
        score = candidate_score(block.text, categories)
        if score < 3:
            continue
        key = (block.anchor, block.text)
        if key in seen:
            continue
        seen.add(key)
        url = base
        if block.anchor:
            url = urllib.parse.urljoin(base, "#" + urllib.parse.quote(block.anchor, safe="-._~:()"))
        records.append({
            "standard_id": standard["id"],
            "standard": standard["title"],
            "heading": block.heading,
            "url": url,
            "categories": categories,
            "evidence": excerpt(block.text),
            "evidence_kind": "short_quote",
            "evidence_class": evidence_class(block.text, block.heading),
            "score": score,
            "source_sha256": source_sha256,
        })
    return sorted(records, key=lambda record: (-int(record["score"]), str(record["url"]), str(record["evidence"])))


def load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def anchor_exists(data: bytes, anchor: str) -> bool:
    decoded = urllib.parse.unquote(anchor)
    escaped = re.escape(decoded.encode("utf-8"))
    return bool(re.search(rb"\bid=[\"']" + escaped + rb"[\"']", data))


def validate_findings(findings: list[dict[str, object]], inventory: dict[str, object], artifacts: Path | None = None) -> list[str]:
    errors: list[str] = []
    standards = {record["id"]: record for record in inventory["standards"]}  # type: ignore[index]
    seen: set[str] = set()
    required = {
        "id", "standard_id", "control", "category", "section", "url", "evidence",
        "evidence_kind", "normative_status", "evidence_class", "applicability",
        "secure_default", "failure_behavior", "exceptions", "dependencies",
        "limitations", "confidence",
    }
    for finding in findings:
        missing = sorted(required - set(finding))
        if missing:
            errors.append(f"{finding.get('id', '<unknown>')}: missing {', '.join(missing)}")
            continue
        finding_id = str(finding["id"])
        if finding_id in seen:
            errors.append(f"duplicate finding id: {finding_id}")
        seen.add(finding_id)
        standard_id = str(finding["standard_id"])
        if standard_id not in standards:
            errors.append(f"{finding_id}: unknown standard {standard_id}")
            continue
        parsed = urllib.parse.urlparse(str(finding["url"]))
        if parsed.scheme != "https" or not (parsed.hostname or "").endswith(".spec.whatwg.org"):
            errors.append(f"{finding_id}: non-WHATWG URL {finding['url']}")
        if not parsed.fragment:
            errors.append(f"{finding_id}: URL has no anchor")
        if finding["evidence_kind"] not in {"semantic_summary", "short_quote"}:
            errors.append(f"{finding_id}: invalid evidence_kind")
        if finding["normative_status"] not in {"normative", "informative", "mixed"}:
            errors.append(f"{finding_id}: invalid normative_status")
        if finding["confidence"] not in {"high", "medium"}:
            errors.append(f"{finding_id}: curated findings cannot have candidate confidence")
        if finding["evidence_class"] not in {"security_control", "security_rationale"}:
            errors.append(f"{finding_id}: excluded evidence class in curated catalog")
        if artifacts and parsed.fragment:
            path = artifacts / f"{standard_id}.html"
            if path.exists() and not anchor_exists(path.read_bytes(), parsed.fragment):
                errors.append(f"{finding_id}: anchor not found in snapshot: {parsed.fragment}")
    return errors
