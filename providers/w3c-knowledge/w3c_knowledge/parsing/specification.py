from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from bs4.element import Tag

CONSIDERATION_ALIASES = {
    "privacy_considerations": [
        "privacy considerations",
        "privacy",
    ],
    "security_considerations": [
        "security considerations",
        "security",
    ],
    "privacy_security_considerations": [
        "privacy and security considerations",
        "security and privacy considerations",
    ],
    "accessibility_considerations": [
        "accessibility considerations",
        "accessibility",
    ],
    "internationalization_considerations": [
        "internationalization considerations",
        "internationalization",
        "i18n considerations",
        "i18n",
    ],
}
CONSIDERATION_TYPES = {
    "security": "security_considerations",
    "privacy": "privacy_considerations",
    "accessibility": "accessibility_considerations",
    "internationalization": "internationalization_considerations",
}


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_heading(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", value.lower())).strip()


def classify_section(heading: str, body: str) -> str | None:
    normalized = normalize_heading(heading)
    if normalized in {
        "security and privacy considerations",
        "privacy and security considerations",
    }:
        return "privacy_security_considerations"
    for section_type, aliases in CONSIDERATION_ALIASES.items():
        if any(alias == normalized or alias in normalized for alias in aliases):
            return section_type
    return None


@dataclass(frozen=True)
class ParsedSection:
    heading: str
    anchor: str
    parent_anchor: str | None
    heading_level: int | None
    display_number: str | None
    text: str
    raw_html: str
    order: int
    section_type: str | None
    content_hash: str
    normative: bool | None


@dataclass(frozen=True)
class ParsedIdlBlock:
    order: int
    section_anchor: str | None
    fragment: str | None
    text: str
    source_url: str | None
    content_hash: str


@dataclass(frozen=True)
class ParsedReference:
    reference_type: str
    label: str
    title: str | None
    url: str | None
    section_fragment: str | None


@dataclass(frozen=True)
class ParsedConsiderationStatus:
    consideration_type: str
    status: str
    section_anchor: str | None


@dataclass(frozen=True)
class ParsedSpecification:
    title: str
    text: str
    sections: list[ParsedSection]
    raw_html: str
    webidl_blocks: list[ParsedIdlBlock]
    references: list[ParsedReference]
    consideration_statuses: list[ParsedConsiderationStatus]
    metadata: dict[str, Any]

    @property
    def normative_references(self) -> list[str]:
        return [reference.label for reference in self.references if reference.reference_type == "normative"]

    @property
    def informative_references(self) -> list[str]:
        return [reference.label for reference in self.references if reference.reference_type == "informative"]


def parse_specification_html(html: str, source_url: str | None = None) -> ParsedSpecification:
    soup = BeautifulSoup(html, "lxml")
    for node in soup(["script", "style", "template"]):
        node.decompose()
    for node in soup.find_all(["nav"]):
        node.decompose()
    title = soup.find("title")
    title_text = title.get_text(" ", strip=True) if title else "Untitled specification"
    body_text = soup.get_text("\n", strip=True)
    sections = _extract_sections(soup)
    webidl_blocks = _extract_webidl_blocks(soup, sections, source_url)
    references = _extract_references(soup, source_url)
    metadata = _extract_metadata(soup, source_url)
    return ParsedSpecification(
        title=title_text,
        text=body_text,
        sections=sections,
        raw_html=html,
        webidl_blocks=webidl_blocks,
        references=references,
        consideration_statuses=_consideration_statuses(sections),
        metadata=metadata,
    )


def _extract_sections(soup: BeautifulSoup) -> list[ParsedSection]:
    explicit_sections = [node for node in soup.find_all("section") if isinstance(node, Tag)]
    if explicit_sections:
        return [_section_from_section_node(node, order) for order, node in enumerate(explicit_sections)]
    return _sections_from_headings(soup)


def _section_from_section_node(node: Tag, order: int) -> ParsedSection:
    heading = node.find(re.compile("^h[1-6]$"))
    heading_text = heading.get_text(" ", strip=True) if isinstance(heading, Tag) else f"Section {order + 1}"
    heading_level = _heading_level(heading) if isinstance(heading, Tag) else None
    parent = node.find_parent("section")
    anchor = str(node.get("id") or (heading.get("id") if isinstance(heading, Tag) else "") or _slug(heading_text))
    parent_anchor = str(parent.get("id")) if isinstance(parent, Tag) and parent.get("id") else None
    display_number = _display_number(heading_text)
    text = _document_text(node)
    combined = f"{heading_text}\n{text}".strip()
    return ParsedSection(
        heading=_strip_display_number(heading_text),
        anchor=anchor,
        parent_anchor=parent_anchor,
        heading_level=heading_level,
        display_number=display_number,
        text=text,
        raw_html=str(node),
        order=order,
        section_type=classify_section(heading_text, text),
        content_hash=content_hash(combined),
        normative=bool(re.search(r"\b(MUST|SHOULD|MAY|REQUIRED|SHALL)\b", combined)),
    )


def _sections_from_headings(soup: BeautifulSoup) -> list[ParsedSection]:
    sections: list[ParsedSection] = []
    stack: list[tuple[int, str]] = []
    for order, heading in enumerate(soup.find_all(re.compile("^h[1-6]$"))):
        if not isinstance(heading, Tag):
            continue
        level = _heading_level(heading) or 1
        heading_text = heading.get_text(" ", strip=True)
        anchor = str(heading.get("id") or _slug(heading_text))
        while stack and stack[-1][0] >= level:
            stack.pop()
        parent_anchor = stack[-1][1] if stack else None
        fragments: list[str] = []
        html_fragments: list[str] = []
        for sibling in heading.find_next_siblings():
            if isinstance(sibling, Tag) and re.fullmatch(r"h[1-6]", sibling.name or ""):
                sibling_level = _heading_level(sibling) or 1
                if sibling_level <= level:
                    break
            if isinstance(sibling, Tag):
                html_fragments.append(str(sibling))
                text = _document_text(sibling)
                if text:
                    fragments.append(text)
        text = "\n".join(fragments).strip()
        combined = f"{heading_text}\n{text}".strip()
        sections.append(
            ParsedSection(
                heading=_strip_display_number(heading_text),
                anchor=anchor,
                parent_anchor=parent_anchor,
                heading_level=level,
                display_number=_display_number(heading_text),
                text=text,
                raw_html="\n".join(html_fragments),
                order=order,
                section_type=classify_section(heading_text, text),
                content_hash=content_hash(combined),
                normative=bool(re.search(r"\b(MUST|SHOULD|MAY|REQUIRED|SHALL)\b", combined)),
            )
        )
        stack.append((level, anchor))
    return sections


def _extract_webidl_blocks(
    soup: BeautifulSoup,
    sections: list[ParsedSection],
    source_url: str | None,
) -> list[ParsedIdlBlock]:
    blocks: list[ParsedIdlBlock] = []
    for order, node in enumerate(soup.find_all(["pre", "code"])):
        if not isinstance(node, Tag):
            continue
        classes = " ".join(str(value) for value in node.get("class", []))
        node_id = str(node.get("id") or "")
        if not re.search(r"\b(web)?idl\b", f"{classes} {node_id}", re.I):
            continue
        text = node.get_text("\n", strip=True)
        if not text:
            continue
        section_anchor = _nearest_section_anchor(node, sections)
        fragment = node_id or section_anchor
        blocks.append(
            ParsedIdlBlock(
                order=order,
                section_anchor=section_anchor,
                fragment=fragment,
                text=text,
                source_url=_with_fragment(source_url, fragment),
                content_hash=content_hash(text),
            )
        )
    return blocks


def _extract_references(soup: BeautifulSoup, source_url: str | None) -> list[ParsedReference]:
    references: list[ParsedReference] = []
    for reference_type, fragment in [
        ("normative", "normative-references"),
        ("informative", "informative-references"),
    ]:
        section = soup.find(id=fragment) or _section_by_heading(soup, reference_type)
        if not isinstance(section, Tag):
            continue
        for label, title, url in _references_from_section(section, source_url):
            references.append(
                ParsedReference(
                    reference_type=reference_type,
                    label=label,
                    title=title,
                    url=url,
                    section_fragment=fragment,
                )
            )
    if not references:
        section = soup.find(id="references") or _section_by_exact_heading(soup, "references")
        if isinstance(section, Tag):
            for label, title, url in _references_from_section(section, source_url):
                references.append(
                    ParsedReference(
                        reference_type="unknown",
                        label=label,
                        title=title,
                        url=url,
                        section_fragment="references",
                    )
                )
    return _dedupe_references(references)


def _references_from_section(section: Tag, source_url: str | None) -> list[tuple[str, str | None, str | None]]:
    rows: list[tuple[str, str | None, str | None]] = []
    candidate_nodes = _reference_candidate_nodes(section)
    for dt in (node for node in candidate_nodes if node.name == "dt"):
        if not isinstance(dt, Tag):
            continue
        label = dt.get_text(" ", strip=True).strip("[]")
        dd = dt.find_next_sibling("dd")
        text = dd.get_text(" ", strip=True) if isinstance(dd, Tag) else None
        href = dd.find("a", href=True)["href"] if isinstance(dd, Tag) and dd.find("a", href=True) else None
        rows.append((label, text, urljoin(source_url or "", str(href)) if href else None))
    if rows:
        return rows
    for item in (node for node in candidate_nodes if node.name in {"li", "p"}):
        if not isinstance(item, Tag):
            continue
        text = item.get_text(" ", strip=True)
        match = re.match(r"\[?([A-Za-z0-9._-]+)\]?\s*(.*)", text)
        if not match:
            continue
        link = item.find("a", href=True)
        href = str(link["href"]) if isinstance(link, Tag) else None
        rows.append((match.group(1), match.group(2).strip() or text, urljoin(source_url or "", href) if href else None))
    return rows


def _reference_candidate_nodes(section: Tag) -> list[Tag]:
    if not re.fullmatch(r"h[1-6]", section.name or ""):
        return [node for node in section.find_all(["dt", "li", "p"]) if isinstance(node, Tag)]
    level = _heading_level(section) or 1
    candidates: list[Tag] = []
    for sibling in section.find_next_siblings():
        if isinstance(sibling, Tag) and re.fullmatch(r"h[1-6]", sibling.name or ""):
            sibling_level = _heading_level(sibling) or 1
            if sibling_level <= level:
                break
        if not isinstance(sibling, Tag):
            continue
        if sibling.name in {"dt", "li", "p"}:
            candidates.append(sibling)
        candidates.extend(node for node in sibling.find_all(["dt", "li", "p"]) if isinstance(node, Tag))
    return candidates


def _consideration_statuses(sections: list[ParsedSection]) -> list[ParsedConsiderationStatus]:
    found: dict[str, ParsedSection] = {}
    combined: ParsedSection | None = None
    ambiguous: set[str] = set()
    for section in sections:
        if section.section_type == "privacy_security_considerations":
            combined = section
            continue
        for key, section_type in CONSIDERATION_TYPES.items():
            if section.section_type == section_type:
                if key in found:
                    ambiguous.add(key)
                found[key] = section
    statuses: list[ParsedConsiderationStatus] = []
    for key in ["security", "privacy", "accessibility", "internationalization"]:
        if combined is not None and key in {"security", "privacy"}:
            statuses.append(ParsedConsiderationStatus(key, "combined", combined.anchor))
        elif key in ambiguous:
            statuses.append(ParsedConsiderationStatus(key, "ambiguous", found[key].anchor))
        elif key in found:
            statuses.append(ParsedConsiderationStatus(key, "present", found[key].anchor))
        else:
            statuses.append(ParsedConsiderationStatus(key, "absent", None))
    return statuses


def _extract_metadata(soup: BeautifulSoup, source_url: str | None) -> dict[str, Any]:
    metadata: dict[str, Any] = {"links": {}}
    for link in soup.find_all("link"):
        if isinstance(link, Tag) and link.get("rel") and link.get("href"):
            rel = " ".join(str(item) for item in link.get("rel", []))
            metadata["links"][rel] = urljoin(source_url or "", str(link["href"]))
    text = soup.get_text("\n", strip=True)
    editor_match = re.search(r"Latest editor'?s draft\s*[:\n]\s*(https?://\S+)", text, flags=re.I)
    if editor_match:
        metadata["editors_draft_url"] = editor_match.group(1).rstrip(").,")
    published_match = re.search(r"Latest published version\s*[:\n]\s*(https?://\S+)", text, flags=re.I)
    if published_match:
        metadata["latest_published_url"] = published_match.group(1).rstrip(").,")
    github_links = [
        urljoin(source_url or "", str(link["href"])).rstrip("/")
        for link in soup.find_all("a", href=True)
        if isinstance(link, Tag)
        and re.match(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$", urljoin(source_url or "", str(link["href"])))
    ]
    if github_links:
        metadata["source_repository_url"] = github_links[0]
    repo_match = re.search(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", text)
    if repo_match:
        metadata.setdefault("source_repository_url", repo_match.group(0).rstrip("/"))
    canonical = metadata["links"].get("canonical")
    if canonical:
        metadata["canonical_url"] = canonical
    latest = metadata["links"].get("latest-version")
    if latest:
        metadata["latest_version_url"] = latest
    return metadata


def _dedupe_references(references: list[ParsedReference]) -> list[ParsedReference]:
    seen: set[tuple[str, str]] = set()
    deduped: list[ParsedReference] = []
    for reference in references:
        key = (reference.reference_type, reference.label)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(reference)
    return deduped


def _document_text(node: Tag) -> str:
    return node.get_text("\n", strip=True)


def _heading_level(node: Tag | None) -> int | None:
    if node is None or not node.name:
        return None
    match = re.fullmatch(r"h([1-6])", node.name)
    return int(match.group(1)) if match else None


def _display_number(heading: str) -> str | None:
    match = re.match(r"^\s*((?:\d+\.)+\d*|[A-Z]\.)\s+", heading)
    return match.group(1).rstrip(".") if match else None


def _strip_display_number(heading: str) -> str:
    return re.sub(r"^\s*(?:\d+(?:\.\d+)*\.?|[A-Z]\.)\s+", "", heading).strip()


def _slug(value: str) -> str:
    return normalize_heading(value).replace(" ", "-") or "section"


def _with_fragment(url: str | None, fragment: str | None) -> str | None:
    if not url:
        return None
    return f"{url.rstrip('#')}#{fragment}" if fragment else url


def _nearest_section_anchor(node: Tag, sections: list[ParsedSection]) -> str | None:
    parent = node.find_parent(["section"])
    if isinstance(parent, Tag) and parent.get("id"):
        return str(parent["id"])
    heading = node.find_previous(re.compile("^h[1-6]$"))
    if isinstance(heading, Tag):
        anchor = str(heading.get("id") or _slug(heading.get_text(" ", strip=True)))
        if any(section.anchor == anchor for section in sections):
            return anchor
    return None


def _section_by_heading(soup: BeautifulSoup, reference_type: str) -> Tag | None:
    for heading in soup.find_all(re.compile("^h[1-6]$")):
        if not isinstance(heading, Tag):
            continue
        normalized = normalize_heading(heading.get_text(" ", strip=True))
        if reference_type in normalized and "reference" in normalized:
            return heading.find_parent("section") or heading
    return None


def _section_by_exact_heading(soup: BeautifulSoup, heading_text: str) -> Tag | None:
    expected = normalize_heading(heading_text)
    for heading in soup.find_all(re.compile("^h[1-6]$")):
        if not isinstance(heading, Tag):
            continue
        normalized = normalize_heading(heading.get_text(" ", strip=True))
        if normalized == expected:
            return heading.find_parent("section") or heading
    return None
