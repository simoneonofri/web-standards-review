from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from bs4 import BeautifulSoup, NavigableString, Tag
from lxml import etree

from w3c_knowledge.adapters.rfc_editor import RFCMetadata
from w3c_knowledge.parsing.specification import (
    ParsedConsiderationStatus,
    ParsedReference,
    ParsedSection,
    ParsedSpecification,
    classify_section,
    content_hash,
    normalize_heading,
    parse_specification_html,
)


def parse_rfc_document(
    metadata: RFCMetadata,
    content: str,
    content_format: str,
    source_url: str,
) -> ParsedSpecification:
    if content_format == "xml":
        parsed = _parse_rfc_xml(metadata, content, source_url)
    elif content_format == "html":
        parsed = _parse_rfc_html(metadata, content, source_url)
    elif content_format == "txt":
        parsed = _parse_rfc_txt(metadata, content, source_url)
    else:
        parsed = _metadata_only(metadata, source_url)
    normalized_metadata = _normalized_metadata(metadata, content_format, source_url)
    return replace(parsed, metadata={**parsed.metadata, **normalized_metadata})


def _parse_rfc_xml(metadata: RFCMetadata, content: str, source_url: str) -> ParsedSpecification:
    parser = etree.XMLParser(resolve_entities=False, no_network=True, recover=True)
    root = etree.fromstring(content.encode("utf-8"), parser=parser)
    title = _xml_text(_first_xml(root, ".//front/title")) or metadata.title
    sections: list[ParsedSection] = []
    for node in root.xpath(".//*[local-name()='section']"):
        if not isinstance(node, etree._Element):
            continue
        parent = node.getparent()
        parent_anchor = parent.get("anchor") if parent is not None and _local_name(parent) == "section" else None
        heading = node.get("title") or _xml_text(_first_child(node, "name")) or f"Section {len(sections) + 1}"
        anchor = node.get("anchor") or _slug(f"{_display_number_from_node(node)} {heading}".strip())
        display_number = _display_number_from_node(node)
        text = _xml_section_text(node)
        combined = f"{heading}\n{text}".strip()
        sections.append(
            ParsedSection(
                heading=_strip_display_number(heading),
                anchor=anchor,
                parent_anchor=parent_anchor,
                heading_level=_xml_depth(node),
                display_number=display_number,
                text=text,
                raw_html=etree.tostring(node, encoding="unicode"),
                order=len(sections),
                section_type=classify_section(heading, text),
                content_hash=content_hash(combined),
                normative=bool(re.search(r"\b(MUST|SHOULD|MAY|REQUIRED|SHALL)\b", combined)),
            )
        )
    references = _xml_references(root)
    full_text = "\n\n".join([title, *[section.text for section in sections]]).strip()
    return ParsedSpecification(
        title=title,
        text=full_text,
        sections=sections,
        raw_html=content,
        webidl_blocks=[],
        references=references,
        consideration_statuses=_consideration_statuses(sections),
        metadata={},
    )


def _parse_rfc_html(metadata: RFCMetadata, content: str, source_url: str) -> ParsedSpecification:
    soup = BeautifulSoup(content, "lxml")
    for node in soup(["script", "style", "template", "nav"]):
        node.decompose()
    for node in soup.find_all(class_=re.compile(r"^(toc|navbar|pilcrow)$", re.I)):
        node.decompose()
    for node in soup.find_all(class_=re.compile(r"^(grey|noprint)$", re.I)):
        node.decompose()
    if soup.find("span", class_=re.compile(r"\bh[1-6]\b", re.I)):
        legacy = _parse_rfc_legacy_html(metadata, soup, source_url, content)
        if legacy.sections:
            return legacy
    parsed = parse_specification_html(str(soup), source_url)
    if parsed.sections:
        return replace(
            parsed,
            title=parsed.title if parsed.title != "Untitled specification" else metadata.title,
            metadata={**parsed.metadata, "rfc_html_parser": "specification_html_fallback"},
        )
    text_fallback = _parse_rfc_txt(metadata, soup.get_text("\n"), source_url)
    return replace(
        text_fallback,
        raw_html=content,
        metadata={**text_fallback.metadata, "rfc_html_parser": "text_fallback"},
    )


def _parse_rfc_legacy_html(
    metadata: RFCMetadata,
    soup: BeautifulSoup,
    source_url: str,
    raw_html: str,
) -> ParsedSpecification:
    heading_nodes = [
        node
        for node in soup.find_all("span")
        if isinstance(node, Tag) and _rfc_heading_level(node) is not None and _heading_text(node)
    ]
    sections: list[ParsedSection] = []
    stack: list[tuple[int, str]] = []
    for node in heading_nodes:
        level = _rfc_heading_level(node)
        if level is None:
            continue
        heading_text = _heading_text(node)
        if not heading_text or level == 1:
            continue
        display_number, heading = _split_heading_number(heading_text)
        anchor = _rfc_heading_anchor(node) or _slug(f"{display_number or ''} {heading}".strip())
        while stack and stack[-1][0] >= level:
            stack.pop()
        parent_anchor = stack[-1][1] if stack else None
        body = _legacy_html_section_text(node)
        combined = f"{heading}\n{body}".strip()
        sections.append(
            ParsedSection(
                heading=heading,
                anchor=anchor,
                parent_anchor=parent_anchor,
                heading_level=level,
                display_number=display_number,
                text=body,
                raw_html=str(node.parent) if node.parent is not None else str(node),
                order=len(sections),
                section_type=classify_section(heading, body),
                content_hash=content_hash(combined),
                normative=bool(re.search(r"\b(MUST|SHOULD|MAY|REQUIRED|SHALL)\b", combined)),
            )
        )
        stack.append((level, anchor))
    references = _txt_references(sections)
    title = _html_title(soup) or metadata.title
    full_text = "\n\n".join([title, *[section.text for section in sections]]).strip()
    return ParsedSpecification(
        title=title,
        text=full_text,
        sections=sections,
        raw_html=raw_html,
        webidl_blocks=[],
        references=references,
        consideration_statuses=_consideration_statuses(sections),
        metadata={"canonical_url": source_url, "rfc_html_parser": "legacy_heading_span"},
    )


def _parse_rfc_txt(metadata: RFCMetadata, content: str, source_url: str) -> ParsedSpecification:
    lines = content.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    headings: list[tuple[int, str, str, int]] = []
    known = {
        "abstract",
        "status of this memo",
        "copyright notice",
        "table of contents",
        "introduction",
        "security considerations",
        "privacy considerations",
        "iana considerations",
        "references",
        "normative references",
        "informative references",
        "authors' addresses",
        "authors addresses",
    }
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        number_match = re.match(r"^((?:\d+\.)+\d*|\d+)\s+([A-Z][^\n]{2,120})$", stripped)
        if number_match and _looks_like_numbered_heading(stripped):
            number = number_match.group(1).rstrip(".")
            title = number_match.group(2).strip()
            headings.append((index, title, number, number.count(".") + 1))
            continue
        normalized = normalize_heading(stripped)
        if normalized in known:
            headings.append((index, stripped, "", 1))
    sections: list[ParsedSection] = []
    stack: list[tuple[int, str]] = []
    for order, (line_index, heading, display_number, level) in enumerate(headings):
        next_line = headings[order + 1][0] if order + 1 < len(headings) else len(lines)
        body = "\n".join(lines[line_index + 1 : next_line]).strip()
        while stack and stack[-1][0] >= level:
            stack.pop()
        parent_anchor = stack[-1][1] if stack else None
        anchor = _slug(f"{display_number} {heading}".strip())
        combined = f"{heading}\n{body}".strip()
        sections.append(
            ParsedSection(
                heading=_strip_display_number(heading),
                anchor=anchor,
                parent_anchor=parent_anchor,
                heading_level=level,
                display_number=display_number or None,
                text=body,
                raw_html=body,
                order=order,
                section_type=classify_section(heading, body),
                content_hash=content_hash(combined),
                normative=bool(re.search(r"\b(MUST|SHOULD|MAY|REQUIRED|SHALL)\b", combined)),
            )
        )
        stack.append((level, anchor))
    references = _txt_references(sections)
    title = metadata.title
    return ParsedSpecification(
        title=title,
        text=content.strip(),
        sections=sections,
        raw_html=content,
        webidl_blocks=[],
        references=references,
        consideration_statuses=_consideration_statuses(sections),
        metadata={"canonical_url": source_url},
    )


def _metadata_only(metadata: RFCMetadata, source_url: str) -> ParsedSpecification:
    text = "\n\n".join(item for item in [metadata.title, metadata.abstract or ""] if item)
    return ParsedSpecification(
        title=metadata.title,
        text=text,
        sections=[],
        raw_html="",
        webidl_blocks=[],
        references=[],
        consideration_statuses=[
            ParsedConsiderationStatus("security", "unable_to_parse", None),
            ParsedConsiderationStatus("privacy", "unable_to_parse", None),
            ParsedConsiderationStatus("accessibility", "unable_to_parse", None),
            ParsedConsiderationStatus("internationalization", "unable_to_parse", None),
        ],
        metadata={"canonical_url": source_url},
    )


def _xml_references(root: etree._Element) -> list[ParsedReference]:
    references: list[ParsedReference] = []
    for refs in root.xpath(".//*[local-name()='references']"):
        if not isinstance(refs, etree._Element):
            continue
        title = refs.get("title") or _xml_text(_first_child(refs, "name")) or "References"
        normalized = normalize_heading(title)
        reference_type = "unknown"
        if "normative" in normalized:
            reference_type = "normative"
        elif "informative" in normalized:
            reference_type = "informative"
        for reference in refs.xpath("./*[local-name()='reference']"):
            if not isinstance(reference, etree._Element):
                continue
            anchor = reference.get("anchor") or reference.get("target") or f"REF{len(references) + 1}"
            ref_title = _xml_text(_first_xml(reference, ".//*[local-name()='title']"))
            target = reference.get("target")
            references.append(
                ParsedReference(
                    reference_type=reference_type,
                    label=anchor.strip("[]"),
                    title=ref_title,
                    url=target,
                    section_fragment=_slug(title),
                )
            )
    return _dedupe(references)


def _txt_references(sections: list[ParsedSection]) -> list[ParsedReference]:
    references: list[ParsedReference] = []
    current_type = "unknown"
    for section in sections:
        normalized = normalize_heading(section.heading)
        if "normative" in normalized and "reference" in normalized:
            current_type = "normative"
        elif "informative" in normalized and "reference" in normalized:
            current_type = "informative"
        elif normalized == "references":
            current_type = "unknown"
        else:
            continue
        for match in re.finditer(r"\[?(RFC\d+|[A-Z][A-Z0-9-]{1,30})\]?\s+([^\n]+)", section.text):
            references.append(
                ParsedReference(
                    reference_type=current_type,
                    label=match.group(1).strip("[]"),
                    title=match.group(2).strip(),
                    url=None,
                    section_fragment=section.anchor,
                )
            )
    return _dedupe(references)


def _consideration_statuses(sections: list[ParsedSection]) -> list[ParsedConsiderationStatus]:
    statuses: dict[str, ParsedConsiderationStatus] = {}
    for section in sections:
        if section.section_type == "privacy_security_considerations":
            statuses["security"] = ParsedConsiderationStatus("security", "combined", section.anchor)
            statuses["privacy"] = ParsedConsiderationStatus("privacy", "combined", section.anchor)
        elif section.section_type == "security_considerations":
            statuses["security"] = ParsedConsiderationStatus("security", "present", section.anchor)
        elif section.section_type == "privacy_considerations":
            statuses["privacy"] = ParsedConsiderationStatus("privacy", "present", section.anchor)
        elif section.section_type == "accessibility_considerations":
            statuses["accessibility"] = ParsedConsiderationStatus("accessibility", "present", section.anchor)
        elif section.section_type == "internationalization_considerations":
            statuses["internationalization"] = ParsedConsiderationStatus("internationalization", "present", section.anchor)
    return [
        statuses.get(key, ParsedConsiderationStatus(key, "absent", None))
        for key in ["security", "privacy", "accessibility", "internationalization"]
    ]


def _normalized_metadata(metadata: RFCMetadata, content_format: str, source_url: str) -> dict[str, Any]:
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
        "content_format": content_format,
        "canonical_url": source_url,
    }


def _xml_text(node: etree._Element | None) -> str | None:
    if node is None:
        return None
    text = " ".join(part.strip() for part in node.itertext() if part.strip())
    return re.sub(r"\s+", " ", text).strip() or None


def _xml_section_text(node: etree._Element) -> str:
    fragments: list[str] = []
    for child in node:
        if _local_name(child) == "section":
            continue
        text = _xml_text(child)
        if text:
            fragments.append(text)
    return "\n".join(fragments).strip()


def _first_xml(node: etree._Element, xpath: str) -> etree._Element | None:
    result = node.xpath(xpath)
    return result[0] if result and isinstance(result[0], etree._Element) else None


def _first_child(node: etree._Element, local_name: str) -> etree._Element | None:
    for child in node:
        if _local_name(child) == local_name:
            return child
    return None


def _local_name(node: etree._Element) -> str:
    return etree.QName(node).localname


def _rfc_heading_level(node: Tag) -> int | None:
    classes = node.get("class") or []
    for class_name in classes:
        match = re.fullmatch(r"h([1-6])", str(class_name), re.I)
        if match:
            return int(match.group(1))
    return None


def _rfc_heading_anchor(node: Tag) -> str | None:
    link = node.find("a", id=True)
    if isinstance(link, Tag):
        return str(link.get("id"))
    if node.get("id"):
        return str(node.get("id"))
    return None


def _heading_text(node: Tag) -> str:
    text = node.get_text(" ", strip=True)
    return re.sub(r"\s+", " ", text).strip()


def _split_heading_number(value: str) -> tuple[str | None, str]:
    match = re.match(r"^([A-Z]?(?:\d+(?:\.\d+)*|[A-Z](?:\.\d+)*))\.?\s+(.+)$", value.strip())
    if match:
        heading = re.sub(r"^\.\s*", "", match.group(2).strip())
        return match.group(1), heading
    return None, _strip_display_number(value)


def _legacy_html_section_text(node: Tag) -> str:
    fragments: list[str] = []
    for element in node.next_elements:
        if element is node:
            continue
        if isinstance(element, Tag):
            if element is not node and element.name == "span" and _rfc_heading_level(element) is not None:
                break
            if element.name in {"script", "style", "template"}:
                continue
        if isinstance(element, NavigableString):
            parent = element.parent
            if isinstance(parent, Tag) and parent.name == "span" and _rfc_heading_level(parent) is not None:
                continue
            text = str(element)
            if text.strip():
                fragments.append(text.strip())
    return re.sub(r"\n{3,}", "\n\n", "\n".join(fragments)).strip()


def _html_title(soup: BeautifulSoup) -> str | None:
    if soup.title:
        title = soup.title.get_text(" ", strip=True)
        if title:
            return title
    heading = soup.find("span", class_=re.compile(r"\bh1\b", re.I))
    if isinstance(heading, Tag):
        title = heading.get_text(" ", strip=True)
        if title:
            return title
    return None


def _xml_depth(node: etree._Element) -> int:
    depth = 1
    parent = node.getparent()
    while parent is not None:
        if _local_name(parent) == "section":
            depth += 1
        parent = parent.getparent()
    return depth


def _display_number_from_node(node: etree._Element) -> str | None:
    value = node.get("numbered")
    if value == "false":
        return None
    return node.get("pn", "").removeprefix("section-") or None


def _looks_like_numbered_heading(value: str) -> bool:
    if len(value) > 140:
        return False
    if value.endswith((".", ",", ";")) and not re.match(r"^\d+(?:\.\d+)*\.\s+", value):
        return False
    return True


def _strip_display_number(heading: str) -> str:
    return re.sub(r"^\s*(?:\d+(?:\.\d+)*\.?)\s+", "", heading).strip()


def _slug(value: str) -> str:
    slug = normalize_heading(value).replace(" ", "-")
    return slug or "section"


def _dedupe(references: list[ParsedReference]) -> list[ParsedReference]:
    seen: set[tuple[str, str]] = set()
    result: list[ParsedReference] = []
    for reference in references:
        key = (reference.reference_type, reference.label)
        if key in seen:
            continue
        seen.add(key)
        result.append(reference)
    return result
