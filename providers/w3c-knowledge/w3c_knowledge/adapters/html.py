from __future__ import annotations

from typing import cast

import bleach

ALLOWED_TAGS = [
    "a",
    "p",
    "section",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "pre",
    "code",
    "ol",
    "ul",
    "li",
    "dl",
    "dt",
    "dd",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
]


def sanitize_html(html: str) -> str:
    return cast(
        str,
        bleach.clean(
            html,
            tags=ALLOWED_TAGS,
            attributes={"a": ["href"], "*": ["id", "class"]},
            strip=True,
        ),
    )
