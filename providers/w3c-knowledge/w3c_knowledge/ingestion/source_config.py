from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class SourceConfig(BaseModel):
    name: str
    source_type: str
    url: str
    canonical_url: str | None = None
    organization: str | None = None
    repository: str | None = None
    branch: str | None = None
    document_path: str | None = None
    primary_domain: str
    applicable_domains: list[str] = Field(default_factory=list)
    artifact_types: list[str] = Field(default_factory=list)
    enabled: bool = True
    source_priority: int = 100
    sync_strategy: str = "incremental"
    parser: str | None = None
    default_labels: list[str] = Field(default_factory=list)
    allow_redirects: bool = True
    historical_versions: list[str] = Field(default_factory=list)
    authentication_profile: str | None = None


def load_sources(path: str | Path) -> list[SourceConfig]:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return [SourceConfig.model_validate(item) for item in payload.get("sources", [])]


def source_to_model_kwargs(source: SourceConfig) -> dict[str, Any]:
    data = source.model_dump()
    data["raw_config"] = source.model_dump()
    return data
