from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from tempfile import gettempdir

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "sqlite+pysqlite:///:memory:"
    api_token: str | None = Field(default=None, alias="W3C_KNOWLEDGE_API_TOKEN")
    github_token: str | None = Field(default=None, alias="GITHUB_TOKEN")
    allowed_domains: str = Field(
        default="w3.org,github.com,api.github.com,datatracker.ietf.org,www.ietf.org",
        alias="W3C_KNOWLEDGE_ALLOWED_DOMAINS",
    )
    http_timeout: float = Field(default=20.0, alias="W3C_KNOWLEDGE_HTTP_TIMEOUT")
    max_response_bytes: int = Field(default=20_971_520, alias="W3C_KNOWLEDGE_MAX_RESPONSE_BYTES")
    w3c_retry_attempts: int = Field(default=3, alias="W3C_KNOWLEDGE_W3C_RETRY_ATTEMPTS")
    w3c_retry_backoff_seconds: float = Field(
        default=0.5,
        alias="W3C_KNOWLEDGE_W3C_RETRY_BACKOFF_SECONDS",
    )
    w3c_request_delay_seconds: float = Field(
        default=0.0,
        alias="W3C_KNOWLEDGE_W3C_REQUEST_DELAY_SECONDS",
    )
    rfc_mirror_root: str = Field(
        default=str(Path(gettempdir()) / "w3c-knowledge" / "rfc-mirror"),
        alias="W3C_KNOWLEDGE_RFC_MIRROR_ROOT",
    )
    api_version: str = "1.0.0"
    embedding_model_dir: Path = Field(default=Path.home() / ".cache/w3c-knowledge/e5-small", alias="W3C_KNOWLEDGE_EMBEDDING_MODEL_DIR")
    embedding_threads: int = Field(default=2, ge=1, le=8, alias="W3C_KNOWLEDGE_EMBEDDING_THREADS")

    @property
    def allowed_domain_set(self) -> set[str]:
        return {domain.strip().lower() for domain in self.allowed_domains.split(",") if domain.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
