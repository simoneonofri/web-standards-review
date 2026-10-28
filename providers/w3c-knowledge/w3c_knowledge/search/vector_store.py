"""Vector tables are separate from ingestion metadata, so lexical installs stay optional."""
from __future__ import annotations

from pgvector.sqlalchemy import Vector
from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class VectorBase(DeclarativeBase):
    pass


class VectorDocument(VectorBase):
    __tablename__ = "vector_documents"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    source_id: Mapped[str] = mapped_column(String(36), index=True)
    source_updated_at: Mapped[object] = mapped_column(DateTime(timezone=True))
    source_text: Mapped[str] = mapped_column(Text)
    source_sha256: Mapped[str] = mapped_column(String(64))
    fingerprint: Mapped[str] = mapped_column(String(256), index=True)
    chunk_count: Mapped[int] = mapped_column(Integer)


class VectorChunk(VectorBase):
    __tablename__ = "vector_chunks"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("vector_documents.id", ondelete="CASCADE"), index=True)
    start: Mapped[int] = mapped_column(Integer)
    end: Mapped[int] = mapped_column(Integer)
    text: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    # SQLite is a deterministic test/reference backend; production ranks in PostgreSQL.
    embedding: Mapped[list] = mapped_column(Vector(384).with_variant(JSON(), "sqlite"))
