"""Run only against a disposable migrated PostgreSQL database with the real local model.

This creates synthetic fixture sources. It is deliberately excluded from unit discovery.
"""
import json
from pathlib import Path

from sqlalchemy import text

from w3c_knowledge.config import get_settings
from w3c_knowledge.db import SessionLocal
from w3c_knowledge.ingestion.service import IngestionService
from w3c_knowledge.search.embeddings import LocalEncoder
from w3c_knowledge.search.vectors import VectorService


def main():
    encoder = LocalEncoder(get_settings().embedding_model_dir)
    with SessionLocal() as session:
        assert session.bind.dialect.name == "postgresql", "Use a disposable PostgreSQL database"
        assert session.scalar(text("SELECT count(*) FROM specifications")) == 0, "Smoke requires an empty database"
        html = """<!doctype html><title>Synthetic retrieval test</title>
        <h2 id="permission">Consent and location</h2><p>The browser must obtain user permission before accessing location. Revoking permission prevents subsequent access to the device position.</p>
        <h2 id="payments">Payment amounts</h2><p>The payment amount is a decimal number. The currency field uses a three-letter code.</p>
        <h2 id="styles">Page presentation</h2><p>A stylesheet changes the color of a paragraph. Margins determine the spacing around blocks.</p>"""
        version = IngestionService(session).ingest_specification_html("vector-smoke", html, "https://example.org/vector-smoke/v1/", "v1")
        session.commit()
        service = VectorService(session, encoder)
        report = service.reindex()
        assert report["coverage"]["status"] == "complete"
        assert service.reindex()["changed_documents"] == 0
        query = "Come viene richiesto il consenso per la geolocalizzazione?"
        result = service.search(query, mode="vector", version_id=version.internal_id)
        assert result["results"][0]["anchor"] == "permission", result
        assert result["results"][0]["source_url"].endswith("#permission")
        english = service.search("What happens when the user withdraws access to their position?", mode="hybrid", version_id=version.internal_id)
        assert english["results"][0]["anchor"] == "permission", english
        empty = service.search(query, version_id="nonexistent")
        assert empty["coverage"]["status"] == "empty" and not empty["results"]
        long_text = "  A browser must request permission. " * 600
        spans = encoder.chunks(long_text)
        assert spans[0][0] == 0 and spans[-1][1] == len(long_text)
        assert all(previous[1] >= current[0] for previous, current in zip(spans, spans[1:]))
        for start in range(0, len(spans), 8):
            assert len(encoder.encode([long_text[a:b] for a,b in spans[start:start+8]])) == len(spans[start:start+8])
        print(json.dumps({"status": "pass", "database": "postgresql-pgvector", "model": encoder.fingerprint, "coverage": report["coverage"], "italian_query_top_anchor": result["results"][0]["anchor"], "english_query_top_anchor": english["results"][0]["anchor"], "long_text_chunks": len(spans)}, indent=2))


if __name__ == "__main__":
    main()
