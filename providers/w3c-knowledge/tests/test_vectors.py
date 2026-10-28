"""Control-flow tests use a fake encoder; the separate smoke uses real E5 + PostgreSQL."""
import math
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from w3c_knowledge.db import Base, get_session
from w3c_knowledge.main import app
from w3c_knowledge.models import Artifact, Specification, SpecificationSection, SpecificationVersion
from w3c_knowledge.search.embeddings import EmbeddingUnavailable, LocalEncoder
from w3c_knowledge.search.vector_store import VectorBase, VectorChunk
from w3c_knowledge.search.vectors import VectorService


class FakeEncoder:
    fingerprint = "test-encoder:v1"

    def chunks(self, text):
        return [(start, min(start + 200, len(text))) for start in range(0, len(text), 180)]

    def encode(self, texts, query=False):
        rows = []
        for value in texts:
            vector = [1.0, float("permission" in value.lower())] + [0.0] * 382
            norm = math.sqrt(sum(x*x for x in vector))
            rows.append([x / norm for x in vector])
        return rows


def seed(session):
    spec = Specification(shortname="sample", title="Sample specification")
    session.add(spec)
    session.flush()
    sections = []
    for number, body in enumerate(["Permission is required before reading the user's location.", "The request returns a sequence of coordinate objects."]):
        version = SpecificationVersion(specification_id=spec.internal_id, version=f"v{number}", source_url=f"https://example.org/v{number}/", raw_text=body, content_hash=f"upstream-{number}")
        session.add(version)
        session.flush()
        section = SpecificationSection(specification_version_id=version.internal_id, heading="Requirements", anchor="requirements", source_url=version.source_url + "#requirements", raw_text=body, normalized_text=body, content_hash=f"upstream-section-{number}", evidence_ids=[f"evidence-{number}"])
        session.add(section)
        sections.append(section)
    artifact = Artifact(source_type="fixture", artifact_type="review_finding", title="Permission review", raw_text="A previous review asked about permission revocation.", primary_domain="security", source_url="https://example.org/review/1", provenance={"shortname": "sample"})
    session.add(artifact)
    session.commit()
    return sections, artifact


class VectorTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        VectorBase.metadata.create_all(self.engine)
        self.session = Session(self.engine, expire_on_commit=False)
        self.sections, self.artifact = seed(self.session)
        self.service = VectorService(self.session, FakeEncoder())

    def tearDown(self):
        app.dependency_overrides.clear()
        self.session.close()
        self.engine.dispose()

    def test_index_search_and_exact_version_provenance(self):
        self.assertEqual(self.service.status()["status"], "partial")
        self.assertEqual(self.service.reindex()["changed_documents"], 3)
        self.assertEqual(self.service.reindex()["unchanged_documents"], 3)
        result = self.service.search("permission", version_id=self.sections[0].specification_version_id)
        self.assertEqual(result["coverage"]["indexed_documents"], 1)
        self.assertEqual(len(result["results"]), 1)
        hit = result["results"][0]
        self.assertEqual(hit["source_id"], self.sections[0].internal_id)
        self.assertEqual(hit["text"], self.sections[0].raw_text[hit["start"]:hit["end"]])
        self.assertEqual(hit["evidence_ids"], ["evidence-0"])
        self.assertNotIn("analysis_confidence", hit)
        self.assertEqual(self.service.search("permission", version_id="unknown")["coverage"]["status"], "empty")
        self.assertEqual(self.service.search("permission", domain="security")["coverage"]["eligible_documents"], 1)
        self.assertEqual(self.service.search("permission", version_id=self.sections[0].specification_version_id, domain="security")["results"], [])

    def test_changed_source_is_suppressed_before_reindex(self):
        self.service.reindex()
        self.sections[0].raw_text = "A changed requirement with fresh text."
        self.session.commit()
        self.assertEqual(self.service.status()["unindexed_or_stale_documents"], 1)
        ids = [r["source_id"] for r in self.service.search("permission")["results"]]
        self.assertNotIn(self.sections[0].internal_id, ids)
        self.assertEqual(self.service.reindex()["changed_documents"], 1)
        self.assertEqual(self.service.status()["status"], "complete")

    def test_metadata_change_and_wrong_model_are_stale(self):
        self.service.reindex()
        self.artifact.updated_at += timedelta(seconds=1)
        self.session.commit()
        self.assertEqual(self.service.status()["unindexed_or_stale_documents"], 1)
        self.service.fingerprint = "another-model"
        self.assertEqual(self.service.search("permission")["results"], [])

    def test_failed_rebuild_rolls_back_and_deletion_is_pruned(self):
        self.service.reindex()
        before = list(self.session.scalars(select(VectorChunk.id)))
        with patch.object(self.service.encoder, "encode", side_effect=RuntimeError("failed encoder")):
            with self.assertRaises(RuntimeError):
                self.service.reindex(rebuild=True)
        self.assertEqual(before, list(self.session.scalars(select(VectorChunk.id))))
        self.session.delete(self.artifact)
        self.session.commit()
        self.assertEqual(self.service.status()["eligible_documents"], 2)
        self.service.reindex()
        self.assertEqual(len(list(self.session.scalars(select(VectorChunk.id)))), 2)

    def test_invalid_vectors_and_empty_query_are_rejected(self):
        with patch.object(self.service.encoder, "encode", return_value=[[float("nan")] * 384]):
            with self.assertRaises(ValueError):
                self.service.reindex()
        self.assertEqual(self.service.status()["indexed_documents"], 0)
        for query in [" ", "x" * 4001]:
            with self.assertRaises(ValueError):
                self.service.search(query)

    def test_missing_model_never_downloads(self):
        with patch("w3c_knowledge.search.embeddings.urlopen", side_effect=AssertionError("network forbidden")):
            with self.assertRaises(EmbeddingUnavailable):
                LocalEncoder(Path("/absent-model-test-fixture"))

    def test_api_modes_errors_and_lexical_backwards_compatibility(self):
        app.dependency_overrides[get_session] = lambda: self.session
        client = TestClient(app)
        with patch("w3c_knowledge.api.v1.routes._vector_service", return_value=self.service):
            self.assertEqual(client.get("/api/v1/retrieval/search", params={"q": "a", "mode": "unknown"}).status_code, 422)
            self.assertEqual(client.get("/api/v1/retrieval/search", params={"q": " "}).status_code, 422)
            with patch.object(self.service, "search", side_effect=EmbeddingUnavailable("model missing")):
                self.assertEqual(client.get("/api/v1/retrieval/search", params={"q": "permission"}).status_code, 503)
            self.service.reindex()
            response = client.get("/api/v1/retrieval/search", params={"q": "permission"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["coverage"]["status"], "complete")
        self.assertEqual(client.get("/api/v1/search", params={"q": "permission"}).status_code, 200)


if __name__ == "__main__":
    unittest.main()
