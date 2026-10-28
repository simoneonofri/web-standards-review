from __future__ import annotations

from fastapi import FastAPI

from w3c_knowledge.api.v1.routes import router
from w3c_knowledge.config import get_settings


def create_app() -> FastAPI:
    app = FastAPI(
        title="W3C Knowledge API",
        version=get_settings().api_version,
        description="Versioned API for W3C specifications, reviews, guidance, provenance, and retrieval.",
    )
    app.include_router(router)
    return app


app = create_app()
