from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Beacon Audit API",
        version="1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins(),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type"],
    )
    app.include_router(router)
    return app


def _allowed_origins() -> list[str]:
    configured = os.environ.get("ALLOWED_ORIGINS")
    if configured:
        return [origin.strip() for origin in configured.split(",") if origin.strip()]
    return ["https://beacon-audit.com", "https://www.beacon-audit.com"]


app = create_app()

