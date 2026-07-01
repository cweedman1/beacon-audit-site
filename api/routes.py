from __future__ import annotations

import platform

from fastapi import APIRouter, HTTPException, Request

from api.rate_limit import InMemoryRateLimiter, RateLimitExceeded
from api.schemas import FreeScanRequest, FreeScanResponse, HealthResponse, RootResponse
from api.service import PublicAPIServiceError, QuickScanService
from api.runtime import RuntimeManager


router = APIRouter()
service = QuickScanService()
rate_limiter = InMemoryRateLimiter()


@router.get("/", response_model=RootResponse)
def root() -> RootResponse:
    return RootResponse(
        service="Beacon Audit API",
        api_version="1.0",
        status="running",
        health="/health",
    )


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    runtime = RuntimeManager()
    lighthouse = runtime.lighthouse_runtime()
    chrome = runtime.chrome_path()
    return HealthResponse(
        status="ok",
        service="Beacon Audit API",
        api_version="1.0",
        python=platform.python_version(),
        node=_node_version(lighthouse.node_version if lighthouse else None),
        lighthouse="available" if lighthouse and lighthouse.lighthouse_entry else "unavailable",
        chromium="available" if chrome else "unavailable",
    )


@router.post("/v1/free-scan", response_model=FreeScanResponse)
def free_scan(payload: FreeScanRequest, request: Request) -> FreeScanResponse:
    try:
        rate_limiter.check(_client_key(request))
        return service.scan(payload.url)
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail={"error": "rate_limited", "message": str(exc), "status_code": 429}) from exc
    except PublicAPIServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"error": exc.code, "message": exc.message, "status_code": exc.status_code}) from exc


def _client_key(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _node_version(value: str | None) -> str:
    if not value:
        return "unavailable"
    normalized = value.strip()
    if normalized.startswith("v22") or normalized.startswith("22"):
        return "22"
    return normalized

