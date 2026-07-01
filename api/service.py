from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError
import os
from time import perf_counter

from api.debug import DebugTrace
from api.orchestrator import AuditEngine
from api.response_builder import build_public_response
from api.schemas import FreeScanResponse
from api.security import PublicAPISecurityError, validate_public_target
from api.validation import PublicAPIValidationError, normalize_public_url


class PublicAPIServiceError(Exception):
    def __init__(self, code: str, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class QuickScanService:
    def __init__(self, engine: AuditEngine | None = None, timeout_seconds: int | None = None) -> None:
        self.engine = engine or AuditEngine()
        self.timeout_seconds = timeout_seconds or int(os.environ.get("PUBLIC_SCAN_TIMEOUT", "60"))

    def scan(self, raw_url: str, *, debug: bool = False) -> FreeScanResponse:
        trace = DebugTrace(target_url=raw_url) if debug else None
        try:
            validation_start = perf_counter()
            normalized_url = normalize_public_url(raw_url)
            if trace:
                trace.stage(
                    "URL Validation",
                    elapsed_ms=round((perf_counter() - validation_start) * 1000),
                    success=True,
                    summary="URL normalized",
                    extra={"target_url": raw_url, "normalized_url": normalized_url},
                )
            security_start = perf_counter()
            validate_public_target(normalized_url)
            if trace:
                trace.stage(
                    "SSRF Protection",
                    elapsed_ms=round((perf_counter() - security_start) * 1000),
                    success=True,
                    summary="Target passed public network validation and redirect checks",
                )
        except PublicAPIValidationError as exc:
            if trace:
                trace.stage("URL Validation", success=False, summary=str(exc))
            raise PublicAPIServiceError("invalid_url", str(exc), 400) from exc
        except PublicAPISecurityError as exc:
            if trace:
                trace.stage("SSRF Protection", success=False, summary=str(exc))
            raise PublicAPIServiceError("blocked_target", str(exc), 403) from exc

        executor = ThreadPoolExecutor(max_workers=1)
        engine_start = perf_counter()
        future = executor.submit(self.engine.scan, normalized_url, audit_type="QuickScan")
        try:
            report = future.result(timeout=self.timeout_seconds)
            if trace:
                trace.stage(
                    "QuickScan Orchestrator",
                    elapsed_ms=round((perf_counter() - engine_start) * 1000),
                    success=True,
                    summary="Existing QuickScan engine completed",
                    extra={"scan_id": report.scan_id},
                )
        except TimeoutError as exc:
            future.cancel()
            if trace:
                trace.stage(
                    "QuickScan Orchestrator",
                    elapsed_ms=round((perf_counter() - engine_start) * 1000),
                    success=False,
                    summary="The scan exceeded the public API time limit.",
                )
            raise PublicAPIServiceError("scan_timeout", "The scan exceeded the public API time limit.", 408) from exc
        except Exception as exc:
            if trace:
                trace.stage(
                    "QuickScan Orchestrator",
                    elapsed_ms=round((perf_counter() - engine_start) * 1000),
                    success=False,
                    summary=str(exc),
                )
            raise PublicAPIServiceError("scan_failed", "The scan could not be completed.", 500) from exc
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        response_start = perf_counter()
        response = build_public_response(report)
        response_elapsed_ms = round((perf_counter() - response_start) * 1000)
        if trace:
            response.debug = trace.payload(report, normalized_url=normalized_url, response_elapsed_ms=response_elapsed_ms)
        return response
