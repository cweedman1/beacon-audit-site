from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError
import os

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

    def scan(self, raw_url: str) -> FreeScanResponse:
        try:
            normalized_url = normalize_public_url(raw_url)
            validate_public_target(normalized_url)
        except PublicAPIValidationError as exc:
            raise PublicAPIServiceError("invalid_url", str(exc), 400) from exc
        except PublicAPISecurityError as exc:
            raise PublicAPIServiceError("blocked_target", str(exc), 403) from exc

        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(self.engine.scan, normalized_url, audit_type="QuickScan")
        try:
            report = future.result(timeout=self.timeout_seconds)
        except TimeoutError as exc:
            future.cancel()
            raise PublicAPIServiceError("scan_timeout", "The scan exceeded the public API time limit.", 408) from exc
        except Exception as exc:
            raise PublicAPIServiceError("scan_failed", "The scan could not be completed.", 500) from exc
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        return build_public_response(report)
