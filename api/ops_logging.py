from __future__ import annotations

import json
import logging
import os
import platform
import sys
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from api.models import AuditReport
from api.runtime import RuntimeManager


logger = logging.getLogger("beacon.ops")
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


def log_startup_summary() -> None:
    runtime = RuntimeManager()
    lighthouse = runtime.lighthouse_runtime()
    chrome = runtime.chrome_path()
    _emit(
        "startup",
        {
            "python": platform.python_version(),
            "node": lighthouse.node_version if lighthouse else None,
            "lighthouse": lighthouse.lighthouse_version if lighthouse else None,
            "chromium": runtime.chrome_version(chrome) if chrome else None,
            "google_psi_enabled": True,
            "pagespeed_api_key_configured": bool(os.environ.get("PAGESPEED_API_KEY")),
        },
    )


def log_scan_success(report: AuditReport) -> None:
    lighthouse = _lighthouse_status(report)
    timing = report.metadata.get("timing", {}) if isinstance(report.metadata, dict) else {}
    debug_timing = report.metadata.get("debug_stage_timings", {}) if isinstance(report.metadata, dict) else {}
    _emit(
        "scan_completed",
        {
            "scan_id": report.scan_id,
            "domain": _domain(report.target_url),
            "status": "success",
            "elapsed_ms": report.elapsed_ms,
            "provider": lighthouse.get("provider_used"),
            "fallback": bool(lighthouse.get("fallback_occurred")),
            "fallback_reason": lighthouse.get("fallback_reason"),
            "http_status": lighthouse.get("http_status"),
            "stage_timings": _stage_timings(timing, debug_timing, lighthouse, report.elapsed_ms),
        },
    )


def log_scan_failure(
    *,
    raw_url: str,
    normalized_url: str | None = None,
    scan_id: str | None = None,
    failure_type: str,
    message: str,
    elapsed_ms: int | None = None,
    http_status: int | None = None,
    provider: str | None = None,
    fallback: bool | None = None,
    fallback_reason: str | None = None,
) -> None:
    _emit(
        "scan_failed",
        {
            "scan_id": scan_id,
            "domain": _domain(normalized_url or raw_url),
            "status": "failure",
            "failure_type": failure_type,
            "message": message,
            "elapsed_ms": elapsed_ms,
            "provider": provider,
            "fallback": fallback,
            "fallback_reason": fallback_reason,
            "http_status": http_status,
        },
    )


def log_failure_metric(event_type: str, **fields: object) -> None:
    _emit(event_type, fields)


def _stage_timings(
    timing: dict[str, Any],
    debug_timing: dict[str, Any],
    lighthouse: dict[str, Any],
    elapsed_ms: int,
) -> dict[str, Any]:
    return {
        "dns_ms": timing.get("dns_time_ms"),
        "ssl_ms": timing.get("ssl_time_ms"),
        "security_headers_ms": timing.get("headers_time_ms"),
        "technology_detection_ms": timing.get("technology_profile_time_ms"),
        "google_psi_ms": lighthouse.get("google_fetch_time_ms"),
        "local_lighthouse_ms": lighthouse.get("local_lighthouse_execution_time_ms")
        or (lighthouse.get("elapsed_ms") if lighthouse.get("provider_used") == "local_lighthouse" else None),
        "scoring_ms": debug_timing.get("scoring_time_ms"),
        "recommendation_generation_ms": debug_timing.get("opportunity_builder_time_ms"),
        "scanner_pool_ms": debug_timing.get("scanner_pool_time_ms"),
        "concurrent_work_ms": debug_timing.get("concurrent_work_time_ms"),
        "critical_path_ms": debug_timing.get("critical_path_time_ms"),
        "total_scan_ms": elapsed_ms,
    }


def _lighthouse_status(report: AuditReport) -> dict[str, Any]:
    if isinstance(report.metadata, dict):
        status = report.metadata.get("lighthouse")
        if isinstance(status, dict):
            return status
    return {}


def _domain(value: str) -> str | None:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return parsed.hostname.lower() if parsed.hostname else None


def _emit(event: str, fields: dict[str, object]) -> None:
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event": event,
        **fields,
    }
    logger.info(json.dumps(payload, sort_keys=True, default=str))
