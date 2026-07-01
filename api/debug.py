from __future__ import annotations

import logging
import platform
from datetime import UTC, datetime
from time import perf_counter
from typing import Any

from api.models import AuditReport, ScannerResult
from api.runtime import RuntimeManager
from api.scoring import CATEGORY_WEIGHTS


logger = logging.getLogger("beacon.public_api.debug")


class DebugTrace:
    def __init__(self, *, target_url: str) -> None:
        self.target_url = target_url
        self.started_at = datetime.now(UTC)
        self._start = perf_counter()
        self.stages: list[dict[str, Any]] = []

    def stage(
        self,
        name: str,
        *,
        started: bool = True,
        completed: bool = True,
        success: bool = True,
        elapsed_ms: int | None = None,
        summary: str = "",
        extra: dict[str, Any] | None = None,
    ) -> None:
        row: dict[str, Any] = {
            "stage": name,
            "started": started,
            "completed": completed,
            "elapsed_ms": elapsed_ms,
            "success": success,
            "summary": summary,
        }
        if extra:
            row.update(extra)
        self.stages.append(row)

    def payload(self, report: AuditReport, *, normalized_url: str, response_elapsed_ms: int | None = None) -> dict[str, Any]:
        ended_at = datetime.now(UTC)
        elapsed_ms = round((perf_counter() - self._start) * 1000)
        scanner_stages = _scanner_stages(report)
        technology_stage = _technology_stage(report)
        scoring = _scoring_debug(report)
        lighthouse = _lighthouse_debug(report)
        versions = _versions()
        timings = (report.metadata or {}).get("debug_stage_timings", {})
        if not isinstance(timings, dict):
            timings = {}
        payload = {
            "scan_id": report.scan_id,
            "target_url": self.target_url,
            "normalized_url": normalized_url,
            "start_time": self.started_at.isoformat(),
            "end_time": ended_at.isoformat(),
            "elapsed_ms": elapsed_ms,
            "stages": [
                *self.stages,
                *scanner_stages,
                technology_stage,
                _static_stage("Scoring", _int_or_none(timings.get("scoring_time_ms")), True, f"Beacon score {report.scores.beacon_score}, grade {report.scores.grade}", scoring),
                _static_stage("Opportunity Builder", _int_or_none(timings.get("opportunity_builder_time_ms")), True, f"{len(report.opportunities)} recommendations generated"),
                _static_stage("Response Builder", response_elapsed_ms, True, "Customer response generated"),
            ],
            "raw_scores": {
                "scanner_scores": _scanner_scores(report.scanner_results),
                "lighthouse": lighthouse.get("raw_category_scores", {}),
                "categories": {
                    "security": report.scores.security,
                    "performance": report.scores.performance,
                    "seo": report.scores.seo,
                    "accessibility": report.scores.accessibility,
                    "best_practices": report.scores.best_practices,
                    "infrastructure": report.scores.infrastructure,
                    "beacon_score": report.scores.beacon_score,
                    "overall_grade": report.scores.grade,
                },
            },
            "scoring": scoring,
            "lighthouse": lighthouse,
            "versions": versions,
        }
        logger.info("beacon_debug_scan=%s", payload)
        return payload


def debug_enabled(value: str | None, *, env_value: str | None) -> bool:
    if value is not None and value.strip().lower() in {"1", "true", "yes", "on"}:
        return True
    return (env_value or "").strip().lower() in {"1", "true", "yes", "on"}


def _scanner_stages(report: AuditReport) -> list[dict[str, Any]]:
    by_name = {item.scanner: item for item in report.scanner_results}
    labels = {
        "dns": "DNS",
        "hosting": "Hosting",
        "ssl": "SSL",
        "security_headers": "Security Headers",
        "lighthouse": "Lighthouse",
    }
    return [_scanner_stage(labels[name], by_name.get(name)) for name in labels]


def _scanner_stage(label: str, result: ScannerResult | None) -> dict[str, Any]:
    if result is None:
        return _static_stage(label, None, False, "Scanner did not run")
    extra: dict[str, Any] = {
        "scanner": result.scanner,
        "status": result.status.value,
        "included_in_score": result.included_in_score,
        "score": result.score,
        "scores": result.scores,
        "warnings": result.warnings,
    }
    if result.error:
        extra["error"] = result.error
    if result.scanner == "lighthouse":
        status = result.raw.get("status", {}) if isinstance(result.raw, dict) else {}
        if isinstance(status, dict):
            extra["lighthouse"] = {
                "mode": _lighthouse_mode(status),
                "raw_category_scores": status.get("raw_scores", {}),
                "runtime": status.get("runtime_source"),
                "node_version": status.get("node_version"),
                "chromium_version": status.get("chrome_version"),
                "execution_time_ms": status.get("execution_time_ms") or result.elapsed_ms,
                "failed": status.get("failed"),
                "failure_reason": status.get("error") or status.get("parse_error") or result.error,
            }
    return _static_stage(label, result.elapsed_ms, result.status.value in {"ok", "warning"}, _scanner_summary(result), extra)


def _technology_stage(report: AuditReport) -> dict[str, Any]:
    metadata = report.metadata or {}
    subsystems = metadata.get("subsystems", [])
    technology = next((item for item in subsystems if isinstance(item, dict) and item.get("subsystem") == "technology_profile"), None)
    if not isinstance(technology, dict):
        return _static_stage("Technology", None, "technology_profile" in metadata, "Technology profile status unavailable")
    return _static_stage(
        "Technology",
        _int_or_none(technology.get("elapsed_ms")),
        technology.get("status") == "succeeded",
        str(technology.get("error") or technology.get("status") or "Technology profile completed"),
        {
            "status": technology.get("status"),
            "included_in_score": technology.get("included_in_score"),
            "warnings": technology.get("warnings") or [],
        },
    )


def _scoring_debug(report: AuditReport) -> dict[str, Any]:
    category_scores = {
        "security": report.scores.security,
        "performance": report.scores.performance,
        "seo": report.scores.seo,
        "infrastructure": report.scores.infrastructure,
    }
    weighted_inputs = {
        name: {
            "score": score,
            "weight": CATEGORY_WEIGHTS[name],
            "included": score is not None,
            "weighted_value": None if score is None else round(score * CATEGORY_WEIGHTS[name], 4),
        }
        for name, score in category_scores.items()
    }
    available_weight = round(sum(CATEGORY_WEIGHTS[name] for name, score in category_scores.items() if score is not None), 4)
    weighted_total = round(sum((score or 0) * CATEGORY_WEIGHTS[name] for name, score in category_scores.items() if score is not None), 4)
    return {
        "raw_numeric_inputs": _scanner_scores(report.scanner_results),
        "category_scores": {
            **category_scores,
            "accessibility": report.scores.accessibility,
            "best_practices": report.scores.best_practices,
        },
        "weights": CATEGORY_WEIGHTS,
        "weighted_calculations": weighted_inputs,
        "available_weight": available_weight,
        "weighted_total": weighted_total,
        "calculation": "round(weighted_total / available_weight)" if available_weight else "no verified weighted categories",
        "beacon_score": report.scores.beacon_score,
        "letter_grade_mapping": _letter_mapping(),
        "overall_grade": report.scores.grade,
    }


def _lighthouse_debug(report: AuditReport) -> dict[str, Any]:
    status = (report.metadata or {}).get("lighthouse", {})
    if not isinstance(status, dict):
        status = {}
    return {
        "mode": _lighthouse_mode(status),
        "raw_category_scores": status.get("raw_scores", {}),
        "runtime": status.get("runtime_source"),
        "node_version": status.get("node_version"),
        "chromium_version": status.get("chrome_version"),
        "lighthouse_version": status.get("lighthouse_version"),
        "execution_time_ms": status.get("execution_time_ms") or status.get("elapsed_ms"),
        "succeeded": status.get("succeeded"),
        "failed": status.get("failed"),
        "timed_out": status.get("timed_out"),
        "failure_reason": status.get("error") or status.get("parse_error"),
        "scores_returned": status.get("scores_returned"),
        "included_in_score": status.get("included_in_score"),
    }


def _versions() -> dict[str, str | None]:
    runtime = RuntimeManager()
    lighthouse = runtime.lighthouse_runtime()
    chrome = runtime.chrome_path()
    return {
        "python": platform.python_version(),
        "node": lighthouse.node_version if lighthouse else None,
        "lighthouse": lighthouse.lighthouse_version if lighthouse else None,
        "chromium": runtime.chrome_version(chrome) if chrome else None,
    }


def _scanner_scores(results: list[ScannerResult]) -> dict[str, Any]:
    return {
        result.scanner: {
            "score": result.score,
            "scores": result.scores,
            "status": result.status.value,
            "included_in_score": result.included_in_score,
        }
        for result in results
    }


def _scanner_summary(result: ScannerResult) -> str:
    if result.error:
        return result.error
    if result.score is not None:
        return f"{result.scanner} score {result.score}"
    return f"{result.scanner} completed with status {result.status.value}"


def _static_stage(
    name: str,
    elapsed_ms: int | None,
    success: bool,
    summary: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "stage": name,
        "started": True,
        "completed": True,
        "elapsed_ms": elapsed_ms,
        "success": success,
        "summary": summary,
    }
    if extra:
        row.update(extra)
    return row


def _lighthouse_mode(status: dict[str, Any]) -> str:
    command = str(status.get("command") or "")
    if "desktop" in command:
        return "desktop"
    if "mobile" in command:
        return "mobile"
    return "mobile_default"


def _letter_mapping() -> dict[str, str]:
    return {
        "97-100": "A+",
        "93-96": "A",
        "90-92": "A-",
        "87-89": "B+",
        "83-86": "B",
        "80-82": "B-",
        "77-79": "C+",
        "73-76": "C",
        "70-72": "C-",
        "60-69": "D",
        "0-59": "F",
    }


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
