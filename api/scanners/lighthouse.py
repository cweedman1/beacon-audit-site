from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from time import perf_counter
from typing import Any

from api.models import Category, Finding, ScannerResult, ScannerStatus, Severity
from api.runtime import RuntimeManager
from api.scanners.base import Scanner


LIGHTHOUSE_CATEGORIES = {
    "performance": Category.PERFORMANCE,
    "accessibility": Category.ACCESSIBILITY,
    "best-practices": Category.BEST_PRACTICES,
    "seo": Category.SEO,
}

logger = logging.getLogger(__name__)


class PageSpeedProviderError(Exception):
    def __init__(self, reason: str, details: dict[str, object] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.details = details or {}


class PerformanceProvider:
    name = "performance_provider"

    def scan(self, scanner: "LighthouseScanner", target_url: str) -> ScannerResult:
        raise NotImplementedError


class GooglePageSpeedProvider(PerformanceProvider):
    name = "google_pagespeed"

    def scan(self, scanner: "LighthouseScanner", target_url: str) -> ScannerResult:
        return scanner._scan_google_pagespeed(target_url)


class LocalLighthouseProvider(PerformanceProvider):
    name = "local_lighthouse"

    def scan(self, scanner: "LighthouseScanner", target_url: str) -> ScannerResult:
        return scanner._scan_local(target_url)


class LighthouseScanner(Scanner):
    name = "lighthouse"
    DEFAULT_TIMEOUTS = {
        "QuickScan": 60,
        "Business Audit": 90,
        "Deep Site Audit": 120,
    }

    def __init__(self, runtime_manager: RuntimeManager | None = None, audit_type: str = "Business Audit") -> None:
        self.runtime_manager = runtime_manager or RuntimeManager()
        self.audit_type = audit_type

    def scan(self, target_url: str) -> ScannerResult:
        google_provider = GooglePageSpeedProvider()
        local_provider = LocalLighthouseProvider()
        try:
            return google_provider.scan(self, target_url)
        except PageSpeedProviderError as exc:
            local_started = perf_counter()
            local_result = local_provider.scan(self, target_url)
            local_elapsed_ms = round((perf_counter() - local_started) * 1000)
            return self._with_provider_fallback(local_result, exc, local_elapsed_ms)

    def _scan_local(self, target_url: str) -> ScannerResult:
        base_timeout = self._timeout_seconds()
        retry_timeout = max(base_timeout + 60, round(base_timeout * 1.5))
        status: dict[str, object] = {
            "executed": False,
            "succeeded": False,
            "timed_out": False,
            "failed": False,
            "skipped": False,
            "launched": False,
            "completed": False,
            "json_parsed": False,
            "scores_returned": False,
            "raw_scores": {},
            "parse_error": None,
            "fallback_used": False,
            "command": None,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "chrome_path": None,
            "attempts": [],
            "retry_recommendation": None,
            "json_report_written": False,
            "json_report_written_before_cleanup": False,
            "completed_with_cleanup_warning": False,
            "cleanup_warning": None,
            "cleanup_deferred": False,
            "cleanup_scheduled": False,
            "cleanup_path": None,
            "node_executable": None,
            "node_version": None,
            "lighthouse_version": None,
            "runtime_source": None,
            "chrome_version": None,
            "retry_count": 0,
            "audit_type": self.audit_type,
            "timeout_seconds": base_timeout,
            "retry_timeout_seconds": retry_timeout,
            "completed_with_timeout_warning": False,
            "timeout_warning": None,
            "timeout_location": None,
            "runtime_error": None,
            "execution_reached": {
                "chrome_launch": False,
                "page_loaded": False,
                "audit_started": False,
                "audit_completed": False,
            },
            "timeline": {},
            "profile_dir": None,
            "temp_dir": None,
            "accepted_attempt": None,
            "retry_result_used": False,
            "requested_url": None,
            "final_url": None,
            "redirect_chain": [],
            "fetch_time": None,
            "config_settings": {},
            "screen_emulation": {},
            "user_agent": None,
            "cpu_throttling": {},
            "network_throttling": {},
            "storage_reset": {},
            "run_warnings": [],
            "environment": {},
            "lighthouse_metrics": {},
            "performance_audit_refs": [],
            "lighthouse_flags": [],
            "chrome_flags": [],
            "command_parts": [],
            "retry_flag_changes": [],
        }
        runtime = None
        command = self._command()
        runtime = getattr(self, "_selected_runtime", None)
        if not command:
            status["skipped"] = True
            status["error"] = "lighthouse_not_installed"
            self._log_status(status)
            finding = Finding(
                scanner=self.name,
                category=Category.PERFORMANCE,
                title="Lighthouse is not installed",
                description="Beacon could not find a local Lighthouse command.",
                severity=Severity.INFO,
                recommendation="Install Lighthouse with npm or provide it in the deployment image.",
                impact="Performance, accessibility, best practices, and SEO scoring are limited.",
                evidence={"runtime_policy": "Beacon requires Node 22 for Lighthouse and rejects Node 24 on Windows."},
                weight=0,
            )
            return ScannerResult(
                self.name,
                target_url,
                False,
                None,
                [finding],
                {"available": False, "status": status},
                status=ScannerStatus.SKIPPED,
                included_in_score=False,
                error="Lighthouse command not found",
            )

        if runtime:
            status["node_executable"] = runtime.node_executable
            status["node_version"] = runtime.node_version
            status["lighthouse_version"] = runtime.lighthouse_version
            status["runtime_source"] = runtime.source
            status["chrome_version"] = runtime.chrome_version

        chrome_path = self._chrome_path(runtime)
        status["chrome_path"] = chrome_path
        temp_dir = str(self.runtime_manager.temp_dir("beacon-lighthouse-"))
        status["temp_dir"] = temp_dir
        cleanup_error: str | None = None
        cleanup_deferred = False
        cleanup_scheduled = False
        report: dict[str, object] | None = None
        cleanup_started = perf_counter()
        cleanup_time_ms: int | None = None
        try:
            output_path = Path(temp_dir) / "lighthouse.json"
            completed: subprocess.CompletedProcess[str] | None = None
            lighthouse_started = perf_counter()
            status["timeline"] = {
                "lighthouse_startup": "Started",
                "chrome_launch": "Invoked by Lighthouse CLI",
                "chrome_ready": "Not separately observable through Lighthouse CLI",
                "page_load_complete": "Pending",
                "audit_execution": "Pending",
                "json_written": False,
                "cleanup": "Pending",
            }
            for attempt in range(1, 3):
                attempt_timeout = base_timeout if attempt == 1 else retry_timeout
                profile_dir = Path(temp_dir) / f"chrome-profile-{attempt}"
                profile_dir.mkdir(parents=True, exist_ok=True)
                full_command = self._full_command(command, target_url, output_path, profile_dir, chrome_path, retry_mode=attempt > 1)
                status["command"] = " ".join(full_command)
                status["command_parts"] = full_command
                status["lighthouse_flags"] = self._lighthouse_flags(full_command)
                status["chrome_flags"] = self._chrome_flags(full_command)
                status["retry_flag_changes"] = self._retry_flag_changes(attempt > 1)
                status["profile_dir"] = str(profile_dir)
                attempt_started = perf_counter()
                try:
                    status["executed"] = True
                    status["launched"] = True
                    self._mark_reached(status, "chrome_launch", True)
                    self._mark_reached(status, "audit_started", True)
                    status["timeline"]["audit_execution"] = "Started"  # type: ignore[index]
                    completed = subprocess.run(
                        full_command,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=attempt_timeout,
                        env=self._environment(chrome_path, temp_dir),
                    )
                except subprocess.TimeoutExpired as exc:
                    json_report_written = output_path.exists()
                    parsed_after_timeout, parse_error = self._parse_report(output_path)
                    attempt_status = {
                        "attempt": attempt,
                        "status": "Timed Out",
                        "elapsed_ms": round((perf_counter() - attempt_started) * 1000),
                        "returncode": None,
                        "stdout": self._tail(exc.stdout),
                        "stderr": self._tail(exc.stderr),
                        "timeout_seconds": attempt_timeout,
                        "json_report_written": json_report_written,
                        "json_parsed_after_timeout": parsed_after_timeout is not None,
                        "retry_mode": attempt > 1,
                        "command": " ".join(full_command),
                        "command_parts": full_command,
                        "lighthouse_flags": self._lighthouse_flags(full_command),
                        "chrome_flags": self._chrome_flags(full_command),
                        "flag_changes_from_initial": self._retry_flag_changes(attempt > 1),
                    }
                    status["attempts"].append(attempt_status)  # type: ignore[union-attr]
                    status["timed_out"] = True
                    status["execution_time_ms"] = round((perf_counter() - lighthouse_started) * 1000)
                    status["error"] = "Lighthouse exceeded the allotted execution time."
                    status["timeout_warning"] = f"Lighthouse exceeded the allotted execution time after {attempt_timeout} seconds."
                    status["timeout_location"] = self._timeout_location(json_report_written, parsed_after_timeout is not None, parse_error)
                    status["retry_recommendation"] = "Yes" if attempt == 1 and parsed_after_timeout is None else "No"
                    status["stdout"] = attempt_status["stdout"]
                    status["stderr"] = attempt_status["stderr"]
                    status["json_report_written"] = json_report_written
                    status["timeline"]["json_written"] = json_report_written  # type: ignore[index]
                    if parsed_after_timeout is not None:
                        report = parsed_after_timeout
                        status["accepted_attempt"] = attempt
                        status["retry_result_used"] = attempt > 1
                        status["completed"] = True
                        status["completed_with_timeout_warning"] = True
                        status["json_parsed"] = True
                        status["parse_error"] = None
                        status["failed"] = False
                        self._mark_reached(status, "page_loaded", True)
                        self._mark_reached(status, "audit_completed", True)
                        status["timeline"]["page_load_complete"] = "Inferred from valid Lighthouse JSON"  # type: ignore[index]
                        status["timeline"]["audit_execution"] = "Completed with timeout warning"  # type: ignore[index]
                        break
                    if parse_error:
                        status["parse_error"] = parse_error
                    if attempt == 1:
                        status["retry_count"] = int(status.get("retry_count") or 0) + 1
                        status["retry_recommendation"] = "Lighthouse timed out once and was retried with a fresh Chrome profile, a longer timeout, disabled storage reset, and provided throttling."
                        continue
                    status["failed"] = True
                    self._log_status(status)
                    return self._failed(target_url, str(status["error"]), status)
                except OSError as exc:
                    attempt_status = {
                        "attempt": attempt,
                        "status": "Verification Failed",
                        "elapsed_ms": round((perf_counter() - attempt_started) * 1000),
                        "returncode": None,
                        "stdout": "",
                        "stderr": str(exc),
                    }
                    status["attempts"].append(attempt_status)  # type: ignore[union-attr]
                    if attempt == 1 and self._transient_launch_failure(str(exc)):
                        continue
                    status["failed"] = True
                    status["execution_time_ms"] = round((perf_counter() - lighthouse_started) * 1000)
                    status["error"] = str(exc)
                    status["stderr"] = str(exc)
                    self._log_status(status)
                    return self._failed(target_url, str(exc), status)
                json_report_written = output_path.exists()
                attempt_status = {
                    "attempt": attempt,
                    "status": "Verified" if completed.returncode == 0 and json_report_written else "Verification Failed",
                    "elapsed_ms": round((perf_counter() - attempt_started) * 1000),
                    "returncode": completed.returncode,
                    "stdout": completed.stdout[-4000:],
                    "stderr": completed.stderr[-4000:],
                    "json_report_written": json_report_written,
                    "timeout_seconds": attempt_timeout,
                    "retry_mode": attempt > 1,
                    "command": " ".join(full_command),
                    "command_parts": full_command,
                    "lighthouse_flags": self._lighthouse_flags(full_command),
                    "chrome_flags": self._chrome_flags(full_command),
                    "flag_changes_from_initial": self._retry_flag_changes(attempt > 1),
                }
                status["attempts"].append(attempt_status)  # type: ignore[union-attr]
                status["timeline"]["json_written"] = json_report_written  # type: ignore[index]
                if completed.returncode == 0 and json_report_written:
                    status["accepted_attempt"] = attempt
                    status["retry_result_used"] = attempt > 1
                    break
                message = completed.stderr.strip() or completed.stdout.strip() or "Lighthouse failed"
                if json_report_written and self._cleanup_only_failure(message):
                    status["accepted_attempt"] = attempt
                    status["retry_result_used"] = attempt > 1
                    break
                if attempt == 1 and self._transient_launch_failure(message):
                    status["retry_count"] = int(status.get("retry_count") or 0) + 1
                    status["retry_recommendation"] = "Lighthouse launch failed once and was retried with a fresh isolated Chrome profile."
                    continue
                break

            status["returncode"] = completed.returncode if completed else None
            status["stdout"] = completed.stdout[-4000:] if completed else ""
            status["stderr"] = completed.stderr[-4000:] if completed else ""
            status["execution_time_ms"] = round((perf_counter() - lighthouse_started) * 1000)
            status["json_report_written"] = output_path.exists()
            status["json_report_written_before_cleanup"] = output_path.exists()

            if report is None and (completed is None or not output_path.exists()):
                message = status["stderr"] or status["stdout"] or "Lighthouse failed"
                status["completed"] = False
                status["failed"] = True
                status["error"] = message[-1000:]
                status["retry_recommendation"] = status.get("retry_recommendation") or "Retry the scan after confirming Chrome and Lighthouse can run from this Windows user account."
                self._log_status(status)
                return self._failed(target_url, str(message), status)

            status["completed"] = True
            if report is None:
                report, parse_error = self._parse_report(output_path)
                if report is None:
                    status["parse_error"] = parse_error or "Lighthouse JSON parse failed"
                    status["failed"] = True
                    self._log_status(status)
                    return self._failed(target_url, f"Lighthouse JSON parse failed: {status['parse_error']}", status)

            if completed is not None and completed.returncode != 0:
                message = status["stderr"] or status["stdout"] or "Lighthouse failed"
                if self._cleanup_only_failure(str(message)):
                    cleanup_error = str(message)[-1000:]
                    cleanup_deferred = True
                    status["completed_with_cleanup_warning"] = True
                    status["cleanup_warning"] = cleanup_error
                    status["cleanup_deferred"] = True
                    status["cleanup_path"] = temp_dir
                    status["retry_recommendation"] = "The audit completed and valid metrics were preserved. Retry later only if cleanup warnings persist."
                else:
                    status["failed"] = True
                    status["error"] = str(message)[-1000:]
                    status["retry_recommendation"] = status.get("retry_recommendation") or "Retry the scan after confirming Chrome and Lighthouse can run from this Windows user account."
                    self._log_status(status)
                    return self._failed(target_url, str(message), status)

            status["json_parsed"] = True
            self._attach_report_debug(status, report)
            runtime_error = report.get("runtimeError")
            if isinstance(runtime_error, dict):
                status["runtime_error"] = runtime_error
            self._mark_reached(status, "page_loaded", True)
            self._mark_reached(status, "audit_completed", True)
            status["timeline"]["page_load_complete"] = "Inferred from valid Lighthouse JSON"  # type: ignore[index]
            status["timeline"]["audit_execution"] = "Completed"  # type: ignore[index]
        finally:
            cleanup_started = perf_counter()
            if isinstance(status.get("timeline"), dict):
                status["timeline"]["cleanup"] = "Started"  # type: ignore[index]
            if cleanup_deferred:
                cleanup_scheduled = self._schedule_cleanup_later(temp_dir, cleanup_error or "Lighthouse cleanup warning")
                status["cleanup_scheduled"] = cleanup_scheduled
            else:
                try:
                    shutil.rmtree(temp_dir)
                except OSError as exc:
                    cleanup_error = str(exc)
                    if status.get("json_parsed"):
                        status["cleanup_warning"] = cleanup_error
                        cleanup_scheduled = self._schedule_cleanup_later(temp_dir, cleanup_error)
                        status["cleanup_deferred"] = True
                        status["cleanup_scheduled"] = cleanup_scheduled
                        status["cleanup_path"] = temp_dir
            cleanup_time_ms = round((perf_counter() - cleanup_started) * 1000)
            status["cleanup_time_ms"] = cleanup_time_ms
            if isinstance(status.get("timeline"), dict):
                status["timeline"]["cleanup"] = "Completed"  # type: ignore[index]

        findings: list[Finding] = []
        scores: dict[str, int] = {}
        for key, category in LIGHTHOUSE_CATEGORIES.items():
            raw_score = report.get("categories", {}).get(key, {}).get("score")
            if raw_score is None:
                continue
            try:
                score = round(float(raw_score) * 100)
            except (TypeError, ValueError):
                continue
            scores[key] = score
            if score < 90:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=category,
                        title=f"Lighthouse {key.replace('-', ' ').title()} score is {score}",
                        description=f"The Lighthouse {key} category scored below the recommended 90 threshold.",
                        severity=Severity.HIGH if score < 50 else Severity.MEDIUM,
                        recommendation=f"Review Lighthouse recommendations and improve the {key} category.",
                        impact="Lower Lighthouse scores can reduce conversion, trust, search visibility, or usability.",
                        evidence={"score": score},
                        weight=max(3, round((90 - score) / 4)),
                    )
                )

        audits = report.get("audits", {})
        for audit_id in ["largest-contentful-paint", "cumulative-layout-shift", "total-blocking-time", "uses-optimized-images", "meta-description", "document-title"]:
            audit = audits.get(audit_id)
            if not audit or audit.get("score") in (None, 1):
                continue
            title = audit.get("title", audit_id)
            findings.append(
                Finding(
                    scanner=self.name,
                    category=self._audit_category(audit_id),
                    title=title,
                    description=audit.get("description", "Lighthouse reported an optimization opportunity."),
                    severity=Severity.MEDIUM,
                    recommendation="Apply the Lighthouse recommendation for this audit.",
                    impact="Improving this item can improve visitor experience and search presentation.",
                    evidence={"audit_id": audit_id, "display_value": audit.get("displayValue")},
                    weight=5,
                )
            )

        overall = round(sum(scores.values()) / len(scores)) if scores else None
        if overall is None:
            runtime_error = status.get("runtime_error")
            if isinstance(runtime_error, dict):
                message = str(runtime_error.get("message") or runtime_error.get("code") or "No Lighthouse category scores returned")
                status["error"] = message
            else:
                message = "No Lighthouse category scores returned"
                status["error"] = message
            status["failed"] = True
            self._log_status(status)
            return self._failed(target_url, message, status)
        status["raw_scores"] = scores
        status["scores_returned"] = bool(scores)
        status["succeeded"] = True
        status["failed"] = False
        self._log_status(status)
        raw: dict[str, object] = {"scores": scores, "status": status}
        warnings = []
        if cleanup_error:
            raw["cleanup_warning"] = cleanup_error
            warnings.append(f"Lighthouse completed with cleanup warning: {cleanup_error}")
        if status.get("completed_with_timeout_warning"):
            warning = str(status.get("timeout_warning") or "Lighthouse completed with timeout warning.")
            raw["timeout_warning"] = warning
            warnings.append(warning)
        return ScannerResult(
            self.name,
            target_url,
            True,
            overall,
            findings,
            raw,
            status=ScannerStatus.WARNING if warnings else ScannerStatus.OK,
            included_in_score=True,
            scores=scores,
            warnings=warnings,
        )

    def _scan_google_pagespeed(self, target_url: str) -> ScannerResult:
        timeout = self._pagespeed_timeout_seconds()
        started = perf_counter()
        status: dict[str, object] = {
            "executed": True,
            "succeeded": False,
            "timed_out": False,
            "failed": False,
            "skipped": False,
            "launched": True,
            "completed": False,
            "json_parsed": False,
            "scores_returned": False,
            "raw_scores": {},
            "parse_error": None,
            "fallback_used": False,
            "provider_used": "google_pagespeed",
            "provider_attempted": "google_pagespeed",
            "fallback_occurred": False,
            "fallback_reason": None,
            "google_fetch_time_ms": None,
            "local_lighthouse_execution_time_ms": None,
            "http_status": None,
            "api_key_configured": bool(os.environ.get("PAGESPEED_API_KEY")),
            "requested_url": target_url,
            "final_url": None,
            "fetch_time": None,
            "config_settings": {},
            "screen_emulation": {},
            "user_agent": None,
            "cpu_throttling": {},
            "network_throttling": {},
            "storage_reset": {},
            "run_warnings": [],
            "environment": {},
            "lighthouse_metrics": {},
            "performance_audit_refs": [],
            "attempts": [],
            "command": "Google PageSpeed Insights API",
            "command_parts": ["google_pagespeed", "mobile", "performance", "accessibility", "best-practices", "seo"],
            "lighthouse_flags": [],
            "chrome_flags": [],
            "retry_count": 0,
            "retry_result_used": False,
            "accepted_attempt": 1,
            "runtime_source": "Google PageSpeed Insights",
        }
        request_url = self._pagespeed_url(target_url)
        try:
            request = urllib.request.Request(
                request_url,
                headers={"User-Agent": "BeaconAudit/1.0 (+https://beacon-audit.com)"},
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status["http_status"] = response.status
                body = response.read()
        except TimeoutError as exc:
            elapsed_ms = round((perf_counter() - started) * 1000)
            details = {"reason": "timeout", "timeout_seconds": timeout, "google_fetch_time_ms": elapsed_ms}
            raise PageSpeedProviderError("Google PageSpeed Insights timed out.", details) from exc
        except urllib.error.HTTPError as exc:
            elapsed_ms = round((perf_counter() - started) * 1000)
            error_body = self._tail(exc.read())
            details = {
                "reason": self._pagespeed_http_reason(exc.code, error_body),
                "http_status": exc.code,
                "response_body": error_body,
                "google_fetch_time_ms": elapsed_ms,
            }
            raise PageSpeedProviderError("Google PageSpeed Insights returned an HTTP error.", details) from exc
        except urllib.error.URLError as exc:
            elapsed_ms = round((perf_counter() - started) * 1000)
            details = {"reason": "network_failure", "error": str(exc.reason), "google_fetch_time_ms": elapsed_ms}
            raise PageSpeedProviderError("Google PageSpeed Insights network request failed.", details) from exc
        except OSError as exc:
            elapsed_ms = round((perf_counter() - started) * 1000)
            details = {"reason": "network_failure", "error": str(exc), "google_fetch_time_ms": elapsed_ms}
            raise PageSpeedProviderError("Google PageSpeed Insights request failed.", details) from exc

        status["google_fetch_time_ms"] = round((perf_counter() - started) * 1000)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            details = {
                "reason": "invalid_response",
                "http_status": status.get("http_status"),
                "google_fetch_time_ms": status.get("google_fetch_time_ms"),
                "parse_error": str(exc),
            }
            raise PageSpeedProviderError("Google PageSpeed Insights returned invalid JSON.", details) from exc

        lighthouse_result = payload.get("lighthouseResult")
        if not isinstance(lighthouse_result, dict):
            details = {
                "reason": "invalid_response",
                "http_status": status.get("http_status"),
                "google_fetch_time_ms": status.get("google_fetch_time_ms"),
                "response_keys": sorted(payload.keys()) if isinstance(payload, dict) else [],
            }
            raise PageSpeedProviderError("Google PageSpeed Insights response did not include Lighthouse results.", details)

        status["completed"] = True
        status["json_parsed"] = True
        status["attempts"] = [
            {
                "attempt": 1,
                "provider": "google_pagespeed",
                "status": "Verified",
                "elapsed_ms": status.get("google_fetch_time_ms"),
                "http_status": status.get("http_status"),
            }
        ]
        self._attach_report_debug(status, lighthouse_result)
        return self._result_from_lighthouse_report(target_url, lighthouse_result, status)

    def _pagespeed_url(self, target_url: str) -> str:
        params: list[tuple[str, str]] = [
            ("url", target_url),
            ("strategy", "mobile"),
            ("category", "performance"),
            ("category", "accessibility"),
            ("category", "best-practices"),
            ("category", "seo"),
        ]
        api_key = os.environ.get("PAGESPEED_API_KEY")
        if api_key:
            params.append(("key", api_key))
        return "https://www.googleapis.com/pagespeedonline/v5/runPagespeed?" + urllib.parse.urlencode(params)

    def _pagespeed_timeout_seconds(self) -> int:
        value = os.environ.get("PAGESPEED_TIMEOUT") or os.environ.get("PUBLIC_SCAN_TIMEOUT")
        if value:
            try:
                return max(5, int(value))
            except ValueError:
                logger.warning("Ignoring invalid PageSpeed timeout value=%s", value)
        return 45

    def _pagespeed_http_reason(self, status_code: int, body: str) -> str:
        lowered = body.lower()
        if status_code == 429 or "quota" in lowered or "rate limit" in lowered:
            return "quota_exceeded"
        if status_code == 400:
            return "api_error"
        if status_code in {401, 403}:
            return "api_auth_error"
        if status_code >= 500:
            return "api_unavailable"
        return "api_error"

    def _with_provider_fallback(self, result: ScannerResult, exc: PageSpeedProviderError, local_elapsed_ms: int) -> ScannerResult:
        raw = dict(result.raw)
        status: dict[str, Any]
        if isinstance(raw.get("status"), dict):
            status = dict(raw["status"])
        else:
            status = {}
        status.update(
            {
                "provider_used": "local_lighthouse",
                "provider_attempted": "google_pagespeed",
                "fallback_occurred": True,
                "fallback_used": True,
                "fallback_reason": exc.reason,
                "google_pagespeed": exc.details,
                "local_lighthouse_execution_time_ms": local_elapsed_ms,
            }
        )
        raw["status"] = status
        warnings = [*result.warnings, f"Google PageSpeed Insights unavailable; used local Lighthouse fallback: {exc.reason}"]
        return ScannerResult(
            scanner=result.scanner,
            target_url=result.target_url,
            ok=result.ok,
            score=result.score,
            findings=result.findings,
            raw=raw,
            elapsed_ms=result.elapsed_ms,
            status=result.status,
            included_in_score=result.included_in_score,
            scores=result.scores,
            error=result.error,
            warnings=warnings,
        )

    def _result_from_lighthouse_report(self, target_url: str, report: dict[str, object], status: dict[str, object]) -> ScannerResult:
        findings: list[Finding] = []
        scores: dict[str, int] = {}
        categories = report.get("categories")
        if not isinstance(categories, dict):
            categories = {}
        for key, category in LIGHTHOUSE_CATEGORIES.items():
            category_payload = categories.get(key)
            if not isinstance(category_payload, dict):
                continue
            raw_score = category_payload.get("score")
            if raw_score is None:
                continue
            try:
                score = round(float(raw_score) * 100)
            except (TypeError, ValueError):
                continue
            scores[key] = score
            if score < 90:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=category,
                        title=f"Lighthouse {key.replace('-', ' ').title()} score is {score}",
                        description=f"The Lighthouse {key} category scored below the recommended 90 threshold.",
                        severity=Severity.HIGH if score < 50 else Severity.MEDIUM,
                        recommendation=f"Review Lighthouse recommendations and improve the {key} category.",
                        impact="Lower Lighthouse scores can reduce conversion, trust, search visibility, or usability.",
                        evidence={"score": score},
                        weight=max(3, round((90 - score) / 4)),
                    )
                )

        audits = report.get("audits", {})
        if isinstance(audits, dict):
            for audit_id in ["largest-contentful-paint", "cumulative-layout-shift", "total-blocking-time", "uses-optimized-images", "meta-description", "document-title"]:
                audit = audits.get(audit_id)
                if not isinstance(audit, dict) or audit.get("score") in (None, 1):
                    continue
                title = audit.get("title", audit_id)
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=self._audit_category(audit_id),
                        title=str(title),
                        description=str(audit.get("description", "Lighthouse reported an optimization opportunity.")),
                        severity=Severity.MEDIUM,
                        recommendation="Apply the Lighthouse recommendation for this audit.",
                        impact="Improving this item can improve visitor experience and search presentation.",
                        evidence={"audit_id": audit_id, "display_value": audit.get("displayValue")},
                        weight=5,
                    )
                )

        overall = round(sum(scores.values()) / len(scores)) if scores else None
        if overall is None:
            runtime_error = status.get("runtime_error")
            if isinstance(runtime_error, dict):
                message = str(runtime_error.get("message") or runtime_error.get("code") or "No Lighthouse category scores returned")
            else:
                message = "No Lighthouse category scores returned"
            status["error"] = message
            status["failed"] = True
            self._log_status(status)
            return self._failed(target_url, message, status)

        status["raw_scores"] = scores
        status["scores_returned"] = True
        status["succeeded"] = True
        status["failed"] = False
        self._log_status(status)
        return ScannerResult(
            self.name,
            target_url,
            True,
            overall,
            findings,
            {"scores": scores, "status": status},
            status=ScannerStatus.OK,
            included_in_score=True,
            scores=scores,
        )

    def _command(self, runtime: object | None = None) -> list[str] | None:
        if runtime is None:
            runtime = self.runtime_manager.lighthouse_runtime()
            self._selected_runtime = runtime
        if runtime and getattr(runtime, "node_executable", None) and getattr(runtime, "lighthouse_entry", None):
            return [str(getattr(runtime, "node_executable")), str(getattr(runtime, "lighthouse_entry"))]
        return None

    def _chrome_path(self, runtime: object | None = None) -> str | None:
        if runtime and getattr(runtime, "chrome_path", None):
            return str(getattr(runtime, "chrome_path"))
        path = self.runtime_manager.chrome_path()
        return str(path) if path else None

    def _full_command(self, command: list[str], target_url: str, output_path: Path, profile_dir: Path, chrome_path: str | None, *, retry_mode: bool = False) -> list[str]:
        chrome_flags = [
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-extensions",
            f"--user-data-dir={profile_dir}",
        ]
        if chrome_path:
            pass
        lighthouse_flags = [
            *command,
            target_url,
            "--quiet",
            f"--chrome-flags={' '.join(chrome_flags)}",
            "--output=json",
            f"--output-path={output_path}",
            "--only-categories=performance,accessibility,best-practices,seo",
        ]
        if retry_mode:
            lighthouse_flags.extend(["--disable-storage-reset", "--throttling-method=provided"])
        return lighthouse_flags

    def _lighthouse_flags(self, command: list[str]) -> list[str]:
        return [part for part in command if part.startswith("--")]

    def _chrome_flags(self, command: list[str]) -> list[str]:
        for part in command:
            if part.startswith("--chrome-flags="):
                return part.removeprefix("--chrome-flags=").split()
        return []

    def _retry_flag_changes(self, retry_mode: bool) -> list[dict[str, str]]:
        if not retry_mode:
            return []
        return [
            {
                "flag": "--disable-storage-reset",
                "initial": "absent",
                "retry": "present",
                "performance_impact_risk": "Medium",
                "reason": "Changes page storage/cache reset behavior between attempts.",
            },
            {
                "flag": "--throttling-method=provided",
                "initial": "Lighthouse default simulated throttling",
                "retry": "Provided runtime throttling",
                "performance_impact_risk": "High",
                "reason": "Makes the score depend more directly on the container CPU/network environment instead of Lighthouse simulated mobile throttling.",
            },
        ]

    def _attach_report_debug(self, status: dict[str, object], report: dict[str, object]) -> None:
        status["requested_url"] = report.get("requestedUrl")
        status["final_url"] = report.get("finalUrl")
        status["fetch_time"] = report.get("fetchTime")
        status["run_warnings"] = report.get("runWarnings") if isinstance(report.get("runWarnings"), list) else []
        status["environment"] = report.get("environment") if isinstance(report.get("environment"), dict) else {}

        config_settings = report.get("configSettings")
        if not isinstance(config_settings, dict):
            config_settings = {}
        status["config_settings"] = config_settings
        status["screen_emulation"] = config_settings.get("screenEmulation") if isinstance(config_settings.get("screenEmulation"), dict) else {}
        status["user_agent"] = config_settings.get("emulatedUserAgent") or config_settings.get("userAgent")
        throttling = config_settings.get("throttling") if isinstance(config_settings.get("throttling"), dict) else {}
        status["network_throttling"] = throttling
        status["cpu_throttling"] = {
            "throttlingMethod": config_settings.get("throttlingMethod"),
            "cpuSlowdownMultiplier": throttling.get("cpuSlowdownMultiplier") if isinstance(throttling, dict) else None,
        }
        status["storage_reset"] = {
            "disableStorageReset": config_settings.get("disableStorageReset"),
            "clearStorageTypes": config_settings.get("clearStorageTypes"),
        }
        status["redirect_chain"] = self._redirect_chain(report)
        status["performance_audit_refs"] = self._performance_audit_refs(report)
        status["lighthouse_metrics"] = self._performance_metrics(report)

    def _redirect_chain(self, report: dict[str, object]) -> list[dict[str, object]]:
        audits = report.get("audits")
        if not isinstance(audits, dict):
            return []
        redirects = audits.get("redirects")
        if not isinstance(redirects, dict):
            return []
        details = redirects.get("details")
        if not isinstance(details, dict):
            return []
        items = details.get("items")
        return items if isinstance(items, list) else []

    def _performance_audit_refs(self, report: dict[str, object]) -> list[dict[str, object]]:
        categories = report.get("categories")
        if not isinstance(categories, dict):
            return []
        performance = categories.get("performance")
        if not isinstance(performance, dict):
            return []
        audit_refs = performance.get("auditRefs")
        if not isinstance(audit_refs, list):
            return []
        return [
            {
                "id": item.get("id"),
                "weight": item.get("weight"),
                "group": item.get("group"),
            }
            for item in audit_refs
            if isinstance(item, dict)
        ]

    def _performance_metrics(self, report: dict[str, object]) -> dict[str, object]:
        audits = report.get("audits")
        if not isinstance(audits, dict):
            return {}
        metric_ids = [
            "first-contentful-paint",
            "largest-contentful-paint",
            "speed-index",
            "interactive",
            "total-blocking-time",
            "cumulative-layout-shift",
            "server-response-time",
            "dom-size",
            "network-requests",
            "total-byte-weight",
            "mainthread-work-breakdown",
            "bootup-time",
            "unused-javascript",
            "unused-css-rules",
            "uses-optimized-images",
            "uses-responsive-images",
            "efficient-animated-content",
            "modern-image-formats",
            "offscreen-images",
            "render-blocking-resources",
            "unminified-css",
            "unminified-javascript",
            "uses-text-compression",
            "uses-rel-preconnect",
            "uses-rel-preload",
            "third-party-summary",
            "diagnostics",
            "metrics",
        ]
        metrics: dict[str, object] = {}
        for audit_id in metric_ids:
            audit = audits.get(audit_id)
            if not isinstance(audit, dict):
                continue
            metrics[audit_id] = self._audit_payload(audit)
        return metrics

    def _audit_payload(self, audit: dict[str, object]) -> dict[str, object]:
        payload: dict[str, object] = {
            "score": audit.get("score"),
            "scoreDisplayMode": audit.get("scoreDisplayMode"),
            "numericValue": audit.get("numericValue"),
            "numericUnit": audit.get("numericUnit"),
            "displayValue": audit.get("displayValue"),
            "title": audit.get("title"),
            "description": audit.get("description"),
        }
        details = audit.get("details")
        if isinstance(details, dict):
            payload["details"] = details
        return payload

    def _timeout_seconds(self) -> int:
        env_value = os.environ.get("BEACON_LIGHTHOUSE_TIMEOUT")
        if env_value:
            try:
                return max(5, int(env_value))
            except ValueError:
                logger.warning("Ignoring invalid BEACON_LIGHTHOUSE_TIMEOUT=%s", env_value)
        config_timeout = self._config_timeout()
        if config_timeout is not None:
            return config_timeout
        return self.DEFAULT_TIMEOUTS.get(self.audit_type, self.DEFAULT_TIMEOUTS["Business Audit"])

    def _config_timeout(self) -> int | None:
        config_path = self.runtime_manager.project_root / "beacon.toml"
        if not config_path.exists():
            return None
        try:
            import tomllib
        except ImportError:  # pragma: no cover - Python <3.11 fallback.
            return None
        try:
            data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            logger.warning("Ignoring invalid beacon.toml Lighthouse timeout config: %s", exc)
            return None
        lighthouse = data.get("lighthouse")
        if not isinstance(lighthouse, dict):
            return None
        keys = {
            "QuickScan": "quick_timeout_seconds",
            "Business Audit": "business_timeout_seconds",
            "Deep Site Audit": "deep_timeout_seconds",
        }
        value = lighthouse.get(keys.get(self.audit_type, "")) or lighthouse.get("timeout_seconds")
        try:
            return max(5, int(value)) if value is not None else None
        except (TypeError, ValueError):
            return None

    def _parse_report(self, output_path: Path) -> tuple[dict[str, object] | None, str | None]:
        try:
            report = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return None, str(exc)
        if not isinstance(report, dict) or not isinstance(report.get("categories"), dict):
            return None, "Lighthouse JSON missing categories object"
        return report, None

    def _timeout_location(self, json_written: bool, json_valid: bool, parse_error: str | None) -> str:
        if json_valid:
            return "after_json_report"
        if json_written and parse_error:
            return "json_parse"
        if json_written:
            return "after_json_write"
        return "before_json_report"

    def _mark_reached(self, status: dict[str, object], key: str, value: bool) -> None:
        reached = status.get("execution_reached")
        if isinstance(reached, dict):
            reached[key] = value

    def _environment(self, chrome_path: str | None, temp_dir: str | None = None) -> dict[str, str] | None:
        env = self.runtime_manager.lighthouse_environment(chrome_path)
        if temp_dir:
            env["TEMP"] = temp_dir
            env["TMP"] = temp_dir
            env["TMPDIR"] = temp_dir
        return env

    def _transient_launch_failure(self, message: str) -> bool:
        lowered = message.lower()
        markers = ["eperm", "permission", "chrome", "launch", "profile", "temp", "user data directory", "timeout"]
        return any(marker in lowered for marker in markers)

    def _cleanup_only_failure(self, message: str) -> bool:
        lowered = message.lower()
        permission_markers = ["eperm", "ebusy", "resource busy", "locked", "permission denied", "access is denied", "operation not permitted"]
        cleanup_markers = ["destroytmp", "cleanup", "rmdir", "unlink", "remove", "temp", "tmp", "profile", "user data directory"]
        return any(marker in lowered for marker in permission_markers) and any(marker in lowered for marker in cleanup_markers)

    def _schedule_cleanup_later(self, path: str, reason: str) -> bool:
        logger.warning("Deferring Lighthouse temp cleanup for %s: %s", path, reason)

        def cleanup() -> None:
            try:
                shutil.rmtree(path)
            except OSError as exc:
                logger.warning("Deferred Lighthouse temp cleanup failed for %s: %s", path, exc)

        timer = threading.Timer(30.0, cleanup)
        timer.daemon = True
        timer.start()
        return True

    def _failed(self, target_url: str, message: str, status: dict[str, object] | None = None) -> ScannerResult:
        raw_status = status or {
            "launched": False,
            "completed": False,
            "json_parsed": False,
            "scores_returned": False,
            "raw_scores": {},
            "parse_error": None,
            "fallback_used": False,
            "error": message[-1000:],
        }
        finding = Finding(
            scanner=self.name,
            category=Category.PERFORMANCE,
            title="Lighthouse scan failed",
            description="Beacon could not complete the Lighthouse scan.",
            severity=Severity.MEDIUM,
            recommendation="Retry the scan after confirming Chrome and Lighthouse can run from this Windows account.",
            impact="Performance metrics are not included. All other completed scanners remain valid.",
            evidence={"error": message[-1000:]},
            weight=5,
        )
        return ScannerResult(
            self.name,
            target_url,
            False,
            None,
            [finding],
            {"error": message, "status": raw_status},
            status=ScannerStatus.FAILED,
            included_in_score=False,
            error=message[-4000:],
        )

    def _audit_category(self, audit_id: str) -> Category:
        if audit_id in {"meta-description", "document-title"}:
            return Category.SEO
        return Category.PERFORMANCE

    def _log_status(self, status: dict[str, object]) -> None:
        logger.info(
            "Lighthouse status launched=%s completed=%s json_parsed=%s scores_returned=%s fallback_used=%s",
            status.get("launched"),
            status.get("completed"),
            status.get("json_parsed"),
            status.get("scores_returned"),
            status.get("fallback_used"),
        )

    def _tail(self, value: object) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", "ignore")[-4000:]
        return str(value)[-4000:]
