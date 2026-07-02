from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from time import perf_counter

from api.capabilities import capability_matrix, section_contract
from api.models import AuditReport, Finding, ScannerResult, ScannerStatus
from api.ops_logging import log_failure_metric
from api.opportunities import OpportunityEngine
from api.scanners import DnsScanner, HostingScanner, LighthouseScanner, SecurityHeadersScanner, SslScanner
from api.scanners.base import Scanner
from api.scoring import BeaconScorer
from api.technology import TechnologyFingerprinter
from api.utils import normalize_url, stable_scan_id


DEFAULT_SCANNERS: tuple[type[Scanner], ...] = (
    SecurityHeadersScanner,
    SslScanner,
    DnsScanner,
    HostingScanner,
    LighthouseScanner,
)


class AuditEngine:
    def __init__(self, scanners: list[Scanner] | None = None, max_workers: int = 5) -> None:
        self.scanners = scanners or [scanner_type() for scanner_type in DEFAULT_SCANNERS]
        self.max_workers = max_workers
        self.scorer = BeaconScorer()
        self.opportunities = OpportunityEngine()
        self.technology = TechnologyFingerprinter()

    def scan(self, target_url: str, *, lead_email: str | None = None, audit_type: str = "Business Audit") -> AuditReport:
        normalized_url = normalize_url(target_url)
        scan_started_at = datetime.now(UTC)
        start = perf_counter()
        results: list[ScannerResult] = []
        for scanner in self.scanners:
            if isinstance(scanner, LighthouseScanner):
                scanner.audit_type = audit_type

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(self.scanners))) as executor:
            futures = {executor.submit(scanner.run, normalized_url): scanner.name for scanner in self.scanners}
            for future in as_completed(futures):
                scanner_name = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    log_failure_metric(
                        "scanner_exception",
                        domain=normalize_url(normalized_url).split("://", 1)[-1].split("/", 1)[0],
                        scanner=scanner_name,
                        status="failure",
                        failure_type="scanner_exception",
                        message=str(exc),
                    )
                    raise

        results.sort(key=lambda result: result.scanner)
        results = [self._normalize_result(result) for result in results]
        findings: list[Finding] = [finding for result in results for finding in result.findings]
        lighthouse_status = self._lighthouse_status(results)
        scoring_started = perf_counter()
        scores = self.scorer.score_results(findings, results)
        scoring_elapsed_ms = round((perf_counter() - scoring_started) * 1000)
        opportunities_started = perf_counter()
        opportunities = self.opportunities.generate(findings)
        opportunities_elapsed_ms = round((perf_counter() - opportunities_started) * 1000)
        technology_status = self._technology_status(normalized_url)
        scan_finished_at = datetime.now(UTC)
        elapsed_ms = round((perf_counter() - start) * 1000)
        summary = self._summary(normalized_url, scores.beacon_score, scores.grade, findings)
        metadata = {
            "scan_started_at": scan_started_at.isoformat(),
            "scan_finished_at": scan_finished_at.isoformat(),
            "elapsed_ms": elapsed_ms,
            "lighthouse": lighthouse_status,
            "lighthouse_metrics_available": bool(lighthouse_status.get("scores_returned")),
            "score_is_partial": any(not result.included_in_score for result in results),
            "scanner_statuses": [self._scanner_status_payload(result) for result in results],
            "subsystems": self._subsystems(results, technology_status, elapsed_ms),
            "timing": self._timing(results, technology_status, elapsed_ms),
            "debug_stage_timings": {
                "scoring_time_ms": scoring_elapsed_ms,
                "opportunity_builder_time_ms": opportunities_elapsed_ms,
            },
            "capability_matrix": capability_matrix(audit_type),
            "report_sections": section_contract(audit_type),
        }
        if technology_status["status"] == "succeeded":
            metadata["technology_profile"] = technology_status["data"]
        else:
            metadata["technology_profile_error"] = technology_status["error"]

        return AuditReport.now(
            scan_id=stable_scan_id(normalized_url),
            target_url=normalized_url,
            elapsed_ms=elapsed_ms,
            scores=scores,
            scanner_results=results,
            findings=findings,
            opportunities=opportunities,
            summary=summary,
            lead_email=lead_email,
            metadata=metadata,
        )

    def _summary(self, target_url: str, score: int, grade: str, findings: list[Finding]) -> str:
        if not findings:
            return f"{target_url} scored {score} ({grade}) with no priority findings detected."
        top = sorted(findings, key=lambda finding: finding.weight, reverse=True)[:3]
        issues = "; ".join(finding.title for finding in top)
        return f"{target_url} scored {score} ({grade}). Highest-priority issues: {issues}."

    def _normalize_result(self, result: ScannerResult) -> ScannerResult:
        status = result.status
        if status == ScannerStatus.OK and not result.ok:
            status = ScannerStatus.FAILED
        included = result.included_in_score and status in {ScannerStatus.OK, ScannerStatus.WARNING} and result.score is not None
        return ScannerResult(
            scanner=result.scanner,
            target_url=result.target_url,
            ok=result.ok and status in {ScannerStatus.OK, ScannerStatus.WARNING},
            score=result.score if included else None,
            findings=result.findings,
            raw=result.raw,
            elapsed_ms=result.elapsed_ms,
            status=status,
            included_in_score=included,
            scores=result.scores if included else {},
            error=result.error or result.raw.get("error"),
            warnings=result.warnings,
        )

    def _scanner_status_payload(self, result: ScannerResult) -> dict[str, object]:
        return {
            "scanner": result.scanner,
            "status": result.status.value,
            "elapsed_ms": result.elapsed_ms,
            "included_in_score": result.included_in_score,
            "score": result.score,
            "scores": result.scores,
            "error": result.error,
            "warnings": result.warnings,
            "executed": True,
            "succeeded": result.status in {ScannerStatus.OK, ScannerStatus.WARNING},
            "failed": result.status == ScannerStatus.FAILED,
            "skipped": result.status == ScannerStatus.SKIPPED,
        }

    def _technology_status(self, normalized_url: str) -> dict[str, object]:
        start = perf_counter()
        try:
            profile = self.technology.fingerprint(normalized_url)
            elapsed_ms = round((perf_counter() - start) * 1000)
            return {
                "subsystem": "technology_profile",
                "executed": True,
                "status": "succeeded",
                "elapsed_ms": elapsed_ms,
                "error": None,
                "warnings": [],
                "data": profile,
            }
        except Exception as exc:
            elapsed_ms = round((perf_counter() - start) * 1000)
            return {
                "subsystem": "technology_profile",
                "executed": True,
                "status": "failed",
                "elapsed_ms": elapsed_ms,
                "error": str(exc),
                "warnings": [],
                "data": None,
            }

    def _subsystems(self, results: list[ScannerResult], technology_status: dict[str, object], elapsed_ms: int) -> list[dict[str, object]]:
        rows = [
            {
                "subsystem": result.scanner,
                "executed": True,
                "status": "succeeded" if result.status in {ScannerStatus.OK, ScannerStatus.WARNING} else "failed" if result.status == ScannerStatus.FAILED else "skipped",
                "elapsed_ms": result.elapsed_ms,
                "error": result.error,
                "warnings": result.warnings,
                "included_in_score": result.included_in_score,
            }
            for result in results
        ]
        rows.append(
            {
                "subsystem": "technology_profile",
                "executed": bool(technology_status["executed"]),
                "status": technology_status["status"],
                "elapsed_ms": technology_status["elapsed_ms"],
                "error": technology_status["error"],
                "warnings": technology_status["warnings"],
                "included_in_score": False,
            }
        )
        rows.append(
            {
                "subsystem": "scan_total",
                "executed": True,
                "status": "succeeded",
                "elapsed_ms": elapsed_ms,
                "error": None,
                "warnings": [],
                "included_in_score": False,
            }
        )
        return rows

    def _timing(self, results: list[ScannerResult], technology_status: dict[str, object], elapsed_ms: int) -> dict[str, int | None]:
        by_scanner = {result.scanner: result.elapsed_ms for result in results}
        return {
            "scan_elapsed_ms": elapsed_ms,
            "dns_time_ms": by_scanner.get("dns"),
            "ssl_time_ms": by_scanner.get("ssl"),
            "headers_time_ms": by_scanner.get("security_headers"),
            "hosting_time_ms": by_scanner.get("hosting"),
            "technology_profile_time_ms": int(technology_status["elapsed_ms"]),
            "crawler_time_ms": 0,
            "lighthouse_time_ms": by_scanner.get("lighthouse"),
        }

    def _lighthouse_status(self, results: list[ScannerResult]) -> dict[str, object]:
        default_status: dict[str, object] = {
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
            "available": False,
            "command": None,
            "returncode": None,
            "execution_time_ms": None,
            "stdout": "",
            "stderr": "",
        }
        for result in results:
            if result.scanner != "lighthouse":
                continue
            status = result.raw.get("status")
            if isinstance(status, dict):
                result_status = {
                    **default_status,
                    **status,
                    "available": bool(result.included_in_score and status.get("scores_returned")),
                    "scanner_status": result.status.value,
                    "included_in_score": result.included_in_score,
                    "elapsed_ms": result.elapsed_ms,
                    "error": result.error,
                    "warnings": result.warnings,
                }
                if not result.included_in_score:
                    result_status["raw_scores"] = {}
                    result_status["scores_returned"] = False
                return result_status
            return default_status
        return default_status
