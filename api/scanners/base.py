from __future__ import annotations

from abc import ABC, abstractmethod
from time import perf_counter

from api.models import ScannerResult, ScannerStatus


class Scanner(ABC):
    name: str
    timeout_seconds: int = 15

    def run(self, target_url: str) -> ScannerResult:
        start = perf_counter()
        result = self.scan(target_url)
        elapsed_ms = round((perf_counter() - start) * 1000)
        status = result.status
        if status == ScannerStatus.OK and not result.ok:
            status = ScannerStatus.FAILED
        return ScannerResult(
            scanner=result.scanner,
            target_url=result.target_url,
            ok=result.ok,
            score=result.score,
            findings=result.findings,
            raw=result.raw,
            elapsed_ms=elapsed_ms,
            status=status,
            included_in_score=result.included_in_score and status in {ScannerStatus.OK, ScannerStatus.WARNING},
            scores=result.scores,
            error=result.error,
            warnings=result.warnings,
        )

    @abstractmethod
    def scan(self, target_url: str) -> ScannerResult:
        raise NotImplementedError
