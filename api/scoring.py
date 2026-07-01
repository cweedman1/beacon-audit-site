from __future__ import annotations

from collections import defaultdict

from api.models import Category, Finding, ScannerResult, ScannerStatus, ScoreBreakdown, Severity
from api.utils import clamp_score


CATEGORY_ALIASES = {
    Category.ACCESSIBILITY: Category.PERFORMANCE,
    Category.BEST_PRACTICES: Category.SECURITY,
}

CATEGORY_WEIGHTS = {
    "security": 0.35,
    "performance": 0.25,
    "seo": 0.15,
    "infrastructure": 0.25,
}

SEVERITY_PRIORITY = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class BeaconScorer:
    def score_results(self, findings: list[Finding], scanner_results: list[ScannerResult]) -> ScoreBreakdown:
        scanner_scores = {
            result.scanner: result.score
            for result in scanner_results
            if result.included_in_score and result.status in {ScannerStatus.OK, ScannerStatus.WARNING}
        }
        lighthouse = next((result for result in scanner_results if result.scanner == "lighthouse"), None)
        lighthouse_scores = lighthouse.scores if lighthouse and lighthouse.included_in_score and lighthouse.scores else None
        return self.score(findings, scanner_scores, lighthouse_scores=lighthouse_scores)

    def score(
        self,
        findings: list[Finding],
        scanner_scores: dict[str, int | None],
        lighthouse_scores: dict[str, int] | None = None,
    ) -> ScoreBreakdown:
        penalties: dict[Category, int] = defaultdict(int)
        for finding in findings:
            category = CATEGORY_ALIASES.get(finding.category, finding.category)
            penalties[category] += finding.weight

        security = self._category_score(Category.SECURITY, penalties, scanner_scores, ["security_headers", "ssl"])
        performance = self._lighthouse_category_score(lighthouse_scores, "performance")
        seo = self._lighthouse_category_score(lighthouse_scores, "seo")
        infrastructure = self._category_score(Category.INFRASTRUCTURE, penalties, scanner_scores, ["dns", "hosting"])
        accessibility = self._lighthouse_category_score(lighthouse_scores, "accessibility")
        best_practices = self._lighthouse_category_score(lighthouse_scores, "best-practices")

        beacon_score = self._weighted_score(
            {
                "security": security,
                "performance": performance,
                "seo": seo,
                "infrastructure": infrastructure,
            }
        )

        top_findings = sorted(
            findings,
            key=lambda item: (SEVERITY_PRIORITY[item.severity], item.weight),
            reverse=True,
        )[:10]

        return ScoreBreakdown(
            security=security,
            performance=performance,
            seo=seo,
            infrastructure=infrastructure,
            accessibility=accessibility,
            best_practices=best_practices,
            beacon_score=beacon_score,
            grade=self._grade(beacon_score),
            top_findings=top_findings,
        )

    def _category_score(
        self,
        category: Category,
        penalties: dict[Category, int],
        scanner_scores: dict[str, int | None],
        scanners: list[str],
    ) -> int | None:
        explicit_scores = [scanner_scores[name] for name in scanners if scanner_scores.get(name) is not None]
        if not explicit_scores:
            return None
        base = sum(explicit_scores) / len(explicit_scores)
        return clamp_score(base - penalties.get(category, 0) * 0.35)

    def _raw_category_score(self, category: Category, penalties: dict[Category, int]) -> int:
        return clamp_score(100 - penalties.get(category, 0))

    def _lighthouse_category_score(self, lighthouse_scores: dict[str, int] | None, category: str) -> int | None:
        if not lighthouse_scores:
            return None
        return lighthouse_scores.get(category)

    def _weighted_score(self, category_scores: dict[str, int | None]) -> int:
        available_weight = sum(CATEGORY_WEIGHTS[name] for name, score in category_scores.items() if score is not None)
        if available_weight == 0:
            return 0
        total = sum((score or 0) * CATEGORY_WEIGHTS[name] for name, score in category_scores.items() if score is not None)
        return clamp_score(total / available_weight)

    def _grade(self, score: int) -> str:
        if score >= 97:
            return "A+"
        if score >= 93:
            return "A"
        if score >= 90:
            return "A-"
        if score >= 87:
            return "B+"
        if score >= 83:
            return "B"
        if score >= 80:
            return "B-"
        if score >= 77:
            return "C+"
        if score >= 73:
            return "C"
        if score >= 70:
            return "C-"
        if score >= 60:
            return "D"
        return "F"
