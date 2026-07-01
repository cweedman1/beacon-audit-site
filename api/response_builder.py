from __future__ import annotations

from api.models import AuditReport, Finding, Opportunity, Severity
from api.schemas import CategoryGrade, FreeScanResponse, IssueSummary, OverallGrade, RecommendedFix


API_VERSION = "1.0"
SCAN_ENGINE = "Beacon QuickScan"


def build_public_response(report: AuditReport) -> FreeScanResponse:
    top_issues = [_issue_summary(finding) for finding in _top_findings(report)[:3]]
    fixes = [_recommended_fix(opportunity) for opportunity in report.opportunities[:3]]
    summary = _summary(report)
    return FreeScanResponse(
        api_version=API_VERSION,
        scan_engine=SCAN_ENGINE,
        url=report.target_url,
        overall=OverallGrade(
            grade=report.scores.grade,
            status=_overall_status(report.scores.beacon_score),
            summary=summary,
        ),
        categories={
            "security": _category(report.scores.security),
            "performance": _category(report.scores.performance),
            "seo": _category(report.scores.seo),
            "accessibility": _category(report.scores.accessibility),
            "infrastructure": _category(report.scores.infrastructure),
        },
        summary=summary,
        top_issues=top_issues,
        recommended_fixes=fixes,
        estimated_effort=_estimated_effort(report.opportunities),
    )


def _category(score: int | None) -> CategoryGrade:
    if score is None:
        return CategoryGrade(score=None, grade=None, status="not_verified")
    return CategoryGrade(score=score, grade=_grade(score), status="verified")


def _grade(score: int) -> str:
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


def _overall_status(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 80:
        return "Good"
    if score >= 70:
        return "Fair"
    return "Needs attention"


def _summary(report: AuditReport) -> str:
    if report.summary:
        return report.summary
    score = report.scores.beacon_score
    if score >= 80:
        return "Your website is healthy overall with several worthwhile improvements."
    if score >= 70:
        return "Your website is working, but several improvements could increase trust, speed, and visibility."
    return "Your website has important issues that should be reviewed before they affect customer trust or performance."


def _top_findings(report: AuditReport) -> list[Finding]:
    return report.scores.top_findings or report.findings


def _issue_summary(finding: Finding) -> IssueSummary:
    return IssueSummary(
        title=finding.title,
        severity=finding.severity.value,
        explanation=finding.description,
        business_impact=finding.impact,
        recommended_fix=finding.recommendation,
    )


def _recommended_fix(opportunity: Opportunity) -> RecommendedFix:
    return RecommendedFix(
        title=opportunity.recommended_fix,
        priority=_priority_label(opportunity.severity),
        estimated_effort=_complexity_effort(opportunity.estimated_fix_complexity),
        business_impact=opportunity.business_impact,
    )


def _priority_label(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "high"
    if severity == Severity.MEDIUM:
        return "medium"
    return "low"


def _estimated_effort(opportunities: list[Opportunity]) -> str:
    complexities = {item.estimated_fix_complexity.lower() for item in opportunities}
    if any("high" in item for item in complexities):
        return "4-8 hours"
    if any("medium" in item for item in complexities):
        return "2-4 hours"
    if opportunities:
        return "30-60 minutes"
    return "No immediate repair estimate"


def _complexity_effort(complexity: str) -> str:
    normalized = complexity.lower()
    if "high" in normalized:
        return "4-8 hours"
    if "medium" in normalized:
        return "2-4 hours"
    return "30-60 minutes"

