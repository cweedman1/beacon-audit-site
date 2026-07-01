from __future__ import annotations

from api.models import Category, Finding, Opportunity, Severity
from api.scoring import SEVERITY_PRIORITY


BUSINESS_IMPACT_BY_CATEGORY = {
    Category.SECURITY: "Reduces trust risk, browser warnings, spoofing exposure, and preventable security incidents.",
    Category.PERFORMANCE: "Improves load speed, customer patience, conversion, and mobile experience.",
    Category.SEO: "Improves how the business appears in search results and shared links.",
    Category.INFRASTRUCTURE: "Improves reliability, email trust, and operational resilience.",
    Category.ACCESSIBILITY: "Improves usability for more visitors and reduces accessibility risk.",
    Category.BEST_PRACTICES: "Improves browser compatibility and maintainability.",
}

ESTIMATED_IMPACT_BY_SEVERITY = {
    Severity.CRITICAL: "Immediate business risk; fix first.",
    Severity.HIGH: "High-value improvement likely to affect trust, traffic, or conversion.",
    Severity.MEDIUM: "Meaningful improvement for professionalism and customer experience.",
    Severity.LOW: "Good hygiene item after higher-priority fixes.",
    Severity.INFO: "Maintenance awareness item.",
}

COMPLEXITY_BY_SEVERITY = {
    Severity.CRITICAL: "High",
    Severity.HIGH: "Medium",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Low",
}


class OpportunityEngine:
    def generate(self, findings: list[Finding]) -> list[Opportunity]:
        ranked = sorted(
            findings,
            key=lambda finding: (SEVERITY_PRIORITY[finding.severity], finding.weight),
            reverse=True,
        )
        opportunities: list[Opportunity] = []
        for index, finding in enumerate(ranked, start=1):
            opportunities.append(
                Opportunity(
                    issue=finding.title,
                    severity=finding.severity,
                    category=finding.category,
                    business_impact=BUSINESS_IMPACT_BY_CATEGORY.get(
                        finding.category,
                        "Improves the public quality and reliability of the website.",
                    ),
                    recommended_fix=finding.recommendation,
                    priority=index,
                    estimated_impact=ESTIMATED_IMPACT_BY_SEVERITY[finding.severity],
                    estimated_fix_complexity=COMPLEXITY_BY_SEVERITY[finding.severity],
                )
            )
        return opportunities
