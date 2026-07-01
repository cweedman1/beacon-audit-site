from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SECURITY = "security"
    PERFORMANCE = "performance"
    SEO = "seo"
    INFRASTRUCTURE = "infrastructure"
    ACCESSIBILITY = "accessibility"
    BEST_PRACTICES = "best_practices"


class ScannerStatus(str, Enum):
    OK = "ok"
    WARNING = "warning"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class Finding:
    scanner: str
    category: Category
    title: str
    description: str
    severity: Severity
    recommendation: str
    impact: str
    evidence: dict[str, Any] = field(default_factory=dict)
    weight: int = 5


@dataclass(frozen=True)
class Opportunity:
    issue: str
    severity: Severity
    category: Category
    business_impact: str
    recommended_fix: str
    priority: int
    estimated_impact: str
    estimated_fix_complexity: str


@dataclass(frozen=True)
class ScannerResult:
    scanner: str
    target_url: str
    ok: bool
    score: int | None
    findings: list[Finding]
    raw: dict[str, Any] = field(default_factory=dict)
    elapsed_ms: int = 0
    status: ScannerStatus = ScannerStatus.OK
    included_in_score: bool = True
    scores: dict[str, int] = field(default_factory=dict)
    error: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ScoreBreakdown:
    security: int | None
    performance: int | None
    seo: int | None
    infrastructure: int | None
    accessibility: int | None
    best_practices: int | None
    beacon_score: int
    grade: str
    top_findings: list[Finding]


@dataclass(frozen=True)
class AuditReport:
    scan_id: str
    target_url: str
    scanned_at: datetime
    elapsed_ms: int
    scores: ScoreBreakdown
    scanner_results: list[ScannerResult]
    findings: list[Finding]
    opportunities: list[Opportunity]
    summary: str
    lead_email: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def now(
        cls,
        scan_id: str,
        target_url: str,
        elapsed_ms: int,
        scores: ScoreBreakdown,
        scanner_results: list[ScannerResult],
        findings: list[Finding],
        opportunities: list[Opportunity],
        summary: str,
        lead_email: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "AuditReport":
        return cls(
            scan_id=scan_id,
            target_url=target_url,
            scanned_at=datetime.now(UTC),
            elapsed_ms=elapsed_ms,
            scores=scores,
            scanner_results=scanner_results,
            findings=findings,
            opportunities=opportunities,
            summary=summary,
            lead_email=lead_email,
            metadata=metadata or {},
        )


@dataclass(frozen=True)
class CrawledPage:
    url: str
    status_code: int | None
    final_url: str
    title: str | None
    meta_description: str | None
    links: list[str]
    elapsed_ms: int
    error: str | None = None
    redirect_chain: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CrawlResult:
    start_url: str
    pages: list[CrawledPage]
    broken_links: list[dict[str, Any]]
    redirect_chains: list[dict[str, Any]]
    robots_allowed: bool
    sitemap_urls: list[str]
    page_limit: int


@dataclass(frozen=True)
class ExpertReviewPrompt:
    category: str
    prompt: str
    observation: str | None = None
    reviewer: str | None = None


@dataclass(frozen=True)
class TechnologyDetection:
    name: str
    value: str
    confidence: str
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TechnologyProfile:
    target_url: str
    domain: dict[str, TechnologyDetection]
    dns: dict[str, TechnologyDetection]
    hosting: dict[str, TechnologyDetection]
    platform: dict[str, TechnologyDetection]
    frameworks: dict[str, TechnologyDetection]
    analytics: dict[str, TechnologyDetection]
    infrastructure: dict[str, TechnologyDetection]
    email: dict[str, TechnologyDetection]
    cms: dict[str, TechnologyDetection]
    migration_assessment: dict[str, TechnologyDetection]
    raw_evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SiteAuditReport:
    scan_id: str
    start_url: str
    scanned_at: datetime
    elapsed_ms: int
    page_limit: int
    pages_scanned: int
    site_scores: ScoreBreakdown
    page_reports: list[AuditReport]
    crawl: CrawlResult
    issue_summary: list[dict[str, Any]]
    most_critical_pages: list[dict[str, Any]]
    missing_metadata: list[dict[str, Any]]
    missing_security_headers_by_page: list[dict[str, Any]]
    slow_pages: list[dict[str, Any]]
    accessibility_issues_by_page: list[dict[str, Any]]
    expert_review: list[ExpertReviewPrompt]
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)
