from __future__ import annotations

from api.models import AuditReport, Category, Finding, Opportunity, Severity
from api.schemas import CategoryGrade, FreeScanResponse, IssueSummary, OverallGrade, RecommendedFix, ReportMetadata


API_VERSION = "1.0"
SCAN_ENGINE = "Beacon QuickScan"


def build_public_response(report: AuditReport) -> FreeScanResponse:
    top_issues = [_issue_summary(finding) for finding in _display_findings(report)]
    fixes = [_recommended_fix(opportunity) for opportunity in _display_opportunities(report)]
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
        report_metadata=_report_metadata(report),
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


def _display_findings(report: AuditReport) -> list[Finding]:
    return _balanced_by_category(_top_findings(report), 3)


def _display_opportunities(report: AuditReport) -> list[Opportunity]:
    return _balanced_by_category(report.opportunities, 3)


def _balanced_by_category(items: list[Finding] | list[Opportunity], limit: int) -> list[Finding] | list[Opportunity]:
    selected = []
    selected_categories: set[Category] = set()
    for item in items:
        category = item.category
        if category in selected_categories:
            continue
        selected.append(item)
        selected_categories.add(category)
        if len(selected) == limit:
            return selected
    for item in items:
        if item in selected:
            continue
        selected.append(item)
        if len(selected) == limit:
            break
    return selected


def _issue_summary(finding: Finding) -> IssueSummary:
    wording = _finding_wording(finding)
    return IssueSummary(
        title=wording["title"],
        severity=finding.severity.value,
        explanation=wording["explanation"],
        business_impact=wording["business_impact"],
        recommended_fix=wording["recommended_fix"],
    )


def _recommended_fix(opportunity: Opportunity) -> RecommendedFix:
    wording = _opportunity_wording(opportunity)
    return RecommendedFix(
        title=wording["title"],
        priority=_priority_label(opportunity.severity),
        estimated_effort=_complexity_effort(opportunity.estimated_fix_complexity),
        business_impact=wording["business_impact"],
    )


def _finding_wording(finding: Finding) -> dict[str, str]:
    technical = _technical_detail(finding.title)
    title = finding.title.lower()
    if title == "csp allows unsafe inline scripts":
        return {
            "title": "Browser security policy could be stronger",
            "explanation": "Your website allows certain script behavior that is safer to restrict. Strengthening this policy reduces the impact of malicious code if the site is ever compromised. " + technical,
            "business_impact": "A stronger browser policy improves visitor trust and reduces preventable client-side security risk.",
            "recommended_fix": "Move inline scripts to approved files or use a nonce or hash based Content Security Policy.",
        }
    if title == "missing hsts":
        return _security_header_wording(
            "HTTPS protection can be strengthened",
            "Modern browsers can be told to always use the secure version of your website. Enabling this helps prevent visitors from being downgraded to an insecure connection.",
            "Add the Strict-Transport-Security header after confirming HTTPS is stable.",
            technical,
        )
    if title == "missing content security policy":
        return _security_header_wording(
            "Browser security policy is not configured",
            "A Content Security Policy tells browsers which scripts, styles, and resources are trusted. This limits damage if unwanted code is injected into the site.",
            "Add a restrictive Content Security Policy that matches the scripts and services your site actually uses.",
            technical,
        )
    if title == "missing x-frame-options":
        return _security_header_wording(
            "Clickjacking protection can be improved",
            "Browsers can block other sites from placing your pages inside hidden frames. This helps protect visitors from deceptive clicks.",
            "Add X-Frame-Options or the frame-ancestors Content Security Policy directive.",
            technical,
        )
    if title == "missing referrer-policy":
        return _security_header_wording(
            "Visitor URL privacy can be improved",
            "A referrer policy limits how much page address information is shared when visitors click from your site to another site.",
            "Add a Referrer-Policy header with an appropriate privacy setting.",
            technical,
        )
    if title == "missing permissions-policy":
        return _security_header_wording(
            "Unused browser features are not restricted",
            "Browsers support features such as camera, microphone, location, and sensors. Sites should explicitly disable features they do not use.",
            "Add a Permissions-Policy header that allows only the browser features your site needs.",
            technical,
        )
    if title == "missing x-content-type-options":
        return _security_header_wording(
            "Browser file-type protection can be improved",
            "Browsers can be told not to guess file types. This reduces avoidable risk from misinterpreted scripts or files.",
            "Add X-Content-Type-Options: nosniff.",
            technical,
        )
    if title == "cdn not detected":
        return {
            "title": "No Content Delivery Network detected",
            "explanation": "A CDN, such as Cloudflare, serves your website from locations closer to visitors. This usually improves speed, reliability, and resilience. " + technical,
            "business_impact": "Visitors farther from your host may see slower page loads, especially on mobile or weaker connections.",
            "recommended_fix": "Review whether the site should use a CDN for public pages and static assets.",
        }
    if title == "spf record not detected":
        return {
            "title": "Email sender protection can be improved",
            "explanation": "SPF tells receiving mail systems which services are allowed to send email for your domain. This helps reduce spoofing and delivery problems. " + technical,
            "business_impact": "Stronger email authentication helps protect the brand and can improve the reliability of customer email delivery.",
            "recommended_fix": "Publish an SPF record that lists the services authorized to send email for the business.",
        }
    if title == "dmarc record not detected":
        return {
            "title": "Email impersonation protection can be improved",
            "explanation": "DMARC tells mail systems what to do when someone sends suspicious email using your domain. It helps reduce impersonation and phishing risk. " + technical,
            "business_impact": "Better domain email protection helps customers trust messages that appear to come from the business.",
            "recommended_fix": "Publish a DMARC record and gradually move toward a stronger policy after monitoring legitimate email.",
        }
    if title == "no a or aaaa records resolved":
        return {
            "title": "Website address is not resolving",
            "explanation": "The website address did not resolve to a public server address during the scan. Visitors may not be able to reach the site. " + technical,
            "business_impact": "If DNS resolution fails for customers, the website is effectively offline for them.",
            "recommended_fix": "Fix the DNS records so the website hostname points to the correct hosting provider.",
        }
    if title == "no ipv6 record detected":
        return {
            "title": "Modern network support can be improved",
            "explanation": "The website does not currently publish an IPv6 address. Most visitors can still reach the site, but some modern networks may route less efficiently. " + technical,
            "business_impact": "This is usually a lower-priority infrastructure improvement, but it can improve compatibility over time.",
            "recommended_fix": "Add IPv6 support when the hosting platform supports it and higher-priority fixes are complete.",
        }
    if title == "ssl/tls connection failed":
        return {
            "title": "Secure website connection failed",
            "explanation": "The scan could not verify a secure HTTPS connection. Visitors may see browser warnings or may not be able to connect safely. " + technical,
            "business_impact": "HTTPS problems can immediately reduce customer trust and block access to the website.",
            "recommended_fix": "Install or repair the website certificate and confirm HTTPS is reachable on port 443.",
        }
    if title == "tls certificate is expired":
        return {
            "title": "Website security certificate is expired",
            "explanation": "The certificate used for HTTPS is past its expiration date. Browsers may warn visitors before they reach the site. " + technical,
            "business_impact": "Expired certificates can make the business look unmaintained and can stop customers from using the site.",
            "recommended_fix": "Renew and deploy the TLS certificate immediately.",
        }
    if title == "tls certificate expires soon":
        return {
            "title": "Website security certificate needs renewal soon",
            "explanation": "The HTTPS certificate is close to expiration. If it expires, visitors may be blocked by browser warnings. " + technical,
            "business_impact": "Renewing early prevents avoidable downtime and trust issues.",
            "recommended_fix": "Renew the TLS certificate before it expires.",
        }
    if title == "legacy tls version negotiated":
        return {
            "title": "Secure connection settings are outdated",
            "explanation": "The site accepted an older TLS protocol version. Modern hosting should prefer TLS 1.2 or TLS 1.3. " + technical,
            "business_impact": "Updating TLS settings improves customer trust and supports modern security expectations.",
            "recommended_fix": "Disable TLS 1.0 and TLS 1.1 and keep TLS 1.2 or TLS 1.3 enabled.",
        }
    if title == "weak tls cipher negotiated":
        return {
            "title": "Secure connection encryption can be strengthened",
            "explanation": "The site accepted an older or weaker encryption method during the secure connection check. " + technical,
            "business_impact": "Stronger encryption settings help protect visitor traffic and improve security posture.",
            "recommended_fix": "Disable weak cipher suites in the hosting TLS configuration.",
        }
    if "largest contentful paint" in title:
        return _performance_wording(
            "Main page content appears slowly",
            "Visitors may wait longer than recommended before the largest part of your homepage becomes visible.",
            "Review the page's main image, fonts, server response, and render-blocking resources.",
            finding,
        )
    if "total blocking time" in title:
        return _performance_wording(
            "Page scripts may delay interaction",
            "The page may look visible before it is fully ready for visitor taps, clicks, or form input.",
            "Review large JavaScript tasks, third-party scripts, and unused code that runs during page load.",
            finding,
        )
    if "cumulative layout shift" in title:
        return _performance_wording(
            "Page layout may move while loading",
            "Content that shifts after it appears can make the site feel unstable and can cause visitors to click the wrong item.",
            "Reserve space for images, ads, embeds, and late-loading page elements.",
            finding,
        )
    if "uses optimized images" in title or "image" in title:
        return _performance_wording(
            "Images can be optimized",
            "Large or inefficient images can make pages feel slower than necessary, especially for mobile visitors.",
            "Compress oversized images and use modern image formats where practical.",
            finding,
        )
    if "meta description" in title:
        return {
            "title": "Search result summary needs attention",
            "explanation": "Search engines often use the page description as the preview text shown to potential customers. " + technical,
            "business_impact": "A clearer search preview can improve click-through from people already looking for the business.",
            "recommended_fix": "Write a concise page description that explains the business and the primary service or offer.",
        }
    if "document title" in title:
        return {
            "title": "Page title needs attention",
            "explanation": "The page title is one of the first signals visitors and search engines see. " + technical,
            "business_impact": "A clear title helps customers understand the page and supports search visibility.",
            "recommended_fix": "Use a specific title that includes the business name and the main service or location.",
        }
    if title.startswith("lighthouse performance score"):
        return _category_score_wording("Website speed needs attention", "Performance", finding)
    if title.startswith("lighthouse accessibility score"):
        return _category_score_wording("Website usability can be improved", "Accessibility", finding)
    if title.startswith("lighthouse seo score"):
        return _category_score_wording("Search visibility signals can be improved", "SEO", finding)
    if title.startswith("lighthouse best practices score"):
        return _category_score_wording("Browser quality checks need attention", "Best Practices", finding)
    return {
        "title": _category_title(finding),
        "explanation": f"{finding.description} {technical}",
        "business_impact": _business_impact(finding.category, finding.impact),
        "recommended_fix": _next_step(finding.category, finding.recommendation),
    }


def _opportunity_wording(opportunity: Opportunity) -> dict[str, str]:
    title = _finding_wording(
        Finding(
            scanner="response_builder",
            category=opportunity.category,
            title=opportunity.issue,
            description=opportunity.issue,
            severity=opportunity.severity,
            recommendation=opportunity.recommended_fix,
            impact=opportunity.business_impact,
        )
    )
    return {
        "title": title["recommended_fix"],
        "business_impact": title["business_impact"],
    }


def _security_header_wording(title: str, explanation: str, fix: str, technical: str) -> dict[str, str]:
    return {
        "title": title,
        "explanation": f"{explanation} {technical}",
        "business_impact": "This improves customer trust and closes a preventable browser-security gap.",
        "recommended_fix": fix,
    }


def _performance_wording(title: str, explanation: str, fix: str, finding: Finding) -> dict[str, str]:
    technical = _technical_detail(finding.title)
    return {
        "title": title,
        "explanation": f"{explanation} This can make the website feel slow and may reduce conversions and search performance. {technical}",
        "business_impact": "A faster, more responsive page helps visitors stay engaged and makes the business look more professional.",
        "recommended_fix": fix,
    }


def _category_score_wording(title: str, label: str, finding: Finding) -> dict[str, str]:
    score = finding.evidence.get("score")
    score_text = f" The measured score was {score}." if score is not None else ""
    return {
        "title": title,
        "explanation": f"The {label} category came in below the recommended range.{score_text} Technical detail: {finding.title}.",
        "business_impact": _business_impact(finding.category, finding.impact),
        "recommended_fix": _next_step(finding.category, finding.recommendation),
    }


def _category_title(finding: Finding) -> str:
    titles = {
        Category.SECURITY: "Website security configuration can be improved",
        Category.PERFORMANCE: "Website speed can be improved",
        Category.SEO: "Search visibility can be improved",
        Category.INFRASTRUCTURE: "Website infrastructure can be improved",
        Category.ACCESSIBILITY: "Website usability can be improved",
        Category.BEST_PRACTICES: "Browser quality checks need attention",
    }
    return titles.get(finding.category, finding.title)


def _business_impact(category: Category, fallback: str) -> str:
    impacts = {
        Category.SECURITY: "Improving this reduces preventable security risk and helps the site feel more trustworthy.",
        Category.PERFORMANCE: "Improving this can make the site feel faster and reduce visitor drop-off.",
        Category.SEO: "Improving this helps search engines and customers understand the page more clearly.",
        Category.INFRASTRUCTURE: "Improving this can increase reliability, resilience, and maintainability.",
        Category.ACCESSIBILITY: "Improving this makes the site easier for more visitors to use.",
        Category.BEST_PRACTICES: "Improving this helps the site behave more consistently in modern browsers.",
    }
    return impacts.get(category, fallback)


def _next_step(category: Category, fallback: str) -> str:
    steps = {
        Category.SECURITY: "Review the affected browser security setting and apply the recommended header or policy change.",
        Category.PERFORMANCE: "Review the affected page-speed item and prioritize the largest visible delays first.",
        Category.SEO: "Update the page metadata so search engines and customers get a clearer preview.",
        Category.INFRASTRUCTURE: "Review the hosting, DNS, or delivery configuration and apply the smallest reliable improvement.",
        Category.ACCESSIBILITY: "Review the affected usability item and adjust the page so more visitors can use it comfortably.",
        Category.BEST_PRACTICES: "Review the browser quality warning and update the affected implementation.",
    }
    return steps.get(category, fallback)


def _technical_detail(value: str) -> str:
    return f"Technical detail: {value}."


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


def _report_metadata(report: AuditReport) -> ReportMetadata:
    duration_ms = int(report.elapsed_ms)
    return ReportMetadata(
        completed_at=_completed_at(report),
        scan_duration_ms=duration_ms,
        scan_duration_seconds=round(duration_ms / 1000, 1),
        checks_completed=_checks_completed(report),
    )


def _completed_at(report: AuditReport) -> str | None:
    value = (report.metadata or {}).get("scan_finished_at")
    return str(value) if value else report.scanned_at.isoformat()


def _checks_completed(report: AuditReport) -> list[str]:
    scanner_labels = {
        "dns": "DNS",
        "ssl": "HTTPS",
        "security_headers": "Security Headers",
        "lighthouse": "Website Performance",
    }
    checks: list[str] = []
    for result in report.scanner_results:
        label = scanner_labels.get(result.scanner)
        if label and result.ok:
            checks.append(label)

    technology = (report.metadata or {}).get("technology_profile")
    if technology:
        checks.append("Technology Detection")

    return checks
