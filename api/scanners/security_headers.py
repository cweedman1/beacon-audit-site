from __future__ import annotations

import urllib.error
import urllib.request

from api.models import Category, Finding, ScannerResult, ScannerStatus, Severity
from api.scanners.base import Scanner


REQUIRED_HEADERS = {
    "strict-transport-security": (
        "Missing HSTS",
        "Add Strict-Transport-Security with a long max-age once HTTPS is stable.",
        Severity.HIGH,
        15,
    ),
    "content-security-policy": (
        "Missing Content Security Policy",
        "Add a restrictive Content-Security-Policy to reduce script injection risk.",
        Severity.HIGH,
        14,
    ),
    "x-frame-options": (
        "Missing X-Frame-Options",
        "Add X-Frame-Options or frame-ancestors in CSP to prevent clickjacking.",
        Severity.MEDIUM,
        9,
    ),
    "referrer-policy": (
        "Missing Referrer-Policy",
        "Add Referrer-Policy to limit leakage of full URLs to third parties.",
        Severity.MEDIUM,
        7,
    ),
    "permissions-policy": (
        "Missing Permissions-Policy",
        "Add Permissions-Policy to disable browser features the site does not use.",
        Severity.LOW,
        4,
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options",
        "Add X-Content-Type-Options: nosniff.",
        Severity.MEDIUM,
        7,
    ),
}


class SecurityHeadersScanner(Scanner):
    name = "security_headers"
    timeout_seconds = 10

    def scan(self, target_url: str) -> ScannerResult:
        request = urllib.request.Request(
            target_url,
            method="GET",
            headers={"User-Agent": "BeaconAudit/0.1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
                status = response.status
        except urllib.error.HTTPError as exc:
            headers = {key.lower(): value for key, value in exc.headers.items()}
            status = exc.code
        except OSError as exc:
            finding = Finding(
                scanner=self.name,
                category=Category.SECURITY,
                title="Could not fetch security headers",
                description="Beacon could not retrieve the site response headers.",
                severity=Severity.HIGH,
                recommendation="Confirm the website is reachable and not blocking standard HTTP clients.",
                impact="Visitors and crawlers may be unable to reach the site reliably.",
                evidence={"error": str(exc)},
                weight=12,
            )
            return ScannerResult(
                self.name,
                target_url,
                False,
                None,
                [finding],
                {"error": str(exc)},
                status=ScannerStatus.FAILED,
                included_in_score=False,
                error=str(exc),
            )

        findings: list[Finding] = []
        for header, (title, recommendation, severity, weight) in REQUIRED_HEADERS.items():
            if header not in headers:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=Category.SECURITY,
                        title=title,
                        description=f"The `{header}` response header was not present.",
                        severity=severity,
                        recommendation=recommendation,
                        impact="Missing browser security controls increase preventable client-side risk.",
                        evidence={"header": header, "status_code": status},
                        weight=weight,
                    )
                )

        csp = headers.get("content-security-policy", "")
        if csp and "unsafe-inline" in csp:
            findings.append(
                Finding(
                    scanner=self.name,
                    category=Category.SECURITY,
                    title="CSP allows unsafe inline scripts",
                    description="The Content-Security-Policy includes unsafe-inline.",
                    severity=Severity.MEDIUM,
                    recommendation="Remove unsafe-inline by moving inline scripts to nonce or hash based policy.",
                    impact="A weak CSP reduces protection against cross-site scripting.",
                    evidence={"content-security-policy": csp},
                    weight=8,
                )
            )

        score = max(0, 100 - sum(finding.weight for finding in findings))
        return ScannerResult(
            self.name,
            target_url,
            True,
            score,
            findings,
            {"status_code": status, "headers": headers},
            status=ScannerStatus.OK,
            included_in_score=True,
            scores={"security": score},
        )
