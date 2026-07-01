from __future__ import annotations

import urllib.error
import urllib.request

from api.models import Category, Finding, ScannerResult, ScannerStatus, Severity
from api.scanners.base import Scanner
from api.utils import hostname_for


class HostingScanner(Scanner):
    name = "hosting"
    timeout_seconds = 10

    def scan(self, target_url: str) -> ScannerResult:
        hostname = hostname_for(target_url)
        raw: dict[str, object] = {"hostname": hostname, "detected": []}
        findings: list[Finding] = []
        body = ""
        headers: dict[str, str] = {}

        request = urllib.request.Request(target_url, headers={"User-Agent": "BeaconAudit/0.1"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
                body = response.read(200_000).decode("utf-8", "ignore").lower()
        except urllib.error.HTTPError as exc:
            headers = {key.lower(): value for key, value in exc.headers.items()}
            body = exc.read(200_000).decode("utf-8", "ignore").lower()
        except OSError as exc:
            findings.append(
                Finding(
                    scanner=self.name,
                    category=Category.INFRASTRUCTURE,
                    title="Hosting detection failed",
                    description="Beacon could not fetch the page for hosting detection.",
                    severity=Severity.MEDIUM,
                    recommendation="Confirm the website allows normal web requests.",
                    impact="Some infrastructure recommendations were not executed because hosting detection did not verify the provider.",
                    evidence={"error": str(exc)},
                    weight=6,
                )
            )
            return ScannerResult(
                self.name,
                target_url,
                False,
                None,
                findings,
                {**raw, "error": str(exc)},
                status=ScannerStatus.FAILED,
                included_in_score=False,
                error=str(exc),
            )

        haystack = f"{hostname.lower()} {headers} {body}"
        detected = self._detect(haystack, headers)
        raw["headers"] = headers
        raw["detected"] = detected

        cdn_present = any(provider in detected for provider in {"cloudflare", "cloudfront", "fastly"})
        raw["cdn_present"] = cdn_present

        if not cdn_present:
            findings.append(
                Finding(
                    scanner=self.name,
                    category=Category.PERFORMANCE,
                    title="CDN not detected",
                    description="Beacon did not detect a common CDN in the response path.",
                    severity=Severity.MEDIUM,
                    recommendation="Put static assets and public pages behind a CDN when supported.",
                    impact="Visitors farther from the host may see slower page loads.",
                    evidence={"detected": detected},
                    weight=10,
                )
            )

        if "wordpress" in detected:
            findings.append(
                Finding(
                    scanner=self.name,
                    category=Category.INFRASTRUCTURE,
                    title="WordPress detected",
                    description="The site appears to run WordPress.",
                    severity=Severity.INFO,
                    recommendation="Keep WordPress core, themes, and plugins patched with backups enabled.",
                    impact="WordPress sites need routine maintenance to avoid avoidable security issues.",
                    evidence={"detected": detected},
                    weight=0,
                )
            )

        score = max(0, 100 - sum(finding.weight for finding in findings))
        return ScannerResult(
            self.name,
            target_url,
            True,
            score,
            findings,
            raw,
            status=ScannerStatus.OK,
            included_in_score=True,
            scores={"infrastructure": score},
        )

    def _detect(self, haystack: str, headers: dict[str, str]) -> list[str]:
        detected: set[str] = set()
        server = headers.get("server", "").lower()
        powered_by = headers.get("x-powered-by", "").lower()
        if "cloudflare" in server or "cf-ray" in headers:
            detected.add("cloudflare")
        if "cloudfront" in haystack or "x-amz-cf-id" in headers or "x-cache" in headers and "cloudfront" in headers.get("x-cache", "").lower():
            detected.add("cloudfront")
            detected.add("aws")
        if "amazon" in haystack or "aws" in haystack:
            detected.add("aws")
        if "azure" in haystack or "azurewebsites" in haystack:
            detected.add("azure")
        if "godaddy" in haystack:
            detected.add("godaddy")
        if "squarespace" in haystack:
            detected.add("squarespace")
        if "wix" in haystack or "x-seen-by" in headers:
            detected.add("wix")
        if "wp-content" in haystack or "wordpress" in haystack or "x-pingback" in headers:
            detected.add("wordpress")
        if "fastly" in server or "x-served-by" in headers:
            detected.add("fastly")
        if powered_by:
            detected.add(f"powered_by:{powered_by}")
        return sorted(detected)
