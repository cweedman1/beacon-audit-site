from __future__ import annotations

import socket

from api.models import Category, Finding, ScannerResult, ScannerStatus, Severity
from api.scanners.base import Scanner
from api.utils import hostname_for


class DnsScanner(Scanner):
    name = "dns"
    timeout_seconds = 10

    def scan(self, target_url: str) -> ScannerResult:
        hostname = hostname_for(target_url)
        raw: dict[str, object] = {"hostname": hostname}
        findings: list[Finding] = []

        try:
            ipv4 = sorted({item[4][0] for item in socket.getaddrinfo(hostname, 80, socket.AF_INET)})
        except OSError as exc:
            ipv4 = []
            raw["a_error"] = str(exc)
        try:
            ipv6 = sorted({item[4][0] for item in socket.getaddrinfo(hostname, 80, socket.AF_INET6)})
        except OSError as exc:
            ipv6 = []
            raw["aaaa_error"] = str(exc)

        raw["a_records"] = ipv4
        raw["aaaa_records"] = ipv6
        raw["mx_records"] = []
        raw["spf"] = None
        raw["dkim"] = "not_checked_selector_unknown"
        raw["dmarc"] = None

        if not ipv4 and not ipv6:
            findings.append(
                Finding(
                    scanner=self.name,
                    category=Category.INFRASTRUCTURE,
                    title="No A or AAAA records resolved",
                    description="The website hostname did not resolve to an IPv4 or IPv6 address.",
                    severity=Severity.CRITICAL,
                    recommendation="Fix DNS records so the website hostname resolves reliably.",
                    impact="Customers may be unable to load the website.",
                    evidence={"hostname": hostname},
                    weight=35,
                )
            )
        if not ipv6:
            findings.append(
                Finding(
                    scanner=self.name,
                    category=Category.INFRASTRUCTURE,
                    title="No IPv6 record detected",
                    description="The website has no AAAA record.",
                    severity=Severity.LOW,
                    recommendation="Add IPv6 hosting support when the platform supports it.",
                    impact="Some modern networks may use less optimal routing.",
                    evidence={"hostname": hostname},
                    weight=3,
                )
            )

        txt_checks = self._query_txt_records(hostname)
        raw.update(txt_checks)

        if txt_checks.get("txt_verification") != "available":
            raw["email_authentication_status"] = "Verification Failed"
        elif not txt_checks.get("spf"):
            findings.append(
                Finding(
                    scanner=self.name,
                    category=Category.INFRASTRUCTURE,
                    title="SPF record not detected",
                    description="Beacon did not detect an SPF TXT record on the root domain.",
                    severity=Severity.MEDIUM,
                    recommendation="Publish an SPF record for authorized email senders.",
                    impact="Email from the business may be easier to spoof or more likely to land in spam.",
                    evidence={"hostname": hostname},
                    weight=8,
                )
            )
        if txt_checks.get("dmarc_verification") != "available":
            raw["dmarc_status"] = "Verification Failed"
        elif not txt_checks.get("dmarc"):
            findings.append(
                Finding(
                    scanner=self.name,
                    category=Category.INFRASTRUCTURE,
                    title="DMARC record not detected",
                    description="Beacon did not detect a DMARC TXT record.",
                    severity=Severity.MEDIUM,
                    recommendation="Publish a DMARC record and move toward quarantine or reject policy.",
                    impact="The domain has weaker protection against email impersonation.",
                    evidence={"hostname": hostname},
                    weight=8,
                )
            )

        if not ipv4 and not ipv6:
            return ScannerResult(
                self.name,
                target_url,
                False,
                None,
                findings,
                raw,
                status=ScannerStatus.FAILED,
                included_in_score=False,
                error="No A or AAAA records resolved",
            )

        warnings = []
        if raw.get("email_authentication_status") == "Verification Failed":
            warnings.append("Email TXT verification failed; SPF was not scored.")
        if raw.get("dmarc_status") == "Verification Failed":
            warnings.append("DMARC TXT verification failed; DMARC was not scored.")
        score = max(0, 100 - sum(finding.weight for finding in findings))
        status = ScannerStatus.WARNING if warnings else ScannerStatus.OK
        return ScannerResult(
            self.name,
            target_url,
            True,
            score,
            findings,
            raw,
            status=status,
            included_in_score=True,
            scores={"infrastructure": score},
            warnings=warnings,
        )

    def _query_txt_records(self, hostname: str) -> dict[str, object]:
        try:
            import dns.resolver  # type: ignore[import-not-found]
        except ImportError:
            return {
                "txt_lookup": "dnspython_not_installed",
                "txt_verification": "Verification Failed",
                "dmarc_verification": "Verification Failed",
                "spf": None,
                "dmarc": None,
                "mx_records": [],
            }

        result: dict[str, object] = {
            "spf": None,
            "dmarc": None,
            "mx_records": [],
            "txt_verification": "available",
            "dmarc_verification": "available",
        }
        try:
            txt_records = ["".join(part.decode("utf-8", "ignore") for part in record.strings) for record in dns.resolver.resolve(hostname, "TXT", lifetime=4)]
            result["spf"] = next((record for record in txt_records if record.lower().startswith("v=spf1")), None)
        except Exception as exc:  # DNS libraries expose resolver-specific exceptions.
            result["txt_error"] = str(exc)
            result["txt_verification"] = "Verification Failed"

        try:
            dmarc_records = ["".join(part.decode("utf-8", "ignore") for part in record.strings) for record in dns.resolver.resolve(f"_dmarc.{hostname}", "TXT", lifetime=4)]
            result["dmarc"] = next((record for record in dmarc_records if record.lower().startswith("v=dmarc1")), None)
        except Exception as exc:
            result["dmarc_error"] = str(exc)
            result["dmarc_verification"] = "Verification Failed"

        try:
            mx_records = [str(record.exchange).rstrip(".") for record in dns.resolver.resolve(hostname, "MX", lifetime=4)]
            result["mx_records"] = sorted(mx_records)
        except Exception as exc:
            result["mx_error"] = str(exc)

        return result
