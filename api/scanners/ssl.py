from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime

from api.models import Category, Finding, ScannerResult, ScannerStatus, Severity
from api.scanners.base import Scanner
from api.utils import hostname_for


class SslScanner(Scanner):
    name = "ssl"
    timeout_seconds = 10

    def scan(self, target_url: str) -> ScannerResult:
        hostname = hostname_for(target_url)
        findings: list[Finding] = []
        raw: dict[str, object] = {"hostname": hostname}

        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443), timeout=self.timeout_seconds) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls:
                    cert = tls.getpeercert()
                    raw["tls_version"] = tls.version()
                    raw["cipher"] = tls.cipher()
        except Exception as exc:
            finding = Finding(
                scanner=self.name,
                category=Category.SECURITY,
                title="SSL/TLS connection failed",
                description="Beacon could not establish a validated TLS connection.",
                severity=Severity.CRITICAL,
                recommendation="Install a valid certificate and confirm HTTPS is reachable on port 443.",
                impact="Visitors may see browser warnings or fail to connect securely.",
                evidence={"hostname": hostname, "error": str(exc)},
                weight=40,
            )
            return ScannerResult(
                self.name,
                target_url,
                False,
                None,
                [finding],
                {**raw, "error": str(exc)},
                status=ScannerStatus.FAILED,
                included_in_score=False,
                error=str(exc),
            )

        not_after = cert.get("notAfter")
        raw["certificate"] = cert
        if not_after:
            expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
            days_remaining = (expires_at - datetime.now(UTC)).days
            raw["expires_at"] = expires_at.isoformat()
            raw["days_remaining"] = days_remaining
            if days_remaining < 0:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=Category.SECURITY,
                        title="TLS certificate is expired",
                        description="The website certificate expiration date is in the past.",
                        severity=Severity.CRITICAL,
                        recommendation="Renew and deploy the TLS certificate immediately.",
                        impact="Visitors may be blocked by browser security warnings.",
                        evidence={"days_remaining": days_remaining},
                        weight=45,
                    )
                )
            elif days_remaining <= 14:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category=Category.SECURITY,
                        title="TLS certificate expires soon",
                        description="The website certificate expires within 14 days.",
                        severity=Severity.HIGH,
                        recommendation="Renew the TLS certificate before it expires.",
                        impact="Certificate expiration can abruptly break customer access.",
                        evidence={"days_remaining": days_remaining},
                        weight=18,
                    )
                )

        tls_version = raw.get("tls_version")
        if tls_version in {"TLSv1", "TLSv1.1"}:
            findings.append(
                Finding(
                    scanner=self.name,
                    category=Category.SECURITY,
                    title="Legacy TLS version negotiated",
                    description=f"The connection negotiated {tls_version}.",
                    severity=Severity.HIGH,
                    recommendation="Disable TLS 1.0 and TLS 1.1; support TLS 1.2 and TLS 1.3.",
                    impact="Legacy TLS support weakens transport security and compliance posture.",
                    evidence={"tls_version": tls_version},
                    weight=20,
                )
            )

        cipher = raw.get("cipher")
        if isinstance(cipher, tuple) and ("RC4" in cipher[0] or "3DES" in cipher[0]):
            findings.append(
                Finding(
                    scanner=self.name,
                    category=Category.SECURITY,
                    title="Weak TLS cipher negotiated",
                    description=f"The connection negotiated {cipher[0]}.",
                    severity=Severity.HIGH,
                    recommendation="Disable weak cipher suites in the hosting TLS configuration.",
                    impact="Weak ciphers reduce the confidentiality of customer traffic.",
                    evidence={"cipher": cipher},
                    weight=20,
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
            scores={"security": score},
        )
