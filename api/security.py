from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse


class PublicAPISecurityError(ValueError):
    pass


@dataclass(frozen=True)
class RedirectValidation:
    final_url: str
    redirects: list[str]


BLOCKED_HOSTS = {"localhost", "metadata.google.internal"}
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
}


def validate_public_target(url: str, *, max_redirects: int = 5) -> RedirectValidation:
    host = _host_for_url(url)
    validate_public_host(host)
    validate_resolved_host(host)
    return validate_redirect_chain(url, max_redirects=max_redirects)


def validate_public_host(hostname: str) -> None:
    normalized = hostname.strip().lower().rstrip(".")
    if not normalized:
        raise PublicAPISecurityError("URL host is required")
    if normalized in BLOCKED_HOSTS or normalized.endswith(".localhost") or normalized.endswith(".local"):
        raise PublicAPISecurityError("Local or internal hostnames cannot be scanned")
    try:
        address = ipaddress.ip_address(normalized.strip("[]"))
    except ValueError:
        return
    validate_public_ip(address)


def validate_resolved_host(hostname: str) -> list[str]:
    try:
        records = socket.getaddrinfo(hostname, None)
    except OSError as exc:
        raise PublicAPISecurityError(f"Hostname could not be resolved: {hostname}") from exc

    addresses = sorted({record[4][0] for record in records})
    if not addresses:
        raise PublicAPISecurityError(f"Hostname could not be resolved: {hostname}")
    for address in addresses:
        validate_public_ip(ipaddress.ip_address(address))
    return addresses


def validate_public_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if address in METADATA_IPS:
        raise PublicAPISecurityError("Cloud metadata endpoints cannot be scanned")
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise PublicAPISecurityError("Private or internal network targets cannot be scanned")


def validate_redirect_chain(url: str, *, max_redirects: int = 5) -> RedirectValidation:
    current = url
    redirects: list[str] = []
    opener = urllib.request.build_opener(_NoRedirectHandler)
    for _ in range(max_redirects + 1):
        request = urllib.request.Request(current, method="HEAD", headers={"User-Agent": "BeaconAuditPublic/1.0"})
        try:
            with opener.open(request, timeout=5) as response:
                final_url = response.geturl()
                host = _host_for_url(final_url)
                validate_public_host(host)
                validate_resolved_host(host)
                return RedirectValidation(final_url=final_url, redirects=redirects)
        except urllib.error.HTTPError as exc:
            if exc.code not in {301, 302, 303, 307, 308}:
                final_url = exc.geturl()
                host = _host_for_url(final_url)
                validate_public_host(host)
                validate_resolved_host(host)
                return RedirectValidation(final_url=final_url, redirects=redirects)
            location = exc.headers.get("Location")
            if not location:
                raise PublicAPISecurityError("Redirect response did not include a Location header") from exc
            current = urllib.request.urljoin(current, location)
            host = _host_for_url(current)
            validate_public_host(host)
            validate_resolved_host(host)
            redirects.append(current)
        except urllib.error.URLError as exc:
            raise PublicAPISecurityError(f"Website validation request failed: {exc.reason}") from exc
    raise PublicAPISecurityError("Too many redirects")


def _host_for_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise PublicAPISecurityError("Only http and https URLs can be scanned")
    if parsed.username or parsed.password:
        raise PublicAPISecurityError("URLs with embedded credentials cannot be scanned")
    if not parsed.hostname:
        raise PublicAPISecurityError("URL host is required")
    return parsed.hostname


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None
