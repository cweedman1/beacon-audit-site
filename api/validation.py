from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse


class PublicAPIValidationError(ValueError):
    pass


HOSTNAME_PATTERN = re.compile(r"^[a-z0-9.-]+$")


def normalize_public_url(raw_url: str) -> str:
    value = raw_url.strip().lower()
    if not value:
        raise PublicAPIValidationError("URL is required")
    parsed = urlparse(value)
    if not parsed.scheme:
        value = f"https://{value}"
        parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise PublicAPIValidationError("Only http and https URLs can be scanned")
    if parsed.username or parsed.password:
        raise PublicAPIValidationError("URLs with embedded credentials cannot be scanned")
    if not parsed.netloc or not parsed.hostname:
        raise PublicAPIValidationError("URL host is required")
    hostname = normalize_public_hostname(parsed.hostname)
    return urlunparse(("https", hostname, "", "", "", ""))


def normalize_public_hostname(raw_hostname: str) -> str:
    hostname = raw_hostname.strip().lower().rstrip(".")
    if hostname.startswith("www."):
        hostname = hostname[4:]
    validate_hostname_syntax(hostname)
    return hostname


def validate_hostname_syntax(hostname: str) -> None:
    if not hostname or len(hostname) > 253:
        raise PublicAPIValidationError("Website address is not valid")
    if "." not in hostname:
        raise PublicAPIValidationError("Website address must include a public domain")
    if not HOSTNAME_PATTERN.fullmatch(hostname):
        raise PublicAPIValidationError("Website address contains unsupported characters")
    if hostname.startswith(".") or hostname.endswith(".") or ".." in hostname:
        raise PublicAPIValidationError("Website address is not valid")
    try:
        ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        pass
    else:
        raise PublicAPIValidationError("Website address must be a public domain")

    labels = hostname.split(".")
    for label in labels:
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise PublicAPIValidationError("Website address is not valid")
    if len(labels[-1]) < 2 or labels[-1].isdigit():
        raise PublicAPIValidationError("Website address must include a public domain")
