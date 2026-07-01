from __future__ import annotations

from urllib.parse import urlparse, urlunparse


class PublicAPIValidationError(ValueError):
    pass


def normalize_public_url(raw_url: str) -> str:
    value = raw_url.strip()
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
    if parsed.fragment:
        parsed = parsed._replace(fragment="")
    path = parsed.path or ""
    normalized = urlunparse(parsed)
    if path == "/" and not parsed.query:
        normalized = normalized.rstrip("/")
    return normalized

