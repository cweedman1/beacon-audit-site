from __future__ import annotations

import hashlib
import json
import socket
from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any
from urllib.parse import urlparse


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("URL is required")
    parsed = urlparse(raw_url)
    if not parsed.scheme:
        raw_url = f"https://{raw_url}"
        parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs can be scanned")
    if not parsed.netloc:
        raise ValueError("URL host is required")
    return raw_url.rstrip("/")


def hostname_for(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    host = parsed.hostname
    if not host:
        raise ValueError("URL host is required")
    return host


def stable_scan_id(url: str) -> str:
    digest = hashlib.sha256(f"{normalize_url(url)}".encode("utf-8")).hexdigest()
    return digest[:16]


def resolve_host(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None


def json_default(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime | date):
        return value.isoformat()
    return str(value)


def to_json(data: Any, *, indent: int = 2) -> str:
    return json.dumps(data, default=json_default, indent=indent, sort_keys=True)


def clamp_score(value: float) -> int:
    return max(0, min(100, round(value)))
