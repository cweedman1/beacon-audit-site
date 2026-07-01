from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import Lock


class RateLimitExceeded(ValueError):
    pass


@dataclass
class InMemoryRateLimiter:
    limit: int = field(default_factory=lambda: int(os.environ.get("PUBLIC_RATE_LIMIT_PER_MINUTE", "10")))
    window_seconds: int = 60

    def __post_init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str) -> None:
        if self.limit <= 0:
            return
        now = time.monotonic()
        with self._lock:
            events = self._events[key]
            while events and now - events[0] > self.window_seconds:
                events.popleft()
            if len(events) >= self.limit:
                raise RateLimitExceeded("Too many scan requests. Please try again later.")
            events.append(now)

