"""Bounded opaque browser sessions. Restart or token rotation invalidates all sessions."""

import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class BrowserSession:
    csrf: str
    created: float
    authenticated: bool


class Sessions:
    def __init__(self, *, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self._sessions: dict[str, BrowserSession] = {}
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _expire(self) -> None:
        now = self.clock()
        self._sessions = {
            key: value for key, value in self._sessions.items() if now - value.created < 1800
        }
        self._failures = {
            key: [value for value in times if now - value < 60]
            for key, times in self._failures.items()
            if times and now - times[-1] < 60
        }

    def create(self, *, authenticated: bool = False) -> tuple[str, BrowserSession]:
        with self._lock:
            self._expire()
            if len(self._sessions) >= 128:
                oldest = min(self._sessions, key=lambda key: self._sessions[key].created)
                del self._sessions[oldest]
            identifier = secrets.token_urlsafe(32)
            session = BrowserSession(secrets.token_urlsafe(32), self.clock(), authenticated)
            self._sessions[identifier] = session
            return identifier, session

    def get(self, identifier: str) -> BrowserSession | None:
        with self._lock:
            self._expire()
            return self._sessions.get(identifier)

    def remove(self, identifier: str) -> None:
        with self._lock:
            self._sessions.pop(identifier, None)

    def throttled(self, address: str) -> bool:
        with self._lock:
            self._expire()
            return len(self._failures.get(address, [])) >= 5

    def failed(self, address: str) -> None:
        with self._lock:
            self._expire()
            if address not in self._failures and len(self._failures) >= 1024:
                del self._failures[next(iter(self._failures))]
            self._failures.setdefault(address, []).append(self.clock())
