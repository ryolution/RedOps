"""Health provider abstraction and an explicitly identified offline mock."""

from typing import Protocol


class HealthProvider(Protocol):
    def health(self) -> dict[str, str]:
        """Return health metadata or raise an integration error."""


class MockMetasploitClient:
    def health(self) -> dict[str, str]:
        return {"mode": "mock", "version": "synthetic-fixture", "api": "fixture"}
