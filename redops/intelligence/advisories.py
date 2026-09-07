"""Advisory contracts and validation shared by live, cached, and mock providers."""

import math
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import urlsplit

from redops.core.errors import InputError, RedOpsError


class AdvisoryNotFound(RedOpsError):
    """The provider has no record for the requested identifier."""


def validate_cve(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,19}", value):
        raise InputError("Expected a CVE identifier such as CVE-2024-12345.")
    return value


def timestamp(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # NVD's API timestamps are UTC even when their JSON omits the suffix.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat()


@dataclass(frozen=True)
class Advisory:
    cve_id: str
    description: str
    cvss: float | None
    cvss_version: str | None
    vector: str | None
    status: str
    published: str
    last_modified: str
    references: tuple[str, ...]
    provider: str
    retrieved_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Advisory":
        try:
            validate_cve(data["cve_id"])
            for field in ("description", "status", "provider"):
                if not isinstance(data[field], str) or not 1 <= len(data[field]) <= 30000:
                    raise ValueError
            if data["provider"] not in {"nvd", "mock"}:
                raise ValueError
            score = data["cvss"]
            if score is not None and (
                type(score) not in {int, float} or not math.isfinite(score) or not 0 <= score <= 10
            ):
                raise ValueError
            if data["cvss_version"] not in {None, "2.0", "3.0", "3.1", "4.0"}:
                raise ValueError
            if data["vector"] is not None and (
                not isinstance(data["vector"], str) or len(data["vector"]) > 1000
            ):
                raise ValueError
            references = data["references"]
            if not isinstance(references, (list, tuple)) or len(references) > 500:
                raise ValueError
            for reference in references:
                parsed = urlsplit(reference)
                if (
                    parsed.scheme not in {"http", "https"}
                    or not parsed.hostname
                    or parsed.username
                    or parsed.password
                    or len(reference) > 8192
                ):
                    raise ValueError
            return cls(
                cve_id=data["cve_id"],
                description=data["description"],
                cvss=score,
                cvss_version=data["cvss_version"],
                vector=data["vector"],
                status=data["status"],
                published=timestamp(data["published"]),
                last_modified=timestamp(data["last_modified"]),
                references=tuple(references),
                provider=data["provider"],
                retrieved_at=timestamp(data["retrieved_at"]),
            )
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise InputError("Invalid advisory record.") from exc


class AdvisoryProvider(Protocol):
    def lookup(self, cve_id: str) -> Advisory:
        """Return a validated advisory or raise an explicit provider error."""


class MockAdvisoryProvider:
    """An explicit offline test provider; never masquerades as NVD evidence."""

    def lookup(self, cve_id: str) -> Advisory:
        if validate_cve(cve_id) != "CVE-2099-0001":
            raise AdvisoryNotFound("The mock provider only contains CVE-2099-0001.")
        return Advisory(
            cve_id=cve_id,
            description="Fictional advisory for offline integration testing.",
            cvss=5.0,
            cvss_version="3.1",
            vector=None,
            status="Synthetic",
            published="2099-01-01T00:00:00+00:00",
            last_modified="2099-01-01T00:00:00+00:00",
            references=("https://example.invalid/redops/mock-advisory",),
            provider="mock",
            retrieved_at=datetime.now(UTC).isoformat(),
        )
