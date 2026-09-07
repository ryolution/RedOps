"""Immutable input observations, independent of persistence and CLI."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Port:
    number: int
    protocol: str


@dataclass(frozen=True)
class Service:
    port: Port
    name: str
    product: str
    version: str
    cpes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Host:
    ip: str
    addresses: tuple[str, ...]
    hostname: str
    os: str
    services: tuple[Service, ...]


@dataclass(frozen=True)
class Finding:
    host: str
    port: int
    protocol: str
    vulnerability_id: str
    cvss: float | None
    description: str
    remediation: str
    source: str
    matched_cpes: tuple[str, ...]
    status: str = "candidate_needs_review"


def severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "none"
