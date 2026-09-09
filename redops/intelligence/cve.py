"""Validated local evidence catalog; never implies that a finding is confirmed."""

import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

from redops.core.errors import InputError


def canonical_cpe(value: str) -> str | None:
    """Accept simple URI/2.3 bindings only; decline escapes, wildcards in versions, ranges."""
    value = value.lower()
    if value.startswith("cpe:/"):
        fields = value[5:].split(":")
        if not 4 <= len(fields) <= 7:
            return None
        fields = [field or "*" for field in fields] + ["*"] * (11 - len(fields))
    elif value.startswith("cpe:2.3:"):
        fields = value[8:].split(":")
        if len(fields) != 11:
            return None
    else:
        return None
    if fields[0] not in {"a", "o", "h"}:
        return None
    if any(field in {"*", "-", ""} for field in fields[1:4]):
        return None
    if not all(field in {"*", "-"} or re.fullmatch(r"[a-z0-9_.-]+", field) for field in fields):
        return None
    return "cpe:2.3:" + ":".join(fields)


@dataclass(frozen=True)
class Evidence:
    identifier: str
    cpes: tuple[str, ...]
    cvss: float | None
    description: str
    remediation: str
    source: str


@dataclass(frozen=True)
class Catalog:
    kind: str
    updated_at: str
    records: tuple[Evidence, ...]


def catalog_warnings(catalog: Catalog, *, now: datetime | None = None) -> list[str]:
    age = ((now or datetime.now(UTC)) - datetime.fromisoformat(catalog.updated_at)).total_seconds()
    if age < 0:
        return ["Catalog update time is in the future; review its provenance."]
    if age > 30 * 86400:
        return ["Catalog is older than 30 days; review evidence freshness. Records were retained."]
    return []


def validate_catalog(content: bytes) -> dict:
    catalog = load_catalog(content)
    return {
        "status": "validated",
        "kind": catalog.kind,
        "updated_at": catalog.updated_at,
        "records": len(catalog.records),
        "supported_cpes": len({cpe for record in catalog.records for cpe in record.cpes}),
        "warnings": catalog_warnings(catalog),
        "matching_policy": "Exact reviewed CPE evidence; ambiguous identities remain unresolved.",
    }


def load_catalog(content: bytes) -> Catalog:
    try:
        data = json.loads(content)
        if (
            not isinstance(data, dict)
            or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1
        ):
            raise ValueError
        kind = data["kind"]
        if kind not in {"synthetic", "reviewed"}:
            raise ValueError
        updated_at = datetime.fromisoformat(data["updated_at"].replace("Z", "+00:00"))
        if updated_at.tzinfo is None:
            raise ValueError
        if not isinstance(data["records"], list) or len(data["records"]) > 10000:
            raise ValueError
        records = []
        seen: set[str] = set()
        for item in data["records"]:
            identifier = item["id"]
            pattern = r"DEMO-[A-Z0-9-]+" if kind == "synthetic" else r"CVE-\d{4}-\d{4,}"
            if (
                not isinstance(identifier, str)
                or len(identifier) > 100
                or not re.fullmatch(pattern, identifier)
                or identifier in seen
            ):
                raise ValueError
            seen.add(identifier)
            raw_cpes = item["cpes"]
            if not isinstance(raw_cpes, list) or not 1 <= len(raw_cpes) <= 100:
                raise ValueError
            cpes = []
            for value in raw_cpes:
                normalized = canonical_cpe(value) if isinstance(value, str) else None
                if normalized is None:
                    raise ValueError
                cpes.append(normalized)
            score = item["cvss"]
            if score is not None:
                if (
                    type(score) not in {int, float}
                    or not math.isfinite(score)
                    or not 0 <= score <= 10
                ):
                    raise ValueError
                score = float(score)
            for key in ("description", "remediation", "source"):
                if (
                    not isinstance(item[key], str)
                    or not item[key].strip()
                    or len(item[key]) > 10000
                ):
                    raise ValueError
            source = urlsplit(item["source"])
            if (
                source.scheme != "https"
                or not source.hostname
                or source.username
                or source.password
            ):
                raise ValueError
            records.append(
                Evidence(
                    identifier=identifier,
                    cpes=tuple(sorted(set(cpes))),
                    cvss=score,
                    description=item["description"],
                    remediation=item["remediation"],
                    source=item["source"],
                )
            )
        return Catalog(kind, updated_at.isoformat(), tuple(records))
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        raise InputError(
            "Invalid evidence catalog: check schema, identifiers, exact CPEs, and scores."
        ) from exc
