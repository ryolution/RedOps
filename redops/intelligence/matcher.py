"""Exact evidence correlation, without exploit or module selection."""

from redops.core.domain import Finding, Host
from redops.intelligence.cve import Catalog, canonical_cpe


def correlate(hosts: tuple[Host, ...], catalog: Catalog) -> tuple[list[Finding], dict[str, int]]:
    index = {}
    for record in catalog.records:
        for cpe in record.cpes:
            index.setdefault(cpe, []).append(record)
    findings = []
    coverage = {
        "services_total": 0,
        "services_with_supported_cpe": 0,
        "services_with_candidates": 0,
    }
    for host in hosts:
        for service in host.services:
            coverage["services_total"] += 1
            cpes = {value for raw in service.cpes if (value := canonical_cpe(raw)) is not None}
            coverage["services_with_supported_cpe"] += bool(cpes)
            matches = {}
            for cpe in sorted(cpes):
                for record in index.get(cpe, []):
                    if record.identifier not in matches:
                        matches[record.identifier] = (record, [])
                    matches[record.identifier][1].append(cpe)
            coverage["services_with_candidates"] += bool(matches)
            for record, matched_cpes in matches.values():
                findings.append(
                    Finding(
                        host=host.ip,
                        port=service.port.number,
                        protocol=service.port.protocol,
                        vulnerability_id=record.identifier,
                        cvss=record.cvss,
                        description=record.description,
                        remediation=record.remediation,
                        source=record.source,
                        matched_cpes=tuple(matched_cpes),
                    )
                )
    return sorted(
        findings,
        key=lambda item: (
            -(item.cvss if item.cvss is not None else -1),
            item.host,
            item.port,
            item.vulnerability_id,
        ),
    ), coverage
