"""A bounded offline assessment from imported observations to stored evidence."""

import hashlib
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

from redops.core.audit import AuditLog
from redops.core.config import Settings
from redops.core.domain import severity
from redops.core.errors import RedOpsError
from redops.core.io import read_bounded, require_distinct_paths
from redops.core.scope import load_scope
from redops.database.repository import Repository
from redops.intelligence.cve import load_catalog
from redops.intelligence.matcher import correlate
from redops.recon.parser import parse_nmap


def run_assessment(
    settings: Settings,
    scope_path: Path,
    xml_path: Path,
    catalog_path: Path,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    require_distinct_paths([*settings.storage_paths(), scope_path, xml_path, catalog_path])
    started = perf_counter()
    audit = AuditLog(settings.audit_path)
    assessment_id = str(uuid.uuid4())
    operator = "unknown"
    committed = False
    audit.record("assessment", "started", assessment_id=assessment_id, dry_run=dry_run)
    try:
        scope = load_scope(scope_path)
        operator = scope.operator
        xml = read_bounded(xml_path)
        hosts = parse_nmap(xml)
        scope.validate(hosts)
        catalog_bytes = read_bounded(catalog_path)
        catalog = load_catalog(catalog_bytes)
        findings, coverage = correlate(hosts, catalog)
        warnings = [
            "CPE/banner matches are candidates requiring review, not confirmed vulnerabilities.",
            "No match does not establish that a service is secure; catalog coverage is limited.",
        ]
        if catalog.kind == "synthetic":
            warnings.append("Synthetic demonstration evidence; these are not real CVE findings.")
        missing = coverage["services_total"] - coverage["services_with_supported_cpe"]
        if missing:
            warnings.append(f"{missing} service(s) lack a supported exact, versioned CPE.")
        document = {
            "schema_version": 1,
            "id": assessment_id,
            "created_at": datetime.now(UTC).isoformat(),
            "status": "preview" if dry_run else "completed",
            "scope": scope.snapshot(),
            "provenance": {
                "nmap_sha256": hashlib.sha256(xml).hexdigest(),
                "catalog_sha256": hashlib.sha256(catalog_bytes).hexdigest(),
                "catalog_kind": catalog.kind,
                "catalog_updated_at": catalog.updated_at,
            },
            "hosts": [asdict(host) for host in hosts],
            "findings": [
                {**asdict(finding), "severity": severity(finding.cvss)} for finding in findings
            ],
            "coverage": coverage,
            "warnings": warnings,
            "processing_seconds": round(perf_counter() - started, 6),
        }
        # Recheck expiry after parsing/correlation and before opening a database.
        scope.validate(hosts)
        if not dry_run:
            repository = Repository(settings.database_url, create=True)
            try:
                repository.initialize()
                repository.save(document)
                committed = True
            finally:
                repository.close()
        audit.record(
            "assessment",
            "preview" if dry_run else "completed",
            operator=operator,
            assessment_id=assessment_id,
            hosts=len(hosts),
            findings=len(findings),
        )
        return document
    except Exception as exc:
        if committed:
            raise RedOpsError(
                f"Assessment {assessment_id} was committed, but the final audit append failed."
            ) from exc
        try:
            audit.record(
                "assessment",
                "failed",
                operator=operator,
                assessment_id=assessment_id,
                error_type=type(exc).__name__,
            )
        except OSError:
            raise RedOpsError(
                "Assessment failed and the audit event could not be written."
            ) from exc
        raise
