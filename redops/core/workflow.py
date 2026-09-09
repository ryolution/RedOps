"""A bounded assessment with optional advisory context and no target connections."""

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
from redops.intelligence.advisories import AdvisoryProvider
from redops.intelligence.cve import catalog_warnings, load_catalog
from redops.intelligence.matcher import correlate
from redops.recon.json_inventory import parse_inventory_json
from redops.recon.source import InventoryParser, NmapXmlParser


def run_assessment(
    settings: Settings,
    scope_path: Path,
    xml_path: Path,
    catalog_path: Path,
    *,
    dry_run: bool = False,
    inventory_parser: InventoryParser | None = None,
    advisory_provider: AdvisoryProvider | None = None,
    input_format: str = "nmap-xml",
) -> dict[str, Any]:
    if dry_run and advisory_provider is not None:
        raise RedOpsError("Dry-run cannot invoke advisory providers; use a local evidence catalog.")
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
        source_metadata = {
            "input_format": input_format,
            "input_sha256": hashlib.sha256(xml).hexdigest(),
        }
        if input_format == "inventory-json":
            if inventory_parser is not None:
                raise RedOpsError("Custom parser injection cannot be combined with inventory-json.")
            imported = parse_inventory_json(xml)
            hosts = imported.hosts
            source_metadata.update(source=imported.source, collected_at=imported.collected_at)
        elif input_format == "nmap-xml":
            hosts = (inventory_parser or NmapXmlParser()).parse(xml)
            source_metadata["nmap_sha256"] = hashlib.sha256(xml).hexdigest()
        else:
            raise RedOpsError("Unsupported inventory input format.")
        if not hosts:
            raise RedOpsError("The inventory provider returned no hosts.")
        scope.validate(hosts)
        catalog_bytes = read_bounded(catalog_path)
        catalog = load_catalog(catalog_bytes)
        findings, coverage = correlate(hosts, catalog)
        advisories = []
        if advisory_provider is not None:
            if catalog.kind != "reviewed":
                raise RedOpsError(
                    "NVD enrichment requires a reviewed catalog with real CVE identifiers."
                )
            for identifier in sorted({finding.vulnerability_id for finding in findings}):
                advisory = advisory_provider.lookup(identifier)
                if advisory.provider != "nvd" or advisory.cve_id != identifier:
                    raise RedOpsError(
                        "Assessment enrichment requires matching NVD advisory records."
                    )
                advisories.append(advisory.to_dict())
        warnings = [
            "CPE/banner matches are candidates requiring review, not confirmed vulnerabilities.",
            "No match does not establish that a service is secure; catalog coverage is limited.",
        ]
        warnings.extend(catalog_warnings(catalog))
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
                **source_metadata,
                "catalog_sha256": hashlib.sha256(catalog_bytes).hexdigest(),
                "catalog_kind": catalog.kind,
                "catalog_updated_at": catalog.updated_at,
            },
            "hosts": [asdict(host) for host in hosts],
            "findings": [
                {**asdict(finding), "severity": severity(finding.cvss)} for finding in findings
            ],
            "coverage": coverage,
            "advisories": advisories,
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
