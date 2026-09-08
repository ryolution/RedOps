"""Audited backups, empty-database restores, explicit migration, and bounded retention."""

import getpass
import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, select

from redops.core.audit import AuditLog
from redops.core.config import Settings
from redops.core.errors import InputError, RedOpsError
from redops.core.io import require_distinct_paths
from redops.database.archive import export_archive, load_archive, restore_rows
from redops.database.models import (
    ActionRecord,
    Assessment,
    Base,
    HostRecord,
    SchemaVersion,
    ServiceRecord,
    VulnerabilityRecord,
)
from redops.database.repository import Repository
from redops.database.schema import (
    CURRENT_SCHEMA,
    HISTORY_INDEX,
    lock_tables,
    schema_version,
    transaction,
)

logger = logging.getLogger(__name__)


def _audited(
    settings: Settings,
    action: str,
    paths: list[Path],
    operation: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    require_distinct_paths([*settings.storage_paths(), *paths])
    audit, operator = AuditLog(settings.audit_path), getpass.getuser()
    audit.record(action, "started", operator=operator)
    committed = False
    try:
        result = operation()
        committed = result["status"] == "completed"
        audit.record(action, result["status"], operator=operator)
        logger.info("Database operation %s: %s", action, result["status"])
        return result
    except Exception as exc:
        if committed:
            raise RedOpsError(
                f"Database operation {action} completed, but its final audit append failed."
            ) from exc
        try:
            audit.record(action, "failed", operator=operator, error_type=type(exc).__name__)
        except OSError:
            raise RedOpsError(
                "Database operation failed and its audit event could not be written."
            ) from exc
        raise


@contextmanager
def _repository(settings: Settings, *, create: bool = False) -> Iterator[Repository]:
    repository = Repository(settings.database_url, create=create)
    try:
        yield repository
    finally:
        repository.close()


def backup_database(settings: Settings, output: Path) -> dict[str, Any]:
    def execute() -> dict[str, Any]:
        with _repository(settings) as repository, transaction(repository.engine) as connection:
            result = export_archive(connection, output)
        return {"status": "completed", **result}

    return _audited(settings, "database.backup", [output], execute)


def restore_database(settings: Settings, source: Path) -> dict[str, Any]:
    def execute() -> dict[str, Any]:
        payload = load_archive(source)
        with _repository(settings, create=True) as repository:
            repository.initialize()
            with transaction(repository.engine, write=True) as connection:
                lock_tables(connection)
                count = restore_rows(connection, payload)
        return {
            "status": "completed",
            "restored_assessments": count,
            "schema_version": CURRENT_SCHEMA,
        }

    return _audited(settings, "database.restore", [source], execute)


def database_status(settings: Settings) -> dict[str, Any]:
    def execute() -> dict[str, Any]:
        with _repository(settings) as repository, transaction(repository.engine) as connection:
            version = schema_version(connection)
            counts = {
                table.name: connection.scalar(select(func.count()).select_from(table))
                for table in Base.metadata.sorted_tables
            }
            return {
                "status": "checked",
                "backend": connection.dialect.name,
                "schema_version": version,
                "upgrade_available": version < CURRENT_SCHEMA,
                "rows": counts,
            }

    return _audited(settings, "database.status", [], execute)


def migrate_database(settings: Settings, backup: Path) -> dict[str, Any]:
    """Upgrade the engagement/history query index, preserving all observation records."""

    def execute() -> dict[str, Any]:
        with (
            _repository(settings) as repository,
            transaction(repository.engine, write=True) as connection,
        ):
            lock_tables(connection)
            previous = schema_version(connection)
            if previous == CURRENT_SCHEMA:
                return {"status": "unchanged", "schema_version": previous}
            archived = export_archive(connection, backup)
            HISTORY_INDEX.create(connection, checkfirst=True)
            connection.execute(
                SchemaVersion.__table__.update()
                .where(SchemaVersion.id == 1)
                .values(version=CURRENT_SCHEMA)
            )
            schema_version(connection)
        return {
            "status": "completed",
            "from_schema": previous,
            "schema_version": CURRENT_SCHEMA,
            "backup": archived,
        }

    return _audited(settings, "database.migrate", [backup], execute)


def _timestamp(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError
        return result.astimezone(UTC)
    except (ValueError, TypeError, AttributeError) as exc:
        raise InputError("Retention timestamps must be ISO 8601 with a timezone.") from exc


def prune_database(
    settings: Settings,
    *,
    engagement: str,
    before: str,
    keep_latest: int = 1,
    apply: bool = False,
    backup: Path | None = None,
) -> dict[str, Any]:
    """Keep the newest snapshots and preview by default; applying always backs up first."""

    def execute() -> dict[str, Any]:
        cutoff = _timestamp(before)
        if cutoff >= datetime.now(UTC):
            raise InputError("Retention cutoff must be in the past.")
        if not engagement.strip() or len(engagement) > 200 or not 1 <= keep_latest <= 10000:
            raise InputError(
                "Specify an engagement and keep between 1 and 10000 latest assessments."
            )
        if apply and backup is None:
            raise InputError("Applying retention requires --backup with a new archive path.")
        with (
            _repository(settings) as repository,
            transaction(repository.engine, write=apply) as connection,
        ):
            if apply:
                lock_tables(connection)
            schema_version(connection)
            rows = connection.execute(
                select(Assessment.id, Assessment.created_at)
                .where(Assessment.engagement == engagement)
                .limit(10001)
            ).all()
            if len(rows) > 10000:
                raise InputError("Retention supports at most 10000 assessments per engagement.")
            ordered = sorted(((_timestamp(row.created_at), row.id) for row in rows), reverse=True)
            candidates = [
                identifier for timestamp, identifier in ordered[keep_latest:] if timestamp < cutoff
            ]
            chosen = candidates[:1000]
            archived = None
            if apply and chosen:
                assert backup is not None
                archived = export_archive(connection, backup)
                host_ids = select(HostRecord.id).where(HostRecord.assessment_id.in_(chosen))
                service_ids = select(ServiceRecord.id).where(ServiceRecord.host_id.in_(host_ids))
                connection.execute(
                    delete(VulnerabilityRecord).where(
                        VulnerabilityRecord.service_id.in_(service_ids)
                    )
                )
                connection.execute(delete(ServiceRecord).where(ServiceRecord.host_id.in_(host_ids)))
                connection.execute(delete(HostRecord).where(HostRecord.assessment_id.in_(chosen)))
                connection.execute(
                    delete(ActionRecord).where(ActionRecord.assessment_id.in_(chosen))
                )
                connection.execute(delete(Assessment).where(Assessment.id.in_(chosen)))
        return {
            "status": "completed" if apply else "preview",
            "engagement": engagement,
            "before": cutoff.isoformat(),
            "keep_latest": keep_latest,
            "assessment_ids": chosen,
            "eligible": len(candidates),
            "deleted": len(chosen) if apply else 0,
            "backup": archived,
        }

    return _audited(settings, "database.prune", [backup] if backup is not None else [], execute)
