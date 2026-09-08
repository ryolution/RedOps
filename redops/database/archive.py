"""Portable, bounded JSON backups of RedOps tables; no SQL or executable serialization."""

import hashlib
import hmac
import json
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, Float, Integer, String, func, select
from sqlalchemy.engine import Connection

from redops.core.errors import InputError
from redops.core.io import atomic_write, read_bounded
from redops.database.models import Base, SchemaVersion
from redops.database.schema import CURRENT_SCHEMA, HISTORY_INDEX, schema_version

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_ROWS = 100000
FORMAT = "redops-database-backup"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def export_archive(connection: Connection, path: Path) -> dict[str, Any]:
    """Caller holds a consistent database transaction for the entire export."""
    version = schema_version(connection)
    tables: dict[str, list[dict[str, Any]]] = {}
    size, count = 0, 0
    for table in Base.metadata.sorted_tables:
        tables[table.name] = []
        for mapping in connection.execute(select(table).order_by(*table.primary_key)).mappings():
            row = dict(mapping)
            size += len(canonical(row))
            count += 1
            if size > MAX_ARCHIVE_BYTES or count > MAX_ARCHIVE_ROWS:
                raise InputError(
                    "Backup exceeds the 64 MiB or 100000-row limit; use native database tools."
                )
            tables[table.name].append(row)
    try:
        _validate_rows(tables)
    except (ValueError, TypeError, KeyError, OverflowError) as exc:
        raise InputError(
            "Database rows exceed portable archive constraints; use native database backup tools."
        ) from exc
    payload = {
        "format": FORMAT,
        "archive_version": 1,
        "schema_version": version,
        "created_at": datetime.now(UTC).isoformat(),
        "source_backend": connection.dialect.name,
        "tables": tables,
    }
    digest = hashlib.sha256(canonical(payload)).hexdigest()
    content = canonical({"payload": payload, "sha256": digest}) + b"\n"
    if len(content) > MAX_ARCHIVE_BYTES:
        raise InputError("Backup exceeds the 64 MiB limit; use native database tools.")
    atomic_write(path, content, overwrite=False)
    return {
        "backup": str(path),
        "sha256": digest,
        "rows": count,
        "assessments": len(tables["assessments"]),
        "schema_version": version,
    }


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _validate_rows(tables: Any) -> None:
    if not isinstance(tables, dict) or set(tables) != set(Base.metadata.tables):
        raise ValueError
    count = 0
    for table in Base.metadata.sorted_tables:
        rows = tables[table.name]
        if not isinstance(rows, list):
            raise ValueError
        count += len(rows)
        if count > MAX_ARCHIVE_ROWS:
            raise ValueError
        for row in rows:
            if not isinstance(row, dict) or set(row) != set(table.columns.keys()):
                raise ValueError
            for column in table.columns:
                value = row[column.name]
                if value is None and column.nullable:
                    continue
                if isinstance(column.type, Integer):
                    valid = type(value) is int and 0 < value <= 2147483647
                elif isinstance(column.type, Float):
                    valid = type(value) in {float, int} and math.isfinite(value)
                elif isinstance(column.type, String):
                    valid = (
                        isinstance(value, str)
                        and "\x00" not in value
                        and (column.type.length is None or len(value) <= column.type.length)
                    )
                elif isinstance(column.type, JSON):
                    valid = isinstance(value, (dict, list))
                else:
                    valid = False
                if not valid:
                    raise ValueError
    for row in tables["assessments"]:
        document = row["document"]
        if not isinstance(document, dict) or any(
            document.get(key) != row[key] for key in ("id", "created_at")
        ):
            raise ValueError
        if not isinstance(document.get("scope"), dict) or any(
            document["scope"].get(key) != row[key] for key in ("operator", "engagement")
        ):
            raise ValueError


def load_archive(path: Path) -> dict[str, Any]:
    """Verify structure, types, limits, and corruption checksum before opening the target DB."""
    try:
        document = json.loads(
            read_bounded(path, MAX_ARCHIVE_BYTES), object_pairs_hook=_unique_object
        )
        if not isinstance(document, dict) or set(document) != {"payload", "sha256"}:
            raise ValueError
        payload = document["payload"]
        if not isinstance(payload, dict) or set(payload) != {
            "format",
            "archive_version",
            "schema_version",
            "created_at",
            "source_backend",
            "tables",
        }:
            raise ValueError
        if (
            payload["format"] != FORMAT
            or type(payload["archive_version"]) is not int
            or payload["archive_version"] != 1
            or type(payload["schema_version"]) is not int
            or payload["schema_version"] not in {1, CURRENT_SCHEMA}
            or payload["source_backend"] not in {"sqlite", "postgresql"}
        ):
            raise ValueError
        if datetime.fromisoformat(payload["created_at"]).tzinfo is None:
            raise ValueError
        expected = hashlib.sha256(canonical(payload)).hexdigest()
        if not isinstance(document["sha256"], str) or not hmac.compare_digest(
            document["sha256"], expected
        ):
            raise ValueError
        _validate_rows(payload["tables"])
        if payload["tables"]["schema_version"] != [{"id": 1, "version": payload["schema_version"]}]:
            raise ValueError
        return payload
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
        raise InputError(
            "Invalid database backup: check format, checksum, schema, and row values."
        ) from exc


def restore_rows(connection: Connection, payload: dict[str, Any]) -> int:
    """Restore into empty RedOps tables under a writer lock and a single transaction."""
    schema_version(connection)
    for table in Base.metadata.sorted_tables:
        if table.name != "schema_version" and connection.scalar(
            select(func.count()).select_from(table)
        ):
            raise InputError(
                "Restore requires an empty RedOps database; existing data is never replaced."
            )
    for table in Base.metadata.sorted_tables:
        rows = payload["tables"][table.name]
        if table.name != "schema_version":
            for start in range(0, len(rows), 500):
                connection.execute(table.insert(), rows[start : start + 500])
    HISTORY_INDEX.create(connection, checkfirst=True)
    connection.execute(
        SchemaVersion.__table__.update().where(SchemaVersion.id == 1).values(version=CURRENT_SCHEMA)
    )
    schema_version(connection)
    if connection.dialect.name == "postgresql":
        for table in Base.metadata.sorted_tables:
            if isinstance(table.c.id.type, Integer):
                sequence = connection.scalar(select(func.pg_get_serial_sequence(table.name, "id")))
                if sequence:
                    maximum = connection.scalar(select(func.max(table.c.id)))
                    connection.execute(
                        select(func.setval(sequence, maximum or 1, maximum is not None))
                    )
    return len(payload["tables"]["assessments"])
