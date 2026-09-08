"""Explicit schema compatibility checks and consistent maintenance transactions."""

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import inspect, select
from sqlalchemy.engine import Connection, Engine

from redops.core.errors import RedOpsError
from redops.database.models import Assessment, Base, SchemaVersion

CURRENT_SCHEMA = 2
HISTORY_INDEX = next(
    index
    for index in Assessment.__table__.indexes
    if index.name == "ix_assessments_engagement_history"
)


@contextmanager
def transaction(engine: Engine, *, write: bool = False) -> Iterator[Connection]:
    """Use an actual SQLite snapshot, including on drivers with legacy transaction mode."""
    with engine.connect() as connection:
        if engine.dialect.name == "postgresql" and not write:
            connection = connection.execution_options(isolation_level="REPEATABLE READ")
        with connection.begin():
            if engine.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE" if write else "BEGIN")
            else:
                connection.exec_driver_sql("SET LOCAL lock_timeout = '5s'")
                connection.exec_driver_sql("SET LOCAL statement_timeout = '30s'")
                if not write:
                    connection.exec_driver_sql("SET TRANSACTION READ ONLY")
            yield connection


def lock_tables(connection: Connection) -> None:
    """Serialize maintenance with assessment writes before reading affected rows."""
    if connection.dialect.name == "postgresql":
        # Static names only. SQLite's BEGIN IMMEDIATE already holds the writer lock.
        connection.exec_driver_sql(
            "LOCK TABLE assessments, hosts, services, vulnerabilities, actions, schema_version "
            "IN SHARE ROW EXCLUSIVE MODE"
        )


def schema_version(connection: Connection) -> int:
    inspector = inspect(connection)
    if not set(Base.metadata.tables).issubset(inspector.get_table_names()):
        raise RedOpsError(
            "Database schema is missing or incompatible; an explicit migration is required."
        )
    for table in Base.metadata.sorted_tables:
        actual = {column["name"] for column in inspector.get_columns(table.name)}
        if actual != set(table.columns.keys()):
            raise RedOpsError("Database columns are incompatible with this installation.")
    rows = connection.execute(select(SchemaVersion.id, SchemaVersion.version)).all()
    if len(rows) != 1 or rows[0].id != 1 or rows[0].version not in {1, CURRENT_SCHEMA}:
        raise RedOpsError(
            "Database schema version is incompatible; an explicit migration is required."
        )
    version = rows[0].version
    if version == CURRENT_SCHEMA:
        indexes = inspector.get_indexes("assessments")
        if not any(
            index["name"] == HISTORY_INDEX.name
            and index["column_names"] == ["engagement", "created_at", "id"]
            for index in indexes
        ):
            raise RedOpsError("The database history index is missing or incompatible.")
    return version
