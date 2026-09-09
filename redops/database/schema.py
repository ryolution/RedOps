"""Explicit schema compatibility checks and consistent maintenance transactions."""

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import inspect, select
from sqlalchemy.engine import Connection, Engine

from redops.core.errors import RedOpsError
from redops.database.models import Assessment, Base, FindingReview, SchemaVersion

CURRENT_SCHEMA = 3
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
        extra = (
            ", finding_reviews"
            if "finding_reviews" in inspect(connection).get_table_names()
            else ""
        )
        connection.exec_driver_sql(
            "LOCK TABLE assessments, hosts, services, vulnerabilities, actions, schema_version "
            + extra
            + " IN SHARE ROW EXCLUSIVE MODE"
        )


def tables_for_schema(version: int) -> list:
    return [
        table
        for table in Base.metadata.sorted_tables
        if version >= 3 or table.name != "finding_reviews"
    ]


def upgrade_schema(connection: Connection) -> None:
    HISTORY_INDEX.create(connection, checkfirst=True)
    FindingReview.__table__.create(connection, checkfirst=True)
    connection.execute(
        SchemaVersion.__table__.update().where(SchemaVersion.id == 1).values(version=CURRENT_SCHEMA)
    )
    schema_version(connection)


def schema_version(connection: Connection) -> int:
    inspector = inspect(connection)
    available = set(inspector.get_table_names())
    if "schema_version" not in available:
        raise RedOpsError(
            "Database schema is missing or incompatible; an explicit migration is required."
        )
    rows = connection.execute(select(SchemaVersion.id, SchemaVersion.version)).all()
    if len(rows) != 1 or rows[0].id != 1 or rows[0].version not in {1, 2, 3}:
        raise RedOpsError(
            "Database schema version is incompatible; an explicit migration is required."
        )
    version = rows[0].version
    if not {table.name for table in tables_for_schema(version)}.issubset(available):
        raise RedOpsError(
            "Database schema is missing required tables; an explicit migration is required."
        )
    for table in tables_for_schema(version):
        actual = {column["name"] for column in inspector.get_columns(table.name)}
        if actual != set(table.columns.keys()):
            raise RedOpsError("Database columns are incompatible with this installation.")
    if version >= 2:
        indexes = inspector.get_indexes("assessments")
        if not any(
            index["name"] == HISTORY_INDEX.name
            and index["column_names"] == ["engagement", "created_at", "id"]
            for index in indexes
        ):
            raise RedOpsError("The database history index is missing or incompatible.")
    return version
