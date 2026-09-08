import copy
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event, inspect, select
from sqlalchemy.exc import IntegrityError

from redops.cli.main import main
from redops.core.audit import AuditLog
from redops.core.config import Settings
from redops.core.errors import InputError, RedOpsError
from redops.database import archive, maintenance
from redops.database.archive import canonical, load_archive
from redops.database.maintenance import (
    backup_database,
    database_status,
    migrate_database,
    prune_database,
    restore_database,
)
from redops.database.models import SchemaVersion
from redops.database.repository import Repository
from redops.database.schema import HISTORY_INDEX, transaction


@pytest.fixture
def populated(settings, preview):
    repository = Repository(settings.database_url, create=True)
    repository.initialize()
    documents = []
    try:
        for days, engagement in [
            (4, "retention-test"),
            (3, "retention-test"),
            (2, "retention-test"),
            (4, "another-engagement"),
        ]:
            document = copy.deepcopy(preview)
            document.update(
                id=str(uuid.uuid4()),
                created_at=(datetime.now(UTC) - timedelta(days=days)).isoformat(),
            )
            document["scope"]["engagement"] = engagement
            repository.save(document)
            documents.append(document)
    finally:
        repository.close()
    return documents


@pytest.fixture
def destination(tmp_path):
    return Settings(f"sqlite:///{tmp_path / 'restored.db'}", tmp_path / "restored-audit.jsonl")


def rewrite_archive(path, mutate):
    data = json.loads(path.read_bytes())
    mutate(data["payload"])
    data["sha256"] = hashlib.sha256(canonical(data["payload"])).hexdigest()
    path.write_bytes(canonical(data))


def test_portable_backup_restore_preserves_all_rows(settings, populated, destination, tmp_path):
    path = tmp_path / "backup.json"
    result = backup_database(settings, path)
    assert result["assessments"] == 4
    assert restore_database(destination, path)["restored_assessments"] == 4
    assert database_status(settings)["rows"] == database_status(destination)["rows"]
    repository = Repository(destination.database_url)
    try:
        for document in populated:
            assert repository.get(document["id"]) == json.loads(json.dumps(document))
        new = copy.deepcopy(populated[0])
        new["id"] = str(uuid.uuid4())
        repository.save(new)
        assert len(repository.inventory(new["id"])) == 12
    finally:
        repository.close()
    with pytest.raises(InputError, match="empty"):
        restore_database(destination, path)
    assert database_status(destination)["rows"]["assessments"] == 5


def test_backup_never_overwrites_or_aliases_database(settings, populated, tmp_path):
    path = tmp_path / "backup.json"
    backup_database(settings, path)
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        backup_database(settings, path)
    assert path.read_bytes() == original
    with pytest.raises(InputError, match="distinct"):
        backup_database(settings, settings.storage_paths()[1])


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.update(schema_version=999),
        lambda payload: payload["tables"].update(unexpected=[]),
        lambda payload: payload["tables"]["hosts"][0].update(id=True),
        lambda payload: payload["tables"]["hosts"][0].update(assessment_id="x" * 37),
        lambda payload: payload["tables"]["assessments"][0]["document"].update(id="different"),
    ],
)
def test_invalid_archive_rejected_before_target_creation(
    settings, populated, destination, tmp_path, mutation
):
    path = tmp_path / "backup.json"
    backup_database(settings, path)
    rewrite_archive(path, mutation)
    with pytest.raises(InputError, match="Invalid database backup"):
        restore_database(destination, path)
    assert not (tmp_path / "restored.db").exists()


def test_checksum_and_archive_limits(settings, populated, destination, tmp_path, monkeypatch):
    path = tmp_path / "backup.json"
    backup_database(settings, path)
    original = path.read_bytes()
    path.write_bytes(original.replace(b"retention-test", b"changed-name"))
    with pytest.raises(InputError, match="checksum"):
        restore_database(destination, path)
    path.write_bytes(original)
    monkeypatch.setattr(archive, "MAX_ARCHIVE_BYTES", 100)
    with pytest.raises(InputError, match="limit"):
        backup_database(settings, tmp_path / "limited.json")
    with pytest.raises(InputError):
        load_archive(path)
    assert not (tmp_path / "limited.json").exists()


def test_backup_refuses_nonportable_source_rows(settings, populated, tmp_path):
    from redops.database.models import HostRecord

    repository = Repository(settings.database_url)
    try:
        with repository.engine.begin() as connection:
            connection.execute(HostRecord.__table__.update().values(hostname="name\x00suffix"))
    finally:
        repository.close()
    path = tmp_path / "backup.json"
    with pytest.raises(InputError, match="portable archive constraints"):
        backup_database(settings, path)
    assert not path.exists()


def test_restore_rolls_back_partial_rows_on_constraint_failure(
    settings, populated, destination, tmp_path
):
    path = tmp_path / "backup.json"
    backup_database(settings, path)
    rewrite_archive(
        path, lambda payload: payload["tables"]["services"][0].update(host_id=2147483647)
    )
    with pytest.raises(IntegrityError):
        restore_database(destination, path)
    counts = database_status(destination)["rows"]
    assert all(count == 0 for table, count in counts.items() if table != "schema_version")


def test_retention_preview_and_apply_preserve_latest_and_other_engagement(
    settings, populated, tmp_path
):
    before = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    backup = tmp_path / "before-retention.json"
    result = prune_database(settings, engagement="retention-test", before=before, backup=backup)
    assert result["status"] == "preview"
    assert set(result["assessment_ids"]) == {doc["id"] for doc in populated[:2]}
    assert not backup.exists()
    assert database_status(settings)["rows"]["assessments"] == 4
    result = prune_database(
        settings, engagement="retention-test", before=before, apply=True, backup=backup
    )
    assert result["deleted"] == 2
    assert len(load_archive(backup)["tables"]["assessments"]) == 4
    counts = database_status(settings)["rows"]
    assert counts["assessments"] == counts["actions"] == 2
    assert counts["hosts"] == counts["services"] == 24
    assert counts["vulnerabilities"] == 16


@pytest.mark.parametrize(
    "kwargs",
    [
        {"before": "2000-01-01"},
        {"before": "2999-01-01T00:00:00Z"},
        {"keep_latest": 0},
        {"engagement": ""},
        {"apply": True},
    ],
)
def test_retention_rejects_unsafe_or_invalid_parameters(settings, populated, kwargs):
    arguments = {"engagement": "retention-test", "before": "2020-01-01T00:00:00Z", **kwargs}
    with pytest.raises(InputError):
        prune_database(settings, **arguments)
    assert database_status(settings)["rows"]["assessments"] == 4


def test_backup_failure_prevents_retention(settings, populated, tmp_path, monkeypatch):
    def fail(*args):
        raise OSError("full filesystem")

    monkeypatch.setattr(maintenance, "export_archive", fail)
    with pytest.raises(OSError):
        prune_database(
            settings,
            engagement="retention-test",
            before=datetime.now(UTC).isoformat(),
            apply=True,
            backup=tmp_path / "backup.json",
        )
    assert database_status(settings)["rows"]["assessments"] == 4


def test_failed_delete_rolls_back_every_table(settings, populated, tmp_path, monkeypatch):
    original = Repository.__init__

    def initialize(self, *args, **kwargs):
        original(self, *args, **kwargs)

        @event.listens_for(self.engine, "before_cursor_execute")
        def fail(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith("DELETE FROM assessments"):
                raise OSError("simulated failure after child deletion")

    counts = database_status(settings)["rows"]
    monkeypatch.setattr(Repository, "__init__", initialize)
    with pytest.raises(OSError):
        prune_database(
            settings,
            engagement="retention-test",
            before=datetime.now(UTC).isoformat(),
            apply=True,
            backup=tmp_path / "backup.json",
        )
    assert database_status(settings)["rows"] == counts


def downgrade_fixture(settings):
    repository = Repository(settings.database_url)
    try:
        with transaction(repository.engine, write=True) as connection:
            HISTORY_INDEX.drop(connection)
            connection.execute(SchemaVersion.__table__.update().values(version=1))
    finally:
        repository.close()


def test_explicit_migration_is_backed_up_and_preserves_records(settings, populated, tmp_path):
    downgrade_fixture(settings)
    repository = Repository(settings.database_url)
    try:
        assert repository.initialize() == 1
        assert len(repository.inventory()) == 12
    finally:
        repository.close()
    assert database_status(settings)["upgrade_available"] is True
    backup = tmp_path / "before-migration.json"
    result = migrate_database(settings, backup)
    assert result["from_schema"] == 1 and result["schema_version"] == 2
    assert load_archive(backup)["schema_version"] == 1
    assert database_status(settings)["rows"]["assessments"] == 4
    assert database_status(settings)["upgrade_available"] is False
    assert migrate_database(settings, backup)["status"] == "unchanged"


def test_migration_ddl_rolls_back_on_failure(settings, populated, tmp_path, monkeypatch):
    downgrade_fixture(settings)
    original = Repository.__init__

    def initialize(self, *args, **kwargs):
        original(self, *args, **kwargs)

        @event.listens_for(self.engine, "before_cursor_execute")
        def fail(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith("UPDATE schema_version"):
                raise OSError("migration interrupted")

    monkeypatch.setattr(Repository, "__init__", initialize)
    with pytest.raises(OSError):
        migrate_database(settings, tmp_path / "before-migration.json")
    repository = Repository(settings.database_url)
    try:
        with repository.engine.connect() as connection:
            assert connection.scalar(select(SchemaVersion.version)) == 1
            assert HISTORY_INDEX.name not in {
                item["name"] for item in inspect(connection).get_indexes("assessments")
            }
    finally:
        repository.close()


def test_backup_holds_consistent_snapshot_during_concurrent_write(
    settings, populated, tmp_path, monkeypatch
):
    writer = Repository(settings.database_url)
    with writer.engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA journal_mode=WAL")
    original, inserted = Repository.__init__, False

    def initialize(self, *args, **kwargs):
        original(self, *args, **kwargs)

        @event.listens_for(self.engine, "after_cursor_execute")
        def concurrent_insert(connection, cursor, statement, parameters, context, executemany):
            nonlocal inserted
            if statement.startswith("SELECT assessments.id") and not inserted:
                inserted = True
                document = copy.deepcopy(populated[0])
                document["id"] = str(uuid.uuid4())
                writer.save(document)

    monkeypatch.setattr(Repository, "__init__", initialize)
    try:
        path = tmp_path / "concurrent.json"
        backup_database(settings, path)
        tables = load_archive(path)["tables"]
        assert inserted
        assert len(tables["assessments"]) == 4
        assert len(tables["hosts"]) == 48
        assert len(tables["actions"]) == 4
        assert database_status(settings)["rows"]["assessments"] == 5
    finally:
        writer.close()


def test_completed_maintenance_audit_failure_is_explicit(
    settings, populated, tmp_path, monkeypatch
):
    original = AuditLog.record

    def fail(self, action, status, **kwargs):
        if status == "completed":
            raise OSError("audit failure")
        return original(self, action, status, **kwargs)

    monkeypatch.setattr(AuditLog, "record", fail)
    backup = tmp_path / "backup.json"
    with pytest.raises(RedOpsError, match="completed, but"):
        backup_database(settings, backup)
    assert load_archive(backup)["format"] == archive.FORMAT


def test_maintenance_cli(settings, populated, tmp_path, capsys):
    prefix = ["--database", settings.database_url, "--audit", str(settings.audit_path), "database"]
    assert main([*prefix, "status"]) == 0
    assert json.loads(capsys.readouterr().out)["schema_version"] == 2
    assert main([*prefix, "backup", "--output", str(tmp_path / "backup.json")]) == 0
    assert json.loads(capsys.readouterr().out)["assessments"] == 4
