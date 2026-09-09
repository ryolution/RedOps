"""Opt-in integration check against a dedicated disposable PostgreSQL test database."""

import copy
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

from redops.core.config import Settings
from redops.core.reviews import finding_key
from redops.core.workflow import run_assessment
from redops.database.maintenance import (
    backup_database,
    database_status,
    migrate_database,
    prune_database,
    restore_database,
)
from redops.database.models import SchemaVersion
from redops.database.repository import Repository
from redops.database.reviews import add_review, list_reviews
from redops.database.schema import HISTORY_INDEX, transaction


@pytest.mark.skipif(
    not os.environ.get("REDOPS_TEST_POSTGRES_URL"), reason="PostgreSQL test database not configured"
)
def test_postgres_assessment_round_trip(tmp_path, labs):
    settings = Settings(os.environ["REDOPS_TEST_POSTGRES_URL"], tmp_path / "postgres-audit.jsonl")
    document = run_assessment(
        settings,
        labs / "demo-scope.yaml",
        labs / "demo-nmap.xml",
        labs / "demo-catalog.json",
    )
    repository = Repository(settings.database_url)
    try:
        assert repository.get(document["id"])["scope"] == document["scope"]
        assert len(repository.inventory(document["id"])) == 12
        assert repository.list_assessments(limit=1)[0]["id"] == document["id"]
    finally:
        repository.close()


@pytest.mark.skipif(
    not os.environ.get("REDOPS_TEST_POSTGRES_URL"), reason="PostgreSQL test database not configured"
)
def test_postgres_portable_restore_sequences_migration_and_retention(settings, preview, tmp_path):
    # Create and remove only this test's unique schema in the disposable test database.
    url = make_url(os.environ["REDOPS_TEST_POSTGRES_URL"])
    schema = f"redops_test_{uuid.uuid4().hex}"
    engine = create_engine(url, hide_parameters=True)
    with engine.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    scoped_url = url.update_query_dict({"options": f"-csearch_path={schema}"})
    target = Settings(scoped_url.render_as_string(hide_password=False), tmp_path / "pg-audit.jsonl")
    repository = Repository(settings.database_url, create=True)
    try:
        repository.initialize()
        preview["created_at"] = (datetime.now(UTC) - timedelta(days=3)).isoformat()
        repository.save(preview)
        source = tmp_path / "sqlite-backup.json"
        backup_database(settings, source)
        assert restore_database(target, source)["restored_assessments"] == 1
        postgres = Repository(target.database_url)
        try:
            later = copy.deepcopy(preview)
            later.update(
                id=str(uuid.uuid4()), created_at=(datetime.now(UTC) - timedelta(days=2)).isoformat()
            )
            postgres.save(later)  # Restored serial sequences must permit fresh normalized rows.
            assert len(postgres.inventory(later["id"])) == 12
            with transaction(postgres.engine, write=True) as connection:
                HISTORY_INDEX.drop(connection)
                connection.execute(SchemaVersion.__table__.update().values(version=1))
            result = migrate_database(target, tmp_path / "pg-before-migrate.json")
            assert result["schema_version"] == 3
            for document in (preview, later):
                add_review(
                    target,
                    document["id"],
                    finding_key(document["id"], document["findings"][0]),
                    disposition="affected",
                    notes="Test operator review",
                    expected_previous=0,
                    operator="test-operator",
                )
            result = prune_database(
                target,
                engagement=preview["scope"]["engagement"],
                before=datetime.now(UTC).isoformat(),
                apply=True,
                backup=tmp_path / "pg-before-prune.json",
            )
            assert result["deleted"] == 1
            assert database_status(target)["rows"]["assessments"] == 1
            source = tmp_path / "pg-backup.json"
            backup_database(target, source)
            restored = Settings(
                f"sqlite:///{tmp_path / 'from-pg.db'}", tmp_path / "from-pg-audit.jsonl"
            )
            assert restore_database(restored, source)["restored_assessments"] == 1
            assert database_status(restored)["rows"] == database_status(target)["rows"]
            assert list_reviews(restored, later["id"])["revision"] > 0
        finally:
            postgres.close()
    finally:
        repository.close()
        with engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        engine.dispose()
