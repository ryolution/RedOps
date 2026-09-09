import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, func, select

from redops.api.app import create_app
from redops.cli.main import main
from redops.core.config import Settings
from redops.core.errors import AssessmentNotFound, InputError, RedOpsError, ReviewConflict
from redops.core.reviews import finding_key
from redops.core.workflow import run_assessment
from redops.database.archive import load_archive
from redops.database.maintenance import (
    backup_database,
    migrate_database,
    prune_database,
    restore_database,
)
from redops.database.models import ActionRecord, FindingReview, SchemaVersion
from redops.database.repository import Repository
from redops.database.reviews import add_review, list_reviews
from redops.database.schema import transaction


@pytest.fixture
def assessment(settings, labs):
    return run_assessment(
        settings, labs / "demo-scope.yaml", labs / "demo-nmap.xml", labs / "demo-catalog.json"
    )


def append(settings, document, *, previous=0, key=None, **changes):
    return add_review(
        settings,
        document["id"],
        key or finding_key(document["id"], document["findings"][0]),
        disposition="affected",
        notes="Operator reviewed supplied evidence",
        expected_previous=previous,
        operator="test-operator",
        **changes,
    )


def test_stable_key_reviews_and_immutable_snapshot(settings, assessment):
    key = finding_key(assessment["id"], assessment["findings"][0])
    assert len(key) == 64
    assert finding_key("different-assessment", assessment["findings"][0]) != key
    first = append(settings, assessment)["review"]
    second = append(settings, assessment, previous=first["id"])["review"]
    history = list_reviews(settings, assessment["id"], key)
    assert history["latest_id"] == second["id"]
    assert [row["id"] for row in history["items"]] == [second["id"], first["id"]]
    with pytest.raises(ReviewConflict):
        append(settings, assessment, previous=first["id"])
    repository = Repository(settings.database_url)
    try:
        assert repository.get(assessment["id"]) == json.loads(json.dumps(assessment))
        with repository.engine.connect() as connection:
            assert connection.scalar(select(func.count()).select_from(ActionRecord)) == 3
    finally:
        repository.close()


def test_two_concurrent_first_reviews_do_not_overwrite(settings, assessment):
    def submit():
        try:
            return append(settings, assessment)["status"]
        except ReviewConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: submit(), range(2)))
    assert sorted(results) == ["completed", "conflict"]


@pytest.mark.parametrize(
    "changes",
    [
        {"disposition": "unknown"},
        {"notes": ""},
        {"notes": "x" * 10001},
        {"expected_previous": True},
    ],
)
def test_invalid_reviews(settings, assessment, changes):
    arguments = {
        "disposition": "affected",
        "notes": "evidence",
        "expected_previous": 0,
        "operator": "tester",
        **changes,
    }
    with pytest.raises(InputError):
        add_review(
            settings,
            assessment["id"],
            finding_key(assessment["id"], assessment["findings"][0]),
            **arguments,
        )


def test_nonexistent_finding_rejected(settings, assessment):
    with pytest.raises(AssessmentNotFound):
        append(settings, assessment, key="0" * 64)


def test_action_failure_rolls_back_review(settings, assessment, monkeypatch):
    original = Repository.__init__

    def initialize(self, *args, **kwargs):
        original(self, *args, **kwargs)

        @event.listens_for(self.engine, "before_cursor_execute")
        def fail(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith("INSERT INTO actions"):
                raise OSError("Action storage failed")

    monkeypatch.setattr(Repository, "__init__", initialize)
    with pytest.raises(OSError):
        append(settings, assessment)
    assert list_reviews(settings, assessment["id"])["revision"] == 0


@pytest.mark.parametrize("version", [1, 2])
def test_legacy_read_restore_and_explicit_review_migration(settings, assessment, tmp_path, version):
    repository = Repository(settings.database_url)
    try:
        with transaction(repository.engine, write=True) as connection:
            FindingReview.__table__.drop(connection)
            connection.execute(SchemaVersion.__table__.update().values(version=version))
    finally:
        repository.close()
    assert list_reviews(settings, assessment["id"])["writable"] is False
    with pytest.raises(RedOpsError, match="migration"):
        append(settings, assessment)
    source = tmp_path / "legacy.json"
    backup_database(settings, source)
    assert "finding_reviews" not in load_archive(source)["tables"]
    destination = Settings(
        f"sqlite:///{tmp_path / 'restored.db'}", tmp_path / "restore-audit.jsonl"
    )
    assert restore_database(destination, source)["schema_version"] == 3
    assert list_reviews(destination, assessment["id"])["revision"] == 0
    assert migrate_database(settings, tmp_path / "migration.json")["schema_version"] == 3
    assert append(settings, assessment)["status"] == "completed"


def test_review_backup_restore_and_retention(settings, assessment, tmp_path):
    saved = append(settings, assessment)["review"]
    source = tmp_path / "reviews.json"
    backup_database(settings, source)
    destination = Settings(
        f"sqlite:///{tmp_path / 'restored.db'}", tmp_path / "restore-audit.jsonl"
    )
    restore_database(destination, source)
    assert list_reviews(destination, assessment["id"])["revision"] == saved["id"]
    # Create a later snapshot so the original is eligible while the newest is retained.
    import copy
    import uuid

    later = copy.deepcopy(assessment)
    later.update(
        id=str(uuid.uuid4()), created_at=(datetime.now(UTC) + timedelta(seconds=1)).isoformat()
    )
    repository = Repository(destination.database_url)
    try:
        repository.save(later)
    finally:
        repository.close()
    result = prune_database(
        destination,
        engagement=assessment["scope"]["engagement"],
        before=datetime.now(UTC).isoformat(),
        apply=True,
        backup=tmp_path / "retained.json",
    )
    assert result["deleted"] == 1
    repository = Repository(destination.database_url)
    try:
        with repository.engine.connect() as connection:
            assert connection.scalar(select(func.count()).select_from(FindingReview)) == 0
    finally:
        repository.close()


def test_review_api_authentication_conflicts_and_actor(settings, assessment, monkeypatch):
    monkeypatch.setenv("REDOPS_OPERATOR", "configured-operator")
    token = "test-token-" * 5
    key = finding_key(assessment["id"], assessment["findings"][0])
    url = f"/assessments/{assessment['id']}/findings/{key}/reviews"
    body = {"disposition": "affected", "notes": "Evidence checked", "expected_previous": 0}
    with TestClient(create_app(settings, token=token)) as client:
        assert client.post(url, json=body).status_code == 401
        headers = {"Authorization": f"Bearer {token}"}
        result = client.post(url, json=body, headers=headers)
        assert result.status_code == 201
        assert result.json()["review"]["operator"] == "configured-operator"
        assert client.post(url, json=body, headers=headers).status_code == 409
        assert client.get(url, headers=headers).json()["latest_id"] == result.json()["review"]["id"]
        assert (
            client.post(url, json={**body, "operator": "spoofed"}, headers=headers).status_code
            == 422
        )


def test_review_cli(settings, assessment, capsys):
    prefix = ["--database", settings.database_url, "--audit", str(settings.audit_path), "review"]
    assert main([*prefix, "list", "--assessment", assessment["id"]]) == 0
    key = json.loads(capsys.readouterr().out)["findings"][0]["key"]
    assert (
        main(
            [
                *prefix,
                "add",
                "--assessment",
                assessment["id"],
                "--finding",
                key,
                "--disposition",
                "not_affected",
                "--notes",
                "Backport verified",
                "--expected-previous",
                "0",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["review"]["disposition"] == "not_affected"
