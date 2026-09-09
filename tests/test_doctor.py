import json
import socket

import pytest

from redops.cli.main import main
from redops.core.config import Settings
from redops.core.doctor import diagnose
from redops.database.repository import Repository


def test_doctor_creates_nothing_and_contacts_nothing(settings, tmp_path, monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Network access is forbidden")

    monkeypatch.setattr(socket, "create_connection", denied)
    result = diagnose(settings)
    assert result["network_requests"] == 0 and result["storage_created"] is False
    assert not list(tmp_path.iterdir())


def test_local_schema_read_preserves_every_file(settings, tmp_path):
    repository = Repository(settings.database_url, create=True)
    try:
        repository.initialize()
    finally:
        repository.close()
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    checks = {row["check"]: row for row in diagnose(settings)["checks"]}
    assert checks["database"]["status"] == "ok"
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_doctor_redacts_and_does_not_connect_postgres(tmp_path, monkeypatch):
    secret = "diagnostic-secret-value"
    monkeypatch.setenv("REDOPS_API_TOKEN", secret)
    monkeypatch.setenv("REDOPS_MSF_PASSWORD", secret)
    monkeypatch.setenv("REDOPS_MSF_URL", "https://user:" + secret + "@localhost:55553")
    result = diagnose(
        Settings("postgresql+psycopg://user:" + secret + "@remote/db", tmp_path / "audit")
    )
    assert secret not in json.dumps(result)
    assert result["status"] == "error"
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("database", ["invalid://", "sqlite:///", "not a database url"])
def test_invalid_or_uninitialized_configuration_is_reported(tmp_path, database):
    result = diagnose(Settings(database, tmp_path / "audit"))
    assert result["status"] in {"attention", "error"}
    assert not list(tmp_path.iterdir())


def test_missing_asset_and_cli_exit(settings, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("redops.core.doctor.PACKAGE", tmp_path)
    assert (
        main(["--database", settings.database_url, "--audit", str(settings.audit_path), "doctor"])
        == 2
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "error" and not list(tmp_path.iterdir())


def test_active_journal_requires_separate_check(settings, tmp_path):
    path = tmp_path / "assessment.db"
    path.write_bytes(b"not opened when a journal exists")
    path.with_name(path.name + "-wal").touch()
    checks = {row["check"]: row for row in diagnose(settings)["checks"]}
    assert checks["database"]["status"] == "warning"
