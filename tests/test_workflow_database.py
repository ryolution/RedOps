import json

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from redops.core.config import Settings
from redops.core.errors import InputError, RedOpsError, ScopeError
from redops.core.workflow import run_assessment
from redops.database.models import (
    ActionRecord,
    Assessment,
    HostRecord,
    SchemaVersion,
    ServiceRecord,
)
from redops.database.repository import Repository


def run_demo(settings, labs, **kwargs):
    return run_assessment(
        settings,
        labs / "demo-scope.yaml",
        labs / "demo-nmap.xml",
        labs / "demo-catalog.json",
        **kwargs,
    )


def test_preview_creates_only_audit(preview, tmp_path):
    assert preview["status"] == "preview"
    assert not (tmp_path / "assessment.db").exists()
    assert {item.name for item in tmp_path.iterdir()} == {"audit.jsonl"}
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [event["status"] for event in events] == ["started", "preview"]


def test_snapshot_and_relational_storage(settings, labs):
    first = run_demo(settings, labs)
    second = run_demo(settings, labs)
    assert first["id"] != second["id"]
    repository = Repository(settings.database_url)
    try:
        assert repository.get()["id"] == second["id"]
        assert repository.get(first["id"]) == json.loads(json.dumps(first))
        assert len(repository.inventory(first["id"])) == 12
        with Session(repository.engine) as session:
            assert session.scalar(select(func.count()).select_from(HostRecord)) == 24
            assert session.scalar(select(func.count()).select_from(ServiceRecord)) == 24
            assert session.scalar(select(func.count()).select_from(ActionRecord)) == 2
    finally:
        repository.close()


def test_failure_rolls_back_entire_assessment(settings, preview):
    repository = Repository(settings.database_url, create=True)
    try:
        repository.initialize()
        preview["hosts"].append(preview["hosts"][0])
        with pytest.raises(IntegrityError):
            repository.save(preview)
        with Session(repository.engine) as session:
            for model in (Assessment, HostRecord, ServiceRecord, ActionRecord):
                assert session.scalar(select(func.count()).select_from(model)) == 0
    finally:
        repository.close()


def test_scope_failure_precedes_database_creation(settings, labs, tmp_path):
    xml = tmp_path / "input.xml"
    xml.write_bytes((labs / "demo-nmap.xml").read_bytes().replace(b"192.0.2.10", b"198.51.100.10"))
    with pytest.raises(ScopeError):
        run_assessment(settings, labs / "demo-scope.yaml", xml, labs / "demo-catalog.json")
    assert not (tmp_path / "assessment.db").exists()
    assert json.loads(settings.audit_path.read_text().splitlines()[-1])["status"] == "failed"


def test_incompatible_schema_is_not_silently_changed(settings):
    repository = Repository(settings.database_url, create=True)
    try:
        repository.initialize()
        with Session(repository.engine) as session, session.begin():
            session.get(SchemaVersion, 1).version = 999
        with pytest.raises(RedOpsError, match="version"):
            repository.initialize()
    finally:
        repository.close()


def test_read_does_not_create_database(settings, tmp_path):
    with pytest.raises(RedOpsError, match="does not exist"):
        Repository(settings.database_url)
    assert not (tmp_path / "assessment.db").exists()


def test_audit_cannot_overwrite_input(settings, labs, tmp_path):
    xml = tmp_path / "input.xml"
    original = (labs / "demo-nmap.xml").read_bytes()
    xml.write_bytes(original)
    colliding = Settings(settings.database_url, xml)
    with pytest.raises(InputError, match="distinct"):
        run_assessment(colliding, labs / "demo-scope.yaml", xml, labs / "demo-catalog.json")
    assert xml.read_bytes() == original


def test_final_audit_failure_reports_committed_state(settings, labs, monkeypatch):
    from redops.core.audit import AuditLog

    original = AuditLog.record

    def fail_completion(self, action, status, **kwargs):
        if status == "completed":
            raise OSError("simulated disk failure")
        return original(self, action, status, **kwargs)

    monkeypatch.setattr(AuditLog, "record", fail_completion)
    with pytest.raises(RedOpsError, match="was committed"):
        run_demo(settings, labs)
    repository = Repository(settings.database_url)
    try:
        assert repository.get()["status"] == "completed"
    finally:
        repository.close()
