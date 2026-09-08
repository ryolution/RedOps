"""Opt-in integration check against a dedicated disposable PostgreSQL test database."""

import os

import pytest

from redops.core.config import Settings
from redops.core.workflow import run_assessment
from redops.database.repository import Repository


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
