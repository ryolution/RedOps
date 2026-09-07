from pathlib import Path

import pytest

from redops.core.config import Settings
from redops.core.workflow import run_assessment

LABS = Path(__file__).resolve().parents[1] / "labs"


@pytest.fixture
def settings(tmp_path):
    return Settings(f"sqlite:///{tmp_path / 'assessment.db'}", tmp_path / "audit.jsonl")


@pytest.fixture
def labs():
    return LABS


@pytest.fixture
def preview(settings):
    return run_assessment(
        settings,
        LABS / "demo-scope.yaml",
        LABS / "demo-nmap.xml",
        LABS / "demo-catalog.json",
        dry_run=True,
    )
