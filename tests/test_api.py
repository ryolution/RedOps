from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from redops.api.app import create_app
from redops.core.errors import RedOpsError
from redops.core.workflow import run_assessment

TOKEN = "test-only-api-token-with-at-least-32-characters"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def saved(settings, labs):
    return run_assessment(
        settings,
        labs / "demo-scope.yaml",
        labs / "demo-nmap.xml",
        labs / "demo-catalog.json",
    )


def test_api_refuses_missing_or_short_token(settings):
    with pytest.raises(RedOpsError, match="REDOPS_API_TOKEN"):
        create_app(settings, token="")


def test_liveness_does_not_open_storage(settings, tmp_path):
    with TestClient(create_app(settings, token=TOKEN)) as client:
        response = client.get("/health")
        assert response.json() == {"status": "ok", "service": "RedOps"}
        assert response.headers["Cache-Control"] == "no-store"
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Bearer incorrect"}, {"Authorization": "Basic abc"}]
)
def test_data_requires_authentication(settings, headers):
    with TestClient(create_app(settings, token=TOKEN)) as client:
        response = client.get("/assessments", headers=headers)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert "incorrect" not in settings.audit_path.read_text()


def test_list_inventory_and_readiness(settings, saved):
    with TestClient(create_app(settings, token=TOKEN)) as client:
        assert client.get("/ready", headers=HEADERS).status_code == 200
        response = client.get("/assessments?limit=1", headers=HEADERS)
        assert response.json()["items"][0]["id"] == saved["id"]
        assert "document" not in response.json()["items"][0]
        response = client.get(f"/assessments/{saved['id']}/inventory", headers=HEADERS)
        assert len(response.json()) == 12
        assert (
            client.get("/assessments?engagement=another-engagement", headers=HEADERS).json()[
                "items"
            ]
            == []
        )
        assert client.get("/assessments?offset=1", headers=HEADERS).json()["items"] == []


@pytest.mark.parametrize(
    "format_name,media",
    [("json", "application/json"), ("html", "text/html"), ("pdf", "application/pdf")],
)
def test_report_downloads(settings, saved, format_name, media):
    with TestClient(create_app(settings, token=TOKEN)) as client:
        response = client.get(
            f"/assessments/{saved['id']}/report?format={format_name}", headers=HEADERS
        )
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith(media)
    assert response.headers["Content-Disposition"].startswith("attachment;")
    if format_name == "pdf":
        assert response.content.startswith(b"%PDF-")


def test_invalid_queries_and_missing_assessments(settings, saved):
    with TestClient(create_app(settings, token=TOKEN)) as client:
        assert client.get("/assessments?limit=101", headers=HEADERS).status_code == 422
        assert client.get("/assessments?offset=-1", headers=HEADERS).status_code == 422
        assert client.get("/assessments/not-a-uuid", headers=HEADERS).status_code == 422
        assert client.get(f"/assessments/{uuid4()}", headers=HEADERS).status_code == 404
        assert client.post("/assessments", headers=HEADERS, json={}).status_code == 405


def test_uninitialized_storage_returns_service_unavailable(settings):
    with TestClient(create_app(settings, token=TOKEN)) as client:
        response = client.get("/ready", headers=HEADERS)
    assert response.status_code == 503
    assert settings.database_url not in response.text


def test_tokens_are_not_audited(settings, saved):
    with TestClient(create_app(settings, token=TOKEN)) as client:
        client.get("/assessments", headers=HEADERS)
    assert TOKEN not in settings.audit_path.read_text()


def test_audit_failure_fails_closed(settings, saved, monkeypatch):
    from redops.core.audit import AuditLog

    def fail(*args, **kwargs):
        raise OSError("simulated audit storage failure")

    monkeypatch.setattr(AuditLog, "record", fail)
    with TestClient(create_app(settings, token=TOKEN)) as client:
        assert client.get("/assessments", headers=HEADERS).status_code == 503
