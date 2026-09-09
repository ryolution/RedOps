import re

import pytest
from fastapi.testclient import TestClient

from redops.api.app import create_app
from redops.core.workflow import run_assessment
from redops.database.repository import Repository
from redops.web.sessions import Sessions

TOKEN = "dashboard-fixture-token-" * 3


def csrf(response):
    return re.search(r'name="csrf" value="([^"]+)"', response.text).group(1)


@pytest.fixture
def document(settings, labs):
    return run_assessment(
        settings, labs / "demo-scope.yaml", labs / "demo-nmap.xml", labs / "demo-catalog.json"
    )


@pytest.fixture
def client(settings, document):
    with TestClient(
        create_app(settings, token=TOKEN, allow_http_ui=True), base_url="http://127.0.0.1"
    ) as client:
        yield client


def login(client):
    page = client.get("/ui/login")
    assert page.status_code == 200
    response = client.post("/ui/login", data={"csrf": csrf(page), "token": TOKEN})
    assert response.status_code == 200 and "<h1>Assessments</h1>" in response.text
    return response


def test_full_browser_http_journey_and_api_isolation(client, document, settings):
    page = login(client)
    cookie = client.cookies.get("redops_session")
    assert cookie != TOKEN and len(cookie) >= 32
    assert client.get("/assessments").status_code == 401
    page = client.get(f"/ui/assessments/{document['id']}")
    assert "Candidate findings" in page.text and "Inventory" in page.text
    path = re.search(r'href="(/ui/assessments/[^"]+/findings/[a-f0-9]+)"', page.text).group(1)
    page = client.get(path)
    assert "<h2>Review</h2>" in page.text
    response = client.post(
        path + "/reviews",
        data={
            "csrf": csrf(page),
            "disposition": "not_affected",
            "notes": "Vendor backport reviewed",
            "expected_previous": "0",
        },
    )
    assert response.status_code == 200
    assert "Vendor backport reviewed" in response.text
    conflict = client.post(
        path + "/reviews",
        data={
            "csrf": csrf(response),
            "disposition": "affected",
            "notes": "Unsaved second opinion",
            "expected_previous": "0",
        },
    )
    assert conflict.status_code == 409 and "Unsaved second opinion" in conflict.text
    for format in ("json", "html", "pdf"):
        download = client.get(f"/ui/assessments/{document['id']}/report?format={format}")
        assert download.status_code == 200
        assert "attachment" in download.headers["content-disposition"]
    assert TOKEN not in settings.audit_path.read_text()
    assert cookie not in settings.audit_path.read_text()
    assert client.post("/ui/logout", data={"csrf": csrf(response)}).status_code == 200
    assert "Sign in" in client.get("/ui").text


def test_csrf_origin_and_form_bounds(client, document):
    page = client.get("/ui/login")
    assert client.post("/ui/login", data={"csrf": "incorrect", "token": TOKEN}).status_code == 403
    assert (
        client.post(
            "/ui/login",
            data={"csrf": csrf(page), "token": TOKEN},
            headers={"Origin": "https://other.example"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/ui/login",
            content="csrf=x&token=" + "x" * 70000,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ).status_code
        == 413
    )
    assert client.post("/ui/login", json={"csrf": csrf(page), "token": TOKEN}).status_code == 415


def test_login_rotation_cookie_flags_expiry_and_restart(client, settings):
    now = [1000.0]
    client.app.state.browser_sessions.clock = lambda: now[0]
    page = client.get("/ui/login")
    anonymous = client.cookies.get("redops_session")
    result = client.post(
        "/ui/login", data={"csrf": csrf(page), "token": TOKEN}, follow_redirects=False
    )
    assert result.status_code == 303
    assert client.cookies.get("redops_session") != anonymous
    cookie = result.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/ui" in cookie
    assert TOKEN not in cookie
    now[0] += 1800
    assert "Session expired" in client.get("/ui").text
    app = create_app(settings, token=TOKEN, allow_http_ui=True)
    with TestClient(app, base_url="http://127.0.0.1", cookies=client.cookies) as fresh:
        assert "Sign in" in fresh.get("/ui").text


def test_login_failure_throttle_and_no_token_reflection(client):
    page = client.get("/ui/login")
    for _ in range(5):
        result = client.post(
            "/ui/login", data={"csrf": csrf(page), "token": "secret-invalid-input"}
        )
        assert result.status_code == 401
        assert "secret-invalid-input" not in result.text
    assert client.post("/ui/login", data={"csrf": csrf(page), "token": TOKEN}).status_code == 429


def test_https_required_and_secure_cookie(settings, document):
    app = create_app(settings, token=TOKEN)
    with TestClient(app, base_url="http://workspace.example") as plain:
        assert plain.get("/ui/login").status_code == 400
    with TestClient(app, base_url="https://workspace.example") as secure:
        response = secure.get("/ui/login")
        assert response.status_code == 200
        assert "Secure" in response.headers["set-cookie"]


def test_search_filter_and_missing_record(client, document):
    login(client)
    root = f"/ui/assessments/{document['id']}"
    assert "No matching inventory" in client.get(root + "?q=does-not-exist").text
    assert "No matching candidates" in client.get(root + "?severity=critical").text
    assert client.get(root + "?severity=invalid").status_code == 422
    assert client.get(root + "?findings_page=-1").status_code == 422
    assert client.get("/ui/assessments/not-a-uuid").status_code == 422
    assert client.get(root + "/findings/unknown").status_code == 404


def test_escaped_inventory_and_review_content(settings, document):
    import uuid

    document["id"] = str(uuid.uuid4())
    document["scope"]["engagement"] = '<script>alert("evidence")</script>'
    document["hosts"][0]["hostname"] = '<img src=x onerror="alert(1)">'
    repository = Repository(settings.database_url)
    try:
        repository.save(document)
    finally:
        repository.close()
    with TestClient(
        create_app(settings, token=TOKEN, allow_http_ui=True), base_url="http://127.0.0.1"
    ) as client:
        login(client)
        page = client.get(f"/ui/assessments/{document['id']}")
        assert "<script>alert" not in page.text and "<img src=x" not in page.text
        assert "&lt;script&gt;" in page.text
        assert "unsafe-inline" not in page.headers["content-security-policy"]


def test_empty_and_unavailable_storage(settings):
    app = create_app(settings, token=TOKEN, allow_http_ui=True)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        page = client.get("/ui/login")
        client.post("/ui/login", data={"csrf": csrf(page), "token": TOKEN}, follow_redirects=False)
        assert client.get("/ui").status_code == 503
        repository = Repository(settings.database_url, create=True)
        try:
            repository.initialize()
        finally:
            repository.close()
        assert "No assessments yet" in client.get("/ui").text


def test_session_capacity_and_expiry():
    now = [0.0]
    store = Sessions(clock=lambda: now[0])
    original, _ = store.create()
    for _ in range(128):
        now[0] += 1
        store.create()
    assert store.get(original) is None
    now[0] += 1800
    assert len(store._sessions) <= 128
    store.get("absent")
    assert store._sessions == {}


def test_inventory_and_finding_pagination(client, settings, document):
    from copy import deepcopy
    from uuid import uuid4

    expanded = deepcopy(document)
    expanded["id"] = str(uuid4())
    host = expanded["hosts"][0]
    service = host["services"][0]
    host["services"] = [
        {**service, "port": {"number": 6000 + number, "protocol": "tcp"}} for number in range(30)
    ]
    expanded["hosts"] = [host]
    expanded["findings"] = [
        {**document["findings"][0], "port": 6000 + number} for number in range(30)
    ]
    expanded["coverage"]["services_total"] = 30
    expanded["coverage"]["services_with_supported_cpe"] = 30
    repository = Repository(settings.database_url)
    try:
        repository.save(expanded)
    finally:
        repository.close()
    login(client)
    root = f"/ui/assessments/{expanded['id']}"
    first = client.get(root).text
    second = client.get(root + "?inventory_page=2&findings_page=2").text
    assert len(re.findall(r'<td class="mono">60\d\d/tcp</td>', first)) == 25
    assert len(re.findall(r'<td class="mono">60\d\d/tcp</td>', second)) == 5
    assert len(re.findall(r"/findings/[a-f0-9]{64}", first)) == 25
    assert len(re.findall(r"/findings/[a-f0-9]{64}", second)) == 5
