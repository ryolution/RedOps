"""Real Chromium journeys against a disposable loopback application."""

import json
import os
import socket
import threading
import time
from pathlib import Path
from uuid import uuid4

import pytest
import uvicorn

from redops.api.app import create_app
from redops.core.workflow import run_assessment
from redops.database.repository import Repository

pytestmark = pytest.mark.skipif(
    os.environ.get("REDOPS_BROWSER_TESTS") != "1", reason="Opt-in real browser check"
)
TOKEN = "synthetic-browser-fixture-token" * 3


@pytest.fixture
def server(settings, labs, monkeypatch):
    monkeypatch.setenv("REDOPS_OPERATOR", "demo-reviewer")
    document = run_assessment(
        settings, labs / "demo-scope.yaml", labs / "demo-nmap.xml", labs / "demo-catalog.json"
    )
    app = create_app(settings, token=TOKEN, allow_http_ui=True)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    service = uvicorn.Server(uvicorn.Config(app, access_log=False, log_level="error"))
    thread = threading.Thread(target=service.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    try:
        while not service.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert service.started, "Local test server failed to start"
        yield f"http://127.0.0.1:{port}", document, app
    finally:
        service.should_exit = True
        thread.join(timeout=10)
        listener.close()
        assert not thread.is_alive(), "Local test server failed to stop"


def screenshot(page, name, *, full_page=True):
    directory = os.environ.get("REDOPS_SCREENSHOT_DIR")
    if directory:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(path / (name + ".png")), full_page=full_page)


def sign_in(page, origin, capture=None):
    from playwright.sync_api import expect

    page.goto(origin + "/ui")
    page.wait_for_load_state("load")
    card = page.locator(".login-card").bounding_box()
    viewport = page.viewport_size
    assert abs(card["x"] + card["width"] / 2 - viewport["width"] / 2) < 2
    assert abs(card["y"] + card["height"] / 2 - viewport["height"] / 2) < 2
    if capture:
        screenshot(page, "login-" + capture)
    page.keyboard.press("Tab")
    expect(page.get_by_role("link", name="Skip to content")).to_be_focused()
    page.get_by_label("Workspace token").focus()
    page.keyboard.type(TOKEN)
    page.keyboard.press("Enter")
    expect(page.get_by_role("heading", name="Assessments", level=1)).to_be_visible()


@pytest.mark.parametrize("width,name", [(1440, "desktop"), (390, "mobile")])
def test_keyboard_browse_review_and_exports(page, server, width, name):
    from playwright.sync_api import expect

    origin, document, _ = server
    foreign = []
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))

    def route(request):
        if request.request.url.startswith(origin + "/"):
            request.continue_()
        else:
            foreign.append(request.request.url)
            request.abort()

    page.route("**/*", route)
    page.set_viewport_size({"width": width, "height": 900})
    sign_in(page, origin, name)
    page.wait_for_load_state("load")
    screenshot(page, "history-" + name)
    page.get_by_role("link", name=document["scope"]["engagement"], exact=True).focus()
    page.keyboard.press("Enter")
    expect(page.get_by_role("heading", name="Inventory", exact=True)).to_be_visible()
    page.wait_for_load_state("load")
    expect(page.locator('.severity-chart meter[aria-label="High candidates"]')).to_have_attribute(
        "value", "4"
    )
    expect(page.locator(".review-ring strong")).to_have_text("0")
    navigation = page.get_by_role("navigation", name="Main navigation")
    if width < 851:
        page.get_by_role("button", name="Open navigation").click()
        expect(navigation).to_be_visible()
        screenshot(page, "sidebar-" + name, full_page=False)
        page.keyboard.press("Escape")
        expect(navigation).not_to_be_visible()
        expect(page.get_by_role("button", name="Open navigation")).to_be_focused()
        page.keyboard.press("Enter")
    navigation.get_by_role("link", name="Inventory", exact=True).click()
    expect(page).to_have_url(origin + f"/ui/assessments/{document['id']}#inventory")
    if width < 851:
        expect(navigation).not_to_be_visible()
        page.get_by_role("button", name="Open navigation").click()
    navigation.get_by_role("link", name="Overview", exact=True).click()
    page.wait_for_load_state("load")
    screenshot(page, "dashboard-" + name, full_page=False)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), (
        page.evaluate(
            """Array.from(document.querySelectorAll('body *')).filter(e =>
        e.getBoundingClientRect().right > innerWidth && !e.closest('.table-wrap'))
        .map(e => [e.tagName, e.className, e.getBoundingClientRect().right])"""
        )
    )
    finding = page.get_by_role("link", name="DEMO-WEB-001", exact=True).first
    finding.focus()
    page.keyboard.press("Enter")
    page.get_by_label("Disposition").select_option("not_affected")
    page.get_by_label("Notes", exact=True).fill(
        "Synthetic review: vendor backport confirmed. café مرحبا"
    )
    page.get_by_role("button", name="Save review").focus()
    page.keyboard.press("Enter")
    expect(
        page.get_by_text("Synthetic review: vendor backport confirmed. café مرحبا")
    ).to_be_visible()
    page.wait_for_load_state("load")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), (
        page.evaluate(
            """Array.from(document.querySelectorAll('body *')).filter(e =>
        e.getBoundingClientRect().right > innerWidth && !e.closest('.table-wrap'))
        .map(e => [e.tagName, e.className, e.getBoundingClientRect().right])"""
        )
    )
    screenshot(page, "review-" + name)
    page.locator("a.back").click()
    page.get_by_label("Review", exact=True).select_option("not_affected")
    page.get_by_role("button", name="Filter", exact=True).click()
    # Escape handling is installed by the deferred script on this new document.
    page.wait_for_load_state("load")
    expect(page.get_by_role("link", name="DEMO-WEB-001", exact=True)).to_have_count(1)
    expect(page.locator(".review-ring strong")).to_have_text("1")
    expect(page.locator('.severity-chart meter[aria-label="High candidates"]')).to_have_attribute(
        "value", "4"
    )
    menu = page.locator(".export-menu > summary")
    menu.focus()
    page.keyboard.press("Enter")
    expect(page.get_by_role("link", name="JSON", exact=True)).to_be_visible()
    page.keyboard.press("Escape")
    expect(page.get_by_role("link", name="JSON", exact=True)).not_to_be_visible()
    expect(menu).to_be_focused()
    page.keyboard.press("Enter")
    for format_name in ("JSON", "HTML", "PDF"):
        with page.expect_download() as pending:
            page.get_by_role("link", name=format_name, exact=True).click()
        download = pending.value
        assert download.failure() is None
        assert Path(download.path()).stat().st_size > 100
    page.get_by_label("Reviewed report format").select_option("json")
    with page.expect_download() as pending:
        page.get_by_role("button", name="Export with reviews").click()
    export = json.loads(Path(pending.value.path()).read_text())
    assert export["review_export"]["revision"] > 0
    assert export["findings"][0]["status"] == "candidate_needs_review"
    page.get_by_role("button", name="Sign out").click()
    expect(page.get_by_role("button", name="Sign in")).to_be_visible()
    assert not foreign and not errors
    assert page.evaluate("localStorage.length + sessionStorage.length") == 0


def test_pagination_escaped_content_and_expired_session(page, server, settings):
    from playwright.sync_api import expect

    origin, document, app = server
    repository = Repository(settings.database_url)
    try:
        for _ in range(26):
            copy = json.loads(json.dumps(document))
            copy["id"] = str(uuid4())
            repository.save(copy)
        copy["id"] = str(uuid4())
        copy["scope"]["engagement"] = "<script>window.importExecuted=true</script>"
        repository.save(copy)
    finally:
        repository.close()
    sign_in(page, origin)
    expect(page.locator("tbody tr")).to_have_count(25)
    page.get_by_role("link", name="Next").click()
    expect(page.locator("tbody tr")).to_have_count(3)
    page.get_by_label("Engagement", exact=True).fill(copy["scope"]["engagement"])
    page.get_by_role("button", name="Filter", exact=True).click()
    expect(page.locator("tbody tr")).to_have_count(1)
    assert page.evaluate("window.importExecuted") is None
    page.get_by_role("link", name=copy["scope"]["engagement"], exact=True).click()
    expect(page.get_by_role("heading", level=1)).to_have_text(copy["scope"]["engagement"])
    assert page.evaluate("window.importExecuted") is None
    app.state.browser_sessions.clock = lambda: time.monotonic() + 1801
    page.goto(origin + "/ui")
    expect(page.get_by_text("Session expired. Sign in again.")).to_be_visible()
