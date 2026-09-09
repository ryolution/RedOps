import io
import json
from copy import deepcopy

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from redops.api.app import create_app
from redops.cli.main import main
from redops.core.reviews import finding_key
from redops.core.workflow import run_assessment
from redops.database.repository import Repository
from redops.database.reviews import add_review
from redops.reporting.document import report_document
from redops.reporting.render import render_html, render_report

TOKEN = "review-report-fixture-token" * 3


@pytest.fixture
def reviewed(settings, labs):
    document = run_assessment(
        settings, labs / "demo-scope.yaml", labs / "demo-nmap.xml", labs / "demo-catalog.json"
    )
    document = json.loads(json.dumps(document))
    review = add_review(
        settings,
        document["id"],
        finding_key(document["id"], document["findings"][0]),
        disposition="not_affected",
        notes="Backport confirmed; café <script>example</script>",
        expected_previous=0,
        operator="reviewer-fixture",
    )["review"]
    return document, review


def test_exports_preserve_snapshot_and_show_revision_in_all_formats(settings, reviewed):
    original, review = reviewed
    repository = Repository(settings.database_url)
    try:
        annotated = report_document(repository, original["id"], include_reviews=True)
        assert report_document(repository, original["id"]) == original
        assert repository.get(original["id"]) == original
    finally:
        repository.close()
    expected = deepcopy(annotated)
    export = expected.pop("review_export")
    assert expected == original
    assert export["revision"] == review["id"]
    assert len(export["findings"]) == len(original["findings"])
    assert export["findings"][0]["review"] == review
    content = json.loads(render_report(annotated, "json"))
    assert content == annotated
    html = render_report(annotated, "html")
    pdf = "\n".join(
        page.extract_text() for page in PdfReader(io.BytesIO(render_report(annotated, "pdf"))).pages
    )
    for rendered in (html, pdf):
        for value in (
            "not_affected",
            "candidate_needs_review",
            "reviewer-fixture",
            "café",
            export["exported_at"],
            f"Review revision: {review['id']}",
        ):
            assert value in rendered
        for finding in original["findings"]:
            assert finding["vulnerability_id"] in rendered
    assert "<script>example" not in html
    assert "&lt;script&gt;" in html
    assert "Operator disposition:" not in render_html(original)


def test_cli_and_api_explicit_review_inclusion(settings, reviewed, tmp_path, capsys):
    original, review = reviewed
    output = tmp_path / "reviewed.json"
    assert (
        main(
            [
                "--database",
                settings.database_url,
                "--audit",
                str(settings.audit_path),
                "report",
                "--assessment",
                original["id"],
                "--include-reviews",
                "--format",
                "json",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert json.loads(output.read_text())["review_export"]["revision"] == review["id"]
    with TestClient(create_app(settings, token=TOKEN)) as client:
        route = f"/assessments/{original['id']}/report"
        headers = {"Authorization": "Bearer " + TOKEN}
        assert client.get(route, headers=headers).json() == original
        result = client.get(route + "?include_reviews=true", headers=headers).json()
        assert result["review_export"]["revision"] == review["id"]
        assert client.get(route + "?include_reviews=invalid", headers=headers).status_code == 422


def test_legacy_database_reports_have_empty_reviews(settings, reviewed):
    original, _ = reviewed
    repository = Repository(settings.database_url)
    try:
        with repository.engine.begin() as connection:
            connection.exec_driver_sql("DROP TABLE finding_reviews")
            connection.exec_driver_sql("UPDATE schema_version SET version = 2")
        annotated = report_document(repository, original["id"], include_reviews=True)
        assert annotated["review_export"]["revision"] == 0
        assert all(item["review"] is None for item in annotated["review_export"]["findings"])
        for format_name in ("json", "html", "pdf"):
            assert render_report(annotated, format_name)
    finally:
        repository.close()


def test_json_inventory_provenance_renders_in_all_formats(preview):
    preview["provenance"].pop("nmap_sha256")
    preview["provenance"]["input_format"] = "inventory-json"
    preview["provenance"]["source"] = "Operator-supplied café inventory"
    assert "Operator-supplied café inventory" in render_html(preview)
    assert render_report(preview, "pdf").startswith(b"%PDF-")
