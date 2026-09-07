import json

import pytest

from redops.cli.main import main
from redops.core.errors import InputError
from redops.reporting.benchmark import calculate_benchmark
from redops.reporting.render import export_report, render_html


def test_html_escapes_observed_content(preview):
    marker = '<b data-example="untrusted">sample & text</b>'
    preview["hosts"][0]["hostname"] = marker
    preview["findings"][0]["description"] = marker
    content = render_html(preview)
    assert marker not in content
    assert "&lt;b data-example=&quot;untrusted&quot;&gt;sample &amp; text&lt;/b&gt;" in content
    assert "Content-Security-Policy" in content
    assert "Synthetic demonstration evidence" in content


def test_json_atomic_export(preview, tmp_path):
    destination = tmp_path / "reports" / "result.json"
    export_report(preview, destination, "json")
    assert json.loads(destination.read_text())["id"] == preview["id"]
    assert list(destination.parent.iterdir()) == [destination]


def test_benchmark_uses_weighted_total(tmp_path):
    path = tmp_path / "timing.csv"
    path.write_text("target,manual_seconds,redops_seconds\na,100,50\nb,900,180\n")
    result = calculate_benchmark(path)
    assert result["reduction_percent"] == 77
    assert result["exceeds_60_percent"] is True


@pytest.mark.parametrize("rows", ["", "a,0,1\n", "a,nan,1\n", "a,10,inf\n", "a,10,1\na,10,2\n"])
def test_invalid_benchmark_is_rejected(tmp_path, rows):
    path = tmp_path / "timing.csv"
    path.write_text("target,manual_seconds,redops_seconds\n" + rows)
    with pytest.raises(InputError):
        calculate_benchmark(path)


def test_cli_full_workflow_and_report(tmp_path, labs, capsys):
    base = [
        "--database",
        f"sqlite:///{tmp_path / 'cli.db'}",
        "--audit",
        str(tmp_path / "audit.jsonl"),
    ]
    assert (
        main(
            base
            + [
                "workflow",
                "run",
                "--scope",
                str(labs / "demo-scope.yaml"),
                "--input",
                str(labs / "demo-nmap.xml"),
                "--catalog",
                str(labs / "demo-catalog.json"),
                "--output-dir",
                str(tmp_path / "reports"),
            ]
        )
        == 0
    )
    document = json.loads(capsys.readouterr().out)
    assert len(document["hosts"]) == 12
    assert len(list((tmp_path / "reports").iterdir())) == 2
    assert main(base + ["inventory"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 12
    assert (
        main(base + ["report", "--format", "html", "--output", str(tmp_path / "latest.html")]) == 0
    )
    assert (tmp_path / "latest.html").is_file()


def test_dry_run_refuses_report_output(labs, tmp_path, capsys):
    assert (
        main(
            [
                "--audit",
                str(tmp_path / "audit.jsonl"),
                "analyze",
                "--scope",
                str(labs / "demo-scope.yaml"),
                "--input",
                str(labs / "demo-nmap.xml"),
                "--catalog",
                str(labs / "demo-catalog.json"),
                "--dry-run",
                "--output-dir",
                str(tmp_path),
            ]
        )
        == 2
    )
    assert "cannot be combined" in capsys.readouterr().err
    assert not list(tmp_path.iterdir())


def test_database_errors_do_not_disclose_credentials(tmp_path, capsys):
    assert (
        main(
            [
                "--database",
                "postgresql+missingdriver://user:test-secret@localhost/db",
                "--audit",
                str(tmp_path / "audit.jsonl"),
                "inventory",
            ]
        )
        == 2
    )
    result = capsys.readouterr()
    assert "test-secret" not in result.err
    assert "test-secret" not in (tmp_path / "audit.jsonl").read_text()


def test_report_cannot_overwrite_database(tmp_path, capsys):
    database = tmp_path / "existing.db"
    database.write_bytes(b"existing artifact")
    assert (
        main(
            [
                "--database",
                f"sqlite:///{database}",
                "--audit",
                str(tmp_path / "audit.jsonl"),
                "report",
                "--output",
                str(database),
            ]
        )
        == 2
    )
    assert "distinct" in capsys.readouterr().err
    assert database.read_bytes() == b"existing artifact"
