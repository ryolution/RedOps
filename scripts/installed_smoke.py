"""Executed in an isolated interpreter by check_distribution.py."""

import re
import socket
import sys
from pathlib import Path


def main() -> None:
    site, labs = Path(sys.argv[1]), Path(sys.argv[2])
    sys.path.insert(0, str(site))
    from fastapi.testclient import TestClient

    import redops
    from redops.api.app import create_app
    from redops.core.config import Settings
    from redops.core.doctor import diagnose
    from redops.core.workflow import run_assessment
    from redops.database.maintenance import backup_database, restore_database
    from redops.database.repository import Repository
    from redops.reporting.render import export_report

    assert Path(redops.__file__).is_relative_to(site)

    def no_network(*args, **kwargs):
        raise AssertionError("Installed offline check attempted a network connection")

    socket.create_connection = no_network
    settings = Settings("sqlite:///assessment.db", Path("audit.jsonl"))
    document = run_assessment(
        settings, labs / "demo-scope.yaml", labs / "demo-nmap.xml", labs / "demo-catalog.json"
    )
    for format_name in ("json", "html", "pdf"):
        export_report(document, Path("report." + format_name), format_name)
    backup_database(settings, Path("backup.json"))
    restored = Settings("sqlite:///restored.db", Path("restore-audit.jsonl"))
    restore_database(restored, Path("backup.json"))
    repository = Repository(restored.database_url)
    try:
        assert repository.get(document["id"])["id"] == document["id"]
    finally:
        repository.close()
    token = "installed-wheel-synthetic-test-token" * 2
    with TestClient(
        create_app(restored, token=token, allow_http_ui=True), base_url="http://127.0.0.1"
    ) as client:
        login = client.get("/ui/login")
        csrf = re.search(r'name="csrf" value="([^"]+)"', login.text).group(1)
        assert client.post("/ui/login", data={"csrf": csrf, "token": token}).status_code == 200
        assert client.get(f"/ui/assessments/{document['id']}").status_code == 200
        assert client.get("/ui/static/app.css").status_code == 200
    assert diagnose(restored)["status"] != "error"


main()
