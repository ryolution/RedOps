import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network

import pytest

from redops.cli.main import main
from redops.core.audit import AuditLog
from redops.core.domain import Host
from redops.core.errors import InputError, RedOpsError, ScopeError
from redops.core.scope import load_scope
from redops.recon import nmap
from redops.recon.nmap import MockScanRunner, NmapRunner, plan_scan, scan_inventory

XML = b"""<nmaprun><host><status state="up"/>
<address addr="172.30.77.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8080"><state state="open"/>
<service name="http-proxy" method="table"/></port></ports></host>
<runstats><finished exit="success"/></runstats></nmaprun>"""


@pytest.fixture
def scope_path(labs):
    return labs / "inventory" / "scope.yaml"


@pytest.mark.parametrize(
    "targets,ports",
    [
        (["example.com"], "8080"),
        (["--script=anything"], "8080"),
        (["172.30.77.0/24"], "8080"),
        (["172.30.77.10", "172.30.77.10"], "8080"),
        (["172.30.77.10"], "1-100"),
        (["172.30.77.10"], "0"),
        (["172.30.77.10"], "65536"),
        (["172.30.77.10"], "8080,8080"),
        (["172.30.77.10"], ",".join(str(i) for i in range(1, 34))),
        (["172.30.77.10"], "８０"),
    ],
)
def test_plan_rejects_invalid_targets_and_ports(scope_path, targets, ports):
    with pytest.raises(InputError):
        plan_scan(load_scope(scope_path), targets, ports)


@pytest.mark.parametrize("target", ["8.8.8.8", "169.254.169.254", "::1", "172.30.77.50"])
def test_scope_and_lab_boundary(scope_path, target):
    with pytest.raises(ScopeError):
        plan_scan(load_scope(scope_path), [target], "8080")


def test_scope_host_limit_and_expiry(scope_path):
    scope = load_scope(scope_path)
    with pytest.raises(ScopeError):
        plan_scan(replace(scope, max_hosts=1), ["172.30.77.10", "172.30.77.11"], "8080")
    with pytest.raises(ScopeError):
        plan_scan(replace(scope, expires_at=datetime.now(UTC)), ["172.30.77.10"], "8080")
    with pytest.raises(ScopeError):
        plan_scan(replace(scope, max_hosts=512), [f"172.30.77.{i}" for i in range(10, 27)], "80")
    loopback = replace(scope, networks=(ip_network("127.0.0.1/32"),))
    assert plan_scan(loopback, ["127.0.0.1"], "8080").targets == ("127.0.0.1",)


def test_scope_requires_primary_address(scope_path):
    with pytest.raises(ScopeError, match="primary"):
        load_scope(scope_path).validate((Host("8.8.8.8", ("172.30.77.10",), "", "", ()),))


def test_cli_preview_does_not_run_nmap_or_create_output(
    settings, scope_path, tmp_path, monkeypatch, capsys
):
    def forbidden(*args):
        pytest.fail("Preview must not start Nmap")

    monkeypatch.setattr(NmapRunner, "run", forbidden)
    output = tmp_path / "inventory.xml"
    args = [
        "--database",
        settings.database_url,
        "--audit",
        str(settings.audit_path),
        "scan",
        "--scope",
        str(scope_path),
        "--target",
        "172.30.77.10",
        "--ports",
        "8080",
        "--output",
        str(output),
        "--dry-run",
    ]
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "preview"
    assert result["targets"] == ["172.30.77.10"]
    assert {path.name for path in tmp_path.iterdir()} == {"audit.jsonl"}


def test_scan_records_xml_and_marks_observation_limits(settings, scope_path, tmp_path):
    output = tmp_path / "inventory.xml"
    result = scan_inventory(
        settings,
        scope_path,
        ["172.30.77.10", "172.30.77.11"],
        "8080",
        output,
        runner=MockScanRunner(XML),
    )
    assert output.read_bytes() == XML
    assert result["status"] == "completed"
    assert result["hosts"][0]["services"][0]["product"] == ""
    assert result["targets_without_open_ports"] == ["172.30.77.11"]
    assert len(result["sha256"]) == 64
    assert not (tmp_path / "assessment.db").exists()
    events = [json.loads(line) for line in settings.audit_path.read_text().splitlines()]
    assert [event["status"] for event in events] == ["started", "completed"]


def test_completed_scan_with_no_open_ports(settings, scope_path, tmp_path):
    xml = b'<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'
    result = scan_inventory(
        settings,
        scope_path,
        ["172.30.77.10"],
        "8080",
        tmp_path / "scan.xml",
        runner=MockScanRunner(xml),
    )
    assert result["hosts"] == []
    assert result["targets_without_open_ports"] == ["172.30.77.10"]


@pytest.mark.parametrize(
    "content",
    [
        XML.replace(b'portid="8080"', b'portid="22"'),
        XML.replace(b'protocol="tcp"', b'protocol="udp"'),
        XML.replace(b"172.30.77.10", b"172.30.77.11"),
        XML.replace(b'<finished exit="success"/>', b'<finished exit="error"/>'),
        XML.replace(b'<runstats><finished exit="success"/></runstats>', b""),
        XML.replace(b"<host>", b'<host timedout="true">'),
        b"<nmaprun>",
    ],
)
def test_scan_rejects_unexpected_or_incomplete_output(settings, scope_path, tmp_path, content):
    output = tmp_path / "inventory.xml"
    with pytest.raises(RedOpsError):
        scan_inventory(
            settings, scope_path, ["172.30.77.10"], "8080", output, runner=MockScanRunner(content)
        )
    assert not output.exists()
    assert json.loads(settings.audit_path.read_text().splitlines()[-1])["status"] == "failed"


def test_output_collision_and_publication_race(settings, scope_path, tmp_path):
    output = tmp_path / "inventory.xml"

    class ConcurrentWriter:
        def run(self, plan):
            output.write_text("existing evidence")
            return XML

    with pytest.raises(FileExistsError):
        scan_inventory(
            settings, scope_path, ["172.30.77.10"], "8080", output, runner=ConcurrentWriter()
        )
    with pytest.raises(InputError, match="already exists"):
        scan_inventory(
            settings, scope_path, ["172.30.77.10"], "8080", output, runner=MockScanRunner(XML)
        )
    assert output.read_text() == "existing evidence"
    assert not list(tmp_path.glob(".redops-*"))


def test_target_file_and_path_protection(settings, scope_path, tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("# inventory fixture\n\n172.30.77.10\n")
    result = scan_inventory(
        settings,
        scope_path,
        [],
        "8080",
        tmp_path / "scan.xml",
        targets_path=targets,
        runner=MockScanRunner(XML),
    )
    assert result["targets"] == ("172.30.77.10",)
    with pytest.raises(InputError, match="distinct"):
        scan_inventory(settings, scope_path, [], "8080", targets, targets_path=targets)


def test_final_audit_failure_reports_saved_xml(settings, scope_path, tmp_path, monkeypatch):
    original = AuditLog.record

    def fail(self, action, status, **kwargs):
        if status == "completed":
            raise OSError("disk full")
        return original(self, action, status, **kwargs)

    monkeypatch.setattr(AuditLog, "record", fail)
    output = tmp_path / "scan.xml"
    with pytest.raises(RedOpsError, match="was saved"):
        scan_inventory(
            settings, scope_path, ["172.30.77.10"], "8080", output, runner=MockScanRunner(XML)
        )
    assert output.read_bytes() == XML


def test_missing_nmap_is_actionable(scope_path, monkeypatch):
    monkeypatch.setattr(nmap.shutil, "which", lambda name: None)
    with pytest.raises(RedOpsError, match="Nmap is unavailable"):
        NmapRunner().run(plan_scan(load_scope(scope_path), ["172.30.77.10"], "8080"))


@pytest.mark.parametrize("mode", ["success", "exit", "timeout", "oversize"])
def test_process_execution_and_cleanup(scope_path, monkeypatch, mode):
    monkeypatch.setattr(nmap.shutil, "which", lambda name: "/test/nmap")
    plan = plan_scan(load_scope(scope_path), ["172.30.77.10"], "8080")
    ticks = iter([0, 121])
    monkeypatch.setattr(nmap.time, "monotonic", lambda: next(ticks))

    class Process:
        returncode = 2 if mode == "exit" else (None if mode == "timeout" else 0)
        killed = False

        def poll(self):
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -9

        def wait(self, timeout):
            assert timeout == 5

    process = Process()

    def launch(args, **kwargs):
        assert kwargs["shell"] is False
        assert args[0] == "/test/nmap"
        assert args[-1] == "172.30.77.10"
        assert "-sT" in args and "--unprivileged" in args
        assert not any(flag in args for flag in ("-sV", "-sC", "-A", "-O", "--script"))
        kwargs["stdout"].write(XML if mode != "oversize" else b"x" * (nmap.MAX_OUTPUT + 1))
        return process

    monkeypatch.setattr(nmap.subprocess, "Popen", launch)
    if mode == "success":
        assert NmapRunner().run(plan) == XML
    else:
        with pytest.raises(RedOpsError):
            NmapRunner().run(plan)
    assert process.killed is (mode == "timeout")


def test_runner_rechecks_scope_expiry(scope_path, monkeypatch):
    monkeypatch.setattr(nmap.shutil, "which", lambda name: "/test/nmap")
    plan = plan_scan(load_scope(scope_path), ["172.30.77.10"], "8080")
    with pytest.raises(ScopeError):
        NmapRunner().run(replace(plan, expires_at=datetime.now(UTC) + timedelta(milliseconds=10)))
