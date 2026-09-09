"""Controlled TLS/RPC fixtures, explicitly not evidence of a real Metasploit server."""

import io
import json
import shutil
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import msgpack
import pytest

from redops.cli.main import main
from redops.core.errors import InputError, RedOpsError
from redops.metasploit.rpc import MetasploitClient
from redops.metasploit.validation import record_health

PASSWORD = "controlled-fixture-password"
SESSION = "controlled-fixture-session"


@pytest.fixture
def tls_rpc(tmp_path, monkeypatch):
    if not shutil.which("openssl"):
        pytest.skip("OpenSSL is required for the controlled TLS fixture")
    certificate, key = tmp_path / "fixture.crt", tmp_path / "fixture.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
    )
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            method, *arguments = msgpack.unpackb(body, raw=False)
            calls.append(method)
            if method == "auth.login":
                result = (
                    {"result": "success", "token": SESSION}
                    if arguments == ["fixture-user", PASSWORD]
                    else {"result": "failure"}
                )
            elif method == "core.version" and arguments == [SESSION]:
                result = {
                    "version": "controlled-test-fixture",
                    "ruby": "fixture",
                    "extra": PASSWORD,
                }
            elif method == "auth.logout" and arguments == [SESSION]:
                result = {"result": "success"}
            else:
                result = {"error": True}
            data = msgpack.packb(result, use_bin_type=True)
            self.send_response(200)
            self.send_header("Content-Type", "binary/message-pack")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"https://127.0.0.1:{server.server_port}/api/1.0"
    monkeypatch.setenv("REDOPS_MSF_URL", url)
    monkeypatch.setenv("REDOPS_MSF_USERNAME", "fixture-user")
    monkeypatch.setenv("REDOPS_MSF_PASSWORD", PASSWORD)
    monkeypatch.setenv("REDOPS_MSF_CA_FILE", str(certificate))
    try:
        yield url, certificate, calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_trusted_tls_contract_and_sanitized_record(tls_rpc, tmp_path):
    url, certificate, calls = tls_rpc
    output = tmp_path / "controlled-fixture-evidence.json"
    result = record_health(output, environment="controlled-fixture", operator="test-operator")
    assert result["status"] == "passed"
    assert set(result["checks"].values()) == {"passed"}
    assert calls == ["auth.login", "core.version", "auth.logout"]
    assert result["metadata"]["version"] == "controlled-test-fixture"
    assert len(result["trust"]["ca_sha256"]) == 64
    assert json.loads(output.read_text()) == result
    for secret in (PASSWORD, SESSION, "fixture-user", url, str(certificate)):
        assert secret not in output.read_text()
    with pytest.raises(InputError, match="new"):
        record_health(output, environment="controlled-fixture", operator="test-operator")


def test_untrusted_certificate_rejected(tls_rpc):
    url, _, calls = tls_rpc
    with pytest.raises(RedOpsError, match="TLS trust"):
        MetasploitClient(url, "fixture-user", PASSWORD).health()
    assert calls == []


def test_invalid_credentials_save_failed_evidence(tls_rpc, tmp_path, monkeypatch):
    monkeypatch.setenv("REDOPS_MSF_PASSWORD", "wrong-fixture-password")
    output = tmp_path / "failed.json"
    with pytest.raises(RedOpsError, match="failure evidence was saved"):
        record_health(output, environment="controlled-fixture", operator="test-operator")
    result = json.loads(output.read_text())
    assert result["status"] == "failed"
    assert "wrong-fixture-password" not in output.read_text()
    assert tls_rpc[2] == ["auth.login"]


def test_unavailable_service(tls_rpc):
    _, certificate, _ = tls_rpc
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        url = f"https://127.0.0.1:{reserved.getsockname()[1]}"
        with pytest.raises(RedOpsError):
            MetasploitClient(url, "fixture-user", PASSWORD, ca_file=str(certificate)).health()


@pytest.mark.parametrize(
    "response",
    [b"\xc1", b"x" * (1024 * 1024 + 1), msgpack.packb(["invalid"]), msgpack.packb({"error": True})],
)
def test_malformed_and_oversized_responses(response, monkeypatch):
    client = MetasploitClient("https://localhost:55553/api/1.0", "fixture-user", PASSWORD)
    monkeypatch.setattr(client._opener, "open", lambda *args, **kwargs: io.BytesIO(response))
    with pytest.raises(RedOpsError):
        client.health()


def test_timeout_is_bounded_and_does_not_expose_context(monkeypatch):
    client = MetasploitClient("https://localhost:55553/api/1.0", "fixture-user", PASSWORD)

    def timeout(*args, **kwargs):
        assert kwargs["timeout"] == 10
        raise TimeoutError(PASSWORD)

    monkeypatch.setattr(client._opener, "open", timeout)
    with pytest.raises(RedOpsError) as error:
        client.health()
    assert PASSWORD not in str(error.value)


def test_version_and_logout_failures_are_both_reported(monkeypatch):
    client = MetasploitClient("https://localhost:55553/api/1.0", "fixture-user", PASSWORD)

    def request(method, arguments):
        return {"result": "success", "token": SESSION} if method == "auth.login" else {}

    monkeypatch.setattr(client, "_request", request)
    with pytest.raises(RedOpsError, match="health failed and logout"):
        client.health()


def test_metadata_cannot_reflect_credentials(monkeypatch):
    client = MetasploitClient("https://localhost:55553/api/1.0", "fixture-user", PASSWORD)
    replies = iter(
        [
            {"result": "success", "token": SESSION},
            {"version": PASSWORD + " " + SESSION},
            {"result": "success"},
        ]
    )
    monkeypatch.setattr(client, "_request", lambda *args: next(replies))
    assert client.health()["version"] == "[redacted] [redacted]"


def test_cli_evidence_and_mock_rejection(tls_rpc, tmp_path, capsys):
    base = ["--audit", str(tmp_path / "audit.jsonl"), "metasploit", "status"]
    arguments = [
        "--evidence",
        str(tmp_path / "evidence.json"),
        "--environment",
        "fixture",
        "--operator-pseudonym",
        "tester",
    ]
    assert main(base + arguments) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "passed"
    assert main(base + arguments + ["--mock"]) == 2
    assert "mocks cannot" in capsys.readouterr().err
    certificate = tls_rpc[1]
    before = certificate.read_bytes()
    assert main(["--audit", str(certificate), "metasploit", "status"]) == 2
    assert certificate.read_bytes() == before
