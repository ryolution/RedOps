import io

import msgpack
import pytest

from redops.core.errors import RedOpsError
from redops.metasploit.rpc import MetasploitClient, NoRedirects


def client():
    return MetasploitClient("https://localhost:55553/api/1.0", "test-user", "test-only-secret")


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/api",
        "https://name:secret@localhost/api",
        "https://localhost/api?token=test",
    ],
)
def test_tls_and_credential_free_url_required(url):
    with pytest.raises(RedOpsError):
        MetasploitClient(url, "name", "test-only-secret")


def test_health_transport_and_logout(monkeypatch):
    instance = client()
    calls = []
    responses = iter(
        [
            {"result": "success", "token": "test-only-token"},
            {"version": "test-version", "ruby": "test-ruby", "extra": "discard"},
            {"result": "success"},
        ]
    )

    def open_request(request, timeout):
        calls.append(msgpack.unpackb(request.data, raw=False))
        assert timeout == 10
        assert request.get_header("Content-type") == "binary/message-pack"
        return io.BytesIO(msgpack.packb(next(responses), use_bin_type=True))

    monkeypatch.setattr(instance._opener, "open", open_request)
    assert instance.health() == {"version": "test-version", "ruby": "test-ruby"}
    assert [call[0] for call in calls] == ["auth.login", "core.version", "auth.logout"]
    assert calls[1][1] == "test-only-token"


def test_redirects_refused():
    with pytest.raises(RedOpsError, match="redirects"):
        NoRedirects().redirect_request(None, None, 302, "", {}, "https://example.invalid")


def test_logout_after_version_failure(monkeypatch):
    instance = client()
    calls = []

    def request(method, arguments):
        calls.append(method)
        if method == "auth.login":
            return {"result": "success", "token": "test-only-token"}
        if method == "core.version":
            raise RedOpsError("simulated integration failure")
        return {"result": "success"}

    monkeypatch.setattr(instance, "_request", request)
    with pytest.raises(RedOpsError, match="integration"):
        instance.health()
    assert calls[-1] == "auth.logout"


def test_no_general_rpc_interface():
    with pytest.raises(RedOpsError, match="outside"):
        client()._request("unsupported.method", [])
