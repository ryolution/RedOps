import importlib.util
import json
import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer


def test_healthy_inventory_fixture_routes(labs, monkeypatch):
    spec = importlib.util.spec_from_file_location("lab_server", labs / "inventory" / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("LAB_SERVICE_NAME", "test-fixture")
    with ThreadingHTTPServer(("127.0.0.1", 0), module.Handler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            for path, status, field, value in (
                ("/health", 200, "status", "ok"),
                ("/metadata", 200, "name", "test-fixture"),
                ("/server.py", 404, "error", "not_found"),
            ):
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                try:
                    connection.request("GET", path)
                    response = connection.getresponse()
                    assert response.status == status
                    assert json.loads(response.read())[field] == value
                finally:
                    connection.close()
        finally:
            server.shutdown()
            worker.join(timeout=3)
