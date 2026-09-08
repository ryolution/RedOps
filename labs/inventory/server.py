"""Healthy HTTP fixture: two static routes and no filesystem or command access."""

import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logger = logging.getLogger("redops.lab")


class Handler(BaseHTTPRequestHandler):
    server_version = "RedOpsLab"
    sys_version = ""

    def do_GET(self) -> None:
        if self.path == "/health":
            status, document = 200, {"status": "ok"}
        elif self.path == "/metadata":
            status, document = (
                200,
                {
                    "name": os.environ.get("LAB_SERVICE_NAME", "inventory-fixture"),
                    "purpose": "Healthy local inventory fixture",
                },
            )
        else:
            status, document = 404, {"error": "not_found"}
        content = json.dumps(document).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: object) -> None:
        # Log the response status, without attacker-controlled paths or headers.
        logger.info("HTTP request handled")

    def setup(self) -> None:
        self.request.settimeout(5)
        super().setup()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        with ThreadingHTTPServer(("0.0.0.0", 8080), Handler) as server:
            logger.info("Inventory fixture listening on port 8080")
            server.serve_forever()
    except OSError:
        logger.exception("Inventory fixture could not run")
        raise


if __name__ == "__main__":
    main()
