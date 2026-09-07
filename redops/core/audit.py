"""Structured local audit events. Not an authenticated or tamper-proof journal."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path


class AuditLog:
    def __init__(self, path: Path):
        self.path = path

    def record(
        self, action: str, status: str, *, operator: str = "unknown", **fields: object
    ) -> None:
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "action": action,
            "status": status,
            "operator": operator,
            **fields,
        }
        data = (json.dumps(event, sort_keys=True, allow_nan=False) + "\n").encode()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        try:
            if os.write(descriptor, data) != len(data):
                raise OSError("Incomplete audit append")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
