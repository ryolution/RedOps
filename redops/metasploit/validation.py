"""Record sanitized health-contract evidence from an operator-configured RPC endpoint."""

import hashlib
import json
import logging
import os
import platform
import re
import time
from datetime import UTC, datetime
from pathlib import Path

from redops.core.errors import InputError, RedOpsError
from redops.core.io import atomic_write, read_bounded
from redops.metasploit.rpc import MetasploitClient

logger = logging.getLogger(__name__)


def record_health(output: Path, *, environment: str, operator: str) -> dict:
    for label in (environment, operator):
        if not isinstance(label, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}", label
        ):
            raise InputError("Health evidence requires an environment ID and operator pseudonym.")
    if output.exists():
        raise InputError("Health evidence destination must be new.")
    record = {
        "schema": "redops-rpc-health-evidence",
        "schema_version": 1,
        "environment_id": environment,
        "operator": operator,
        "started_at": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "platform": platform.system(),
        "provider": "operator_configured_rpc",
        "status": "failed",
        "checks": {
            name: "not_confirmed"
            for name in ("authentication", "version_retrieval", "tls_trust", "logout")
        },
        "interpretation": (
            "Verifies the TLS/RPC health contract; "
            "the operator must attest to the actual server environment."
        ),
    }
    started = time.monotonic()
    failure = None
    try:
        ca_file = os.environ.get("REDOPS_MSF_CA_FILE")
        record["trust"] = {
            "mode": "configured_ca" if ca_file else "system_ca",
            "ca_sha256": hashlib.sha256(read_bounded(Path(ca_file), 1024 * 1024)).hexdigest()
            if ca_file
            else None,
        }
        record["metadata"] = MetasploitClient.from_env().health()
        record["status"] = "passed"
        record["checks"] = dict.fromkeys(record["checks"], "passed")
    except (RedOpsError, OSError, ValueError) as exc:
        failure = exc
        record["error"] = (
            "Health contract was not verified; "
            "inspect local service, credentials, TLS trust and logout."
        )
    record["completed_at"] = datetime.now(UTC).isoformat()
    record["duration_seconds"] = time.monotonic() - started
    atomic_write(output, json.dumps(record, indent=2, allow_nan=False) + "\n", overwrite=False)
    logger.info("Recorded RPC health validation: %s", record["status"])
    if failure is not None:
        raise RedOpsError(
            "RPC health validation failed; sanitized failure evidence was saved."
        ) from failure
    return record
