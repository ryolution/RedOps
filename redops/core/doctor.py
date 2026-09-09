"""Read local readiness without contacting services or creating application storage."""

import logging
import os
import shutil
import sqlite3
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

from redops.core.config import Settings
from redops.core.errors import RedOpsError
from redops.core.io import require_distinct_paths
from redops.database.schema import CURRENT_SCHEMA, schema_version

logger = logging.getLogger(__name__)
PACKAGE = Path(__file__).resolve().parents[1]
REQUIRED_FILES = (
    "web/templates/base.html",
    "web/templates/login.html",
    "web/templates/history.html",
    "web/templates/assessment.html",
    "web/templates/finding.html",
    "web/templates/error.html",
    "web/templates/macros.html",
    "web/static/app.css",
    "web/static/app.js",
    "web/static/redops-mark.png",
    "reporting/fonts/DejaVuSans.ttf",
    "reporting/fonts/DejaVuSans-Bold.ttf",
    "reporting/fonts/LICENSE.txt",
)
DEPENDENCIES = (
    "SQLAlchemy",
    "PyYAML",
    "defusedxml",
    "msgpack",
    "fpdf2",
    "fastapi",
    "uvicorn",
    "Jinja2",
    "uharfbuzz",
    "fonttools",
)


def diagnose(settings: Settings) -> dict:
    checks = []

    def record(name: str, status: str, detail: str) -> None:
        checks.append({"check": name, "status": status, "detail": detail})

    supported = sys.version_info[:2] in {(3, 11), (3, 13), (3, 14)}
    record("python", "ok" if supported else "warning", sys.version.split()[0])
    for dependency in DEPENDENCIES:
        try:
            record("dependency:" + dependency, "ok", version(dependency))
        except PackageNotFoundError:
            record("dependency:" + dependency, "error", "Required distribution is missing.")
    for filename in REQUIRED_FILES:
        present = (PACKAGE / filename).is_file() and os.access(PACKAGE / filename, os.R_OK)
        record(
            "asset:" + filename, "ok" if present else "error", "Readable" if present else "Missing"
        )
    record("nmap", "ok" if shutil.which("nmap") else "warning", "Optional TCP inventory executable")
    try:
        require_distinct_paths(settings.storage_paths())
        record("storage_paths", "ok", "Database and audit paths are distinct.")
    except (ValueError, SQLAlchemyError, RedOpsError, OSError):
        record("storage_paths", "error", "Invalid or conflicting storage configuration.")

    try:
        url = make_url(settings.database_url)
        backend = url.get_backend_name()
        if backend not in {"sqlite", "postgresql"}:
            record("database", "error", "Only SQLite and PostgreSQL are supported.")
        elif backend == "postgresql":
            record(
                "database",
                "warning",
                "PostgreSQL configured; schema requires a separate live check.",
            )
            try:
                record("postgres_driver", "ok", version("psycopg"))
            except PackageNotFoundError:
                record("postgres_driver", "error", "Install the PostgreSQL dependency extra.")
        elif url.database in {None, "", ":memory:"}:
            record(
                "database",
                "warning",
                "In-memory storage is not persistent and cannot be inspected.",
            )
        else:
            _sqlite_check(Path(url.database), record)
    except (ValueError, SQLAlchemyError, RedOpsError, sqlite3.Error, OSError):
        record("database", "error", "Database configuration or local schema is incompatible.")

    token = os.environ.get("REDOPS_API_TOKEN", "")
    record(
        "api_token",
        "ok" if 32 <= len(token) <= 4096 else "warning" if not token else "error",
        "Configured"
        if 32 <= len(token) <= 4096
        else "Dashboard requires a 32–4096 character token.",
    )
    http = os.environ.get("REDOPS_UI_ALLOW_HTTP", "0")
    record(
        "ui_transport",
        "ok" if http in {"0", "1"} else "error",
        "HTTPS required"
        if http == "0"
        else "Loopback development only"
        if http == "1"
        else "Invalid setting",
    )
    operator = os.environ.get("REDOPS_OPERATOR")
    valid = (
        operator is None
        or bool(operator.strip())
        and len(operator) <= 200
        and "\x00" not in operator
    )
    record(
        "operator",
        "ok" if valid else "error",
        "Valid attribution" if valid else "Invalid attribution",
    )
    try:
        rpc = urlsplit(os.environ.get("REDOPS_MSF_URL", "https://127.0.0.1:55553/api/1.0"))
        valid = (
            rpc.scheme == "https"
            and bool(rpc.hostname)
            and not any((rpc.username, rpc.password, rpc.query, rpc.fragment))
            and (rpc.port is None or 1 <= rpc.port <= 65535)
        )
    except ValueError:
        valid = False
    record(
        "rpc_url", "ok" if valid else "error", "HTTPS endpoint syntax checked; no connection made."
    )
    credentials = bool(os.environ.get("REDOPS_MSF_USERNAME")) and bool(
        os.environ.get("REDOPS_MSF_PASSWORD")
    )
    record(
        "rpc_credentials",
        "ok" if credentials else "warning",
        "Configured" if credentials else "Optional live health credentials are not configured.",
    )
    ca = os.environ.get("REDOPS_MSF_CA_FILE")
    if ca:
        available = Path(ca).is_file() and os.access(ca, os.R_OK)
        record(
            "rpc_ca",
            "ok" if available else "error",
            "Readable CA file" if available else "CA file unavailable",
        )
    audit_parent = settings.audit_path.resolve().parent
    while not audit_parent.exists() and audit_parent != audit_parent.parent:
        audit_parent = audit_parent.parent
    writable = os.access(
        settings.audit_path if settings.audit_path.exists() else audit_parent, os.W_OK
    )
    record(
        "audit_access",
        "ok" if writable else "warning",
        "Permission check only; no audit event written.",
    )
    status = (
        "error"
        if any(item["status"] == "error" for item in checks)
        else ("attention" if any(item["status"] == "warning" for item in checks) else "ok")
    )
    logger.info("Local diagnostics completed: %s", status)
    return {"status": status, "network_requests": 0, "storage_created": False, "checks": checks}


def _sqlite_check(path: Path, record) -> None:
    if not path.is_file():
        record("database", "warning", "No local database yet; initialize with the CLI.")
        return
    if Path(str(path) + "-wal").exists() or Path(str(path) + "-journal").exists():
        record(
            "database",
            "warning",
            "Journal present; stop writers and checkpoint before offline schema inspection.",
        )
        return
    # Immutable read-only mode cannot create journals or shared-memory sidecars.
    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    engine = create_engine("sqlite://", creator=lambda: sqlite3.connect(uri, uri=True))
    try:
        with engine.connect() as connection:
            current = schema_version(connection)
        record(
            "database",
            "ok" if current == CURRENT_SCHEMA else "warning",
            f"Schema {current}; expected {CURRENT_SCHEMA}."
            + (" Review writes require migration." if current < CURRENT_SCHEMA else ""),
        )
    finally:
        engine.dispose()
