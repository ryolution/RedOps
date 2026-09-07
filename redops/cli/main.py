"""CLI entry point; machine-readable stdout and concise errors on stderr."""

import argparse
import getpass
import json
import sys
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

from redops.core.audit import AuditLog
from redops.core.config import Settings
from redops.core.errors import RedOpsError
from redops.core.io import require_distinct_paths
from redops.core.workflow import run_assessment
from redops.database.repository import Repository
from redops.metasploit.rpc import MetasploitClient
from redops.reporting.benchmark import calculate_benchmark
from redops.reporting.render import export_report


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="RedOps inventory and vulnerability evidence assessment"
    )
    root.add_argument("--about", action="version", version="RedOps — Offensive Automation Toolkit")
    root.add_argument(
        "--database", help="SQLAlchemy URL; defaults to REDOPS_DATABASE_URL or local SQLite"
    )
    root.add_argument("--audit", type=Path, help="Audit JSONL path; defaults to REDOPS_AUDIT_PATH")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Initialize schema version 1 in a new database")
    inventory = commands.add_parser("inventory", help="Read an assessment's stored inventory")
    inventory.add_argument("--assessment", help="Assessment ID; default is the latest assessment")
    report = commands.add_parser("report", help="Export a stored assessment")
    report.add_argument("--assessment")
    report.add_argument("--format", choices=["json", "html"], default="html")
    report.add_argument("--output", type=Path, required=True)
    workflow = commands.add_parser("workflow", help="Run an offline assessment")
    run = workflow.add_subparsers(dest="workflow_command", required=True).add_parser("run")
    analyze = commands.add_parser("analyze", help="Analyze scoped, previously collected Nmap XML")
    for command in (run, analyze):
        command.add_argument("--scope", type=Path, required=True)
        command.add_argument("--input", type=Path, required=True, help="Existing Nmap XML file")
        command.add_argument("--catalog", type=Path, required=True, help="Reviewed evidence JSON")
        command.add_argument(
            "--dry-run", action="store_true", help="Preview; only audit events are written"
        )
        command.add_argument("--output-dir", type=Path, help="Export JSON and HTML after saving")
    metasploit = commands.add_parser("metasploit", help="Separate integration health check")
    metasploit.add_subparsers(dest="msf_command", required=True).add_parser("status")
    benchmark = commands.add_parser(
        "benchmark", help="Calculate savings from supplied measurements"
    )
    benchmark.add_argument("--input", type=Path, required=True)
    return root


def dispatch(args: argparse.Namespace, settings: Settings) -> object:
    protected_paths = settings.storage_paths()
    if args.command == "report":
        protected_paths.append(args.output)
    elif args.command == "benchmark":
        protected_paths.append(args.input)
    require_distinct_paths(protected_paths)
    if args.command in {"workflow", "analyze"}:
        if args.dry_run and args.output_dir:
            raise RedOpsError("--output-dir cannot be combined with --dry-run.")
        document = run_assessment(
            settings, args.scope, args.input, args.catalog, dry_run=args.dry_run
        )
        if args.output_dir:
            try:
                for format_name in ("json", "html"):
                    export_report(
                        document, args.output_dir / f"{document['id']}.{format_name}", format_name
                    )
            except OSError as exc:
                raise RedOpsError(
                    f"Assessment {document['id']} was saved, but report export failed."
                ) from exc
        return document

    audit = AuditLog(settings.audit_path)
    operator = getpass.getuser()
    audit.record(args.command, "started", operator=operator)
    try:
        if args.command == "benchmark":
            result = calculate_benchmark(args.input)
        elif args.command == "metasploit":
            result = MetasploitClient.from_env().health()
        else:
            repository = Repository(settings.database_url, create=args.command == "init")
            try:
                if args.command == "init":
                    repository.initialize()
                    result = {"status": "initialized", "schema_version": 1}
                elif args.command == "inventory":
                    result = repository.inventory(args.assessment)
                else:
                    document = repository.get(args.assessment)
                    export_report(document, args.output, args.format)
                    result = {"assessment_id": document["id"], "output": str(args.output)}
            finally:
                repository.close()
        audit.record(args.command, "completed", operator=operator)
        return result
    except Exception as exc:
        audit.record(args.command, "failed", operator=operator, error_type=type(exc).__name__)
        raise


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    defaults = Settings.from_env()
    settings = Settings(args.database or defaults.database_url, args.audit or defaults.audit_path)
    try:
        print(json.dumps(dispatch(args, settings), indent=2, allow_nan=False))
        return 0
    except RedOpsError as exc:
        print(f"redops: {exc}", file=sys.stderr)
    except SQLAlchemyError:
        print("redops: Database operation failed; check connectivity and schema.", file=sys.stderr)
    except OSError:
        print(
            "redops: File or connection operation failed; check paths, permissions, and service.",
            file=sys.stderr,
        )
    except (ValueError, ImportError):
        print(
            "redops: Invalid configuration or a required optional dependency is missing.",
            file=sys.stderr,
        )
    return 2
