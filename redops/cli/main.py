"""CLI entry point; machine-readable stdout and concise errors on stderr."""

import argparse
import getpass
import json
import logging
import os
import sys
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

from redops.core.audit import AuditLog
from redops.core.config import Settings
from redops.core.errors import RedOpsError
from redops.core.io import read_bounded, require_distinct_paths
from redops.core.reviews import DISPOSITIONS
from redops.core.workflow import run_assessment
from redops.database.maintenance import (
    backup_database,
    database_status,
    migrate_database,
    prune_database,
    restore_database,
)
from redops.database.repository import Repository
from redops.database.reviews import add_review, list_reviews
from redops.intelligence.advisories import AdvisoryProvider, MockAdvisoryProvider
from redops.intelligence.cve import validate_catalog
from redops.intelligence.nvd import CachedAdvisoryProvider, NvdClient
from redops.metasploit.health import HealthProvider, MockMetasploitClient
from redops.metasploit.rpc import MetasploitClient
from redops.metasploit.validation import record_health
from redops.recon.nmap import scan_inventory
from redops.reporting.benchmark import calculate_benchmark
from redops.reporting.document import report_document
from redops.reporting.render import export_report
from redops.reporting.trials import OUTPUTS, benchmark_trials


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="RedOps inventory and vulnerability evidence assessment"
    )
    root.add_argument("--about", action="version", version="RedOps — Offensive Automation Toolkit")
    root.add_argument(
        "--database", help="SQLAlchemy URL; defaults to REDOPS_DATABASE_URL or local SQLite"
    )
    root.add_argument("--audit", type=Path, help="Audit JSONL path; defaults to REDOPS_AUDIT_PATH")
    root.add_argument("--verbose", action="store_true", help="Write operational logs to stderr")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Initialize an empty database with the current schema")
    commands.add_parser("doctor", help="Check local readiness without writes or network access")
    review = commands.add_parser("review", help="Inspect or append operator finding decisions")
    reviews = review.add_subparsers(dest="review_command", required=True)
    listing = reviews.add_parser("list")
    listing.add_argument("--assessment", required=True)
    listing.add_argument("--finding")
    listing.add_argument("--limit", type=int, default=50)
    listing.add_argument("--offset", type=int, default=0)
    adding = reviews.add_parser("add")
    adding.add_argument("--assessment", required=True)
    adding.add_argument("--finding", required=True)
    adding.add_argument("--disposition", choices=DISPOSITIONS, required=True)
    adding.add_argument("--notes", default="")
    adding.add_argument(
        "--expected-previous",
        type=int,
        required=True,
        help="Latest review ID, or 0 for the first decision",
    )
    database = commands.add_parser("database", help="Backup, restore, migration, and retention")
    maintenance = database.add_subparsers(dest="database_command", required=True)
    maintenance.add_parser("status", help="Check schema compatibility and row counts")
    backup = maintenance.add_parser("backup", help="Save a consistent portable database archive")
    backup.add_argument("--output", type=Path, required=True)
    restore = maintenance.add_parser("restore", help="Restore into an empty database")
    restore.add_argument("--input", type=Path, required=True)
    migrate = maintenance.add_parser(
        "migrate", help="Back up and apply the supported schema upgrade"
    )
    migrate.add_argument("--backup", type=Path, required=True)
    prune = maintenance.add_parser(
        "prune", help="Preview old assessment removal; explicit apply required"
    )
    prune.add_argument("--engagement", required=True)
    prune.add_argument(
        "--before", required=True, help="Exclusive ISO 8601 cutoff, including timezone"
    )
    prune.add_argument("--keep-latest", type=int, default=1)
    prune.add_argument("--apply", action="store_true")
    prune.add_argument("--backup", type=Path, help="New backup file; mandatory with --apply")
    scan = commands.add_parser("scan", help="Bounded TCP inventory of scoped private lab hosts")
    scan.add_argument("--scope", type=Path, required=True)
    targets = scan.add_mutually_exclusive_group(required=True)
    targets.add_argument("--target", action="append", help="Literal IPv4 address; repeat per host")
    targets.add_argument("--targets-file", type=Path, help="One literal IPv4 address per line")
    scan.add_argument("--ports", required=True, help="1–32 comma-separated TCP port numbers")
    scan.add_argument("--output", type=Path, required=True, help="New XML file; never overwritten")
    scan.add_argument(
        "--dry-run", action="store_true", help="Validate plan; write only audit events"
    )
    inventory = commands.add_parser("inventory", help="Read an assessment's stored inventory")
    inventory.add_argument("--assessment", help="Assessment ID; default is the latest assessment")
    report = commands.add_parser("report", help="Export a stored assessment")
    report.add_argument("--assessment")
    report.add_argument("--format", choices=["json", "html", "pdf"], default="html")
    report.add_argument("--output", type=Path, required=True)
    report.add_argument("--include-reviews", action="store_true")
    workflow = commands.add_parser("workflow", help="Run an offline assessment")
    run = workflow.add_subparsers(dest="workflow_command", required=True).add_parser("run")
    analyze = commands.add_parser("analyze", help="Analyze scoped, previously collected Nmap XML")
    for command in (run, analyze):
        command.add_argument("--scope", type=Path, required=True)
        command.add_argument("--input", type=Path, required=True, help="Existing Nmap XML file")
        command.add_argument(
            "--input-format", choices=["nmap-xml", "inventory-json"], default="nmap-xml"
        )
        command.add_argument("--catalog", type=Path, required=True, help="Reviewed evidence JSON")
        command.add_argument(
            "--dry-run", action="store_true", help="Preview; only audit events are written"
        )
        command.add_argument(
            "--output-dir", type=Path, help="Export JSON, HTML, and PDF after saving"
        )
        command.add_argument(
            "--nvd", choices=["online", "offline"], help="Attach NVD advisories to candidates"
        )
        command.add_argument(
            "--cache", type=Path, default=Path(os.environ.get("REDOPS_NVD_CACHE", "data/nvd-cache"))
        )
    metasploit = commands.add_parser("metasploit", help="Separate integration health check")
    status = metasploit.add_subparsers(dest="msf_command", required=True).add_parser("status")
    status.add_argument(
        "--mock", action="store_true", help="Use an explicitly marked offline fixture"
    )
    status.add_argument("--evidence", type=Path, help="New sanitized live-health evidence file")
    status.add_argument("--environment", help="Environment ID for live evidence")
    status.add_argument("--operator-pseudonym", help="Operator attribution for live evidence")
    intelligence = commands.add_parser("intelligence", help="CVE advisory lookup")
    intelligence_commands = intelligence.add_subparsers(dest="intelligence_command", required=True)
    lookup = intelligence_commands.add_parser("lookup")
    catalog = intelligence_commands.add_parser("catalog")
    validate = catalog.add_subparsers(dest="catalog_command", required=True).add_parser("validate")
    validate.add_argument("--input", type=Path, required=True)
    lookup.add_argument("--cve", required=True)
    sources = lookup.add_mutually_exclusive_group()
    sources.add_argument("--mock", action="store_true")
    sources.add_argument(
        "--offline", action="store_true", help="Require a fresh cache record; never use the network"
    )
    lookup.add_argument(
        "--cache", type=Path, default=Path(os.environ.get("REDOPS_NVD_CACHE", "data/nvd-cache"))
    )
    benchmark = commands.add_parser(
        "benchmark", help="Calculate savings from supplied measurements"
    )
    measurements = benchmark.add_mutually_exclusive_group(required=True)
    measurements.add_argument("--input", type=Path, help="Legacy aggregate CSV")
    measurements.add_argument("--trials", type=Path, help="Paired full-task CSV")
    benchmark.add_argument(
        "--output-dir", type=Path, help="New paired benchmark artifact directory"
    )
    assessments = commands.add_parser("assessments", help="List saved assessment summaries")
    assessments.add_argument("--engagement")
    assessments.add_argument("--limit", type=int, default=50)
    assessments.add_argument("--offset", type=int, default=0)
    serve = commands.add_parser("serve", help="Start the authenticated dashboard and API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    return root


def dispatch(args: argparse.Namespace, settings: Settings) -> object:
    if args.command == "doctor":
        from redops.core.doctor import diagnose

        return diagnose(settings)
    protected_paths = settings.storage_paths()
    if args.command == "report":
        protected_paths.append(args.output)
    elif args.command == "benchmark":
        protected_paths.append(args.input or args.trials)
        if args.output_dir:
            if not args.trials:
                raise RedOpsError("--output-dir requires --trials.")
            protected_paths.extend(args.output_dir / name for name in OUTPUTS)
    elif args.command == "intelligence" and args.intelligence_command == "catalog":
        protected_paths.append(args.input)
    elif args.command == "metasploit":
        if args.evidence:
            if args.mock or not args.environment or not args.operator_pseudonym:
                raise RedOpsError(
                    "Live evidence requires --environment and --operator-pseudonym; "
                    "mocks cannot supply it."
                )
            protected_paths.append(args.evidence)
        elif args.environment or args.operator_pseudonym:
            raise RedOpsError("Evidence attribution requires --evidence.")
        if os.environ.get("REDOPS_MSF_CA_FILE") and not args.mock:
            protected_paths.append(Path(os.environ["REDOPS_MSF_CA_FILE"]))
    require_distinct_paths(protected_paths)
    if args.command == "review":
        if args.review_command == "list":
            return list_reviews(
                settings, args.assessment, args.finding, limit=args.limit, offset=args.offset
            )
        return add_review(
            settings,
            args.assessment,
            args.finding,
            disposition=args.disposition,
            notes=args.notes,
            expected_previous=args.expected_previous,
            operator=getpass.getuser(),
        )
    if args.command == "database":
        if args.database_command == "status":
            return database_status(settings)
        if args.database_command == "backup":
            return backup_database(settings, args.output)
        if args.database_command == "restore":
            return restore_database(settings, args.input)
        if args.database_command == "migrate":
            return migrate_database(settings, args.backup)
        return prune_database(
            settings,
            engagement=args.engagement,
            before=args.before,
            keep_latest=args.keep_latest,
            apply=args.apply,
            backup=args.backup,
        )
    if args.command == "scan":
        return scan_inventory(
            settings,
            args.scope,
            args.target or [],
            args.ports,
            args.output,
            dry_run=args.dry_run,
            targets_path=args.targets_file,
        )
    if args.command in {"workflow", "analyze"}:
        if args.dry_run and args.output_dir:
            raise RedOpsError("--output-dir cannot be combined with --dry-run.")
        if args.dry_run and args.nvd:
            raise RedOpsError("--nvd cannot be combined with --dry-run.")
        provider = None
        if args.nvd:
            provider = CachedAdvisoryProvider(
                args.cache,
                NvdClient() if args.nvd == "online" else None,
                protected_paths=tuple([*protected_paths, args.scope, args.input, args.catalog]),
            )
        document = run_assessment(
            settings,
            args.scope,
            args.input,
            args.catalog,
            dry_run=args.dry_run,
            advisory_provider=provider,
            input_format=args.input_format,
        )
        if args.output_dir:
            try:
                for format_name in ("json", "html", "pdf"):
                    export_report(
                        document, args.output_dir / f"{document['id']}.{format_name}", format_name
                    )
            except (OSError, RedOpsError) as exc:
                raise RedOpsError(
                    f"Assessment {document['id']} was saved, but report export failed."
                ) from exc
        return document

    audit = AuditLog(settings.audit_path)
    operator = getpass.getuser()
    audit.record(args.command, "started", operator=operator)
    try:
        if args.command == "benchmark":
            result = (
                benchmark_trials(
                    args.trials, args.output_dir, protected_paths=settings.storage_paths()
                )
                if args.trials
                else calculate_benchmark(args.input)
            )
        elif args.command == "serve":
            import uvicorn

            from redops.api.app import create_app

            if not 1 <= args.port <= 65535:
                raise RedOpsError("API port must be between 1 and 65535.")
            uvicorn.run(
                create_app(settings, allow_http_ui=args.host in {"127.0.0.1", "localhost", "::1"}),
                host=args.host,
                port=args.port,
                access_log=False,
                workers=1,
            )
            result = {"status": "stopped"}
        elif args.command == "intelligence" and args.intelligence_command == "catalog":
            result = validate_catalog(read_bounded(args.input))
        elif args.command == "intelligence":
            advisory_source: AdvisoryProvider = (
                MockAdvisoryProvider()
                if args.mock
                else CachedAdvisoryProvider(
                    args.cache,
                    None if args.offline else NvdClient(),
                    protected_paths=tuple(protected_paths),
                )
            )
            result = advisory_source.lookup(args.cve).to_dict()
        elif args.command == "metasploit":
            if args.evidence:
                result = record_health(
                    args.evidence, environment=args.environment, operator=args.operator_pseudonym
                )
            else:
                health_source: HealthProvider = (
                    MockMetasploitClient() if args.mock else MetasploitClient.from_env()
                )
                result = health_source.health()
        else:
            repository = Repository(settings.database_url, create=args.command == "init")
            try:
                if args.command == "init":
                    version = repository.initialize()
                    result = {"status": "initialized", "schema_version": version}
                elif args.command == "inventory":
                    result = repository.inventory(args.assessment)
                elif args.command == "assessments":
                    result = repository.list_assessments(
                        engagement=args.engagement,
                        limit=args.limit,
                        offset=args.offset,
                    )
                else:
                    document = report_document(
                        repository, args.assessment, include_reviews=args.include_reviews
                    )
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
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    defaults = Settings.from_env()
    settings = Settings(args.database or defaults.database_url, args.audit or defaults.audit_path)
    try:
        result = dispatch(args, settings)
        print(json.dumps(result, indent=2, allow_nan=False))
        if args.command == "doctor" and result["status"] == "error":
            return 2
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
