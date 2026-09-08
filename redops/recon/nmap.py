"""Bounded TCP inventory for explicitly scoped local/private IPv4 lab hosts."""

import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Protocol

from defusedxml import ElementTree

from redops.core.audit import AuditLog
from redops.core.config import Settings
from redops.core.domain import Host
from redops.core.errors import InputError, RedOpsError, ScopeError
from redops.core.io import atomic_write, read_bounded, require_distinct_paths
from redops.core.scope import Scope, load_scope
from redops.recon.parser import parse_nmap

logger = logging.getLogger(__name__)
LAB_NETWORKS = tuple(
    ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    )
)
MAX_OUTPUT = 8 * 1024 * 1024


@dataclass(frozen=True)
class ScanPlan:
    targets: tuple[str, ...]
    ports: tuple[int, ...]
    expires_at: datetime

    def arguments(self) -> list[str]:
        return [
            "-sT",
            "-n",
            "-Pn",
            "--open",
            "--unprivileged",
            "--max-parallelism",
            "4",
            "--max-retries",
            "1",
            "--scan-delay",
            "100ms",
            "--host-timeout",
            "30s",
            "-p",
            ",".join(str(port) for port in self.ports),
            "-oX",
            "-",
            *self.targets,
        ]


def plan_scan(scope: Scope, targets: list[str], ports: str) -> ScanPlan:
    if not 1 <= len(targets) <= min(scope.max_hosts, 16):
        raise ScopeError("Inventory scans require 1–16 explicit hosts within the scope host limit.")
    normalized = []
    try:
        for value in targets:
            address = ip_address(value)
            if address.version != 4 or not any(address in network for network in LAB_NETWORKS):
                raise ScopeError(
                    "Active inventory is limited to private or loopback IPv4 lab addresses."
                )
            normalized.append(str(address))
        if len(set(normalized)) != len(normalized):
            raise ValueError
        parts = ports.split(",")
        if not 1 <= len(parts) <= 32 or not all(
            part.isascii() and part.isdecimal() for part in parts
        ):
            raise ValueError
        numbers = tuple(sorted({int(part) for part in parts}))
        if len(numbers) != len(parts) or any(not 1 <= port <= 65535 for port in numbers):
            raise ValueError
    except ValueError as exc:
        raise InputError(
            "Provide unique literal IPv4 addresses and 1–32 comma-separated TCP ports."
        ) from exc
    scope.validate(tuple(Host(ip, (ip,), "", "", ()) for ip in normalized))
    return ScanPlan(tuple(normalized), numbers, scope.expires_at)


class ScanRunner(Protocol):
    def run(self, plan: ScanPlan) -> bytes:
        """Return a completed Nmap XML document or raise an execution error."""


class NmapRunner:
    def run(self, plan: ScanPlan) -> bytes:
        binary = shutil.which("nmap")
        if binary is None:
            raise RedOpsError("Nmap is unavailable; install it or use the inventory lab container.")
        budget = min(120.0, (plan.expires_at - datetime.now(UTC)).total_seconds())
        if budget < 1:
            raise ScopeError("The scope expires too soon to start an inventory scan.")
        deadline = time.monotonic() + budget
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            process = subprocess.Popen(
                [binary, *plan.arguments()],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=errors,
                shell=False,
            )
            try:
                while True:
                    if (
                        os.fstat(output.fileno()).st_size > MAX_OUTPUT
                        or os.fstat(errors.fileno()).st_size > 1024 * 1024
                    ):
                        raise RedOpsError("Nmap output exceeded its size limit.")
                    if process.poll() is not None:
                        break
                    if time.monotonic() >= deadline:
                        raise RedOpsError("Nmap exceeded its execution or scope-expiry deadline.")
                    time.sleep(0.05)
                if process.returncode != 0:
                    raise RedOpsError(
                        f"Nmap inventory failed with exit status {process.returncode}."
                    )
                output.seek(0)
                content = output.read(MAX_OUTPUT + 1)
                if len(content) > MAX_OUTPUT:
                    raise RedOpsError("Nmap output exceeded its size limit.")
                return content
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)


@dataclass(frozen=True)
class MockScanRunner:
    """Supply recorded output to exercise execution, validation, and persistence offline."""

    xml: bytes

    def run(self, plan: ScanPlan) -> bytes:
        return self.xml


def scan_inventory(
    settings: Settings,
    scope_path: Path,
    targets: list[str],
    ports: str,
    output_path: Path,
    *,
    dry_run: bool = False,
    runner: ScanRunner | None = None,
    targets_path: Path | None = None,
) -> dict[str, Any]:
    paths = [*settings.storage_paths(), scope_path, output_path]
    if targets_path is not None:
        paths.append(targets_path)
    require_distinct_paths(paths)
    audit = AuditLog(settings.audit_path)
    saved = False
    operator = "unknown"
    audit.record("scan", "started", dry_run=dry_run)
    try:
        scope = load_scope(scope_path)
        operator = scope.operator
        if targets_path is not None:
            targets = [
                line.strip()
                for line in read_bounded(targets_path, 64 * 1024).decode().splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
        plan = plan_scan(scope, targets, ports)
        if output_path.exists():
            raise InputError("Scan output already exists; choose a new output path.")
        result: dict[str, Any] = {
            "status": "preview" if dry_run else "completed",
            "targets": plan.targets,
            "ports": plan.ports,
            "profile": "tcp-connect-inventory",
            "output": str(output_path),
            "scope": scope.snapshot(),
            "limitations": [
                "Only TCP reachability is checked; service names are port-table guesses.",
                "Hosts without recorded open ports are not proof of absence or security.",
            ],
        }
        if not dry_run:
            content = (runner or NmapRunner()).run(plan)
            hosts = parse_nmap(content, allow_empty=True)
            root = ElementTree.fromstring(content, forbid_entities=True, forbid_external=True)
            finished = root.find("runstats/finished")
            if finished is None or finished.get("exit") != "success":
                raise InputError("Nmap output is incomplete; no inventory file was saved.")
            if any(node.get("timedout") == "true" for node in root.findall("host")):
                raise InputError("Nmap reported a host timeout; no inventory file was saved.")
            scope.validate(hosts)
            for host in hosts:
                if any(ip not in plan.targets for ip in host.addresses):
                    raise ScopeError("Nmap returned an address outside the requested host set.")
                if any(
                    service.port.number not in plan.ports or service.port.protocol != "tcp"
                    for service in host.services
                ):
                    raise InputError("Nmap returned a port outside the requested inventory plan.")
            atomic_write(output_path, content, overwrite=False)
            saved = True
            observed = {host.ip for host in hosts if host.services}
            result.update(
                hosts=[asdict(host) for host in hosts],
                targets_without_open_ports=sorted(set(plan.targets) - observed),
                sha256=hashlib.sha256(content).hexdigest(),
            )
            logger.info("Inventory scan recorded %s hosts", len(hosts))
        audit.record("scan", result["status"], operator=operator, target_count=len(plan.targets))
        return result
    except Exception as exc:
        if saved:
            raise RedOpsError(
                "Inventory XML was saved, but the final audit append failed."
            ) from exc
        audit.record("scan", "failed", operator=operator, error_type=type(exc).__name__)
        raise
