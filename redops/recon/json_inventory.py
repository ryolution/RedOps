"""Bounded import of operator-supplied software/OS observations, without inference."""

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address

from redops.core.domain import Host, Port, Service
from redops.core.errors import InputError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class InventoryDocument:
    hosts: tuple[Host, ...]
    source: str
    collected_at: str


def _object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def _text(value: object, limit: int = 10000) -> str:
    if not isinstance(value, str) or len(value) > limit or "\x00" in value:
        raise ValueError
    return value


def parse_inventory_json(content: bytes) -> InventoryDocument:
    if len(content) > 8 * 1024 * 1024:
        raise InputError("Inventory JSON exceeds the 8 MiB limit.")
    try:
        data = json.loads(content, object_pairs_hook=_object)
        if not isinstance(data, dict) or set(data) != {
            "schema",
            "schema_version",
            "source",
            "collected_at",
            "hosts",
        }:
            raise ValueError
        if (
            data["schema"] != "redops-inventory"
            or type(data["schema_version"]) is not int
            or data["schema_version"] != 1
        ):
            raise ValueError
        source = _text(data["source"], 2000).strip()
        collected = datetime.fromisoformat(data["collected_at"].replace("Z", "+00:00"))
        if (
            not source
            or collected.tzinfo is None
            or not isinstance(data["hosts"], list)
            or not 1 <= len(data["hosts"]) <= 512
        ):
            raise ValueError
        hosts, seen = [], set()
        for item in data["hosts"]:
            if not isinstance(item, dict) or set(item) != {
                "ip",
                "addresses",
                "hostname",
                "os",
                "services",
            }:
                raise ValueError
            ip = str(ip_address(_text(item["ip"], 45)))
            if not isinstance(item["addresses"], list) or not 1 <= len(item["addresses"]) <= 128:
                raise ValueError
            addresses = tuple(str(ip_address(_text(value, 45))) for value in item["addresses"])
            if (
                ip not in addresses
                or len(set(addresses)) != len(addresses)
                or seen.intersection(addresses)
            ):
                raise ValueError
            seen.update(addresses)
            if not isinstance(item["services"], list) or len(item["services"]) > 4096:
                raise ValueError
            services, seen_ports = [], set()
            for service in item["services"]:
                if not isinstance(service, dict) or set(service) != {
                    "port",
                    "name",
                    "product",
                    "version",
                    "cpes",
                }:
                    raise ValueError
                port = service["port"]
                if not isinstance(port, dict) or set(port) != {"number", "protocol"}:
                    raise ValueError
                number, protocol = port["number"], port["protocol"]
                if (
                    type(number) is not int
                    or not 1 <= number <= 65535
                    or protocol not in {"tcp", "udp", "sctp"}
                ):
                    raise ValueError
                if (number, protocol) in seen_ports:
                    raise ValueError
                seen_ports.add((number, protocol))
                cpes = service["cpes"]
                if not isinstance(cpes, list) or len(cpes) > 100:
                    raise ValueError
                services.append(
                    Service(
                        Port(number, protocol),
                        _text(service["name"]),
                        _text(service["product"]),
                        _text(service["version"]),
                        tuple(sorted({_text(value, 1000) for value in cpes})),
                    )
                )
            hosts.append(
                Host(
                    ip,
                    addresses,
                    _text(item["hostname"]),
                    _text(item["os"]),
                    tuple(
                        sorted(services, key=lambda value: (value.port.number, value.port.protocol))
                    ),
                )
            )
        result = InventoryDocument(
            tuple(sorted(hosts, key=lambda h: (ip_address(h.ip).version, int(ip_address(h.ip))))),
            source,
            collected.astimezone(UTC).isoformat(),
        )
        logger.info("Imported JSON inventory with %s hosts", len(hosts))
        return result
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        raise InputError(
            "Invalid inventory JSON: check schema, timestamp, addresses, services, and limits."
        ) from exc


class JsonInventoryParser:
    def parse(self, content: bytes) -> tuple[Host, ...]:
        return parse_inventory_json(content).hosts
