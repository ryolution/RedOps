"""Strict, offline IP scope validation."""

from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from pathlib import Path
from typing import Any

import yaml

from redops.core.domain import Host
from redops.core.errors import ScopeError
from redops.core.io import read_bounded


@dataclass(frozen=True)
class Scope:
    engagement: str
    operator: str
    authorized_by: str
    expires_at: datetime
    networks: tuple[IPv4Network | IPv6Network, ...]
    max_hosts: int

    def validate(self, hosts: tuple[Host, ...], now: datetime | None = None) -> None:
        if self.expires_at <= (now or datetime.now(UTC)):
            raise ScopeError("The scope declaration has expired.")
        if len(hosts) > self.max_hosts:
            raise ScopeError("Imported host count exceeds the declared limit.")
        for host in hosts:
            for value in host.addresses:
                address = ip_address(value)
                if not any(
                    address.version == net.version and address in net for net in self.networks
                ):
                    raise ScopeError(
                        f"Imported address {address} is outside the declared allowlist."
                    )

    def snapshot(self) -> dict[str, Any]:
        return {
            "engagement": self.engagement,
            "operator": self.operator,
            "authorized_by": self.authorized_by,
            "expires_at": self.expires_at.isoformat(),
            "allowlist": [str(net) for net in self.networks],
            "max_hosts": self.max_hosts,
        }


def load_scope(path: Path) -> Scope:
    try:
        data = yaml.safe_load(read_bounded(path, 64 * 1024))
        required = {
            "engagement",
            "operator",
            "authorized_by",
            "expires_at",
            "allowlist",
            "max_hosts",
        }
        if not isinstance(data, dict) or set(data) != required:
            raise ValueError
        for key in ("engagement", "operator", "authorized_by"):
            if not isinstance(data[key], str) or not data[key].strip() or len(data[key]) > 200:
                raise ValueError
        expiry = data["expires_at"]
        if isinstance(expiry, str):
            expiry = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        if not isinstance(expiry, datetime) or expiry.tzinfo is None:
            raise ValueError
        allowlist = data["allowlist"]
        if not isinstance(allowlist, list) or not 1 <= len(allowlist) <= 128:
            raise ValueError
        if not all(isinstance(value, str) for value in allowlist):
            raise ValueError
        networks = tuple(ip_network(value, strict=True) for value in allowlist)
        if type(data["max_hosts"]) is not int or not 1 <= data["max_hosts"] <= 512:
            raise ValueError
        result = Scope(
            engagement=data["engagement"].strip(),
            operator=data["operator"].strip(),
            authorized_by=data["authorized_by"].strip(),
            expires_at=expiry.astimezone(UTC),
            networks=networks,
            max_hosts=data["max_hosts"],
        )
        result.validate(())
        return result
    except (ValueError, TypeError, KeyError, yaml.YAMLError, RecursionError) as exc:
        raise ScopeError(
            "Invalid scope: check required fields, CIDRs, host limit, and UTC expiry."
        ) from exc
