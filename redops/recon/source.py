"""Real and mock inventory-parser implementations behind the same contract."""

from dataclasses import dataclass
from typing import Protocol

from redops.core.domain import Host
from redops.recon.parser import parse_nmap


class InventoryParser(Protocol):
    def parse(self, content: bytes) -> tuple[Host, ...]:
        """Parse observations; implementations must not contact targets."""


class NmapXmlParser:
    def parse(self, content: bytes) -> tuple[Host, ...]:
        return parse_nmap(content)


@dataclass(frozen=True)
class MockInventoryParser:
    """Inject predefined observations into workflow tests without an external scanner."""

    hosts: tuple[Host, ...]

    def parse(self, content: bytes) -> tuple[Host, ...]:
        return self.hosts
