"""Defensive Nmap XML parser. Does not launch scanners or process NSE output."""

import logging
from ipaddress import ip_address
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from redops.core.domain import Host, Port, Service
from redops.core.errors import InputError

logger = logging.getLogger(__name__)


def parse_nmap(content: bytes, *, allow_empty: bool = False) -> tuple[Host, ...]:
    if len(content) > 8 * 1024 * 1024:
        raise InputError("Nmap XML exceeds the 8 MiB limit.")
    try:
        root = ElementTree.fromstring(content, forbid_entities=True, forbid_external=True)
    except (ParseError, DefusedXmlException, ValueError) as exc:
        raise InputError("Invalid or unsafe Nmap XML.") from exc
    if root.tag != "nmaprun":
        raise InputError("Expected an nmaprun document.")
    hosts: list[Host] = []
    seen_addresses: set[str] = set()
    try:
        nodes = root.findall("host")
        if len(nodes) > 512:
            raise InputError("Nmap XML exceeds the 512-host limit.")
        for node in nodes:
            status = node.find("status")
            if status is None or status.get("state") != "up":
                continue
            addresses = []
            for address_node in node.findall("address"):
                kind = address_node.get("addrtype")
                if kind in {"ipv4", "ipv6"}:
                    address = ip_address(address_node.attrib["addr"])
                    if kind != f"ipv{address.version}":
                        raise ValueError
                    addresses.append(str(address))
            addresses = list(dict.fromkeys(addresses))
            if not addresses or seen_addresses.intersection(addresses):
                raise InputError("Missing or duplicated host address in Nmap XML.")
            seen_addresses.update(addresses)
            hostname = node.find("hostnames/hostname")
            os_match = node.find("os/osmatch")
            services = []
            seen_ports: set[tuple[int, str]] = set()
            port_nodes = node.findall("ports/port")
            if len(port_nodes) > 4096:
                raise InputError("A host exceeds the 4096-port limit.")
            for port_node in port_nodes:
                state = port_node.find("state")
                if state is None or state.get("state") != "open":
                    continue
                number = int(port_node.attrib["portid"])
                protocol = port_node.attrib["protocol"]
                if not 1 <= number <= 65535 or protocol not in {"tcp", "udp", "sctp"}:
                    raise ValueError
                key = number, protocol
                if key in seen_ports:
                    raise InputError("Duplicated open port in Nmap XML.")
                seen_ports.add(key)
                service = port_node.find("service")
                attrs = service.attrib if service is not None else {}
                cpes = (
                    tuple(sorted({cpe.text.strip() for cpe in service.findall("cpe") if cpe.text}))
                    if service is not None
                    else ()
                )
                services.append(
                    Service(
                        port=Port(number, protocol),
                        name=attrs.get("name", "unknown"),
                        product=attrs.get("product", ""),
                        version=attrs.get("version", ""),
                        cpes=cpes,
                    )
                )
            hosts.append(
                Host(
                    ip=addresses[0],
                    addresses=tuple(addresses),
                    hostname=hostname.get("name", "") if hostname is not None else "",
                    os=os_match.get("name", "") if os_match is not None else "",
                    services=tuple(
                        sorted(services, key=lambda item: (item.port.number, item.port.protocol))
                    ),
                )
            )
    except (KeyError, ValueError) as exc:
        raise InputError("Nmap XML contains an invalid address or port.") from exc
    if not hosts and not allow_empty:
        raise InputError("Nmap XML contains no up hosts with IP addresses.")
    logger.info(
        "Imported %s hosts and %s open services",
        len(hosts),
        sum(len(host.services) for host in hosts),
    )
    return tuple(
        sorted(hosts, key=lambda item: (ip_address(item.ip).version, int(ip_address(item.ip))))
    )
