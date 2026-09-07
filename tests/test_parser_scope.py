from dataclasses import replace
from datetime import UTC, datetime
from ipaddress import ip_network

import pytest
import yaml

from redops.core.errors import InputError, ScopeError
from redops.core.scope import load_scope
from redops.recon.parser import parse_nmap


def test_demo_parser(labs):
    hosts = parse_nmap((labs / "demo-nmap.xml").read_bytes())
    assert len(hosts) == 12
    assert hosts[0].ip == "192.0.2.10"
    assert hosts[0].services[0].port.number == 8080
    assert hosts[4].services[0].port.number == 5432


def test_normal_doctype_is_accepted(labs):
    content = (
        (labs / "demo-nmap.xml")
        .read_bytes()
        .replace(b'<?xml version="1.0"?>', b'<?xml version="1.0"?><!DOCTYPE nmaprun>')
    )
    assert len(parse_nmap(content)) == 12


@pytest.mark.parametrize(
    "content",
    [
        b"not XML",
        b"<other/>",
        b"<nmaprun/>",
        b'<!DOCTYPE nmaprun [<!ENTITY sample "local">]><nmaprun>&sample;</nmaprun>',
        b'<!DOCTYPE nmaprun [<!ENTITY sample SYSTEM "file:///nonexistent">]><nmaprun/>',
    ],
)
def test_bad_xml_is_rejected(content):
    with pytest.raises(InputError):
        parse_nmap(content)


@pytest.mark.parametrize(
    "old,new",
    [
        (b'portid="8080"', b'portid="70000"'),
        (b'protocol="tcp"', b'protocol="other"'),
        (b'addr="192.0.2.10"', b'addr="not-an-ip"'),
        (b'addr="192.0.2.11"', b'addr="192.0.2.10"'),
    ],
)
def test_invalid_observations_are_rejected(labs, old, new):
    content = (labs / "demo-nmap.xml").read_bytes().replace(old, new)
    with pytest.raises(InputError):
        parse_nmap(content)


def test_closed_ports_and_down_hosts_are_omitted(labs):
    content = (labs / "demo-nmap.xml").read_bytes()
    content = content.replace(b'state="up"', b'state="down"', 1)
    content = content.replace(b'state="open"', b'state="closed"')
    hosts = parse_nmap(content)
    assert len(hosts) == 11
    assert all(not host.services for host in hosts)


def test_scope_validates_secondary_ipv6_addresses(labs):
    content = (
        (labs / "demo-nmap.xml")
        .read_bytes()
        .replace(
            b'<address addr="192.0.2.10" addrtype="ipv4" />',
            b'<address addr="192.0.2.10" addrtype="ipv4" />'
            b'<address addr="2001:db8::10" addrtype="ipv6" />',
        )
    )
    hosts = parse_nmap(content)
    scope = load_scope(labs / "demo-scope.yaml")
    with pytest.raises(ScopeError, match="outside"):
        scope.validate(hosts)
    scope = replace(scope, networks=(*scope.networks, ip_network("2001:db8::/32")))
    scope.validate(hosts)


def test_scope_expiry_and_limit(labs):
    scope = load_scope(labs / "demo-scope.yaml")
    hosts = parse_nmap((labs / "demo-nmap.xml").read_bytes())
    with pytest.raises(ScopeError, match="expired"):
        scope.validate(hosts, datetime(2100, 1, 1, tzinfo=UTC))
    with pytest.raises(ScopeError, match="count"):
        replace(scope, max_hosts=1).validate(hosts)


@pytest.mark.parametrize(
    "field,value",
    [
        ("operator", ""),
        ("max_hosts", True),
        ("max_hosts", 0),
        ("allowlist", []),
        ("allowlist", ["localhost"]),
        ("allowlist", [123]),
        ("expires_at", "2099-01-01T00:00:00"),
        ("unknown", "field"),
    ],
)
def test_invalid_scope(labs, tmp_path, field, value):
    data = yaml.safe_load((labs / "demo-scope.yaml").read_bytes())
    data[field] = value
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(ScopeError):
        load_scope(path)
