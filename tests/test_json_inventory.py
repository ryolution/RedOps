import copy
import json
from dataclasses import asdict
from datetime import UTC, datetime, timedelta

import pytest

from redops.cli.main import main
from redops.core.errors import InputError, ScopeError
from redops.core.workflow import run_assessment
from redops.intelligence.cve import Catalog, catalog_warnings
from redops.recon.json_inventory import JsonInventoryParser, parse_inventory_json
from redops.recon.parser import parse_nmap


@pytest.fixture
def envelope(labs):
    return {
        "schema": "redops-inventory",
        "schema_version": 1,
        "collected_at": "2025-01-01T00:00:00Z",
        "source": "Synthetic XML equivalence fixture",
        "hosts": json.loads(
            json.dumps([asdict(host) for host in parse_nmap((labs / "demo-nmap.xml").read_bytes())])
        ),
    }


def test_inventory_equivalence_provenance_and_preview(envelope, settings, labs, tmp_path):
    content = json.dumps(envelope).encode()
    assert JsonInventoryParser().parse(content) == parse_nmap((labs / "demo-nmap.xml").read_bytes())
    path = tmp_path / "input.json"
    path.write_bytes(content)
    result = run_assessment(
        settings,
        labs / "demo-scope.yaml",
        path,
        labs / "demo-catalog.json",
        input_format="inventory-json",
        dry_run=True,
    )
    expected = run_assessment(
        settings,
        labs / "demo-scope.yaml",
        labs / "demo-nmap.xml",
        labs / "demo-catalog.json",
        dry_run=True,
    )
    assert result["findings"] == expected["findings"]
    assert result["hosts"] == expected["hosts"]
    assert result["provenance"]["source"] == envelope["source"]
    assert len(result["provenance"]["input_sha256"]) == 64
    assert "nmap_sha256" not in result["provenance"]
    assert not (tmp_path / "assessment.db").exists()


@pytest.mark.parametrize(
    "case",
    [
        "schema",
        "timestamp",
        "duplicate_host",
        "duplicate_port",
        "primary_ip",
        "boolean_port",
        "oversized_port",
        "invalid_protocol",
        "unknown_field",
    ],
)
def test_invalid_inventory(envelope, case):
    data = copy.deepcopy(envelope)
    host = data["hosts"][0]
    service = host["services"][0]
    if case == "schema":
        data["schema"] = "other"
    elif case == "timestamp":
        data["collected_at"] = "2025-01-01"
    elif case == "duplicate_host":
        data["hosts"].append(host)
    elif case == "duplicate_port":
        host["services"].append(service)
    elif case == "primary_ip":
        host["ip"] = "198.51.100.1"
    elif case == "boolean_port":
        service["port"]["number"] = True
    elif case == "oversized_port":
        service["port"]["number"] = 65536
    elif case == "invalid_protocol":
        service["port"]["protocol"] = "other"
    else:
        host["unexpected"] = "value"
    with pytest.raises(InputError):
        parse_inventory_json(json.dumps(data).encode())


def test_bounds_and_duplicate_json_fields(envelope):
    with pytest.raises(InputError):
        parse_inventory_json(b"x" * (8 * 1024 * 1024 + 1))
    with pytest.raises(InputError):
        parse_inventory_json(b'{"schema": 1, "schema": 2}')
    envelope["hosts"] *= 43
    with pytest.raises(InputError):
        parse_inventory_json(json.dumps(envelope).encode())


def test_json_secondary_address_scope_check(envelope, settings, labs, tmp_path):
    envelope["hosts"][0]["addresses"].append("198.51.100.1")
    path = tmp_path / "input.json"
    path.write_text(json.dumps(envelope))
    with pytest.raises(ScopeError):
        run_assessment(
            settings,
            labs / "demo-scope.yaml",
            path,
            labs / "demo-catalog.json",
            input_format="inventory-json",
        )
    assert not (tmp_path / "assessment.db").exists()


def test_unknown_identity_is_preserved(envelope):
    service = envelope["hosts"][0]["services"][0]
    service.update(product="", version="", cpes=["unsupported:cpe"])
    parsed = parse_inventory_json(json.dumps(envelope).encode()).hosts[0].services[0]
    assert parsed.product == parsed.version == ""
    assert parsed.cpes == ("unsupported:cpe",)


def test_catalog_age_boundaries():
    now = datetime.now(UTC)
    for days, expected in [(30, False), (31, True), (-1, True)]:
        catalog = Catalog("reviewed", (now - timedelta(days=days)).isoformat(), ())
        assert bool(catalog_warnings(catalog, now=now)) is expected


def test_catalog_validation_cli(settings, labs, capsys):
    assert (
        main(
            [
                "--database",
                settings.database_url,
                "--audit",
                str(settings.audit_path),
                "intelligence",
                "catalog",
                "validate",
                "--input",
                str(labs / "demo-catalog.json"),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "validated"
    assert result["records"] > 0 and result["supported_cpes"] > 0
