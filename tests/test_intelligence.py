import json
from dataclasses import replace

import pytest

from redops.core.domain import severity
from redops.core.errors import InputError
from redops.intelligence.cve import canonical_cpe, load_catalog
from redops.intelligence.matcher import correlate
from redops.recon.parser import parse_nmap


def test_matching_has_explicit_coverage_and_unconfirmed_status(labs):
    hosts = parse_nmap((labs / "demo-nmap.xml").read_bytes())
    catalog = load_catalog((labs / "demo-catalog.json").read_bytes())
    findings, coverage = correlate(hosts, catalog)
    assert len(findings) == 8
    assert coverage == {
        "services_total": 12,
        "services_with_supported_cpe": 10,
        "services_with_candidates": 8,
    }
    assert all(item.status == "candidate_needs_review" for item in findings)
    assert findings[0].cvss == 7.5


def test_same_cpe_in_both_bindings_does_not_duplicate_findings(labs):
    host = parse_nmap((labs / "demo-nmap.xml").read_bytes())[0]
    service = host.services[0]
    service = replace(service, cpes=(*service.cpes, canonical_cpe(service.cpes[0])))
    catalog = load_catalog((labs / "demo-catalog.json").read_bytes())
    findings, _ = correlate((replace(host, services=(service,)),), catalog)
    assert len(findings) == 1


@pytest.mark.parametrize(
    "value",
    [
        "cpe:/a:vendor:product",
        "cpe:/a:vendor:product:*",
        "Apache 1.0",
        "cpe:/a:vendor:product:1%3a0",
        "cpe:2.3:a:vendor:product:1.0",
        "cpe:/a:*:product:1.0",
    ],
)
def test_unsupported_cpes_are_not_guessed(value):
    assert canonical_cpe(value) is None


@pytest.mark.parametrize("score", [True, float("nan"), float("inf"), -1, 11, "9.0"])
def test_invalid_catalog_scores(labs, score):
    data = json.loads((labs / "demo-catalog.json").read_bytes())
    data["records"][0]["cvss"] = score
    with pytest.raises(InputError):
        load_catalog(json.dumps(data).encode())


def test_reviewed_catalog_rejects_synthetic_identifiers(labs):
    data = json.loads((labs / "demo-catalog.json").read_bytes())
    data["kind"] = "reviewed"
    with pytest.raises(InputError):
        load_catalog(json.dumps(data).encode())


def test_missing_cvss_is_preserved(labs):
    data = json.loads((labs / "demo-catalog.json").read_bytes())
    data["records"][0]["cvss"] = None
    catalog = load_catalog(json.dumps(data).encode())
    assert catalog.records[0].cvss is None
    assert severity(None) == "unknown"
    assert severity(0) == "none"
