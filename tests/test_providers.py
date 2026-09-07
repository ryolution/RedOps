import json

import pytest

from redops.core.errors import RedOpsError, ScopeError
from redops.core.workflow import run_assessment
from redops.intelligence.advisories import MockAdvisoryProvider
from redops.recon.parser import parse_nmap
from redops.recon.source import MockInventoryParser


def test_inventory_mock_still_obeys_scope(settings, labs):
    from dataclasses import replace

    host = parse_nmap((labs / "demo-nmap.xml").read_bytes())[0]
    outside = replace(host, ip="198.51.100.1", addresses=("198.51.100.1",))
    with pytest.raises(ScopeError):
        run_assessment(
            settings,
            labs / "demo-scope.yaml",
            labs / "demo-nmap.xml",
            labs / "demo-catalog.json",
            inventory_parser=MockInventoryParser((outside,)),
            dry_run=True,
        )


def test_dry_run_cannot_call_advisory_provider(settings, labs):
    with pytest.raises(RedOpsError, match="Dry-run"):
        run_assessment(
            settings,
            labs / "demo-scope.yaml",
            labs / "demo-nmap.xml",
            labs / "demo-catalog.json",
            dry_run=True,
            advisory_provider=MockAdvisoryProvider(),
        )
    assert not settings.audit_path.exists()


def test_workflow_enriches_each_distinct_cve_once(settings, labs, tmp_path):
    from dataclasses import replace

    catalog = json.loads((labs / "demo-catalog.json").read_bytes())
    catalog["kind"] = "reviewed"
    catalog["records"] = [catalog["records"][0]]
    catalog["records"][0]["id"] = "CVE-2099-0001"
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog))
    calls = []

    class Provider:
        def lookup(self, identifier):
            calls.append(identifier)
            return replace(MockAdvisoryProvider().lookup(identifier), provider="nvd")

    document = run_assessment(
        settings,
        labs / "demo-scope.yaml",
        labs / "demo-nmap.xml",
        path,
        advisory_provider=Provider(),
    )
    assert len(document["findings"]) == 4
    assert calls == ["CVE-2099-0001"]
    assert document["advisories"][0]["provider"] == "nvd"
    assert (
        document["findings"][0]["cvss"] == 7.5
    )  # Catalog evidence remains independently traceable.
