import io
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError

import pytest

from redops.cli.main import main
from redops.core.errors import InputError, RedOpsError
from redops.intelligence.advisories import AdvisoryNotFound, MockAdvisoryProvider
from redops.intelligence.nvd import CachedAdvisoryProvider, NvdClient, NvdHTTPTransport, parse_nvd

CVE = "CVE-2099-0001"


@pytest.fixture
def response():
    return {
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": CVE,
                    "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-02-01T00:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Test-only advisory."}],
                    "references": [{"url": "https://example.invalid/advisory"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "source": "nvd@nist.gov",
                                "cvssData": {
                                    "baseScore": 7.5,
                                    "version": "3.1",
                                    "vectorString": "test-vector",
                                },
                            }
                        ]
                    },
                }
            }
        ],
    }


def test_live_client_contract_can_use_transport_mock(response):
    class Transport:
        def fetch(self, cve_id):
            assert cve_id == CVE
            return response

    record = NvdClient(Transport()).lookup(CVE)
    assert record.cvss == 7.5
    assert record.provider == "nvd"
    assert record.published.endswith("+00:00")


def test_cvss_precedence(response):
    response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV40"] = [
        {
            "type": "Primary",
            "cvssData": {"baseScore": 8.1, "version": "4.0"},
        }
    ]
    assert parse_nvd(response, CVE).cvss_version == "4.0"
    assert parse_nvd(response, CVE).cvss == 8.1


def test_missing_metrics_remain_unknown(response):
    response["vulnerabilities"][0]["cve"]["metrics"] = {}
    assert parse_nvd(response, CVE).cvss is None


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data.update(totalResults=2),
        lambda data: data.update(totalResults=True),
        lambda data: data["vulnerabilities"][0]["cve"].update(id="CVE-2099-0002"),
        lambda data: data["vulnerabilities"][0]["cve"].update(metrics=[]),
    ],
)
def test_invalid_nvd_response_is_rejected(response, mutation):
    mutation(response)
    with pytest.raises(InputError):
        parse_nvd(response, CVE)


def test_not_found_is_explicit():
    with pytest.raises(AdvisoryNotFound):
        parse_nvd({"totalResults": 0, "vulnerabilities": []}, CVE)


def test_http_transport_uses_fixed_endpoint_and_headers(response, monkeypatch):
    transport = NvdHTTPTransport(api_key="test-only-key")

    def open_request(request, timeout):
        assert request.full_url == f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE}"
        assert request.get_header("Apikey") == "test-only-key"
        assert timeout == 15
        return io.BytesIO(json.dumps(response).encode())

    monkeypatch.setattr(transport._opener, "open", open_request)
    assert transport.fetch(CVE) == response


def test_rate_limit_retries_are_bounded(monkeypatch):
    transport = NvdHTTPTransport()
    calls, waits = [], []

    def fail(request, timeout):
        calls.append(request)
        raise HTTPError(request.full_url, 429, "test", {"Retry-After": "120"}, None)

    monkeypatch.setattr(transport._opener, "open", fail)
    monkeypatch.setattr("redops.intelligence.nvd.time.sleep", waits.append)
    with pytest.raises(RedOpsError, match="429"):
        transport.fetch(CVE)
    assert len(calls) == 3
    assert all(wait <= 30 for wait in waits)


def test_cache_round_trip_and_offline_hit(response, tmp_path):
    class Provider:
        def lookup(self, cve_id):
            return parse_nvd(response, cve_id)

    saved = CachedAdvisoryProvider(tmp_path, Provider()).lookup(CVE)
    assert CachedAdvisoryProvider(tmp_path).lookup(CVE) == saved


def test_offline_cache_miss_does_not_create_directory(tmp_path):
    destination = tmp_path / "missing"
    with pytest.raises(AdvisoryNotFound, match="offline"):
        CachedAdvisoryProvider(destination).lookup(CVE)
    assert not destination.exists()


def test_expired_cache_is_not_silently_used(response, tmp_path):
    advisory = replace(
        parse_nvd(response, CVE), retrieved_at=(datetime.now(UTC) - timedelta(days=2)).isoformat()
    )
    path = tmp_path / f"{CVE}.json"
    original = json.dumps(advisory.to_dict())
    path.write_text(original)
    with pytest.raises(AdvisoryNotFound):
        CachedAdvisoryProvider(tmp_path).lookup(CVE)
    assert path.read_text() == original


def test_mock_records_cannot_enter_live_cache(tmp_path):
    with pytest.raises(InputError, match="Only matching NVD"):
        CachedAdvisoryProvider(tmp_path, MockAdvisoryProvider()).lookup(CVE)
    assert not list(tmp_path.iterdir())


def test_cache_protects_existing_artifacts(tmp_path):
    protected = tmp_path / f"{CVE}.json"
    protected.write_text("preserve me")
    with pytest.raises(InputError, match="distinct"):
        CachedAdvisoryProvider(tmp_path, protected_paths=(protected,)).lookup(CVE)
    assert protected.read_text() == "preserve me"


@pytest.mark.parametrize(
    "value", ["../cache", "cve-2099-0001", "CVE-2099-0", "CVE-2099-0001?key=x"]
)
def test_identifier_validation_precedes_transport(value):
    with pytest.raises(InputError):
        NvdHTTPTransport().fetch(value)


def test_cli_mock_lookup_and_health(tmp_path, capsys):
    base = ["--audit", str(tmp_path / "audit.jsonl")]
    assert main(base + ["intelligence", "lookup", "--cve", CVE, "--mock"]) == 0
    assert json.loads(capsys.readouterr().out)["provider"] == "mock"
    assert main(base + ["metasploit", "status", "--mock"]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "mock"
