"""Bounded NVD CVE API lookup with explicit transport, retry, and cache policies."""

import json
import logging
import os
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from redops.core.errors import InputError, RedOpsError
from redops.core.io import atomic_write, read_bounded, require_distinct_paths
from redops.intelligence.advisories import (
    Advisory,
    AdvisoryNotFound,
    AdvisoryProvider,
    validate_cve,
)

logger = logging.getLogger(__name__)
NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdTransport(Protocol):
    def fetch(self, cve_id: str) -> dict[str, Any]:
        """Fetch a single CVE response without exposing credentials to callers."""


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RedOpsError("NVD redirects are refused.")


class NvdHTTPTransport:
    """One CVE per request; bounded retries and per-instance request pacing."""

    def __init__(self, *, api_key: str | None = None):
        self._api_key = api_key
        self._opener = build_opener(
            _NoRedirects(),
            HTTPSHandler(context=ssl.create_default_context()),
        )
        self._last_request = 0.0
        self._lock = threading.Lock()
        self._interval = 6.0

    def fetch(self, cve_id: str) -> dict[str, Any]:
        validate_cve(cve_id)
        headers = {"Accept": "application/json", "User-Agent": "RedOps"}
        if self._api_key:
            headers["apiKey"] = self._api_key
        request = Request(NVD_ENDPOINT + "?" + urlencode({"cveId": cve_id}), headers=headers)
        with self._lock:
            for attempt in range(3):
                delay = max(0.0, self._interval - (time.monotonic() - self._last_request))
                if delay:
                    time.sleep(delay)
                self._last_request = time.monotonic()
                try:
                    with self._opener.open(request, timeout=15) as response:
                        content = response.read(4 * 1024 * 1024 + 1)
                    if len(content) > 4 * 1024 * 1024:
                        raise InputError("NVD response exceeds the 4 MiB limit.")
                    document = json.loads(content)
                    if not isinstance(document, dict):
                        raise ValueError
                    logger.info("NVD lookup completed for %s", cve_id)
                    return document
                except HTTPError as exc:
                    status = exc.code
                    retry_after = exc.headers.get("Retry-After", "6")
                    exc.close()
                    if status not in {429, 500, 502, 503, 504} or attempt == 2:
                        raise RedOpsError(
                            f"NVD request failed with HTTP status {status}."
                        ) from None
                    try:
                        wait = max(6.0, min(float(retry_after), 30.0))
                    except (ValueError, TypeError):
                        wait = 6.0
                    logger.warning("NVD request will retry after HTTP status %s", status)
                    time.sleep(wait)
                except (URLError, TimeoutError, OSError) as exc:
                    raise RedOpsError(
                        "NVD connection failed; check connectivity and TLS trust."
                    ) from exc
                except (ValueError, RecursionError) as exc:
                    raise InputError("NVD returned invalid JSON.") from exc
        raise RedOpsError("NVD retry budget exhausted.")


def parse_nvd(document: dict[str, Any], cve_id: str) -> Advisory:
    """Read advisory metadata only; never flatten NVD applicability trees into matches."""
    validate_cve(cve_id)
    try:
        results = document["vulnerabilities"]
        total = document["totalResults"]
        if type(total) is not int or not isinstance(results, list) or total != len(results):
            raise ValueError
        if total == 0:
            raise AdvisoryNotFound(f"NVD has no advisory for {cve_id}.")
        if total != 1 or results[0]["cve"]["id"] != cve_id:
            raise ValueError
        item = results[0]["cve"]
        description = next(
            (entry["value"] for entry in item.get("descriptions", []) if entry.get("lang") == "en"),
            "NVD has not supplied an English description.",
        )
        score, version, vector = None, None, None
        metrics = item.get("metrics", {})
        for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            candidates = metrics.get(metric_name, [])
            if candidates:
                metric = min(
                    candidates,
                    key=lambda entry: (
                        entry.get("type") != "Primary",
                        entry.get("source") != "nvd@nist.gov",
                    ),
                )["cvssData"]
                score, version, vector = (
                    metric["baseScore"],
                    metric["version"],
                    metric.get("vectorString"),
                )
                break
        return Advisory.from_dict(
            {
                "cve_id": cve_id,
                "description": description,
                "cvss": score,
                "cvss_version": version,
                "vector": vector,
                "status": item.get("vulnStatus", "Unknown"),
                "published": item["published"],
                "last_modified": item["lastModified"],
                "references": [ref["url"] for ref in item.get("references", [])],
                "provider": "nvd",
                "retrieved_at": datetime.now(UTC).isoformat(),
            }
        )
    except (ValueError, TypeError, KeyError, AttributeError, IndexError) as exc:
        raise InputError("NVD returned an invalid or incomplete advisory response.") from exc


class NvdClient:
    def __init__(self, transport: NvdTransport | None = None):
        self.transport = transport or NvdHTTPTransport(api_key=os.environ.get("REDOPS_NVD_API_KEY"))

    def lookup(self, cve_id: str) -> Advisory:
        return parse_nvd(self.transport.fetch(validate_cve(cve_id)), cve_id)


class CachedAdvisoryProvider:
    """Offline mode never creates files, refreshes data, or contacts a provider."""

    def __init__(
        self,
        directory: Path,
        upstream: AdvisoryProvider | None = None,
        *,
        max_age: timedelta = timedelta(hours=24),
        protected_paths: tuple[Path, ...] = (),
    ):
        if max_age.total_seconds() <= 0:
            raise InputError("Advisory cache lifetime must be positive.")
        self.directory, self.upstream, self.max_age = directory, upstream, max_age
        self.protected_paths = protected_paths

    def lookup(self, cve_id: str) -> Advisory:
        path = self.directory / f"{validate_cve(cve_id)}.json"
        require_distinct_paths([*self.protected_paths, path])
        if path.exists():
            try:
                advisory = Advisory.from_dict(json.loads(read_bounded(path, 1024 * 1024)))
                if advisory.cve_id != cve_id or advisory.provider != "nvd":
                    raise ValueError
                age = datetime.now(UTC) - datetime.fromisoformat(advisory.retrieved_at)
                if age < timedelta(0):
                    raise ValueError
                if age <= self.max_age:
                    logger.info("Advisory cache hit for %s", cve_id)
                    return advisory
            except (ValueError, TypeError, KeyError, RecursionError) as exc:
                raise InputError("The advisory cache contains an invalid record.") from exc
        if self.upstream is None:
            raise AdvisoryNotFound(
                f"No fresh cached advisory for {cve_id}; offline lookup stopped."
            )
        advisory = self.upstream.lookup(cve_id)
        if advisory.cve_id != cve_id or advisory.provider != "nvd":
            raise InputError("Only matching NVD records can be stored in the live advisory cache.")
        atomic_write(path, json.dumps(advisory.to_dict(), indent=2, allow_nan=False) + "\n")
        return advisory
