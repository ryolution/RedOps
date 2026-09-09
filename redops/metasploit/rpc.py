"""Minimal verified-TLS MessagePack health adapter; no execution interface."""

import logging
import os
import ssl
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

import msgpack

from redops.core.errors import RedOpsError

logger = logging.getLogger(__name__)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RedOpsError("RPC redirects are refused.")


class MetasploitClient:
    def __init__(self, url: str, username: str, password: str, *, ca_file: str | None = None):
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise RedOpsError("RPC requires an HTTPS URL without credentials, query, or fragment.")
        if not username or not password or len(username) > 200 or len(password) > 4096:
            raise RedOpsError(
                "Set REDOPS_MSF_USERNAME and REDOPS_MSF_PASSWORD for the health check."
            )
        self._url, self._username, self._password = url, username, password
        self._opener = build_opener(
            NoRedirects(),
            HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)),
        )

    @classmethod
    def from_env(cls) -> "MetasploitClient":
        return cls(
            os.environ.get("REDOPS_MSF_URL", "https://127.0.0.1:55553/api/1.0"),
            os.environ.get("REDOPS_MSF_USERNAME", ""),
            os.environ.get("REDOPS_MSF_PASSWORD", ""),
            ca_file=os.environ.get("REDOPS_MSF_CA_FILE"),
        )

    def _request(self, method: str, arguments: list[str]) -> dict:
        if method not in {"auth.login", "core.version", "auth.logout"}:
            raise RedOpsError("RPC method is outside the health-check interface.")
        request = Request(
            self._url,
            data=msgpack.packb([method, *arguments], use_bin_type=True),
            headers={"Content-Type": "binary/message-pack"},
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=10) as response:
                body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                raise ValueError
            result = msgpack.unpackb(body, raw=False, strict_map_key=True)
            if not isinstance(result, dict) or result.get("error"):
                raise ValueError
            logger.info("RPC health method completed: %s", method)
            return result
        except (OSError, ValueError, msgpack.exceptions.UnpackException) as exc:
            raise RedOpsError(
                "RPC health request failed; check service, credentials, and TLS trust."
            ) from exc

    def health(self) -> dict[str, str]:
        login = self._request("auth.login", [self._username, self._password])
        token = login.get("token")
        if (
            login.get("result") != "success"
            or not isinstance(token, str)
            or not token
            or len(token) > 4096
        ):
            raise RedOpsError("RPC authentication failed.")
        primary_error = None
        metadata = {}
        try:
            version = self._request("core.version", [token])
            value = version.get("version")
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 256
                or not value.isprintable()
            ):
                raise RedOpsError("RPC returned an invalid version response.")
            for key in ("version", "ruby", "api"):
                value = version.get(key)
                if isinstance(value, str) and len(value) <= 256 and value.isprintable():
                    for secret in sorted(
                        (self._username, self._password, token), key=len, reverse=True
                    ):
                        value = value.replace(secret, "[redacted]")
                    metadata[key] = value
        except RedOpsError as exc:
            primary_error = exc
        finally:
            try:
                logout = self._request("auth.logout", [token])
                if logout.get("result") != "success":
                    raise RedOpsError(
                        "RPC health check could not close its authentication session."
                    )
            except RedOpsError:
                if primary_error:
                    raise RedOpsError(
                        "RPC health failed and logout could not be confirmed."
                    ) from primary_error
                raise
        if primary_error:
            raise primary_error
        return metadata
