"""HTTPS to the CryptoScan console — the standard library only.

Every request carries the agent's machine key in ``X-API-Key`` (issued at activation,
scoped to observations + heartbeats). TLS verification is on unless the operator
explicitly sets ``insecure_skip_verify`` (sandbox only); ``ca_file`` pins the bank's
internal CA.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any

from cryptava import __version__

USER_AGENT = f"cryptava/{__version__}"


class TransportError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class Client:
    def __init__(self, server: str, *, api_key: str | None = None, ca_file: str | None = None,
                 insecure: bool = False, timeout: float = 60.0) -> None:
        if not server:
            raise TransportError("no console URL configured (set 'server' or CRYPTAVA_SERVER)")
        if not server.startswith(("https://", "http://")):
            raise TransportError(f"console URL must start with https:// — got {server!r}")
        self.server = server.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._context: ssl.SSLContext | None = None
        if self.server.startswith("https://"):
            context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
            if insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            self._context = context

    def post(self, path: str, body: dict[str, Any], *, api_key: str | None = None,
             headers: dict[str, str] | None = None) -> dict[str, Any]:
        data = json.dumps(body, separators=(",", ":"), default=str).encode("utf-8")
        request = urllib.request.Request(self.server + path, data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json")
        request.add_header("User-Agent", USER_AGENT)
        key = api_key or self.api_key
        if key:
            request.add_header("X-API-Key", key)
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self._context) as response:  # nosec B310
                raw = response.read()
        except urllib.error.HTTPError as exc:
            payload: Any
            try:
                payload = json.loads(exc.read() or b"null")
            except ValueError:
                payload = None
            detail = payload.get("detail") if isinstance(payload, dict) else payload
            if isinstance(detail, dict):
                detail = detail.get("message") or detail.get("error") or detail
            raise TransportError(f"{path}: HTTP {exc.code} — {detail}", status=exc.code, body=payload) from exc
        except (urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise TransportError(f"{path}: cannot reach {self.server} ({reason})") from exc
        try:
            return json.loads(raw or b"{}")
        except ValueError as exc:
            raise TransportError(f"{path}: the console did not return JSON") from exc
