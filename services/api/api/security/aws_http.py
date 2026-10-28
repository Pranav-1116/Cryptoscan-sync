"""Signed AWS HTTP calls, shared by the cloud configuration and KMS-usage planes.

Two collectors talk to AWS: the cloud plane reads *configuration* (listeners, key
specs) and the KMS plane reads *usage* (CloudTrail). Both need the same three
things — endpoint selection, SigV4, and a refusal that is distinguishable from an
error — so it lives here rather than in either collector.

Refusal vs error matters for the estate: a 403 means "we were not allowed to look",
which is ``blocked`` + ``PARTIAL``; a 500 means the source is broken, which is
``FAILED``. Neither is ever an empty result.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any, Callable, Mapping

from api.security.aws_sigv4 import sigv4_headers

Transport = Callable[[str, str, Mapping[str, str], "bytes | None", float], tuple[int, bytes]]


class AwsHttpError(RuntimeError):
    """The service answered, but not with data we can use."""


def base_url(config: Mapping[str, Any], service: str, *, prefix: str = "") -> str:
    """The endpoint for ``service``: an override, or the regional AWS host."""
    if config.get("endpoint"):
        return str(config["endpoint"])
    host = f"{prefix}{service}.{config['region']}.amazonaws.com"
    return f"https://{host}"


def default_transport(method: str, url: str, headers: Mapping[str, str], body: "bytes | None",
                      timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method.upper())
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read() or b""


def send_signed(
    config: Mapping[str, Any],
    service: str,
    *,
    method: str,
    path: str,
    query: str,
    body: bytes | None,
    headers: Mapping[str, str],
    transport: Transport,
    timeout: float,
    label: str,
    prefix: str = "",
) -> bytes:
    """Sign and send one request; 403 raises ``PermissionError``, other errors raise."""
    url = base_url(config, service, prefix=prefix) + path + (f"?{query}" if query else "")
    extras = dict(headers)
    if body:
        extras.setdefault("content-type", "application/x-www-form-urlencoded")
    signed = sigv4_headers(
        method=method,
        url=url,
        body=body or b"",
        region=str(config["region"]),
        access_key=str(config["access_key"]),
        secret_key=str(config["secret_key"]),
        session_token=config.get("session_token"),
        extra_headers=extras,
        service=service,
    )
    request_headers = dict(signed)
    request_headers["Host"] = signed["host"]
    for key, value in headers.items():
        request_headers[key] = value

    status, payload = transport(method, url, request_headers, body, timeout)
    if status == 403:
        # "we were not allowed to look" is coverage debt, not an empty result
        raise PermissionError(label)
    if status >= 300:
        raise AwsHttpError(f"{label}: HTTP {status} {payload[:200].decode('utf-8', 'replace')}")
    return payload
