"""RESTCONF -> hardware facts (phase H5): the API-first half of the estate.

Some vendors document NETCONF and ship RESTCONF; the newer appliances often
ship only the REST half. Both expose the same YANG models (RFC 8040 over
``ietf-system`` and ``ietf-hardware``), so the facts they produce are the same
facts, and the estate must not care which door was used.

What is here:

* **YANG-prefixed JSON parsing.** RESTCONF wraps responses in the module name
  (``{"ietf-hardware:hardware": …}``), returns a bare object where NETCONF
  returns a list when there is one component, and omits keys rather than
  emptying them. The parser handles all three because vendors do all three.
* **HTTPS only, by construction.** :class:`HttpsRestconfTransport` refuses a
  plain ``http://`` base URL: reading a bank's device inventory over cleartext
  would be a worse finding than the inventory is worth.
* **A credential reference, never a value.** The bearer token or basic-auth
  pair is used to sign the request and is not placed on the facts; a payload
  that echoes it is refused.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from typing import Any, Callable
from urllib.parse import urlparse

from universal_vendor.hardware.host.credentials import (
    refuse_credential_echo,
    refuse_secret_shapes,
)
from universal_vendor.hardware.host.netconf import select_chassis
from universal_vendor.hardware.host.snmp_bridge import NetworkDeviceFacts

SCHEMA = "cryptoscan.restconf-hardware/1"

SYSTEM_PATH = "/restconf/data/ietf-system:system"
HARDWARE_PATH = "/restconf/data/ietf-hardware:hardware"

Fetcher = Callable[[str, str], Any]  # (base_url, path) -> parsed JSON


class RestconfError(RuntimeError):
    """The request failed, or the answer was not JSON we can read."""


def strip_prefix(value: Any) -> Any:
    """Drop the ``module:`` prefix RESTCONF puts on every top-level key."""
    if isinstance(value, dict):
        return {str(key).split(":", 1)[-1]: strip_prefix(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [strip_prefix(item) for item in value]
    return value


def parse_system(payload: Any) -> dict[str, Any]:
    """``ietf-system:system`` -> {hostname, location} without the prefix."""
    data = strip_prefix(payload or {})
    system = data.get("system") if isinstance(data, dict) else None
    return system if isinstance(system, dict) else {}


def parse_hardware(payload: Any) -> list[dict[str, Any]]:
    """``ietf-hardware:hardware`` -> components as a list, one or many."""
    data = strip_prefix(payload or {})
    hardware = data.get("hardware") if isinstance(data, dict) else None
    if not isinstance(hardware, dict):
        return []
    components = hardware.get("component")
    if isinstance(components, dict):
        return [components]
    if isinstance(components, list):
        return [component for component in components if isinstance(component, dict)]
    return []


class HttpsRestconfTransport:
    """A read-only HTTPS GET with a bearer token or basic-auth pair.

    The opener is injected for tests; the default uses the standard library so
    the collector does not add a dependency to read one device.
    """

    def __init__(self, opener: Callable[[urllib.request.Request], Any] | None = None,
                 timeout: float = 15.0, credential: str | None = None) -> None:
        self._opener = opener or self._urlopen
        self.timeout = timeout
        # Held only for the lifetime of the transport, applied per request, and
        # never written to a fact record.
        self._credential = credential

    def __call__(self, base_url: str, path: str) -> Any:
        url = self._url(base_url) + path
        headers = {
            "Accept": "application/yang-data+json",
            "User-Agent": "cryptoscan-hardware/1",
        }
        if self._credential:
            headers.update(authorization_header(self._credential))
        request = urllib.request.Request(url, method="GET", headers=headers)
        try:
            response = self._opener(request)
        except urllib.error.HTTPError as exc:
            raise RestconfError(f"HTTP {exc.code} on {path}") from exc
        except urllib.error.URLError as exc:
            raise RestconfError(f"no route to {urlparse(url).netloc}: {exc.reason}") from exc
        body = response.read()
        try:
            return json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RestconfError(f"{path} did not answer with JSON: {exc}") from exc

    @staticmethod
    def _url(base_url: str) -> str:
        parsed = urlparse(base_url or "")
        if parsed.scheme != "https":
            raise RestconfError(
                f"{base_url!r} is not https: device inventory is not read over cleartext")
        return base_url.rstrip("/")

    def _urlopen(self, request: urllib.request.Request) -> Any:
        return urllib.request.urlopen(request, timeout=self.timeout)  # noqa: S310


def authorization_header(token: str) -> dict[str, str]:
    """Build the auth header. The caller passes it; the collector never stores it.

    A token is sent as a bearer, a ``user:password`` pair as basic auth — and the
    returned header exists only for the duration of the request.
    """
    if not token:
        raise RestconfError("a RESTCONF request needs a credential")
    if ":" in token and " " not in token:
        encoded = base64.b64encode(token.encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {encoded}"}
    return {"Authorization": f"Bearer {token}"}


class RestconfCollector:
    """Read one device over RESTCONF into the same facts every transport produces."""

    def __init__(self, fetch: Fetcher | None = None,
                 opener: Callable[[urllib.request.Request], Any] | None = None) -> None:
        self._fetch = fetch
        self._opener = opener

    def _get(self, base_url: str, path: str) -> Any:
        if self._fetch is not None:
            return self._fetch(base_url, path)
        return HttpsRestconfTransport(opener=self._opener)(base_url, path)

    def collect(self, base_url: str, *, credential_ref: str | None = None,
                device_type: str = "switch",
                host: str | None = None) -> NetworkDeviceFacts:
        target = host or urlparse(base_url).hostname or base_url
        facts = NetworkDeviceFacts(host=target, transport="restconf",
                                   security_mode="RESTCONF-over-HTTPS")
        try:
            system_payload = self._get(base_url, SYSTEM_PATH)
            hardware_payload = self._get(base_url, HARDWARE_PATH)
        except (RestconfError, OSError) as exc:
            facts.unavailable.append(f"restconf {target}: {exc}")
            return facts

        system = parse_system(system_payload)
        components = parse_hardware(hardware_payload)
        chassis = select_chassis(components)

        facts.reachable = True
        facts.sys_name = _text(system.get("hostname"))
        facts.sys_location = _text(system.get("location"))
        if chassis is not None:
            facts.serial_reference = _text(chassis.get("serial-num"))
            facts.model = _text(chassis.get("model-name"))
            facts.firmware = _text(chassis.get("firmware-rev")) or \
                _text(chassis.get("software-rev"))
            facts.vendor = _text(chassis.get("manufacturer"))
            facts.sources["chassis"] = "ietf-hardware"
        if not components:
            facts.unavailable.append(
                f"restconf {target}: the device answered but exposed no components — "
                "a RESTCONF server without ietf-hardware is a limitation to record, "
                "not an empty chassis")
        facts.context = {
            "asset_id": facts.sys_name or target,
            "device_type": device_type,
            "manufacturer": facts.vendor or "",
            "model": facts.model or "",
            "serial_reference": facts.serial_reference,
            "firmware": facts.firmware,
            "network_device": {
                "sysname": facts.sys_name,
                "location": facts.sys_location,
                "manufacturer": facts.vendor,
                "model": facts.model,
                "serial": facts.serial_reference,
                "firmware": facts.firmware,
                "security_mode": facts.security_mode,
                "protocol": "restconf",
            },
        }
        refuse_credential_echo(facts.context, credential_ref, host=target,
                               kind="credential reference")
        refuse_secret_shapes(facts.context, host=target)
        return facts


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
