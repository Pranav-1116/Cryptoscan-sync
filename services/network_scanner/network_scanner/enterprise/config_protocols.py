"""NETCONF / RESTCONF / gNMI scanners — structured crypto configuration.

These protocols give far higher accuracy than banner scanning for modern
Cisco and multi-vendor infrastructure. The scanners are transport-agnostic:
live transports are injected (``ncclient`` SSH for NETCONF, httpx for
RESTCONF, grpcio for gNMI), and every scanner is fully unit-tested against
fake transports that speak the same data shapes.

Security rule: credentials are vault references only; secrets never enter
scan records.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Callable

from network_scanner.enterprise.credentials import CredentialRef, scrub_secrets

CRYPTO_FILTERS = ("crypto", "ipsec", "ike", "ssh", "tls", "certificates", "routing-security")


class ConfigProtocolError(Exception):
    pass


def _parse_xml_data(payload: Any) -> dict[str, Any]:
    """Best-effort XML (NETCONF) or JSON (RESTCONF) -> nested dict."""
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str):
        text = payload.strip()
        if text.startswith("{"):
            import json

            try:
                return json.loads(text)
            except ValueError as exc:
                raise ConfigProtocolError(f"invalid JSON: {exc}") from exc
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise ConfigProtocolError(f"invalid XML: {exc}") from exc
        return _etree_to_dict(root)
    return {}


def _etree_to_dict(element: ET.Element) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for child in element:
        tag = child.tag.split("}")[-1]
        text = (child.text or "").strip()
        children = list(child)
        if children:
            out[tag] = _etree_to_dict(child)
        elif text:
            out[tag] = text
        else:
            out.setdefault(tag, None)
    return out


# ------------------------------------------------------------------ NETCONF


class NetconfScanner:
    """NETCONF (RFC 6241) over an injected SSH transport.

    ``transport`` must expose ``get(filter_xml) -> str`` and, optionally,
    ``capabilities``. With no transport, live mode fails honestly.
    """

    def __init__(self, transport: Any = None, *, credential: CredentialRef | None = None,
                 device: str = "") -> None:
        self.transport = transport
        self.credential = credential
        self.device = device

    def build_get_filter(self, subtree: str = "crypto") -> str:
        return (
            "<filter type='subtree'>"
            f"<native xmlns='http://cisco.com/ns/yang/Cisco-IOS-XE-native'>{subtree}</native>"
            "</filter>"
        )

    def collect_crypto_configuration(self) -> dict[str, Any]:
        if self.transport is None:
            raise ConfigProtocolError(
                "no NETCONF transport (install ncclient or inject a transport); "
                "credential ref: %s" % (self.credential.ref if self.credential else "none")
            )
        payloads: dict[str, Any] = {}
        for subtree in CRYPTO_FILTERS:
            try:
                raw = self.transport.get(self.build_get_filter(subtree))
                payloads[subtree] = _parse_xml_data(raw)
            except Exception as exc:  # noqa: BLE001
                payloads[subtree] = {"error": f"{type(exc).__name__}: {str(exc)[:120]}"}
        return scrub_secrets(payloads)


# ------------------------------------------------------------------ RESTCONF


class RestconfScanner:
    """RESTCONF (RFC 8040) over an injected HTTP client.

    ``client`` must expose ``get(url) -> {"status": int, "json": dict}`` or
    ``get(url) -> dict``. The default client uses httpx when available.
    """

    def __init__(self, client: Any = None, *, base_url: str = "",
                 credential: CredentialRef | None = None, device: str = "") -> None:
        self.client = client or _HttpxRestconfClient(base_url)
        self.base_url = base_url
        self.credential = credential
        self.device = device

    def collect_crypto_configuration(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for module in ("Cisco-IOS-XE-crypto", "Cisco-IOS-XE-ipsec", "Cisco-IOS-XE-ike",
                       "Cisco-IOS-XE-ssh", "Cisco-IOS-XE-certificates"):
            url = f"{self.base_url.rstrip('/')}/restconf/data/{module}?content=config"
            try:
                result = self.client.get(url)
                data = result.get("json") if isinstance(result, dict) and "json" in result else result
                if isinstance(result, dict) and result.get("status") not in (200, 201, None):
                    out[module] = {"error": f"http {result.get('status')}"}
                else:
                    out[module] = _parse_xml_data(data)
            except Exception as exc:  # noqa: BLE001
                out[module] = {"error": f"{type(exc).__name__}: {str(exc)[:120]}"}
        return scrub_secrets(out)


class _HttpxRestconfClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    def get(self, url: str) -> dict[str, Any]:
        try:
            import httpx  # type: ignore
        except ImportError as exc:
            raise ConfigProtocolError("httpx not installed") from exc
        response = httpx.get(url, verify=False, timeout=5.0)
        try:
            payload = response.json()
        except Exception:
            payload = response.text
        return {"status": response.status_code, "json": payload}


# ------------------------------------------------------------------ gNMI


class GnmiScanner:
    """gNMI (RFC 8011-style telemetry/config) over an injected transport.

    ``transport`` must expose ``get(paths: list[str]) -> dict[str, Any]``.
    The gRPC transport is only imported when a real client is injected —
    grpcio is an optional dependency.
    """

    def __init__(self, transport: Any = None, *, credential: CredentialRef | None = None,
                 device: str = "") -> None:
        self.transport = transport
        self.credential = credential
        self.device = device

    def collect_crypto_configuration(self) -> dict[str, Any]:
        if self.transport is None:
            raise ConfigProtocolError(
                "no gNMI transport (install grpcio + inject a client); "
                "credential ref: %s" % (self.credential.ref if self.credential else "none")
            )
        paths = [
            "/interfaces/interface[name=*]/routing-policy",
            "/interfaces/interface[name=*]/security/ipsec",
            "/system/ssh/server",
            "/system/aaa",
            "/network-instances/network-instance[name=*]/protocols",
        ]
        try:
            data = self.transport.get(paths)
            return scrub_secrets(_parse_xml_data(data))
        except Exception as exc:  # noqa: BLE001
            raise ConfigProtocolError(f"gNMI get failed: {exc}") from exc


def discover_with_config_protocols(device: str, *, kind: str, **kwargs: Any) -> dict[str, Any]:
    """One-call helper: run the right scanner for the configured protocol."""
    if kind.upper() == "NETCONF":
        return NetconfScanner(**kwargs).collect_crypto_configuration()
    if kind.upper() == "RESTCONF":
        return RestconfScanner(**kwargs).collect_crypto_configuration()
    if kind.upper() == "GNMI":
        return GnmiScanner(**kwargs).collect_crypto_configuration()
    raise ConfigProtocolError(f"unknown config protocol '{kind}'")
