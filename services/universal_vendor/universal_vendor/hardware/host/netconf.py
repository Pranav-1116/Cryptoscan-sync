"""NETCONF -> hardware facts (phase H5): the devices that do not speak SNMP.

Plenty of bank network estates answer SNMP and stop there, but the ones that
matter most — firewalls, load balancers, newer switches with SNMP disabled by
policy — speak NETCONF over SSH and nothing else. This module reads them.

What is here and what is not:

* **The protocol is here.** ``<hello>`` exchange, capability negotiation,
  ``<rpc>``/``<get>`` with a subtree filter, ``<rpc-error>`` handling, and
  parsers for ``ietf-system`` and ``ietf-hardware`` (RFC 8348) — the YANG models
  that carry hostname, chassis serial, model and firmware revision.
* **The transport is injected.** :class:`SshNetconfTransport` builds a fixed
  argv for the OpenSSH client (``ssh -o BatchMode=yes … -s <host> netconf``)
  with the host validated against a hostname grammar and ``--`` before the
  positional, exactly as the SSH host-key probe does. Tests inject an
  ``exchange`` callable instead, so the whole protocol path runs without a
  network.
* **Credentials do not survive.** The password or key reference is used to open
  the session and is never placed on the facts; a payload echoing it is refused
  (:class:`~universal_vendor.hardware.host.credentials.CredentialLeakRefused`).

An appliance that answers with an ``<rpc-error>`` gets that error text as a
reason — a NETCONF server saying "access denied" is a fact about the estate,
not an empty device.
"""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404 - fixed argv, shell=False, validated host
from dataclasses import dataclass, field
from typing import Any, Callable
from xml.etree import ElementTree

from universal_vendor.hardware.host.credentials import (
    refuse_credential_echo,
    refuse_secret_shapes,
)
from universal_vendor.hardware.host.snmp_bridge import NetworkDeviceFacts

SCHEMA = "cryptoscan.netconf-hardware/1"

BASE_10 = "urn:ietf:params:netconf:base:1.0"
BASE_11 = "urn:ietf:params:netconf:base:1.1"
SUPPORTED_BASES = (BASE_10, BASE_11)

SYSTEM_NS = "urn:ietf:params:xml:ns:yang:ietf-system"
HARDWARE_NS = "urn:ietf:params:xml:ns:yang:ietf-hardware"

#: Only the SSH client may be executed, and only in NETCONF subsystem mode.
ALLOWED_BINARIES = frozenset({"ssh"})
_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._\-]{0,253}[A-Za-z0-9])?$")

_SSH_OPTIONS = (
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", "ConnectTimeout=10",
)


class NetconfError(RuntimeError):
    """The session or the RPC failed in a way the caller must see."""


class TransportUnavailable(RuntimeError):
    """No transport is configured for this deployment."""


@dataclass(frozen=True)
class NetconfReply:
    """One decoded ``<rpc-reply>``."""

    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    error_type: str | None = None


# --------------------------------------------------------------------------- #
# XML helpers
# --------------------------------------------------------------------------- #

def _local(tag: str) -> str:
    """``{urn:…}hostname`` -> ``hostname``: YANG modules differ, names do not."""
    return tag.rsplit("}", 1)[-1]


def _children(element: ElementTree.Element) -> dict[str, Any]:
    """Flatten one element's children by local name; repeated names become lists."""
    out: dict[str, Any] = {}
    for child in element:
        name = _local(child.tag)
        value: Any = (child.text or "").strip() if len(child) == 0 else _children(child)
        if name in out:
            if not isinstance(out[name], list):
                out[name] = [out[name]]
            out[name].append(value)
        else:
            out[name] = value
    return out


def parse_hello(xml_text: str) -> list[str]:
    """Capabilities advertised in a ``<hello>``."""
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise NetconfError(f"hello is not XML: {exc}") from exc
    if _local(root.tag) != "hello":
        raise NetconfError(f"expected <hello>, got <{_local(root.tag)}>")
    capabilities: list[str] = []
    for child in root:
        if _local(child.tag) == "capabilities":
            for capability in child:
                text = (capability.text or "").strip()
                if text:
                    capabilities.append(text)
    return capabilities


def base_capability(capabilities: list[str]) -> str | None:
    """The highest NETCONF base version both ends can speak."""
    for wanted in (BASE_11, BASE_10):
        if wanted in capabilities:
            return wanted
    return None


def build_hello() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
        f"<capabilities><capability>{BASE_10}</capability>"
        f"<capability>{BASE_11}</capability></capabilities>"
        "<session-id>1</session-id></hello>"
    )


def build_get(message_id: str = "1") -> str:
    """A read-only ``<get>`` for the two models this module understands.

    No ``<edit-config>`` exists in this module at all: the collector is
    read-only by construction, not by a flag somebody can flip.
    """
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<rpc message-id="' + message_id + '" '
        'xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
        "<get><filter type=\"subtree\">"
        f'<system xmlns="{SYSTEM_NS}"><hostname/><location/></system>'
        f'<hardware xmlns="{HARDWARE_NS}"><component>'
        "<name/><class/><serial-num/><model-name/><hardware-rev/><firmware-rev/>"
        "<software-rev/><manufacturer/>"
        "</component></hardware>"
        "</filter></get></rpc>"
    )


def parse_rpc_reply(xml_text: str) -> NetconfReply:
    """Decode a ``<rpc-reply>`` into system facts, components, or an error."""
    if not (xml_text or "").strip():
        return NetconfReply(ok=False, error="empty reply — the session closed")
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        return NetconfReply(ok=False, error=f"reply is not XML: {exc}")
    if _local(root.tag) != "rpc-reply":
        return NetconfReply(ok=False, error=f"expected <rpc-reply>, got <{_local(root.tag)}>")

    for child in root:
        if _local(child.tag) != "rpc-error":
            continue
        fields = _children(child)
        message = fields.get("error-message") or "an <rpc-error> with no message"
        return NetconfReply(ok=False, error=str(message),
                            error_type=str(fields.get("error-type") or "unknown"))

    data: dict[str, Any] = {"system": {}, "components": []}
    for child in root:
        if _local(child.tag) != "data":
            continue
        for section in child:
            name = _local(section.tag)
            if name == "system":
                data["system"] = _children(section)
            elif name == "hardware":
                components = [component for element in section
                              if _local(element.tag) == "component"
                              for component in [_children(element)]]
                data["components"] = components
    return NetconfReply(ok=True, data=data)


def select_chassis(components: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The chassis, not a fan tray that also has a serial.

    Same rule as the SNMP bridge: a box with twelve field-replaceable parts must
    not be inventoried as whichever part the device happened to list first.
    """
    if not components:
        return None
    for component in components:
        if str(component.get("class", "")).lower() == "chassis" and \
                component.get("serial-num"):
            return component
    for component in components:
        if component.get("serial-num"):
            return component
    for component in components:
        if str(component.get("class", "")).lower() == "chassis":
            return component
    return None


# --------------------------------------------------------------------------- #
# transports
# --------------------------------------------------------------------------- #

class SshNetconfTransport:
    """OpenSSH in NETCONF subsystem mode: one fixed argv, no shell.

    The password handling is deliberately out of scope: the session rides on the
    agent's mTLS-registered key material through an SSH key or an
    ``ssh-agent``, and a password that must be typed interactively is a reason
    to use the vendor API instead. ``BatchMode=yes`` makes that explicit
    instead of hanging on a prompt nobody can answer.
    """

    def __init__(self, *, runner: Callable[[list[str]], tuple[int, str, str]] | None = None,
                 timeout: float = 20.0) -> None:
        self._runner = runner or self._subprocess_runner
        self.timeout = timeout

    @staticmethod
    def build_argv(host: str) -> list[str]:
        if not _HOSTNAME.match(host or ""):
            raise NetconfError(f"{host!r} is not a hostname; NETCONF takes a host, not a "
                               "command line")
        return ["ssh", *_SSH_OPTIONS, "--", host, "-s", "netconf"]

    def __call__(self, host: str, request: str) -> str:
        argv = self.build_argv(host)
        binary = shutil.which(argv[0])
        if binary is None:
            raise TransportUnavailable("the OpenSSH client is not installed")
        code, stdout, stderr = self._runner([binary, *argv[1:]])
        if code != 0:
            raise NetconfError(f"ssh exited {code}: {(stderr or '').strip()[:200]}")
        return stdout

    def _subprocess_runner(self, argv: list[str]) -> tuple[int, str, str]:
        completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False
            argv, capture_output=True, text=True, timeout=self.timeout, check=False,
            shell=False,
            input=build_hello(),
        )
        return completed.returncode, completed.stdout, completed.stderr


Exchange = Callable[[str, str], str]


# --------------------------------------------------------------------------- #
# the collector
# --------------------------------------------------------------------------- #

class NetconfCollector:
    """Read one device over NETCONF and normalise it into hardware facts."""

    def __init__(self, exchange: Exchange | None = None) -> None:
        self._exchange = exchange

    def _send(self, host: str, request: str) -> str:
        transport = self._exchange or SshNetconfTransport()
        return transport(host, request)

    def collect(self, host: str, *, credential_ref: str | None = None,
                device_type: str = "switch") -> NetworkDeviceFacts:
        facts = NetworkDeviceFacts(host=host, transport="netconf",
                                   security_mode="NETCONF-over-SSH")
        try:
            greeting = self._send(host, build_hello())
        except (NetconfError, TransportUnavailable, OSError) as exc:
            facts.unavailable.append(f"netconf {host}: {exc}")
            return facts
        try:
            capabilities = parse_hello(greeting)
        except NetconfError as exc:
            facts.unavailable.append(f"netconf {host}: {exc}")
            return facts
        if base_capability(capabilities) is None:
            facts.unavailable.append(
                f"netconf {host}: no common NETCONF base capability "
                f"(server offered {len(capabilities)} capabilit(ies), none of "
                f"{list(SUPPORTED_BASES)})")
            return facts
        facts.sources["session"] = base_capability(capabilities) or ""

        try:
            reply_text = self._send(host, build_get())
        except (NetconfError, TransportUnavailable, OSError) as exc:
            facts.unavailable.append(f"netconf {host}: {exc}")
            return facts

        reply = parse_rpc_reply(reply_text)
        if not reply.ok:
            facts.unavailable.append(
                f"netconf {host}: {reply.error}"
                + (f" ({reply.error_type})" if reply.error_type else "")
                + " — an <rpc-error> is a permissions answer, not an empty device")
            return facts

        facts.reachable = True
        self._apply(facts, reply.data, device_type)
        refuse_credential_echo(facts.context, credential_ref, host=host,
                               kind="credential reference")
        refuse_secret_shapes(facts.context, host=host)
        return facts

    @staticmethod
    def _apply(facts: NetworkDeviceFacts, data: dict[str, Any], device_type: str) -> None:
        system = data.get("system") or {}
        chassis = select_chassis(data.get("components") or [])
        facts.sys_name = _text(system.get("hostname"))
        facts.sys_location = _text(system.get("location"))
        if chassis is not None:
            facts.serial_reference = _text(chassis.get("serial-num"))
            facts.model = _text(chassis.get("model-name"))
            facts.firmware = _text(chassis.get("firmware-rev")) or \
                _text(chassis.get("software-rev"))
            facts.vendor = _text(chassis.get("manufacturer"))
            facts.sources["chassis"] = "ietf-hardware"
        if facts.firmware is None and chassis is not None:
            facts.sources.pop("firmware", None)
        facts.context = {
            "asset_id": facts.sys_name or facts.host,
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
                "protocol": "netconf",
            },
        }


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
