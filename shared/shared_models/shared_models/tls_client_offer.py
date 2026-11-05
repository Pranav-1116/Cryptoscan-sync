"""What a client put on the wire: one bounded ClientHello, observed — never completed.

The protocol floor's leading blind spot was "runtime client acceptance": a declaration
says what a configuration allows, but what a client actually offers in a real handshake
was not evidence this build collected. This module is that evidence, at the same
standard as ``tls_session``: one explicitly approved observation surface, bounded wire
bytes, a sealed fact, and a refusal to say anything the bytes do not say.

Two rules shape the parsing:

* **an offer is not a negotiation.** A ClientHello lists what the client is willing to
  speak. The probe sends no ServerHello and completes no handshake (``handshake_completed``
  is a sealed ``False``), so nothing here may be read as "the client used X" — only as
  "the client offered X". The floor's negotiated bucket must never be satisfied by one
  of these facts.
* **a value this parser cannot name is echoed verbatim.** GREASE decoys (RFC 8701) are
  dropped with a count, because they are deliberately not offers; anything else that is
  not on the version table is published as its codepoint (``0x7A7A``), never renamed and
  never silently absorbed into a known version.

The observation surface is inbound: the collector binds an approved numeric endpoint and
records the ClientHellos that arrive. A client that never connected to that endpoint is
not covered, and the estate must say so rather than assume its offer matched its config.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Literal

from pydantic import Field, model_validator

from shared_models.host_common import Strict

KIND = "NETWORK_TLS_CLIENT_OFFER"
OPERATION = "OBSERVE_APPROVED_CLIENT_HELLO"
#: one ClientHello record + framing headroom; a hello larger than this is refused
WIRE_LIMIT = 131072
HELLO_LIMIT = 4096
#: bounded observation window per approved input: offers seen, not offers forced
MAX_OFFERS = 16
MAX_OFFERED_VALUES = 64

#: Wire codepoints whose *name* this build knows. Everything else is echoed as its
#: codepoint: inventing a name for a codepoint is inventing a fact.
VERSION_NAMES: dict[int, str] = {
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}
SUITE_NAMES: dict[int, str] = {
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}
GROUP_NAMES: dict[int, str] = {
    23: "secp256r1",
    24: "secp384r1",
    25: "secp521r1",
    29: "x25519",
    30: "x448",
    256: "ffdhe2048",
    257: "ffdhe3072",
    258: "ffdhe4096",
}
#: a rung name, or a codepoint echoed exactly as it appeared on the wire
VALUE_PATTERN = r"^(?:TLSv\d+(?:\.\d+)*|SSLv\d+(?:\.\d+)*|0x[0-9A-F]{4,6}|[A-Za-z0-9][A-Za-z0-9_-]{0,62})$"


def endpoint(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def client_offer_resource(path: str) -> tuple[str, int]:
    """The approved *inbound* observation endpoint: where the probe may bind and listen."""
    match = re.fullmatch(r"tls-client-offer://(\[[0-9a-f:]+\]|[0-9.]+):([1-9][0-9]{0,4})", path)
    if not match:
        raise ValueError("Exact numeric bind endpoint required")
    host, port = match.groups()
    ip = ipaddress.ip_address(host.strip("[]"))
    if (
        host != ("[" + str(ip) + "]" if ip.version == 6 else str(ip))
        or int(port) > 65535
        or ip.is_multicast
        or ip.is_unspecified
        or str(ip) == "255.255.255.255"
        or ip.version == 6
        and (ip.is_link_local or ip.ipv4_mapped is not None)
    ):
        raise ValueError("Noncanonical/unsupported numeric bind endpoint")
    return str(ip), int(port)


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE: ``0x?A?A``. A decoy, deliberately not an offer."""
    return value & 0x0F0F == 0x0A0A


def _codepoint(value: int, names: dict[int, str]) -> str:
    return names.get(value, f"0x{value:04X}")


def parse_client_hello(data: bytes) -> dict[str, object]:
    """Parse one bounded handshake message and return only what it actually offers.

    Refuses rather than guesses: a truncated list, a second ``supported_versions``, a
    non-ClientHello handshake or an over-long message raises ``ValueError``, and the
    caller records a refusal instead of a fact.
    """
    if not 44 <= len(data) <= HELLO_LIMIT or data[0] != 1 or int.from_bytes(data[1:4], "big") != len(data) - 4:
        raise ValueError("Malformed bounded ClientHello")
    body = data[4:]
    legacy = int.from_bytes(body[:2], "big")
    if not 0x0300 <= legacy <= 0x0304:
        raise ValueError("Unsupported legacy version codepoint")
    pos = 2 + 32
    sid_len = body[pos]
    pos += 1 + sid_len
    if sid_len > 32 or pos + 2 > len(body):
        raise ValueError("Invalid session ID")
    suites_len = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    if suites_len % 2 or not 2 <= suites_len <= 2 * MAX_OFFERED_VALUES or pos + suites_len + 1 > len(body):
        raise ValueError("Invalid cipher suite list")
    raw_suites = [int.from_bytes(body[i : i + 2], "big") for i in range(pos, pos + suites_len, 2)]
    pos += suites_len
    comp_len = body[pos]
    pos += 1 + comp_len
    if comp_len < 1 or pos > len(body) or 0 not in body[pos - comp_len : pos]:
        raise ValueError("Invalid compression methods")
    extensions: dict[int, bytes] = {}
    if pos < len(body):
        if pos + 2 > len(body):
            raise ValueError("Truncated extension length")
        total = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        end = pos + total
        if end != len(body):
            raise ValueError("Invalid extension block length")
        while pos < end:
            if pos + 4 > end or len(extensions) >= 32:
                raise ValueError("Truncated/too many extensions")
            kind = int.from_bytes(body[pos : pos + 2], "big")
            n = int.from_bytes(body[pos + 2 : pos + 4], "big")
            pos += 4
            if kind in extensions or pos + n > end:
                raise ValueError("Duplicate/truncated extension")
            extensions[kind] = body[pos : pos + n]
            pos += n

    grease = 0
    for value in raw_suites:
        grease += is_grease(value)
    suites = [_codepoint(v, SUITE_NAMES) for v in raw_suites if not is_grease(v)]
    if not suites:
        raise ValueError("A ClientHello with no non-GREASE cipher suite offers nothing")

    raw_versions: list[int] = []
    versions_field = "supported_versions"
    if 43 in extensions:
        payload = extensions[43]
        if not payload:
            raise ValueError("Empty supported_versions extension")
        n = payload[0]
        if n % 2 or n == 0 or 1 + n != len(payload):
            raise ValueError("Invalid supported_versions list")
        raw_versions = [int.from_bytes(payload[i : i + 2], "big") for i in range(1, 1 + n, 2)]
    else:
        # TLS 1.2 and earlier: the legacy_version field *is* the offer
        raw_versions = [legacy]
        versions_field = "legacy_version"
    for value in raw_versions:
        grease += is_grease(value)
    versions = [_codepoint(v, VERSION_NAMES) for v in raw_versions if not is_grease(v)]
    if not versions:
        raise ValueError("A ClientHello whose versions are all GREASE offers nothing")

    groups: list[str] = []
    if 10 in extensions:
        payload = extensions[10]
        n = int.from_bytes(payload[:2], "big") if len(payload) >= 2 else 0
        if n % 2 or 2 + n != len(payload) or n // 2 > MAX_OFFERED_VALUES:
            raise ValueError("Invalid supported_groups list")
        raw_groups = [int.from_bytes(payload[i : i + 2], "big") for i in range(2, 2 + n, 2)]
        for value in raw_groups:
            grease += is_grease(value)
        groups = [_codepoint(v, GROUP_NAMES) for v in raw_groups if not is_grease(v)]

    sigalgs: list[str] = []
    if 13 in extensions:
        payload = extensions[13]
        n = int.from_bytes(payload[:2], "big") if len(payload) >= 2 else 0
        if n % 2 or 2 + n != len(payload) or n // 2 > MAX_OFFERED_VALUES:
            raise ValueError("Invalid signature_algorithms list")
        sigalgs = [f"0x{int.from_bytes(payload[i:i + 2], 'big'):04X}" for i in range(2, 2 + n, 2)]

    sni: str | None = None
    if 0 in extensions:
        payload = extensions[0]
        if len(payload) < 5 or payload[2] != 0:
            raise ValueError("Invalid server_name extension")
        n = int.from_bytes(payload[3:5], "big")
        if 5 + n != len(payload) or not 1 <= n <= 253:
            raise ValueError("Invalid server_name list")
        try:
            sni = payload[5:].decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("SNI must be canonical ASCII") from None
        if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in sni.split(".")):
            raise ValueError("Canonical ASCII DNS SNI required; no wildcard/implicit IDNA")

    alpn: list[str] = []
    if 16 in extensions:
        payload = extensions[16]
        if len(payload) < 3:
            raise ValueError("Invalid ALPN extension")
        n = int.from_bytes(payload[:2], "big")
        if 2 + n != len(payload):
            raise ValueError("Invalid ALPN list length")
        pos = 2
        while pos < 2 + n:
            size = payload[pos]
            if not 1 <= size <= 32 or pos + 1 + size > 2 + n:
                raise ValueError("Invalid ALPN protocol name")
            try:
                alpn.append(payload[pos + 1 : pos + 1 + size].decode("ascii"))
            except UnicodeDecodeError:
                raise ValueError("ALPN names must be ASCII") from None
            pos += 1 + size

    return {
        "legacy_version": _codepoint(legacy, VERSION_NAMES),
        "versions_field": versions_field,
        "offered_versions": versions,
        "offered_cipher_suites": suites,
        "offered_groups": groups,
        "offered_signature_algorithms": sigalgs,
        "sni": sni,
        "alpn": alpn,
        "grease_values_seen": grease,
    }


def selected_bytes(fact) -> bytes:
    if hasattr(fact, "model_dump"):
        fact = fact.model_dump(mode="json")
    return json.dumps(
        {k: v for k, v in fact.items() if k != "interface_sha256"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


class TlsClientOfferFact(Strict):
    """One sealed observation: client X, connecting to an approved probe, offered these."""

    kind: Literal["NETWORK_TLS_CLIENT_OFFER"] = "NETWORK_TLS_CLIENT_OFFER"
    local_basis: Literal["OBSERVED"] = "OBSERVED"
    purpose: Literal["CLIENT_HELLO_OFFERS_OBSERVED"] = "CLIENT_HELLO_OFFERS_OBSERVED"
    interface: Literal["BOUND_NUMERIC_LISTEN_SOCKET_CLIENT_HELLO_ONLY"] = (
        "BOUND_NUMERIC_LISTEN_SOCKET_CLIENT_HELLO_ONLY"
    )
    algorithm: Literal["UNKNOWN"] = "UNKNOWN"
    key_size: None = None
    software_name: None = None
    software_version: None = None
    runtime_use: Literal["UNKNOWN"] = "UNKNOWN"
    operation_use: Literal["UNKNOWN"] = "UNKNOWN"
    policy_result: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    pqc_assessment: Literal["UNKNOWN"] = "UNKNOWN"
    capabilities_observed: Literal[False] = False
    reviewed_target_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorized_operation: Literal["OBSERVE_APPROVED_CLIENT_HELLO"] = "OBSERVE_APPROVED_CLIENT_HELLO"
    bind_address: str = Field(max_length=45)
    bind_port: int = Field(ge=1, le=65535, strict=True)
    client_address: str = Field(max_length=45)
    client_port: int = Field(ge=1, le=65535, strict=True)
    sni: str | None = Field(default=None, max_length=253)
    offered_versions: list[str] = Field(min_length=1, max_length=32)
    offered_cipher_suites: list[str] = Field(min_length=1, max_length=MAX_OFFERED_VALUES)
    offered_groups: list[str] = Field(default_factory=list, max_length=MAX_OFFERED_VALUES)
    offered_signature_algorithms: list[str] = Field(default_factory=list, max_length=MAX_OFFERED_VALUES)
    alpn: list[str] = Field(default_factory=list, max_length=16)
    grease_values_seen: int = Field(default=0, ge=0, le=32, strict=True)
    versions_field: Literal["supported_versions", "legacy_version"] = "supported_versions"
    wire_bytes_received: int = Field(ge=1, le=HELLO_LIMIT, strict=True)
    handshake_completed: Literal[False] = False
    application_data_sent: Literal[False] = False
    client_identity_resolved: Literal[False] = False
    identity_key: str = Field(max_length=400)
    interface_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def consistent(self):
        import re as _re

        for value in [*self.offered_versions, *self.offered_cipher_suites,
                     *self.offered_groups, *self.offered_signature_algorithms]:
            if not _re.fullmatch(VALUE_PATTERN, value):
                raise ValueError("Offered value is neither a known name nor an echoed codepoint")
        client_offer_resource(f"tls-client-offer://{endpoint(self.bind_address, self.bind_port)}")
        if self.wire_bytes_received + len(selected_bytes(self)) > WIRE_LIMIT:
            raise ValueError("Combined client-offer byte limit exceeded")
        expected = (
            "tls-client-endpoint:" + endpoint(self.bind_address, self.bind_port)
            + ":client:" + endpoint(self.client_address, self.client_port)
        )
        if self.identity_key != expected or hashlib.sha256(selected_bytes(self)).hexdigest() != self.interface_sha256:
            raise ValueError("Client-offer identity/selected commitment mismatch")
        return self


def seal_offer(*, on_selected=None, **value) -> TlsClientOfferFact:
    fact = TlsClientOfferFact.model_construct(**value, interface_sha256="0" * 64)
    if on_selected is not None:
        on_selected(selected_bytes(fact))
    return TlsClientOfferFact.model_validate(
        {**fact.model_dump(mode="json"), "interface_sha256": hashlib.sha256(selected_bytes(fact)).hexdigest()}
    )


def validate_offer(item, facts) -> None:
    """Every offer must come from the approved bind endpoint, at most once per client.

    An empty list is a valid answer — the probe was bound for the whole window and no
    client connected. That is ``NOT_OBSERVED``, and the collector records it as a failed
    read rather than an estate with no weak clients.
    """
    approved = client_offer_resource(item.path)
    seen: set[tuple[str, int]] = set()
    for fact in facts:
        if (fact.bind_address, fact.bind_port) != approved:
            raise ValueError("Client offer observed outside the approved bind endpoint")
        key = (fact.client_address, fact.client_port)
        if key in seen:
            raise ValueError("One offer per client connection per input")
        seen.add(key)


__all__ = [
    "HELLO_LIMIT",
    "KIND",
    "MAX_OFFERS",
    "OPERATION",
    "TlsClientOfferFact",
    "VALUE_PATTERN",
    "WIRE_LIMIT",
    "client_offer_resource",
    "endpoint",
    "is_grease",
    "parse_client_hello",
    "seal_offer",
    "selected_bytes",
    "validate_offer",
]
