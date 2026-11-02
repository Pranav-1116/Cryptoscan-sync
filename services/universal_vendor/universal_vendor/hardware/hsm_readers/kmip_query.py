"""KMIP ``Query`` -> HSM capabilities (phase H4).

PKCS#11 tells you what a partition can do *once you can open it*. ``Query`` asks
the appliance itself, over the same KMIP session a bank already runs, and it
needs no PIN for the capability surface: which operations the server supports,
which object types, which profiles it claims, and — the useful part — its
**vendor identification**, which names the appliance without trusting a banner.

This is a capability reader, and it is deliberately narrow:

* the only operation this module can build is ``Query`` (0x18). There is no
  ``Get``, no ``Locate``, no ``Create``, and no key identifier anywhere in the
  code — a capability question does not need an object to answer it;
* the TTLV tag numbers below were read from the ``pykmip`` 0.10.0 enumerations
  while writing this module, not recalled. A wrong tag does not fail loudly on
  the wire; it produces a message the appliance rejects, which then looks like
  "no capabilities";
* algorithm names are not part of a standard ``Query`` response. Cryptographic
  algorithms come from PKCS#11 mechanisms (see :mod:`.pkcs11`) or a vendor API,
  and this module says so rather than inventing them.

.. note::
   KMIP 2.1 added post-quantum algorithm enumerations that ``pykmip`` 0.10.0
   predates. Where a server returns an algorithm code this table does not know,
   the parser reports ``unknown_0x…`` instead of guessing a name — an HSM whose
   ML-DSA support is mislabelled is worse than one whose code is unresolvable.
"""

from __future__ import annotations

import socket
import ssl
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

SCHEMA = "cryptoscan.hsm-kmip-query/1"

# ── TTLV encoding ───────────────────────────────────────────────────────────
TTLV_STRUCTURE = 0x01
TTLV_INTEGER = 0x02
TTLV_ENUMERATION = 0x05
TTLV_TEXT = 0x07

TAG_REQUEST_MESSAGE = 0x420078
TAG_REQUEST_HEADER = 0x420077
TAG_RESPONSE_MESSAGE = 0x42007B
TAG_BATCH_ITEM = 0x42000F
TAG_OPERATION = 0x42005C
TAG_REQUEST_PAYLOAD = 0x420079
TAG_RESPONSE_PAYLOAD = 0x42007C
TAG_RESULT_STATUS = 0x42007F
TAG_RESULT_REASON = 0x42007E
TAG_RESULT_MESSAGE = 0x42007D
TAG_PROTOCOL_VERSION = 0x420069
TAG_PROTOCOL_VERSION_MAJOR = 0x42006A
TAG_PROTOCOL_VERSION_MINOR = 0x42006B
TAG_BATCH_COUNT = 0x42000D
TAG_QUERY_FUNCTION = 0x420074
TAG_OPERATIONS = 0x42014F  # note: the *response* tag is distinct from the request's
TAG_OBJECTS = 0x42014E
TAG_SERVER_INFORMATION = 0x420088
TAG_VENDOR_IDENTIFICATION = 0x42009D
TAG_SERVER_SERIAL_NUMBER = 0x42012E
TAG_PROFILE_INFORMATION = 0x4200EB
TAG_NAME = 0x420053

OPERATION_QUERY = 0x00000018
RESULT_SUCCESS = 0x00000000

#: QueryFunction values (KMIP 1.0–1.2), read from pykmip 0.10.0.
QUERY_OPERATIONS = 0x00000001
QUERY_OBJECTS = 0x00000002
QUERY_SERVER_INFORMATION = 0x00000003
QUERY_PROFILES = 0x0000000A
QUERY_CAPABILITIES = 0x0000000B

#: Every function this module can ask for — all read-only by definition.
READ_FUNCTIONS = (QUERY_OPERATIONS, QUERY_OBJECTS, QUERY_SERVER_INFORMATION,
                  QUERY_PROFILES)

#: Operation codes -> names (pykmip 0.10.0 `Operation`).
_OPERATIONS: dict[int, str] = {
    0x01: "create", 0x02: "create_key_pair", 0x03: "register", 0x04: "rekey",
    0x05: "derive_key", 0x06: "certify", 0x07: "recertify", 0x08: "locate",
    0x09: "check", 0x0A: "get", 0x0B: "get_attributes", 0x0C: "get_attribute_list",
    0x0D: "add_attribute", 0x0E: "modify_attribute", 0x0F: "delete_attribute",
    0x10: "obtain_lease", 0x11: "get_usage_allocation", 0x12: "activate",
    0x13: "revoke", 0x14: "destroy", 0x15: "archive", 0x16: "recover",
    0x17: "validate", 0x18: "query", 0x19: "cancel", 0x1A: "poll", 0x1B: "notify",
    0x1C: "put", 0x1D: "rekey_key_pair", 0x1E: "discover_versions", 0x1F: "encrypt",
    0x20: "decrypt", 0x21: "sign", 0x22: "signature_verify", 0x23: "mac",
    0x24: "mac_verify", 0x25: "rng_retrieve", 0x26: "rng_seed", 0x27: "hash",
}
_OBJECTS: dict[int, str] = {
    0x01: "certificate", 0x02: "symmetric_key", 0x03: "public_key",
    0x04: "private_key", 0x05: "split_key", 0x06: "template", 0x07: "secret_data",
    0x08: "opaque_data", 0x09: "pgp_key", 0x0A: "certificate_request",
}
_ALGORITHMS: dict[int, str] = {
    0x01: "DES", 0x02: "3DES", 0x03: "AES", 0x04: "RSA", 0x05: "DSA", 0x06: "ECDSA",
    0x07: "HMAC-SHA1", 0x08: "HMAC-SHA224", 0x09: "HMAC-SHA256", 0x0A: "HMAC-SHA384",
    0x0B: "HMAC-SHA512", 0x0C: "HMAC-MD5", 0x0D: "DH", 0x0E: "ECDH", 0x0F: "ECMQV",
    0x10: "Blowfish", 0x11: "Camellia", 0x12: "CAST5", 0x1A: "EC",
    0x1C: "ChaCha20", 0x1D: "Poly1305", 0x1E: "ChaCha20-Poly1305",
    0x1F: "SHA3-224", 0x20: "SHA3-256", 0x21: "SHA3-384", 0x22: "SHA3-512",
    0x29: "ARIA", 0x2A: "SEED", 0x2B: "SM2", 0x2C: "SM3", 0x2D: "SM4",
    0x32: "XMSS", 0x33: "SPHINCS-256", 0x34: "McEliece", 0x37: "Ed25519",
    0x38: "Ed448",
}

Transport = Callable[[bytes], bytes]


class KmipQueryError(RuntimeError):
    """The appliance answered with a failure result or an unreadable message."""


class FunctionNotAllowed(RuntimeError):
    """A Query function outside the read-only set was requested."""


# --------------------------------------------------------------------------- #
# TTLV
# --------------------------------------------------------------------------- #

def _pad(payload: bytes) -> bytes:
    remainder = len(payload) % 8
    return payload + (b"\x00" * (8 - remainder) if remainder else b"")


def ttlv(tag: int, type_code: int, value: bytes) -> bytes:
    return struct.pack(">I", tag)[1:] + bytes([type_code]) + \
        struct.pack(">I", len(value)) + _pad(value)


def ttlv_structure(tag: int, *items: bytes) -> bytes:
    return ttlv(tag, TTLV_STRUCTURE, b"".join(items))


def ttlv_int(tag: int, value: int) -> bytes:
    return ttlv(tag, TTLV_INTEGER, struct.pack(">i", int(value)))


def ttlv_enum(tag: int, value: int) -> bytes:
    return ttlv(tag, TTLV_ENUMERATION, struct.pack(">I", int(value)))


def ttlv_text(tag: int, value: str) -> bytes:
    return ttlv(tag, TTLV_TEXT, str(value).encode("utf-8"))


def decode(data: bytes) -> list[dict[str, Any]]:
    """Parse a TTLV stream into ``{tag, type, value, items}`` nodes."""
    nodes: list[dict[str, Any]] = []
    offset = 0
    while offset + 8 <= len(data):
        tag = int.from_bytes(data[offset:offset + 3], "big")
        type_code = data[offset + 3]
        length = int.from_bytes(data[offset + 4:offset + 8], "big")
        start = offset + 8
        if start + length > len(data):
            raise KmipQueryError("truncated TTLV item")
        raw = data[start:start + length]
        node: dict[str, Any] = {"tag": tag, "type": type_code, "value": None, "items": []}
        if type_code == TTLV_STRUCTURE:
            node["items"] = decode(raw)
        elif type_code == TTLV_INTEGER:
            node["value"] = int.from_bytes(raw, "big", signed=True)
        elif type_code == TTLV_ENUMERATION:
            node["value"] = int.from_bytes(raw, "big") if raw else 0
        elif type_code == TTLV_TEXT:
            node["value"] = raw.decode("utf-8", errors="replace").rstrip("\x00")
        else:
            node["value"] = raw
        nodes.append(node)
        offset = start + length + (-length % 8)
    return nodes


def _find(nodes: Iterable[dict[str, Any]], tag: int) -> dict[str, Any] | None:
    for node in nodes:
        if node["tag"] == tag:
            return node
    return None


def _all(nodes: Iterable[dict[str, Any]], tag: int) -> list[dict[str, Any]]:
    return [node for node in nodes if node["tag"] == tag]


# --------------------------------------------------------------------------- #
# request
# --------------------------------------------------------------------------- #

def query_request(functions: Sequence[int] = READ_FUNCTIONS) -> bytes:
    """Build a read-only ``Query``. Nothing else can be built here."""
    for function in functions:
        if function not in READ_FUNCTIONS:
            raise FunctionNotAllowed(
                f"QueryFunction 0x{function:08X} is not read-only and this reader will "
                f"not ask it; allowed: {[hex(item) for item in READ_FUNCTIONS]}")
    header = ttlv_structure(
        TAG_REQUEST_HEADER,
        ttlv_structure(TAG_PROTOCOL_VERSION,
                       ttlv_int(TAG_PROTOCOL_VERSION_MAJOR, 2),
                       ttlv_int(TAG_PROTOCOL_VERSION_MINOR, 0)),
        ttlv_int(TAG_BATCH_COUNT, 1),
    )
    payload = ttlv_structure(
        TAG_REQUEST_PAYLOAD,
        *(ttlv_enum(TAG_QUERY_FUNCTION, function) for function in functions))
    batch = ttlv_structure(TAG_BATCH_ITEM, ttlv_enum(TAG_OPERATION, OPERATION_QUERY),
                           payload)
    return ttlv_structure(TAG_REQUEST_MESSAGE, header, batch)


# --------------------------------------------------------------------------- #
# response
# --------------------------------------------------------------------------- #

def parse_query_response(response: bytes) -> dict[str, Any]:
    """Decode a ``Query`` response into capabilities, or raise with the reason."""
    if not response:
        raise KmipQueryError("empty response — the session closed")
    root = decode(response)
    message = _find(root, TAG_RESPONSE_MESSAGE)
    if message is None:
        raise KmipQueryError("response is not a KMIP ResponseMessage")
    batch = _find(message["items"], TAG_BATCH_ITEM)
    if batch is None:
        raise KmipQueryError("response has no BatchItem")
    status = _find(batch["items"], TAG_RESULT_STATUS)
    code = status["value"] if status and isinstance(status["value"], int) else None
    if code != RESULT_SUCCESS:
        reason = _find(batch["items"], TAG_RESULT_REASON)
        detail = _find(batch["items"], TAG_RESULT_MESSAGE)
        raise KmipQueryError(
            "Query failed: "
            + (str(detail["value"]) if detail and detail["value"] else
               f"result status 0x{code:08X}" if isinstance(code, int) else "no result status")
            + (f" (reason 0x{reason['value']:08X})" if reason and
               isinstance(reason["value"], int) else ""))
    payload = _find(batch["items"], TAG_RESPONSE_PAYLOAD)
    if payload is None:
        raise KmipQueryError("Query succeeded but returned no payload")

    result: dict[str, Any] = {
        "schema": SCHEMA,
        "operations": [], "objects": [], "profiles": [],
        "vendor_identification": None, "server_serial_number": None,
        "supports_query": True,
    }
    for node in payload["items"]:
        if node["tag"] == TAG_OPERATIONS:
            result["operations"] = [_OPERATIONS.get(item["value"], f"unknown_{item['value']}")
                                    for item in _all(node["items"], TAG_OPERATION)
                                    if isinstance(item["value"], int)]
        elif node["tag"] == TAG_OBJECTS:
            result["objects"] = [_OBJECTS.get(item["value"], f"unknown_0x{item['value']:08X}")
                                 for item in _all(node["items"], TAG_OPERATION)
                                 if isinstance(item["value"], int)]
        elif node["tag"] == TAG_SERVER_INFORMATION:
            vendor = _find(node["items"], TAG_VENDOR_IDENTIFICATION)
            serial = _find(node["items"], TAG_SERVER_SERIAL_NUMBER)
            if vendor and vendor["value"]:
                result["vendor_identification"] = str(vendor["value"]).strip()
            if serial and serial["value"]:
                result["server_serial_number"] = str(serial["value"]).strip()
        elif node["tag"] == TAG_PROFILE_INFORMATION:
            name = _find(node["items"], TAG_NAME)
            if name and name["value"]:
                result["profiles"].append(str(name["value"]).strip())
    return result


def algorithm_name(code: int) -> str:
    """A KMIP algorithm enum -> its name, or an honest unknown."""
    return _ALGORITHMS.get(code, f"unknown_0x{code:08X}")


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #

def tls_transport(host: str, port: int = 5696, *, ca_file: str | None = None,
                  cert_file: str | None = None, key_file: str | None = None,
                  timeout: float = 10.0) -> Transport:
    """Mutual-TLS transport. The key material stays in the TLS layer.

    Certificates are *paths* the agent already holds; nothing about them is
    copied into a fact record, and this function returns no credential.
    """
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if cert_file:
        context.load_cert_chain(cert_file, key_file)

    def send(request: bytes) -> bytes:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                tls.sendall(struct.pack(">I", len(request)) + request)
                header = _recv_exact(tls, 4)
                size = struct.unpack(">I", header)[0]
                return _recv_exact(tls, size)

    return send


def _recv_exact(sock: Any, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise KmipQueryError(f"connection closed after {count - remaining} of {count} bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------- #
# the reader
# --------------------------------------------------------------------------- #

@dataclass
class KmipCapabilities:
    vendor_identification: str | None = None
    server_serial_number: str | None = None
    operations: list[str] = field(default_factory=list)
    objects: list[str] = field(default_factory=list)
    profiles: list[str] = field(default_factory=list)
    supports_query: bool = False
    unavailable: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "vendor_identification": self.vendor_identification,
            "server_serial_number": self.server_serial_number,
            "operations": list(self.operations),
            "objects": list(self.objects),
            "profiles": list(self.profiles),
            "supports_query": self.supports_query,
            "unavailable": list(self.unavailable),
        }

    def to_raw(self) -> dict[str, Any]:
        """The raw shape the HSM scanner reads.

        ``Query`` names the vendor and the capability surface; it does not name
        the firmware, so that field is left empty rather than filled with the
        protocol version.
        """
        return {
            "manufacturer": self.vendor_identification or "",
            "model": "",
            "firmware": None,
            "crypto_capabilities": list(self.profiles),
            "certificate_dependencies": [],
            "key_type_metadata": [],
            "supported_algorithms": [],
            "kmip_objects": list(self.objects),
        }


class KmipQueryReader:
    """Ask one appliance what it can do, without asking it for a key."""

    def __init__(self, transport: Transport | None = None) -> None:
        self._transport = transport

    def collect(self, transport: Transport | None = None) -> KmipCapabilities:
        capabilities = KmipCapabilities()
        send = transport or self._transport
        if send is None:
            capabilities.unavailable.append(
                "no KMIP transport configured: pass a TLS transport or a callable")
            return capabilities
        try:
            response = send(query_request())
        except (KmipQueryError, OSError) as exc:
            capabilities.unavailable.append(f"kmip query: {exc}")
            return capabilities
        try:
            parsed = parse_query_response(response)
        except KmipQueryError as exc:
            capabilities.unavailable.append(f"kmip query: {exc}")
            return capabilities
        capabilities.vendor_identification = parsed["vendor_identification"]
        capabilities.server_serial_number = parsed["server_serial_number"]
        capabilities.operations = parsed["operations"]
        capabilities.objects = parsed["objects"]
        capabilities.profiles = parsed["profiles"]
        capabilities.supports_query = True
        return capabilities
