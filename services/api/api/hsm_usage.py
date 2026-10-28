"""HSM *usage* observation over KMIP (spec 67 §17; spec 93 §13).

An HSM could previously only be described from a vendor questionnaire. KMIP is the
vendor-neutral way to ask one — Thales, Entrust, Utimaco, Fortanix and the rest
speak it — and KMIP 2.0 carries the attributes that separate "this key exists" from
"this key has been used":

* ``Usage Limits`` (total / count / unit) — the appliance's own counter of the
  operations performed against the key;
* ``State`` — PreActive / Active / Deactivated / Compromised / Destroyed;
* ``Cryptographic Usage Mask`` — what the key *may* do (capability);
* ``Initial Date`` / ``Activation Date`` / ``Process Start Date`` — lifecycle.

Read-only, three calls, no key material: ``Locate`` filtered to symmetric keys,
then ``GetAttributes`` per key. ``Get`` (which would return the key value) is never
issued, and nothing here can create, rotate, revoke or destroy anything.

Usage state, honestly:

* ``OBSERVED`` — the appliance's usage counter is above zero: operations really ran;
* ``CONFIGURED`` — the key is Active but its counter is zero or absent: it may be
  used, and this read cannot prove that it was;
* ``SUPPORTED`` — Pre-Activated: a key exists and could do crypto, nothing more;
* ``NOT_OBSERVED`` — Deactivated/Compromised/Destroyed: not in use, and the reason
  is recorded rather than the key being silently dropped.

The TTLV tags below are not from memory: they were checked against the ``pykmip``
tag/attribute enumerations (KMIP 1.0–2.0) while writing this module — a wrong tag
number produces a message the appliance rejects, which would look like "no keys".
"""

from __future__ import annotations

import os
import socket
import ssl
import struct
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from api.estate_planes import PlaneNotConfigured
from shared_models.estate_graph import make_evidence, normalize_asset

SCHEMA = "cryptoscan.hsm-usage/1"
PLANE = "HSM"

#: KMIP TTLV tags (verified against pykmip 0.11.0 `enums.Tags`)
TAG_REQUEST_MESSAGE = 0x420078
TAG_RESPONSE_MESSAGE = 0x42007B
TAG_REQUEST_HEADER = 0x420077
TAG_RESPONSE_HEADER = 0x42007A
TAG_PROTOCOL_VERSION = 0x420069
TAG_PROTOCOL_VERSION_MAJOR = 0x42006A
TAG_PROTOCOL_VERSION_MINOR = 0x42006B
TAG_BATCH_COUNT = 0x42000D
TAG_BATCH_ITEM = 0x42000F
TAG_OPERATION = 0x42005C
TAG_REQUEST_PAYLOAD = 0x420079
TAG_RESPONSE_PAYLOAD = 0x42007C
TAG_RESULT_STATUS = 0x42007F
TAG_RESULT_REASON = 0x42007E
TAG_RESULT_MESSAGE = 0x42007D
TAG_UNIQUE_IDENTIFIER = 0x420094
TAG_ATTRIBUTE = 0x420008
TAG_ATTRIBUTE_NAME = 0x42000A
TAG_MAXIMUM_ITEMS = 0x42004F
TAG_LOCATED_ITEMS = 0x4200D5
TAG_OBJECT_TYPE = 0x420057
TAG_CRYPTOGRAPHIC_ALGORITHM = 0x420028
TAG_CRYPTOGRAPHIC_USAGE_MASK = 0x42002C
TAG_STATE = 0x42008D
TAG_USAGE_LIMITS = 0x420095
TAG_USAGE_LIMITS_COUNT = 0x420096
TAG_USAGE_LIMITS_TOTAL = 0x420097
TAG_USAGE_LIMITS_UNIT = 0x420098
TAG_INITIAL_DATE = 0x420039
TAG_ACTIVATION_DATE = 0x420001
TAG_PROCESS_START_DATE = 0x420067
TAG_DEACTIVATION_DATE = 0x42002F
TAG_LAST_CHANGE_DATE = 0x420048

#: KMIP TTLV type octets
TTLV_STRUCTURE = 0x01
TTLV_INTEGER = 0x02
TTLV_LONG_INTEGER = 0x03
TTLV_ENUMERATION = 0x05
TTLV_BOOLEAN = 0x06
TTLV_TEXT_STRING = 0x07
TTLV_BYTE_STRING = 0x08
TTLV_DATE_TIME = 0x09
TTLV_INTERVAL = 0x0A

OPERATION_LOCATE = 0x00000008
OPERATION_GET_ATTRIBUTES = 0x0000000B

RESULT_SUCCESS = 0x00000000

#: KMIP Object Type enumeration
OBJECT_TYPE_SYMMETRIC_KEY = 0x00000002

#: KMIP State enumeration
STATE_PRE_ACTIVE = 0x00000001
STATE_ACTIVE = 0x00000002
STATE_DEACTIVATED = 0x00000003
STATE_COMPROMISED = 0x00000004
STATE_DESTROYED = 0x00000005
STATE_DESTROYED_COMPROMISED = 0x00000006

STATE_NAMES = {
    STATE_PRE_ACTIVE: "PRE_ACTIVE",
    STATE_ACTIVE: "ACTIVE",
    STATE_DEACTIVATED: "DEACTIVATED",
    STATE_COMPROMISED: "COMPROMISED",
    STATE_DESTROYED: "DESTROYED",
    STATE_DESTROYED_COMPROMISED: "DESTROYED_COMPROMISED",
}

#: KMIP Cryptographic Algorithm enumeration (the subset an estate actually meets)
ALGORITHM_NAMES = {
    0x00000001: "DES", 0x00000002: "3DES", 0x00000003: "AES", 0x00000004: "RSA",
    0x00000005: "DSA", 0x00000006: "ECDSA", 0x00000007: "HMAC_SHA1",
    0x00000008: "HMAC_SHA224", 0x00000009: "HMAC_SHA256", 0x0000000A: "HMAC_SHA384",
    0x0000000B: "HMAC_SHA512", 0x0000000D: "DH", 0x0000000E: "ECDH", 0x0000001A: "EC",
    0x0000001C: "CHACHA20", 0x0000001D: "POLY1305", 0x0000001E: "CHACHA20_POLY1305",
    0x0000001F: "SHA3_224", 0x00000020: "SHA3_256", 0x00000021: "SHA3_384",
    0x00000022: "SHA3_512",
}

#: Cryptographic Usage Mask bits → operation names
USAGE_MASK_BITS: tuple[tuple[int, str], ...] = (
    (0x00000001, "SIGN"), (0x00000002, "VERIFY"), (0x00000004, "ENCRYPT"), (0x00000008, "DECRYPT"),
    (0x00000010, "WRAP_KEY"), (0x00000020, "UNWRAP_KEY"), (0x00000040, "EXPORT"),
    (0x00000080, "MAC_GENERATE"), (0x00000100, "MAC_VERIFY"), (0x00000200, "DERIVE_KEY"),
    (0x00000800, "KEY_AGREEMENT"), (0x00100000, "AUTHENTICATE"),
)

#: attribute names as KMIP spells them (verified against pykmip `AttributeType`)
ATTR_NAMES = (
    "Object Type", "Cryptographic Algorithm", "Cryptographic Usage Mask", "State",
    "Usage Limits", "Initial Date", "Activation Date", "Process Start Date", "Deactivation Date",
    "Last Change Date",
)

Transport = Callable[[bytes], bytes]


# --------------------------------------------------------------------------- #
# TTLV encoding
# --------------------------------------------------------------------------- #
def _pad(payload: bytes) -> bytes:
    remainder = len(payload) % 8
    return payload + (b"\x00" * (8 - remainder) if remainder else b"")


def ttlv(tag: int, type_code: int, value: bytes) -> bytes:
    """One TTLV item: 3-byte tag, 1-byte type, 4-byte length, padded value."""
    return struct.pack(">I", tag)[1:] + bytes([type_code]) + struct.pack(">I", len(value)) + _pad(value)


def ttlv_structure(tag: int, *items: bytes) -> bytes:
    return ttlv(tag, TTLV_STRUCTURE, b"".join(items))


def ttlv_int(tag: int, value: int) -> bytes:
    return ttlv(tag, TTLV_INTEGER, struct.pack(">i", int(value)))


def ttlv_long(tag: int, value: int) -> bytes:
    return ttlv(tag, TTLV_LONG_INTEGER, struct.pack(">q", int(value)))


def ttlv_enum(tag: int, value: int) -> bytes:
    return ttlv(tag, TTLV_ENUMERATION, struct.pack(">I", int(value)))


def ttlv_text(tag: int, value: str) -> bytes:
    return ttlv(tag, TTLV_TEXT_STRING, str(value).encode("utf-8"))


def ttlv_datetime(tag: int, value: datetime) -> bytes:
    return ttlv(tag, TTLV_DATE_TIME, struct.pack(">q", int(value.timestamp())))


def decode(data: bytes) -> list[dict[str, Any]]:
    """Parse a TTLV stream into ``{tag, type, value, items}`` dicts."""
    items: list[dict[str, Any]] = []
    offset = 0
    while offset + 8 <= len(data):
        tag = int.from_bytes(data[offset:offset + 3], "big")
        type_code = data[offset + 3]
        length = struct.unpack(">I", data[offset + 4:offset + 8])[0]
        body = data[offset + 8:offset + 8 + length]
        if len(body) < length:
            break
        item: dict[str, Any] = {"tag": tag, "type": type_code, "raw": body, "items": []}
        if type_code == TTLV_STRUCTURE:
            item["items"] = decode(body)
            item["value"] = None
        elif type_code == TTLV_INTEGER:
            item["value"] = struct.unpack(">i", body[:4])[0] if len(body) >= 4 else None
        elif type_code == TTLV_LONG_INTEGER:
            item["value"] = struct.unpack(">q", body[:8])[0] if len(body) >= 8 else None
        elif type_code == TTLV_ENUMERATION:
            item["value"] = struct.unpack(">I", body[:4])[0] if len(body) >= 4 else None
        elif type_code == TTLV_BOOLEAN:
            item["value"] = bool(body and body[0])
        elif type_code == TTLV_TEXT_STRING:
            item["value"] = body.decode("utf-8", "replace")
        elif type_code == TTLV_DATE_TIME:
            item["value"] = (
                datetime.fromtimestamp(struct.unpack(">q", body[:8])[0], tz=timezone.utc)
                if len(body) >= 8 else None
            )
        else:
            item["value"] = body
        items.append(item)
        offset += 8 + len(_pad(body))
    return items


def _find(items: Iterable[dict[str, Any]], tag: int) -> dict[str, Any] | None:
    for item in items:
        if item["tag"] == tag:
            return item
    return None


def _all(items: Iterable[dict[str, Any]], tag: int) -> list[dict[str, Any]]:
    return [item for item in items if item["tag"] == tag]


# --------------------------------------------------------------------------- #
# request building
# --------------------------------------------------------------------------- #
def _message(operation: int, payload_items: list[bytes]) -> bytes:
    header = ttlv_structure(
        TAG_REQUEST_HEADER,
        ttlv_structure(TAG_PROTOCOL_VERSION,
                       ttlv_int(TAG_PROTOCOL_VERSION_MAJOR, 2),
                       ttlv_int(TAG_PROTOCOL_VERSION_MINOR, 0)),
        ttlv_int(TAG_BATCH_COUNT, 1),
    )
    batch = ttlv_structure(
        TAG_BATCH_ITEM,
        ttlv_enum(TAG_OPERATION, operation),
        ttlv_structure(TAG_REQUEST_PAYLOAD, *payload_items),
    )
    return ttlv_structure(TAG_REQUEST_MESSAGE, header, batch)


def locate_request(*, maximum_items: int = 200) -> bytes:
    """Locate every symmetric key. Read-only; no filter on state so retired keys show up too."""
    attribute = ttlv_structure(
        TAG_ATTRIBUTE,
        ttlv_text(TAG_ATTRIBUTE_NAME, "Object Type"),
        ttlv_enum(TAG_OBJECT_TYPE, OBJECT_TYPE_SYMMETRIC_KEY),
    )
    return _message(OPERATION_LOCATE, [ttlv_int(TAG_MAXIMUM_ITEMS, maximum_items), attribute])


def get_attributes_request(unique_identifier: str, names: Iterable[str] = ATTR_NAMES) -> bytes:
    """Ask for the attributes that distinguish existence from use. Never ``Get``."""
    items = [ttlv_text(TAG_UNIQUE_IDENTIFIER, unique_identifier)]
    items.extend(ttlv_text(TAG_ATTRIBUTE_NAME, name) for name in names)
    return _message(OPERATION_GET_ATTRIBUTES, items)


# --------------------------------------------------------------------------- #
# response parsing
# --------------------------------------------------------------------------- #
class KmipError(RuntimeError):
    """The appliance answered with a failure result or an unparseable message."""


def _batch_item(response: bytes) -> dict[str, Any]:
    root = decode(response)
    message = _find(root, TAG_RESPONSE_MESSAGE)
    if message is None:
        raise KmipError("response is not a KMIP ResponseMessage")
    batch = _find(message["items"], TAG_BATCH_ITEM)
    if batch is None:
        raise KmipError("response has no BatchItem")
    return batch


def parse_locate(response: bytes) -> list[str]:
    """The unique identifiers the appliance returned."""
    batch = _batch_item(response)
    payload = _find(batch["items"], TAG_RESPONSE_PAYLOAD)
    if payload is None:
        return []
    located = _find(payload["items"], TAG_LOCATED_ITEMS)
    if located is None:
        return []
    return [str(item["value"]) for item in _all(located["items"], TAG_UNIQUE_IDENTIFIER) if item["value"]]


def _usage_limits(attribute: dict[str, Any]) -> dict[str, Any] | None:
    limits = _find(attribute["items"], TAG_USAGE_LIMITS)
    if limits is None:
        return None
    total = _find(limits["items"], TAG_USAGE_LIMITS_TOTAL)
    count = _find(limits["items"], TAG_USAGE_LIMITS_COUNT)
    unit = _find(limits["items"], TAG_USAGE_LIMITS_UNIT)
    unit_names = {0x00000001: "BYTE", 0x00000002: "OBJECT", 0x00000003: "PERMISSION"}
    return {
        "total": total["value"] if total else None,
        "count": count["value"] if count else None,
        "unit": unit_names.get(unit["value"], str(unit["value"])) if unit else None,
    }


def parse_attributes(response: bytes) -> dict[str, Any]:
    """Flatten the GetAttributes response into the handful of fields we judge on."""
    batch = _batch_item(response)
    status = _find(batch["items"], TAG_RESULT_STATUS)
    if status is not None and status["value"] not in (None, RESULT_SUCCESS):
        reason = _find(batch["items"], TAG_RESULT_REASON)
        message = _find(batch["items"], TAG_RESULT_MESSAGE)
        raise KmipError(
            f"KMIP result status {status['value']}"
            + (f" ({reason['value']})" if reason else "")
            + (f": {message['value']}" if message else "")
        )
    payload = _find(batch["items"], TAG_RESPONSE_PAYLOAD)
    attributes: dict[str, Any] = {}
    if payload is None:
        return attributes
    identifier = _find(payload["items"], TAG_UNIQUE_IDENTIFIER)
    if identifier is not None:
        attributes["unique_identifier"] = identifier["value"]
    for attribute in _all(payload["items"], TAG_ATTRIBUTE):
        name = _find(attribute["items"], TAG_ATTRIBUTE_NAME)
        label = str(name["value"]) if name and name["value"] else ""
        if label == "Object Type":
            item = _find(attribute["items"], TAG_OBJECT_TYPE)
            attributes["object_type"] = item["value"] if item else None
        elif label == "Cryptographic Algorithm":
            item = _find(attribute["items"], TAG_CRYPTOGRAPHIC_ALGORITHM)
            if item is not None:
                attributes["algorithm"] = ALGORITHM_NAMES.get(item["value"], str(item["value"]))
        elif label == "Cryptographic Usage Mask":
            item = _find(attribute["items"], TAG_CRYPTOGRAPHIC_USAGE_MASK)
            if item is not None:
                mask = int(item["value"] or 0)
                attributes["usage_mask"] = mask
                attributes["capabilities"] = [name_ for bit, name_ in USAGE_MASK_BITS if mask & bit]
                known = 0
                for bit, _name in USAGE_MASK_BITS:
                    known |= bit
                # a bit this reader does not know is reported, never ignored: an
                # unread capability is an open question, not an absent one
                attributes["usage_mask_unmapped"] = [
                    hex(mask & ~known & (1 << position))
                    for position in range(mask.bit_length())
                    if (mask & ~known) & (1 << position)
                ]
        elif label == "State":
            item = _find(attribute["items"], TAG_STATE)
            if item is not None:
                attributes["state"] = STATE_NAMES.get(item["value"], str(item["value"]))
                attributes["state_code"] = item["value"]
        elif label == "Usage Limits":
            attributes["usage_limits"] = _usage_limits(attribute)
        elif label == "Initial Date":
            item = _find(attribute["items"], TAG_INITIAL_DATE)
            if item is not None:
                attributes["initial_date"] = _stamp(item["value"])
        elif label == "Activation Date":
            item = _find(attribute["items"], TAG_ACTIVATION_DATE)
            if item is not None:
                attributes["activation_date"] = _stamp(item["value"])
        elif label == "Process Start Date":
            item = _find(attribute["items"], TAG_PROCESS_START_DATE)
            if item is not None:
                attributes["process_start_date"] = _stamp(item["value"])
        elif label == "Deactivation Date":
            item = _find(attribute["items"], TAG_DEACTIVATION_DATE)
            if item is not None:
                attributes["deactivation_date"] = _stamp(item["value"])
        elif label == "Last Change Date":
            item = _find(attribute["items"], TAG_LAST_CHANGE_DATE)
            if item is not None:
                attributes["last_change_date"] = _stamp(item["value"])
    return attributes


def _stamp(value: Any) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else None


def usage_state(attributes: Mapping[str, Any]) -> tuple[str, str]:
    """``(usage_state, reason)`` — existence, capability and use are kept apart."""
    state = str(attributes.get("state") or "UNKNOWN")
    limits = attributes.get("usage_limits") or {}
    count = limits.get("count") if isinstance(limits, Mapping) else None
    if state in {"DEACTIVATED", "COMPROMISED", "DESTROYED", "DESTROYED_COMPROMISED"}:
        return "NOT_OBSERVED", f"the key is {state}: it cannot be doing crypto now"
    if isinstance(count, int) and count > 0:
        return "OBSERVED", (
            f"the appliance's own usage counter is {count}"
            f"{' of ' + str(limits['total']) if limits.get('total') else ''} — operations really ran"
        )
    if state == "ACTIVE":
        return "CONFIGURED", (
            "the key is Active but its usage counter is zero or absent: it may be used, and this read cannot "
            "prove that it was"
        )
    return "SUPPORTED", f"the key is {state}: it exists and could do crypto, nothing more"


# --------------------------------------------------------------------------- #
# configuration and transport
# --------------------------------------------------------------------------- #
def hsm_config(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """KMIP endpoint + credentials, or :class:`PlaneNotConfigured`."""
    env = dict(os.environ if environ is None else environ)
    host = str(env.get("KMIP_HOST") or "").strip()
    if not host:
        raise PlaneNotConfigured(
            "no HSM is configured: set KMIP_HOST (and KMIP_PORT, plus KMIP_CLIENT_CERT/KMIP_CLIENT_KEY or "
            "KMIP_USERNAME/KMIP_PASSWORD) to read key usage from the appliance"
        )
    config: dict[str, Any] = {
        "host": host,
        "port": int(env.get("KMIP_PORT") or 5696),
        "username": str(env.get("KMIP_USERNAME") or "").strip() or None,
        "password": str(env.get("KMIP_PASSWORD") or "") or None,
        "client_cert": str(env.get("KMIP_CLIENT_CERT") or "").strip() or None,
        "client_key": str(env.get("KMIP_CLIENT_KEY") or "").strip() or None,
        "ca_file": str(env.get("KMIP_CA_FILE") or "").strip() or None,
        "insecure": str(env.get("KMIP_INSECURE") or "").lower() in {"1", "true", "yes"},
        "timeout": float(env.get("KMIP_TIMEOUT") or 10.0),
        "source": "ENVIRONMENT",
    }
    if config["insecure"]:
        # a lab-only escape hatch; recorded in the result so nobody mistakes it for TLS
        config["tls_verification"] = "DISABLED"
    else:
        config["tls_verification"] = "REQUIRED"
    return config


def tls_transport(config: Mapping[str, Any]) -> Transport:
    """A TLS transport to the appliance; one request, one response, no reuse."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if config.get("insecure"):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    elif config.get("ca_file"):
        context.load_verify_locations(cafile=str(config["ca_file"]))
    if config.get("client_cert") and config.get("client_key"):
        context.load_cert_chain(str(config["client_cert"]), str(config["client_key"]))
    host, port = str(config["host"]), int(config["port"])

    def send(request: bytes) -> bytes:
        with socket.create_connection((host, port), timeout=float(config.get("timeout") or 10.0)) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                tls.sendall(request)
                return _read_message(tls)

    return send


def _read_message(sock: Any) -> bytes:
    """Read one TTLV message: the length of the outer structure tells us when to stop."""
    header = _recv_exact(sock, 8)
    length = struct.unpack(">I", header[4:8])[0]
    body = _recv_exact(sock, length + ((8 - length % 8) % 8))
    return header + body


def _recv_exact(sock: Any, count: int) -> bytes:
    chunks = b""
    while len(chunks) < count:
        chunk = sock.recv(count - len(chunks))
        if not chunk:
            raise KmipError("the appliance closed the connection mid-message")
        chunks += chunk
    return chunks


# --------------------------------------------------------------------------- #
# collector
# --------------------------------------------------------------------------- #
def collect_hsm_usage(
    _db: Any = None,
    *,
    transport: Transport | None = None,
    config: Mapping[str, Any] | None = None,
    max_keys: int = 200,
) -> dict[str, Any]:
    """Locate symmetric keys and read their usage attributes — read-only."""
    resolved = dict(config) if config else hsm_config()
    resolved.setdefault("source", "INJECTED")
    resolved.setdefault("tls_verification", "INJECTED")
    send = transport or tls_transport(resolved)

    assets: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    blocked: list[str] = []
    limitations: list[str] = [
        "read-only KMIP: Locate + GetAttributes. The Get operation (which returns key material) is never issued, "
        "and nothing here can create, rotate, revoke or destroy a key",
        "usage counters are the appliance's own; a zero counter means 'not counted', which is reported as "
        "CONFIGURED, not as 'unused'",
    ]
    answered = 0

    try:
        identifiers = parse_locate(send(locate_request(maximum_items=max_keys)))
        answered += 1
    except (KmipError, OSError) as exc:
        blocked.append(f"kmip:Locate: {exc}")
        limitations.append(f"KMIP Locate failed ({exc}) — the HSM's keys are NOT_OBSERVED, not absent")
        identifiers = []

    if len(identifiers) >= max_keys:
        limitations.append(
            f"the {max_keys}-key cap was reached — further keys were NOT read, so this inventory is PARTIAL"
        )
    if not identifiers and not blocked:
        limitations.append("the appliance returned no symmetric keys — an empty partition, not an empty HSM estate")

    appliance_name = str(resolved.get("host") or "hsm")
    # the appliance is part of the estate whether or not it answered: a failed read
    # is an UNKNOWN appliance, not a missing one
    appliance = normalize_asset("HARDWARE", appliance_name, identity={"model": appliance_name},
                                source="kmip",
                                attributes={"kmip_endpoint": f"{resolved.get('host')}:{resolved.get('port')}",
                                            "tls_verification": resolved.get("tls_verification"),
                                            "reachable": bool(answered)})
    assets.append(appliance)
    appliance_id = appliance["asset_id"]

    for identifier in identifiers:
        try:
            attributes = parse_attributes(send(get_attributes_request(identifier)))
            answered += 1
        except (KmipError, OSError) as exc:
            blocked.append(f"kmip:GetAttributes({identifier}): {exc}")
            limitations.append(
                f"key {identifier}: attributes could not be read ({exc}) — its usage is NOT_OBSERVED"
            )
            continue
        state, reason = usage_state(attributes)
        key_asset = normalize_asset(
            "HSM", identifier,
            identity={"vendor": appliance_name, "serial_number": identifier},
            source="kmip",
            attributes={
                "object_type": "SYMMETRIC_KEY",
                "algorithm": attributes.get("algorithm"),
                "capabilities": attributes.get("capabilities"),
                "state": attributes.get("state"),
                "kmip_endpoint": f"{resolved.get('host')}:{resolved.get('port')}",
            },
        )
        assets.append(key_asset)
        evidence.append(make_evidence(
            source="kmip",
            evidence_type="CONFIGURED",
            target=key_asset["asset_id"],
            layer="HSM",
            collector="kmip:GetAttributes",
            facts={
                "unique_identifier": identifier,
                "state": attributes.get("state"),
                "algorithm": attributes.get("algorithm"),
                "capabilities": attributes.get("capabilities"),
                "usage_mask": attributes.get("usage_mask"),
                "usage_mask_unmapped": attributes.get("usage_mask_unmapped") or [],
                "usage_limits": attributes.get("usage_limits"),
                "usage_state": state,
                "usage_reason": reason,
                "initial_date": attributes.get("initial_date"),
                "activation_date": attributes.get("activation_date"),
                "deactivation_date": attributes.get("deactivation_date"),
                "claim": (
                    "the appliance reports this key's state and counters; key material is never read"
                ),
            },
        ))

    return {
        "schema": SCHEMA,
        "plane": PLANE,
        "provider": "KMIP",
        "appliance": appliance_name,
        "endpoint": f"{resolved.get('host')}:{resolved.get('port')}",
        "tls_verification": resolved.get("tls_verification"),
        "expected": max(1, len(identifiers)),
        "collected": answered,
        "assets": assets,
        "evidence": evidence,
        "relationships": [],
        "blocked": blocked,
        "keys_read": len([item for item in assets if item["type"] == "HSM"]),
        "appliance_asset_id": appliance_id or None,
        "note": (
            "HSM key state and usage counters over KMIP: capability, lifecycle and observed use, never key "
            "material"
        ),
        "limitations": limitations,
    }
