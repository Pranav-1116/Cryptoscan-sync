"""Bounded public TLS 1.3 ServerHello evidence, not software/HSM/PQC readiness."""

import hashlib
from typing import Literal
from pydantic import Field, model_validator
from shared_models.tls_session import TlsSessionFact, WIRE_LIMIT, selected_bytes, tls_resource

KIND = "NETWORK_TLS13_KEY_SHARE"
PREFIX = "tls-key-share://"
HELLO_LIMIT = 4096
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
# Classical IDs: RFC 8446/7919; hybrid IDs: pinned OpenSSL 3.5.0 tlsgroups.h.
GROUPS = {
    23: "secp256r1",
    24: "secp384r1",
    25: "secp521r1",
    29: "X25519",
    30: "X448",
    256: "ffdhe2048",
    257: "ffdhe3072",
    258: "ffdhe4096",
    259: "ffdhe6144",
    260: "ffdhe8192",
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
}
SUITES = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256"}


def group_classification(group):
    if group in {0x11EB, 0x11EC, 0x11ED}:
        return "REGISTERED_HYBRID_GROUP_SELECTED"
    return "REGISTERED_CLASSICAL_GROUP_SELECTED" if group in GROUPS else "UNRECOGNIZED_GROUP"


def key_share_resource(path):
    if not path.startswith(PREFIX):
        raise ValueError("Explicit TLS key-share resource required")
    result = tls_resource("tls-session://" + path[len(PREFIX) :])
    if result[3] != "TLSv1.3":
        raise ValueError("Only TLS 1.3 final ServerHello key-share evidence supported")
    return result


def parse_hello(data):
    """Parse a complete public handshake message. HRR is a request, not negotiation."""
    if not 44 <= len(data) <= HELLO_LIMIT or data[0] != 2 or int.from_bytes(data[1:4], "big") != len(data) - 4:
        raise ValueError("Malformed bounded ServerHello")
    body = data[4:]
    if body[:2] != b"\x03\x03":
        raise ValueError("TLS 1.3 legacy version must be 0303")
    hrr = body[2:34] == HRR_RANDOM
    sid = body[34]
    pos = 35 + sid
    if sid > 32 or pos + 5 > len(body):
        raise ValueError("Invalid session ID")
    cipher = int.from_bytes(body[pos : pos + 2], "big")
    if cipher not in SUITES or body[pos + 2] != 0:
        raise ValueError("Unsupported cipher/compression")
    size = int.from_bytes(body[pos + 3 : pos + 5], "big")
    pos += 5
    if pos + size != len(body):
        raise ValueError("Invalid extension length")
    extensions = {}
    while pos < len(body):
        if pos + 4 > len(body) or len(extensions) >= 32:
            raise ValueError("Truncated/too many extensions")
        kind = int.from_bytes(body[pos : pos + 2], "big")
        n = int.from_bytes(body[pos + 2 : pos + 4], "big")
        pos += 4
        if kind in extensions or pos + n > len(body):
            raise ValueError("Duplicate/truncated extension")
        extensions[kind] = body[pos : pos + n]
        pos += n
    if extensions.get(43) != b"\x03\x04" or set(extensions) - ({43, 51, 44} if hrr else {43, 51}):
        raise ValueError("Not a supported fresh TLS 1.3 ServerHello")
    share = extensions.get(51)
    if hrr:
        if share is not None and len(share) != 2:
            raise ValueError("Invalid retry group request")
        return hrr, None if share is None else int.from_bytes(share, "big"), cipher
    if share is None or len(share) < 5 or int.from_bytes(share[2:4], "big") != len(share) - 4:
        raise ValueError("Missing/truncated/empty selected key share")
    group = int.from_bytes(share[:2], "big")
    expected = {23: 65, 24: 97, 25: 133, 29: 32, 30: 56, 256: 256, 257: 384, 258: 512, 259: 768, 260: 1024}.get(group)
    if expected is not None and len(share) - 4 != expected:
        raise ValueError("Classical public-share length mismatch")
    return False, group, cipher


class ServerHelloReader:
    """Incremental TLS record/handshake framing; stops at the final ServerHello."""

    def __init__(self):
        self.record = bytearray()
        self.handshake = bytearray()
        self.final = None
        self.retries = 0
        self.requested = None
        self.records_seen = 0
        self.retry_cipher = None

    def feed(self, data):
        if self.final is not None:
            return
        if len(data) > 16384 or len(self.record) + len(data) > 32773:
            raise ValueError("Record buffer bound")
        self.record.extend(data)
        while len(self.record) >= 5:
            kind = self.record[0]
            size = int.from_bytes(self.record[3:5], "big")
            if size > 16384 or bytes(self.record[1:3]) not in {b"\x03\x01", b"\x03\x03"}:
                raise ValueError("Unsupported plaintext record")
            if len(self.record) < 5 + size:
                return
            self.records_seen += 1
            if self.records_seen > 128:
                raise ValueError("Public record count bound")
            payload = bytes(self.record[5 : 5 + size])
            del self.record[: 5 + size]
            if kind == 20 and payload == b"\x01":
                continue
            if kind != 22:
                raise ValueError("Expected public ServerHello before encrypted traffic")
            if len(self.handshake) + len(payload) > HELLO_LIMIT:
                raise ValueError("Handshake buffer bound")
            self.handshake.extend(payload)
            while len(self.handshake) >= 4:
                n = 4 + int.from_bytes(self.handshake[1:4], "big")
                if n > HELLO_LIMIT:
                    raise ValueError("ServerHello bound")
                if len(self.handshake) < n:
                    break
                hello = bytes(self.handshake[:n])
                del self.handshake[:n]
                retry, group, cipher = parse_hello(hello)
                if retry:
                    if self.retries:
                        raise ValueError("Repeated HelloRetryRequest")
                    self.retries = 1
                    self.requested = group
                    self.retry_cipher = cipher
                else:
                    if self.retry_cipher is not None and cipher != self.retry_cipher:
                        raise ValueError("Retry/final cipher mismatch")
                    if self.requested is not None and group != self.requested:
                        raise ValueError("Retry/final group mismatch")
                    self.final = hello
                    self.record.clear()
                    self.handshake.clear()
                    return


class TlsKeyShareFact(TlsSessionFact):
    kind: Literal["NETWORK_TLS13_KEY_SHARE"] = "NETWORK_TLS13_KEY_SHARE"
    purpose: Literal["PINNED_TLS13_FINAL_SERVER_HELLO"] = "PINNED_TLS13_FINAL_SERVER_HELLO"
    tls_version: Literal["TLSv1.3"] = "TLSv1.3"
    key_exchange_group: str = Field(max_length=40)
    selected_group_id: int = Field(ge=0, le=65535, strict=True)
    group_classification: Literal[
        "REGISTERED_HYBRID_GROUP_SELECTED", "REGISTERED_CLASSICAL_GROUP_SELECTED", "UNRECOGNIZED_GROUP"
    ]
    server_hello_hex: str = Field(min_length=88, max_length=HELLO_LIMIT * 2, pattern=r"^(?:[0-9a-f]{2})+$")
    server_hello_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    hello_retry_request_seen: bool
    capture_basis: Literal["FINAL_SERVER_HELLO_SAME_PINNED_COMPLETED_HANDSHAKE"] = (
        "FINAL_SERVER_HELLO_SAME_PINNED_COMPLETED_HANDSHAKE"
    )
    group_classification_basis: Literal["PINNED_REGISTRY_MAPPING_NOT_IMPLEMENTATION_PROOF"] = (
        "PINNED_REGISTRY_MAPPING_NOT_IMPLEMENTATION_PROOF"
    )
    pqc_implementation_verified: Literal[False] = False
    pqc_readiness_verified: Literal[False] = False
    all_groups_tested: Literal[False] = False

    @model_validator(mode="after")
    def key_share_consistent(self):
        data = bytes.fromhex(self.server_hello_hex)
        retry, group, cipher = parse_hello(data)
        if (
            retry
            or group != self.selected_group_id
            or SUITES[cipher] != self.cipher_suite
            or self.key_exchange_group != GROUPS.get(group, "UNKNOWN")
            or self.group_classification != group_classification(group)
            or hashlib.sha256(data).hexdigest() != self.server_hello_sha256
        ):
            raise ValueError("Final ServerHello/group/cipher/commitment mismatch")
        if (
            self.wire_bytes_sent
            + self.wire_bytes_received
            + self.peer_der_bytes
            + len(data)
            + len(selected_bytes(self))
            > WIRE_LIMIT
        ):
            raise ValueError("Combined key-share session byte limit exceeded")
        return self
