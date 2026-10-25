"""One explicitly approved TLS session, not endpoint inventory or PKI authority."""

import hashlib
import ipaddress
import json
import re
from typing import Literal
from pydantic import Field, model_validator
from shared_models.host_common import Strict

KIND = "NETWORK_TLS_SESSION"
OPERATION = "OBSERVE_APPROVED_TLS_SESSION"
WIRE_LIMIT = 131072
PEER_LIMIT = 65536


def endpoint(ip, port):
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def tls_resource(path):
    match = re.fullmatch(
        r"tls-session://(\[[0-9a-f:]+\]|[0-9.]+):([1-9][0-9]{0,4})/sni/([a-z0-9.-]{1,253})"
        r"/version/(TLSv1\.[23])/peer/sha256/([0-9a-f]{64})",
        path,
    )
    if not match:
        raise ValueError("Exact numeric endpoint/SNI/version/certificate pin required")
    host, port, sni, version, pin = match.groups()
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
        raise ValueError("Noncanonical/unsupported numeric endpoint")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in sni.split(".")):
        raise ValueError("Canonical ASCII DNS SNI required; no wildcard/implicit IDNA")
    try:
        ipaddress.ip_address(sni)
    except ValueError:
        pass
    else:
        raise ValueError("SNI must be a reviewed DNS name, not an IP")
    return str(ip), int(port), sni, version, pin


def selected_bytes(fact):
    if hasattr(fact, "model_dump"):
        fact = fact.model_dump(mode="json")
    return json.dumps(
        {k: v for k, v in fact.items() if k != "interface_sha256"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


class TlsPeerCertificate(Strict):
    fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    algorithm: Literal["RSA", "EC", "DSA", "ED25519", "ED448", "UNKNOWN"]
    key_size: int | None = Field(ge=1, le=65536)
    curve: Literal["secp256r1", "secp384r1", "secp521r1", "UNKNOWN"]
    signature_hash: Literal["SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "UNKNOWN"]
    certificate_signature_oid: str = Field(max_length=100, pattern=r"^(UNKNOWN|[0-9]+(?:\.[0-9]+)+)$")

    @model_validator(mode="after")
    def consistent(self):
        if (
            self.algorithm in {"RSA", "EC", "DSA"}
            and self.key_size is None
            or self.algorithm in {"ED25519", "ED448", "UNKNOWN"}
            and self.key_size is not None
            or self.algorithm != "EC"
            and self.curve != "UNKNOWN"
        ):
            raise ValueError("Certificate public metadata mismatch")
        if (
            self.curve != "UNKNOWN"
            and self.key_size != {"secp256r1": 256, "secp384r1": 384, "secp521r1": 521}[self.curve]
        ):
            raise ValueError("Certificate curve/size mismatch")
        return self


class TlsSessionFact(Strict):
    kind: Literal["NETWORK_TLS_SESSION"] = "NETWORK_TLS_SESSION"
    local_basis: Literal["OBSERVED"] = "OBSERVED"
    purpose: Literal["ONE_PINNED_NEGOTIATED_TLS_SESSION"] = "ONE_PINNED_NEGOTIATED_TLS_SESSION"
    interface: Literal["EXPLICIT_NUMERIC_TCP_TLS_MEMORY_BIO"] = "EXPLICIT_NUMERIC_TCP_TLS_MEMORY_BIO"
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
    authorized_operation: Literal["OBSERVE_APPROVED_TLS_SESSION"] = "OBSERVE_APPROVED_TLS_SESSION"
    address: str = Field(max_length=45)
    port: int = Field(ge=1, le=65535, strict=True)
    sni: str = Field(max_length=253)
    tls_version: Literal["TLSv1.2", "TLSv1.3"]
    cipher_suite: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    cipher_bits: int = Field(ge=1, le=512, strict=True)
    certificate: TlsPeerCertificate
    peer_der_bytes: int = Field(ge=1, le=PEER_LIMIT, strict=True)
    wire_bytes_sent: int = Field(ge=1, le=WIRE_LIMIT, strict=True)
    wire_bytes_received: int = Field(ge=1, le=WIRE_LIMIT, strict=True)
    identity_key: str = Field(max_length=400)
    interface_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    negotiated_session_observed: Literal[True] = True
    peer_fingerprint_matched: Literal[True] = True
    certificate_chain_validated: Literal[False] = False
    hostname_validated: Literal[False] = False
    revocation_checked: Literal[False] = False
    all_tls_versions_tested: Literal[False] = False
    application_data_sent: Literal[False] = False
    application_identity_verified: Literal[False] = False
    key_exchange_group: Literal["UNKNOWN"] = "UNKNOWN"
    server_signature_scheme: Literal["UNKNOWN"] = "UNKNOWN"

    @model_validator(mode="after")
    def consistent(self):
        path = (
            f"tls-session://{endpoint(self.address, self.port)}/sni/{self.sni}/version/{self.tls_version}"
            f"/peer/sha256/{self.certificate.fingerprint_sha256}"
        )
        tls_resource(path)
        modern = {"TLS_AES_128_GCM_SHA256": 128, "TLS_AES_256_GCM_SHA384": 256, "TLS_CHACHA20_POLY1305_SHA256": 256}
        if (
            self.tls_version == "TLSv1.3"
            and modern.get(self.cipher_suite) != self.cipher_bits
            or self.tls_version == "TLSv1.2"
            and self.cipher_suite.startswith("TLS_")
        ):
            raise ValueError("Cipher suite/version/strength mismatch")
        if (
            self.wire_bytes_sent + self.wire_bytes_received + self.peer_der_bytes + len(selected_bytes(self))
            > WIRE_LIMIT
        ):
            raise ValueError("Combined TLS session byte limit exceeded")
        expected = "tls-endpoint:" + endpoint(self.address, self.port) + ":sni:" + self.sni
        if self.identity_key != expected or hashlib.sha256(selected_bytes(self)).hexdigest() != self.interface_sha256:
            raise ValueError("TLS identity/selected commitment mismatch")
        return self


def seal_session(*, on_selected=None, **value):
    fact = TlsSessionFact.model_construct(**value, interface_sha256="0" * 64)
    if on_selected is not None:
        on_selected(selected_bytes(fact))
    return TlsSessionFact.model_validate(
        {**fact.model_dump(mode="json"), "interface_sha256": hashlib.sha256(selected_bytes(fact)).hexdigest()}
    )


def validate_session(item, facts):
    if facts:
        if len(facts) != 1:
            raise ValueError("Exactly one TLS session per approved input")
        f = facts[0]
        if (f.address, f.port, f.sni, f.tls_version, f.certificate.fingerprint_sha256) != tls_resource(item.path):
            raise ValueError("TLS session outside approved endpoint/SNI/version/pin")


def client_session(sni, version):
    """No connect/discovery here. Shared constrained TLS setup for explicit callers."""
    import ssl

    if version not in {"TLSv1.2", "TLSv1.3"}:
        raise ValueError("Explicit supported TLS version required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Fingerprint pin is checked by caller, not PKI validation.
    context.minimum_version = context.maximum_version = getattr(ssl.TLSVersion, version.replace(".", "_"))
    context.options |= ssl.OP_NO_TICKET
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    return context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=sni), incoming, outgoing
