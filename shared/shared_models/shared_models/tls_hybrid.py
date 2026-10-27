"""Explicit actual-hybrid session profile; never HSM or production readiness."""

from typing import Literal
from pydantic import Field, model_validator
from shared_models.tls_key_share import TlsKeyShareFact, key_share_resource

KIND = "NETWORK_TLS13_HYBRID"
PREFIX = "tls-hybrid://"


def hybrid_resource(path):
    if not path.startswith(PREFIX) or "/group/X25519MLKEM768/" not in path:
        raise ValueError("Exact approved X25519MLKEM768 profile required")
    mapped = "tls-key-share://" + path[len(PREFIX) :]
    mapped = mapped.replace("/group/X25519MLKEM768/", "/", 1)
    return key_share_resource(mapped)


class TlsHybridFact(TlsKeyShareFact):
    kind: Literal["NETWORK_TLS13_HYBRID"] = "NETWORK_TLS13_HYBRID"
    purpose: Literal["PINNED_COMPLETED_X25519_MLKEM768_SESSION"] = "PINNED_COMPLETED_X25519_MLKEM768_SESSION"
    selected_group_id: Literal[4588] = 4588
    key_exchange_group: Literal["X25519MLKEM768"] = "X25519MLKEM768"
    group_classification: Literal["REGISTERED_HYBRID_GROUP_SELECTED"] = "REGISTERED_HYBRID_GROUP_SELECTED"
    hybrid_session_completed: Literal[True] = True
    tls_provider: Literal["PYOPENSSL_CRYPTOGRAPHY_OPENSSL"] = "PYOPENSSL_CRYPTOGRAPHY_OPENSSL"
    openssl_version: str = Field(
        min_length=10, max_length=100, pattern=r"^OpenSSL [0-9]+\.[0-9]+\.[0-9]+ [A-Za-z0-9 .-]+$"
    )
    pyopenssl_version: str = Field(max_length=40, pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    cryptography_version: str = Field(max_length=40, pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    provider_identity_basis: Literal["SELF_REPORTED_LIBRARY_VERSION_NOT_MEASURED_EXECUTION"] = (
        "SELF_REPORTED_LIBRARY_VERSION_NOT_MEASURED_EXECUTION"
    )

    @model_validator(mode="after")
    def actual_hybrid_shape(self):
        # Actual finished-handshake enforcement happens at collection; imports remain claims.
        data = bytes.fromhex(self.server_hello_hex)
        pos = 39 + data[38] + 5
        share_size = None
        while pos < len(data):
            kind = int.from_bytes(data[pos : pos + 2], "big")
            n = int.from_bytes(data[pos + 2 : pos + 4], "big")
            pos += 4
            if kind == 51:
                share_size = n - 4
            pos += n
        if share_size != 1120:
            raise ValueError("X25519MLKEM768 server share must contain 32+1088 public bytes")
        import re

        match = re.match(r"OpenSSL ([0-9]+)\.([0-9]+)\.", self.openssl_version)
        if not match or tuple(map(int, match.groups())) < (3, 5):
            raise ValueError("Hybrid-capable provider generation required")
        return self
