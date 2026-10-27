"""Bounded TPM 2.0 quote verification against an externally enrolled AK/PCR policy.

No device access, command execution, EK discovery, private keys or auto-enrollment.
A valid signature under a pinned key is NOT proof of the key's hardware origin.
"""

import hashlib
import hmac
import json
import struct
from datetime import datetime
from typing import Literal
from pydantic import Field, field_validator, model_validator
from shared_models.host_common import Strict
from shared_models.host_collection import Digest, Token, HostManifest


def canonical(value):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


class QuotePolicy(Strict):
    schema_version: Literal["cryptoscan.tpm-quote-policy/v1"] = "cryptoscan.tpm-quote-policy/v1"
    host_id: Token
    tenant_id: str | None = Field(max_length=36)
    enrollment_reference: Token
    ak_public_key_pem: str = Field(min_length=40, max_length=8192)
    qualified_signer_hex: str = Field(pattern=r"^000b[0-9a-f]{64}$")
    pcr_sha256: dict[str, Digest] = Field(min_length=1, max_length=24)
    min_clock: int = Field(default=0, ge=0, le=2**64 - 1)
    reset_count: int = Field(ge=0, le=2**32 - 1)
    restart_count: int = Field(ge=0, le=2**32 - 1)
    min_firmware_version: int = Field(default=0, ge=0, le=2**64 - 1)

    @field_validator("pcr_sha256")
    @classmethod
    def indices(cls, value):
        if any(not k.isascii() or not k.isdigit() or str(int(k)) != k or not 0 <= int(k) < 24 for k in value):
            raise ValueError("Exact SHA256 PCR indices 0..23 required")
        return value


class QuoteChallenge(Strict):
    schema_version: Literal["cryptoscan.tpm-quote-challenge/v1"] = "cryptoscan.tpm-quote-challenge/v1"
    challenge_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    nonce: Digest
    campaign_id: Token
    host_id: Token
    tenant_id: str | None = Field(max_length=36)
    policy_sha256: Digest
    target_sha256: Digest
    source_lock_sha256: Digest
    snapshot_sha256: Digest
    worker_claim_sha256: Digest
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at", mode="before")
    @classmethod
    def aware(cls, value):
        return HostManifest.aware(value)

    @model_validator(mode="after")
    def window(self):
        duration = (self.expires_at - self.issued_at).total_seconds()
        if not 0 < duration <= 300:
            raise ValueError("Challenge lifetime must be at most 300 seconds")
        return self


def qualifying_data(challenge):
    return hashlib.sha256(b"cryptoscan.tpm-quote/v1\0" + canonical(challenge)).digest()


class Reader:
    def __init__(self, data, limit):
        if not isinstance(data, bytes) or not 0 < len(data) <= limit:
            raise ValueError("Bounded binary artifact required")
        self.data, self.pos = data, 0

    def take(self, size):
        if not 0 <= size <= len(self.data) - self.pos:
            raise ValueError("Truncated TPM artifact")
        data = self.data[self.pos : self.pos + size]
        self.pos += size
        return data

    def number(self, fmt):
        return struct.unpack(">" + fmt, self.take(struct.calcsize(">" + fmt)))[0]

    def sized(self, limit):
        size = self.number("H")
        if size > limit:
            raise ValueError("TPM field size limit")
        return self.take(size)

    def end(self):
        if self.pos != len(self.data):
            raise ValueError("Trailing TPM data")


def verify_quote(policy, challenge, attestation, signature, pcr_sha256, now):
    """Raw TPMS_ATTEST + TPMT_SIGNATURE, SHA256, RSA RSASSA or P-256 ECDSA.

    Caller must authenticate policy, issue/expire/consume challenges durably and
    perform AK hardware enrollment independently. The CLI supplies local replay
    handling. Neither quote clock nor caller wall clock is an attested UTC clock.
    """
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
    from cryptography.exceptions import InvalidSignature

    if now.tzinfo is None or not challenge.issued_at <= now < challenge.expires_at:
        raise ValueError("Challenge expired or not yet valid")
    if (
        challenge.host_id != policy.host_id
        or challenge.tenant_id != policy.tenant_id
        or challenge.policy_sha256 != sha(policy)
    ):
        raise ValueError("Challenge enrollment/policy mismatch")
    if pcr_sha256 != policy.pcr_sha256:
        raise ValueError("PCR values differ from independently approved baseline")
    # Parse only fixed, bounded TPM structures; no len-controlled allocation.
    r = Reader(attestation, 4096)
    if r.number("I") != 0xFF544347 or r.number("H") != 0x8018:
        raise ValueError("Raw TPM_ST_ATTEST_QUOTE required")
    signer = r.sized(68)
    if not hmac.compare_digest(signer.hex(), policy.qualified_signer_hex):
        raise ValueError("Unenrolled qualified signer")
    if not hmac.compare_digest(r.sized(64), qualifying_data(challenge)):
        raise ValueError("Quote is not bound to this exact fresh challenge")
    clock, resets, restarts, safe = r.number("Q"), r.number("I"), r.number("I"), r.number("B")
    firmware = r.number("Q")
    if (
        safe != 1
        or clock < policy.min_clock
        or resets != policy.reset_count
        or restarts != policy.restart_count
        or firmware < policy.min_firmware_version
    ):
        raise ValueError("Unsafe or changed TPM clock/reset/firmware state")
    if r.number("I") != 1 or r.number("H") != 0x000B or r.number("B") != 3:
        raise ValueError("Exactly one 24-PCR SHA256 bank required")
    mask = int.from_bytes(r.take(3), "little")
    selected = [i for i in range(24) if mask & (1 << i)]
    if selected != sorted(int(i) for i in policy.pcr_sha256):
        raise ValueError("Quote PCR selection differs from policy")
    expected = hashlib.sha256(b"".join(bytes.fromhex(pcr_sha256[str(i)]) for i in selected)).digest()
    if not hmac.compare_digest(r.sized(64), expected):
        raise ValueError("Quote PCR composite mismatch")
    r.end()
    key = serialization.load_pem_public_key(policy.ak_public_key_pem.encode("ascii"))
    sig = Reader(signature, 1024)
    algorithm = sig.number("H")
    if sig.number("H") != 0x000B:
        raise ValueError("SHA256 signature required")
    try:
        if (
            algorithm == 0x0014
            and isinstance(key, rsa.RSAPublicKey)
            and key.key_size in {2048, 3072, 4096}
            and key.public_numbers().e == 65537
        ):
            value = sig.sized(512)
            sig.end()
            if len(value) != key.key_size // 8:
                raise ValueError("RSA signature size mismatch")
            key.verify(value, attestation, padding.PKCS1v15(), hashes.SHA256())
        elif algorithm == 0x0018 and isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
            a, b = sig.sized(32), sig.sized(32)
            sig.end()
            if not a or not b:
                raise ValueError("Empty ECDSA integer")
            key.verify(
                utils.encode_dss_signature(int.from_bytes(a, "big"), int.from_bytes(b, "big")),
                attestation,
                ec.ECDSA(hashes.SHA256()),
            )
        else:
            raise ValueError("Unsupported or mismatched AK signature algorithm")
    except InvalidSignature:
        raise ValueError("TPM quote signature invalid") from None
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {
        "verdict": "VERIFIED_ENROLLED_KEY_QUOTE",
        "challenge_sha256": sha(challenge),
        "host_id": policy.host_id,
        "enrollment_reference": policy.enrollment_reference,
        "ak_spki_sha256": hashlib.sha256(spki).hexdigest(),
        "quote_sha256": hashlib.sha256(attestation).hexdigest(),
        "pcr_indices": selected,
        "tpm_clock": clock,
        "reset_count": resets,
        "restart_count": restarts,
        "firmware_version": firmware,
        "quote_signature_verified": True,
        "hardware_origin_verified": False,
        "measured_executable_verified": False,
        "attested_utc_clock": False,
        "production_execution_qualified": False,
    }
