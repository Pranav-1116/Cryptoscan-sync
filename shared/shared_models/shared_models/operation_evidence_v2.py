"""RSA/ECDSA public operation verification. Hardware origin remains unproven."""

import base64
import hashlib
from datetime import datetime
from typing import Literal
from pydantic import Field, model_validator
from shared_models.operation_evidence import OperationApproval, OperationLog, operation_message
from shared_models.host_common import Strict
from shared_models.host_collection import Digest
from shared_models.collector_identity import decode
from shared_models.collection import offset_time
from shared_models.tpm_quote_verification import canonical, sha

Mechanism = Literal["RSA_PKCS1_SHA256", "RSA_PSS_SHA256", "ECDSA_P256_SHA256"]


def public_bytes(value, limit):
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ValueError("Canonical public base64 required") from None
    if not 0 < len(data) <= limit or base64.b64encode(data).decode() != value:
        raise ValueError("Public byte encoding/size mismatch")
    return data


class OperationApprovalV2(OperationApproval):
    schema_version: Literal["cryptoscan.operation-approval/v2"] = "cryptoscan.operation-approval/v2"
    mechanism: Mechanism
    operation_public_key: str = Field(min_length=44, max_length=4096)
    operation_public_key_sha256: Digest

    @model_validator(mode="after")
    def pins(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, ec

        decode(self.application_log_public_key, 32)
        decode(self.provider_log_public_key, 32)
        if self.application_log_public_key == self.provider_log_public_key or not self.not_before < self.expires_at:
            raise ValueError("Distinct logger roots and ordered window required")
        data = public_bytes(self.operation_public_key, 3072)
        if hashlib.sha256(data).hexdigest() != self.operation_public_key_sha256:
            raise ValueError("Approved public-key fingerprint mismatch")
        key = serialization.load_der_public_key(data)
        if key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != data:
            raise ValueError("Canonical public SPKI DER required, never private material")
        if self.mechanism.startswith("RSA_"):
            if (
                not isinstance(key, rsa.RSAPublicKey)
                or not 2048 <= key.key_size <= 8192
                or key.public_numbers().e != 65537
            ):
                raise ValueError("Approved RSA generation/size required")
        elif not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("Exact P-256 public key required")
        return self


class OperationLogV2(OperationLog):
    mechanism: Mechanism


class SignedOperationLogV2(Strict):
    statement: OperationLogV2
    signature: str = Field(min_length=88, max_length=88)


class OperationEvidenceV2(Strict):
    schema_version: Literal["cryptoscan.operation-evidence/v2"] = "cryptoscan.operation-evidence/v2"
    operation_signature: str = Field(min_length=12, max_length=1368)
    application_log: SignedOperationLogV2
    provider_log: SignedOperationLogV2


def verify_operation_signature(approval, signature):
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding, ec
    from cryptography.exceptions import InvalidSignature

    key = serialization.load_der_public_key(public_bytes(approval.operation_public_key, 3072))
    signature = public_bytes(signature, 1024)
    message = operation_message(approval)
    try:
        if approval.mechanism.startswith("RSA_"):
            if len(signature) != key.key_size // 8:
                raise ValueError("RSA signature size mismatch")
            pad = (
                padding.PKCS1v15()
                if approval.mechanism == "RSA_PKCS1_SHA256"
                else padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
            )
            key.verify(signature, message, pad, hashes.SHA256())
        else:
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ValueError("Invalid approved operation signature") from None
    return signature


def verify_operation_v2(approval: OperationApprovalV2, evidence: OperationEvidenceV2, now: datetime):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    now = offset_time(now)
    if not approval.not_before <= now < approval.expires_at:
        raise ValueError("Operation approval not current")
    signature = verify_operation_signature(approval, evidence.operation_signature)
    for signed, key, event in [
        (evidence.application_log, approval.application_log_public_key, "APPLICATION_OPERATION_COMPLETED"),
        (evidence.provider_log, approval.provider_log_public_key, "PROVIDER_SIGN_COMPLETED"),
    ]:
        log = signed.statement
        if (
            log.event != event
            or log.approval_sha256 != sha(approval)
            or log.application_id != approval.application_id
            or log.provider_key_id != approval.provider_key_id
            or log.operation_id != approval.operation_id
            or log.message_sha256 != hashlib.sha256(operation_message(approval)).hexdigest()
            or log.operation_signature_sha256 != hashlib.sha256(signature).hexdigest()
            or log.mechanism != approval.mechanism
            or not approval.not_before <= log.occurred_at <= now
        ):
            raise ValueError("Log outside approved operation/challenge/window")
        try:
            Ed25519PublicKey.from_public_bytes(decode(key, 32)).verify(decode(signed.signature, 64), canonical(log))
        except InvalidSignature:
            raise ValueError("Invalid approved logger signature") from None
    return {
        "schema_version": "cryptoscan.operation-verification/v2",
        "approval_sha256": sha(approval),
        "evidence_sha256": sha(evidence),
        "application_id": approval.application_id,
        "provider_key_id": approval.provider_key_id,
        "operation_id": approval.operation_id,
        "mechanism": approval.mechanism,
        "operation_public_key_sha256": approval.operation_public_key_sha256,
        "verified_at": now.isoformat(),
        "operation_signature_verified": True,
        "application_provider_logs_correlated": True,
        "source_basis": "IMPORTED_SIGNED_CLAIMS",
        "application_execution_attested": False,
        "hardware_backing_verified": False,
        "application_uses_physical_hsm": "UNKNOWN",
        "signer_organizational_independence_verified": False,
        "whole_application_crypto_coverage_verified": False,
        "production_execution_qualified": False,
    }
