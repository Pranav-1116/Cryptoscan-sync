"""Public signed application/provider operation correlation; not HSM attestation.

No signing key, SDK call, evidence-supplied trust root, or inferred hardware use.
"""

from datetime import datetime
import hashlib
from typing import Literal
from pydantic import Field, field_validator, model_validator
from shared_models.host_common import Strict
from shared_models.host_collection import Token, Digest
from shared_models.collector_identity import decode
from shared_models.collection import offset_time
from shared_models.tpm_quote_verification import canonical, sha


class OperationApproval(Strict):
    schema_version: Literal["cryptoscan.operation-approval/v1"] = "cryptoscan.operation-approval/v1"
    approval_id: Token
    application_id: Token
    provider_key_id: Token
    operation_id: Token
    nonce_hex: str = Field(pattern=r"^[0-9a-f]{64}$")
    application_log_public_key: str = Field(min_length=44, max_length=44)
    provider_log_public_key: str = Field(min_length=44, max_length=44)
    operation_public_key: str = Field(min_length=44, max_length=44)
    mechanism: Literal["ED25519"] = "ED25519"
    not_before: datetime
    expires_at: datetime
    reviewer_reference: Token

    @field_validator("not_before", "expires_at", mode="before")
    @classmethod
    def aware(cls, value):
        return offset_time(value)

    @model_validator(mode="after")
    def pins(self):
        keys = [self.application_log_public_key, self.provider_log_public_key, self.operation_public_key]
        for value in keys:
            decode(value, 32)
        if len(set(keys)) != 3 or not self.not_before < self.expires_at:
            raise ValueError("Distinct pre-enrolled keys and ordered approval window required")
        return self


def operation_message(approval):
    return canonical(
        {
            "schema_version": "cryptoscan.operation-challenge/v1",
            "approval_id": approval.approval_id,
            "approval_sha256": sha(approval),
            "operation_id": approval.operation_id,
            "application_id": approval.application_id,
            "provider_key_id": approval.provider_key_id,
            "mechanism": approval.mechanism,
            "nonce_hex": approval.nonce_hex,
        }
    )


class OperationLog(Strict):
    approval_sha256: Digest
    event: Literal["APPLICATION_OPERATION_COMPLETED", "PROVIDER_SIGN_COMPLETED"]
    application_id: Token
    provider_key_id: Token
    operation_id: Token
    message_sha256: Digest
    operation_signature_sha256: Digest
    mechanism: Literal["ED25519"]
    outcome: Literal["SUCCESS"]
    occurred_at: datetime

    @field_validator("occurred_at", mode="before")
    @classmethod
    def aware(cls, value):
        return offset_time(value)


class SignedOperationLog(Strict):
    statement: OperationLog
    signature: str = Field(min_length=88, max_length=88)


class OperationEvidence(Strict):
    schema_version: Literal["cryptoscan.operation-evidence/v1"] = "cryptoscan.operation-evidence/v1"
    operation_signature: str = Field(min_length=88, max_length=88)
    application_log: SignedOperationLog
    provider_log: SignedOperationLog


def verify_operation(approval: OperationApproval, evidence: OperationEvidence, now: datetime):
    """All roots come from separately reviewed approval, never from the packet."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    now = offset_time(now)
    if not approval.not_before <= now < approval.expires_at:
        raise ValueError("Operation approval not current")
    signature = decode(evidence.operation_signature, 64)
    message = operation_message(approval)
    try:
        Ed25519PublicKey.from_public_bytes(decode(approval.operation_public_key, 32)).verify(signature, message)
    except InvalidSignature:
        raise ValueError("Invalid challenge operation signature") from None
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
            or log.message_sha256 != hashlib.sha256(message).hexdigest()
            or log.operation_signature_sha256 != hashlib.sha256(signature).hexdigest()
            or log.mechanism != approval.mechanism
            or not approval.not_before <= log.occurred_at <= now
        ):
            raise ValueError("Log outside exact approved operation/challenge/window")
        try:
            Ed25519PublicKey.from_public_bytes(decode(key, 32)).verify(decode(signed.signature, 64), canonical(log))
        except InvalidSignature:
            raise ValueError("Invalid enrolled log signature") from None
    return {
        "schema_version": "cryptoscan.operation-verification/v1",
        "approval_sha256": sha(approval),
        "evidence_sha256": sha(evidence),
        "application_id": approval.application_id,
        "provider_key_id": approval.provider_key_id,
        "operation_id": approval.operation_id,
        "verified_at": now.isoformat(),
        "mechanism": approval.mechanism,
        "operation_signature_verified": True,
        "application_provider_logs_correlated": True,
        "source_basis": "IMPORTED_SIGNED_CLAIMS",
        "relationship": "APPLICATION_REPORTED_MATCHING_PROVIDER_SIGNATURE",
        "application_execution_attested": False,
        "signer_organizational_independence_verified": False,
        "hardware_backing_verified": False,
        "application_uses_physical_hsm": "UNKNOWN",
        "whole_application_crypto_coverage_verified": False,
        "production_execution_qualified": False,
    }
