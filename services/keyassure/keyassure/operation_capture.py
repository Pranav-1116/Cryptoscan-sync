"""Authorized operator challenge only, never synthetic customer-application logs."""

import base64
from datetime import datetime, timezone
from shared_models.operation_evidence import operation_message
from shared_models.operation_evidence_v2 import verify_operation_signature
from shared_models.tpm_quote_verification import sha

ALGORITHMS = {
    "RSA_PKCS1_SHA256": "RSASSA_PKCS1_V1_5_SHA_256",
    "RSA_PSS_SHA256": "RSASSA_PSS_SHA_256",
    "ECDSA_P256_SHA256": "ECDSA_SHA_256",
}


def capture(request, backend):
    a = request.approval
    if not a.not_before <= datetime.now(timezone.utc) < a.expires_at:
        raise ValueError("Approval not current")
    result = backend.sign_challenge(a.provider_key_id, operation_message(a), algorithm=ALGORITHMS[a.mechanism])
    signature = result.get("signature")
    if (
        not isinstance(signature, bytes)
        or not 0 < len(signature) <= 1024
        or result.get("algorithm") != ALGORITHMS[a.mechanism]
    ):
        raise ValueError("Bounded exact-mechanism signature response required")
    encoded = base64.b64encode(signature).decode()
    verify_operation_signature(a, encoded)
    if not a.not_before <= datetime.now(timezone.utc) < a.expires_at:
        raise ValueError("Approval expired during provider operation")
    return {
        "schema_version": "cryptoscan.hsm-operation-capture/v1",
        "request_sha256": sha(request),
        "approval_sha256": sha(a),
        "provider": "aws_kms",
        "mechanism": a.mechanism,
        "operation_signature": encoded,
        "operation_signature_verified": True,
        "capture_basis": "OPERATOR_INITIATED_PROVIDER_CHALLENGE_NOT_CUSTOMER_APPLICATION_TRACE",
        "application_provider_logs_correlated": False,
        "application_execution_attested": False,
        "hardware_backing_verified": False,
        "application_uses_physical_hsm": "UNKNOWN",
        "production_execution_qualified": False,
    }
