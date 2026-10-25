"""Actual software RSA/ECDSA signatures, not customer/physical HSM proof."""

import base64
from datetime import datetime, timezone, timedelta
import hashlib
import secrets
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, ed25519
from shared_models.operation_evidence import operation_message
from shared_models.operation_evidence_v2 import (
    OperationApprovalV2,
    OperationLogV2,
    SignedOperationLogV2,
    OperationEvidenceV2,
    verify_operation_v2,
)
from shared_models.tpm_quote_verification import canonical, sha


def packet(mechanism="RSA_PKCS1_SHA256"):
    op = (
        ec.generate_private_key(ec.SECP256R1())
        if mechanism == "ECDSA_P256_SHA256"
        else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )
    app, provider = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
    public = lambda k: base64.b64encode(
        k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    der = op.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    now = datetime.now(timezone.utc)
    a = OperationApprovalV2(
        approval_id="fixture-v2",
        application_id="software-fixture",
        provider_key_id="arn:aws:kms:ap-south-1:123456789012:key/00000000-0000-0000-0000-000000000001",
        operation_id="one-signature",
        nonce_hex=secrets.token_hex(32),
        application_log_public_key=public(app),
        provider_log_public_key=public(provider),
        operation_public_key=base64.b64encode(der).decode(),
        operation_public_key_sha256=hashlib.sha256(der).hexdigest(),
        mechanism=mechanism,
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=5),
        reviewer_reference="software-fixture-not-independent",
    )

    def sign(message):
        if mechanism == "ECDSA_P256_SHA256":
            return op.sign(message, ec.ECDSA(hashes.SHA256()))
        pad = (
            padding.PKCS1v15()
            if mechanism == "RSA_PKCS1_SHA256"
            else padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
        )
        return op.sign(message, pad, hashes.SHA256())

    sig = sign(operation_message(a))
    logs = []
    for logger, event in [(app, "APPLICATION_OPERATION_COMPLETED"), (provider, "PROVIDER_SIGN_COMPLETED")]:
        statement = OperationLogV2(
            approval_sha256=sha(a),
            event=event,
            application_id=a.application_id,
            provider_key_id=a.provider_key_id,
            operation_id=a.operation_id,
            message_sha256=hashlib.sha256(operation_message(a)).hexdigest(),
            operation_signature_sha256=hashlib.sha256(sig).hexdigest(),
            mechanism=mechanism,
            outcome="SUCCESS",
            occurred_at=now,
        )
        logs.append(
            SignedOperationLogV2(
                statement=statement, signature=base64.b64encode(logger.sign(canonical(statement))).decode()
            )
        )
    return (
        a,
        OperationEvidenceV2(
            operation_signature=base64.b64encode(sig).decode(), application_log=logs[0], provider_log=logs[1]
        ),
        now,
        sign,
    )


@pytest.mark.parametrize("mechanism", ["RSA_PKCS1_SHA256", "RSA_PSS_SHA256", "ECDSA_P256_SHA256"])
def test_real_signature_and_signed_logs_no_hardware_promotion(mechanism):
    a, e, now, _ = packet(mechanism)
    report = verify_operation_v2(a, e, now)
    assert report["operation_signature_verified"] and report["application_provider_logs_correlated"]
    assert report["hardware_backing_verified"] is False and report["application_uses_physical_hsm"] == "UNKNOWN"


@pytest.mark.parametrize(
    "field,value",
    [
        ("operation_id", "other"),
        ("operation_public_key_sha256", "a" * 64),
        ("mechanism", "RSA_PSS_SHA256"),
        ("nonce_hex", "0" * 64),
    ],
)
def test_operation_context_or_key_pin_changes_refuse(field, value):
    a, e, now, _ = packet()
    data = a.model_dump(mode="python")
    data[field] = value
    with pytest.raises(ValueError):
        changed = OperationApprovalV2.model_validate(data)
        verify_operation_v2(changed, e, now)


@pytest.mark.parametrize("field", ["operation_signature", "application_log", "provider_log"])
def test_each_forged_signature_refused(field):
    a, e, now, _ = packet()
    bad = base64.b64encode(b"0" * 64).decode()
    if field == "operation_signature":
        e = e.model_copy(update={field: bad})
    else:
        e = e.model_copy(update={field: getattr(e, field).model_copy(update={"signature": bad})})
    with pytest.raises(ValueError):
        verify_operation_v2(a, e, now)


def test_private_der_is_never_a_public_key():
    a, _, _, _ = packet()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    with pytest.raises(ValueError):
        OperationApprovalV2.model_validate(
            {
                **a.model_dump(mode="python"),
                "operation_public_key": base64.b64encode(der).decode(),
                "operation_public_key_sha256": hashlib.sha256(der).hexdigest(),
            }
        )


def test_expired_approval_and_future_event_refuse():
    a, e, now, _ = packet()
    with pytest.raises(ValueError):
        verify_operation_v2(a, e, a.expires_at)
    e = e.model_copy(
        update={
            "provider_log": e.provider_log.model_copy(
                update={
                    "statement": e.provider_log.statement.model_copy(update={"occurred_at": now + timedelta(seconds=1)})
                }
            )
        }
    )
    with pytest.raises(ValueError):
        verify_operation_v2(a, e, now)
