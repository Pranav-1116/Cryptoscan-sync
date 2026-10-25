"""Real software signatures; no physical HSM/application execution attestation."""

from datetime import datetime, timezone, timedelta
import base64
import hashlib
import os
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from shared_models.operation_evidence import (
    OperationApproval,
    OperationEvidence,
    OperationLog,
    SignedOperationLog,
    operation_message,
    verify_operation,
)
from shared_models.tpm_quote_verification import canonical, sha


def packet():
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    public = lambda key: base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    now = datetime.now(timezone.utc)
    a = OperationApproval(
        approval_id="owned-software-test",
        application_id="fixture-app",
        provider_key_id="fixture-software-key",
        operation_id="operation-a",
        nonce_hex=os.urandom(32).hex(),
        application_log_public_key=public(keys[0]),
        provider_log_public_key=public(keys[1]),
        operation_public_key=public(keys[2]),
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=5),
        reviewer_reference="fixture/not-independent",
    )
    operation_signature = keys[2].sign(operation_message(a))
    logs = []
    for key, event in zip(keys, ["APPLICATION_OPERATION_COMPLETED", "PROVIDER_SIGN_COMPLETED"]):
        log = OperationLog(
            approval_sha256=sha(a),
            event=event,
            application_id=a.application_id,
            provider_key_id=a.provider_key_id,
            operation_id=a.operation_id,
            message_sha256=hashlib.sha256(operation_message(a)).hexdigest(),
            operation_signature_sha256=hashlib.sha256(operation_signature).hexdigest(),
            mechanism="ED25519",
            outcome="SUCCESS",
            occurred_at=now,
        )
        logs.append(SignedOperationLog(statement=log, signature=base64.b64encode(key.sign(canonical(log))).decode()))
    return (
        a,
        OperationEvidence(
            operation_signature=base64.b64encode(operation_signature).decode(),
            application_log=logs[0],
            provider_log=logs[1],
        ),
        now,
    )


def test_actual_operation_and_two_logs_verified_without_hardware_promotion():
    a, e, now = packet()
    r = verify_operation(a, e, now)
    assert r["operation_signature_verified"] and r["application_provider_logs_correlated"]
    assert r["hardware_backing_verified"] is False and r["application_uses_physical_hsm"] == "UNKNOWN"
    assert r["application_execution_attested"] is False and r["source_basis"] == "IMPORTED_SIGNED_CLAIMS"


@pytest.mark.parametrize(
    "change",
    [
        "operation-signature",
        "application-signature",
        "provider-signature",
        "app-id",
        "key-id",
        "operation-id",
        "nonce",
        "window",
        "self-root",
        "log-hash",
        "future-log",
    ],
)
def test_invalid_mismatched_or_replayed_context_refuses(change):
    a, e, now = packet()
    if change == "operation-signature":
        e = e.model_copy(update={"operation_signature": base64.b64encode(b"0" * 64).decode()})
    elif change in {"application-signature", "provider-signature"}:
        field = "application_log" if change.startswith("application") else "provider_log"
        e = e.model_copy(
            update={field: getattr(e, field).model_copy(update={"signature": base64.b64encode(b"0" * 64).decode()})}
        )
    elif change in {"app-id", "key-id", "operation-id", "nonce"}:
        name = {
            "app-id": "application_id",
            "key-id": "provider_key_id",
            "operation-id": "operation_id",
            "nonce": "nonce_hex",
        }[change]
        a = a.model_copy(update={name: "f" * 64 if change == "nonce" else "other"})
    elif change == "window":
        now = a.expires_at
    elif change == "self-root":
        a = a.model_copy(update={"application_log_public_key": a.provider_log_public_key})
    else:
        field = "message_sha256" if change == "log-hash" else "occurred_at"
        e = e.model_copy(
            update={
                "provider_log": e.provider_log.model_copy(
                    update={
                        "statement": e.provider_log.statement.model_copy(
                            update={field: "a" * 64 if change == "log-hash" else now + timedelta(seconds=1)}
                        )
                    }
                )
            }
        )
    with pytest.raises(ValueError):
        verify_operation(a, e, now)


def test_packet_cannot_supply_its_own_roots_or_private_material():
    a, e, _ = packet()
    data = e.model_dump(mode="json")
    data["private_key"] = "not-allowed"
    with pytest.raises(ValueError):
        OperationEvidence.model_validate(data)
    with pytest.raises(ValueError):
        OperationApproval.model_validate(
            {**a.model_dump(mode="json"), "provider_log_public_key": a.application_log_public_key}
        )
