"""Software-generated protocol fixtures ONLY, never genuine TPM qualification."""

import hashlib
import struct
from datetime import datetime, timedelta, timezone
import pytest
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from shared_models.tpm_quote_verification import QuotePolicy, QuoteChallenge, verify_quote, qualifying_data, sha


def fixture(algorithm="rsa"):
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if algorithm == "rsa"
        else ec.generate_private_key(ec.SECP256R1())
    )
    now = datetime.now(timezone.utc)
    policy = QuotePolicy(
        host_id="fixture-host",
        tenant_id="fixture-bank",
        enrollment_reference="synthetic-not-enrollment",
        ak_public_key_pem=key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode(),
        qualified_signer_hex="000b" + "a" * 64,
        pcr_sha256={"0": "b" * 64, "7": "c" * 64},
        reset_count=0,
        restart_count=0,
        min_clock=10,
        min_firmware_version=1,
    )
    challenge = QuoteChallenge(
        challenge_id="d" * 32,
        nonce="e" * 64,
        campaign_id="fixture-campaign",
        host_id=policy.host_id,
        tenant_id="fixture-bank",
        policy_sha256=sha(policy),
        target_sha256="1" * 64,
        source_lock_sha256="2" * 64,
        snapshot_sha256="3" * 64,
        worker_claim_sha256="4" * 64,
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=4),
    )
    return key, policy, challenge, now


def sized(data):
    return struct.pack(">H", len(data)) + data


def quote_bytes(policy, challenge, **changes):
    values = {
        "magic": 0xFF544347,
        "type": 0x8018,
        "signer": bytes.fromhex(policy.qualified_signer_hex),
        "nonce": qualifying_data(challenge),
        "clock": 100,
        "resets": 0,
        "restarts": 0,
        "safe": 1,
        "firmware": 1,
        "banks": 1,
        "bank_alg": 0x000B,
        "mask_size": 3,
        "mask": b"\x81\x00\x00",
        "digest": hashlib.sha256(bytes.fromhex("b" * 64 + "c" * 64)).digest(),
    }
    values.update(changes)
    v = values
    return (
        struct.pack(">IH", v["magic"], v["type"])
        + sized(v["signer"])
        + sized(v["nonce"])
        + struct.pack(">QIIBQ", v["clock"], v["resets"], v["restarts"], v["safe"], v["firmware"])
        + struct.pack(">IHB", v["banks"], v["bank_alg"], v["mask_size"])
        + v["mask"]
        + sized(v["digest"])
    )


def sign(key, data):
    if isinstance(key, rsa.RSAPrivateKey):
        return struct.pack(">HH", 0x0014, 0x000B) + sized(key.sign(data, padding.PKCS1v15(), hashes.SHA256()))
    a, b = utils.decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return struct.pack(">HH", 0x0018, 0x000B) + sized(a.to_bytes(32, "big")) + sized(b.to_bytes(32, "big"))


@pytest.mark.parametrize("algorithm", ["rsa", "ecdsa"])
def test_valid_software_quote_does_not_claim_hardware_origin_or_clearance(algorithm):
    key, policy, challenge, now = fixture(algorithm)
    data = quote_bytes(policy, challenge)
    report = verify_quote(policy, challenge, data, sign(key, data), policy.pcr_sha256, now)
    assert report["quote_signature_verified"] and report["pcr_indices"] == [0, 7]
    assert not report["hardware_origin_verified"] and not report["measured_executable_verified"]
    assert not report["attested_utc_clock"] and not report["production_execution_qualified"]


@pytest.mark.parametrize(
    "change",
    [
        {"magic": 0},
        {"type": 0x8017},
        {"signer": b"x" * 34},
        {"nonce": b"x" * 32},
        {"clock": 0},
        {"resets": 1},
        {"restarts": 1},
        {"safe": 0},
        {"safe": 2},
        {"firmware": 0},
        {"banks": 2},
        {"bank_alg": 0x0004},
        {"mask_size": 4},
        {"mask": b"\x01\x00\x00"},
        {"digest": b"x" * 32},
        {"digest": b"x" * 64},
    ],
)
def test_signed_but_wrong_tpm_semantics_refused(change):
    key, policy, challenge, now = fixture()
    data = quote_bytes(policy, challenge, **change)
    with pytest.raises(ValueError):
        verify_quote(policy, challenge, data, sign(key, data), policy.pcr_sha256, now)


@pytest.mark.parametrize(
    "field",
    [
        "host_id",
        "policy_sha256",
        "campaign_id",
        "tenant_id",
        "target_sha256",
        "source_lock_sha256",
        "snapshot_sha256",
        "worker_claim_sha256",
        "nonce",
        "challenge_id",
    ],
)
def test_challenge_cannot_be_rebound_even_with_same_nonce(field):
    key, policy, challenge, now = fixture()
    data = quote_bytes(policy, challenge)
    value = (
        "f" * 32 if field == "challenge_id" else "f" * 64 if field.endswith("sha256") or field == "nonce" else "other"
    )
    changed = challenge.model_copy(update={field: value})
    with pytest.raises(ValueError):
        verify_quote(policy, changed, data, sign(key, data), policy.pcr_sha256, now)


@pytest.mark.parametrize(
    "case",
    [
        "truncated",
        "trailing",
        "huge",
        "signature",
        "signature-trailing",
        "wrong-key",
        "pcr",
        "expired",
        "future",
        "naive",
        "wrong-algorithm",
    ],
)
def test_protocol_failures(case):
    key, policy, challenge, now = fixture()
    data = quote_bytes(policy, challenge)
    signature = sign(key, data)
    pcr = policy.pcr_sha256
    if case == "truncated":
        data = data[:-1]
    elif case == "trailing":
        data += b"\0"
    elif case == "huge":
        data = b"\0" * 4097
    elif case == "signature":
        signature = signature[:-1] + bytes([signature[-1] ^ 1])
    elif case == "signature-trailing":
        signature += b"\0"
    elif case == "wrong-key":
        signature = sign(fixture()[0], data)
    elif case == "pcr":
        pcr = {"0": "b" * 64, "7": "a" * 64}
    elif case == "expired":
        now = challenge.expires_at
    elif case == "future":
        now = challenge.issued_at - timedelta(seconds=1)
    elif case == "naive":
        now = now.replace(tzinfo=None)
    elif case == "wrong-algorithm":
        signature = b"\x00\x16" + signature[2:]
    with pytest.raises(ValueError):
        verify_quote(policy, challenge, data, signature, pcr, now)


@pytest.mark.parametrize("indices", [{"24": "a" * 64}, {"00": "a" * 64}, {"-1": "a" * 64}, {"０": "a" * 64}, {}])
def test_pcr_policy_scope_strict(indices):
    _, policy, _, _ = fixture()
    value = policy.model_dump()
    value["pcr_sha256"] = indices
    with pytest.raises(ValueError):
        QuotePolicy.model_validate(value)


def test_challenge_window_strict():
    _, _, challenge, _ = fixture()
    value = challenge.model_dump()
    value["expires_at"] = challenge.issued_at + timedelta(seconds=301)
    with pytest.raises(ValueError):
        QuoteChallenge.model_validate(value)
