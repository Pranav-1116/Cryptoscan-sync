"""Injected SDK with real software signatures. No cloud account/physical HSM execution."""

import pytest
from shared.shared_models.tests.test_operation_evidence_v2 import packet
from shared_models.hsm_operation_request import HsmOperationRequest
from keyassure.operation_capture import capture, ALGORITHMS
from keyassure.hsm_backends import AwsKmsBackend


@pytest.mark.parametrize("mechanism", ["RSA_PKCS1_SHA256", "RSA_PSS_SHA256", "ECDSA_P256_SHA256"])
def test_exact_approved_sdk_algorithm_and_verified_public_signature(mechanism):
    a, _, _, sign = packet(mechanism)
    calls = []

    class Client:
        def describe_key(self, **kw):
            calls.append(("describe", kw))
            return {"KeyMetadata": {"SigningAlgorithms": ["unused", ALGORITHMS[mechanism]]}}

        def sign(self, **kw):
            calls.append(("sign", kw))
            return {"Signature": sign(kw["Message"]), "SigningAlgorithm": kw["SigningAlgorithm"]}

    r = capture(HsmOperationRequest(region="ap-south-1", approval=a), AwsKmsBackend(client=Client()))
    assert [c[0] for c in calls] == ["describe", "sign"]
    assert calls[-1][1]["SigningAlgorithm"] == ALGORITHMS[mechanism] and calls[-1][1]["MessageType"] == "RAW"
    assert (
        r["operation_signature_verified"]
        and not r["application_provider_logs_correlated"]
        and not r["hardware_backing_verified"]
    )


@pytest.mark.parametrize("failure", ["missing-algorithm", "wrong-signature", "wrong-algorithm"])
def test_no_nonempty_response_pass(failure):
    a, _, _, sign = packet()
    calls = []

    class Client:
        def describe_key(self, **kw):
            return {
                "KeyMetadata": {
                    "SigningAlgorithms": ["unapproved"] if failure == "missing-algorithm" else [ALGORITHMS[a.mechanism]]
                }
            }

        def sign(self, **kw):
            calls.append("sign")
            return {
                "Signature": b"garbage" if failure == "wrong-signature" else sign(kw["Message"]),
                "SigningAlgorithm": "unapproved" if failure == "wrong-algorithm" else kw["SigningAlgorithm"],
            }

    with pytest.raises(ValueError):
        capture(HsmOperationRequest(region="ap-south-1", approval=a), AwsKmsBackend(client=Client()))
    if failure == "missing-algorithm":
        assert not calls


@pytest.mark.parametrize("mode", ["alias", "region", "expired"])
def test_bad_scope_no_sdk_call(mode):
    a, _, _, _ = packet()
    if mode == "expired":
        a = a.model_copy(update={"expires_at": a.not_before})
    elif mode == "alias":
        a = a.model_copy(update={"provider_key_id": "alias/mutable"})

    class Forbidden:
        def sign_challenge(self, *args, **kw):
            raise AssertionError("No provider calls allowed")

    with pytest.raises(ValueError):
        request = HsmOperationRequest(region="eu-west-1" if mode == "region" else "ap-south-1", approval=a)
        capture(request, Forbidden())
