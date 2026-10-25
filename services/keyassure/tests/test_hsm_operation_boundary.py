"""Legacy provider receipts must never become operation/physical hardware proof."""

from keyassure.hsm_connectivity import check_key


class Backend:
    def __init__(self):
        self.challenges = []

    def describe(self, key):
        return {"metadata": {"origin": "AWS_CLOUDHSM", "protection_level": "HARDWARE"}}

    def sign_challenge(self, key, nonce):
        self.challenges.append(nonce)
        return {"signature": b"not-a-valid-signature"}


def test_fresh_nonce_but_receipt_is_not_signature_or_application_proof():
    b = Backend()
    one = check_key("fixture-key", provider="aws_kms", backend=b)
    two = check_key("fixture-key", provider="aws_kms", backend=b)
    assert (
        len(b.challenges) == 2
        and b.challenges[0] != b.challenges[1]
        and one["challenge_sha256"] != two["challenge_sha256"]
    )
    assert one["sign_challenge"] == "OK"  # Compatibility: receipt only.
    assert one["sign_challenge_basis"] == "NONEMPTY_RESPONSE_NOT_SIGNATURE_VERIFICATION"
    assert one["operation_signature_verified"] is False and one["hardware_backing_verified"] is False
    assert one["application_uses_physical_hsm"] == "UNKNOWN" and one["application_execution_attested"] is False


def test_private_exposure_detected_before_scrub_no_more_operation_or_retention():
    class Leaky(Backend):
        def describe(self, key):
            return {
                "algorithm": "-----BEGIN PRIVATE KEY-----",
                "metadata": {"private_key": "must-not-retain", "protection_level": "HARDWARE"},
            }

    b = Leaky()
    r = check_key("fixture-key", provider="aws_kms", backend=b)
    assert (
        r["raw_key_material_present"] is True and r["key_residence"] == "UNDETERMINED" and r["hardware_backed"] is False
    )
    assert r["sign_challenge"] == "UNKNOWN" and not b.challenges
    assert any(i["code"] == "KEY_MATERIAL_EXPOSED" for i in r["issues"])
    assert "must-not-retain" not in str(r) and "BEGIN PRIVATE KEY" not in str(r)


def test_backend_error_text_never_exposes_credentials():
    class Fails(Backend):
        def describe(self, key):
            raise RuntimeError("credential=must-not-retain")

    r = check_key("fixture-key", provider="aws_kms", backend=Fails())
    assert r["connectivity"] == "FAIL" and "must-not-retain" not in str(r)
