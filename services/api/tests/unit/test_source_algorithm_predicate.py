"""Exact approved digest identity across existing normalized representations."""
import pytest
from api.assurance.remediation import exact_algorithm


@pytest.mark.parametrize("bits", [224, 256, 384, 512])
def test_family_plus_exact_digest_width_matches_explicit_identity(bits):
    assert exact_algorithm({"algorithm": "SHA2", "key_size": bits}, f"SHA-{bits}")


@pytest.mark.parametrize("bits", [None, 224, 384, 512, True, "256", 256.0])
def test_other_or_unknown_digest_width_is_not_sha256(bits):
    assert not exact_algorithm({"algorithm": "SHA2", "key_size": bits}, "SHA-256")


def test_existing_literal_identity_remains_supported_without_invented_parameters():
    assert exact_algorithm({"algorithm": "SHA-256", "key_size": None}, "sha-256")
    assert not exact_algorithm({"algorithm": "SHA-384", "key_size": 256}, "SHA-256")
    assert not exact_algorithm({"algorithm": "UNKNOWN", "key_size": 256}, "SHA-256")
