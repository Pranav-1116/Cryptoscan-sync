"""Original M5/R1: parameter names, public-key bytes and approval are distinct."""
import pytest
from shared_models.algorithm_registry import parse_algorithm


@pytest.mark.parametrize("name,size", [
    ("ML-KEM-512", 800), ("ML-KEM-768", 1184), ("ML-KEM-1024", 1568),
    ("ML-DSA-44", 1312), ("ML-DSA-65", 1952), ("ML-DSA-87", 2592),
    ("HQC-128", 3626), ("HQC-192", 7242), ("HQC-256", 14434),
])
def test_existing_pqc_sizes_are_public_key_bytes_not_key_bits(name, size):
    info = parse_algorithm(name)
    assert info.key_size == size
    assert info.parameter_kind == "public_key_bytes"


@pytest.mark.parametrize("hash_family", ["SHA2", "SHAKE"])
@pytest.mark.parametrize("security,size", [(128, 32), (192, 48), (256, 64)])
@pytest.mark.parametrize("variant", ["s", "f"])
def test_all_twelve_fips205_parameter_sets_are_exactly_recognized(hash_family, security, size, variant):
    name = f"SLH-DSA-{hash_family}-{security}{variant}"
    info = parse_algorithm(name)
    assert info.recognized is True
    assert info.family == "signature-pqc"
    assert info.canonical == name
    assert info.key_size == size
    assert info.parameter_kind == "public_key_bytes"


@pytest.mark.parametrize("name", ["FN-DSA", "FN-DSA-512", "Falcon-512", "HQC-128", "McEliece"])
def test_draft_selected_or_legacy_names_do_not_get_automatic_policy_approval(name):
    assert parse_algorithm(name).status != "ALLOWED"
