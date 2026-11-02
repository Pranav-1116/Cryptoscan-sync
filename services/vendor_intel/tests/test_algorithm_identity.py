"""Algorithm identity: spelling is not disagreement, and a size is not a typo."""

from __future__ import annotations

import pytest

from vendor_intel.algorithm_names import (
    algorithm_identity,
    compare_algorithms,
    identity_summary,
    normalise_algorithm,
    same_algorithm,
)


def test_one_algorithm_four_spellings():
    spellings = ["AES256", "aes_256", "AES 256", "AES-256"]
    canonicals = {algorithm_identity(name).canonical for name in spellings}
    assert canonicals == {"AES-256"}
    assert algorithm_identity("AES256").normalised is True
    assert algorithm_identity("AES-256").normalised is False


def test_a_size_difference_is_not_a_spelling_difference():
    result = compare_algorithms("AES-128", "AES-256")
    assert result["relation"] == "DIFFERENT_PARAMETER"
    assert "128" in result["reason"] and "256" in result["reason"]
    assert same_algorithm("AES-128", "AES-256") is False


def test_a_missing_mode_is_less_specific_not_wrong():
    result = compare_algorithms("AES-256", "AES-256-GCM")
    assert result["relation"] == "LESS_SPECIFIC"
    assert "mode" in result["reason"]


def test_two_modes_are_a_conflict():
    assert compare_algorithms("AES-256-GCM", "AES-256-CBC")["relation"] == "DIFFERENT_MODE"


def test_two_families_are_not_merged():
    assert compare_algorithms("3DES", "AES-256")["relation"] == "DIFFERENT_ALGORITHM"
    assert same_algorithm("RSA-2048", "ECDSA-P-256") is False


def test_a_sha2_spelling_and_a_curve_alias_resolve_to_one_identity():
    assert algorithm_identity("SHA2-256").canonical == "SHA-256"
    assert algorithm_identity("secp256r1").canonical == "ECDSA-P-256"
    assert algorithm_identity("ECDSA P-256").canonical == "ECDSA-P-256"


def test_legacy_pqc_names_resolve_to_the_standard_ones():
    assert algorithm_identity("Dilithium3").canonical == "ML-DSA-65"
    assert algorithm_identity("KYBER768").canonical == "ML-KEM-768"
    assert algorithm_identity("ML-DSA-65").pqc is True


def test_an_unknown_name_compares_by_shape_and_says_so():
    left = algorithm_identity("FOO256")
    right = algorithm_identity("FOO-256")
    assert left.canonical == right.canonical == "FOO-256"
    assert left.recognised is False and right.recognised is False
    summary = identity_summary(["FOO256"])
    assert summary["unrecognised"] == ["FOO256"]
    assert "must not be asserted" in summary["statement"]


def test_a_name_that_is_not_a_name_is_refused():
    with pytest.raises(ValueError):
        algorithm_identity("")
    with pytest.raises(ValueError):
        algorithm_identity("   ")
    assert compare_algorithms("", "AES-256")["relation"] == "UNKNOWN_IDENTITY"
    assert normalise_algorithm("") == ""


def test_identity_summary_separates_recognised_from_guessed():
    summary = identity_summary(["AES256", "ML-DSA-65", "FOO-256", "rsa3072"])
    assert summary["canonical"] == ["AES-256", "ML-DSA-65", "FOO-256", "RSA-3072"]
    assert summary["pqc"] == ["ML-DSA-65"]
    assert summary["unrecognised"] == ["FOO-256"]
