"""Alias-collision regression suite (report 53 recommendation #12, round 25).

Every variant family from the report's §2.2/§5.1 catalogue must normalize
to ONE canonical identity — same ``standard_name``, consistent family and
key size — so the same algorithm discovered under two spellings cannot
become two graph nodes or two CBOM components. ``raw_input`` must keep
the original observation (provenance survives canonicalization).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from normalization.core.engine import NormalizationEngine
from normalization.matchers.alias_canonicalizer import canonicalize


@pytest.fixture(scope="module")
def engine():
    rules_dir = Path(__file__).resolve().parents[1] / "rule_definitions"
    return NormalizationEngine(str(rules_dir))


# variant family -> (canonical standard_name, family, key_size or None)
CATALOGUE = [
    # §2.2 symmetric
    (["AES-256", "AES256", "AES_256", "aes-256"], "AES-256", "symmetric", 256),
    (["AES-128", "AES128", "AES_128"], "AES-128", "symmetric", 128),
    # §2.2 asymmetric
    (["RSA-2048", "RSA2048", "RSA_2048"], "RSA-2048", "asymmetric", 2048),
    (["RSA-1024", "RSA_1024"], "RSA-1024", "asymmetric", 1024),
    # §2.2 signature
    (["ECDSA-P256", "ECDSA_P256"], "ECDSA-P256", "signature", None),
    # §2.2 hashes (underscore forms previously pattern-extracted a bogus
    # key_size equal to the digest size)
    (["SHA-256", "SHA256", "SHA_256", "sha256"], "SHA-256", "hash", None),
    (["SHA-384", "SHA384", "SHA_384"], "SHA-384", "hash", None),
    # MACs
    (["HMAC-SHA256", "HMACSHA256"], "HMAC-SHA256", "mac", None),
    (["HMAC-SHA512", "HMACSHA512"], "HMAC-SHA512", "mac", None),
    # §5.1 curves — every spelling of one curve is one identity
    (["P-256", "secp256r1", "prime256v1"], "P-256", None, 256),
    (["P-384", "secp384r1"], "P-384", None, 384),
    (["P-521", "secp521r1"], "P-521", None, 521),
    (["X25519", "Curve25519"], "X25519", None, None),
]


@pytest.mark.parametrize(
    "variants,standard_name,family,key_size",
    CATALOGUE,
    ids=[v[0][0] for v in CATALOGUE],
)
def test_variant_family_collapses_to_one_identity(
    engine, variants, standard_name, family, key_size
):
    for variant in variants:
        normalized = engine.normalize(variant).model_dump(mode="json")
        assert normalized["standard_name"] == standard_name, (
            f"{variant!r} normalized to {normalized['standard_name']!r}, "
            f"expected {standard_name!r}"
        )
        if family is not None:
            assert normalized["algorithm_family"] == family, variant
        if key_size is not None:
            assert normalized["key_size"] == key_size, variant
        # provenance: the original observation survives canonicalization
        assert normalized["raw_input"] == variant


def test_no_bogus_key_size_for_hash_underscore_forms(engine):
    """SHA_384 must not carry key_size=384 — those digits are the digest
    size, not a key size (the pre-alias pattern path got this wrong)."""
    for variant in ["SHA_384", "SHA_512", "SHA_256", "SHA_224"]:
        normalized = engine.normalize(variant).model_dump(mode="json")
        assert normalized["key_size"] is None, variant


def test_alias_layer_is_a_rescue_not_a_rewrite(engine):
    """Inputs that already exact-match keep their original path: the
    compound transformation parser still owns AES/GCM/NoPadding."""
    normalized = engine.normalize("AES/GCM/NoPadding").model_dump(mode="json")
    assert normalized["standard_name"] == "AES-256-GCM"
    assert normalized["mode"] == "GCM"


def test_canonicalizer_never_guesses():
    """Unknown inputs are only stripped and (for mixed-case strings)
    uppercased for a retry — never remapped to a different algorithm, so
    the fallback path with its human-review flag still owns them."""
    assert canonicalize("  Twofish-CBC  ") == "TWOFISH-CBC"
    assert canonicalize("") == ""
    assert canonicalize("AES256") == "AES-256"
    assert canonicalize("secp256r1") == "P-256"
    # no key/algorithm remap for unknowns — same characters, uppercased
    assert canonicalize("Not-An-Algorithm").replace("-", "") == "NOTANALGORITHM"


def test_case_rescue_matches_canonical(engine):
    """A lowercase spelling of a canonical name resolves to the same
    identity as the canonical spelling."""
    for lower, canonical in [("aes-256", "AES-256"), ("sha-256", "SHA-256")]:
        a = engine.normalize(lower).model_dump(mode="json")
        b = engine.normalize(canonical).model_dump(mode="json")
        assert a["standard_name"] == b["standard_name"] == canonical.replace("aes-", "AES-").replace("sha-", "SHA-")
