"""Registry bridge + upgraded matcher/enricher behavior (Ask-51)."""

from __future__ import annotations

from normalization.core.registry_bridge import (
    canonical_name,
    fixed_key_size,
    model_family,
    name_key_size,
    nist_designation,
    resolve_key_size,
)
from normalization.enrichers.family_enricher import FamilyEnricher
from normalization.enrichers.iana_enricher import IANAEnricher
from normalization.enrichers.nist_enricher import NISTEnricher
from normalization.matchers.pattern_matcher import PatternMatcher
from normalization.models.normalized_crypto import NormalizedCrypto


# --------------------------------------------------------------------------- #
# bridge semantics
# --------------------------------------------------------------------------- #

def test_canonical_names_and_families():
    assert canonical_name("AES_128_CBC") == "AES"
    assert canonical_name("DESede") == "3DES"
    assert canonical_name("ARCFOUR") == "RC4"
    assert canonical_name("totally-made-up") is None  # honest: no guess
    # families land in the model-allowed vocabulary
    assert model_family("AES") == "symmetric"
    assert model_family("RSA") == "asymmetric"
    assert model_family("SHA-256") == "hash"
    assert model_family("HMAC-SHA256") == "mac"
    assert model_family("Kyber") == "key-agreement"  # was invalid 'pqc'
    assert model_family("ML-DSA-65") == "signature"


def test_key_size_extraction_and_fixedness():
    assert name_key_size("RSA-2048") == 2048
    assert name_key_size("AES_128_CBC") == 128
    assert name_key_size("SHA-256") is None  # digest size is not a key size
    assert fixed_key_size("DES") == 56
    assert fixed_key_size("AES") is None  # 128/192/256 — scanner evidence wins
    assert fixed_key_size("3DES") is None  # 112 or 168


def test_nist_designation_from_registry():
    assert nist_designation("DES") == "DISALLOWED"
    assert nist_designation("3DES") == "DEPRECATED"
    assert nist_designation("RSA", key_size=1024) == "DISALLOWED"  # below min 2048
    assert nist_designation("RSA", key_size=2048) == "APPROVED"
    assert nist_designation("Kyber") == "ACCEPTABLE"  # RESTRICTED -> constrained use
    assert nist_designation("made-up-cipher") is None


def test_resolve_key_size_precedence():
    # scanner-measured beats a rule default for undersized patterns
    assert resolve_key_size(256, "AES/GCM/NoPadding", 128) == 128
    # the raw string itself pins the size — string wins over the scanner hint
    assert resolve_key_size(256, "AES-256-GCM", 128) == 256
    # structurally single option (DES) — rule wins even over a bogus hint
    assert resolve_key_size(56, "DES", 999) == 56
    assert resolve_key_size(None, "RSA", 3072) == 3072
    assert resolve_key_size(2048, "RSA-2048", None) == 2048
    assert resolve_key_size(256, "AES", 256) == 256


# --------------------------------------------------------------------------- #
# matcher: compound forms in, junk still out
# --------------------------------------------------------------------------- #

def _match(raw):
    return PatternMatcher().match(raw)


def test_compound_dash_and_underscore_forms_parse():
    hit = _match("AES-256-GCM")
    assert (hit.algorithm, hit.mode, hit.key_size) == ("AES-GCM", "GCM", 256)
    hit = _match("AES_128_CBC")
    assert (hit.algorithm, hit.mode, hit.key_size) == ("AES", "CBC", 128)
    hit = _match("RSA-3072")
    assert (hit.algorithm, hit.key_size, hit.algorithm_family) == ("RSA", 3072, "asymmetric")


def test_full_raw_registry_recognition_when_split_fails():
    hit = _match("DES-EDE3-CBC")
    assert (hit.algorithm, hit.key_size) == ("3DES", 168)
    hit = _match("DESede/CBC/PKCS5Padding")
    assert (hit.algorithm, hit.mode) == ("3DES", "CBC")


def test_unrecognized_compounds_stay_unknown():
    assert _match("FOOBAR-999") is None
    assert _match("CUSTOMCRYPTO99") is None  # digits do not grant confidence


def test_legacy_aliases_still_canonicalize():
    assert _match("TripleDES/CBC/PKCS5Padding").algorithm == "3DES"
    assert _match("ARCFOUR/ECB").algorithm == "RC4"


# --------------------------------------------------------------------------- #
# enrichers through the bridge
# --------------------------------------------------------------------------- #

def _crypto(**kw):
    base = dict(
        algorithm="AES",
        algorithm_family="unknown",
        standard_name="AES",
        normalization_confidence="HIGH",
        raw_input="AES",
    )
    base.update(kw)
    return NormalizedCrypto(**base)


def test_family_enricher_model_allowed_values_only():
    for raw, expected in [("Kyber", "key-agreement"), ("ML-DSA-65", "signature"), ("HMAC-SHA256", "mac"), ("ChaCha20", "symmetric"), ("PBKDF2", "kdf")]:
        enriched = FamilyEnricher().enrich(_crypto(algorithm=raw, standard_name=raw, raw_input=raw))
        assert enriched.algorithm_family == expected
        NormalizedCrypto.model_validate(enriched.model_dump())  # 'pqc' used to fail this


def test_nist_enricher_registry_first(monkeypatch):
    assert NISTEnricher().enrich(_crypto(algorithm="RSA", key_size=1024)).nist_designation == "DISALLOWED"
    assert NISTEnricher().enrich(_crypto(algorithm="3DES")).nist_designation == "DEPRECATED"
    assert NISTEnricher().enrich(_crypto(algorithm="BLOWFISH")).nist_designation == "ACCEPTABLE"  # RESTRICTED

    # registry unavailable -> legacy tables still answer, honestly
    import normalization.core.registry_bridge as bridge

    monkeypatch.setattr(bridge, "parse_algorithm", None)
    assert NISTEnricher().enrich(_crypto(algorithm="DES")).nist_designation == "DISALLOWED"
    assert NISTEnricher().enrich(_crypto(algorithm="TWOFISH")).nist_designation == "UNKNOWN"


def test_iana_enricher_no_fabricated_ids():
    known = IANAEnricher().enrich(_crypto(algorithm="AES", mode="GCM", key_size=256))
    assert known.iana_id == "aes256-gcm"  # real mapping
    unknown = IANAEnricher().enrich(_crypto(algorithm="Kyber"))
    assert unknown.iana_id is None  # generated slug used to impersonate a registration
