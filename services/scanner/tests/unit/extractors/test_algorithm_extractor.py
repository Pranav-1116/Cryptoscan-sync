from scanner.extractors.algorithm_extractor import parse_transformation


def test_compound_aes_gcm():
    parsed = parse_transformation("AES/GCM/NoPadding")
    assert parsed.algorithm == "AES"
    assert parsed.mode == "GCM"


def test_desede_alias():
    parsed = parse_transformation("DESede")
    assert parsed.algorithm == "3DES"


def test_hmac_separators_and_pbe_do_not_invent_a_cipher_mode():
    hmac = parse_transformation("HMAC-SHA256")
    assert hmac.algorithm == "HMAC-SHA-256"
    assert hmac.hash_algorithm == "SHA-256"

    pbe = parse_transformation("PBEWithHMACSHA512AndAES_256")
    assert pbe.algorithm == "AES"
    assert pbe.hash_algorithm == "SHA-512"
    assert pbe.mode is None


def test_algorithm_gate_rejects_near_miss_identifiers():
    from scanner.extractors.algorithm_extractor import known_algorithm_or_unknown

    assert known_algorithm_or_unknown("AESX") == "UNKNOWN"
    assert known_algorithm_or_unknown("SHA256foo") == "UNKNOWN"
    assert known_algorithm_or_unknown("HMAC-SHA256") == "HMAC-SHA-256"
    # Protocol and JOSE labels are more specific than their underlying
    # registry primitive and must remain stable in scanner output.
    assert known_algorithm_or_unknown("TLS1.2") == "TLS1.2"
    assert known_algorithm_or_unknown("RS256") == "RS256"


def test_sha3_signature_transformation_preserves_digest_and_signer():
    parsed = parse_transformation("SHA3-256withRSA")
    assert parsed.algorithm == "RSA"
    assert parsed.hash_algorithm == "SHA3-256"
    assert parsed.signing_algorithm == "RSA"
    assert parsed.is_signature_combo is True
