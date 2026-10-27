from scanner.extractors.algorithm_extractor import parse_transformation


def test_compound_aes_gcm():
    parsed = parse_transformation("AES/GCM/NoPadding")
    assert parsed.algorithm == "AES"
    assert parsed.mode == "GCM"


def test_desede_alias():
    parsed = parse_transformation("DESede")
    assert parsed.algorithm == "3DES"
