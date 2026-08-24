from scanner.models.raw_finding import RawFinding


def test_flat_constructor():
    finding = RawFinding(algorithm="DES", file_path="A.java", line_number=4, confidence="HIGH")
    assert finding.crypto.algorithm == "DES"
    assert finding.source.file_path == "A.java"
    assert finding.metadata.confidence == "HIGH"


def test_canonical_json_is_stable():
    finding = RawFinding(algorithm="AES", file_path="B.java", line_number=1, confidence="HIGH")
    first = finding.to_canonical_json()
    second = finding.to_canonical_json()
    assert first == second
