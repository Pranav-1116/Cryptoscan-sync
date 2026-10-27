from shared_models.safe_finding import safe_finding


def test_signature_hash_is_structured_without_exposing_raw_transformation():
    raw = {
        "source": {"file_path": "Signer.java", "line_number": 4,
                   "code_snippet": "SECRET_KEY=synthetic-test-value"},
        "crypto": {"algorithm": "RSA", "api_type": "SIGNATURE",
                   "raw_transformation": "SHA256withRSA"},
        "metadata": {"confidence": "HIGH", "confidence_reason": "literal-api"},
    }
    safe = safe_finding(raw)
    assert safe["crypto"]["hash_algorithm"] == "SHA-256"
    assert "synthetic-test-value" not in str(safe)
    assert "raw_transformation" not in safe["crypto"]
