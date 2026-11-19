"""Central CBOM normalization registry and purpose-aware risk model."""
import pytest

from cbom.crypto_normalization import (ASSET, CONFIGURATION, EXCLUDED, UNRECOGNIZED, deployment_stage,
                                       normalize, suite_algorithms)
from cbom.crypto_risk import FINDING_STATUS, assess


@pytest.mark.parametrize("algorithm,kwargs", [("AES", {"key_size": 256, "mode": "GCM"}),
                                              ("AES-GCM", {"key_size": 256}), ("AES-256-GCM", {})])
def test_aes_gcm_spellings_share_one_variant_identity(algorithm, kwargs):
    n = normalize(algorithm, **kwargs)
    assert (n.name, n.primitive, n.mode, n.parameter_set) == ("AES-256-GCM", "ae", "gcm", "256")
    assert (n.classical_level, n.quantum_level) == (256, 5)
    assert n.identity_key() == "aes-256-gcm"


def test_aes_without_parameters_is_not_upgraded():
    n = normalize("AES")
    assert n.name == "AES" and n.primitive == "block-cipher" and n.parameter_set is None and n.mode is None
    assert n.quantum_level is None


def test_ml_kem_768_is_a_parameter_set_with_fips_203_sizes():
    for algorithm, size in (("ML-KEM", 768), ("ML-KEM-768", None), ("ML-KEM-768", 1184)):
        n = normalize(algorithm, key_size=size)
        assert n.name == "ML-KEM-768" and n.primitive == "kem" and n.parameter_set == "768"
        assert n.quantum_level == 3 and n.key_size_bits is None
        assert n.parameter_facts["public_key_bytes"] == 1184 and n.parameter_facts["ciphertext_bytes"] == 1088
        assert n.standard.startswith("FIPS 203")


def test_protocols_are_protocols_and_version_is_never_invented():
    bare = normalize("TLS")
    assert bare.asset_type == "protocol" and bare.protocol_version is None and bare.registry_status == "UNKNOWN"
    assert normalize("TLSv1.3").protocol_version == "1.3"
    suite = normalize("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    assert suite.asset_type == "protocol" and suite.parameter_facts["cipher_suite"]
    assert suite_algorithms("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")


def test_classification_stage():
    assert normalize("MARKER", purpose="SEED").classification == EXCLUDED
    assert normalize("not-real-ML-KEM").classification == UNRECOGNIZED
    assert normalize("RSA", key_size=2048, location="src/A.java").classification == ASSET
    assert normalize("RSA", key_size=2048, location="conf/app.yaml").classification == CONFIGURATION
    assert normalize("TLS 1.2", location="conf/nginx.conf").classification == CONFIGURATION


def test_deployment_stage_follows_evidence_only():
    assert deployment_stage("src/A.java") == "DETECTED_IN_SOURCE"
    assert deployment_stage("conf/app.yaml") == "CONFIGURED"
    assert deployment_stage("lib/app.jar") == "PRESENT_IN_BINARY"
    assert deployment_stage("/etc/ssl/a.pem", host_evidence=True) == "PRESENT_ON_HOST"
    assert deployment_stage("tls://pay.example:443") == "RUNTIME_OBSERVED"
    assert deployment_stage("https://github.com/org/repo") == "DETECTED_IN_SOURCE"


def test_fields_only_when_supported():
    rsa = normalize("RSA", key_size=2048)
    assert rsa.crypto_functions == [] and rsa.crypto_functions_basis
    assert normalize("RSA", key_size=4096, purpose="SIGNING").crypto_functions == ["sign"]
    assert normalize("ECDSA", key_size=256).curve is None
    assert normalize("ECDSA", key_size=256, curve="P-256").curve


@pytest.mark.parametrize("algorithm,size,purpose,expected", [
    ("MD5", None, "CHECKSUM", "LOW"),
    ("MD5", None, "SIGNING", "HIGH"),
    ("MD5", None, None, "REVIEW"),
    ("SHA-1", None, "HMAC", "LOW"),
    ("SHA-1", None, "CERTIFICATE_SIGNATURE", "HIGH"),
    ("DES", None, "ENCRYPTION", "HIGH"),
    ("3DES", 168, "ENCRYPTION", "HIGH"),
    ("RC4", None, None, "HIGH"),
    ("DHE", 1024, "KEY_EXCHANGE", "HIGH"),
    ("AES", 256, "ENCRYPTION", "NONE"),
    ("TLS", None, None, "REVIEW"),
    ("TLS 1.2", None, None, "REVIEW"),  # version alone is neither approved nor deprecated
])
def test_weak_algorithm_risk_is_purpose_aware(algorithm, size, purpose, expected):
    result = assess(normalize(algorithm, key_size=size, purpose=purpose), purpose=purpose)
    assert result["algorithm_risk"] == expected
    assert result["finding_status"] == FINDING_STATUS


def test_harvest_now_decrypt_later_is_prioritised_without_overstating_the_algorithm():
    n = normalize("RSA", key_size=2048, purpose="KEY_EXCHANGE")
    result = assess(n, purpose="KEY_EXCHANGE", retention_years=12)
    assert result["quantum_exposure"] == "HARVEST_NOW_DECRYPT_LATER"
    assert result["algorithm_risk"] == "NONE" and result["priority"] == "P3"
    assert assess(n, purpose="KEY_EXCHANGE", retention_years=12, criticality="CRITICAL")["priority"] == "P2"


def test_pqc_detection_is_not_deployment():
    n = normalize("ML-KEM-768")
    assert assess(n, deployment_stage="DETECTED_IN_SOURCE")["quantum_exposure"] \
        == "QUANTUM_RESISTANT_ALGORITHM_DEPLOYMENT_NOT_ESTABLISHED"
    assert assess(n, deployment_stage="RUNTIME_OBSERVED")["quantum_exposure"] == "QUANTUM_RESISTANT_OBSERVED_AT_RUNTIME"
