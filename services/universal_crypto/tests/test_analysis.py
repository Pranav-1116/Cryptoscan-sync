"""§17–§27 analysis engines: classification, quantum, PQC readiness,
agility, hard-coded, weak policy, misconfig, custom crypto, randomness,
key lifecycle, capability vs usage."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from universal_crypto.agility import CryptoAgilityEngine
from universal_crypto.classification import (
    CryptoClassifier,
    QuantumVulnerabilityClassifier,
)
from universal_crypto.custom_crypto import CustomCryptoClassifier
from universal_crypto.hardcoded import HardcodedCryptoDetector
from universal_crypto.key_lifecycle import KeyLifecycleAnalyzer
from universal_crypto.misconfig import MisconfigurationDetector
from universal_crypto.models import (
    Classification,
    CryptoObservation,
    Evidence,
    EvidenceType,
    ImplementationClass,
    Operation,
    QuantumStatus,
)
from universal_crypto.pqc_readiness import PqcReadinessEngine
from universal_crypto.randomness import RandomnessAnalyzer
from universal_crypto.runtime_engine import RuntimeCryptoEngine
from universal_crypto.weak_crypto import WeakCryptoClassifier


# ── §17 classification ────────────────────────────────────────────────────

def _obs(**overrides):
    base = dict(algorithm="RSA", evidence=[Evidence(kind=EvidenceType.AST,
                                                    detail="x")])
    base.update(overrides)
    return CryptoObservation(**base)


def test_classification_catalog():
    classifier = CryptoClassifier()
    assert classifier.classify_observation(_obs()) == Classification.ALGORITHM
    assert classifier.classify_observation(
        _obs(protocol="TLS")) == Classification.PROTOCOL
    assert classifier.classify_observation(
        _obs(library="OpenSSL", evidence=[Evidence(kind=EvidenceType.LIBRARY,
                                                   detail="x")])
    ) == Classification.CRYPTO_LIBRARY
    assert classifier.classify_observation(
        _obs(operation=Operation.KEYGEN)) == Classification.KEY
    assert classifier.classify_observation(
        _obs(evidence=[Evidence(kind=EvidenceType.CERTIFICATE, detail="x")])
    ) == Classification.CERTIFICATE
    assert classifier.classify_observation(
        _obs(evidence=[Evidence(kind=EvidenceType.CONFIG, detail="x")])
    ) == Classification.CONFIGURATION
    assert classifier.classify_observation(
        _obs(capability=True, usage=False)) == Classification.HARDWARE_CAPABILITY
    assert classifier.classify_observation(
        _obs(operation=Operation.HASH)) == Classification.PRIMITIVE


# ── §18 quantum classification ────────────────────────────────────────────

def test_quantum_classification_not_blanket_bad():
    result = QuantumVulnerabilityClassifier().classify(
        algorithm="RSA-2048", usage=True, dependency_count=421)
    assert result["classical_status"] == "accepted"
    assert result["quantum_status"] == "QUANTUM_VULNERABLE"
    assert result["usage"] is True
    assert result["dependency_count"] == 421
    assert result["migration_priority"] == "HIGH"


def test_quantum_classification_pqc():
    result = QuantumVulnerabilityClassifier().classify(
        algorithm="ML-KEM-768", usage=True)
    assert result["quantum_status"] == "QUANTUM_SAFE"
    assert result["migration_priority"] == "LOW"


# ── §19 PQC readiness ─────────────────────────────────────────────────────

def test_pqc_readiness_pipeline():
    result = PqcReadinessEngine().migration_readiness(
        algorithm="RSA", protocol="TLS", library="OpenSSL",
        usage=True)
    assert result["current_status"] == "QUANTUM_VULNERABLE"
    candidates = [c["candidate"] for c in result["candidate_analysis"]]
    assert "ML-KEM-768" in candidates
    assert result["migration_readiness"] in ("READY", "PLANNED")


def test_pqc_readiness_statuses():
    engine = PqcReadinessEngine()
    assert engine.readiness_status(algorithm="RSA", usage=True) == QuantumStatus.QUANTUM_VULNERABLE
    assert engine.readiness_status(algorithm="ML-KEM-768", usage=True) == QuantumStatus.PQC_READY
    assert engine.readiness_status(algorithm="Hybrid: X25519+ML-KEM-768", usage=True) == QuantumStatus.HYBRID


# ── §20 agility ───────────────────────────────────────────────────────────

def test_agility_example_profiles():
    engine = CryptoAgilityEngine()
    assert engine.profile("hardcoded")["score"] == 15
    assert engine.profile("configurable")["score"] == 75
    assert engine.profile("abstraction")["score"] == 95


# ── §21 hard-coded crypto ─────────────────────────────────────────────────

def test_hardcoded_detection():
    result = HardcodedCryptoDetector().detect([
        "cipher = \"AES/GCM/NoPadding\"",
        "key_size = 2048",
        "setCipherSuites(\"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\")",
        "cert_pem = \"-----BEGIN CERTIFICATE-----\"",
        "# hardcoded_algorithm in comment is not code",
    ], asset_id="svc")
    assert result["migration_risk"] == "HIGH"
    assert "hardcoded_algorithm" in result["hardcoded"]
    assert "hardcoded_certificate" in result["hardcoded"]


def test_no_hardcoded_means_low_risk():
    result = HardcodedCryptoDetector().detect(["algorithm = config.get(\"cipher\")"])
    assert result["migration_risk"] == "LOW"


# ── §22 policy-driven weak crypto ─────────────────────────────────────────

def test_policy_driven_not_universal():
    classifier = WeakCryptoClassifier()
    sha1_nist = classifier.classify(algorithm="SHA-1", policy="NIST")
    assert sha1_nist["verdict"] == "DEPRECATED"
    rsa_nist = classifier.classify(algorithm="RSA", policy="NIST", key_size=2048)
    assert rsa_nist["verdict"] == "ALLOWED"
    rsa_eu = classifier.classify(algorithm="RSA", policy="EU", key_size=2048)
    assert rsa_eu["verdict"] == "DEPRECATED"  # EU demands 3072
    tls10 = classifier.classify(algorithm="AES", policy="PCI_DSS", tls_version="TLS 1.0")
    assert tls10["verdict"] == "DEPRECATED"


def test_custom_policy():
    rules = {"min_rsa": 4096, "min_dh": 4096, "min_ecc": 384,
             "banned_algorithms": ["RC4"], "banned_modes": ["ECB"],
             "min_tls": "TLS 1.3", "banned_tls_suites": []}
    result = WeakCryptoClassifier().classify(
        algorithm="RSA", policy="CUSTOM", key_size=2048, custom_rules=rules)
    assert result["verdict"] == "DEPRECATED"
    result2 = WeakCryptoClassifier().classify(
        algorithm="RSA", policy="CUSTOM", key_size=4096, custom_rules=rules)
    assert result2["verdict"] == "ALLOWED"


# ── §23 misconfiguration ──────────────────────────────────────────────────

def test_misconfig_checks():
    detector = MisconfigurationDetector()
    tls = detector.check_tls(tls_version="TLS 1.0", cipher_suite="TLS_RSA_WITH_RC4_128_SHA",
                             pfs=False)
    assert {f["type"] for f in tls} == {"obsolete_tls", "weak_cipher", "non_pfs"}
    cert = detector.check_certificate(signature_hash="SHA-1", expired=True,
                                      key_algorithm="RSA", key_size=1024)
    assert {f["type"] for f in cert} == {"sha1_certificate", "expired_certificate",
                                         "rsa_key_too_small"}
    assert detector.check_dh(dh_group="2")
    ssh = detector.check_ssh(ciphers=["arcfour", "aes256-gcm@openssh.com"])
    assert ssh and ssh[0]["type"] == "weak_ssh_algorithm"
    vpn = detector.check_vpn(ike_version="IKEv1", encryption="3DES", pfs=False)
    assert {f["type"] for f in vpn} == {"legacy_vpn", "weak_vpn_cipher", "vpn_no_pfs"}
    assert detector.check_mode(mode="ECB")
    assert detector.check_mode(mode="CBC", policy="FIPS")


# ── §24 custom crypto ─────────────────────────────────────────────────────

def test_custom_crypto_classification():
    classifier = CustomCryptoClassifier()
    known = classifier.classify(library_hint="OpenSSL")
    assert known["classification"] == ImplementationClass.KNOWN_LIBRARY.value
    impl = classifier.classify(symbols=["EVP_sha256"])
    assert impl["classification"] == ImplementationClass.KNOWN_IMPLEMENTATION.value
    modified = classifier.classify(implementation_name="custom_aes_encrypt")
    assert modified["classification"] == ImplementationClass.MODIFIED_IMPLEMENTATION.value
    custom = classifier.classify(implementation_name="my_digest")
    assert custom["classification"] == ImplementationClass.CUSTOM_IMPLEMENTATION.value
    unknown = classifier.classify()
    assert unknown["classification"] == ImplementationClass.UNKNOWN.value
    assert unknown["security_label"] is None  # never auto-label secure/insecure


# ── §25 randomness ────────────────────────────────────────────────────────

def test_randomness_detection():
    result = RandomnessAnalyzer().analyze([
        "import random",
        "key = \"\".join(random.choice(chars) for _ in range(32))",
        "nonce = os.urandom(12)",
    ])
    flagged = [w for w in result["weak_sources"] if w["flagged"]]
    assert flagged, "random feeding a key must be flagged"
    assert result["verdict"] == "DANGEROUS_PATTERN"
    assert any(s["source"] == "os.urandom" for s in result["strong_sources"])


# ── §26 key lifecycle ─────────────────────────────────────────────────────

def test_key_lifecycle_findings():
    now = datetime.now(timezone.utc)
    records = [
        {"key_id": "k-old", "algorithm": "RSA", "usage": "signing",
         "generated_at": (now - timedelta(days=700)).isoformat(),
         "stored": True, "used": True},
        {"key_id": "k-exp", "algorithm": "AES", "usage": "encryption",
         "generated_at": (now - timedelta(days=30)).isoformat(),
         "expires_at": (now - timedelta(days=1)).isoformat(),
         "stored": True, "used": True},
        {"key_id": "k-orphan", "algorithm": "RSA", "usage": "tls",
         "generated_at": (now - timedelta(days=100)).isoformat(),
         "revoked_at": (now - timedelta(days=10)).isoformat(),
         "still_referenced": True, "stored": True, "used": True},
        {"key_id": "k-md5", "algorithm": "MD5", "usage": "signing",
         "generated_at": (now - timedelta(days=10)).isoformat(),
         "stored": True, "used": True},
        {"key_id": "k-long", "algorithm": "RSA", "usage": "encryption",
         "generated_at": (now - timedelta(days=400)).isoformat(),
         "stored": True, "used": True},
        {"key_id": "k-good", "algorithm": "RSA", "usage": "signing",
         "generated_at": (now - timedelta(days=10)).isoformat(),
         "rotated_at": (now - timedelta(days=2)).isoformat(),
         "backed_up": True, "owner": "payments", "storage": "hsm",
         "hardware_backed": True, "stored": True, "used": True},
    ]
    result = KeyLifecycleAnalyzer().analyze(records)
    types = {f["type"] for f in result["findings"]}
    assert {"never_rotated", "long_lived", "expired", "orphaned",
            "unsupported_algorithm", "unknown_owner", "unknown_storage"} <= types


# ── §27 capability vs usage ───────────────────────────────────────────────

def test_capability_vs_usage_never_conflated():
    engine = RuntimeCryptoEngine()
    observations = engine.observe(
        process="payments", loaded_libraries=["libssl.so"],
        api_calls=["EVP_EncryptUpdate", "RAND_bytes"],
        connections=[{"protocol": "TLS", "peer": "gw:443"}])
    result = engine.capability_vs_usage(
        capabilities=[
            {"algorithm": "AES-NI", "hardware": "cpu", "supported": True},
            {"algorithm": "ML-KEM-768", "hardware": "HSM", "supported": True},
            {"algorithm": "AES", "hardware": "cpu", "supported": True},
        ],
        usage=observations)
    # HSM supports ML-KEM ≠ app uses ML-KEM
    assert result["capabilities"]["ML-KEM-768"]["supported"] is True
    assert result["capabilities"]["ML-KEM-768"]["usage"] is False
    assert "ML-KEM-768" in result["supported_but_unused"]
    # AES capability exercised at runtime
    assert result["capabilities"]["AES"]["usage"] is True


def test_unknown_algorithm_never_labeled_safe():
    """§18/§24 honesty rule: algorithms outside the registry are PQC_UNKNOWN,
    never auto-labeled QUANTUM_SAFE."""
    result = QuantumVulnerabilityClassifier().classify(
        algorithm="ProprietaryDigest-X", usage=True)
    assert result["quantum_status"] == "PQC_UNKNOWN"
    assert result["migration_priority"] == "LOW"
    assert "cannot classify" in result["rationale"]
    # known symmetric/hash families still resolve through the registry
    assert QuantumVulnerabilityClassifier().classify(
        algorithm="AES-256", usage=True)["quantum_status"] == "QUANTUM_SAFE"


def test_weak_ecc_curve_parameters():
    """§22: curve approval is policy-driven — no universal judgment."""
    classifier = WeakCryptoClassifier()
    assert classifier.classify(algorithm="ECDSA", policy="FIPS",
                              curve="secp256k1")["verdict"] == "DEPRECATED"
    assert classifier.classify(algorithm="ECDSA", policy="FIPS",
                              curve="P-256")["verdict"] == "ALLOWED"
    assert classifier.classify(algorithm="ECDSA", policy="EU",
                              curve="BrainpoolP384r1")["verdict"] == "ALLOWED"
    assert classifier.classify(algorithm="ECDSA", policy="FIPS",
                              curve="BrainpoolP384r1")["verdict"] == "DEPRECATED"
    # alias: secp256r1 IS P-256
    assert classifier.classify(algorithm="ECDSA", policy="FIPS",
                              curve="secp256r1")["verdict"] == "ALLOWED"
    # custom policy can approve its own curves
    rules = {"min_rsa": 2048, "min_dh": 2048, "min_ecc": 256,
             "banned_algorithms": [], "banned_modes": [],
             "min_tls": "TLS 1.2", "banned_tls_suites": [],
             "approved_curves": ["secp256k1"]}
    assert classifier.classify(algorithm="ECDSA", policy="CUSTOM",
                              curve="secp256k1",
                              custom_rules=rules)["verdict"] == "ALLOWED"


def test_randomness_numpy_and_seed_flagged():
    result = RandomnessAnalyzer().analyze([
        "import numpy",
        "key = numpy.random.bytes(32)",
        "random.seed(1234)",
    ])
    weak = {w["source"] for w in result["weak_sources"] if w["flagged"]}
    assert "numpy.random" in weak
    assert "random.seed" in weak
