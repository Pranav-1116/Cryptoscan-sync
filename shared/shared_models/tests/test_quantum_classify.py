"""Shared quantum classifier: one verdict for one algorithm name, everywhere."""

from __future__ import annotations

from shared_models.quantum_classify import (
    GROVER_MARGINAL,
    PQC_RESISTANT,
    QUANTUM_RESISTANT,
    SHOR_VULNERABLE,
    UNKNOWN,
    is_shor_vulnerable,
    quantum_verdict,
    summarize_verdicts,
)


# --------------------------------------------------------------------------- #
# asymmetric -> Shor
# --------------------------------------------------------------------------- #

def test_asymmetric_names_are_shor_vulnerable():
    for name in [
        "RSA", "RSA-2048", "rsa_4096", "ECDSA-P256", "ECDH", "X25519", "Ed25519",
        "secp256k1", "Diffie-Hellman", "DSA", "SHA256withRSA",
    ]:
        assert quantum_verdict(name)["verdict"] == SHOR_VULNERABLE, name


def test_tls_suite_decomposes_to_shor_via_components():
    # ECDHE key exchange + RSA certificate in the suite -> Shor-vulnerable
    row = quantum_verdict("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    assert row["verdict"] == SHOR_VULNERABLE
    assert row["family"] == "tls-suite"


# --------------------------------------------------------------------------- #
# PQC families
# --------------------------------------------------------------------------- #

def test_pqc_families_are_resistant():
    for name in ["ML-KEM-768", "ML-DSA-65", "SLH-DSA-128S", "MLKEM768", "Kyber768"]:
        row = quantum_verdict(name)
        assert row["verdict"] == PQC_RESISTANT, name


# --------------------------------------------------------------------------- #
# symmetric / hash: Grover thresholds
# --------------------------------------------------------------------------- #

def test_grover_marginal_below_floors():
    assert quantum_verdict("AES-128")["verdict"] == GROVER_MARGINAL
    assert quantum_verdict("AES-128-GCM")["verdict"] == GROVER_MARGINAL
    assert quantum_verdict("SHA-256")["verdict"] == GROVER_MARGINAL


def test_adequate_symmetric_is_resistant():
    for name in ["AES-256", "AES-256-GCM", "ChaCha20-Poly1305", "SHA-384", "SHA-512", "HMAC-SHA256"]:
        assert quantum_verdict(name)["verdict"] == QUANTUM_RESISTANT, name


def test_ecb_is_not_confused_with_ecc():
    # the classic substring trap: "EC" inside "ECB"
    row = quantum_verdict("AES-128-ECB")
    assert row["verdict"] != SHOR_VULNERABLE
    assert row["status"] == "DISALLOWED"  # policy verdict comes along for free


# --------------------------------------------------------------------------- #
# honesty: unknown stays unknown
# --------------------------------------------------------------------------- #

def test_unrecognized_and_unmodeled_stay_unknown():
    assert quantum_verdict("")["verdict"] == UNKNOWN
    assert quantum_verdict(None)["verdict"] == UNKNOWN
    assert quantum_verdict("totally-not-an-algorithm")["verdict"] == UNKNOWN
    assert quantum_verdict("scrypt")["verdict"] == UNKNOWN  # kdf family: no quantum model yet
    row = quantum_verdict("scrypt")
    assert row["recognized"] is True and "no quantum model" in row["reason"]


def test_verdict_carries_registry_context():
    row = quantum_verdict("rsa_2048")
    assert row["algorithm"] == "RSA"
    assert row["key_size"] == 2048
    assert row["quantum_vulnerable"] is True
    assert quantum_verdict("AES-256")["quantum_vulnerable"] is False


# --------------------------------------------------------------------------- #
# predicate + aggregation
# --------------------------------------------------------------------------- #

def test_is_shor_vulnerable_predicate():
    assert is_shor_vulnerable("RSA-2048") is True
    assert is_shor_vulnerable("AES-256-GCM") is False
    assert is_shor_vulnerable("ML-KEM-768") is False
    assert is_shor_vulnerable(None) is False


def test_summarize_verdicts():
    summary = summarize_verdicts(
        ["RSA-2048", "RSA-4096", "ECDSA-P256", "AES-256-GCM", "ML-KEM-768", "AES-128", "mystery-box", None]
    )
    assert summary["total"] == 8
    assert summary["counts"] == {"GROVER_MARGINAL": 1, "PQC_RESISTANT": 1, "QUANTUM_RESISTANT": 1, "SHOR_VULNERABLE": 3, "UNKNOWN": 2}
    assert summary["shor_vulnerable_algorithms"] == ["ECDSA", "RSA"]
    assert "mystery-box" in summary["unknown_names"] and "None" in summary["unknown_names"]


def test_summarize_empty():
    assert summarize_verdicts([]) == {"total": 0, "counts": {}, "shor_vulnerable_algorithms": [], "unknown_names": []}


# --------------------------------------------------------------------------- #
# cross-service agreement: consumers must not diverge from the shared verdict
# --------------------------------------------------------------------------- #

def test_graph_hotspots_and_agility_agree_with_shared_classifier():
    from agility.system_score import classify_quantum
    from graph_engine.core.engine import GraphEngine

    names = ["RSA-2048", "ECDSA-P256", "AES-128-ECB", "AES-256-GCM", "ML-KEM-768", "scrypt"]
    for name in names:
        shared = quantum_verdict(name)["verdict"]
        # agility label
        expected_agility = (
            "QUANTUM_VULNERABLE" if shared == SHOR_VULNERABLE
            else "QUANTUM_RESISTANT" if shared in {QUANTUM_RESISTANT, PQC_RESISTANT, GROVER_MARGINAL}
            else "UNKNOWN"
        )
        assert classify_quantum(name) == expected_agility, name
        # graph hotspots count only Shor-vulnerable assets
        graph = GraphEngine().build(
            systems=[{"id": "s", "name": "svc"}],
            assets=[{"id": "a", "algorithm": name, "system_id": "s"}],
        )
        expected_count = 1 if shared == SHOR_VULNERABLE else 0
        assert graph.crypto_hotspots()["hotspots"][0]["quantum_vulnerable_assets"] == expected_count, name
