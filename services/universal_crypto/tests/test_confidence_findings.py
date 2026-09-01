"""§28 confidence fusion + calibration, §29 findings, §30 correlator,
§31 unknown-crypto detector."""

from __future__ import annotations

import json
import os

from universal_crypto.confidence import (
    DEFAULT_WEIGHTS,
    band_for,
    calibrate_weights,
    evaluate_weights,
    score_evidence,
)
from universal_crypto.correlator import FindingCorrelator
from universal_crypto.findings import FindingBuilder
from universal_crypto.models import (
    ConfidenceBand,
    CryptoObservation,
    Evidence,
    EvidenceType,
    Operation,
    QuantumStatus,
)
from universal_crypto.unknown_detector import UnknownCryptoDetector


def _ev(kind: EvidenceType, detail: str = "x") -> Evidence:
    return Evidence(kind=kind, detail=detail)


# ── §28 fusion ────────────────────────────────────────────────────────────

def test_spec_weights_example():
    # source API +30, library +20, binary +20, config +15, runtime +15
    score = score_evidence([
        _ev(EvidenceType.AST), _ev(EvidenceType.LIBRARY),
        _ev(EvidenceType.BINARY), _ev(EvidenceType.CONFIG),
        _ev(EvidenceType.RUNTIME)])
    assert score == 100.0


def test_confidence_bands():
    assert band_for(96) == ConfidenceBand.CONFIRMED
    assert band_for(95) == ConfidenceBand.CONFIRMED
    assert band_for(90) == ConfidenceBand.HIGH_CONFIDENCE
    assert band_for(75) == ConfidenceBand.MEDIUM
    assert band_for(55) == ConfidenceBand.LOW
    assert band_for(30) == ConfidenceBand.UNCONFIRMED


def test_evidence_kind_counts_once():
    score = score_evidence([_ev(EvidenceType.AST), _ev(EvidenceType.AST),
                            _ev(EvidenceType.AST, "y")])
    assert score == 30.0


def test_confirmatory_kinds_boost():
    score = score_evidence([_ev(EvidenceType.AST), _ev(EvidenceType.PROTOCOL)])
    assert score == 40.0


def test_calibration_is_deterministic_and_stable():
    corpus_path = os.path.join(os.path.dirname(__file__), "..",
                               "universal_crypto", "accuracy_data",
                               "calibration_corpus.json")
    with open(corpus_path) as fh:
        corpus = json.load(fh)
    first = calibrate_weights(corpus)
    second = calibrate_weights(corpus)
    assert first == second  # deterministic
    assert evaluate_weights(corpus, DEFAULT_WEIGHTS)["f1"] >= 0.85
    # calibrated weights stay within one step of the spec-seeded defaults
    for kind in DEFAULT_WEIGHTS:
        assert abs(first[kind] - DEFAULT_WEIGHTS[kind]) <= 5.0, kind


# ── §29 explainable findings ──────────────────────────────────────────────

def test_finding_has_all_explainability_fields():
    obs = CryptoObservation(
        algorithm="RSA-2048", operation=Operation.SIGN,
        library="BouncyCastle", key_size=2048,
        asset_id="authentication-service", location="auth-svc",
        evidence=[_ev(EvidenceType.AST, "JCA Signature API"),
                  _ev(EvidenceType.LIBRARY, "Bouncy Castle dependency"),
                  _ev(EvidenceType.CERTIFICATE, "runtime certificate")],
        confidence=98.0, band=ConfidenceBand.CONFIRMED,
        usage=True, source="ast")
    finding = FindingBuilder().build(
        obs, affected_assets=43,
        quantum_classification={"quantum_status": "QUANTUM_VULNERABLE",
                                "migration_priority": "HIGH"})
    assert finding.what.startswith("RSA-2048")
    assert finding.where == "auth-svc"
    assert "JCA Signature API" in finding.how_detected
    assert "43 asset(s)" in finding.impact
    assert "quantum" in finding.impact.lower()
    assert "ML-DSA" in finding.recommendation
    assert finding.quantum_status == QuantumStatus.QUANTUM_VULNERABLE
    assert finding.migration_priority.value == "HIGH"
    assert finding.confidence == 98.0


# ── §30 correlator ────────────────────────────────────────────────────────

def test_correlator_suppresses_doc_mentions():
    correlator = FindingCorrelator()
    rows = correlator.correlate([
        {"algorithm": "RSA", "operation": None, "asset_id": "svc",
         "location": "docs/architecture.md",
         "evidence": [_ev(EvidenceType.CONFIG, "doc mention")]},
    ])
    assert rows == []


def test_correlator_merges_duplicates_across_sources():
    correlator = FindingCorrelator()
    rows = correlator.correlate([
        {"algorithm": "SHA-256", "operation": "hash", "asset_id": "svc",
         "location": "app/main.py:12",
         "evidence": [_ev(EvidenceType.AST, "hashlib.sha256")]},
        {"algorithm": "SHA-256", "operation": "hash", "asset_id": "svc",
         "location": "tls:svc:443",
         "evidence": [_ev(EvidenceType.PROTOCOL, "TLS 1.3")]},
    ])
    assert len(rows) == 1
    assert len(rows[0]["evidence"]) == 2


def test_correlator_tags_weak_evidence():
    rows = FindingCorrelator().correlate([
        {"algorithm": "RSA", "operation": None, "asset_id": "svc",
         "location": "registry.json",
         "evidence": [_ev(EvidenceType.KEY_METADATA, "key record")]},
    ])
    assert rows[0]["suppression_reason"] == "weak_evidence_only"


# ── §31 unknown crypto detector ───────────────────────────────────────────

def test_unknown_crypto_queued_for_deep_analysis():
    detector = UnknownCryptoDetector()
    items = detector.scan_source([
        "def custom_hash(data):",
        "    return proprietary_digest(data)",
    ], asset_id="svc", location="lib/private.py")
    assert len(items) == 1
    assert items[0]["status"] == "OPEN"
    assert items[0]["deep_analysis"] == [
        "deep_binary_analysis", "ast_analysis",
        "runtime_observation", "human_review"]


def test_unknown_review_workflow():
    detector = UnknownCryptoDetector()
    items = detector.scan_source(["def custom_encrypt(x):\n    return x"],
                                 asset_id="svc")
    detector.queue.analyze(items[0]["unknown_id"], result="no known fingerprint")
    reviewed = detector.queue.review(items[0]["unknown_id"],
                                     decision="crypto", note="vendor impl")
    assert reviewed["status"] == "REVIEWED"
    assert reviewed["review_decision"] == "crypto"
    assert detector.queue.pending() == []
