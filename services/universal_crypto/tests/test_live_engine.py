"""§34/§35 live crypto scanner: events → state → targeted analysis →
CBOM → PQC risk recalculation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from universal_crypto.live.engine import LiveCryptoEngine
from universal_crypto.live.events import CryptoEvent
from universal_crypto.models import CryptoEventType


def _event(event_type: CryptoEventType, asset_id: str = "payments",
           **payload) -> CryptoEvent:
    return CryptoEvent(event_type=event_type, asset_id=asset_id, payload=payload)


def test_certificate_renewal_flow():
    engine = LiveCryptoEngine()
    engine.ingest(_event(CryptoEventType.CERT_NEW,
                         certificate_id="cert-1", subject="payments.internal",
                         signature_algorithm="RSA-PSS",
                         public_key_algorithm="RSA", key_size=2048))
    before_version = engine.state("payments").cbom_version
    before = engine.state("payments").to_dict()  # snapshot
    assert before["certificates"]["cert-1"]["status"] == "VALID"
    assert before["quantum_status"].get("RSA-PSS") == "QUANTUM_VULNERABLE"
    # used + vulnerable certificate → 40 (used) + 30 (readiness) = 70 HIGH
    assert engine.risk("payments")["level"] == "HIGH"

    # certificate renewed → signature algorithm changed → PQC status
    # recalculated → risk updated (§34 example)
    result = engine.ingest(_event(CryptoEventType.CERT_RENEWED,
                                  certificate_id="cert-1",
                                  previous_signature_algorithm="RSA-PSS",
                                  signature_algorithm="ML-DSA-65",
                                  public_key_algorithm="ML-DSA-65",
                                  key_size=1952))
    state = engine.state("payments")
    assert state.certificates["cert-1"]["status"] == "RENEWED"
    assert state.quantum_status["ML-DSA-65"] == "QUANTUM_SAFE"
    assert "RSA-PSS" not in state.quantum_status  # retired by renewal
    assert state.cbom_version == before_version + 1
    assert engine.risk("payments")["level"] == "NONE"  # risk updated
    assert result["cbom"]["bomFormat"] == "CycloneDX"


def test_pqc_capability_change_updates_readiness_not_usage():
    engine = LiveCryptoEngine()
    engine.ingest(_event(CryptoEventType.ALGORITHM_DETECTED,
                         algorithm="RSA", usage=True))
    result = engine.ingest(_event(CryptoEventType.PQC_CAPABILITY_CHANGED,
                                  algorithm="ML-KEM-768", supported=True))
    state = engine.state("payments")
    # §27: HSM supports ML-KEM ≠ application uses ML-KEM
    assert state.capabilities["ML-KEM-768"] is True
    assert state.usage.get("ML-KEM-768") is None
    assert state.quantum_status["ML-KEM-768"] == "PQC_READY"
    assert result["cbom"]["components"]  # CBOM carries the hardware capability


def test_live_cbom_uses_cyclonedx_oids():
    engine = LiveCryptoEngine()
    engine.ingest(_event(CryptoEventType.ALGORITHM_DETECTED,
                         algorithm="AES-GCM", operation="encrypt"))
    engine.ingest(_event(CryptoEventType.TLS_POLICY_CHANGED,
                         protocol="TLS", min_version="TLS 1.3", pfs=True))
    cbom = engine.cbom("payments")
    assert cbom["specVersion"] == "1.6"
    assert cbom["bomFormat"] == "CycloneDX"
    crypto_components = [c for c in cbom["components"] if c["type"] == "cryptography"]
    aes = next(c for c in crypto_components if c["name"] == "AES-GCM")
    assert aes["cryptography"]["algorithm"]["oid"].startswith("2.16.840")
    assert any(r["relationship"] == "uses" for r in cbom["relationships"])
    assert cbom["metadata"]["properties"]  # readiness/agility attached


def test_state_replay_state_at():
    engine = LiveCryptoEngine()
    t0 = datetime.now(timezone.utc)
    engine.ingest(CryptoEvent(event_type=CryptoEventType.ALGORITHM_DETECTED,
                              asset_id="payments", observed_at=t0,
                              payload={"algorithm": "RSA", "usage": True}))
    engine.ingest(CryptoEvent(event_type=CryptoEventType.ALGORITHM_DETECTED,
                              asset_id="payments",
                              observed_at=t0 + timedelta(minutes=5),
                              payload={"algorithm": "ML-KEM-768", "usage": False}))
    before = engine.state_engine.state_at("payments", t0 + timedelta(minutes=1))
    after = engine.state_engine.state_at("payments", t0 + timedelta(minutes=10))
    assert "RSA" in before["algorithms"]
    assert "ML-KEM-768" not in before["algorithms"]
    assert "ML-KEM-768" in after["algorithms"]


def test_library_upgrade_recalculates_pqc():
    engine = LiveCryptoEngine()
    engine.ingest(_event(CryptoEventType.ALGORITHM_DETECTED,
                         algorithm="ML-DSA-65", usage=False))
    engine.ingest(_event(CryptoEventType.LIBRARY_UPGRADED,
                         library="OpenSSL", version="3.5.0", pqc_support=True))
    state = engine.state("payments")
    assert state.libraries["OpenSSL"]["version"] == "3.5.0"
    assert state.quantum_status.get("ML-DSA-65") == "PQC_READY"


def test_unknown_crypto_operation_event():
    engine = LiveCryptoEngine()
    result = engine.ingest(_event(CryptoEventType.UNKNOWN_CRYPTO_OPERATION,
                                  location="lib/private.py:3",
                                  snippet="def custom_hash(data):"))
    state = engine.state("payments")
    assert "UNKNOWN_CRYPTO_OPERATION" in state.algorithms
    assert result["risk"]["score"] >= 10


def test_algorithm_removed_retires_status_and_usage():
    engine = LiveCryptoEngine()
    engine.ingest(_event(CryptoEventType.ALGORITHM_DETECTED,
                         algorithm="RSA", usage=True))
    state = engine.state("payments")
    assert state.quantum_status["RSA"] == "QUANTUM_VULNERABLE"
    engine.ingest(_event(CryptoEventType.ALGORITHM_REMOVED, algorithm="RSA"))
    state = engine.state("payments")
    assert "RSA" not in state.quantum_status
    assert "RSA" not in state.usage
    assert "RSA" not in state.algorithms


def test_key_expired_clears_usage():
    engine = LiveCryptoEngine()
    engine.ingest(_event(CryptoEventType.ALGORITHM_DETECTED,
                         algorithm="RSA", usage=True))
    result = engine.ingest(_event(CryptoEventType.KEY_EXPIRED,
                                  key_id="k1", algorithm="RSA", usage=False))
    state = engine.state("payments")
    assert state.usage.get("RSA") is False
    assert result["risk"]["score"] < 100  # risk recalculated after key expiry


def test_config_change_refreshes_usage():
    engine = LiveCryptoEngine()
    engine.ingest(_event(CryptoEventType.ALGORITHM_DETECTED,
                         algorithm="AES-GCM", usage=True))
    engine.ingest(_event(CryptoEventType.CONFIG_CHANGED,
                         algorithm="AES-GCM", usage=False))
    state = engine.state("payments")
    assert state.usage["AES-GCM"] is False
    assert state.algorithms["AES-GCM"]["usage"] is False


def test_implementation_change_reclassifies():
    engine = LiveCryptoEngine()
    engine.ingest(_event(CryptoEventType.ALGORITHM_DETECTED,
                         algorithm="SHA-256", usage=True))
    engine.ingest(_event(CryptoEventType.IMPLEMENTATION_CHANGED,
                         implementation="digest-lib",
                         classification="KNOWN_IMPLEMENTATION"))
    state = engine.state("payments")
    assert state.libraries["digest-lib"]["implementation"] == "KNOWN_IMPLEMENTATION"
    assert state.quantum_status["SHA-256"] == "QUANTUM_SAFE"
