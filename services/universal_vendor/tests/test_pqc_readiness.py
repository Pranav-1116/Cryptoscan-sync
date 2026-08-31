"""PQC readiness database tests (spec §22)."""

from __future__ import annotations

from universal_vendor.models import PqcCapability
from universal_vendor.pqc_readiness import PqcReadinessDatabase


def test_db_versioned():
    db = PqcReadinessDatabase()
    assert db.version == "2026-08"
    entries = db.entries()
    assert entries, "seed entries required"
    # every entry must carry evidence
    for entry in entries:
        assert entry["evidence_source"], "evidence source required per entry"


def test_never_infer_from_name():
    """Unknown vendor/product must never be inferred from the product name —
    the honest verdict is UNKNOWN."""
    db = PqcReadinessDatabase()
    verdict = db.verdict("FictionalVendor", "QuantumSuperBox-9000", "1.0")
    assert verdict["pqc_capability"] == PqcCapability.UNKNOWN.value
    assert verdict["confidence"] == 0.0
    assert "NOT inferred" in verdict["reason"]


def test_known_algorithm_level_facts():
    db = PqcReadinessDatabase()
    # RSA-2048 is NIST-disallowed for 2030 security (public standard) —
    # must be recorded with evidence, not guessed
    verdict = db.verdict("NIST", "RSA", "2048")
    assert verdict["pqc_capability"] in {
        PqcCapability.NOT_SUPPORTED.value, PqcCapability.ROADMAP_DECLARED.value,
    }
    assert verdict["evidence_source"]


def test_verdict_structure():
    db = PqcReadinessDatabase()
    verdict = db.verdict("Cisco", "IOS-XE", "17.9.4a")
    assert set(verdict) >= {
        "vendor", "product", "version", "pqc_capability", "db_version",
        "confidence",
    }
    if verdict["pqc_capability"] != PqcCapability.UNKNOWN.value:
        assert verdict["evidence_source"]
        assert verdict["last_verified"]
