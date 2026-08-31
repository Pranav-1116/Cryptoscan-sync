"""Vendor lifecycle + migration priority tests (spec §23)."""

from __future__ import annotations

from universal_vendor.lifecycle import VendorLifecycleDatabase
from universal_vendor.models import LifecycleStatus


def test_db_versioned():
    db = VendorLifecycleDatabase()
    assert db.version == "2026-08"
    assert db.entries(), "seed entries required"


def test_known_milestones():
    db = VendorLifecycleDatabase()
    tls = db.status("IETF", "TLS", "1.0")
    assert tls["support_status"] == LifecycleStatus.END_OF_LIFE.value
    assert "RFC 8996" in tls["evidence_source"]

    ws2012 = db.status("Microsoft", "Windows Server", "2012 R2")
    assert ws2012["support_status"] == LifecycleStatus.END_OF_SUPPORT.value

    ubuntu = db.status("Canonical", "Ubuntu", "16.04")
    assert ubuntu["support_status"] in (
        LifecycleStatus.END_OF_SUPPORT.value, LifecycleStatus.END_OF_LIFE.value,
    )


def test_unknown_product_honest():
    db = VendorLifecycleDatabase()
    status = db.status("FictionalVendor", "Frobnicator", "9.9")
    assert status["support_status"] == LifecycleStatus.UNKNOWN.value


def test_migration_priority_high():
    """Legacy + PQC migration required + EOS → HIGH (spec §23)."""
    db = VendorLifecycleDatabase()
    result = db.migration_priority("Microsoft", "Windows Server", "2012 R2",
                                   pqc_required=True)
    assert result["migration_priority"] == "HIGH"
    assert result["pqc_required"] is True


def test_migration_priority_medium_pqc_only():
    db = VendorLifecycleDatabase()
    result = db.migration_priority("IETF", "TLS", "1.2", pqc_required=True)
    assert result["migration_priority"] in ("MEDIUM", "HIGH")


def test_migration_priority_low_without_signals():
    db = VendorLifecycleDatabase()
    result = db.migration_priority("FictionalVendor", "Thing", "1.0")
    assert result["migration_priority"] == "LOW"


def test_entries_evidence_backed():
    db = VendorLifecycleDatabase()
    for entry in db.entries():
        assert entry["evidence_source"], "evidence source required"
