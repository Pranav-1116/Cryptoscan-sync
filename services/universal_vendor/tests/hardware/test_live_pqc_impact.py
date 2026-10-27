"""Live hardware PQC monitoring (§18) — hardware change → crypto capability
→ PQC capability → affected software → migration impact."""

from __future__ import annotations

from universal_vendor.hardware.live import HardwarePqcImpactEngine
from universal_vendor.pqc_readiness import PqcReadinessDatabase


def test_legacy_hsm_with_many_dependencies_is_high_impact():
    """§18 example: legacy HSM + no required PQC capability + 100
    applications → HIGH migration dependency."""
    engine = HardwarePqcImpactEngine()
    apps = [f"app-{i}" for i in range(100)]
    result = engine.assess(
        asset_id="hsm-1",
        manufacturer="Thales",
        model="Luna Legacy",
        affected_applications=apps,
        hardware_change_type="HSM_CHANGED",
    )
    assert result["pqc_capability"] == "UNKNOWN"  # honest, not inferred
    assert result["affected_application_count"] == 100
    assert result["migration_impact"] == "HIGH"


def test_supported_pqc_means_no_migration_dependency():
    from universal_vendor.pqc_readiness import PqcReadinessEntry

    db = PqcReadinessDatabase()
    db.add(PqcReadinessEntry(
        vendor="Nitrokey", product="NetHSM", version=None, firmware=None,
        crypto_capability="AES", pqc_capability="HYBRID_SUPPORTED",
        hybrid_capability=True, confidence=1.0,
    ))
    engine = HardwarePqcImpactEngine(pqc_db=db)
    result = engine.assess(
        asset_id="hsm-2",
        manufacturer="Nitrokey",
        model="NetHSM",
        affected_applications=["a", "b", "c", "d"],
        hardware_change_type="HSM_CHANGED",
    )
    assert result["migration_impact"] == "NONE"
    assert result["hybrid_capability"] is True


def test_medium_impact_thresholds():
    engine = HardwarePqcImpactEngine()
    few = engine.assess(asset_id="hsm-3", manufacturer="Vendor", model="M",
                        affected_applications=["a", "b"])
    assert few["migration_impact"] == "LOW"
    some = engine.assess(asset_id="hsm-4", manufacturer="Vendor", model="M",
                         affected_applications=["a", "b", "c"])
    assert some["migration_impact"] == "MEDIUM"


def test_affected_applications_from_correlation_graph():
    from universal_vendor.hardware.correlation import HardwareCorrelationEngine

    correlation = HardwareCorrelationEngine()
    correlation.link_hardware_to_software(
        server="hsm-5", component="hsm", operating_system="os",
        crypto_library="pkcs11", application="payments", certificate="cert-1",
    )
    engine = HardwarePqcImpactEngine(correlation=correlation)
    apps = engine.affected_applications("hsm-5")
    assert "payments" in apps
    result = engine.assess(asset_id="hsm-5", manufacturer="Vendor", model="M",
                           hardware_change_type="HSM_CHANGED")
    assert result["affected_application_count"] >= 1


def test_assessments_history_and_latest():
    engine = HardwarePqcImpactEngine()
    engine.assess(asset_id="hsm-6", manufacturer="V", model="M")
    engine.assess(asset_id="hsm-6", manufacturer="V", model="M",
                  affected_applications=["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"])
    latest = engine.latest("hsm-6")
    assert latest["migration_impact"] == "HIGH"
    assert len(engine.assessments()) == 2
