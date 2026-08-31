"""Model tests: enums, canonical shapes, vendor_specific preservation (§20)."""

from __future__ import annotations

from universal_vendor.models import (
    AssetType,
    CryptoObservation,
    CryptoType,
    DetectionResult,
    LifecycleStatus,
    PqcCapability,
    PluginStatus,
    ScanMode,
    UniversalObservation,
    VendorCategory,
    Visibility,
)


def test_categories_cover_spec():
    values = {member.value for member in VendorCategory}
    assert values == {
        "network", "firewall", "load_balancer", "cloud", "pki", "hsm",
        "identity", "database", "middleware", "os", "edr", "siem", "devops",
        "container", "kubernetes", "saas", "generic",
    }


def test_statuses_cover_spec_18():
    assert {s.value for s in PluginStatus} == {
        "STABLE", "BETA", "EXPERIMENTAL", "DEPRECATED", "DISABLED",
    }


def test_visibility_cover_spec_15():
    assert {v.value for v in Visibility} == {
        "OBSERVED", "API_VISIBLE", "UNKNOWN", "NOT_SUPPORTED",
    }


def test_pqc_verdicts_cover_spec_22():
    assert {p.value for p in PqcCapability} == {
        "PQC_SUPPORTED", "HYBRID_SUPPORTED", "ROADMAP_DECLARED",
        "NOT_SUPPORTED", "UNKNOWN",
    }


def test_scan_modes_cover_spec_24():
    assert {m.value for m in ScanMode} == {
        "AUTO_DETECT", "INVENTORY_ONLY", "CRYPTO_DISCOVERY",
        "CONFIGURATION_DISCOVERY", "DEEP_DISCOVERY", "CONTINUOUS_MONITORING",
    }


def test_universal_observation_preserves_vendor_specific():
    obs = UniversalObservation(
        vendor="Cisco", product="IOS-XE",
        asset_type=AssetType.ROUTER.value,
        algorithm="AES-256-GCM",
        vendor_specific={"config_line": "crypto ipsec transform-set TS esp-aes 256",
                         "snmp_community": "REDACTED-expected"},
    )
    dumped = obs.model_dump(mode="json")
    assert dumped["vendor_specific"]["config_line"] == (
        "crypto ipsec transform-set TS esp-aes 256"
    )
    assert dumped["algorithm"] == "AES-256-GCM"


def test_detection_result_detected_property():
    assert DetectionResult(detected_vendor="Cisco", confidence=0.9).detected
    assert not DetectionResult(detected_vendor="Cisco", confidence=0.4).detected
    assert not DetectionResult(confidence=0.9).detected


def test_crypto_observation_roundtrip():
    crypto = CryptoObservation(
        vendor="Juniper", product="Junos", algorithm="ECDH",
        algorithm_family="asymmetric", quantum_vulnerable=True,
        nist_status="allowed",
    )
    data = crypto.model_dump(mode="json")
    assert data["vendor"] == "Juniper"
    assert data["quantum_vulnerable"] is True


def test_crypto_type_enum():
    assert CryptoType.ALGORITHM.value == "algorithm"
    assert CryptoType.CERTIFICATE.value == "certificate"
    assert CryptoType.KEY.value == "key"
    assert CryptoType.PROTOCOL.value == "protocol"
    assert CryptoType.CONFIGURATION.value == "configuration"


def test_lifecycle_status_enum():
    assert LifecycleStatus.END_OF_LIFE.value == "END_OF_LIFE"
    assert LifecycleStatus.END_OF_SUPPORT.value == "END_OF_SUPPORT"
