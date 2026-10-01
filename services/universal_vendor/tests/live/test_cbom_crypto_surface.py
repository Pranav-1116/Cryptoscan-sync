"""CBOM coverage for the full realtime cryptographic surface."""

from __future__ import annotations

from universal_vendor.common_discovery import discover_common_crypto
from universal_vendor.live.cbom import LiveCbom
from universal_vendor.live.events import EventType, UniversalVendorEvent


class _Plugin:
    vendor = "TestVendor"
    product = "TestProduct"
    plugin_id = "test"


def test_common_discovery_projects_full_metadata_without_material():
    records = discover_common_crypto(_Plugin(), {
        "asset_id": "asset-1",
        "api_metadata": {
            "algorithms": [{
                "algorithm": "RSA-2048", "algorithm_type": "signature",
                "mode": "PSS", "padding": "PSS", "oid": "1.2.840.113549.1.1.1",
                "quantum_safe_status": "vulnerable", "key_size": 2048,
                "migration_priority": "high", "pqc_alternatives": ["ML-DSA"],
            }],
            "protocols": [{
                "protocol": "TLS", "version": "1.3",
                "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
                "configuration": {"forward_secrecy": True, "password": "must-not-retain"},
            }],
            "keys": [{
                "key_id": "key-1", "key_role": "signing", "storage_location": "hsm://p1",
                "lifecycle_state": "active", "private_key": "private material",
            }],
            "certificates": [{
                "serial_number": "serial-1", "issuer": "Root", "subject": "Leaf",
                "not_after": "2030-01-01", "signature_algorithm": "sha256WithRSAEncryption",
                "public_key": {"type": "RSA", "size": 2048},
            }],
            "crypto_services": [{"name": "vault-1", "service_type": "vault", "provider": "operator"}],
            "rngs": [{"name": "hwrng", "type": "hardware"}],
        },
    })
    algorithm = next(record for record in records if record["crypto_type"] == "algorithm")
    protocol = next(record for record in records if record["crypto_type"] == "protocol")
    key = next(record for record in records if record["crypto_type"] == "key")
    certificate = next(record for record in records if record["crypto_type"] == "certificate")
    service = next(record for record in records if record["crypto_type"] == "service")
    rng = next(record for record in records if record["crypto_type"] == "rng")
    assert algorithm["algorithm_type"] == "signature"
    assert algorithm["padding_scheme"] == "PSS"
    assert algorithm["algorithm_oid"] == "1.2.840.113549.1.1.1"
    assert algorithm["pqc_alternatives"] == ["ML-DSA"]
    assert protocol["cipher_suites"] == ["TLS_AES_256_GCM_SHA384"]
    assert "password" not in str(protocol["protocol_configuration"])
    assert key["private_material_present"] is True
    assert "private material" not in str(key)
    assert certificate["certificate_serial_number"] == "serial-1"
    assert certificate["certificate_public_key_size"] == 2048
    assert service["crypto_service_type"] == "vault"
    assert rng["rng_type"] == "hardware"


def test_live_cbom_keeps_non_algorithm_assets_distinct_and_does_not_invent_unknown():
    cbom = LiveCbom()
    cbom.materialize(UniversalVendorEvent(
        vendor="Cisco", product="IOS-XE", asset_id="router-1",
        event_type=EventType.CONFIG_CHANGED,
        vendor_metadata={"availability": "UNAVAILABLE"},
    ))
    cbom.materialize(UniversalVendorEvent(
        vendor="Cisco", product="IOS-XE", asset_id="router-1",
        event_type=EventType.CRYPTO_CHANGED,
        vendor_metadata={"observation": {
            "crypto_type": "protocol", "protocol": "TLS", "protocol_version": "1.3",
        }},
    ))
    cbom.materialize(UniversalVendorEvent(
        vendor="Cisco", product="IOS-XE", asset_id="router-1",
        event_type=EventType.KEY_CHANGED,
        vendor_metadata={"observation": {
            "crypto_type": "key", "key_id": "hsm-key-1", "key_role": "signing",
        }},
    ))
    components = cbom.components()
    assert len(components) == 2
    assert {item["cryptoProperties"]["assetType"] for item in components} == {"protocol", "key"}
    assert not any(item["bom-ref"].endswith(":unknown") for item in components)


def test_realtime_cbom_retains_algorithm_protocol_certificate_and_migration_data():
    observation = {
        "crypto_type": "algorithm",
        "algorithm_type": "symmetric",
        "algorithm_mode": "GCM",
        "padding_scheme": "OAEP",
        "algorithm_oid": "1.2.840.113549.1.1.1",
        "quantum_safe_status": "CLASSICAL",
        "protocol": "TLS",
        "protocol_version": "1.3",
        "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
        "protocol_configuration": {"forward_secrecy": True},
        "library": "OpenSSL",
        "library_version": "3.0.14",
        "library_dependencies": [{"name": "libcrypto", "version": "3.0.14"}],
        "fips_certification": "140-3- validation-reference",
        "key_type": "RSA",
        "key_size": 2048,
        "key_role": "signing",
        "key_storage_location": "hsm://partition/key-ref",
        "key_lifecycle_state": "active",
        "certificate": {
            "serial_number": "serial-1",
            "issuer": "Example Root CA",
            "subject": "CN=router.example",
            "not_after": "2030-01-01T00:00:00Z",
            "signature_algorithm": "sha256WithRSAEncryption",
        },
        "certificate_chain": [{"serial_number": "serial-root"}],
        "rng_name": "hwrng",
        "forward_secrecy": True,
        "side_channel_resistance": "vendor-declared",
        "related_vulnerabilities": [{"id": "CVE-2024-0001", "severity": "HIGH"}],
        "compliance": ["FIPS", "PCI-DSS"],
        "quantum_vulnerability": "HIGH",
        "migration_priority": "HIGH",
        "pqc_alternatives": ["ML-KEM", "ML-DSA"],
        "migration_status": "planned",
    }
    cbom = LiveCbom()
    cbom.materialize(UniversalVendorEvent(
        vendor="Cisco", product="IOS-XE", asset_id="router-1",
        event_type=EventType.CRYPTO_CHANGED,
        evidence_reference="sha256:evidence",
        vendor_metadata={
            "algorithm": "AES-256-GCM",
            "algorithms": ["AES-256-GCM"],
            "observation": observation,
        },
    ))

    component = cbom.components()[0]
    props = {item["name"]: item["value"] for item in component["properties"]}
    assert component["cryptoProperties"]["oid"] == "1.2.840.113549.1.1.1"
    assert component["cryptoProperties"]["algorithmProperties"]["mode"] == "GCM"
    assert props["cryptoscan:protocol"] == "TLS"
    assert props["cryptoscan:library"] == "OpenSSL"
    assert props["cryptoscan:key_size"] == "2048"
    assert "serial-1" in props["cryptoscan:certificate"]
    assert props["cryptoscan:migration_priority"] == "HIGH"
    assert "CVE-2024-0001" in props["cryptoscan:related_vulnerabilities"]

    document = cbom.generate_document(name="realtime-cbom")
    rendered = document["components"][0]
    assert rendered["cryptoProperties"]["cipherSuites"] == ["TLS_AES_256_GCM_SHA384"]
    assert "cryptoscan:certificate" in {
        item["name"] for item in rendered["properties"]
    }
