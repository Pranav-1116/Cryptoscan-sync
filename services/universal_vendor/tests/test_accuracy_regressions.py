"""Regression coverage for vendor-scanning accuracy and provenance."""

from __future__ import annotations

from universal_vendor.detection import UniversalVendorDetectionEngine
from universal_vendor.evidence import build_evidence_chain, verify_evidence_chain
from universal_vendor.graph import build_graph
from universal_vendor.models import ScanMode, UniversalObservation
from universal_vendor.plugins._helpers import extract_algorithms
from universal_vendor.scan_modes import UniversalVendorScanner
from vendor_intel.docs_extract import extract_crypto_mentions
from vendor_intel.questionnaire import parse_questionnaire
from vendor_intel.sbom_import import import_vendor_cbom


def test_detection_rejects_generic_substrings_and_preserves_sources():
    engine = UniversalVendorDetectionEngine()
    assert not engine.detect({"banner": "redistributable package; awesome mode"}).detected

    result = engine.detect({
        "api_metadata": {"provider": "AWS", "service": "KMS"},
        "tls_certificate": {"issuer": "Example CA", "subject": "service.example"},
    })
    assert result.detected_vendor == "AWS"
    assert all("source" in signal for signal in result.signals)
    assert any(signal["source"].startswith("api_metadata") for signal in result.signals)


def test_detection_structured_metadata_is_order_independent():
    engine = UniversalVendorDetectionEngine()
    left = engine.detect({"api_metadata": {"vendor": "GitHub", "product": "GitHub"}})
    right = engine.detect({"api_metadata": {"product": "GitHub", "vendor": "GitHub"}})
    assert left.model_dump(mode="json") == right.model_dump(mode="json")


def test_algorithm_extraction_is_structured_boundary_safe_and_canonical_ordered():
    metadata = {
        "cipher": "aes-gcm",
        "details": ["TLSv1.3", "RSA-2048"],
        "note": "notAES and CHACHA20-POLY1305X are not evidence",
    }
    found = extract_algorithms(
        metadata,
        known=("AES", "AES-GCM", "TLSv1.3", "RSA-2048", "CHACHA20"),
    )
    assert found == ["AES-GCM", "TLS 1.3", "RSA-2048"]


def test_deep_scan_retains_dependency_edges_and_attribution(registry):
    context = {
        "api_metadata": {
            "dependencies": [{
                "repo": "org/app", "library": "openssl", "version": "3.0",
                "algorithm": "AES-256-GCM",
            }],
        },
    }
    report = UniversalVendorScanner(registry=registry).run(
        context, scan_id="dependency-scan", plugin_id="github",
        mode=ScanMode.DEEP_DISCOVERY,
    )
    assert report.graph["edges"] == [{
        "source": "org/app", "target": "openssl", "relationship": "USES_LIBRARY",
        "detail": {},
    }]
    source = next(node for node in report.graph["nodes"] if node["id"] == "org/app")
    assert source["vendor"] == "GitHub"
    assert source["product"] == "GitHub"
    assert all(obs.asset_id != "openssl" for obs in report.observations)
    assert all(obs.evidence["source"] for obs in report.observations)
    assert all(obs.evidence["field"] for obs in report.observations)


def test_evidence_is_reproducible_and_rejects_cross_scan_records():
    observations = [{"vendor": "Cisco", "product": "IOS-XE", "algorithm": "AES"}]
    first = build_evidence_chain(observations, scan_id="stable")
    second = build_evidence_chain(observations, scan_id="stable")
    assert first == second
    assert verify_evidence_chain(first, scan_id="other")["valid"] is False


def test_vendor_intel_preserves_self_report_uncertainty_and_aliases():
    report = parse_questionnaire({"transit": "tlsv1.3", "rest": "proprietary encryption"})
    assert report["inventory"][0]["algorithm"] == "TLS 1.3"
    assert report["inventory"][0]["observed_usage"] is False
    assert report["inventory"][0]["visibility"] == "self_reported"
    assert report["inventory"][1]["algorithm"] is None
    assert report["inventory"][1]["algorithm_raw"] == "proprietary encryption"


def test_sbom_does_not_invent_algorithm_from_generic_component_name():
    items = import_vendor_cbom({
        "components": [{
            "type": "cryptographic-asset",
            "name": "not-aes-256-service",
            "cryptoProperties": {"algorithmProperties": {}},
        }],
    })
    assert items[0]["algorithm"] is None
    assert items[0]["algorithm_raw"] == "not-aes-256-service"
    assert items[0]["confidence"] == "MEDIUM"


def test_public_documentation_algorithms_are_low_confidence_and_normalized():
    result = extract_crypto_mentions("The service supports TLSv1.3 and AES-256.")
    assert {row["algorithm"] for row in result["inventory"]} == {"TLS 1.3", "AES-256"}
    assert all(row["confidence"] == "LOW" for row in result["inventory"])
