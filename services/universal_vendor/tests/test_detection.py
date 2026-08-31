"""Multi-signal detection engine tests (spec §16)."""

from __future__ import annotations

from universal_vendor.detection import UniversalVendorDetectionEngine


def test_single_weak_signal_has_low_confidence():
    engine = UniversalVendorDetectionEngine()
    result = engine.detect({"banner": "foo bar baz"})
    assert not result.detected
    assert result.confidence == 0.0


def test_cisco_network_banner():
    engine = UniversalVendorDetectionEngine()
    result = engine.detect({"banner": "Cisco IOS-XE Software, Version 17.9.4a"})
    assert result.detected
    assert result.detected_vendor == "Cisco"
    assert result.detected_product in ("IOS-XE", "IOS")
    assert result.detection_method == "multi-signal"
    assert result.signals, "must record the signals used"


def test_multiple_signals_aggregate_confidence():
    engine = UniversalVendorDetectionEngine()
    single = engine.detect({"banner": "Palo Alto Networks PAN-OS"})
    multi = engine.detect({
        "banner": "Palo Alto Networks PAN-OS",
        "config": "set network profiles tls-profile tls web-server",
        "http_headers": {"server": "PAN-OS"},
    })
    assert multi.confidence >= single.confidence


def test_never_single_signal_only():
    """A single match must still go through the multi-signal aggregator and
    record signals; detection never depends on one unrecorded source."""
    engine = UniversalVendorDetectionEngine()
    result = engine.detect({"server_header": "nginx/1.24.0"})
    assert result.detected
    assert result.signals
    assert len(result.signals) >= 1


def test_tls_certificate_signal():
    engine = UniversalVendorDetectionEngine()
    result = engine.detect({
        "tls_certificate": {
            "subject": "CN=*.example.com",
            "issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1",
        },
    })
    assert result.detected
    assert result.detected_vendor == "DigiCert"


def test_cloud_metadata_signal():
    engine = UniversalVendorDetectionEngine()
    result = engine.detect({
        "cloud_metadata": "aws kms acm pca account-1234",
        "config": "kms",
    })
    assert result.detected
    assert result.detected_vendor == "AWS"


def test_kubernetes_kubeconfig_signal():
    engine = UniversalVendorDetectionEngine()
    result = engine.detect({"kubeconfig": "apiVersion: v1  clusters: eks-cluster"})
    assert result.detected
    assert result.detected_vendor in ("AWS", "Kubernetes")


def test_version_extraction():
    engine = UniversalVendorDetectionEngine()
    result = engine.detect({"banner": "FortiOS 7.4.1 build1234", "version": "7.4.1"})
    assert result.detected_version == "7.4.1"


def test_oidc_document_signal():
    engine = UniversalVendorDetectionEngine()
    result = engine.detect({
        "oidc_document": '{"issuer":"https://login.microsoftonline.com/...",'
                         '"id_token_signing_alg_values_supported":["RS256"]}',
    })
    assert result.detected
    assert result.detected_vendor == "Microsoft"
