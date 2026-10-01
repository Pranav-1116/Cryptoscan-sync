"""Contract tests for the common realtime crypto projection.

These tests deliberately exercise scanner-shaped payloads rather than vendor
output. A generic resource/finding must not become a CBOM algorithm.
"""

from api.live_scan.runner import LIVE_SCANNER_FAMILIES, LiveScanRunner


def test_all_crypto_scanner_families_are_registered():
    assert {
        "universal", "source", "runtime", "hardware", "network", "cloud",
        "container", "ot", "telecom", "payment", "keyassure", "binary",
        "devsecops", "vendor",
    } <= set(LIVE_SCANNER_FAMILIES)


def test_explicit_crypto_records_from_every_family_keep_provenance():
    payloads = {
        family: {"findings": [{"algorithm": f"ALG-{family}",
                               "evidence_reference": f"evidence:{family}"}]}
        for family in LIVE_SCANNER_FAMILIES
    }
    for family, payload in payloads.items():
        components = LiveScanRunner._scanner_cbom_components(family, payload)
        assert components
        assert components[0]["source"] == family
        assert components[0]["evidence_reference"] == f"evidence:{family}"


def test_generic_assets_do_not_become_cbom_algorithms():
    components = LiveScanRunner._scanner_cbom_components(
        "cloud",
        {"resources": [{"name": "payment-bucket", "resource_id": "bucket-1"}],
         "findings": [{"message": "encryption posture unavailable"}]},
    )
    assert components == []


def test_unconfigured_is_not_a_failed_or_empty_success():
    state = LiveScanRunner._scanner_availability({}, only=["payment"])["payment"]
    assert state["status"] == "UNCONFIGURED"
    assert state["reason"]
