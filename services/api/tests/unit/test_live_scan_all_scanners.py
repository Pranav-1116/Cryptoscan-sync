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


def test_run_request_rejects_an_unknown_scanner_family():
    """A typo is a client error, not a scanner that silently found nothing.

    The runner tolerates an unknown family by recording UNAVAILABLE, so
    ``{"scanners": ["netwrok"]}`` used to answer 202 and cycle nothing the
    operator asked for. The registry in the runner is the single source of
    truth and the request model refuses anything outside it.
    """
    import pytest
    from pydantic import ValidationError

    from api.routers.live_scan import RunScanRequest

    assert RunScanRequest(scanners=["hardware", "network"]).scanners == ["hardware", "network"]
    # duplicates collapse rather than running a family twice
    assert RunScanRequest(scanners=["hardware", "hardware"]).scanners == ["hardware"]
    with pytest.raises(ValidationError) as excinfo:
        RunScanRequest(scanners=["bogus_scanner"])
    assert "unknown scanner family: bogus_scanner" in str(excinfo.value)
    assert "hardware" in str(excinfo.value)  # the refusal lists the known families
