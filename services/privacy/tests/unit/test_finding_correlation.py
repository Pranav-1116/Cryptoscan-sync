"""Finding deduplication + correlation tests (spec #21, #22)."""

from __future__ import annotations

from privacy.correlation import (
    build_chain,
    correlate_findings,
    finding_fingerprint,
)


def test_five_scanners_same_issue_merge_to_one():
    findings = [
        {"category": "weak_tls", "asset_id": "asset-42", "severity": "high",
         "title": "TLS 1.0", "source": "network"},
        {"category": "weak_tls", "asset_id": "asset-42", "severity": "high",
         "title": "TLS 1.0", "source": "application"},
        {"category": "weak_tls", "asset_id": "asset-42", "severity": "high",
         "title": "TLS 1.0", "source": "certificate"},
        {"category": "weak_tls", "asset_id": "asset-42", "severity": "high",
         "title": "TLS 1.0", "source": "cloud"},
        {"category": "weak_tls", "asset_id": "asset-42", "severity": "high",
         "title": "TLS 1.0", "source": "crypto"},
    ]
    merged = correlate_findings(findings)
    assert len(merged) == 1, merged
    assert merged[0]["sources"] == ["application", "certificate", "cloud", "crypto", "network"]
    assert len(merged[0]["evidence"]) == 5


def test_fingerprint_is_detector_agnostic():
    a = finding_fingerprint(category="weak_crypto", asset_id="asset-1",
                            algorithm="RSA", key_size=1024)
    b = finding_fingerprint(category="weak_crypto", asset_id="asset-1",
                            algorithm="RSA", key_size=1024)
    # same root cause regardless of scanner / detector
    assert a == b


def test_different_assets_do_not_merge():
    findings = [
        {"category": "weak_tls", "asset_id": "asset-1", "severity": "high", "source": "network"},
        {"category": "weak_tls", "asset_id": "asset-2", "severity": "high", "source": "network"},
    ]
    merged = correlate_findings(findings)
    assert len(merged) == 2


def test_severity_rises_with_corroboration():
    findings = [
        {"category": "weak_tls", "asset_id": "asset-1", "severity": "low", "source": "network"},
        {"category": "weak_tls", "asset_id": "asset-1", "severity": "critical", "source": "crypto"},
    ]
    merged = correlate_findings(findings)
    assert merged[0]["severity"] == "critical"


def test_build_chain_compound_critical():
    chain = build_chain("asset-42", [
        {"category": "weak_tls", "severity": "high", "title": "TLS1.0", "source": "network"},
        {"category": "internet_exposure", "severity": "medium", "title": "Exposed", "source": "cloud"},
    ], critical_asset=True, business_value="critical")
    assert chain["compound_risk"] is True
    assert chain["overall_severity"] == "critical"


def test_build_chain_no_compound_no_panic():
    chain = build_chain("asset-7", [
        {"category": "weak_tls", "severity": "high", "title": "TLS1.0", "source": "network"},
    ], critical_asset=False, business_value="low")
    assert chain["compound_risk"] is False
