"""Universal vendor scanner mode tests (spec §24)."""

from __future__ import annotations

import pytest

from universal_vendor.models import ScanMode
from universal_vendor.scan_modes import UniversalVendorScanner


def _scanner(registry):
    return UniversalVendorScanner(registry=registry)


def test_auto_detect_flow(registry, cisco_context):
    report = _scanner(registry).run(cisco_context, scan_id="s1",
                                    mode=ScanMode.AUTO_DETECT)
    assert report.plugin_id == "cisco_ios_xe"
    assert report.detection["detected_vendor"] == "Cisco"
    assert "detect" in report.stages_run
    assert "collect" in report.stages_run
    assert "evidence" in report.stages_run
    assert report.observations
    assert report.evidence_verification["chain_intact"] is True


def test_auto_detect_no_match(registry):
    report = _scanner(registry).run({"banner": "completely unknown thing"},
                                    scan_id="s2")
    assert report.plugin_id is None
    assert "no-plugin-matched" in report.stages_run
    assert report.observations == []


def test_explicit_plugin_id_requires_registered(registry, panos_context):
    report = _scanner(registry).run(panos_context, scan_id="s3",
                                    plugin_id="paloalto_panos",
                                    mode=ScanMode.DEEP_DISCOVERY)
    assert report.plugin_id == "paloalto_panos"
    assert report.observations
    assert "readiness" in report.stages_run


def test_crypto_discovery_mode(registry, cisco_context):
    report = _scanner(registry).run(cisco_context, scan_id="s4",
                                    plugin_id="cisco_ios_xe",
                                    mode=ScanMode.CRYPTO_DISCOVERY)
    assert "crypto" in report.stages_run
    assert "certificates" in report.stages_run
    assert "inventory" not in report.stages_run
    assert report.observations


def test_inventory_only_mode(registry, cisco_context):
    report = _scanner(registry).run(cisco_context, scan_id="s5",
                                    plugin_id="cisco_ios_xe",
                                    mode=ScanMode.INVENTORY_ONLY)
    assert "inventory" in report.stages_run
    assert "crypto" not in report.stages_run


def test_configuration_discovery_mode(registry, cisco_context):
    report = _scanner(registry).run(cisco_context, scan_id="s6",
                                    plugin_id="cisco_ios_xe",
                                    mode=ScanMode.CONFIGURATION_DISCOVERY)
    assert "configuration" in report.stages_run
    assert "crypto" not in report.stages_run


def test_continuous_monitoring_includes_readiness_lifecycle(registry, cisco_context):
    report = _scanner(registry).run(cisco_context, scan_id="s7",
                                    plugin_id="cisco_ios_xe",
                                    mode=ScanMode.CONTINUOUS_MONITORING)
    assert "readiness" in report.stages_run
    assert "lifecycle" in report.stages_run
    assert report.pqc, "readiness verdicts expected"
    assert report.lifecycle, "lifecycle verdicts expected"
    # Cisco is unverified -> honest UNKNOWN (never inferred from name)
    assert all(row["pqc_capability"] == "UNKNOWN" for row in report.pqc)


def test_continuous_monitoring_pqc_unknown_invariant(registry, cisco_context):
    report = _scanner(registry).run(cisco_context, scan_id="s8",
                                    plugin_id="cisco_ios_xe",
                                    mode=ScanMode.CONTINUOUS_MONITORING)
    for row in report.pqc:
        if row["pqc_capability"] == "UNKNOWN":
            assert row["reason"]
        else:
            assert row["evidence_source"]


def test_unknown_mode_rejected(registry, cisco_context):
    with pytest.raises(ValueError):
        _scanner(registry).run(cisco_context, scan_id="s9",
                               plugin_id="cisco_ios_xe", mode="NOT_A_MODE")


def test_validation_failure_returns_empty(registry):
    report = _scanner(registry).run(
        {"config": "this is not cisco config at all"}, scan_id="s10",
        plugin_id="cisco_ios_xe", mode=ScanMode.DEEP_DISCOVERY,
    )
    assert report.observations == []


def test_report_to_dict_roundtrip(registry, cisco_context):
    report = _scanner(registry).run(cisco_context, scan_id="s11",
                                    mode=ScanMode.AUTO_DETECT)
    data = report.to_dict()
    assert data["scan_id"] == "s11"
    assert data["evidence_verification"]["chain_intact"] is True
    assert data["observations"]
