"""H7 wired: drift and correlation reach the live pipeline as events.

The unit modules were already tested; this checks the seam nobody had run — a
real :class:`LiveHardwareController` emitting events produced from a drift diff,
and the correlation verdict appearing in the same response.
"""

from __future__ import annotations

import pytest

from universal_vendor.hardware.live.change_feed import (
    EVENT_TYPE_MAP,
    HardwareChangeFeed,
    ingest_changes,
    to_hardware_event,
)
from universal_vendor.hardware.live.controller import LiveHardwareController
from universal_vendor.hardware.live.events import HardwareEventType

BEFORE = {
    "asset_id": "HSM-01", "device_type": "hsm", "firmware": {"HSM": "8.2.1"},
    "supported_algorithms": ["RSA-2048"], "evidence_history": ["EV-1"],
}
AFTER = {
    "asset_id": "HSM-01", "device_type": "hsm", "firmware": {"HSM": "8.4.0"},
    "supported_algorithms": ["RSA-2048", "ML-DSA-65"],
    "evidence_history": ["EV-1", "EV-2"],
}


def emitted_types(result):
    return [event.event_type.value for event in result.events]


# --------------------------------------------------------------------------- #
# mapping
# --------------------------------------------------------------------------- #

def test_every_drift_row_becomes_a_canonical_event():
    feed = HardwareChangeFeed()
    result = feed.from_diff(BEFORE, AFTER)
    assert emitted_types(result) == [
        "FIRMWARE_CHANGED", "CRYPTO_CAPABILITY_CHANGED", "CRYPTO_CAPABILITY_CHANGED",
        "HSM_CAPABILITY_CHANGED"]
    assert result.unmapped == [], "every drift row in this diff has a canonical type"


def test_a_pqc_row_rides_the_crypto_event_with_its_flag():
    """The taxonomy has no PQC type; the payload must still say it was PQC."""
    event = to_hardware_event({
        "asset_id": "HSM-01", "event_type": "PQC_CAPABILITY_ADDED",
        "change_class": "CAPABILITY_CHANGE", "severity": "MEDIUM",
        "pqc_affected": True, "detail": {"algorithms": ["ML-DSA-65"]},
        "detected_at": "2026-11-02T09:14:00+00:00"})
    assert event.event_type is HardwareEventType.CRYPTO_CAPABILITY_CHANGED
    assert event.payload["pqc"] is True
    assert event.payload["pqc_algorithms"] == ["ML-DSA-65"]
    assert event.payload["drift_event_type"] == "PQC_CAPABILITY_ADDED"


def test_a_firmware_event_carries_the_component_and_the_new_version():
    event = to_hardware_event({
        "asset_id": "HSM-01", "event_type": "FIRMWARE_CHANGED",
        "detail": {"components": {"HSM": {"before": "8.2.1", "after": "8.4.0"}}},
        "detected_at": "2026-11-02T09:14:00+00:00"})
    assert event.component == "HSM"
    assert event.version == "8.4.0"


def test_an_unmapped_drift_row_is_reported_not_dropped():
    feed = HardwareChangeFeed()
    result = feed.from_diff(BEFORE, {**AFTER, "model": "HSM-X900"})
    assert "HARDWARE_CHANGED" in emitted_types(result)
    assert EVENT_TYPE_MAP["FIRMWARE_CHANGED"] == "FIRMWARE_CHANGED"


def test_differing_assets_are_still_refused_at_the_feed():
    with pytest.raises(ValueError):
        HardwareChangeFeed().from_diff(BEFORE, {**AFTER, "asset_id": "HSM-02"})


# --------------------------------------------------------------------------- #
# correlation from the feed
# --------------------------------------------------------------------------- #

def test_a_feed_fills_its_own_window():
    feed = HardwareChangeFeed()
    result = feed.from_diff(BEFORE, AFTER)
    stamp = result.changes[0]["detected_at"]
    feed.record_change("APPLICATION", "HSM-01", "TLS_PROFILE_CHANGED", stamp)
    feed.record_change("CERTIFICATE", "HSM-01", "CERTIFICATE_REISSUED", stamp)
    findings = feed.findings_for("HSM-01")
    assert "CORRELATED" in findings["verdicts"]
    # The firmware row next to a certificate reissue and no capability movement
    # is the suspicious shape, so it is flagged — that is the module working.
    # The capability rows are *not* flagged: their capability did move.
    flagged = {row["change"]["event_type"] for row in findings["needs_attention"]}
    assert flagged == {"FIRMWARE_CHANGED"}


def test_an_unaccompanied_change_is_flagged_for_attention():
    feed = HardwareChangeFeed()
    feed.from_diff(BEFORE, AFTER)
    findings = feed.findings_for("HSM-01")
    assert "UNACCOMPANIED" in findings["verdicts"]
    assert findings["needs_attention"], "an unaccompanied capability change needs a human"


def test_aliases_are_used_by_the_feed():
    feed = HardwareChangeFeed()
    result = feed.from_diff(BEFORE, AFTER)
    feed.alias("hsm-01.bank.example", "HSM-01")
    feed.record_change("APPLICATION", "hsm-01.bank.example", "TLS_PROFILE_CHANGED",
                       result.changes[0]["detected_at"])
    assert "PARTIAL" in feed.findings_for("HSM-01")["verdicts"]


def test_counts_are_available_for_the_report():
    feed = HardwareChangeFeed()
    feed.from_diff(BEFORE, AFTER)
    feed.record_change("POLICY", "HSM-01", "ALGORITHM_POLICY_CHANGED",
                       "2026-11-02T09:30:00+00:00")
    assert feed.counts() == {"hardware_changes": 4, "other_changes": 1, "aliases": 0}


def test_pqc_readiness_is_reachable_from_the_feed():
    feed = HardwareChangeFeed()
    feed.from_diff(BEFORE, AFTER)
    readiness = feed.pqc_readiness()
    assert readiness["capabilities_gained"] == 1
    assert readiness["adoption_observed"] is False


# --------------------------------------------------------------------------- #
# the live controller
# --------------------------------------------------------------------------- #

def test_a_real_controller_ingests_feed_events_and_versions_the_hbom():
    controller = LiveHardwareController(change_feed=HardwareChangeFeed())
    outcome = ingest_changes(controller, controller.change_feed, BEFORE, AFTER)

    assert len(outcome["ingested"]) == 4
    assert controller.event_count() == 4
    for item in outcome["ingested"]:
        assert item["state_verdict"] in {"NEW", "CHANGED", "REMOVED", "UNCHANGED"}
        assert item["evidence_id"], "every ingested change is chained to an evidence row"
        assert item["chain_hash"]
        assert item["envelope"]["asset_id"] == "HSM-01"
    assert "UNACCOMPANIED" in outcome["findings"]["verdicts"]


def test_the_ingest_response_carries_its_own_correlation_finding():
    """The SOC reads one response, not two dashboards."""
    controller = LiveHardwareController(change_feed=HardwareChangeFeed())
    response = controller.ingest({
        "event_type": "CRYPTO_CAPABILITY_CHANGED", "asset_id": "HSM-01",
        "device_type": "hsm", "source": "local_os",
        "payload": {"pqc": True, "detail": {"added": ["ML-DSA-65"]},
                    "evidence": ["EV-9"]},
    })
    findings = response["change_correlation"]
    assert findings is not None
    assert findings["asset_id"] == "HSM-01"
    assert findings["verdicts"], "an ingested capability change must produce a verdict"


def test_a_non_crypto_event_does_not_pollute_the_window():
    feed = HardwareChangeFeed()
    controller = LiveHardwareController(change_feed=feed)
    controller.ingest({"event_type": "NIC_CHANGED", "asset_id": "srv-01",
                       "device_type": "server", "source": "agent"})
    assert feed.counts()["hardware_changes"] == 0
    assert controller.correlation_report()["hardware_changes"] == 0


def test_the_controller_reports_nothing_when_no_feed_is_wired():
    controller = LiveHardwareController()
    assert controller.correlation_report() is None
    assert controller.pqc_migration_readiness() is None
    response = controller.ingest({"event_type": "CRYPTO_CAPABILITY_CHANGED",
                                  "asset_id": "HSM-01", "source": "local_os"})
    assert response["change_correlation"] is None


def test_the_controller_correlation_report_is_the_feed_report():
    feed = HardwareChangeFeed()
    controller = LiveHardwareController(change_feed=feed)
    controller.ingest({"event_type": "CRYPTO_CAPABILITY_CHANGED", "asset_id": "HSM-01",
                       "device_type": "hsm", "source": "local_os",
                       "payload": {"pqc": True}})
    report = controller.correlation_report(window_minutes=30)
    assert report["schema"] == "cryptoscan.hardware-change-correlation/1"
    assert report["hardware_changes"] == 1
    assert report["window_minutes"] == 30
    assert any("not causation" in limit for limit in report["limits"])


def test_a_correlation_finding_does_not_mint_a_dependency():
    """Proximity is not an edge: the relationship engine is unchanged by this."""
    from universal_vendor.hardware.relationships import blast_radius

    feed = HardwareChangeFeed()
    controller = LiveHardwareController(change_feed=feed)
    ingest_changes(controller, feed, BEFORE, AFTER)
    change_row = next(row for row in feed.correlation()["results"]
                      if row["change"]["event_type"] == "PQC_CAPABILITY_ADDED")
    feed.record_change("APPLICATION", "HSM-01", "TLS_PROFILE_CHANGED",
                       change_row["change"]["at"])
    pqc_row = next(row for row in feed.correlation()["results"]
                   if row["change"]["event_type"] == "PQC_CAPABILITY_ADDED")
    assert pqc_row["verdict"] == "PARTIAL", "the application moved, the certificate did not"
    assert blast_radius("HSM-01", [])["applications_affected"] == 0
