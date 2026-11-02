"""H7: hardware drift beside everything else that moved.

The value here is not a new drift event — it is answering "the HSM gained ML-DSA
at 09:14, did anything start using it?" without a human reading three dashboards.
The risk is the opposite claim, that co-occurrence proves causation, so the
tests check the disclaimer as carefully as the finding.
"""

from __future__ import annotations

import pytest

from universal_vendor.hardware.change_correlation import (
    COMPANION_DOMAINS,
    ChangeRecord,
    ChangeRecordRejected,
    correlate_changes,
    migration_readiness,
    record_from_change,
)
from universal_vendor.hardware.drift import diff


def hardware_change(**overrides):
    record = {
        "asset_id": "HSM-01",
        "event_type": "PQC_CAPABILITY_ADDED",
        "change_class": "CAPABILITY_CHANGE",
        "detail": {"algorithms": ["ML-DSA-65"]},
        "severity": "MEDIUM",
        "pqc_affected": True,
        "evidence": ["EV-1", "EV-2"],
        "detected_at": "2026-11-02T09:14:00+00:00",
    }
    record.update(overrides)
    return record


def record(domain, subject, event_type, at, **detail):
    return ChangeRecord(domain=domain, subject=subject, event_type=event_type, at=at,
                        detail=detail)


# --------------------------------------------------------------------------- #
# records
# --------------------------------------------------------------------------- #

def test_a_change_record_needs_a_known_domain_a_subject_and_a_time():
    with pytest.raises(ChangeRecordRejected):
        ChangeRecord(domain="NETWORK", subject="lb-01", event_type="X",
                     at="2026-11-02T09:14:00+00:00")
    with pytest.raises(ChangeRecordRejected):
        ChangeRecord(domain="HARDWARE", subject="  ", event_type="X",
                     at="2026-11-02T09:14:00+00:00")
    with pytest.raises(ChangeRecordRejected):
        ChangeRecord(domain="HARDWARE", subject="HSM-01", event_type="X", at="last tuesday")


def test_a_drift_change_becomes_a_record_with_its_evidence():
    changes = diff(
        {"asset_id": "HSM-01", "device_type": "hsm", "firmware": {"HSM": "8.2.1"},
         "supported_algorithms": ["RSA-2048"], "evidence_history": ["EV-1"]},
        {"asset_id": "HSM-01", "device_type": "hsm", "firmware": {"HSM": "8.4.0"},
         "supported_algorithms": ["RSA-2048", "ML-DSA-65"],
         "evidence_history": ["EV-1", "EV-2"]})
    records = [record_from_change(change) for change in changes]
    pqc = [item for item in records if item.event_type == "PQC_CAPABILITY_ADDED"]
    assert len(pqc) == 1
    assert pqc[0].subject == "HSM-01"
    assert pqc[0].domain == "HARDWARE"
    assert pqc[0].evidence == "EV-1,EV-2"


# --------------------------------------------------------------------------- #
# correlation
# --------------------------------------------------------------------------- #

def test_a_migration_window_is_correlated():
    report = correlate_changes([hardware_change()], [
        record("APPLICATION", "HSM-01", "TLS_PROFILE_CHANGED", "2026-11-02T09:16:00+00:00"),
        record("CERTIFICATE", "HSM-01", "CERTIFICATE_REISSUED", "2026-11-02T09:20:00+00:00"),
    ])
    result = report["results"][0]
    assert result["verdict"] == "CORRELATED"
    assert result["companion_domains"] == ["APPLICATION", "CERTIFICATE"]
    assert result["missing_domains"] == []
    assert len(result["companions"]) == 2


def test_a_pqc_capability_with_nothing_beside_it_is_unaccompanied():
    report = correlate_changes([hardware_change()], [])
    result = report["results"][0]
    assert result["verdict"] == "UNACCOMPANIED"
    assert result["missing_domains"] == ["APPLICATION", "CERTIFICATE"]
    assert report["by_verdict"] == {"UNACCOMPANIED": 1}


def test_a_firmware_bump_needs_no_companions():
    """A switch's firmware moving is not a migration and must not be marked down."""
    report = correlate_changes([hardware_change(event_type="FIRMWARE_CHANGED")], [])
    assert report["results"][0]["verdict"] == "ISOLATED"
    assert report["results"][0]["missing_domains"] == []
    assert COMPANION_DOMAINS["FIRMWARE_CHANGED"] == ()


def test_a_companion_outside_the_window_is_not_a_companion():
    report = correlate_changes([hardware_change()], [
        record("APPLICATION", "HSM-01", "TLS_PROFILE_CHANGED", "2026-11-02T15:00:00+00:00"),
    ], window_minutes=60)
    assert report["results"][0]["companions"] == []


def test_a_companion_about_a_different_subject_is_not_a_companion():
    report = correlate_changes([hardware_change()], [
        record("APPLICATION", "payments-api", "TLS_PROFILE_CHANGED",
               "2026-11-02T09:15:00+00:00"),
    ])
    assert report["results"][0]["companions"] == []


def test_an_alias_lets_a_system_name_match_the_estate_name():
    report = correlate_changes([hardware_change(asset_id="lb-01")], [
        record("CERTIFICATE", "lb-01.bank.example", "CERTIFICATE_REISSUED",
               "2026-11-02T09:20:00+00:00"),
    ], asset_aliases={"lb-01.bank.example": "lb-01"})
    assert report["results"][0]["companions"], "without the alias this pair is missed"
    # The certificate moved but no application did, so the migration is partial:
    # a different answer from "nothing moved at all".
    assert report["results"][0]["verdict"] == "PARTIAL"


def test_a_crypto_change_without_hardware_movement_is_suspicious():
    report = correlate_changes([hardware_change(event_type="FIRMWARE_CHANGED")], [
        record("CERTIFICATE", "HSM-01", "CERTIFICATE_REISSUED",
               "2026-11-02T09:20:00+00:00"),
    ])
    result = report["results"][0]
    assert result["verdict"] == "SUSPICIOUS"
    assert "where the key now lives" in result["suspicious"][0]
    assert report["suspicious"][0]["verdict"] == "SUSPICIOUS"


def test_the_report_says_what_it_cannot_prove():
    report = correlate_changes([hardware_change()], [])
    assert any("not causation" in limit for limit in report["limits"])
    assert any("alias" in limit for limit in report["limits"])


def test_the_counts_are_honest_about_how_much_was_compared():
    report = correlate_changes([hardware_change(), hardware_change(asset_id="HSM-02")], [
        record("APPLICATION", "HSM-01", "TLS_PROFILE_CHANGED", "2026-11-02T09:16:00+00:00"),
    ])
    assert report["hardware_changes"] == 2
    assert report["other_changes"] == 1
    assert report["by_verdict"] == {"PARTIAL": 1, "UNACCOMPANIED": 1}


def test_a_non_positive_window_is_refused():
    with pytest.raises(ValueError):
        correlate_changes([hardware_change()], window_minutes=0)


def test_mapping_records_are_accepted_directly():
    report = correlate_changes([hardware_change()], [
        {"domain": "POLICY", "subject": "HSM-01", "event_type": "ALGORITHM_POLICY_CHANGED",
         "at": "2026-11-02T09:30:00+00:00"},
    ])
    assert report["results"][0]["companion_domains"] == ["POLICY"]


# --------------------------------------------------------------------------- #
# the PQC question
# --------------------------------------------------------------------------- #

def test_a_half_finished_migration_is_partial_not_unaccompanied():
    """The TLS profile moved; the certificate was not reissued."""
    report = correlate_changes([hardware_change()], [
        record("APPLICATION", "HSM-01", "TLS_PROFILE_CHANGED", "2026-11-02T09:16:00+00:00"),
    ])
    result = report["results"][0]
    assert result["verdict"] == "PARTIAL"
    assert result["missing_domains"] == ["CERTIFICATE"]
    assert report["partial"][0]["verdict"] == "PARTIAL"


def test_a_capability_nobody_has_adopted_says_so():
    readiness = migration_readiness([hardware_change()], [])
    assert readiness["capabilities_gained"] == 1
    assert readiness["adoption_observed"] is False
    assert "not a completed one" in readiness["statement"]
    assert readiness["devices"] == ["HSM-01"]


def test_a_capability_with_movement_beside_it_is_an_observed_migration():
    readiness = migration_readiness([hardware_change()], [
        record("APPLICATION", "HSM-01", "SSL_PROFILE_SWITCHED", "2026-11-02T09:30:00+00:00"),
    ])
    assert readiness["adoption_observed"] is True
    assert "something else moved with it" in readiness["statement"]


def test_no_capability_in_the_window_is_said_plainly():
    readiness = migration_readiness([hardware_change(event_type="FIRMWARE_CHANGED")], [])
    assert readiness["capabilities_gained"] == 0
    assert "no post-quantum capability arrived" in readiness["statement"]
