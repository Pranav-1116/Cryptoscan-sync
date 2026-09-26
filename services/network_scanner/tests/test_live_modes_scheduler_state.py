"""Live layer — monitoring modes, priority scheduling, asset state, drift."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from network_scanner.enterprise.live.asset_state import (
    CRYPTO_FIELDS,
    AssetStateEngine,
    NETWORK_FIELDS,
)
from network_scanner.enterprise.live.drift import (
    CRITICAL_DRIFT_FIELDS,
    DriftDetector,
    classify_crypto_drift,
)
from network_scanner.enterprise.live.modes import (
    MODES,
    MONITORING_MODES,
    MonitoringPolicy,
    enabled_modes,
)
from network_scanner.enterprise.live.scheduler import (
    Scheduler,
    priority_score,
    tier_for_score,
)

T0 = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------- modes

def test_five_modes_present():
    assert MONITORING_MODES == (
        "REALTIME_EVENT", "PASSIVE", "PERIODIC_LIGHTWEIGHT",
        "SCHEDULED_DEEP", "CHANGE_TRIGGERED")


def test_every_mode_has_description():
    for name in MONITORING_MODES:
        assert MODES[name].description
        assert MODES[name].enabled is True


def test_enabled_modes_override():
    assert "PASSIVE" in enabled_modes()
    assert "PASSIVE" not in enabled_modes({"PASSIVE": False})
    assert enabled_modes({"PASSIVE": False}) == [
        "REALTIME_EVENT", "PERIODIC_LIGHTWEIGHT", "SCHEDULED_DEEP",
        "CHANGE_TRIGGERED"]


def test_monitoring_policy_defaults_configurable():
    policy = MonitoringPolicy()
    assert policy.interval_for("CRITICAL") == 60
    assert policy.interval_for("LOW") == 86400
    assert policy.deep_interval == 7 * 86400
    policy.set_interval("STANDARD", 7200)
    assert policy.interval_for("STANDARD") == 7200


def test_monitoring_policy_rejects_bad_tier():
    policy = MonitoringPolicy()
    with pytest.raises(ValueError):
        policy.set_interval("UNKNOWN", 60)
    with pytest.raises(ValueError):
        policy.set_interval("HIGH", 0)


def test_monitoring_mode_dict():
    mode = MODES["PASSIVE"]
    d = mode.to_dict()
    assert d["mode"] == "PASSIVE"
    assert d["enabled"] is True


# ---------------------------------------------------------------- scheduler

def test_priority_score_weights_components():
    score = priority_score({
        "business_criticality": 10.0,
        "internet_exposure": 10.0,
        "crypto_risk": 10.0,
        "change_frequency": 10.0,
        "compliance_importance": 10.0,
    })
    assert score == 10.0


def test_priority_score_defaults_missing_to_zero():
    assert priority_score({}) == 0.0
    assert priority_score() == 0.0
    assert 0.0 < priority_score({"business_criticality": 5.0}) < 5.0


def test_priority_score_custom_weights():
    score = priority_score({"business_criticality": 10.0},
                           weights={"business_criticality": 1.0,
                                    "crypto_risk": 1.0})
    assert score == 5.0


def test_priority_score_clamps():
    assert priority_score({"business_criticality": 99}) == priority_score(
        {"business_criticality": 10})
    assert priority_score({"business_criticality": -5}) == 0.0
    assert priority_score({"business_criticality": 99}) > priority_score(
        {"business_criticality": 8})


def test_tier_thresholds():
    assert tier_for_score(9.0) == "CRITICAL"
    assert tier_for_score(8.0) == "CRITICAL"
    assert tier_for_score(7.0) == "HIGH"
    assert tier_for_score(5.0) == "STANDARD"
    assert tier_for_score(3.0) == "LOW"
    assert tier_for_score(-1.0) == "LOW"


def test_scheduler_assigns_tier_and_priority():
    scheduler = Scheduler()
    item = scheduler.schedule("rtr-1", {
        "business_criticality": 10.0, "internet_exposure": 10.0,
        "crypto_risk": 10.0, "change_frequency": 10.0,
        "compliance_importance": 10.0,
    })
    assert item.tier == "CRITICAL"
    assert item.priority == 10.0


def test_lightweight_due_uses_policy_interval():
    scheduler = Scheduler()
    critical = {
        "business_criticality": 10.0, "internet_exposure": 10.0,
        "crypto_risk": 10.0, "compliance_importance": 10.0,
    }
    item = scheduler.schedule("a", critical, last_scanned=T0)
    assert item.tier == "CRITICAL"
    assert scheduler.lightweight_due(item, now=T0 + timedelta(seconds=59)) is False
    assert scheduler.lightweight_due(item, now=T0 + timedelta(seconds=61)) is True
    never = scheduler.schedule("b", critical)
    assert scheduler.lightweight_due(never, now=T0) is True


def test_deep_due_weekly():
    scheduler = Scheduler()
    item = scheduler.schedule("a", last_deep_scan=T0)
    assert scheduler.deep_due(item, now=T0 + timedelta(days=6)) is False
    assert scheduler.deep_due(item, now=T0 + timedelta(days=8)) is True
    assert scheduler.deep_due(scheduler.schedule("b"), now=T0) is True


def test_due_assets_priority_ordered():
    scheduler = Scheduler()
    items = [
        scheduler.schedule("low", {"business_criticality": 2.0}, last_scanned=T0),
        scheduler.schedule("high", {"business_criticality": 9.0}, last_scanned=T0),
    ]
    due = scheduler.due_assets(items, now=T0 + timedelta(days=1))
    assert due == ["high", "low"]


def test_scheduler_injectable_clock():
    now = [T0]
    scheduler = Scheduler(clock=lambda: now[0])
    critical = {
        "business_criticality": 10.0, "internet_exposure": 10.0,
        "crypto_risk": 10.0, "compliance_importance": 10.0,
    }
    item = scheduler.schedule("a", critical, last_scanned=T0)
    assert scheduler.lightweight_due(item) is False
    now[0] = T0 + timedelta(hours=2)
    assert scheduler.lightweight_due(item) is True


def test_scheduler_summarize():
    scheduler = Scheduler()
    critical = {
        "business_criticality": 10.0, "internet_exposure": 10.0,
        "crypto_risk": 10.0, "compliance_importance": 10.0,
    }
    items = [scheduler.schedule("a", critical),
             scheduler.schedule("b", {"business_criticality": 1.0})]
    summary = scheduler.summarize(items)
    assert summary["assets"] == 2
    assert summary["by_tier"] == {"CRITICAL": 1, "LOW": 1}


# ---------------------------------------------------------------- asset state

def _snapshot(**overrides):
    base = {"asset_id": "rtr-1", "ip": "10.0.0.1", "hostname": "rtr-1",
            "device_type": "router", "os": "IOS-XE",
            "tls_version": "TLSv1.3", "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
            "public_key_size": 3072}
    base.update(overrides)
    return base


def test_first_observation_is_first_seen():
    engine = AssetStateEngine()
    transition = engine.observe("rtr-1", _snapshot(), now=T0)
    assert transition.kind == "FIRST_SEEN"
    state = engine.get("rtr-1")
    assert state.first_seen == T0
    assert state.last_seen == T0
    assert state.last_crypto_change is None


def test_no_change_observation():
    engine = AssetStateEngine()
    engine.observe("rtr-1", _snapshot(), now=T0)
    transition = engine.observe("rtr-1", _snapshot(), now=T0 + timedelta(minutes=1))
    assert transition.kind == "NO_CHANGE"
    state = engine.get("rtr-1")
    assert state.last_seen == T0 + timedelta(minutes=1)


def test_crypto_change_classified():
    engine = AssetStateEngine()
    engine.observe("rtr-1", _snapshot(tls_version="TLSv1.3"), now=T0)
    transition = engine.observe("rtr-1", _snapshot(tls_version="TLSv1.2"),
                                now=T0 + timedelta(minutes=1))
    assert transition.kind == "CRYPTO_CHANGED"
    assert transition.crypto_changed is True
    assert transition.network_changed is False
    assert "tls_version" in transition.changed_fields
    assert engine.get("rtr-1").last_crypto_change == T0 + timedelta(minutes=1)


def test_network_change_classified():
    engine = AssetStateEngine()
    engine.observe("rtr-1", _snapshot(ip="10.0.0.1"), now=T0)
    transition = engine.observe("rtr-1", _snapshot(ip="10.0.0.2"), now=T0)
    assert transition.kind == "NETWORK_CHANGED"
    assert transition.crypto_changed is False
    assert transition.network_changed is True


def test_both_changed():
    engine = AssetStateEngine()
    engine.observe("rtr-1", _snapshot(ip="10.0.0.1", tls_version="TLSv1.3"), now=T0)
    transition = engine.observe("rtr-1", _snapshot(ip="10.0.0.2", tls_version="TLSv1.2"),
                                now=T0)
    assert transition.kind == "BOTH_CHANGED"


def test_remove_asset():
    engine = AssetStateEngine()
    engine.observe("rtr-1", _snapshot(), now=T0)
    transition = engine.remove("rtr-1")
    assert transition is not None
    assert transition.kind == "REMOVED"
    assert engine.get("rtr-1") is None


def test_deep_scan_tracking():
    engine = AssetStateEngine()
    engine.observe("rtr-1", _snapshot(), deep=False, now=T0)
    assert engine.get("rtr-1").last_deep_scan is None
    engine.observe("rtr-1", _snapshot(), deep=True, now=T0 + timedelta(hours=1))
    assert engine.get("rtr-1").last_deep_scan == T0 + timedelta(hours=1)


def test_mark_health_and_paused():
    engine = AssetStateEngine()
    engine.observe("rtr-1", _snapshot(), now=T0)
    engine.mark_health("rtr-1", "DEGRADED")
    assert engine.get("rtr-1").scan_health == "DEGRADED"
    engine.mark_paused("rtr-1", paused=True)
    assert engine.get("rtr-1").monitoring_status == "PAUSED"
    engine.mark_paused("rtr-1", paused=False)
    assert engine.get("rtr-1").monitoring_status == "ACTIVE"


def test_previous_state_preserved():
    engine = AssetStateEngine()
    first = _snapshot(tls_version="TLSv1.3")
    second = _snapshot(tls_version="TLSv1.2")
    engine.observe("rtr-1", first, now=T0)
    engine.observe("rtr-1", second, now=T0 + timedelta(minutes=1))
    state = engine.get("rtr-1")
    assert state.previous["tls_version"] == "TLSv1.3"
    assert state.current["tls_version"] == "TLSv1.2"


def test_state_dict_shape():
    engine = AssetStateEngine()
    engine.observe("rtr-1", _snapshot(), now=T0)
    d = engine.to_dicts()[0]
    assert d["asset_id"] == "rtr-1"
    assert d["monitoring_status"] == "ACTIVE"
    assert d["crypto_digest"]
    assert d["network_digest"]


def test_crypto_fields_sets():
    assert "tls_version" in CRYPTO_FIELDS
    assert "ip" in NETWORK_FIELDS
    assert "cipher_suites" in CRYPTO_FIELDS


def test_transitions_history_and_recent():
    engine = AssetStateEngine()
    engine.observe("rtr-1", _snapshot(), now=T0)
    engine.observe("rtr-1", _snapshot(tls_version="TLSv1.2"), now=T0)
    kinds = [t.kind for t in engine.transitions()]
    assert kinds == ["FIRST_SEEN", "CRYPTO_CHANGED"]
    assert engine.recent(since_kind="CRYPTO_CHANGED")[0].asset_id == "rtr-1"


# ---------------------------------------------------------------- drift

def test_drift_no_change():
    results = DriftDetector().detect({"a": 1}, {"a": 1})
    assert results == []


def test_drift_critical_key_size_downgrade():
    detector = DriftDetector()
    results = detector.detect({"public_key_size": 3072}, {"public_key_size": 1024})
    assert len(results) == 1
    assert results[0].classification == "CRITICAL_DRIFT"
    assert results[0].severity == "CRITICAL"


def test_drift_tls_downgrade_critical():
    detector = DriftDetector()
    results = detector.detect({"tls_version": "TLSv1.3"}, {"tls_version": "TLSv1.0"})
    assert results[0].classification == "CRITICAL_DRIFT"


def test_drift_tls_upgrade_expected():
    detector = DriftDetector()
    results = detector.detect({"tls_version": "TLSv1.0"}, {"tls_version": "TLSv1.3"})
    assert results[0].classification == "EXPECTED_CHANGE"


def test_drift_approved_change():
    detector = DriftDetector()
    results = detector.detect({"public_key_size": 3072}, {"public_key_size": 1024},
                              change_id="TICKET-42", approve=True)
    assert results[0].classification == "APPROVED_CHANGE"
    # approval is sticky
    results = detector.detect({"public_key_size": 3072}, {"public_key_size": 1024},
                              change_id="TICKET-42")
    assert results[0].classification == "APPROVED_CHANGE"


def test_drift_unapproved_without_approval():
    detector = DriftDetector()
    results = detector.detect({"public_key_size": 3072}, {"public_key_size": 1024},
                              change_id="TICKET-7")
    assert results[0].classification == "CRITICAL_DRIFT"


def test_drift_custom_policy():
    detector = DriftDetector(policy={"ike_version": {"allowed": {"IKEv1"}}})
    results = detector.detect({"ike_version": "IKEv2"}, {"ike_version": "IKEv1"})
    assert results[0].classification == "EXPECTED_CHANGE"


def test_drift_unknown_field_not_critical():
    detector = DriftDetector()
    results = detector.detect({"interface": "Gi0/0"}, {"interface": "Gi0/1"})
    assert results[0].classification == "EXPECTED_CHANGE"


def test_drift_critical_field_no_rule():
    detector = DriftDetector()
    results = detector.detect({"ike_encryption": "3DES"}, {"ike_encryption": "AES-256"})
    # no rule → but it is a CRITICAL_DRIFT_FIELDS member → UNEXPECTED
    assert results[0].classification == "UNEXPECTED_CHANGE"


def test_classify_crypto_drift_labels():
    assert classify_crypto_drift({"public_key_size": 3072},
                                 {"public_key_size": 1024}) == "CRITICAL_CRYPTO_DRIFT"
    assert classify_crypto_drift({"public_key_size": 3072},
                                 {"public_key_size": 3072}) == "NO_CRYPTO_DRIFT"
    assert classify_crypto_drift({"tls_version": "TLSv1.0"},
                                 {"tls_version": "TLSv1.3"}) == "EXPECTED_CRYPTO_CHANGE"


def test_drift_result_dict():
    result = DriftDetector().detect({"public_key_size": 3072},
                                    {"public_key_size": 1024})[0]
    d = result.to_dict()
    assert d["field"] == "public_key_size"
    assert d["previous"] == 3072
    assert d["current"] == 1024
    assert d["classification"] == "CRITICAL_DRIFT"


def test_critical_drift_fields_include_key_fields():
    assert "public_key_size" in CRITICAL_DRIFT_FIELDS
    assert "tls_version" in CRITICAL_DRIFT_FIELDS
