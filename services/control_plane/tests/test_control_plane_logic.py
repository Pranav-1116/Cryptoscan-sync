"""Unit tests for the deterministic control-plane core (no DB / no FastAPI)."""

from datetime import datetime, timedelta, timezone

from control_plane import (
    Scope,
    assess_credential,
    backoff_delay,
    classify_after_failure,
    confidence_from_evidence,
    evaluate_scan,
    is_authorized,
    lease_event,
    maintenance_window_open,
    next_available,
    residency_permitted,
    resolve_identity,
    score_predictions,
    should_auto_stop,
)

NOW = datetime(2026, 9, 6, 2, 30, tzinfo=timezone.utc)  # a Sunday 02:30 UTC


# ----------------------------------------------------------------------- IAM
def test_fail_closed_without_grant():
    ok, reason = is_authorized([], username="alice", roles=["developer"],
                               action="read", target=Scope(region="uae"))
    assert ok is False
    assert "fail-closed" in reason


def test_region_grant_covers_hierarchy():
    grants = [{"subject": "alice", "subject_type": "user", "actions": ["read"],
               "effect": "allow", "is_active": True, "region": "uae"}]
    tgt = Scope(region="uae", business_unit="retail", environment="prod", asset_id="a1")
    ok, _ = is_authorized(grants, username="alice", roles=[], action="read", target=tgt)
    assert ok is True
    # different region is not covered
    ok2, _ = is_authorized(grants, username="alice", roles=[], action="read",
                           target=Scope(region="eu"))
    assert ok2 is False


def test_role_grant_and_deny_overrides_allow():
    grants = [
        {"subject": "auditor", "subject_type": "role", "actions": ["*"],
         "effect": "allow", "is_active": True, "region": "eu"},
        {"subject": "bob", "subject_type": "user", "actions": ["*"],
         "effect": "deny", "is_active": True, "region": "eu", "environment": "secret"},
    ]
    ok, _ = is_authorized(grants, username="carol", roles=["auditor"],
                          action="read", target=Scope(region="eu"))
    assert ok is True
    ok_deny, _ = is_authorized(grants, username="bob", roles=["auditor"],
                               action="read", target=Scope(region="eu", environment="secret"))
    assert ok_deny is False


def test_inactive_grant_ignored():
    grants = [{"subject": "alice", "subject_type": "user", "actions": ["read"],
               "effect": "allow", "is_active": False, "region": "uae"}]
    ok, _ = is_authorized(grants, username="alice", roles=[], action="read",
                          target=Scope(region="uae"))
    assert ok is False


def test_residency_permitted():
    tenant = {"is_active": True, "processing_regions": ["uae"]}
    assert residency_permitted(tenant, "uae") is True
    assert residency_permitted(tenant, "eu") is False
    assert residency_permitted({"is_active": False}, "uae") is False
    assert residency_permitted(None, "uae") is True


# ---------------------------------------------------------------- safe scan
def test_emergency_stop_blocks_everything():
    d = evaluate_scan({"emergency_stop": True}, now=NOW)
    assert d.permitted is False and d.mode == "emergency_stop"


def test_ot_outside_window_forced_passive():
    policy = {"mode": "deep", "maintenance_windows": [{"day": "sun", "start": "03:00", "duration_minutes": 60}]}
    d = evaluate_scan(policy, is_ot=True, now=NOW)  # Sunday 02:30 — before 03:00 window
    assert d.permitted is True
    assert d.active_probing is False and d.mode == "passive"


def test_ot_inside_window_allows_active():
    policy = {"mode": "standard", "maintenance_windows": [{"day": "sun", "start": "02:00", "duration_minutes": 120}]}
    d = evaluate_scan(policy, is_ot=True, now=NOW)  # 02:30 inside
    assert d.active_probing is True


def test_exclusions():
    policy = {"mode": "standard", "excluded_ports": [22], "excluded_assets": ["hsm-1"]}
    assert evaluate_scan(policy, port=22, now=NOW).permitted is False
    assert evaluate_scan(policy, asset="hsm-1", now=NOW).permitted is False
    assert evaluate_scan(policy, port=443, now=NOW).permitted is True


def test_budgets_are_clamped_not_loosened():
    d = evaluate_scan({"mode": "standard", "rate_limit_qps": 1}, now=NOW)
    assert d.budgets["rate_limit_qps"] == 1  # tightened
    d2 = evaluate_scan({"mode": "standard", "rate_limit_qps": 9999}, now=NOW)
    assert d2.budgets["rate_limit_qps"] == 10  # cannot exceed default


def test_auto_stop_conditions():
    stop, _ = should_auto_stop({"max_error_rate": 0.05}, {"error_rate": 0.2})
    assert stop is True
    stop2, _ = should_auto_stop({"max_error_rate": 0.5}, {"error_rate": 0.01})
    assert stop2 is False


def test_maintenance_window_open():
    assert maintenance_window_open([{"day": "sun", "start": "02:00", "duration_minutes": 60}], now=NOW) is True
    assert maintenance_window_open([{"day": "mon", "start": "02:00", "duration_minutes": 60}], now=NOW) is False
    assert maintenance_window_open(None, now=NOW) is True


# ------------------------------------------------------------ identity
def test_confirmed_with_two_strong_sources():
    obs = [
        {"source": "network", "asset_type": "hsm", "criticality": "tier1",
         "identifiers": {"serial": "ABC"}},
        {"source": "cmdb", "asset_type": "hsm", "criticality": "tier1",
         "identifiers": {"serial": "ABC"}},
    ]
    r = resolve_identity(obs)
    assert r["confidence"] == "CONFIRMED"
    assert r["attributes"]["asset_type"] == "hsm"


def test_conflict_on_disagreeing_criticality():
    obs = [
        {"source": "network", "criticality": "tier1", "identifiers": {"serial": "X"}},
        {"source": "cloud", "criticality": "tier3", "identifiers": {"instance_id": "i-1"}},
    ]
    assert resolve_identity(obs)["confidence"] == "CONFLICT"


def test_empty_is_unknown():
    assert resolve_identity([])["confidence"] == "UNKNOWN"


def test_confidence_from_evidence_never_binary():
    assert confidence_from_evidence(0) == "UNKNOWN"
    assert confidence_from_evidence(1) == "POSSIBLE"
    assert confidence_from_evidence(2) == "PROBABLE"
    assert confidence_from_evidence(4, agreeing=3) == "CONFIRMED"


# ------------------------------------------------------------- benchmark
def test_confusion_matrix_and_metrics():
    cases = [
        {"expected_detection": True, "predicted_detection": True},   # TP
        {"expected_detection": True, "predicted_detection": True},   # TP
        {"expected_detection": True, "predicted_detection": False},  # FN
        {"expected_detection": False, "predicted_detection": True},  # FP
        {"expected_detection": False, "predicted_detection": False}, # TN
    ]
    m = score_predictions(cases)
    assert (m["true_positive"], m["false_positive"], m["true_negative"], m["false_negative"]) == (2, 1, 1, 1)
    assert m["precision"] == 0.6667
    assert m["recall"] == 0.6667
    assert m["f1"] == 0.6667
    assert m["false_positive_rate"] == 0.5


def test_perfect_score_meets_target():
    cases = [{"expected_detection": True, "predicted_detection": True} for _ in range(10)]
    m = score_predictions(cases)
    assert m["accuracy"] == 1.0 and m["meets_95_target"] is True


# ---------------------------------------------------------------- queue
def test_priority_ordering():
    events = [
        {"id": "1", "priority": "normal", "status": "queued"},
        {"id": "2", "priority": "critical", "status": "queued"},
        {"id": "3", "priority": "high", "status": "queued"},
    ]
    assert next_available(events, now=NOW)["id"] == "2"


def test_backoff_and_dead_letter():
    assert backoff_delay(1) == 30
    assert backoff_delay(5) == 480
    assert backoff_delay(10) == 3600  # capped
    ev = {"attempts": 4, "max_attempts": 5}
    out = classify_after_failure(ev, now=NOW)
    assert out["status"] == "dead" and out["attempts"] == 5
    early = classify_after_failure({"attempts": 0, "max_attempts": 5}, now=NOW)
    assert early["status"] == "queued" and early["available_at"] > NOW


def test_lease_sets_worker():
    leased = lease_event({"attempts": 0}, "worker-1", now=NOW)
    assert leased["status"] == "leased" and leased["leased_by"] == "worker-1"


# ----------------------------------------------------------- credentials
def test_credential_expired_and_rotation():
    expired = assess_credential({"status": "active", "health_ok": True,
                                 "expires_at": (NOW - timedelta(days=2)).isoformat()}, now=NOW)
    assert expired.status == "expired" and expired.healthy is False
    due = assess_credential({"status": "active", "health_ok": True,
                             "last_rotated_at": (NOW - timedelta(days=120)).isoformat(),
                             "rotation_policy_days": 90}, now=NOW)
    assert due.rotation_due is True
    unverified = assess_credential({"status": "active", "health_ok": False}, now=NOW)
    assert unverified.healthy is False and unverified.status == "pending"
    revoked = assess_credential({"status": "revoked"}, now=NOW)
    assert revoked.healthy is False
