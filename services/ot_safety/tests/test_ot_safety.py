"""Deterministic OT/ICS maintenance-window safety guard tests (no AI/ML)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ot_safety.policy import (
    Decision,
    DenyReason,
    MaintenanceWindow,
    OtDevice,
    authorize_operation,
)

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)


def _window(**kw):
    base = dict(
        id="w1",
        starts_at=NOW - timedelta(hours=1),
        ends_at=NOW + timedelta(hours=1),
        device_ids=frozenset({"plc-7"}),
        allowed_action_class="interact",
        approved_by="otmgr",
        change_ticket="CHG-1234",
    )
    base.update(kw)
    return MaintenanceWindow(**base)


def _dev(**kw):
    base = dict(id="plc-7", criticality="HIGH", device_type="plc", zone="z1", site="plant-a")
    base.update(kw)
    return OtDevice(**base)


# --- passive: always allowed -------------------------------------------------
def test_passive_ops_always_allowed_no_window():
    for op in ("passive_capture", "filesystem_read", "pcap_read", "inventory", "metrics_render"):
        d = authorize_operation(op, _dev(), [], now=NOW)
        assert d.decision == Decision.ALLOW and d.passive is True


def test_passive_allowed_even_on_safety_controller():
    sis = _dev(device_type="safety_controller", criticality="SAFETY")
    d = authorize_operation("passive_capture", sis, [], now=NOW)
    assert d.decision == Decision.ALLOW


# --- active op safety rules --------------------------------------------------
def test_active_probe_denied_without_window():
    d = authorize_operation("active_probe", _dev(), [], now=NOW)
    assert d.decision == Decision.DENY
    assert d.reason == DenyReason.OUTSIDE_WINDOW


def test_active_probe_allowed_in_window_with_ticket():
    d = authorize_operation("active_probe", _dev(), [_window()], now=NOW)
    assert d.decision == Decision.ALLOW
    assert d.window_id == "w1" and d.matched_window is True


def test_safety_controller_never_actively_probed_even_with_window():
    sis = _dev(device_type="sis", criticality="SAFETY")
    d = authorize_operation("active_probe", sis, [_window(device_ids=frozenset({"plc-7"}))], now=NOW)
    assert d.decision == Decision.DENY
    assert d.reason == DenyReason.SAFETY_CONTROLLER_PROTECTED


def test_window_not_started():
    w = _window(starts_at=NOW + timedelta(hours=2))
    d = authorize_operation("active_probe", _dev(), [w], now=NOW)
    assert d.reason == DenyReason.WINDOW_NOT_STARTED


def test_window_expired():
    w = _window(ends_at=NOW - timedelta(minutes=5))
    d = authorize_operation("active_probe", _dev(), [w], now=NOW)
    assert d.reason == DenyReason.WINDOW_EXPIRED


def test_window_scope_mismatch():
    w = _window(device_ids=frozenset({"other-device"}))
    d = authorize_operation("active_probe", _dev(), [w], now=NOW)
    assert d.decision == Decision.DENY
    assert d.reason == DenyReason.OUTSIDE_WINDOW


def test_zone_scoped_window_covers_device():
    w = _window(device_ids=frozenset(), zones=frozenset({"z1"}))
    d = authorize_operation("active_probe", _dev(), [w], now=NOW)
    assert d.decision == Decision.ALLOW


def test_action_class_exceeded():
    # firmware_push is 'change'; window only grants 'interact'
    w = _window(allowed_action_class="interact")
    d = authorize_operation("firmware_push", _dev(), [w], now=NOW)
    assert d.reason == DenyReason.ACTION_EXCEEDS_WINDOW_CLASS


def test_change_class_allowed_in_change_window():
    w = _window(allowed_action_class="change")
    d = authorize_operation("config_write", _dev(), [w], now=NOW)
    assert d.decision == Decision.ALLOW


def test_change_ticket_required():
    w = _window(change_ticket="")
    d = authorize_operation("active_probe", _dev(), [w], now=NOW)
    assert d.reason == DenyReason.NO_CHANGE_TICKET


def test_ticket_can_be_passed_at_call_time():
    w = _window(change_ticket="")
    d = authorize_operation("active_probe", _dev(), [w], now=NOW, change_ticket="CHG-9999")
    assert d.decision == Decision.ALLOW


def test_invalid_ticket_format_rejected():
    w = _window(change_ticket="just-a-note")
    d = authorize_operation("active_probe", _dev(), [w], now=NOW)
    assert d.reason == DenyReason.NO_CHANGE_TICKET


def test_approval_required():
    w = _window(approved_by="")
    d = authorize_operation("active_probe", _dev(), [w], now=NOW)
    assert d.reason == DenyReason.NO_APPROVAL


def test_unknown_operation_denied():
    d = authorize_operation("rm_rf_plant", _dev(), [], now=NOW)
    assert d.reason == DenyReason.UNKNOWN_OPERATION


def test_active_op_on_unknown_target_denied():
    d = authorize_operation("active_probe", None, [_window()], now=NOW)
    assert d.reason == DenyReason.NO_SUCH_DEVICE


def test_window_dict_roundtrip():
    w = MaintenanceWindow.from_dict({
        "id": "wx", "starts_at": "2026-09-03T11:00:00Z",
        "ends_at": "2026-09-03T13:00:00Z",
        "zones": ["z1"], "allowed_action_class": "change",
        "approved_by": "mgr", "change_ticket": "CHG-7777",
    })
    assert w.covers_device(_dev(zone="z1"))
    d = authorize_operation("reboot", _dev(), [w], now=NOW)
    assert d.decision == Decision.ALLOW


def test_deterministic_decision():
    a = authorize_operation("active_probe", _dev(), [_window()], now=NOW)
    b = authorize_operation("active_probe", _dev(), [_window()], now=NOW)
    assert a.as_dict() == b.as_dict()
