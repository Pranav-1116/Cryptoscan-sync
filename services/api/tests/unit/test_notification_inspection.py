"""Operator-only receipt inspection never invokes dispatch or exposes its secrets."""
from datetime import datetime, timezone

from services.api.tests.unit.test_notifications_dispatch import client as client, _h


def seed():
    from control_plane.notification_dispatch import _values
    from db.connection.session import SessionLocal
    from db.models.notification_delivery import NotificationDelivery

    now = datetime.now(timezone.utc)
    with SessionLocal() as session:
        for index in range(3):
            row = NotificationDelivery(**_values(None, f"event-{index}", "receiver", "siem", "compliance_failure",
                                                {"detail": "hidden-envelope"}, now, status="failed"))
            row.last_error, row.lease_token = "hidden-error", "hidden-token"
            session.add(row)
        session.commit()


def test_inspection_is_read_only_paginated_and_metadata_only(client, monkeypatch):
    import control_plane.notification_dispatch as dispatch

    monkeypatch.setattr(dispatch, "drain_notifications", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("dispatch called")))
    headers = _h(client)
    seed()
    summary = client.get("/api/v1/notifications/delivery-summary", headers=headers)
    assert summary.status_code == 200 and summary.json()["pending"] == 3
    page = client.get("/api/v1/notifications/deliveries?limit=2&status=failed", headers=headers)
    assert page.status_code == 200
    data = page.json()
    assert len(data["items"]) == 2 and data["next_cursor"]
    assert not any(secret in page.text for secret in ("hidden-envelope", "hidden-error", "hidden-token"))
    second = client.get("/api/v1/notifications/deliveries", params={"limit": 2, "status": "failed", "cursor": data["next_cursor"]}, headers=headers)
    assert second.status_code == 200 and len(second.json()["items"]) == 1
    assert second.json()["next_cursor"] is None
    assert client.get("/api/v1/notifications/delivery-summary", headers=headers).json()["counts"]["failed"] == 3


def test_inspection_rejects_bad_bounds_filters_and_cursors(client):
    headers = _h(client)
    for params in ({"limit": 0}, {"limit": 101}, {"status": "healthy"}, {"cursor": "!"}, {"cursor": "a" * 513}):
        assert client.get("/api/v1/notifications/deliveries", params=params, headers=headers).status_code == 422


def test_inspection_requires_fresh_operator_authority(client):
    from db.connection.session import SessionLocal
    from db.models.user import User

    for path in ("delivery-summary", "deliveries"):
        assert client.get(f"/api/v1/notifications/{path}").status_code in (401, 403)
    _h(client)
    with SessionLocal() as session:
        session.query(User).filter_by(username="admin").one().roles = "readonly"
        session.commit()
    headers = _h(client)
    for path in ("delivery-summary", "deliveries"):
        assert client.get(f"/api/v1/notifications/{path}", headers=headers).status_code == 403
