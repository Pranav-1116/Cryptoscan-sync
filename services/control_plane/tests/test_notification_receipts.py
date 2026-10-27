"""Durable notification semantics on real SQLite sessions; HTTP is mocked."""
from __future__ import annotations

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401
from control_plane import delivery
from control_plane.notification_dispatch import (
    LEASE_SECONDS, NotificationPersistenceError, _finish, _values, claim, drain_notifications,
)
from control_plane.notification_routing import merged_routing, save_routing
from db.connection.session import Base
from db.models.app_setting import AppSetting
from db.models.control_plane import DeliveryLog
from db.models.enterprise import Integration
from db.models.monitor import MonitorEvent
from db.models.notification_delivery import NotificationDelivery as Receipt
from db.tenancy import install_tenant_guard, tenant_scope

NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)


@pytest.fixture
def database(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/receipts.db", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    install_tenant_guard()
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        yield session, factory
    engine.dispose()


@pytest.fixture
def posts(monkeypatch):
    captured = []
    monkeypatch.setattr(delivery, "validate_webhook_url", lambda url: url)

    def send(_post, endpoint, **kwargs):
        captured.append((endpoint, kwargs))
        return 200, "accepted"

    monkeypatch.setattr(delivery, "_http_post", send)
    return captured


def event(session, *, owner=None, kind="remediation.task_verified", detail="VERIFIED"):
    row = MonitorEvent(id=str(uuid.uuid4()), tenant_id=owner, event_type=kind, target_name="task",
                       detail=detail, created_at=NOW)
    session.add(row)
    session.commit()
    return row


def integration(session, *, owner=None, kind="siem", endpoint="https://soc.example/hook"):
    row = Integration(id=str(uuid.uuid4()), tenant_id=owner, name="SOC", kind=kind, provider="webhook",
                      enabled=True, endpoint=endpoint)
    session.add(row)
    session.commit()
    return row


def drain(session, **kwargs):
    return drain_notifications(session, clock=lambda: NOW, **kwargs)


def routes(session, enabled):
    routing, _ = merged_routing(session)
    for row in routing:
        if row["id"] == "remediation_verification":
            row["channels"]["siem"] = enabled
            row["channels"]["webhook"] = enabled
    save_routing(session, routing, user="operator")
    session.commit()


def snapshot(row):
    return SimpleNamespace(**{key: getattr(row, key) for key in (
        "id", "event_id", "integration_id", "envelope", "attempt_count", "channel", "event_class", "delivery_key")})


def test_receipt_success_is_durable_across_sessions(database, posts):
    session, factory = database
    event(session)
    integration(session)
    assert drain(session)["delivered"] == 1
    with factory() as replica:
        result = drain(replica)
        assert result["dispatched"] == 0
        assert result["receipts"] == {"delivered": 1}
    assert len(posts) == 1


def test_failed_destination_retries_without_resending_success(database, posts, monkeypatch):
    session, _ = database
    event(session)
    good = integration(session)
    bad = integration(session, kind="itsm", endpoint="https://ops.example/hook")
    captured = []
    recovered = False

    def send(_post, endpoint, **kwargs):
        captured.append((endpoint, kwargs))
        return (200, "ok") if endpoint == good.endpoint or recovered else (503, "down")

    monkeypatch.setattr(delivery, "_http_post", send)
    assert drain(session)["failed"] == 1
    assert drain(session)["dispatched"] == 0  # persistent backoff, no hot loop
    recovered = True
    result = drain_notifications(session, clock=lambda: NOW + timedelta(seconds=61))
    assert result["delivered"] == 1
    assert len([url for url, _ in captured if url == good.endpoint]) == 1
    retried = [kwargs for url, kwargs in captured if url == bad.endpoint]
    assert len(retried) == 2
    assert retried[0]["headers"]["Idempotency-Key"] == retried[1]["headers"]["Idempotency-Key"]
    assert retried[0]["content"] == retried[1]["content"]
    assert result["receipts"] == {"delivered": 2}


def test_air_gap_remains_pending_and_can_deliver_after_configuration(database, posts):
    session, _ = database
    event(session)
    target = integration(session, endpoint=None)
    assert drain(session)["skipped"] == 1
    assert len(posts) == 0
    target.endpoint = "https://soc.example/hook"
    session.commit()
    result = drain_notifications(session, clock=lambda: NOW + timedelta(seconds=61))
    assert result["delivered"] == 1 and len(posts) == 1


def test_no_destination_is_not_an_ack_and_new_receiver_backfills(database, posts):
    session, _ = database
    event(session)
    assert drain(session)["receipts"] == {}
    integration(session)
    assert drain(session)["delivered"] == 1
    integration(session, kind="itsm", endpoint="https://new.example/hook")
    assert drain(session)["delivered"] == 1
    assert len(posts) == 2


def test_unmapped_traffic_cannot_starve_an_old_routed_event(database, posts):
    session, _ = database
    event(session)
    integration(session)
    session.add_all([MonitorEvent(event_type="graph.updated", target_name="graph",
                                  created_at=NOW + timedelta(seconds=1)) for _ in range(500)])
    session.commit()
    result = drain(session, limit=1)
    assert result["delivered"] == 1


def test_receipts_are_not_evicted_after_2000_events(database, posts):
    session, _ = database
    old = event(session)
    target = integration(session)
    ids = [old.id] + [str(uuid.uuid4()) for _ in range(2000)]
    session.add_all([Receipt(**_values(None, identity, target.id, "siem", "remediation_verification", {}, NOW,
                                      status="delivered")) for identity in ids])
    session.commit()
    event(session)
    result = drain(session, limit=2)
    assert result["delivered"] == 1 and len(posts) == 1
    assert result["receipts"] == {"delivered": 2002}


def test_destination_limit_binds_fanout_and_next_drain_progresses(database, posts):
    session, _ = database
    event(session)
    for _ in range(5):
        integration(session)
    assert drain(session, limit=2)["destination_attempts"] == 2
    assert drain(session, limit=2)["destination_attempts"] == 2
    assert drain(session, limit=2)["destination_attempts"] == 1
    assert len(posts) == 5


def test_queued_work_respects_disabled_routes_and_destinations(database, posts):
    session, _ = database
    event(session)
    target = integration(session)
    assert drain(session, budget_s=0)["enqueued"] == 1
    routes(session, False)
    assert drain(session)["dispatched"] == 0
    routes(session, True)
    target.enabled = False
    session.commit()
    assert drain(session)["dispatched"] == 0
    target.enabled = True
    session.commit()
    assert drain(session)["delivered"] == 1


def test_retry_envelope_survives_journal_edit_and_retention(database, posts, monkeypatch):
    session, _ = database
    source = event(session)
    integration(session)
    assert drain(session, budget_s=0)["enqueued"] == 1
    source.detail = "changed after enqueue"
    session.delete(source)
    session.commit()
    assert drain(session)["delivered"] == 1
    body = json.loads(posts[0][1]["content"])
    assert body["payload"]["detail"] == "VERIFIED"


def test_scope_is_exact_for_events_destinations_and_receipts(database, posts):
    session, _ = database
    for owner in (None, "tenant-a", "tenant-b"):
        event(session, owner=owner)
        integration(session, owner=owner, endpoint=f"https://{owner or 'platform'}.example/hook")
    with tenant_scope("tenant-a"):
        result = drain(session)
        assert result["delivered"] == 1 and result["receipts"] == {"delivered": 1}
    assert drain(session)["delivered"] == 1  # platform, never a cross-tenant roll-up
    with tenant_scope("tenant-b"):
        assert drain(session)["delivered"] == 1
    assert len(posts) == 3


def test_routing_can_be_owned_by_two_tenants_without_platform_inheritance(database):
    session, _ = database
    routes(session, False)
    with tenant_scope("tenant-a"):
        rows, persisted = merged_routing(session)
        assert not persisted and next(r for r in rows if r["id"] == "remediation_verification")["channels"]["siem"]
        routes(session, False)
    with tenant_scope("tenant-b"):
        rows, persisted = merged_routing(session)
        assert not persisted
        routes(session, True)
    with tenant_scope("tenant-a"):
        rows, persisted = merged_routing(session)
        assert persisted and not next(r for r in rows if r["id"] == "remediation_verification")["channels"]["siem"]


def test_legacy_registry_is_unknown_not_delivered(database, posts):
    session, _ = database
    source = event(session)
    event(session)
    integration(session)
    session.add(AppSetting(key="notification.dispatch.v1", value=json.dumps({"dispatched": [source.id]})))
    session.commit()
    result = drain(session)
    assert result["delivered"] == 1
    assert result["receipts"] == {"delivered": 1, "legacy_unknown": 1}
    assert drain(session)["dispatched"] == 0


@pytest.mark.parametrize("value", ["bad-json", "[]", '{"dispatched":"bad"}'])
def test_corrupt_legacy_state_fails_closed_before_network(database, posts, value):
    session, _ = database
    event(session)
    integration(session)
    session.add(AppSetting(key="notification.dispatch.v1", value=value))
    session.commit()
    with pytest.raises(NotificationPersistenceError):
        drain(session)
    assert not posts


def test_atomic_claim_has_one_winner_across_real_connections(database, posts):
    session, factory = database
    event(session)
    integration(session)
    drain(session, budget_s=0)
    identity = session.scalar(select(Receipt.id))
    session.commit()
    barrier = threading.Barrier(2)

    def run():
        with factory() as replica:
            barrier.wait(timeout=5)
            return claim(replica, identity, now=NOW)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run) for _ in range(2)]
        winners = [future.result(timeout=10) for future in futures]
    assert sum(token is not None for token in winners) == 1
    assert not posts


def test_expired_claim_is_recoverable_and_old_owner_is_fenced(database, posts):
    session, factory = database
    event(session)
    integration(session)
    drain(session, budget_s=0)
    row = session.scalar(select(Receipt))
    identity = row.id
    first = claim(session, identity, now=NOW)
    session.refresh(row)
    saved = snapshot(row)
    session.commit()
    with factory() as replica:
        second = claim(replica, identity, now=NOW + timedelta(seconds=LEASE_SECONDS + 1))
        assert second and second != first
        observed = delivery.DeliveryResult(integration_id=saved.integration_id, provider="webhook", kind="siem",
                                           endpoint="https://soc.example/hook", status="delivered", attempts=1, http_status=200).to_dict()
        assert not _finish(session, saved, first, observed, NOW + timedelta(seconds=LEASE_SECONDS + 2))
        row = replica.get(Receipt, identity)
        assert row.lease_token == second and row.status == "inflight"
        assert _finish(replica, saved, second, observed, NOW + timedelta(seconds=LEASE_SECONDS + 3))
    assert drain(session)["receipts"] == {"delivered": 1}


def test_no_transaction_is_held_during_network_and_nested_drain_cannot_send(database, posts, monkeypatch):
    session, factory = database
    event(session)
    integration(session)

    def send(_post, _endpoint, **_kwargs):
        assert not session.in_transaction()
        with factory() as replica:
            assert drain(replica)["dispatched"] == 0
        return 200, "ok"

    monkeypatch.setattr(delivery, "_http_post", send)
    assert drain(session)["delivered"] == 1


def test_ack_then_commit_failure_is_not_reported_as_durable_success(database, posts, monkeypatch, caplog):
    session, factory = database
    event(session)
    integration(session)
    received = False
    original = session.commit

    def send(_post, _endpoint, **_kwargs):
        nonlocal received
        received = True
        return 200, "accepted"

    def commit():
        if received:
            raise RuntimeError("private-credential-sentinel")
        return original()

    monkeypatch.setattr(delivery, "_http_post", send)
    monkeypatch.setattr(session, "commit", commit)
    with pytest.raises(NotificationPersistenceError):
        drain(session)
    assert "private-credential-sentinel" not in caplog.text
    with factory() as replica:
        row = replica.scalar(select(Receipt))
        assert row.status == "inflight" and row.delivered_at is None
        assert replica.scalar(select(DeliveryLog)) is None


def test_unexpected_transport_error_is_sanitized_and_retryable(database, posts):
    session, _ = database
    event(session)
    integration(session)

    def broken(*_a, **_k):
        raise RuntimeError("private-credential-sentinel")

    result = drain(session, transport=broken)
    assert result["failed"] == 1
    row = session.scalar(select(Receipt))
    assert row.status == "failed" and "private-credential-sentinel" not in row.last_error


def test_deleted_destination_does_not_delete_or_ack_pending_receipt(database, posts):
    session, _ = database
    event(session)
    target = integration(session)
    drain(session, budget_s=0)
    session.delete(target)
    session.commit()
    result = drain(session)
    assert result["dispatched"] == 0 and result["receipts"] == {"pending": 1}


def test_feed_filters_before_limit_and_never_inherits_platform_events(database):
    from api.routers.notifications import notification_feed

    session, _ = database
    event(session)
    owned = event(session, owner="tenant-a")
    event(session, owner="tenant-b")
    for _ in range(20):
        event(session, owner="tenant-a", kind="graph.updated")
    with tenant_scope("tenant-a"):
        feed = notification_feed(limit=1, user="reader", db=session)
        assert [row["id"] for row in feed["notifications"]] == [owned.id]


def test_legacy_tenant_setting_cannot_block_or_leak_into_platform_routing(database):
    session, _ = database
    session.add(AppSetting(key="notification.routing.v1", tenant_id="tenant-a",
                           value=json.dumps([{"id": "remediation_verification", "channels": {"siem": False}}])))
    session.commit()
    rows, persisted = merged_routing(session)
    assert not persisted and next(r for r in rows if r["id"] == "remediation_verification")["channels"]["siem"]
    routes(session, True)  # must not collide with the tenant's globally unique legacy key
    with tenant_scope("tenant-a"):
        rows, persisted = merged_routing(session)
        assert persisted and not next(r for r in rows if r["id"] == "remediation_verification")["channels"]["siem"]
        routes(session, False)  # moves this owner's legacy key into its namespace
    assert session.query(AppSetting).count() == 2


def test_stop_before_work_does_not_send_or_claim(database, posts):
    session, _ = database
    event(session)
    integration(session)
    outcome = drain(session, should_stop=lambda: True)
    assert outcome["destination_attempts"] == 0 and outcome["receipts"] == {"pending": 1}
    assert not posts


def test_stop_after_claim_leaves_recoverable_lease_without_http(database, posts):
    session, _ = database
    event(session)
    integration(session)
    checks = iter((False, True))
    outcome = drain(session, should_stop=lambda: next(checks))
    assert outcome["destination_attempts"] == 0 and outcome["receipts"] == {"inflight": 1}
    assert not posts
    outcome = drain_notifications(session, clock=lambda: NOW + timedelta(seconds=LEASE_SECONDS + 1))
    assert outcome["delivered"] == 1 and len(posts) == 1


def test_stop_during_transport_records_ack_and_stops_before_next_destination(database):
    session, _ = database
    event(session)
    integration(session)
    integration(session)
    stopped = threading.Event()
    calls = []

    def transport(destination, envelope, **kwargs):
        calls.append(destination["id"])
        stopped.set()
        return delivery.DeliveryResult(integration_id=destination["id"], provider="webhook", kind="siem",
                                       endpoint=destination["endpoint"], status="delivered", http_status=202, attempts=1)

    outcome = drain(session, transport=transport, should_stop=stopped.is_set)
    assert outcome["delivered"] == 1 and outcome["destination_attempts"] == 1 and len(calls) == 1
    assert outcome["receipts"] == {"delivered": 1, "pending": 1}
    assert session.query(DeliveryLog).count() == 1
