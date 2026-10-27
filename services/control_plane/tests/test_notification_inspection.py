"""Read-only diagnostics on real SQLite; no outbound transport or payload reads."""
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session

from control_plane.notification_dispatch import _values
from control_plane.notification_inspection import InvalidReceiptCursor, receipt_page, receipt_summary
from db.models.notification_delivery import NotificationDelivery as Receipt
from db.tenancy import install_tenant_guard, tenant_scope

NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    Receipt.__table__.create(engine)
    install_tenant_guard()
    with Session(engine) as session:
        yield session
    engine.dispose()


def add(session, owner=None, status="pending", **kwargs):
    row = Receipt(**_values(owner, str(uuid.uuid4()), "receiver", "siem", "remediation_verification",
                            {"detail": "hidden-envelope-secret"}, NOW, status=status))
    row.created_at = NOW
    for name, value in kwargs.items():
        setattr(row, name, value)
    session.add(row)
    session.commit()
    return row


def test_summary_is_exact_estate_and_counts_receipts_not_events(session):
    for owner in (None, "tenant-a", "tenant-b"):
        for status in ("pending", "failed", "skipped", "inflight", "delivered", "legacy_unknown"):
            add(session, owner, status, lease_until=NOW - timedelta(seconds=1))
    for owner in (None, "tenant-a", "tenant-b"):
        with tenant_scope(owner):
            data = receipt_summary(session, now=NOW)
            assert data["total"] == 6 and data["pending"] == 4 and data["time_eligible"] == 4
            assert data["expired_claims"] == 1 and data["oldest_pending_at"] == NOW.isoformat()
            assert data["counts"]["legacy_unknown"] == 1
            assert "not event counts" in data["note"]
            assert len(receipt_page(session)["items"]) == 6


def test_summary_distinguishes_backoff_live_lease_and_expired_lease(session):
    add(session, status="failed", next_attempt_at=NOW + timedelta(minutes=1))
    add(session, status="inflight", lease_until=NOW + timedelta(minutes=1))
    add(session, status="inflight", lease_until=NOW - timedelta(minutes=1))
    data = receipt_summary(session, now=NOW)
    assert data["pending"] == 3 and data["time_eligible"] == data["expired_claims"] == 1
    assert receipt_summary(session, now=NOW + timedelta(minutes=2))["time_eligible"] == 3


def test_empty_summary_does_not_invent_scheduler_or_ingestion_health(session):
    data = receipt_summary(session, now=NOW)
    assert data["total"] == data["pending"] == data["time_eligible"] == 0
    assert data["oldest_pending_at"] is None
    assert "Empty does not prove" in data["note"]
    assert "healthy" not in data and "scheduler_alive" not in data


def test_metadata_projection_never_returns_transport_material_or_mutates(session):
    add(session, status="inflight", last_error="hidden-error-secret", lease_token="hidden-token-secret",
        lease_until=NOW - timedelta(seconds=1), delivery_key="hidden-key-secret")
    statements = []
    event.listen(session.get_bind(), "before_cursor_execute", lambda conn, cur, statement, *args: statements.append(statement))
    page = receipt_page(session, now=NOW)
    summary = receipt_summary(session, now=NOW)
    raw = json.dumps([page, summary])
    assert not any(secret in raw for secret in ("hidden-envelope", "hidden-error", "hidden-token", "hidden-key"))
    assert not any(name in page["items"][0] for name in ("envelope", "last_error", "delivery_key", "lease_token", "endpoint", "tenant_id"))
    assert page["items"][0]["has_error"] and page["items"][0]["time_eligible"]
    assert page["items"][0]["next_attempt_at"] is None
    assert all(statement.lstrip().upper().startswith("SELECT") for statement in statements)
    assert all(".envelope" not in statement for statement in statements)
    assert session.scalar(select(Receipt.status)) == "inflight"


def test_keyset_pages_tied_timestamps_without_duplicates_or_tenant_interference(session):
    expected = {add(session, "tenant-a").id for _ in range(7)}
    for _ in range(30):
        add(session, "tenant-b", created_at=NOW + timedelta(days=1))
        add(session, created_at=NOW + timedelta(days=1))
    with tenant_scope("tenant-a"):
        cursor = None
        seen = []
        while True:
            page = receipt_page(session, limit=2, cursor=cursor)
            seen.extend(row["id"] for row in page["items"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        assert len(seen) == len(set(seen)) == 7 and set(seen) == expected
        assert seen == sorted(seen, reverse=True)


def test_filtering_happens_before_limit_and_updates_do_not_reorder_creation(session):
    failed = add(session, status="failed", created_at=NOW - timedelta(days=1))
    for _ in range(4):
        add(session, status="delivered")
    page = receipt_page(session, status="failed", limit=1)
    assert [row["id"] for row in page["items"]] == [failed.id] and page["next_cursor"] is None
    failed.next_attempt_at = NOW + timedelta(days=3)
    session.commit()
    assert receipt_page(session, limit=100)["items"][-1]["id"] == failed.id


def test_legacy_unknown_never_claims_retry_or_acknowledgement(session):
    add(session, status="legacy_unknown", event_class="", channel="legacy")
    item = receipt_page(session, now=NOW)["items"][0]
    assert item["status"] == "legacy_unknown" and not item["time_eligible"]
    assert item["next_attempt_at"] is None and item["delivered_at"] is None


def test_cursor_is_bound_to_scope_and_filter_but_not_an_authorization_token(session):
    for _ in range(3):
        add(session, "tenant-a", "failed")
    with tenant_scope("tenant-a"):
        cursor = receipt_page(session, status="failed", limit=1)["next_cursor"]
        with pytest.raises(InvalidReceiptCursor):
            receipt_page(session, cursor=cursor)
    with tenant_scope("tenant-b"), pytest.raises(InvalidReceiptCursor):
        receipt_page(session, status="failed", cursor=cursor)
    # Editing the scope marker cannot grant rows in another estate.
    body = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    body["scope"] = "tenant:tenant-b"
    changed = base64.urlsafe_b64encode(json.dumps(body).encode()).decode()
    with tenant_scope("tenant-b"), pytest.raises(InvalidReceiptCursor):
        receipt_page(session, status="failed", cursor=changed)


@pytest.mark.parametrize("cursor", ["", "!", "a" * 513, "e30", "W10", "bnVsbA", "eyJ2IjoxfQ"])
def test_malformed_cursor_fails_closed(session, cursor):
    with pytest.raises(InvalidReceiptCursor):
        receipt_page(session, cursor=cursor)


@pytest.mark.parametrize("limit,status", [(0, None), (101, None), (True, None), (25, "unknown")])
def test_service_bounds_are_not_only_http_validation(session, limit, status):
    with pytest.raises(ValueError):
        receipt_page(session, limit=limit, status=status)


@pytest.mark.parametrize("change", [{"id": "\u0000"}, {"id": "☃"}, {"v": True}, {"at": "2026-10-17"}, {"at": 123}])
def test_well_encoded_but_invalid_cursor_values_are_rejected(session, change):
    for _ in range(2):
        add(session)
    cursor = receipt_page(session, limit=1)["next_cursor"]
    body = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    body.update(change)
    cursor = base64.urlsafe_b64encode(json.dumps(body).encode()).decode()
    with pytest.raises(InvalidReceiptCursor):
        receipt_page(session, cursor=cursor)


def test_inspection_does_not_autoflush_callers_uncommitted_receipt_work(session):
    existing = add(session)
    existing.status = "delivered"  # not a durable acknowledgement
    extra = Receipt(**_values(None, "uncommitted-event", "receiver", "siem", "compliance_failure", {}, NOW))
    session.add(extra)
    assert receipt_summary(session, now=NOW)["counts"]["delivered"] == 0
    assert receipt_summary(session, now=NOW)["total"] == 1
    assert [row["status"] for row in receipt_page(session, now=NOW)["items"]] == ["pending"]
    assert extra in session.new and existing in session.dirty
    session.rollback()


def test_sqlite_server_default_timestamp_pages_do_not_repeat_anchor(session):
    from sqlalchemy import func

    expected = {add(session, created_at=func.datetime("2026-10-17 00:00:00")).id for _ in range(5)}
    seen, cursor = [], None
    for _ in range(5):
        page = receipt_page(session, limit=2, cursor=cursor)
        seen.extend(row["id"] for row in page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert cursor is None and len(seen) == len(set(seen)) == 5 and set(seen) == expected
