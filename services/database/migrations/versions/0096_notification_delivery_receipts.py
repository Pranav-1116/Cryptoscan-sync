"""Durable destination receipts and conservative legacy notification handoff.

Successful per-destination HTTP audit rows become delivered receipts; the old
bounded whole-event registry becomes legacy_unknown tombstones, NOT ACKs. This
prevents known legacy events replaying without pretending failed/skipped sends
succeeded. No history is deleted. Stop old drains before applying this migration.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "0096"
down_revision = "0095"
branch_labels = None
depends_on = None


def _values(owner, event_id, integration_id, channel, status, now):
    scope = "platform" if owner is None else f"tenant:{owner}"
    key = hashlib.sha256(json.dumps([scope, event_id, integration_id, channel], separators=(",", ":")).encode()).hexdigest()
    return dict(id=str(uuid.uuid5(uuid.NAMESPACE_URL, "cryptoscan.notification:" + key)), tenant_id=owner,
                scope_key=scope, event_id=event_id, integration_id=integration_id, channel=channel,
                delivery_key=key, event_class="", envelope={}, status=status, attempt_count=0,
                next_attempt_at=now, created_at=now, updated_at=now)


def upgrade() -> None:
    bind = op.get_bind()
    # Validate legacy configuration before DDL (SQLite DDL may not roll back).
    settings = sa.table("app_settings", sa.column("key"), sa.column("value"), sa.column("tenant_id"))
    legacy = []
    for row in bind.execute(sa.select(settings.c.value, settings.c.tenant_id).where(
        settings.c.key == "notification.dispatch.v1")).mappings():
        value = json.loads(row["value"])
        ids = value.get("dispatched") if isinstance(value, dict) else None
        if not isinstance(ids, list) or len(ids) > 2000 or any(
            not isinstance(i, str) or not 1 <= len(i) <= 36 for i in ids
        ):
            raise ValueError("invalid legacy notification dispatch registry; reconcile before migration")
        legacy.append((row["tenant_id"], set(ids)))
    table = op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("scope_key", sa.String(80), nullable=False),
        sa.Column("event_id", sa.String(36), nullable=False),
        sa.Column("integration_id", sa.String(36), nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("event_class", sa.String(80), nullable=False),
        sa.Column("delivery_key", sa.String(64), nullable=False),
        sa.Column("envelope", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_token", sa.String(36)),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(300)),
        sa.Column("http_status", sa.Integer()),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("scope_key", "event_id", "integration_id", "channel", name="uq_notification_destination"),
        sa.UniqueConstraint("delivery_key", name="uq_notification_delivery_key"),
        sa.CheckConstraint("status IN ('pending','inflight','delivered','failed','skipped','legacy_unknown')",
                           name="ck_notification_delivery_status"),
    )
    op.create_index("ix_notification_deliveries_tenant_id", "notification_deliveries", ["tenant_id"])
    op.create_index("ix_notification_deliveries_event_id", "notification_deliveries", ["event_id"])
    op.create_index("ix_notification_deliveries_due", "notification_deliveries", ["scope_key", "status", "next_attempt_at"])
    if bind.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    now = datetime.now(timezone.utc)
    for owner, ids in legacy:
        for event_id in ids:
            bind.execute(insert(table).values(**_values(owner, event_id, "legacy-registry", "legacy", "legacy_unknown", now))
                         .on_conflict_do_nothing())
    logs = sa.table("cp_delivery_logs", sa.column("tenant_id"), sa.column("event_id"), sa.column("integration_id"),
                    sa.column("kind"), sa.column("event_type"), sa.column("status"), sa.column("http_status"),
                    sa.column("created_at"))
    # Include successes already evicted from the capped registry. Failed,
    # skipped or unobserved destinations are NEVER backfilled as delivered.
    for row in bind.execute(sa.select(logs).where(logs.c.status == "delivered",
        logs.c.event_id.is_not(None), logs.c.integration_id.is_not(None),
        logs.c.event_type.like("notification.%"), logs.c.http_status.between(200, 299))).mappings():
        channel = "siem" if row["kind"] in ("siem", "soar") else "webhook" if row["kind"] in ("itsm", "cmdb") else None
        if channel is None:
            continue
        values = _values(row["tenant_id"], row["event_id"], row["integration_id"], channel, "delivered", now)
        values["http_status"] = row["http_status"]
        # Legacy snapshots have no retry envelope; delivered rows never send.
        # The audit row retains the original observation time (not invented).
        observed = row["created_at"]
        if isinstance(observed, str):
            observed = datetime.fromisoformat(observed)
        values["delivered_at"] = observed
        bind.execute(insert(table).values(**values).on_conflict_do_nothing())


def downgrade() -> None:
    bind = op.get_bind()
    table = sa.table("notification_deliveries", sa.column("id"))
    settings = sa.table("app_settings", sa.column("key"))
    scoped_routing = bind.execute(sa.select(sa.func.count()).select_from(settings).where(
        settings.c.key.like("notification.routing.v1:%"))).scalar()
    if bind.execute(sa.select(sa.func.count()).select_from(table)).scalar() or scoped_routing:
        raise RuntimeError("cannot discard notification receipts or scoped routing; reconcile delivery/rollback policy before downgrade")
    op.drop_table("notification_deliveries")
