"""Security bookkeeping that must survive a restart.

Revision ID: 0163
Revises: 0162

Two monitors were process-local lists:

1. **The suspicious-access window** (``api.security.auth_monitor``) — a
   restart erased the failure history, so a probing attacker only had to
   wait for a deploy to clear their flag. ``security_auth_events`` keeps
   the failed-authentication stamps the window is rebuilt from
   (``occurred_at`` is an epoch float: the window math is float-epoch
   arithmetic and hydration must restore the exact stamps).
2. **The vault rotation-staleness watch** (``api.security.vault.RESOLUTION_LOG``)
   — a restart forgot what the process had been running on since boot, so
   ``held`` ages restarted at zero and a rotated-out value stayed
   invisible until it broke. ``vault_resolution_records`` keeps the
   resolution observations the watch reads.

The in-memory structures remain the fast path; these rows are what they
are hydrated from. Both creations are guarded (re-running is a no-op),
and the models declare the same tables/columns (model/migration parity).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0163"
down_revision = "0162"
branch_labels = None
depends_on = None

TABLES = (
    (
        "security_auth_events",
        (
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=True),
            sa.Column("user_key", sa.String(200), nullable=False),
            sa.Column("source", sa.String(120), nullable=False),
            sa.Column("occurred_at", sa.Float(), nullable=False),
        ),
        ("ix_security_auth_events_key_time", ("user_key", "source", "occurred_at")),
    ),
    (
        "vault_resolution_records",
        (
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=True),
            sa.Column("provider", sa.String(80), nullable=False),
            sa.Column("reference", sa.String(400), nullable=False),
            sa.Column("outcome", sa.String(40), nullable=False),
            sa.Column("kind", sa.String(40), nullable=False),
            sa.Column("resolved_at", sa.String(60), nullable=False),
        ),
        ("ix_vault_resolution_ref_kind", ("reference", "kind", "resolved_at")),
    ),
)


def upgrade() -> None:
    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name, columns, (index_name, index_cols) in TABLES:
        if name not in existing:
            op.create_table(name, *columns)
        inspector = {ix["name"] for ix in sa.inspect(bind).get_indexes(name)}
        if index_name not in inspector:
            op.create_index(index_name, name, list(index_cols))


def downgrade() -> None:
    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name, _columns, (index_name, _index_cols) in reversed(TABLES):
        if name in existing:
            op.drop_index(index_name, table_name=name)
            op.drop_table(name)
